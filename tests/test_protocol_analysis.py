"""Tests for :mod:`sih141.protocol.analysis`.

Every closed form in that module is checked twice: once against algebraic
identities that must hold exactly, and once against a **Monte-Carlo simulator
written from the protocol specification inside this file**.

Why the simulator is rebuilt here
---------------------------------
The point of a cross-check is that the two sides are independent. If these tests
drove :mod:`sih141.protocol.distribute` and :mod:`sih141.protocol.verify`, a
shared misreading of the protocol -- unmatched positions counted, the wrong
match probability, an off-by-one in the acceptance rule -- would agree with
itself and the tests would pass. So :func:`_simulate_matched_and_mismatches` and
its helpers implement Phase A and Phase C directly from the written
specification, in about thirty lines of :mod:`numpy`, importing nothing from
``sih141`` except the parameter values. They do not simulate quantum states,
because the analysis does not model them either: Phase 1 already pins the two
facts that matter (a measurement in the preparation basis is deterministic; a
measurement in a conjugate basis is a fair coin) and
``tests/test_protocol_distribute.py`` pins that the teleported pipeline realises
them. What is under test here is everything built on top of those two facts.

Tolerances
----------
Never a magic number. A proportion estimated from ``N`` independent trials has
standard error ``sqrt(p(1-p)/N)``, and every comparison admits
:data:`_SIGMAS` = 5 of them -- a two-sided false-alarm rate near ``6e-7`` per
assertion, so the suite is not flaky even though it is statistical. The
generators are seeded (D3), so a failure is reproducible rather than
intermittent, and a genuine formula error shifts the estimate by far more than
five standard errors at the sample sizes used here.

What is pinned, in order of how badly it fails silently
-------------------------------------------------------
1. **The forgery model.** The claim that an external forger survives a matched
   position with probability exactly ``1/2`` *whatever she declares* is the
   single load-bearing assumption of the security numbers. It is attacked with
   four different adversary strategies, including one that tries to steer the
   matched set, and all four must give the same acceptance probability as the
   closed form.
2. **The matched/unmatched split.** A run whose unmatched positions all
   contradict the declaration must still score ``0``, and the "buggy" rate that
   divides by ``L`` is shown to exceed ``s_v`` on an honest noiseless run --
   which is exactly the symptom the module docstring warns about.
3. **The empty-matched-set convention.** At small ``L`` the ``m = 0`` branch
   carries real probability mass, so the tests run there deliberately and the
   analytic and simulated numbers only agree if both treat it as "not accepted".
4. **Bounds dominate.** Every ``*_bound`` is checked against its exact partner
   over a grid, and the relative-entropy form against the Hoeffding form.
"""

from __future__ import annotations

import math
from functools import partial

import numpy as np
import pytest

from sih141.core.paulis import PauliBasis
from sih141.protocol.analysis import (
    FORGER_MATCHED_MISMATCH_PROBABILITY,
    HonestStatistics,
    MatchedStatistics,
    averaged_repudiation_bound,
    binary_kl_divergence,
    depolarising_error_rate,
    forgery_bound,
    forgery_probability,
    hoeffding_exponent,
    honest_abort_bound,
    honest_abort_probability,
    honest_statistics,
    matched_count_distribution,
    matched_shortfall_probability,
    matched_statistics,
    max_accepted_mismatches,
    recipient_forgery_bound,
    recipient_forgery_probability,
    repudiation_bound,
    repudiation_bound_with_abort,
    repudiation_probability,
    symmetric_repudiation_bound,
)
from sih141.protocol.params import (
    DEFAULT_PARAMS,
    DEMO_PARAMS,
    Party,
    ProtocolParams,
)

_SIGMAS = 5.0
"""Standard errors of slack allowed in a Monte-Carlo comparison."""

_SEED = 20260141


def _rng(offset: int = 0) -> np.random.Generator:
    """Return a seeded generator (D3: no module-level randomness anywhere)."""
    return np.random.default_rng(_SEED + offset)


# =========================================================================== #
# An independent simulator, written from the protocol specification.
#
#   Phase A.  Alice draws basis a_i uniform over B and eigenvalue v_i uniform
#             over {+1,-1}.  Each recipient draws its own basis c_i uniform over
#             B and measures:  c_i == a_i  ->  outcome is v_i with certainty;
#             c_i != a_i      ->  outcome is a fair coin.
#   Phase C.  Against a declaration (d_i, w_i):
#             M = {i : c_i == d_i},  e = |{i in M : o_i != w_i}|,  r = e/|M|,
#             accept iff |M| >= 1 and r <= threshold.
#
# Eigenvalues are carried as bits (0 -> +1, 1 -> -1); the scoring rule only ever
# compares them for equality, so the encoding is immaterial.
# =========================================================================== #


def _draw_key(
    trials: int, key_length: int, n_bases: int, rng: np.random.Generator
) -> tuple[np.ndarray, np.ndarray]:
    """Draw ``trials`` independent private keys of length ``key_length``."""
    bases = rng.integers(0, n_bases, size=(trials, key_length), dtype=np.int8)
    bits = rng.integers(0, 2, size=(trials, key_length), dtype=np.int8)
    return bases, bits


def _measure(
    alice_bases: np.ndarray,
    alice_bits: np.ndarray,
    n_bases: int,
    rng: np.random.Generator,
    *,
    error_rate: float = 0.0,
) -> tuple[np.ndarray, np.ndarray]:
    """One recipient's Phase A: random basis, immediate measurement, classical log.

    A flip applied with probability ``error_rate`` models the channel. Applying
    it on conjugate positions too is deliberate and harmless: a flipped fair coin
    is still a fair coin, so the only visible effect is on matched positions,
    which is exactly what ``p_e`` is defined to be.
    """
    shape = alice_bases.shape
    recipient_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
    coin = rng.integers(0, 2, size=shape, dtype=np.int8)
    outcomes = np.where(recipient_bases == alice_bases, alice_bits, coin)
    if error_rate > 0.0:
        flipped = rng.random(shape) < error_rate
        outcomes = np.where(flipped, 1 - outcomes, outcomes)
    return recipient_bases, outcomes.astype(np.int8)


def _score(
    declared_bases: np.ndarray,
    declared_bits: np.ndarray,
    recipient_bases: np.ndarray,
    recipient_bits: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Phase C counting: return ``(|M|, e)`` per trial, matched positions only."""
    matched = declared_bases == recipient_bases
    return (
        matched.sum(axis=1),
        (matched & (declared_bits != recipient_bits)).sum(axis=1),
    )


def _accepts(matched: np.ndarray, mismatches: np.ndarray, threshold: float) -> np.ndarray:
    """``|M| >= 1 and e/|M| <= threshold``, the rule verify() applies."""
    safe = np.maximum(matched, 1)
    rate = mismatches / safe
    return (matched >= 1) & (rate <= threshold)


def _simulate_matched_and_mismatches(
    trials: int,
    params: ProtocolParams,
    rng: np.random.Generator,
    *,
    error_rate: float = 0.0,
) -> tuple[np.ndarray, np.ndarray]:
    """Full honest pipeline for one recipient: draw, distribute, measure, score."""
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    recipient_bases, outcomes = _measure(
        alice_bases, alice_bits, n_bases, rng, error_rate=error_rate
    )
    return _score(alice_bases, alice_bits, recipient_bases, outcomes)


def _assert_close_to_proportion(
    observed: float,
    expected: float,
    trials: int,
    *,
    label: str,
    sigmas: float = _SIGMAS,
) -> None:
    """Assert a simulated proportion sits within ``sigmas`` standard errors."""
    variance = max(expected * (1.0 - expected), 1e-15)
    tolerance = sigmas * math.sqrt(variance / trials)
    assert abs(observed - expected) <= tolerance, (
        f"{label}: simulated {observed!r} vs analytic {expected!r}, "
        f"difference {abs(observed - expected):.3e} exceeds {sigmas} standard "
        f"errors ({tolerance:.3e}) over {trials} trials"
    )


def _assert_close_to_mean(
    samples: np.ndarray, expected: float, *, label: str, sigmas: float = _SIGMAS
) -> None:
    """Assert a simulated mean sits within ``sigmas`` standard errors of ``expected``."""
    trials = samples.size
    observed = float(samples.mean())
    standard_error = float(samples.std(ddof=1)) / math.sqrt(trials)
    tolerance = sigmas * standard_error + 1e-12
    assert abs(observed - expected) <= tolerance, (
        f"{label}: simulated mean {observed!r} vs analytic {expected!r}, "
        f"difference {abs(observed - expected):.3e} exceeds {sigmas} standard "
        f"errors ({tolerance:.3e}) over {trials} trials"
    )


# =========================================================================== #
# 1. p_match = 1/3, E[|M|] = L/3 and the binomial variance
# =========================================================================== #


def test_match_probability_is_one_over_alphabet_size() -> None:
    """``p_match = 1/|B|``: 1/3 for {X,Y,Z}, 1/2 for a two-basis alphabet."""
    three = matched_statistics(ProtocolParams(key_length=99))
    assert three.match_probability == pytest.approx(1 / 3)
    two = matched_statistics(
        ProtocolParams(key_length=99, bases=(PauliBasis.X, PauliBasis.Z))
    )
    assert two.match_probability == pytest.approx(1 / 2)


def test_expected_matched_is_key_length_over_three() -> None:
    """``E[|M|] = L/3`` and ``Var[|M|] = 2L/9`` for the default alphabet."""
    stats = matched_statistics(ProtocolParams(key_length=900))
    assert stats.expected == pytest.approx(300.0)
    assert stats.variance == pytest.approx(200.0)
    assert stats.standard_deviation == pytest.approx(math.sqrt(200.0))
    assert stats.relative_standard_deviation == pytest.approx(
        math.sqrt(200.0) / 300.0
    )


def test_matched_statistics_agrees_with_protocol_params() -> None:
    """The moments are the same numbers ProtocolParams already advertises."""
    stats = matched_statistics(DEFAULT_PARAMS)
    assert stats.expected == DEFAULT_PARAMS.expected_matched
    assert stats.match_probability == DEFAULT_PARAMS.match_probability


def test_matched_count_moments_match_simulation() -> None:
    """MC: the mean and variance of ``|M|`` are ``L/3`` and ``2L/9``."""
    params = ProtocolParams(key_length=30)
    trials = 60_000
    matched, _ = _simulate_matched_and_mismatches(trials, params, _rng(1))
    stats = matched_statistics(params)
    _assert_close_to_mean(
        matched.astype(float), stats.expected, label="E[|M|]"
    )
    observed_variance = float(matched.var(ddof=1))
    # Var of the sample variance of a binomial: use the delta-method scale
    # sqrt(2/(N-1)) * sigma^2, which is exact for the leading term.
    tolerance = _SIGMAS * stats.variance * math.sqrt(2.0 / (trials - 1)) * 2.0
    assert abs(observed_variance - stats.variance) <= tolerance


def test_matched_count_distribution_matches_simulation() -> None:
    """MC: the whole pmf of ``|M|``, not just its first two moments."""
    params = ProtocolParams(key_length=12)
    trials = 200_000
    matched, _ = _simulate_matched_and_mismatches(trials, params, _rng(2))
    pmf = matched_count_distribution(params)
    assert pmf.shape == (params.key_length + 1,)
    assert float(pmf.sum()) == pytest.approx(1.0)
    counts = np.bincount(matched, minlength=params.key_length + 1)
    for value, expected in enumerate(pmf):
        if expected * trials < 20.0:
            continue
        _assert_close_to_proportion(
            counts[value] / trials,
            float(expected),
            trials,
            label=f"P(|M| = {value})",
        )


def test_forged_declaration_does_not_change_the_matched_distribution() -> None:
    """A forger's declared bases cannot steer ``|M|``: still Binomial(L, 1/3).

    This is step 1 of the forgery derivation. The recipient's basis draw is
    uniform and independent of anything the adversary knows, so the matched set
    has the same law whatever she declares -- here, a deliberately degenerate
    "always declare basis 0" strategy.
    """
    params = ProtocolParams(key_length=30)
    trials = 60_000
    rng = _rng(3)
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    recipient_bases, _ = _measure(alice_bases, alice_bits, n_bases, rng)
    forged_bases = np.zeros_like(alice_bases)
    matched = (forged_bases == recipient_bases).sum(axis=1)
    _assert_close_to_mean(
        matched.astype(float),
        matched_statistics(params).expected,
        label="E[|M|] against a constant-basis forger",
    )


# =========================================================================== #
# 2. the honest rate: exactly zero noiseless, p_e under a noisy channel
# =========================================================================== #


def test_honest_noiseless_run_has_exactly_zero_mismatches() -> None:
    """MC: not "approximately zero" -- zero, in every trial, for both parties."""
    params = ProtocolParams(key_length=40)
    matched, mismatches = _simulate_matched_and_mismatches(20_000, params, _rng(4))
    assert mismatches.max() == 0
    assert matched.min() >= 1  # (2/3)^40 ~ 1e-7, so no empty set is expected
    assert honest_statistics(params).expected_rate == 0.0


def test_counting_unmatched_positions_breaks_an_honest_noiseless_run() -> None:
    """The classic bug, shown failing: dividing by ``L`` rejects honest runs.

    The correct rate is ``0`` on every trial. The buggy rate -- disagreements
    over *all* positions divided by ``L`` -- concentrates at
    ``(1 - 1/|B|)/2 = 1/3``, which is above ``s_v``, so an implementation with
    that bug rejects honest noiseless signatures at *both* verifiers and the
    symptom looks like channel noise.
    """
    params = ProtocolParams(key_length=60)
    trials = 4_000
    rng = _rng(5)
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    recipient_bases, outcomes = _measure(alice_bases, alice_bits, n_bases, rng)

    matched, mismatches = _score(
        alice_bases, alice_bits, recipient_bases, outcomes
    )
    assert mismatches.sum() == 0

    buggy_rate = (alice_bits != outcomes).sum(axis=1) / params.key_length
    assert float(buggy_rate.mean()) == pytest.approx(
        params.unmatched_noise_rate, abs=0.01
    )
    assert (buggy_rate > params.s_v).mean() > 0.99


def test_honest_rate_variance_is_the_exact_algebraic_expression() -> None:
    """``Var[r] = p_e(1 - p_e) E[1/|M| : |M| >= 1]``, recomputed from the pmf.

    The exact pin the Monte-Carlo test below cannot be: a ~10% error in the
    variance formula sits inside any honest sampling tolerance for a *variance*
    estimator, so before this test existed the MC comparison was the only guard
    and a ``* 1.10`` mutation passed the whole suite. Here the conditional
    expectation is rebuilt from ``matched_count_distribution`` and the product
    is asserted to floating-point equality, so any change to the expression
    fails immediately.
    """
    for key_length, error_rate in ((30, 0.2), (90, 0.08), (192, 0.0)):
        params = ProtocolParams(key_length=key_length)
        stats = honest_statistics(params, error_rate=error_rate)

        pmf = matched_count_distribution(params)
        counts = np.arange(1, key_length + 1, dtype=float)
        survivors = pmf[1:]
        reciprocal = float((survivors / counts).sum()) / float(survivors.sum())

        assert stats.expected_reciprocal_matched == pytest.approx(
            reciprocal, rel=1e-12
        , abs=0)
        assert stats.rate_variance == pytest.approx(
            error_rate * (1.0 - error_rate) * reciprocal, rel=1e-12
        , abs=0)
        assert stats.rate_standard_deviation == pytest.approx(
            math.sqrt(stats.rate_variance), rel=1e-12
        , abs=0)


def test_honest_rate_mean_and_variance_match_simulation() -> None:
    """MC: ``E[r] = p_e`` and ``Var[r] = p_e(1-p_e) E[1/|M|]``, exactly.

    The variance tolerance is the principled one for a variance estimator --
    ``sigma^2 sqrt(2/(N-1))`` standard errors, times :data:`_SIGMAS` -- with no
    fudge factor. It used to carry an undocumented ``* 3.0``, which widened the
    acceptance band to about 10% relative and made the test blind to a
    materially wrong formula. The exact pin above is what actually guards the
    expression; this one guards the *model* behind it, so it is allowed to be
    loose in absolute terms but not arbitrary.
    """
    params = ProtocolParams(key_length=90)
    error_rate = 0.08
    trials = 40_000
    matched, mismatches = _simulate_matched_and_mismatches(
        trials, params, _rng(6), error_rate=error_rate
    )
    assert matched.min() >= 1
    rates = mismatches / matched

    stats = honest_statistics(params, error_rate=error_rate)
    _assert_close_to_mean(rates, stats.expected_rate, label="E[r]")

    observed_variance = float(rates.var(ddof=1))
    tolerance = _SIGMAS * stats.rate_variance * math.sqrt(2.0 / (trials - 1))
    assert abs(observed_variance - stats.rate_variance) <= tolerance, (
        f"Var[r]: simulated {observed_variance!r} vs analytic "
        f"{stats.rate_variance!r}"
    )


def test_expected_reciprocal_matched_exceeds_one_over_expected_matched() -> None:
    """Jensen: ``E[1/m] > 1/E[m]``, so the naive substitution understates Var[r]."""
    params = ProtocolParams(key_length=192)
    stats = honest_statistics(params, error_rate=0.05)
    assert stats.expected_reciprocal_matched > 1.0 / params.expected_matched
    assert stats.expected_reciprocal_matched == pytest.approx(
        1.0 / params.expected_matched, rel=0.02
    , abs=0)


def test_honest_statistics_reports_zero_variance_at_zero_error_rate() -> None:
    """No noise, no spread: the honest rate is the constant ``0``."""
    stats = honest_statistics(DEMO_PARAMS, error_rate=0.0)
    assert stats.expected_rate == 0.0
    assert stats.rate_variance == 0.0
    assert stats.rate_standard_deviation == 0.0


def test_depolarising_parameter_maps_to_half_the_error_rate() -> None:
    """``p_e = p/2``, and the default ``s_a`` is the ``p = 1/32`` noise budget."""
    assert depolarising_error_rate(0.0) == 0.0
    assert depolarising_error_rate(1.0) == 0.5
    assert depolarising_error_rate(1 / 32) == pytest.approx(DEFAULT_PARAMS.s_a)


def test_depolarising_error_rate_matches_simulation() -> None:
    """MC: a channel that randomises with probability ``p`` mismatches at ``p/2``.

    Simulated from the definition of the depolarising channel rather than from
    the formula: with probability ``p`` the recipient's qubit is replaced by the
    maximally mixed state, whose measurement is a fair coin.
    """
    depolarising = 0.3
    trials = 200_000
    rng = _rng(7)
    randomised = rng.random(trials) < depolarising
    coin = rng.integers(0, 2, size=trials)
    outcomes = np.where(randomised, coin, 0)
    _assert_close_to_proportion(
        float((outcomes != 0).mean()),
        depolarising_error_rate(depolarising),
        trials,
        label="depolarising p_e",
    )


# =========================================================================== #
# 3. forgery
# =========================================================================== #


def _forger_declaration(
    strategy: str,
    trials: int,
    key_length: int,
    n_bases: int,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    """Build a forged declaration under one of four adversary strategies.

    None of them has any information about the private key, which is the whole
    content of the adversary model: ``uniform`` is the obvious one, ``constant``
    tries to concentrate the matched set on one basis, ``all_plus`` fixes the
    declared eigenvalue, and ``adversarial`` fixes both. If the derivation is
    right, all four are accepted with the same probability.
    """
    shape = (trials, key_length)
    if strategy == "uniform":
        return (
            rng.integers(0, n_bases, size=shape, dtype=np.int8),
            rng.integers(0, 2, size=shape, dtype=np.int8),
        )
    if strategy == "constant":
        return (
            np.zeros(shape, dtype=np.int8),
            rng.integers(0, 2, size=shape, dtype=np.int8),
        )
    if strategy == "all_plus":
        return (
            rng.integers(0, n_bases, size=shape, dtype=np.int8),
            np.zeros(shape, dtype=np.int8),
        )
    if strategy == "adversarial":
        return np.zeros(shape, dtype=np.int8), np.zeros(shape, dtype=np.int8)
    raise ValueError(f"unknown forger strategy {strategy!r}")


def _simulate_forgery(
    strategy: str,
    trials: int,
    params: ProtocolParams,
    threshold: float,
    rng: np.random.Generator,
) -> float:
    """Return the simulated acceptance rate of a key-ignorant forger."""
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    recipient_bases, outcomes = _measure(
        alice_bases, alice_bits, n_bases, rng
    )
    declared_bases, declared_bits = _forger_declaration(
        strategy, trials, params.key_length, n_bases, rng
    )
    matched, mismatches = _score(
        declared_bases, declared_bits, recipient_bases, outcomes
    )
    return float(_accepts(matched, mismatches, threshold).mean())


def test_forger_survives_a_matched_position_with_probability_one_half() -> None:
    """MC: step 2 of the derivation, isolated.

    Conditioned on a matched position the recipient's outcome is a fair coin
    independent of the declared eigenvalue, whichever branch of Alice's basis
    draw produced it. Estimated over matched positions only, pooled across the
    whole run.
    """
    params = ProtocolParams(key_length=20)
    trials = 30_000
    rng = _rng(8)
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    recipient_bases, outcomes = _measure(alice_bases, alice_bits, n_bases, rng)
    declared_bases, declared_bits = _forger_declaration(
        "uniform", trials, params.key_length, n_bases, rng
    )
    matched = declared_bases == recipient_bases
    positions = int(matched.sum())
    disagreements = int((matched & (declared_bits != outcomes)).sum())
    _assert_close_to_proportion(
        disagreements / positions,
        FORGER_MATCHED_MISMATCH_PROBABILITY,
        positions,
        label="forger per-matched-position mismatch rate",
    )


@pytest.mark.parametrize(
    "key_length, s_a, s_v",
    [(12, 1 / 32, 0.4), (18, 0.1, 0.3), (30, 1 / 64, 1 / 16)],
)
def test_forgery_probability_matches_simulation(
    key_length: int, s_a: float, s_v: float
) -> None:
    """MC: the closed form for ``P_forge(L, s_v)``, over three parameter sets.

    ``L = 12`` is deliberately short: ``P(|M| = 0) = (2/3)^12 ~ 0.008`` is real
    probability mass there, so the simulated and analytic numbers only agree if
    both treat an empty matched set as a non-acceptance.
    """
    # ``allow_forgeable`` because two of the three sets deliberately sit above
    # the recipient-forger floor: this test is about the *formula*, and the
    # loose thresholds are what make the empty-matched-set branch and the
    # near-one regime reachable at these tiny key lengths.
    params = ProtocolParams(
        key_length=key_length, s_a=s_a, s_v=s_v, allow_forgeable=s_v > 1 / 12
    )
    trials = 200_000
    expected = forgery_probability(params)
    observed = _simulate_forgery("uniform", trials, params, params.s_v, _rng(9))
    _assert_close_to_proportion(
        observed, expected, trials, label=f"P_forge(L={key_length})"
    )


@pytest.mark.parametrize(
    "strategy", ["uniform", "constant", "all_plus", "adversarial"]
)
def test_forgery_probability_does_not_depend_on_the_declaration_strategy(
    strategy: str,
) -> None:
    """MC: four adversary strategies, one acceptance probability.

    This is the sharpest test of the adversary model. A forger who fixes her
    declared bases changes *which* positions are matched but not how many, and
    conditioning on a matched position tells her nothing, so her acceptance
    probability is strategy-independent. A model that let her steer the matched
    set would show ``constant`` and ``adversarial`` beating ``uniform`` here.
    """
    params = ProtocolParams(
        key_length=15, s_a=1 / 32, s_v=0.4, allow_forgeable=True
    )
    trials = 200_000
    expected = forgery_probability(params)
    observed = _simulate_forgery(strategy, trials, params, params.s_v, _rng(10))
    _assert_close_to_proportion(
        observed, expected, trials, label=f"P_forge under {strategy!r}"
    )


def test_forgery_probability_matches_simulation_against_bob() -> None:
    """MC: the ``s_a`` variant. Bob is the harder target, so the number is lower."""
    params = ProtocolParams(
        key_length=15, s_a=0.2, s_v=0.4, allow_forgeable=True
    )
    trials = 200_000
    expected = forgery_probability(params, party=Party.BOB)
    observed = _simulate_forgery("uniform", trials, params, params.s_a, _rng(11))
    _assert_close_to_proportion(
        observed, expected, trials, label="P_forge against Bob"
    )
    assert expected < forgery_probability(params, party=Party.CHARLIE)


def test_forgery_probability_decays_exponentially_in_key_length() -> None:
    """``ln P_forge`` is asymptotically linear in ``L`` with a negative slope."""
    lengths = [300, 600, 900, 1200]
    logs = [
        math.log(
            forgery_probability(ProtocolParams(key_length=length))
        )
        for length in lengths
    ]
    slopes = [
        (logs[i + 1] - logs[i]) / (lengths[i + 1] - lengths[i])
        for i in range(len(lengths) - 1)
    ]
    assert all(slope < -0.05 for slope in slopes)
    # The successive slopes agree to a few percent: the decay is a clean
    # exponential, not merely a decreasing sequence.
    assert max(slopes) - min(slopes) < 0.02 * abs(min(slopes))


def test_forgery_probability_is_monotone_in_key_length_and_threshold() -> None:
    """More key or a tighter cut can only make forging harder."""
    base = ProtocolParams(key_length=60, s_a=1 / 64, s_v=1 / 16)
    assert forgery_probability(base.with_changes(key_length=120)) < (
        forgery_probability(base)
    )
    assert forgery_probability(base.with_changes(s_v=1 / 32)) < (
        forgery_probability(base)
    )


@pytest.mark.parametrize("key_length", [6, 15, 30, 60])
@pytest.mark.parametrize("method", ["hoeffding", "kl"])
def test_forgery_bound_dominates_the_exact_probability(
    key_length: int, method: str
) -> None:
    """The bound is a bound, at every length and with either inequality."""
    params = ProtocolParams(key_length=key_length)
    assert forgery_probability(params) <= forgery_bound(params, method=method)


def test_kl_forgery_bound_is_tighter_than_hoeffding() -> None:
    """Pinsker in action: ``D(s_v||1/2) > 2(1/2 - s_v)^2``, so the KL bound wins."""
    params = ProtocolParams(key_length=600)
    assert forgery_bound(params, method="kl") < forgery_bound(
        params, method="hoeffding"
    )
    assert binary_kl_divergence(params.s_v, 0.5) > hoeffding_exponent(
        params.s_v, 0.5
    )


def test_forgery_bound_conditional_form_matches_the_hand_expression() -> None:
    """``matched=m`` returns exactly ``exp(-m * exponent)``."""
    params = ProtocolParams(key_length=115200)
    matched = 38400
    assert forgery_bound(params, matched=matched, method="kl") == pytest.approx(
        math.exp(-matched * binary_kl_divergence(params.s_v, 0.5)),
        rel=1e-12,
        abs=0,
    )


def test_averaged_bound_equals_the_binomial_average_of_the_conditional_bound() -> None:
    """``E[exp(-mc)] = (1 - p + p e^-c)^L`` -- the averaging step is an identity."""
    params = ProtocolParams(key_length=40)
    exponent = binary_kl_divergence(params.s_v, 0.5)
    pmf = matched_count_distribution(params)
    counts = np.arange(params.key_length + 1)
    direct = float((pmf * np.exp(-exponent * counts)).sum())
    assert forgery_bound(params, method="kl") == pytest.approx(direct, rel=1e-12, abs=0)


def test_forger_floor_is_the_recipient_forger_not_this_one() -> None:
    """The two forger rates are different objects and must not be conflated.

    Eve's rate *is* exactly ``1/2`` -- that is what "no information" means -- and
    the recipient's is ``1/12``, four times smaller than the ``1/3`` he would
    manage without the symmetrisation exchange. The three numbers are asserted
    together because the module docstring once claimed both were "below the 1/2
    of pure noise", which is false of Eve by definition.
    """
    assert FORGER_MATCHED_MISMATCH_PROBABILITY == 0.5
    assert DEFAULT_PARAMS.forger_floor == pytest.approx(1 / 12)
    assert DEFAULT_PARAMS.unmatched_noise_rate == pytest.approx(1 / 3)
    assert DEFAULT_PARAMS.forger_floor < FORGER_MATCHED_MISMATCH_PROBABILITY


# =========================================================================== #
# 3b. forgery by a recipient -- the binding case
# =========================================================================== #


def _simulate_recipient_forgery(
    trials: int,
    params: ProtocolParams,
    threshold: float,
    rng: np.random.Generator,
    *,
    symmetrised: bool,
) -> float:
    """Simulate Bob forging to Charlie, from the specification.

    Written from the protocol text, not from the closed form:

    * Alice draws ``(a_i, v_i)``; Bob and Charlie each draw their own basis and
      measure their own copy, deterministic on a match and a fair coin
      otherwise.
    * If ``symmetrised``, a fair coin per position swaps the two records, and
      Bob knows which positions were swapped because he supplied them.
    * Bob declares, per position, the entry he believes Charlie holds: the one
      he supplied where the pair was swapped, and his own record elsewhere.
    * Charlie scores it with the ordinary matched/mismatched rule.
    """
    n_bases = len(params.bases)
    shape = (trials, params.key_length)
    alice_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
    alice_bits = rng.integers(0, 2, size=shape, dtype=np.int8)

    bob_bases, bob_bits = _measure(alice_bases, alice_bits, n_bases, rng)
    charlie_bases, charlie_bits = _measure(
        alice_bases, alice_bits, n_bases, rng
    )

    if symmetrised:
        swap = rng.integers(0, 2, size=shape, dtype=np.int8).astype(bool)
        held_bases = np.where(swap, bob_bases, charlie_bases)
        held_bits = np.where(swap, bob_bits, charlie_bits)
    else:
        swap = np.zeros(shape, dtype=bool)
        held_bases, held_bits = charlie_bases, charlie_bits

    # Bob's optimal declaration: the truth where he knows it, his own record
    # elsewhere. Both are "his own record", which is why the compliant strategy
    # is the optimal one.
    declared_bases, declared_bits = bob_bases, bob_bits

    matched, mismatches = _score(
        declared_bases.astype(np.int8),
        declared_bits.astype(np.int8),
        held_bases.astype(np.int8),
        held_bits.astype(np.int8),
    )
    return float(_accepts(matched, mismatches, threshold).mean())


def test_recipient_forger_sits_at_the_documented_scored_fraction_and_rate() -> None:
    """MC: ``p_s = 2/3`` scored, ``rho = 1/12`` mismatched among them.

    The two numbers ``s_v`` is set below, measured from a simulator that knows
    only the protocol text. ``p_s`` is the fraction of positions the forger gets
    scored -- half supplied by him, plus ``1/|B|`` of the rest -- and ``rho`` is
    the mismatch rate among those.
    """
    params = ProtocolParams(key_length=200)
    trials = 4_000
    rng = _rng(30)
    n_bases = len(params.bases)
    shape = (trials, params.key_length)
    alice_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
    alice_bits = rng.integers(0, 2, size=shape, dtype=np.int8)
    bob_bases, bob_bits = _measure(alice_bases, alice_bits, n_bases, rng)
    charlie_bases, charlie_bits = _measure(
        alice_bases, alice_bits, n_bases, rng
    )
    swap = rng.integers(0, 2, size=shape, dtype=np.int8).astype(bool)
    held_bases = np.where(swap, bob_bases, charlie_bases)
    held_bits = np.where(swap, bob_bits, charlie_bits)

    scored = held_bases == bob_bases
    positions = int(scored.sum())
    mismatched = int((scored & (held_bits != bob_bits)).sum())

    _assert_close_to_proportion(
        positions / scored.size,
        params.forger_scored_fraction,
        scored.size,
        label="recipient forger scored fraction",
    )
    _assert_close_to_proportion(
        mismatched / positions,
        params.forger_floor,
        positions,
        label="recipient forger mismatch rate",
    )


@pytest.mark.parametrize("key_length", [12, 30, 90])
def test_recipient_forgery_probability_matches_simulation(
    key_length: int,
) -> None:
    """MC: the closed form for the *binding* forgery case, three key lengths."""
    params = ProtocolParams(key_length=key_length)
    trials = 100_000
    expected = recipient_forgery_probability(params)
    observed = _simulate_recipient_forgery(
        trials, params, params.s_v, _rng(31 + key_length), symmetrised=True
    )
    _assert_close_to_proportion(
        observed,
        expected,
        trials,
        label=f"P_recipient_forge(L={key_length})",
    )


def test_recipient_forgery_without_the_exchange_matches_simulation() -> None:
    """MC: the same forger against the variant with no symmetrisation.

    He is scored on ``1/|B|`` of positions at rate ``(1 - 1/|B|)/2 = 1/3``
    there, so his acceptance probability is *lower* than in the symmetrised
    protocol -- the exchange is what hands him half the target's log, and that
    is the cost the key length pays for non-repudiation.
    """
    params = ProtocolParams(key_length=60)
    trials = 100_000
    expected = recipient_forgery_probability(params, symmetrised=False)
    observed = _simulate_recipient_forgery(
        trials, params, params.s_v, _rng(41), symmetrised=False
    )
    _assert_close_to_proportion(
        observed, expected, trials, label="P_recipient_forge, no exchange"
    )
    assert expected < recipient_forgery_probability(params)


def test_the_recipient_forger_dominates_the_outside_one() -> None:
    """The binding case is the bigger number, at every length that resolves it.

    This is what makes quoting :func:`forgery_probability` alone misleading: at
    the shipped parameters the two differ by thousands of orders of magnitude,
    and only the recipient's number constrains ``s_v``.
    """
    for key_length in (30, 90, 300, 900):
        params = ProtocolParams(key_length=key_length)
        assert recipient_forgery_probability(params) > forgery_probability(
            params
        )
    assert recipient_forgery_bound(
        DEFAULT_PARAMS, method="kl"
    ) > forgery_bound(DEFAULT_PARAMS, method="kl")


@pytest.mark.parametrize("key_length", [6, 15, 30, 60])
@pytest.mark.parametrize("method", ["hoeffding", "kl"])
def test_recipient_forgery_bound_dominates_the_exact_probability(
    key_length: int, method: str
) -> None:
    """The bound is a bound, at every length and with either inequality."""
    params = ProtocolParams(key_length=key_length)
    assert recipient_forgery_probability(params) <= recipient_forgery_bound(
        params, method=method
    )


def test_recipient_forgery_bound_is_trivial_at_or_above_the_floor() -> None:
    """``s_v >= rho`` leaves no decay to bound, and the honest answer is ``1``."""
    forgeable = ProtocolParams(
        key_length=600, s_a=0.02, s_v=0.2, allow_forgeable=True
    )
    assert recipient_forgery_bound(forgeable) == 1.0
    assert recipient_forgery_bound(ProtocolParams(key_length=600)) < 1.0


# =========================================================================== #
# 4. repudiation
#
# Two statements, tested separately and never conflated:
#
#   4a. `repudiation_probability` and `symmetric_repudiation_bound` describe the
#       single-common-q family, in which Alice induces the same mismatch
#       probability on both recipients' copies. The simulator below implements
#       exactly that family, so the cross-check is a check of the arithmetic --
#       and only of the arithmetic. It cannot, by construction, detect that the
#       family is too narrow, which is why it is labelled as a model check.
#   4b. `repudiation_bound` is the guarantee. It conditions on the records, on
#       the declaration, and on the observed matched-record count, and uses only
#       the recipients' private exchange coins, so it must dominate the in-model
#       probability *and* the out-of-model asymmetric attack that the family
#       cannot express. Both are asserted.
#   4b-ii. `averaged_repudiation_bound` is that bound averaged over
#       M ~ Bin(2L, 1/n), which is a *different claim*: it holds only while the
#       declaration is independent of the recipients' logged bases. A signer who
#       reads both raw logs violates it by nine orders of magnitude, and the
#       simulation below is that adversary. The test exists so that the averaged
#       figure can never again be presented as unconditional.
# =========================================================================== #


def _simulate_repudiation(
    trials: int,
    params: ProtocolParams,
    mismatch_probability: float,
    rng: np.random.Generator,
) -> float:
    """Simulate Alice's repudiation attempt from the specification.

    Alice declares ``(d_i, w_i)`` and sends both recipients a state tilted off
    the declared axis, so a recipient who measures in the declared basis records
    the wrong sign with probability ``q`` -- independently for Bob and Charlie,
    because they hold separately prepared copies -- and a recipient who measures
    a conjugate observable still sees a fair coin. Repudiation is the event that
    Bob accepts at ``s_a`` while Charlie does not accept at ``s_v``.
    """
    n_bases = len(params.bases)
    shape = (trials, params.key_length)
    declared_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
    declared_bits = rng.integers(0, 2, size=shape, dtype=np.int8)

    verdicts = []
    for threshold in (params.s_a, params.s_v):
        recipient_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
        coin = rng.integers(0, 2, size=shape, dtype=np.int8)
        tilted = np.where(
            rng.random(shape) < mismatch_probability,
            1 - declared_bits,
            declared_bits,
        ).astype(np.int8)
        outcomes = np.where(recipient_bases == declared_bases, tilted, coin)
        matched, mismatches = _score(
            declared_bases, declared_bits, recipient_bases, outcomes.astype(np.int8)
        )
        verdicts.append(_accepts(matched, mismatches, threshold))
    return float((verdicts[0] & ~verdicts[1]).mean())


@pytest.mark.parametrize("mismatch_probability", [0.05, 0.12, 0.25])
def test_repudiation_probability_matches_simulation(
    mismatch_probability: float,
) -> None:
    """MC: ``P_rep(q) = P(r_B <= s_a) P(r_C > s_v)``, at three values of ``q``.

    A check of the closed form *within* the symmetric family, not of the
    family's adequacy: the simulator is built from the same model, so a shared
    modelling error would agree with itself. What covers Alice's real freedom is
    :func:`repudiation_bound`, tested against an asymmetric attack below.
    """
    params = ProtocolParams(key_length=24, s_a=1 / 64, s_v=1 / 16)
    trials = 200_000
    expected = repudiation_probability(
        params, mismatch_probability=mismatch_probability
    )
    observed = _simulate_repudiation(
        trials, params, mismatch_probability, _rng(12)
    )
    _assert_close_to_proportion(
        observed, expected, trials, label=f"P_rep(q={mismatch_probability})"
    )


def test_repudiation_at_zero_mismatch_is_the_empty_matched_set_event() -> None:
    """``q = 0`` leaves exactly ``P(m_B >= 1) P(m_C = 0)`` -- and nothing else."""
    params = ProtocolParams(key_length=24)
    empty = matched_statistics(params).empty_probability
    assert repudiation_probability(params, mismatch_probability=0.0) == (
        pytest.approx((1.0 - empty) * empty)
    )


def test_repudiation_probability_matches_simulation_at_zero_mismatch() -> None:
    """MC: even the ``q = 0`` residue is the number the closed form predicts."""
    params = ProtocolParams(key_length=6)
    trials = 200_000
    expected = repudiation_probability(params, mismatch_probability=0.0)
    observed = _simulate_repudiation(trials, params, 0.0, _rng(13))
    _assert_close_to_proportion(
        observed, expected, trials, label="P_rep(q=0)"
    )


def test_repudiation_probability_is_maximised_inside_the_threshold_gap() -> None:
    """Alice's best ``q`` sits between ``s_a`` and ``s_v``, as the split argues."""
    params = ProtocolParams(key_length=180, s_a=1 / 64, s_v=1 / 16)
    grid = np.linspace(0.0, 0.5, 101)
    values = [
        repudiation_probability(params, mismatch_probability=float(q))
        for q in grid
    ]
    best = float(grid[int(np.argmax(values))])
    assert params.s_a < best < params.s_v


@pytest.mark.parametrize("method", ["hoeffding", "kl"])
def test_symmetric_repudiation_bound_dominates_every_q(method: str) -> None:
    """Uniform in ``q``: it holds at all 101 grid points at once.

    Uniform in ``q`` is *not* uniform over Alice's strategies, and the name says
    so. The next test is the one that covers her actual freedom.
    """
    params = ProtocolParams(key_length=180, s_a=1 / 64, s_v=1 / 16)
    bound = symmetric_repudiation_bound(params, method=method)
    for q in np.linspace(0.0, 1.0, 101):
        assert (
            repudiation_probability(params, mismatch_probability=float(q))
            <= bound
        )


def test_the_guarantee_dominates_an_attack_the_model_cannot_express() -> None:
    """The point of 4b: an asymmetric Alice, simulated, stays under the bound.

    The in-model family cannot represent ``q_B != q_C``, so no amount of
    scanning ``q`` bounds this adversary. Here she is simulated directly: on a
    fraction ``f`` of positions she sends Bob the eigenstate she declares and
    Charlie its orthogonal partner, then the recipients' exchange coins decide
    who scores which. Measured over 20000 trials at four values of ``f``, and in
    every case both the realised repudiation frequency and its five-sigma upper
    confidence limit sit below ``repudiation_bound``.

    The same attack against *unsymmetrised* records succeeds with probability 1,
    which is asserted too -- it is the reason the guarantee needs the exchange
    and the reason the older bound was wrong rather than merely loose.

    The bound compared against here is the *averaged* one, and that is legitimate
    for this adversary and only for this adversary: she draws her declaration
    before either recipient's basis is drawn, so assumption (IND) holds by
    construction of the simulation and ``M ~ Bin(2L, 1/n)`` really is the law of
    the matched count. An Alice who reads the logs is the next test.
    """
    params = ProtocolParams(key_length=90, s_a=1 / 64, s_v=1 / 16)
    trials = 20_000
    bound = averaged_repudiation_bound(params, signer_sees_recipient_bases=False)
    rng = _rng(20)
    n_bases = len(params.bases)
    shape = (trials, params.key_length)

    for fraction in (0.15, 0.35, 0.70, 1.00):
        declared_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
        declared_bits = rng.integers(0, 2, size=shape, dtype=np.int8)
        attacked = rng.random(shape) < fraction

        # The two copies as prepared: Bob's honest, Charlie's flipped where
        # attacked. Each recipient draws its own basis and measures.
        good_bits = declared_bits
        bad_bits = np.where(attacked, 1 - declared_bits, declared_bits)

        first_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
        second_bases = rng.integers(0, n_bases, size=shape, dtype=np.int8)
        first_coin = rng.integers(0, 2, size=shape, dtype=np.int8)
        second_coin = rng.integers(0, 2, size=shape, dtype=np.int8)
        first_bits = np.where(
            first_bases == declared_bases, good_bits, first_coin
        )
        second_bits = np.where(
            second_bases == declared_bases, bad_bits, second_coin
        )

        # Unsymmetrised: Bob holds the good copy, Charlie the bad one.
        raw = []
        for bases, bits, threshold in (
            (first_bases, first_bits, params.s_a),
            (second_bases, second_bits, params.s_v),
        ):
            matched, mismatches = _score(
                declared_bases, declared_bits, bases, bits.astype(np.int8)
            )
            raw.append(_accepts(matched, mismatches, threshold))
        unmitigated = float((raw[0] & ~raw[1]).mean())
        # At f = 0.15 Charlie's rate is 0.15 against s_v = 0.0625 on only ~30
        # matched positions, so his rejection is overwhelming rather than
        # certain; from f = 0.35 up it is certain to four decimals.
        assert unmitigated > (0.9 if fraction < 0.35 else 0.999)

        # Symmetrised: one fair coin per position decides who scores which.
        swap = rng.integers(0, 2, size=shape, dtype=np.int8).astype(bool)
        bob_bases = np.where(swap, second_bases, first_bases)
        bob_bits = np.where(swap, second_bits, first_bits)
        charlie_bases = np.where(swap, first_bases, second_bases)
        charlie_bits = np.where(swap, first_bits, second_bits)

        verdicts = []
        for bases, bits, threshold in (
            (bob_bases, bob_bits, params.s_a),
            (charlie_bases, charlie_bits, params.s_v),
        ):
            matched, mismatches = _score(
                declared_bases,
                declared_bits,
                bases.astype(np.int8),
                bits.astype(np.int8),
            )
            verdicts.append(_accepts(matched, mismatches, threshold))
        observed = float((verdicts[0] & ~verdicts[1]).mean())

        # Five-sigma upper confidence limit on a proportion of 20000 trials:
        # 0 successes still admits ~1.4e-4, so the bound has to clear that, and
        # at L = 90 it does (0.87) with room to spare.
        upper = observed + _SIGMAS * math.sqrt(
            max(observed * (1.0 - observed), 1.0 / trials) / trials
        )
        assert upper <= bound, (
            f"f={fraction}: symmetrised repudiation frequency {observed} "
            f"(5-sigma UCL {upper}) exceeds the bound {bound}"
        )


def test_repudiation_bound_reproduces_the_documented_default_figure() -> None:
    """``6.9e-10`` is the *averaged* figure, and it is labelled as such.

    Recomputed here from the expression rather than read off, so the params
    docstring and the implementation are two statements that have to agree. Note
    ``matched_records`` counts matched records across *both* verifiers, which is
    ``2L/|B|``, not the per-verifier ``L/|B|``, and that the per-run bound
    carries no ``(1 - 1/|B|)**L`` term: that corner is inside the Hoeffding
    event, and the term is retained only in the averaged expression because it is
    the one published in ``params`` and ``docs/PHASE2.md``.
    """
    conditional = repudiation_bound(DEFAULT_PARAMS, matched_records=76800)
    assert conditional == pytest.approx(
        math.exp(-76800 * DEFAULT_PARAMS.gap**2 / 8.0),
        rel=1e-12,
        abs=0,
    )
    averaged = averaged_repudiation_bound(
        DEFAULT_PARAMS, signer_sees_recipient_bases=False
    )
    assert averaged == pytest.approx(6.9e-10, rel=0.02, abs=0)
    assert averaged < 1e-9
    # The published figure and the per-run guarantee at the expected M agree to
    # the width of the legacy slack term, which underflows to zero here.
    assert averaged == pytest.approx(conditional, rel=0.01, abs=0)


def test_repudiation_bound_pins_the_audited_adversarial_case() -> None:
    """``M = 13`` gives ``0.9964``, and that is the honest number for that run.

    The audited attack (see the simulation below) pins the total matched-record
    count at 13 and repudiates at roughly one half. The per-run bound at that
    count is ``0.9964``: not violated, not reassuring, and correct. Pinned to
    four decimals so that no future edit can quietly reintroduce an averaged
    number in its place -- an averaged number at these parameters is ``6.9e-10``,
    which the same run beats by nine orders of magnitude.
    """
    assert repudiation_bound(DEFAULT_PARAMS, matched_records=13) == (
        pytest.approx(0.9964, abs=5e-5)
    )
    # It dominates every repudiation frequency the audit or this file measured.
    assert repudiation_bound(DEFAULT_PARAMS, matched_records=13) > 0.58
    # And it is a bound, not a constant: more evidence, more guarantee.
    assert repudiation_bound(DEFAULT_PARAMS, matched_records=76800) < 1e-9


def _simulate_log_reading_repudiation(
    trials: int,
    params: ProtocolParams,
    rng: np.random.Generator,
    *,
    singles: int = 11,
) -> tuple[np.ndarray, np.ndarray]:
    """Alice reads both raw logs and declares against them. Returns ``(M, rep)``.

    Written from the specification, like every other simulator in this file, and
    using no quantum resource at all -- the attack is entirely classical.

    Phase A is honest: Alice draws ``(a_i, v_i)``, each recipient draws its own
    basis and measures. Phase B is not. Alice reads both raw logs and declares,
    at every position, a basis that appears in *neither* of them, which exists
    for ``|B| = 3`` whatever the two logs say. That position is then matched at
    neither verifier however the exchange coin falls. She keeps twelve
    exceptions:

    * one position where the two logs used the **same** basis and recorded
      **opposite** outcomes: she declares that basis and Bob's outcome, so both
      raw records are matched and exactly one of them is wrong;
    * ``singles`` positions where the logs used **different** bases: she declares
      Bob's basis and Bob's outcome, so exactly one raw record is matched there
      and it is correct.

    Hence ``M = singles + 2 = 13`` with probability 1 at every ``L``, and the
    single wrong record is handed to Bob or to Charlie by one fair coin: if it
    goes to Charlie he holds one mismatch in at most twelve matched records
    (``r_C >= 1/12 > s_v``, rejects) while Bob holds only clean ones
    (``r_B = 0 <= s_a``, accepts). So repudiation has probability exactly ``1/2``,
    it does not depend on ``L``, and -- worth noting, because it is what makes
    this attack independent of the empty-matched-set question -- Charlie always
    holds evidence, so his rejection is on a rate rather than on a missing set.
    """
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    bob_bases, bob_bits = _measure(alice_bases, alice_bits, n_bases, rng)
    charlie_bases, charlie_bits = _measure(
        alice_bases, alice_bits, n_bases, rng
    )

    # The basis in neither log: the third one when they differ, a neighbour when
    # they agree. Both are still inside B, so nothing here needs a symbol the
    # verifier would refuse.
    assert n_bases == 3, "the construction needs a third basis to hide in"
    declared_bases = np.where(
        bob_bases == charlie_bases,
        (bob_bases + 1) % n_bases,
        3 - bob_bases - charlie_bases,
    ).astype(np.int8)
    declared_bits = np.zeros_like(declared_bases)

    for trial in range(trials):
        both = np.flatnonzero(
            (bob_bases[trial] == charlie_bases[trial])
            & (bob_bits[trial] != charlie_bits[trial])
        )
        one = np.flatnonzero(bob_bases[trial] != charlie_bases[trial])
        assert both.size >= 1 and one.size >= singles, "L too short for the attack"
        chosen = np.concatenate(([both[0]], one[:singles]))
        declared_bases[trial, chosen] = bob_bases[trial, chosen]
        declared_bits[trial, chosen] = bob_bits[trial, chosen]

    swap = rng.integers(
        0, 2, size=declared_bases.shape, dtype=np.int8
    ).astype(bool)
    verdicts = []
    counts = []
    for own, other, threshold in (
        ((bob_bases, bob_bits), (charlie_bases, charlie_bits), params.s_a),
        ((charlie_bases, charlie_bits), (bob_bases, bob_bits), params.s_v),
    ):
        held_bases = np.where(swap, other[0], own[0]).astype(np.int8)
        held_bits = np.where(swap, other[1], own[1]).astype(np.int8)
        matched, mismatches = _score(
            declared_bases, declared_bits, held_bases, held_bits
        )
        counts.append(matched)
        verdicts.append(_accepts(matched, mismatches, threshold))
    return counts[0] + counts[1], verdicts[0] & ~verdicts[1]


@pytest.mark.parametrize("key_length", [600, 115200])
def test_a_log_reading_signer_breaks_the_averaged_bound(key_length: int) -> None:
    """The CRITICAL finding, kept as a test: ``6.9e-10`` is not unconditional.

    ``QDSSession`` hands the ``Signer`` seam both recipients' **raw** logs. A
    signer who reads them chooses the matched set, because the matched set is
    ``{i : c_i == d_i}``, and the averaging over ``M ~ Bin(2L, 1/n)`` that turns
    the per-run bound into the quotable ``6.9e-10`` is exactly the assumption
    that she does not. Measured here at two key lengths three orders of magnitude
    apart, to show the failure is structural rather than a small-``L`` artefact:

    * ``M = 13`` in every trial, at both key lengths;
    * a repudiation frequency near ``1/2``, at both key lengths;
    * which is *above* the averaged bound at ``L = 115200`` by nine orders of
      magnitude, and below the per-run bound ``repudiation_bound(..., 13)``.

    The per-run guarantee is never violated, at any key length, by any strategy.
    That is the whole distinction this test exists to keep alive.
    """
    params = ProtocolParams(key_length=key_length, s_a=1 / 64, s_v=1 / 16)
    trials = 400 if key_length <= 1000 else 64
    counts, repudiated = _simulate_log_reading_repudiation(
        trials, params, _rng(21 + key_length % 7)
    )
    observed = float(repudiated.mean())
    standard_error = math.sqrt(max(observed * (1.0 - observed), 1.0 / trials) / trials)

    assert np.unique(counts).tolist() == [13], (
        f"the attack is supposed to pin M at 13, got {np.unique(counts)}"
    )
    # Exactly one fair coin decides the run, so 1/2 up to five standard errors.
    _assert_close_to_proportion(
        observed, 0.5, trials, label=f"log-reading repudiation, L={key_length}"
    )
    # The per-run guarantee holds, as it must, for this and every strategy.
    per_run = repudiation_bound(params, matched_records=13)
    assert observed + _SIGMAS * standard_error <= per_run

    averaged = averaged_repudiation_bound(
        params, signer_sees_recipient_bases=False
    )
    if key_length >= 115200:
        # The number this package used to publish as its non-repudiation
        # guarantee, beaten by nine orders of magnitude by a classical attack.
        assert averaged < 1e-9
        assert observed - _SIGMAS * standard_error > 1e6 * averaged


def test_averaged_repudiation_bound_refuses_the_adversary_that_breaks_it() -> None:
    """The averaged number cannot be obtained by accident, only by assertion.

    Two barriers, because the error being prevented is a documentation error
    that a reviewer would have to notice: the function is named for what it does,
    and the caller must state the fact about the deployment that makes it true.
    """
    with pytest.raises(TypeError):
        averaged_repudiation_bound(DEFAULT_PARAMS)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="no averaged repudiation bound"):
        averaged_repudiation_bound(
            DEFAULT_PARAMS, signer_sees_recipient_bases=True
        )
    with pytest.raises(TypeError, match="must be a bool"):
        averaged_repudiation_bound(
            DEFAULT_PARAMS, signer_sees_recipient_bases="no"  # type: ignore[arg-type]
        )
    assert averaged_repudiation_bound(
        DEFAULT_PARAMS, signer_sees_recipient_bases=False
    ) < 1e-9


def test_repudiation_bound_demands_an_observed_count() -> None:
    """No default, and the ``None`` that used to mean "average" is a hard error.

    The old signature defaulted to the averaged number. Anything that still calls
    it that way now fails loudly, and the message names the three honest
    replacements rather than just the missing argument.
    """
    with pytest.raises(TypeError):
        repudiation_bound(DEFAULT_PARAMS)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="averaged_repudiation_bound"):
        repudiation_bound(DEFAULT_PARAMS, matched_records=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at least 1"):
        repudiation_bound(DEFAULT_PARAMS, matched_records=0)
    with pytest.raises(TypeError, match="boolean"):
        repudiation_bound(DEFAULT_PARAMS, matched_records=True)  # type: ignore[arg-type]


def test_the_abort_rule_is_the_only_honest_a_priori_guarantee() -> None:
    """4b-iii: an unconditional number exists, and it costs an abort rule.

    Refusing to verify on an anomalously small matched set floors ``M``, and the
    per-run bound at that floor holds for every Alice strategy with no
    independence assumption at all. The rule is nearly free because the honest
    matched count is concentrated: ten standard deviations of headroom costs
    ``5e-24`` and buys ``4e-5`` locally, ``1.3e-9`` pooled -- the latter within a
    factor of two of the figure that used to be published as unconditional.

    None of this is implemented in ``verify``; the numbers say what such a rule
    would be worth, which is the honest way to report a fix that has not landed.
    """
    local = repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=36800
    )
    pooled = repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=74540
    )
    assert local == pytest.approx(
        math.exp(-36800 * DEFAULT_PARAMS.gap**2 / 8.0)
    )
    assert 1e-5 < local < 1e-4
    assert 1e-9 < pooled < 1e-8
    assert matched_shortfall_probability(
        DEFAULT_PARAMS, minimum_matched=36800
    ) < 1e-20
    assert matched_shortfall_probability(
        DEFAULT_PARAMS, minimum_matched=74540, pooled=True
    ) < 1e-20
    # More evidence demanded, more guarantee bought, and never above 1.
    assert repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=1
    ) <= 1.0
    assert pooled < local


def test_a_per_verifier_floor_leaves_a_count_split_route() -> None:
    """The limitation of 4b-iii, pinned as arithmetic so it cannot be dropped.

    ``repudiation_bound_with_abort`` bounds "Bob accepts and Charlie *rejects*",
    plus the empty-set corner. A floor applied at Charlie as well adds a third
    outcome -- a non-empty matched set below his floor, on which he returns no
    verdict -- and if that is counted as a repudiation success then no exponent
    covers it, because nothing about a *rate* deviates.

    The attack is exact rather than statistical. A signer who reads both logs
    pins ``M = 2 m_min`` clean matched records; then Bob accepts exactly when
    ``m_C <= m_min`` and Charlie is below his floor exactly when
    ``m_C < m_min``, and ``m_C ~ Bin(2 m_min, 1/2)`` by the exchange coins. So
    the route succeeds with probability ``(1 - P(m_C = m_min)) / 2``, just under
    one half, at any floor and any key length.

    The floor used here is the one ``verify.minimum_matched_count`` returns at
    ``DEFAULT_PARAMS`` as this is written; the test is deliberately self-contained
    arithmetic, so it keeps its meaning if that constant moves.
    """
    floor = 36555
    log_central = (
        math.lgamma(2 * floor + 1)
        - 2 * math.lgamma(floor + 1)
        - 2 * floor * math.log(2.0)
    )
    split_route = 0.5 * (1.0 - math.exp(log_central))
    assert 0.49 < split_route < 0.5

    covered = repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=floor
    )
    assert covered < 1e-4
    # The bound is not a bound on the route it does not cover, by four orders of
    # magnitude. Nothing here is violated: they are different events.
    assert split_route > 1e3 * covered

    # Pooling the counts closes it: Charlie below his floor then needs a genuine
    # deviation of the split, which Hoeffding bounds at the worst-case M.
    pooled_floor = 75000
    deviation = pooled_floor / 2 - floor
    assert math.exp(-2 * deviation**2 / pooled_floor) < 1e-10
    assert repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=pooled_floor
    ) < 1e-8
    assert matched_shortfall_probability(
        DEFAULT_PARAMS, minimum_matched=pooled_floor, pooled=True
    ) < 1e-12


def test_matched_shortfall_probability_is_the_binomial_lower_tail() -> None:
    """Cross-checked against the pmf it must agree with, and against ``m = 0``."""
    params = ProtocolParams(key_length=30)
    pmf = matched_count_distribution(params)
    for floor in (1, 2, 5, 11):
        assert matched_shortfall_probability(
            params, minimum_matched=floor
        ) == pytest.approx(float(pmf[:floor].sum()))
    assert matched_shortfall_probability(params, minimum_matched=1) == (
        pytest.approx(matched_statistics(params).empty_probability)
    )
    # Pooled reads Bin(2L, 1/|B|): twice the trials, so a far smaller lower tail.
    assert matched_shortfall_probability(
        params, minimum_matched=8, pooled=True
    ) < matched_shortfall_probability(params, minimum_matched=8)
    # A threshold no run can reach is certain shortfall.
    assert matched_shortfall_probability(
        params, minimum_matched=params.key_length + 1
    ) == 1.0
    with pytest.raises(TypeError, match="pooled must be a bool"):
        matched_shortfall_probability(
            params, minimum_matched=4, pooled=1  # type: ignore[arg-type]
        )


def test_the_guarantee_is_weaker_than_the_in_model_bound() -> None:
    """The price of covering every strategy, stated as a number.

    The in-model exponent ``min_q [D(s_a||q) + D(s_v||q)]`` per matched position
    is far larger than the guarantee's ``gap**2 / 8`` per matched record, so the
    guarantee is the bigger probability. Anyone quoting the smaller one is
    quoting a bound on a model, and the two are kept apart by name for exactly
    that reason. Compared at the same evidence: 38400 matched positions each,
    hence 76800 matched records between them.
    """
    assert symmetric_repudiation_bound(
        DEFAULT_PARAMS, matched=38400
    ) < repudiation_bound(DEFAULT_PARAMS, matched_records=76800)
    assert symmetric_repudiation_bound(DEFAULT_PARAMS) < (
        averaged_repudiation_bound(
            DEFAULT_PARAMS, signer_sees_recipient_bases=False
        )
    )
    assert symmetric_repudiation_bound(
        DEFAULT_PARAMS, method="kl"
    ) < symmetric_repudiation_bound(DEFAULT_PARAMS, method="hoeffding")


def test_repudiation_bound_shrinks_with_a_wider_gap() -> None:
    """A wider ``s_v - s_a`` buys a smaller bound at the same evidence."""
    narrow = ProtocolParams(key_length=600, s_a=0.06, s_v=0.07)
    wide = ProtocolParams(key_length=600, s_a=0.001, s_v=0.08)
    assert wide.gap > narrow.gap
    assert repudiation_bound(wide, matched_records=400) < repudiation_bound(
        narrow, matched_records=400
    )
    assert averaged_repudiation_bound(
        wide, signer_sees_recipient_bases=False
    ) < averaged_repudiation_bound(
        narrow, signer_sees_recipient_bases=False
    )
    assert symmetric_repudiation_bound(wide) < symmetric_repudiation_bound(
        narrow
    )


# =========================================================================== #
# 5. robustness
# =========================================================================== #


def _simulate_honest_abort(
    trials: int,
    params: ProtocolParams,
    error_rate: float,
    threshold: float,
    rng: np.random.Generator,
) -> float:
    """Simulated probability that an honest run fails to be accepted."""
    matched, mismatches = _simulate_matched_and_mismatches(
        trials, params, rng, error_rate=error_rate
    )
    return float((~_accepts(matched, mismatches, threshold)).mean())


@pytest.mark.parametrize("error_rate", [0.0, 0.02, 0.08])
def test_honest_abort_probability_matches_simulation(error_rate: float) -> None:
    """MC: the robustness formula at three channel error rates, Charlie's cut."""
    params = ProtocolParams(key_length=24, s_a=1 / 64, s_v=1 / 16)
    trials = 200_000
    expected = honest_abort_probability(
        params, error_rate=error_rate, party=Party.CHARLIE
    )
    observed = _simulate_honest_abort(
        trials, params, error_rate, params.s_v, _rng(14)
    )
    _assert_close_to_proportion(
        observed, expected, trials, label=f"P_abort(p_e={error_rate})"
    )


def test_honest_abort_probability_matches_simulation_for_bob() -> None:
    """MC: Bob's tighter cut aborts more often on the same channel."""
    params = ProtocolParams(key_length=24, s_a=1 / 64, s_v=1 / 16)
    trials = 200_000
    expected = honest_abort_probability(
        params, error_rate=0.05, party=Party.BOB
    )
    observed = _simulate_honest_abort(
        trials, params, 0.05, params.s_a, _rng(15)
    )
    _assert_close_to_proportion(observed, expected, trials, label="P_abort(Bob)")
    assert expected > honest_abort_probability(
        params, error_rate=0.05, party=Party.CHARLIE
    )


def test_noiseless_honest_abort_is_exactly_the_empty_matched_probability() -> None:
    """With ``p_e = 0`` the only way to fail is to hold no evidence at all."""
    params = ProtocolParams(key_length=15)
    empty = matched_statistics(params).empty_probability
    for party in (Party.BOB, Party.CHARLIE):
        assert honest_abort_probability(params, party=party) == pytest.approx(
            empty
        )


def test_combined_honest_abort_uses_exact_inclusion_exclusion() -> None:
    """``party=None`` is ``P_B + P_C - P_B P_C``, not the union bound."""
    params = ProtocolParams(key_length=48, s_a=1 / 64, s_v=1 / 16)
    bob = honest_abort_probability(params, error_rate=0.03, party=Party.BOB)
    charlie = honest_abort_probability(
        params, error_rate=0.03, party=Party.CHARLIE
    )
    combined = honest_abort_probability(params, error_rate=0.03)
    assert combined == pytest.approx(bob + charlie - bob * charlie)
    assert combined < bob + charlie


def test_combined_honest_abort_matches_simulation() -> None:
    """MC: two independent recipients, "either aborts" over the same honest run."""
    params = ProtocolParams(key_length=24, s_a=1 / 64, s_v=1 / 16)
    trials = 200_000
    rng = _rng(16)
    error_rate = 0.04
    n_bases = len(params.bases)
    alice_bases, alice_bits = _draw_key(trials, params.key_length, n_bases, rng)
    aborts = []
    for threshold in (params.s_a, params.s_v):
        recipient_bases, outcomes = _measure(
            alice_bases, alice_bits, n_bases, rng, error_rate=error_rate
        )
        matched, mismatches = _score(
            alice_bases, alice_bits, recipient_bases, outcomes
        )
        aborts.append(~_accepts(matched, mismatches, threshold))
    observed = float((aborts[0] | aborts[1]).mean())
    expected = honest_abort_probability(params, error_rate=error_rate)
    _assert_close_to_proportion(
        observed, expected, trials, label="P(either verifier aborts)"
    )


@pytest.mark.parametrize("error_rate", [0.0, 0.005, 0.02])
@pytest.mark.parametrize("method", ["hoeffding", "kl"])
def test_honest_abort_bound_dominates_the_exact_probability(
    error_rate: float, method: str
) -> None:
    """The robustness bound is a bound, for both parties and both inequalities."""
    params = ProtocolParams(key_length=120, s_a=1 / 64, s_v=1 / 16)
    for party in (Party.BOB, Party.CHARLIE, None):
        exact = honest_abort_probability(
            params, error_rate=error_rate, party=party
        )
        bound = honest_abort_bound(
            params, error_rate=error_rate, party=party, method=method
        )
        assert exact <= bound, f"{party}: {exact} > {bound}"


def test_honest_abort_bound_is_trivial_when_noise_reaches_the_threshold() -> None:
    """At ``p_e >= s`` there is no decay left to bound and the answer is ``1``."""
    params = ProtocolParams(key_length=600, s_a=1 / 64, s_v=1 / 16)
    assert honest_abort_bound(params, error_rate=0.05, party=Party.BOB) == 1.0
    assert honest_abort_bound(params, error_rate=0.01, party=Party.BOB) < 1.0


def test_kl_robustness_bound_is_much_tighter_at_small_noise() -> None:
    """Where Hoeffding is worst: low noise, because it assumes variance 1/4."""
    params = ProtocolParams(key_length=600, s_a=1 / 64, s_v=1 / 16)
    hoeffding = honest_abort_bound(
        params, error_rate=0.001, party=Party.BOB, method="hoeffding"
    )
    kl = honest_abort_bound(
        params, error_rate=0.001, party=Party.BOB, method="kl"
    )
    assert kl < hoeffding
    assert kl < hoeffding / 100.0


def test_robustness_and_security_can_hold_simultaneously() -> None:
    """The headline claim: at the shipped parameters both failure modes are tiny.

    Robustness and unforgeability pull in opposite directions -- a scheme that
    accepts nothing is unforgeable, one that accepts everything is robust -- so
    the parameter set is only meaningful if both numbers are small at once.
    """
    error_rate = depolarising_error_rate(0.01)
    assert honest_abort_bound(DEFAULT_PARAMS, error_rate=error_rate, method="kl") < 1e-9
    assert forgery_bound(DEFAULT_PARAMS, method="kl") < 1e-100
    # The *binding* forgery case, not just the outside adversary.
    assert recipient_forgery_bound(DEFAULT_PARAMS, method="kl") < 1e-100
    # Repudiation is the one where the headline number carries a hypothesis, so
    # it is asserted twice: the averaged figure under (IND), and the a-priori
    # guarantee an abort rule would buy without it. Both are small; only the
    # second is unconditional, and only the second is unimplemented.
    assert averaged_repudiation_bound(
        DEFAULT_PARAMS, signer_sees_recipient_bases=False
    ) < 1e-9
    assert repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=74540
    ) < 1e-8


# =========================================================================== #
# the acceptance rule, the two exponents, and argument validation
# =========================================================================== #


@pytest.mark.parametrize("matched", list(range(1, 40)))
@pytest.mark.parametrize("threshold", [0.0, 1 / 32, 1 / 6, 0.25, 1 / 3, 0.499])
def test_max_accepted_mismatches_matches_the_float_acceptance_rule(
    matched: int, threshold: float
) -> None:
    """``t(m)`` is exactly the largest ``e`` with ``e / m <= threshold`` in floats.

    Brute-forced rather than derived, because the interesting cases are the
    boundaries where ``floor(threshold * m)`` and the actual division disagree.
    """
    limit = max_accepted_mismatches(matched, threshold)
    brute = max(e for e in range(matched + 1) if e / matched <= threshold)
    assert limit == brute


def test_max_accepted_mismatches_handles_the_exact_boundary() -> None:
    """``m = 6``, ``s = 1/6``: ``1/6 <= 1/6`` accepts, so ``t(6) = 1``."""
    assert max_accepted_mismatches(6, 1 / 6) == 1
    assert max_accepted_mismatches(3, 1 / 3) == 1
    assert max_accepted_mismatches(7, 0.0) == 0


def test_exact_rational_floor_would_disagree_with_the_acceptance_rule() -> None:
    """The trap the normalisation loops guard against, pinned rather than described.

    ``floor(Fraction(threshold) * m)`` looks like the exact, principled way to
    compute ``t(m)``. It is exact about the wrong thing: it floors the rational
    value of the float, while the verifier compares the float division
    ``e / m``. The two disagree at every multiple of 6 for ``threshold = 1/6``,
    each disagreement silently discarding one position of head-room from every
    honest run.
    """
    from fractions import Fraction

    threshold = 1 / 6
    disagreements = [
        m
        for m in range(1, 200)
        if int(Fraction(threshold) * m) != max_accepted_mismatches(m, threshold)
    ]
    assert disagreements[:4] == [6, 12, 18, 24]
    assert int(Fraction(threshold) * 6) == 0
    assert max_accepted_mismatches(6, threshold) == 1
    assert 1 / 6 <= threshold  # the comparison verify() actually performs


def test_binary_kl_divergence_basic_properties() -> None:
    """Non-negative, zero on the diagonal, infinite against a degenerate reference."""
    assert binary_kl_divergence(0.3, 0.3) == 0.0
    assert binary_kl_divergence(0.1, 0.9) > 0.0
    assert math.isinf(binary_kl_divergence(0.1, 0.0))
    assert math.isinf(binary_kl_divergence(0.1, 1.0))
    assert binary_kl_divergence(0.0, 0.0) == 0.0
    assert binary_kl_divergence(0.0, 0.25) == pytest.approx(-math.log(0.75))


def test_pinsker_inequality_holds_across_a_grid() -> None:
    """``D(a||b) >= 2(a-b)^2`` everywhere: the KL bound is never the weaker one."""
    for a in np.linspace(0.0, 1.0, 21):
        for b in np.linspace(0.01, 0.99, 21):
            assert binary_kl_divergence(float(a), float(b)) >= (
                hoeffding_exponent(float(a), float(b)) - 1e-12
            )


def test_kl_divergence_is_the_true_binomial_tail_exponent() -> None:
    """Sanity: ``exp(-m D(a||b))`` really does dominate the binomial tail."""
    matched, probability, rate = 200, 0.5, 1 / 6
    limit = max_accepted_mismatches(matched, rate)
    log_tail = math.log(
        sum(
            math.comb(matched, k) * probability**k * (1 - probability) ** (matched - k)
            for k in range(limit + 1)
        )
    )
    assert log_tail <= -matched * binary_kl_divergence(rate, probability)


def test_results_are_frozen_and_json_shaped() -> None:
    """The dataclasses are immutable and made only of plain numbers."""
    stats = matched_statistics(DEMO_PARAMS)
    assert isinstance(stats, MatchedStatistics)
    with pytest.raises((AttributeError, TypeError)):
        stats.expected = 1.0  # type: ignore[misc]
    honest = honest_statistics(DEMO_PARAMS, error_rate=0.01)
    assert isinstance(honest, HonestStatistics)
    with pytest.raises((AttributeError, TypeError)):
        honest.error_rate = 0.5  # type: ignore[misc]


def test_every_function_is_deterministic() -> None:
    """D3: nothing here consumes randomness, so repeated calls are bit-identical."""
    params = ProtocolParams(key_length=45)
    assert forgery_probability(params) == forgery_probability(params)
    assert repudiation_probability(
        params, mismatch_probability=0.1
    ) == repudiation_probability(params, mismatch_probability=0.1)
    assert honest_abort_probability(
        params, error_rate=0.01
    ) == honest_abort_probability(params, error_rate=0.01)


@pytest.mark.parametrize(
    "function",
    [
        matched_statistics,
        matched_count_distribution,
        forgery_probability,
        forgery_bound,
        partial(repudiation_bound, matched_records=10),
        partial(averaged_repudiation_bound, signer_sees_recipient_bases=False),
        partial(repudiation_bound_with_abort, minimum_matched_records=10),
        partial(matched_shortfall_probability, minimum_matched=10),
        honest_abort_probability,
        honest_abort_bound,
        honest_statistics,
    ],
)
def test_params_must_be_a_protocol_params(function) -> None:
    """A duck-typed parameter set would skip the ``s_a < s_v < 1/2`` validation."""
    with pytest.raises(TypeError, match="must be a ProtocolParams"):
        function({"key_length": 30, "s_a": 0.1, "s_v": 0.2})


def test_alice_has_no_acceptance_probability() -> None:
    """She signs; she reaches no verdict, so no acceptance or abort is defined."""
    params = ProtocolParams(key_length=30)
    with pytest.raises(ValueError, match="not a verifier"):
        forgery_probability(params, party=Party.ALICE)
    with pytest.raises(ValueError, match="not a verifier"):
        honest_abort_probability(params, party="alice")


def test_unknown_party_is_rejected() -> None:
    """A misspelled party is a wiring bug, not a silent default."""
    with pytest.raises(ValueError, match="unknown party"):
        forgery_probability(ProtocolParams(key_length=30), party="Dave")


@pytest.mark.parametrize("bad", [-0.1, 1.5, float("nan"), float("inf")])
def test_error_rate_must_be_a_probability(bad: float) -> None:
    """Rates outside ``[0, 1]`` are refused with a message that says why."""
    params = ProtocolParams(key_length=30)
    with pytest.raises(ValueError):
        honest_abort_probability(params, error_rate=bad)
    with pytest.raises(ValueError):
        repudiation_probability(params, mismatch_probability=bad)


def test_boolean_probabilities_are_rejected() -> None:
    """``True`` is an int in Python and would silently read as ``p = 1``."""
    params = ProtocolParams(key_length=30)
    with pytest.raises(TypeError, match="boolean"):
        honest_abort_probability(params, error_rate=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="boolean"):
        depolarising_error_rate(True)  # type: ignore[arg-type]


def test_unknown_bound_method_is_rejected() -> None:
    """The message names both inequalities rather than just failing."""
    with pytest.raises(ValueError, match="hoeffding"):
        forgery_bound(ProtocolParams(key_length=30), method="chernoff")


@pytest.mark.parametrize("bad", [0, -3])
def test_matched_must_be_positive(bad: int) -> None:
    """Conditioning on an empty matched set states a bound on a decision never taken."""
    with pytest.raises(ValueError, match="at least 1"):
        forgery_bound(ProtocolParams(key_length=30), matched=bad)


def test_matched_must_not_be_a_boolean() -> None:
    """``matched=True`` would silently condition on a single matched position."""
    with pytest.raises(TypeError, match="boolean"):
        forgery_bound(ProtocolParams(key_length=30), matched=True)  # type: ignore[arg-type]


def test_probabilities_stay_in_the_unit_interval() -> None:
    """Every returned probability and bound is a probability."""
    params = ProtocolParams(
        key_length=9, s_a=0.1, s_v=0.45, allow_forgeable=True
    )
    values = [
        forgery_probability(params),
        forgery_bound(params),
        forgery_bound(params, method="kl"),
        recipient_forgery_probability(params),
        recipient_forgery_bound(params),
        repudiation_probability(params, mismatch_probability=0.3),
        repudiation_bound(params, matched_records=3),
        repudiation_bound(params, matched_records=1),
        averaged_repudiation_bound(params, signer_sees_recipient_bases=False),
        repudiation_bound_with_abort(params, minimum_matched_records=2),
        matched_shortfall_probability(params, minimum_matched=2),
        matched_shortfall_probability(params, minimum_matched=2, pooled=True),
        symmetric_repudiation_bound(params),
        symmetric_repudiation_bound(params, method="kl"),
        honest_abort_probability(params, error_rate=0.05),
        honest_abort_bound(params, error_rate=0.05),
        matched_statistics(params).empty_probability,
    ]
    for value in values:
        assert 0.0 <= value <= 1.0


def test_two_basis_alphabet_is_handled_throughout() -> None:
    """Nothing is hard-coded to ``1/3``: a BB84-style alphabet works too."""
    params = ProtocolParams(
        key_length=24,
        bases=(PauliBasis.X, PauliBasis.Z),
        s_a=1 / 64,
        s_v=1 / 16,
    )
    assert matched_statistics(params).match_probability == pytest.approx(0.5)
    assert matched_statistics(params).expected == pytest.approx(12.0)
    trials = 200_000
    expected = forgery_probability(params)
    observed = _simulate_forgery("uniform", trials, params, params.s_v, _rng(17))
    _assert_close_to_proportion(
        observed, expected, trials, label="P_forge, two-basis alphabet"
    )
