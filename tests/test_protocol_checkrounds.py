"""Tests for :mod:`sih141.protocol.checkrounds` -- sampled parameter estimation.

Five things are pinned here, in order of how badly they fail *silently*.

1. **The effective key length propagates.** A check fraction shortens the key,
   and every matched-count floor and every repudiation bound in the scheme is
   derived from that length. If
   :attr:`~sih141.protocol.params.ProtocolParams.expected_matched` were ever
   pointed back at the nominal ``L``, the protocol would still run, every
   existing test would still pass, and every published bound would be a claim
   about evidence the run does not have.
   :func:`test_every_derived_quantity_follows_the_signing_length` states the
   invariant in the only form that cannot rot: a checked parameter set and a
   plain one of the *signing* length must agree on every derived quantity, term
   for term.
2. **The sample is unbiased and the key it leaves is unbiased.** The check
   positions come from the recipients' stream and are independent of the key, so
   the retained key is not merely "uniform on test" -- it is *literally the same
   elements Alice drew*, and
   :func:`test_the_retained_key_is_the_drawn_key_restricted_to_the_retained_positions`
   asserts the identity rather than a statistic. The statistical form is
   asserted too, pooled over many seeds, because that is what would catch a
   selection rule that correlated with the key by some route the structural test
   does not see.
3. **Nothing distinguishes a check round from a key round.** An adversary who
   could tell them apart would behave while watched, and every number this
   module produces would be fiction. Three invariants close it and all three
   are asserted outright, not sampled: **every** seam the channel-side
   adversary holds -- ``resource_factory``, ``payload_map`` and
   ``channel_monitor`` -- receives an identical sequence of contexts either
   way; the variate budget is constant at three per position, so a retained
   position of a checked run is *bit-identical* to the same position of an
   unchecked run under one seed; and the two links watch disjoint halves of the
   reserved set, so recovering one does not hand over the other. The first of
   the three was asserted of the factory alone until Phase 3 measured the other
   two seams recovering the whole check set -- ``30/30`` positions from the
   payload seam's call gaps, ``120/120`` from the monitor being called at all --
   which is why ``test_the_factory_cannot_tell_a_check_round_from_a_key_round``
   now drives the full declared adversary rather than one third of it.
4. **The estimates converge and the intervals cover.** Convergence to the true
   channel parameter, half-widths shrinking like ``1/sqrt(n)``, and coverage at
   the stated rate over hundreds of seeded runs -- for the calibrated intervals,
   coverage close to nominal; for the distribution-free ones, coverage at least
   nominal and a strictly wider interval.
5. **The channel predictions are derived, and the derivations are right.** An
   honest channel gives CHSH consistent with ``2 sqrt(2)``; a Werner channel
   tracks ``(1 - p) 2 sqrt(2)`` and a QBER of ``p / 2``; and -- the sharpest of
   the three -- for an arbitrary *Bell-diagonal* resource the check-round QBER
   equals the teleported key's mismatch rate **basis by basis**, which a
   Werner-only test could not tell from the averaged claim.

Fast paths and honest paths
---------------------------
The coverage and convergence tests run on synthetic observations built from a
known Bernoulli model (:func:`_synthetic_qber`, :func:`_synthetic_chsh`),
because coverage is a property of the *statistic* and needs hundreds of
independent samples to measure at all -- simulating hundreds of thousands of
two-qubit measurements to check a confidence interval would buy nothing and cost
minutes. Every claim about the *channel* runs the real thing: two-qubit states,
real Born sampling, real teleportation. The two kinds of test are kept in
separate sections and the helpers are private to this file, so a synthetic
sample can never reach a published estimate.

Statistical tolerances
----------------------
Seeds are fixed throughout, so the suite is deterministic. Where a band is
quoted it is computed from the binomial standard error of that assertion's own
sample size at four sigmas, not guessed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from collections import Counter

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix, Statevector

from sih141.core.measure import expectation, projective_measure
from sih141.core.paulis import PauliBasis
from sih141.core.states import BellState, as_density, bell_state
from sih141.core.teleport import teleport
from sih141.protocol.analysis import (
    averaged_repudiation_bound,
    depolarising_error_rate,
    matched_statistics,
)
from sih141.protocol.checkrounds import (
    CHECK_CHSH_WEIGHT,
    CHECK_CONFIDENCE,
    CHSH_ALICE_ANGLES,
    CHSH_RECIPIENT_ANGLES,
    CLASSICAL_CHSH_BOUND,
    IDEAL_CHSH,
    IDEAL_PAULI_CORRELATION,
    CheckLog,
    CheckRole,
    CheckRoundPlan,
    ChshObservation,
    ChshRound,
    Interval,
    QberObservation,
    QberRound,
    depolarising_chsh,
    draw_check_plan,
    estimate_chsh,
    estimate_qber,
    normal_quantile,
    observe_chsh_round,
    observe_qber_round,
    required_check_rounds,
)
from sih141.protocol.distribute import (
    ResourceContext,
    distribute_public_key_with_checks,
    distribute_to_recipient,
    distribute_to_recipient_with_checks,
    ideal_resource,
)
from sih141.protocol.keys import KeyElement, generate_private_key
from sih141.protocol.params import (
    CHECKED_PARAMS,
    DEFAULT_CHECK_FRACTION,
    DEFAULT_PARAMS,
    DEMO_CHECKED_PARAMS,
    DEMO_PARAMS,
    VERIFIERS,
    Party,
    ProtocolParams,
)
from sih141.protocol.session import QDSSession
from sih141.protocol.verify import (
    enforced_repudiation_bound,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

_BASES = (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)

#: The four ideal correlators of |Phi+> under the shipped CHSH settings.
_IDEAL_CORRELATORS = (
    1 / math.sqrt(2),
    1 / math.sqrt(2),
    1 / math.sqrt(2),
    -1 / math.sqrt(2),
)


def _tolerance(probability: float, samples: int, sigmas: float = 4.0) -> float:
    """Return a ``sigmas``-standard-error band for a sampled proportion."""
    return sigmas * math.sqrt(probability * (1.0 - probability) / samples)


def _werner(depolarising_parameter: float) -> DensityMatrix:
    """Return the Werner resource ``(1-p)|Phi+><Phi+| + p I/4``."""
    ideal = as_density(bell_state(BellState.PHI_PLUS)).data
    mixed = np.eye(4, dtype=complex) / 4.0
    return DensityMatrix(
        (1.0 - depolarising_parameter) * ideal
        + depolarising_parameter * mixed
    )


def _bell_diagonal(weights: dict[BellState, float]) -> DensityMatrix:
    """Return a Bell-diagonal resource with the given weights."""
    total = np.zeros((4, 4), dtype=complex)
    for state, weight in weights.items():
        total += weight * as_density(bell_state(state)).data
    return DensityMatrix(total)


#: A Bell-diagonal resource that is deliberately NOT Werner: its three
#: per-basis error rates differ, so it separates the per-basis identity of
#: :ref:`check-round-qber-identity` from the weaker averaged one.
_SKEWED_WEIGHTS = {
    BellState.PHI_PLUS: 0.70,
    BellState.PSI_PLUS: 0.10,
    BellState.PHI_MINUS: 0.15,
    BellState.PSI_MINUS: 0.05,
}

#: The rates the derivation predicts for `_SKEWED_WEIGHTS`, per basis.
_SKEWED_PREDICTION = {
    PauliBasis.Z: _SKEWED_WEIGHTS[BellState.PSI_PLUS]
    + _SKEWED_WEIGHTS[BellState.PSI_MINUS],
    PauliBasis.X: _SKEWED_WEIGHTS[BellState.PHI_MINUS]
    + _SKEWED_WEIGHTS[BellState.PSI_MINUS],
    PauliBasis.Y: _SKEWED_WEIGHTS[BellState.PHI_MINUS]
    + _SKEWED_WEIGHTS[BellState.PSI_PLUS],
}


def _synthetic_qber(
    rate: float,
    rounds: int,
    rng: np.random.Generator,
    basis: PauliBasis = PauliBasis.Z,
) -> list[QberObservation]:
    """Build QBER observations whose underlying error rate is exactly ``rate``.

    Only the *product* of the two eigenvalues carries information, so Alice's
    wing is a fair coin and the recipient's is set to realise the drawn
    correlation. Used only for the statistical tests of the estimator itself;
    no channel claim rests on it.
    """
    ideal = IDEAL_PAULI_CORRELATION[basis]
    errors = rng.random(rounds) < rate
    alice = np.where(rng.random(rounds) < 0.5, 1, -1)
    return [
        QberObservation(
            index,
            basis,
            int(wing),
            int(wing * (-ideal if erred else ideal)),
        )
        for index, (erred, wing) in enumerate(zip(errors, alice, strict=True))
    ]


def _synthetic_chsh(
    correlators: tuple[float, float, float, float],
    rounds: int,
    rng: np.random.Generator,
) -> list[ChshObservation]:
    """Build CHSH observations whose four cells have the given correlators."""
    cells = rng.integers(4, size=rounds)
    draws = rng.random(rounds)
    alice = np.where(rng.random(rounds) < 0.5, 1, -1)
    sample = []
    for index, (cell, draw, wing) in enumerate(
        zip(cells, draws, alice, strict=True)
    ):
        correlation = correlators[int(cell)]
        product = 1 if draw < (1.0 + correlation) / 2.0 else -1
        alice_setting, recipient_setting = divmod(int(cell), 2)
        sample.append(
            ChshObservation(
                index,
                alice_setting,
                recipient_setting,
                int(wing),
                int(wing * product),
            )
        )
    return sample


def _observe_many(
    resource,
    rounds: int,
    role: CheckRole,
    rng: np.random.Generator,
    basis: PauliBasis | None = None,
):
    """Run ``rounds`` real check rounds over one fixed resource."""
    if role is CheckRole.QBER:
        return [
            observe_qber_round(
                resource,
                QberRound(
                    index,
                    basis
                    if basis is not None
                    else _BASES[int(rng.integers(3))],
                ),
                rng=rng,
            )
            for index in range(rounds)
        ]
    return [
        observe_chsh_round(
            resource,
            ChshRound(index, int(rng.integers(2)), int(rng.integers(2))),
            rng=rng,
        )
        for index in range(rounds)
    ]


# --------------------------------------------------------------------------- #
# 1. The effective key length, and its propagation                             #
# --------------------------------------------------------------------------- #


def test_a_zero_check_fraction_leaves_every_shipped_number_where_it_was():
    """The default is off, and off must be indistinguishable from before."""
    assert DEFAULT_PARAMS.check_fraction == 0.0
    assert DEFAULT_PARAMS.check_count == 0
    assert DEFAULT_PARAMS.has_check_rounds is False
    assert DEFAULT_PARAMS.signing_length == DEFAULT_PARAMS.key_length == 115200
    assert DEFAULT_PARAMS.expected_matched == 38400.0
    assert minimum_matched_count(DEFAULT_PARAMS) == 36555
    assert minimum_pooled_matched_count(DEFAULT_PARAMS) == 74190
    assert enforced_repudiation_bound(DEFAULT_PARAMS) == pytest.approx(
        1.4139e-09, rel=1e-4
    , abs=0)


@pytest.mark.parametrize(
    "key_length, check_fraction",
    [
        (115200, 0.125),
        (115200, 0.0625),
        (131664, 0.125),
        (2400, 0.25),
        (600, 0.5),
        (360, 0.1),
    ],
)
def test_every_derived_quantity_follows_the_signing_length(
    key_length: int, check_fraction: float
):
    """A checked set and a plain set of its signing length must agree, term for term.

    This is the test that stops the whole feature from being a silent
    weakening. Check positions carry no key, so a floor computed from ``L``
    instead of from ``signing_length`` would demand -- and a bound would
    *claim* -- evidence the run cannot have produced.
    """
    checked = ProtocolParams(
        key_length=key_length, check_fraction=check_fraction
    )
    plain = ProtocolParams(key_length=checked.signing_length)

    assert checked.signing_length == key_length - checked.check_count
    assert checked.check_count == math.floor(check_fraction * key_length)
    assert checked.expected_matched == plain.expected_matched
    assert minimum_matched_count(checked) == minimum_matched_count(plain)
    assert minimum_pooled_matched_count(
        checked
    ) == minimum_pooled_matched_count(plain)
    assert enforced_repudiation_bound(checked) == enforced_repudiation_bound(
        plain
    )
    # And the parameter set verification actually runs under is that plain one
    # in every respect but its own bookkeeping.
    assert checked.sifted().key_length == plain.key_length
    assert checked.sifted().check_fraction == 0.0
    assert checked.sifted().expected_matched == checked.expected_matched


def test_spending_key_on_check_rounds_costs_exactly_what_it_looks_like():
    """Shortening the key weakens the bound, monotonically and visibly."""
    fractions = (0.0, 0.0625, 0.125, 0.25, 0.5)
    bounds = [
        enforced_repudiation_bound(
            DEFAULT_PARAMS.with_check_fraction(fraction)
        )
        for fraction in fractions
    ]
    assert bounds == sorted(bounds), "a shorter key must not tighten the bound"
    assert bounds[0] == pytest.approx(1.4139e-09, rel=1e-4, abs=0)
    assert bounds[2] == pytest.approx(1.8853e-08, rel=1e-4, abs=0)
    # Thirteenfold at the shipped fraction: the number that must never be
    # confused with CHECKED_PARAMS's.
    assert bounds[2] / bounds[0] > 10.0


def test_the_shipped_checked_set_buys_its_sample_with_key_length():
    """CHECKED_PARAMS must be no weaker than DEFAULT_PARAMS, not merely close."""
    assert CHECKED_PARAMS.check_fraction == DEFAULT_CHECK_FRACTION
    assert CHECKED_PARAMS.check_count == 16458
    assert CHECKED_PARAMS.signing_length == 115206
    assert CHECKED_PARAMS.signing_length >= DEFAULT_PARAMS.key_length
    assert CHECKED_PARAMS.expected_matched == 38402.0
    assert enforced_repudiation_bound(
        CHECKED_PARAMS
    ) <= enforced_repudiation_bound(DEFAULT_PARAMS)
    # Both thresholds, the alphabet and the forgeability flag are untouched, so
    # the decision rule being demonstrated is the same decision rule.
    for field in ("s_a", "s_v", "bases", "allow_forgeable"):
        assert getattr(CHECKED_PARAMS, field) == getattr(DEFAULT_PARAMS, field)


def test_the_shipped_fraction_meets_the_requirement_it_was_derived_from():
    """Each arm's share of CHECKED_PARAMS clears its own sample-size ask."""
    budget = required_check_rounds(CHECKED_PARAMS)
    assert (budget.qber_rounds, budget.chsh_rounds) == (6688, 6795)
    chsh_share = math.floor(CHECK_CHSH_WEIGHT * CHECKED_PARAMS.check_count)
    qber_share = CHECKED_PARAMS.check_count - chsh_share
    assert chsh_share >= budget.chsh_rounds
    assert qber_share >= budget.qber_rounds
    # And the weight really is what the two requirements imply, not a round
    # number chosen for symmetry.
    assert budget.chsh_rounds / budget.total == pytest.approx(
        CHECK_CHSH_WEIGHT, abs=0.01
    )


def test_the_shortening_now_propagates_into_the_analytic_bounds():
    """The shortening reaches every published number, without the caller helping.

    This test replaces ``test_the_analytic_bounds_must_be_given_the_sifted_parameters``,
    on that test's own instruction: it asserted the discrepancy rather than
    hiding it, and said that "if a future edit to ``analysis`` fixes the root
    cause this test will fail and should be replaced by an equality." It has
    been, so it is.

    What changed. :mod:`sih141.protocol.analysis` predates check rounds and
    counted ``Binomial(L, 1/|B|)`` against ``key_length`` directly, so handed a
    checked set it counted the diverted positions as key and returned a bound
    that was *too good* -- 38400 expected matched positions where the truth is
    33600, and the bounds are exponential in that count.
    :func:`~sih141.protocol.analysis._as_params`, which every public entry point
    in that module routes through, now reduces a checked set to
    :meth:`~sih141.protocol.params.ProtocolParams.sifted` before anything counts
    against it.

    Why the design moved. The old contract made ``sifted()`` the caller's duty
    and this test the reminder. That is exactly the shape of the error this
    project has already shipped three times: a number that errs in the
    flattering direction, reachable by forgetting one call. Twenty call sites
    today, and the twenty-first is the one that forgets. Making the reduction
    happen where the parameter set is validated removes the opportunity rather
    than documenting it.

    ``sifted()`` is idempotent and is the identity on a set that reserves no
    check rounds, so nothing published from ``DEFAULT_PARAMS`` moves.
    """
    checked = ProtocolParams(key_length=115200, check_fraction=0.125)
    sifted = checked.sifted()

    # verify reads expected_matched, which already followed the signing length.
    assert minimum_matched_count(checked) == minimum_matched_count(sifted)
    assert enforced_repudiation_bound(checked) == enforced_repudiation_bound(sifted)

    # analysis now follows it too: the checked set and its sifted form agree,
    # and they agree on the *honest* value rather than the flattering one.
    nominal = matched_statistics(checked)
    honest = matched_statistics(sifted)
    assert nominal.expected == honest.expected
    assert nominal.expected == 33600.0, "counted only the 100800 signing rounds"
    assert nominal.key_length == 100800, "the diverted positions are not key"

    # The property that made forgetting sifted() dangerous is gone: there is no
    # longer a better-looking number to reach by omitting the call.
    assert averaged_repudiation_bound(
        checked, signer_sees_recipient_bases=False
    ) == averaged_repudiation_bound(sifted, signer_sees_recipient_bases=False)


def test_an_unchecked_parameter_set_is_untouched_by_the_reduction():
    """Nothing published from ``DEFAULT_PARAMS`` moves.

    The guard above only bites when check rounds are reserved. This pins the
    other half, because a reduction that silently altered the shipped numbers
    would be a far worse bug than the one it fixes.
    """
    plain = ProtocolParams(key_length=115200)
    assert plain.check_fraction == 0.0
    assert plain.sifted() == plain
    assert matched_statistics(plain).expected == 38400.0
    assert matched_statistics(plain).key_length == 115200


def test_check_fraction_survives_a_round_trip_through_json():
    checked = ProtocolParams(key_length=480, check_fraction=0.125)
    restored = ProtocolParams.from_dict(
        json.loads(json.dumps(checked.to_dict()))
    )
    assert restored == checked
    # A config written before check rounds existed restores as unchecked, which
    # is the truth about it.
    legacy = {"key_length": 480, "s_a": 1 / 64, "s_v": 1 / 16}
    assert ProtocolParams.from_dict(legacy).check_fraction == 0.0


def test_sifted_is_idempotent_and_preserves_every_threshold():
    checked = ProtocolParams(key_length=960, check_fraction=0.25)
    once = checked.sifted()
    assert once.sifted() == once
    assert DEFAULT_PARAMS.sifted() == DEFAULT_PARAMS
    for field in ("s_a", "s_v", "bases", "allow_forgeable"):
        assert getattr(once, field) == getattr(checked, field)


@pytest.mark.parametrize("bad", [1.0, 1.5, -0.01, float("nan"), float("inf")])
def test_an_impossible_check_fraction_is_refused_with_a_reason(bad: float):
    with pytest.raises((ValueError, TypeError)) as excinfo:
        ProtocolParams(key_length=480, check_fraction=bad)
    assert "check_fraction" in str(excinfo.value)


def test_a_check_fraction_that_rounds_to_no_rounds_is_refused():
    """Claiming estimation while doing none is the worst of both."""
    with pytest.raises(ValueError) as excinfo:
        ProtocolParams(key_length=100, check_fraction=0.001)
    message = str(excinfo.value)
    assert "0 check rounds" in message
    assert "check_fraction=0.0" in message


def test_a_check_fraction_is_a_bool_free_zone():
    with pytest.raises(TypeError) as excinfo:
        ProtocolParams(key_length=480, check_fraction=True)
    assert "boolean" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# 2. The plan                                                                  #
# --------------------------------------------------------------------------- #


def test_the_plan_is_reproducible_from_one_seed():
    params = ProtocolParams(key_length=600, check_fraction=0.125)
    first = draw_check_plan(params, rng=np.random.default_rng(2026))
    second = draw_check_plan(params, rng=np.random.default_rng(2026))
    third = draw_check_plan(params, rng=np.random.default_rng(2027))
    assert first == second
    assert first != third


def test_the_plan_partitions_the_run():
    params = ProtocolParams(key_length=600, check_fraction=0.125)
    plan = draw_check_plan(params, rng=np.random.default_rng(5))

    assert plan.check_count == params.check_count == 75
    assert plan.signing_length == params.signing_length == 525
    assert len(set(plan.positions)) == plan.check_count
    assert set(plan.positions).isdisjoint(plan.signing_positions)
    assert sorted(plan.positions + plan.signing_positions) == list(range(600))
    assert all(plan.is_check(index) for index in plan.positions)
    assert not any(plan.is_check(index) for index in plan.signing_positions)
    assert plan.round_at(plan.signing_positions[0]) is None
    assert plan.round_at(plan.positions[0]) is not None


def test_the_two_arms_are_split_by_the_derived_weight():
    params = ProtocolParams(key_length=1600, check_fraction=0.125)
    plan = draw_check_plan(params, rng=np.random.default_rng(6))
    assert plan.check_count == 200
    assert len(plan.chsh_rounds) == 100
    assert len(plan.qber_rounds) == 100
    # An odd count gives its spare round to the QBER arm, whose requirement
    # binds s_a directly.
    odd = draw_check_plan(
        ProtocolParams(key_length=90, check_fraction=0.125),
        rng=np.random.default_rng(7),
    )
    assert odd.check_count == 11
    assert (len(odd.chsh_rounds), len(odd.qber_rounds)) == (5, 6)


def test_the_qber_arm_draws_from_the_run_s_own_alphabet():
    params = ProtocolParams(key_length=3000, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(8))
    counts = Counter(round_.basis for round_ in plan.qber_rounds)
    assert set(counts) == set(params.bases)
    total = sum(counts.values())
    band = _tolerance(1 / 3, total)
    for basis in params.bases:
        assert abs(counts[basis] / total - 1 / 3) < band


def test_the_plan_round_trips_through_json():
    params = ProtocolParams(key_length=240, check_fraction=0.125)
    plan = draw_check_plan(params, rng=np.random.default_rng(9))
    restored = CheckRoundPlan.from_dict(json.loads(json.dumps(plan.to_dict())))
    assert restored == plan


def test_drawing_a_plan_without_a_check_fraction_is_refused():
    with pytest.raises(ValueError) as excinfo:
        draw_check_plan(DEFAULT_PARAMS, rng=np.random.default_rng(0))
    message = str(excinfo.value)
    assert "no check rounds" in message
    assert "with_check_fraction" in message


def test_a_plan_that_leaves_nothing_to_sign_is_refused():
    with pytest.raises(ValueError) as excinfo:
        CheckRoundPlan(
            key_length=3,
            qber_rounds=tuple(
                QberRound(index, PauliBasis.Z) for index in range(3)
            ),
            chsh_rounds=(),
        )
    assert "at least one signing position" in str(excinfo.value)


def test_a_plan_that_reuses_a_position_is_refused():
    with pytest.raises(ValueError) as excinfo:
        CheckRoundPlan(
            key_length=10,
            qber_rounds=(QberRound(4, PauliBasis.Z),),
            chsh_rounds=(ChshRound(4, 0, 1),),
        )
    assert "distinct" in str(excinfo.value)


def test_a_plan_position_outside_the_key_is_refused():
    with pytest.raises(ValueError) as excinfo:
        CheckRoundPlan(
            key_length=10,
            qber_rounds=(QberRound(10, PauliBasis.Z),),
            chsh_rounds=(),
        )
    assert "outside the key" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# 3. Sifting: the retained key is not biased                                   #
# --------------------------------------------------------------------------- #


def test_the_retained_key_is_the_drawn_key_restricted_to_the_retained_positions():
    """The structural statement, which is stronger than any uniformity test.

    No element is altered and none is re-drawn, so the retained key cannot be
    biased by the exclusion however the check set was chosen.
    """
    params = ProtocolParams(key_length=900, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(11))
    key = generate_private_key(params, 0, rng=np.random.default_rng(12))
    sifted = plan.sift_key(key)

    assert len(sifted) == params.signing_length == 675
    assert sifted.message_bit == key.message_bit
    assert tuple(sifted.elements) == tuple(
        key[index] for index in plan.signing_positions
    )
    sifted.check_against(params.sifted())


def test_sifting_leaves_the_retained_key_uniform_over_bases_and_eigenvalues():
    """The statistical form, pooled over many seeds.

    The structural test above says the elements are untouched; this one says the
    *selection* is not correlated with them -- which is the claim a future plan
    drawn from the wrong stream, or from a rule that peeked at the key, would
    break.
    """
    params = ProtocolParams(key_length=360, check_fraction=0.25)
    bases: Counter[PauliBasis] = Counter()
    eigenvalues: Counter[int] = Counter()
    for seed in range(400):
        plan = draw_check_plan(params, rng=np.random.default_rng(1000 + seed))
        key = generate_private_key(
            params, seed % 2, rng=np.random.default_rng(9000 + seed)
        )
        sifted = plan.sift_key(key)
        bases.update(sifted.bases)
        eigenvalues.update(sifted.eigenvalues)

    total = sum(bases.values())
    assert total == 400 * params.signing_length
    basis_band = _tolerance(1 / 3, total)
    for basis in params.bases:
        assert abs(bases[basis] / total - 1 / 3) < basis_band

    value_band = _tolerance(1 / 2, total)
    for value in (1, -1):
        assert abs(eigenvalues[value] / total - 0.5) < value_band


def test_sifting_a_key_of_the_wrong_length_is_refused():
    params = ProtocolParams(key_length=120, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(13))
    other = generate_private_key(
        ProtocolParams(key_length=60), 0, rng=np.random.default_rng(14)
    )
    with pytest.raises(ValueError) as excinfo:
        plan.sift_key(other)
    assert "drawn for a key length" in str(excinfo.value)


def test_sift_record_agrees_with_a_checked_distribution():
    """Sifting a full record after the fact must land on the same key positions.

    The two routes differ physically -- a checked run never teleports the check
    positions at all -- so their *outcomes* differ, but the retained bases must
    be the same sequence, because the basis draw happens on every position
    either way.
    """
    params = ProtocolParams(key_length=120, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(15))
    key = generate_private_key(params, 1, rng=np.random.default_rng(16))

    unchecked = distribute_to_recipient(
        key,
        params.with_check_fraction(0.0),
        party=Party.BOB,
        rng=np.random.default_rng(17),
    )
    checked = distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        check_plan=plan,
        rng=np.random.default_rng(17),
    )
    assert plan.sift_record(unchecked) == checked.record


# --------------------------------------------------------------------------- #
# 4. Distribution: a check round is invisible from the channel                 #
# --------------------------------------------------------------------------- #


def test_the_factory_cannot_tell_a_check_round_from_a_key_round():
    """The load-bearing test of the whole module.

    An adversary that could distinguish a watched round from an unwatched one
    would behave on the watched ones, and every estimate here would describe a
    channel nobody ever used.

    **The adversary is not the factory.** The threat model declared in
    :mod:`sih141.protocol.session` hands one channel-side party three seams --
    ``resource_factory``, ``payload_map`` and ``channel_monitor`` -- and the
    check set is recovered if *any one* of them is offered a different set of
    positions from the others: a seam called only on key rounds publishes the
    check set as the gaps in its call sequence, and one called only on check
    rounds publishes it by being called at all. So all three are driven
    together, against a live session, and the assertion is that each sees
    ``0 .. L-1`` once per link per message bit, in the same order, with nothing
    between them to separate a watched round from an unwatched one.

    A version of this test that drove the factory alone passed against code
    that leaked the whole check set through the other two seams; that is why
    the weaker form is not kept alongside as a fast path.
    """
    params = ProtocolParams(key_length=64, check_fraction=0.25)
    seen: dict[str, list[tuple[Party, int, int]]] = {
        "resource": [],
        "payload": [],
        "monitor": [],
    }

    def hop(context: ResourceContext) -> tuple[Party, int, int]:
        return (context.party, context.message_bit, context.position)

    def factory(context: ResourceContext):
        seen["resource"].append(hop(context))
        return ideal_resource()

    def payload(state, context: ResourceContext):
        seen["payload"].append(hop(context))
        return state

    def monitor(resource, context: ResourceContext):
        seen["monitor"].append(hop(context))
        return {}

    session = QDSSession(
        params,
        resource_factory=factory,
        payload_map=payload,
        channel_monitor=monitor,
        rng=np.random.default_rng(4318),
    )
    session.distribute()

    expected = [
        (party, bit, index)
        for bit in (0, 1)
        for party in VERIFIERS
        for index in range(params.key_length)
    ]
    for name in ("resource", "payload", "monitor"):
        assert seen[name] == expected, f"{name} was not offered every position"

    # Stated the other way round as well, because the equality above would also
    # be satisfied by three seams that all leaked the same thing.
    for bit, plan in session.check_plans.items():
        assert set(plan.positions), "the plan must designate something"
        for name, calls in seen.items():
            offered = {
                position for _, message_bit, position in calls
                if message_bit == bit
            }
            assert offered == set(range(params.key_length)), (
                f"{name}'s call set on bit {bit} narrows the check set to "
                f"{set(range(params.key_length)) - offered}"
            )

    # And the original claim, at the level of one distribution run: the seams
    # see the same sequence with a plan in force as without one.
    plain = params.with_check_fraction(0.0)
    plan = draw_check_plan(params, rng=np.random.default_rng(18))
    key = generate_private_key(params, 0, rng=np.random.default_rng(19))

    def watcher(store: list[ResourceContext]):
        def factory_only(context: ResourceContext):
            store.append(context)
            return ideal_resource()

        return factory_only

    def payload_watcher(store: list[ResourceContext]):
        def payload_only(state, context: ResourceContext):
            store.append(context)
            return state

        return payload_only

    with_plan: list[ResourceContext] = []
    with_plan_payload: list[ResourceContext] = []
    without_plan: list[ResourceContext] = []
    without_plan_payload: list[ResourceContext] = []
    distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.CHARLIE,
        resource_factory=watcher(with_plan),
        payload_map=payload_watcher(with_plan_payload),
        check_plan=plan,
        rng=np.random.default_rng(20),
    )
    distribute_to_recipient(
        key,
        plain,
        party=Party.CHARLIE,
        resource_factory=watcher(without_plan),
        payload_map=payload_watcher(without_plan_payload),
        rng=np.random.default_rng(20),
    )
    assert with_plan == without_plan
    assert with_plan_payload == without_plan_payload
    assert with_plan_payload == with_plan
    assert len(with_plan) == params.key_length
    assert [context.position for context in with_plan] == list(
        range(params.key_length)
    )


def test_no_seam_narrows_the_check_set_below_the_prior():
    """"No better than chance", stated as a number rather than as a hope.

    The three channel-side seams are driven over six runs whose *only*
    difference is the session seed, so the plan moves every time. If any seam
    carried a bit about the plan, its observation would move with it. It does
    not: the three call sequences are one and the same object across all six
    runs, so the adversary's view is a constant function of the plan and
    carries exactly zero bits about it.

    Zero bits means the posterior is the prior, and the prior is uniform over
    the ``C(120, 30)`` -- about ``10**29`` -- subsets a plan could have been.
    So an adversary who must nominate ``check_count`` positions expects
    ``check_count**2 / L = 30 * 30 / 120 = 7.5`` hits, a precision of
    ``check_count / L = 0.25``, which is the base rate. That is measured below
    against a fixed nomination over two hundred plans, and it is what the
    payload seam used to return ``30/30`` on.
    """
    params = ProtocolParams(key_length=120, check_fraction=0.25)
    assert params.check_count == 30

    observations: list[tuple[tuple[str, int, int, int], ...]] = []
    plans: list[tuple[int, ...]] = []
    for seed in range(6):
        seen: list[tuple[str, int, int, int]] = []

        def note(name: str, context: ResourceContext) -> None:
            seen.append(
                (name, context.party, context.message_bit, context.position)
            )

        session = QDSSession(
            params,
            resource_factory=lambda context: (
                note("resource", context) or ideal_resource()
            ),
            payload_map=lambda state, context: (
                note("payload", context) or state
            ),
            channel_monitor=lambda resource, context: (
                note("monitor", context) or {}
            ),
            rng=np.random.default_rng(6100 + seed),
        )
        session.distribute()
        observations.append(tuple(seen))
        plans.append(tuple(session.check_plans[0].positions))

    assert len(set(plans)) == len(plans), "the plans must actually move"
    assert len(set(observations)) == 1, "the adversary's view must not"

    # And the consequence, measured. A fixed nomination of check_count
    # positions -- the best an adversary with no information can do -- hits the
    # base rate, four sigmas of the binomial standard error either side.
    nomination = set(range(params.check_count))
    trials = 200
    hits = sum(
        len(nomination & set(
            draw_check_plan(params, rng=np.random.default_rng(7000 + seed)
                            ).positions
        ))
        for seed in range(trials)
    )
    rate = hits / (trials * params.check_count)
    base = params.check_count / params.key_length
    band = 4.0 * math.sqrt(base * (1.0 - base) / (trials * params.check_count))
    assert abs(rate - base) < band, f"{rate} is not the base rate {base}"


def test_the_two_links_do_not_watch_the_same_positions():
    """Learning one link's check set must not hand over the other's.

    The exploit the split exists to stop runs Bob's whole pass before Charlie's
    first hop, so a shared check set would let an adversary who recovered it on
    Bob's link spare exactly those positions on Charlie's. Disjoint halves make
    that useless: the positions left over from Bob's half are precisely the
    ones Charlie is watching.
    """
    params = ProtocolParams(key_length=240, check_fraction=0.25)
    overlaps = []
    for seed in range(8):
        plan = draw_check_plan(params, rng=np.random.default_rng(6200 + seed))
        bob = set(plan.positions_for(Party.BOB))
        charlie = set(plan.positions_for(Party.CHARLIE))
        assert bob and charlie
        assert bob | charlie == set(plan.positions)
        overlaps.append(len(bob & charlie))
        # What an adversary who learned Bob's half would have to attack on
        # Charlie's link, and what it costs him: every position of the reserved
        # set he does not already know is one Charlie is watching.
        assert set(plan.positions) - bob == charlie
    assert overlaps == [0] * 8

    # The reserved set itself is still shared, because both records have to
    # index the same key.
    plan = draw_check_plan(params, rng=np.random.default_rng(6300))
    assert plan.signing_length == params.signing_length


def test_sparing_the_watched_no_longer_separates_published_from_real():
    """The exploit, run both ways, with the key hops held identical.

    An adversary on the resource line who learns which positions carry key --
    the only thing the seams used to leak -- and degrades those and nothing
    else would publish a pristine channel over a corrupted key. Both arms are
    run here: one degrading every position of Charlie's link, one degrading
    only the positions the payload seam offered it on Bob's link. The two arms
    must now agree, because the payload seam offers every position, and the
    published QBER must track the real damage rather than the watched subset.
    """
    params = ProtocolParams(key_length=240, check_fraction=0.25)
    noisy = _werner(0.9)

    def arm(spare: bool) -> tuple[float, float]:
        keyed: set[int] = set()

        def payload(state, context: ResourceContext):
            if context.party is Party.BOB:
                keyed.add(context.position)
            return state

        def factory(context: ResourceContext):
            if context.party is not Party.CHARLIE:
                return ideal_resource()
            if spare and context.position not in keyed:
                return ideal_resource()
            return noisy

        session = QDSSession(
            params,
            resource_factory=factory,
            payload_map=payload,
            rng=np.random.default_rng(6400),
        )
        session.distribute()
        published = estimate_qber(
            session.check_logs[(Party.CHARLIE, 0)].qber
        ).estimate
        key = session.signing_keys[0]
        record = session.raw_records[0][Party.CHARLIE]
        matched = [
            index
            for index in range(len(record))
            if record.bases[index] is key.bases[index]
        ]
        real = sum(
            record.eigenvalues[index] != key.eigenvalues[index]
            for index in matched
        ) / len(matched)
        return published, real

    naive_published, naive_real = arm(spare=False)
    spared_published, spared_real = arm(spare=True)

    # The key is damaged, identically, in both arms.
    assert naive_real == spared_real > 0.2
    # And the published statistic reports it, identically, in both arms. Before
    # the seams were closed the spared arm published 0.0 against the same 0.22.
    assert spared_published == naive_published
    assert spared_published > 0.2


def test_one_seed_still_reproduces_a_checked_run_byte_for_byte():
    """Three seams on every position instead of some must not cost determinism.

    The seams are called more often than they were and the plan is dealt
    between the links; neither reads the session's generator, so a seed must
    still fix the whole run -- the transcript, the plans, and the order every
    seam was called in.
    """
    params = ProtocolParams(key_length=64, check_fraction=0.25)

    def once() -> tuple[str, tuple, tuple]:
        seen: list[tuple[str, int, int, int]] = []

        def note(name: str, context: ResourceContext) -> None:
            seen.append(
                (name, context.party, context.message_bit, context.position)
            )

        session = QDSSession(
            params,
            resource_factory=lambda context: (
                note("resource", context) or ideal_resource()
            ),
            payload_map=lambda state, context: (
                note("payload", context) or state
            ),
            channel_monitor=lambda resource, context: (
                note("monitor", context) or {"seen": len(seen)}
            ),
            rng=np.random.default_rng(6500),
        )
        transcript = session.run(1)
        return (
            json.dumps(transcript.to_dict(), sort_keys=True),
            tuple(seen),
            tuple(
                session.check_plans[bit].to_dict()["qber_rounds"][0]["position"]
                for bit in (0, 1)
            ),
        )

    first = once()
    second = once()
    assert first[0] == second[0]
    assert first[1] == second[1]
    assert first[2] == second[2]
    assert len(first[1]) == 3 * 2 * 2 * params.key_length


def test_an_observing_seam_changes_the_call_count_and_nothing_else():
    """The honest run's results must survive the seams being called more often.

    An observer that returns what it was given, on every position, must leave
    the records, the verdicts and the transcript exactly where a bare run left
    them -- so that the extra calls buy uninferability and cost nothing.
    """
    params = ProtocolParams(key_length=64, check_fraction=0.25)
    bare = QDSSession(params, rng=np.random.default_rng(6600)).run(0)

    calls = 0

    def counting_monitor(resource, context: ResourceContext) -> dict:
        nonlocal calls
        calls += 1
        return {}

    watched = QDSSession(
        params,
        resource_factory=lambda context: ideal_resource(),
        payload_map=lambda state, context: state,
        channel_monitor=counting_monitor,
        rng=np.random.default_rng(6600),
    ).run(0)

    assert calls == 2 * 2 * params.key_length
    assert watched.to_dict() == bare.to_dict()


def test_an_untagged_plan_is_measured_in_full_by_every_link():
    """The historical shape still means what it used to mean.

    A plan whose rounds carry no link tag -- one hand-built, or one rebuilt
    from a ``to_dict`` written before the tags existed -- is the *shared* plan:
    every link measures every reserved position, at full sample size and with
    the two links coupled. It is what ``parties=None`` draws, and saying so is
    what keeps a pre-split transcript readable.
    """
    params = ProtocolParams(key_length=64, check_fraction=0.25)
    shared = draw_check_plan(
        params, rng=np.random.default_rng(6700), parties=None
    )
    assert not shared.is_split
    assert shared.measured_by == ()
    for party in VERIFIERS:
        assert shared.positions_for(party) == shared.positions

    key = generate_private_key(params, 0, rng=np.random.default_rng(6701))
    outcomes = distribute_public_key_with_checks(
        key, params, check_plan=shared, rng=np.random.default_rng(6702)
    )
    for party in VERIFIERS:
        assert outcomes[party].log.positions == shared.positions
        assert outcomes[party].log.round_count == params.check_count
        assert len(outcomes[party].record) == params.signing_length

    # And it survives the round trip, still untagged.
    restored = CheckRoundPlan.from_dict(
        json.loads(json.dumps(shared.to_dict()))
    )
    assert restored == shared and not restored.is_split

    split = draw_check_plan(params, rng=np.random.default_rng(6700))
    assert split.positions == shared.positions
    assert split.is_split
    assert CheckRoundPlan.from_dict(
        json.loads(json.dumps(split.to_dict()))
    ) == split


def test_a_half_tagged_plan_is_refused():
    """All the rounds carry a link or none of them do."""
    with pytest.raises(ValueError) as excinfo:
        CheckRoundPlan(
            key_length=8,
            qber_rounds=(QberRound(0, PauliBasis.Z, Party.BOB),),
            chsh_rounds=(ChshRound(1, 0, 1),),
        )
    assert "tag every round" in str(excinfo.value)


def test_a_check_round_cannot_be_tagged_with_alice():
    with pytest.raises(ValueError) as excinfo:
        QberRound(0, PauliBasis.Z, Party.ALICE)
    assert "common endpoint" in str(excinfo.value)


@pytest.mark.parametrize(
    "parties, expected",
    [
        ((), ValueError),
        ((Party.ALICE,), ValueError),
        ((Party.BOB, Party.BOB), ValueError),
        ((None,), ValueError),
        ("Bob", TypeError),
        (7, TypeError),
    ],
)
def test_draw_check_plan_refuses_a_malformed_party_list(parties, expected):
    params = ProtocolParams(key_length=48, check_fraction=0.25)
    with pytest.raises(expected):
        draw_check_plan(params, rng=np.random.default_rng(1), parties=parties)


def test_a_single_link_takes_the_whole_reserved_set():
    """One link named means one link measures everything -- and it is tagged.

    Not the same object as the shared plan: this one *says* who measures the
    rounds, so a second link joining the run would measure none of them, which
    is the honest reading of a plan drawn for one recipient.
    """
    params = ProtocolParams(key_length=48, check_fraction=0.25)
    plan = draw_check_plan(
        params, rng=np.random.default_rng(6800), parties=(Party.BOB,)
    )
    assert plan.is_split and plan.measured_by == (Party.BOB,)
    assert plan.positions_for(Party.BOB) == plan.positions
    assert plan.positions_for(Party.CHARLIE) == ()


def test_retained_positions_are_bit_identical_to_an_unchecked_run():
    """Constant variate budget, asserted as equality rather than as a statistic.

    Three variates per position on both branches means the generator is in the
    same state at the start of every position, so a retained position of a
    checked run *is* the corresponding position of an unchecked run. Nothing
    weaker would rule out the check rounds silently shifting the key's
    distribution.
    """
    params = ProtocolParams(key_length=240, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(21))
    key = generate_private_key(params, 1, rng=np.random.default_rng(22))

    plain = distribute_to_recipient(
        key,
        params.with_check_fraction(0.0),
        party=Party.BOB,
        rng=np.random.default_rng(23),
    )
    checked = distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        check_plan=plan,
        rng=np.random.default_rng(23),
    )
    kept = plan.signing_positions
    assert checked.record.bases == tuple(plain.bases[i] for i in kept)
    assert checked.record.eigenvalues == tuple(
        plain.eigenvalues[i] for i in kept
    )
    assert len(checked.record) == params.signing_length
    # The run reserves check_count positions; this link measures its own half
    # of them and runs the other half as key rounds it then drops -- which is
    # what keeps the equality above true position for position.
    assert checked.log.round_count == params.check_count // 2
    assert checked.log.positions == plan.positions_for(Party.BOB)
    assert set(checked.log.positions) < set(plan.positions)


UNCHECKED_TRANSCRIPT_DIGEST = (
    "43ea5ceafda99b83d41dd78b8ef7b6968300a7b005040cbd346a7c0ca726660b"
)
"""SHA-256 of one honest ``check_fraction = 0`` transcript, measured before the fix.

Computed on the code as it stood at commit ``885f342`` -- before ``payload_map``
and ``channel_monitor`` were lifted onto every position and before a plan's
rounds were dealt between the links -- and re-measured identical afterwards. It
is the *cross-version* half of the honest-path claim, which no test written
inside one revision can make on its own.
"""


def test_an_unchecked_honest_run_is_byte_identical_to_the_pre_fix_code():
    """The honest path did not move when the seams were opened. A digest, not a promise.

    Every other invariance test in this file compares two runs of *one* revision
    against each other, which cannot distinguish "the honest path is unchanged"
    from "the honest path changed and both sides of the comparison moved with
    it". This pins the actual bytes, against a value measured on the code before
    the change.

    ``check_fraction = 0`` because that is the configuration in which the claim
    can be exact: with no plan drawn, nothing about the run is check-round
    dependent, so the whole transcript -- keys, records, signature, verdicts,
    the pooled counts, the printed bounds -- must survive the change untouched.

    The claim extends to a **checked** honest run by composition rather than by
    a second digest, which would be wrong to pin: a checked transcript legitimately
    differs from the pre-fix one, because each link now publishes half the
    reserved rounds rather than all of them. What must not differ is the *key*,
    and :func:`test_retained_positions_are_bit_identical_to_an_unchecked_run`
    says a checked run's record is the unchecked run's record sifted -- so an
    unchecked run pinned byte for byte pins the checked run's record too.

    If this fails, the honest protocol produced different numbers under one seed
    and the reason must be found before any measured rate in Phase 3 is quoted
    again. Re-pin the constant only after establishing that the change was
    intended and that nothing published depends on the old bytes.
    """
    session = QDSSession(
        ProtocolParams(key_length=96), rng=np.random.default_rng(20260141)
    )
    transcript = session.run(0)
    digest = hashlib.sha256(
        transcript.to_json(sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert digest == UNCHECKED_TRANSCRIPT_DIGEST, (
        "an honest unchecked run's transcript moved. The check-round seams are "
        "not supposed to be reachable from a run that has no check rounds, so "
        "this is a change to the honest protocol and not to the sampling "
        "design."
    )
    # And the two properties a reader would check the digest for by hand, so a
    # failure above is diagnosable without recomputing a hash.
    assert transcript.params.check_count == 0
    assert not transcript.check_logs and not transcript.channel


def test_the_variate_budget_is_three_per_position_on_both_branches():
    """One integer draw and two uniforms per position, check round or not.

    Replayed against a shadow generator rather than counted, because
    :meth:`~numpy.random.Generator.integers` and
    :meth:`~numpy.random.Generator.random` advance the bit generator by
    different amounts: the *pattern* is the invariant, not a total.
    """
    params = ProtocolParams(key_length=64, check_fraction=0.5)
    plan = draw_check_plan(params, rng=np.random.default_rng(24))
    key = generate_private_key(params, 0, rng=np.random.default_rng(25))
    assert 0 < params.check_count < params.key_length, "both branches must run"

    def shadow() -> np.random.Generator:
        replay = np.random.default_rng(26)
        for _ in range(params.key_length):
            replay.integers(len(params.bases))  # the recipient's basis choice
            replay.random()  # Bell measurement, or Alice's wing
            replay.random()  # the recipient's measurement, either way
        return replay

    for kwargs in (
        {"params": params, "check_plan": plan},
        {"params": params.with_check_fraction(0.0), "check_plan": None},
    ):
        generator = np.random.default_rng(26)
        distribute_to_recipient_with_checks(
            key, party=Party.BOB, rng=generator, **kwargs
        )
        assert generator.bit_generator.state == shadow().bit_generator.state

    # And an implementation that skipped the discarded basis draw on a check
    # round would land somewhere else entirely.
    stub = np.random.default_rng(26)
    for _ in range(params.key_length):
        stub.random()
        stub.random()
    assert stub.bit_generator.state != shadow().bit_generator.state


def test_a_reserved_check_fraction_without_a_plan_is_refused():
    """The silent-weakening guard, at the only boundary that sees both facts."""
    params = ProtocolParams(key_length=120, check_fraction=0.25)
    key = generate_private_key(params, 0, rng=np.random.default_rng(27))
    with pytest.raises(ValueError) as excinfo:
        distribute_to_recipient(
            key, params, party=Party.BOB, rng=np.random.default_rng(28)
        )
    message = str(excinfo.value)
    assert "no check_plan was given" in message
    assert "draw_check_plan" in message
    assert "with_check_fraction(0.0)" in message


def test_a_plan_that_disagrees_with_the_parameters_is_refused():
    params = ProtocolParams(key_length=120, check_fraction=0.25)
    key = generate_private_key(params, 0, rng=np.random.default_rng(29))
    foreign = draw_check_plan(
        ProtocolParams(key_length=240, check_fraction=0.25),
        rng=np.random.default_rng(30),
    )
    with pytest.raises(ValueError) as excinfo:
        distribute_to_recipient_with_checks(
            key,
            params,
            party=Party.BOB,
            check_plan=foreign,
            rng=np.random.default_rng(31),
        )
    assert "not portable" in str(excinfo.value)

    smaller = ProtocolParams(key_length=120, check_fraction=0.125)
    thin = draw_check_plan(smaller, rng=np.random.default_rng(32))
    with pytest.raises(ValueError) as excinfo:
        distribute_to_recipient_with_checks(
            key,
            params,
            party=Party.BOB,
            check_plan=thin,
            rng=np.random.default_rng(33),
        )
    assert "must agree" in str(excinfo.value)


def test_both_recipients_retain_the_same_positions():
    """Symmetrisation exchanges records position by position; they must align."""
    params = ProtocolParams(key_length=180, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(34))
    key = generate_private_key(params, 0, rng=np.random.default_rng(35))
    outcomes = distribute_public_key_with_checks(
        key, params, check_plan=plan, rng=np.random.default_rng(36)
    )
    bob, charlie = outcomes[Party.BOB], outcomes[Party.CHARLIE]
    assert len(bob.record) == len(charlie.record) == params.signing_length
    # The reserved SET is shared -- it has to be, or the two records stop
    # indexing the same key -- and the two links measure disjoint halves of it,
    # so that recovering one link's check set does not hand over the other's.
    assert set(bob.log.positions).isdisjoint(charlie.log.positions)
    assert set(bob.log.positions) | set(charlie.log.positions) == set(
        plan.positions
    )
    assert bob.record.entries != charlie.record.entries
    # Two independent links, so two independent samples: the logs must not be
    # the same object or the same outcomes.
    assert bob.log is not charlie.log
    assert bob.record.bases != charlie.record.bases


def test_a_checked_distribution_verifies_under_the_sifted_parameters():
    params = ProtocolParams(key_length=240, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(37))
    key = generate_private_key(params, 1, rng=np.random.default_rng(38))
    outcome = distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        check_plan=plan,
        rng=np.random.default_rng(39),
    )
    sifted_params = params.sifted()
    outcome.record.check_against(sifted_params)
    plan.sift_key(key).check_against(sifted_params)
    with pytest.raises(ValueError):
        outcome.record.check_against(params)


def test_the_check_log_carries_no_key_position():
    """What is published must be disjoint from what is signed."""
    params = ProtocolParams(key_length=300, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(40))
    key = generate_private_key(params, 0, rng=np.random.default_rng(41))
    outcome = distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        check_plan=plan,
        rng=np.random.default_rng(42),
    )
    assert set(outcome.log.positions).isdisjoint(plan.signing_positions)
    assert json.loads(json.dumps(outcome.log.to_dict()))["party"] == "Bob"
    # Publishing the raw observations, not just the estimate, is what makes the
    # interval auditable: anyone can recompute it from the restored log.
    restored = CheckLog.from_dict(json.loads(json.dumps(outcome.log.to_dict())))
    assert restored == outcome.log
    assert estimate_qber(restored.qber) == estimate_qber(outcome.log.qber)


def test_a_run_without_a_plan_publishes_an_empty_log():
    """The honest representation of "no channel statistics were produced"."""
    outcome = distribute_to_recipient_with_checks(
        generate_private_key(DEMO_PARAMS, 0, rng=np.random.default_rng(43)),
        DEMO_PARAMS,
        party=Party.BOB,
        rng=np.random.default_rng(44),
    )
    assert outcome.plan is None
    assert outcome.log.round_count == 0
    assert len(outcome.record) == DEMO_PARAMS.key_length
    with pytest.raises(ValueError):
        estimate_qber(outcome.log.qber)


# --------------------------------------------------------------------------- #
# 5. The estimators: convergence, coverage, width                              #
# --------------------------------------------------------------------------- #


def test_the_qber_estimate_converges_to_the_truth_as_the_sample_grows():
    truth = 0.05
    errors = []
    for rounds in (500, 2000, 8000, 32000):
        rng = np.random.default_rng(101)
        total = 0.0
        trials = 25
        for _ in range(trials):
            sample = _synthetic_qber(truth, rounds, rng)
            total += abs(estimate_qber(sample).estimate - truth)
        errors.append(total / trials)
    assert errors == sorted(errors, reverse=True)
    # And the decay is 1/sqrt(n), not something slower: a sixty-fourfold sample
    # must cut the mean error by at least fourfold.
    assert errors[0] / errors[-1] > 4.0


def test_the_interval_half_width_shrinks_like_one_over_root_n():
    """Exact for the distribution-free interval, banded for the calibrated one.

    Run at a rate of ``0.3`` rather than near ``0``, so that no endpoint is
    clipped to the unit interval. Clipping is correct -- a rate below zero is
    not a rate -- but it breaks the pure scaling law, and
    :func:`test_a_zero_count_gives_an_interval_rather_than_a_point` is where the
    clipped case is checked instead.
    """
    rng = np.random.default_rng(102)
    hoeffding = []
    wilson = []
    for rounds in (500, 2000, 8000, 32000):
        sample = _synthetic_qber(0.3, rounds, rng)
        estimate = estimate_qber(sample, method="hoeffding")
        assert 0.0 < estimate.interval.low and estimate.interval.high < 1.0
        hoeffding.append(estimate.half_width)
        wilson.append(estimate_qber(sample).half_width)
    for earlier, later in zip(hoeffding, hoeffding[1:], strict=False):
        assert earlier / later == pytest.approx(2.0, rel=1e-12, abs=0)
    for earlier, later in zip(wilson, wilson[1:], strict=False):
        assert 1.8 < earlier / later < 2.2


@pytest.mark.parametrize(
    "truth, rounds, confidence",
    [(0.05, 400, 0.95), (0.02, 1200, 0.95), (0.05, 400, 0.99)],
)
def test_the_qber_interval_covers_the_truth_at_the_stated_rate(
    truth: float, rounds: int, confidence: float
):
    rng = np.random.default_rng(103)
    trials = 400
    covered = sum(
        estimate_qber(
            _synthetic_qber(truth, rounds, rng), confidence=confidence
        ).interval.covers(truth)
        for _ in range(trials)
    )
    coverage = covered / trials
    band = _tolerance(confidence, trials)
    assert abs(coverage - confidence) < band, (
        f"coverage {coverage} is not the stated {confidence}"
    )


@pytest.mark.parametrize(
    "rounds, confidence", [(800, 0.95), (2400, 0.95), (800, 0.99)]
)
def test_the_chsh_interval_covers_the_truth_at_the_stated_rate(
    rounds: int, confidence: float
):
    truth = (
        _IDEAL_CORRELATORS[0]
        + _IDEAL_CORRELATORS[1]
        + _IDEAL_CORRELATORS[2]
        - _IDEAL_CORRELATORS[3]
    )
    assert truth == pytest.approx(IDEAL_CHSH)
    rng = np.random.default_rng(104)
    trials = 300
    covered = sum(
        estimate_chsh(
            _synthetic_chsh(_IDEAL_CORRELATORS, rounds, rng),
            confidence=confidence,
        ).interval.covers(truth)
        for _ in range(trials)
    )
    coverage = covered / trials
    band = _tolerance(confidence, trials)
    assert abs(coverage - confidence) < band


def test_the_distribution_free_intervals_are_wider_and_never_under_cover():
    """A bound must bound: at least the stated coverage, at a visible price."""
    rng = np.random.default_rng(105)
    trials = 200
    qber_hits = chsh_hits = 0
    qber_wider = chsh_wider = 0
    for _ in range(trials):
        qber_sample = _synthetic_qber(0.05, 400, rng)
        calibrated = estimate_qber(qber_sample, confidence=0.95)
        conservative = estimate_qber(
            qber_sample, confidence=0.95, method="hoeffding"
        )
        qber_hits += conservative.interval.covers(0.05)
        qber_wider += conservative.half_width > calibrated.half_width

        chsh_sample = _synthetic_chsh(_IDEAL_CORRELATORS, 800, rng)
        normal = estimate_chsh(chsh_sample, confidence=0.95)
        bounded = estimate_chsh(
            chsh_sample, confidence=0.95, method="hoeffding"
        )
        chsh_hits += bounded.interval.covers(IDEAL_CHSH)
        chsh_wider += bounded.interval.half_width > normal.interval.half_width

    assert qber_hits / trials >= 0.95
    assert chsh_hits / trials >= 0.95
    assert qber_wider == chsh_wider == trials


def test_the_chsh_interval_is_clipped_at_the_algebraic_bound_not_tsirelson():
    """Clipping at 2 sqrt(2) would assume the conclusion the test is checking."""
    sample = [
        ChshObservation(index, index // 2 % 2, index % 2, 1, 1)
        for index in range(400)
    ]
    estimate = estimate_chsh(sample)
    # Every product is +1, so E = (1, 1, 1, 1) and S = 2 -- an algebraically
    # legal statistic that no entangled state produces under these settings.
    assert estimate.correlators == (1.0, 1.0, 1.0, 1.0)
    assert estimate.statistic == pytest.approx(2.0)
    assert estimate.interval.high <= 4.0
    assert estimate.interval.low >= -4.0
    assert not estimate.violates_classical_bound


def test_both_estimators_report_the_level_and_the_method_they_used():
    """A confidence level with no method beside it is not a confidence level."""
    qber = estimate_qber(
        [QberObservation(index, PauliBasis.Z, 1, 1) for index in range(200)]
    )
    assert isinstance(qber.interval, Interval)
    assert qber.interval.confidence == CHECK_CONFIDENCE == 0.99
    assert qber.interval.method == "wilson"
    assert (
        estimate_qber(
            [QberObservation(0, PauliBasis.Z, 1, 1)], method="hoeffding"
        ).interval.method
        == "hoeffding"
    )

    chsh = estimate_chsh(
        _synthetic_chsh(_IDEAL_CORRELATORS, 400, np.random.default_rng(107))
    )
    assert chsh.interval.confidence == CHECK_CONFIDENCE
    assert chsh.interval.method == "normal"
    assert chsh.interval.excludes(IDEAL_CHSH) is not chsh.interval.covers(
        IDEAL_CHSH
    )


def test_an_empty_sample_is_refused_by_both_estimators():
    with pytest.raises(ValueError) as excinfo:
        estimate_qber([])
    assert "denominator" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        estimate_chsh(
            [ChshObservation(0, 0, 0, 1, 1), ChshObservation(1, 0, 1, 1, -1)]
        )
    message = str(excinfo.value)
    assert "no rounds" in message
    assert "[2, 3]" in message


def test_the_two_arms_cannot_be_pooled_by_accident():
    with pytest.raises(TypeError) as excinfo:
        estimate_qber([ChshObservation(0, 0, 0, 1, 1)])
    assert "QberObservation" in str(excinfo.value)
    with pytest.raises(TypeError) as excinfo:
        estimate_chsh([QberObservation(0, PauliBasis.Z, 1, 1)])
    assert "ChshObservation" in str(excinfo.value)


def test_an_unknown_interval_method_is_refused_with_the_alternatives():
    with pytest.raises(ValueError) as excinfo:
        estimate_qber(
            [QberObservation(0, PauliBasis.Z, 1, 1)], method="clopper-pearson"
        )
    assert "'wilson'" in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        estimate_chsh(
            [
                ChshObservation(index, index // 2 % 2, index % 2, 1, 1)
                for index in range(4)
            ],
            method="bootstrap",
        )
    assert "'normal'" in str(excinfo.value)


def test_a_zero_count_gives_an_interval_rather_than_a_point():
    """Absence of evidence must not be reported as certainty."""
    clean = [QberObservation(i, PauliBasis.Z, 1, 1) for i in range(400)]
    estimate = estimate_qber(clean)
    assert estimate.errors == 0
    assert estimate.estimate == 0.0
    assert estimate.interval.low == 0.0
    assert estimate.interval.high > 0.0
    assert estimate.within_budget(DEFAULT_PARAMS.s_v)
    assert not estimate.within_budget(0.0)


def test_the_estimates_convert_into_the_language_the_thresholds_are_written_in():
    qber = estimate_qber(
        [
            QberObservation(index, PauliBasis.Z, 1, 1 if index % 20 else -1)
            for index in range(2000)
        ]
    )
    depolarising = qber.implied_depolarising()
    assert depolarising.low == pytest.approx(2 * qber.interval.low)
    assert depolarising.high == pytest.approx(2 * qber.interval.high)
    assert depolarising.covers(2 * qber.estimate)

    chsh = estimate_chsh(
        _synthetic_chsh(_IDEAL_CORRELATORS, 4000, np.random.default_rng(106))
    )
    strength = chsh.implied_depolarising()
    assert strength.covers(0.0)
    assert strength.low >= 0.0
    # The map is decreasing, so the endpoints must have swapped.
    assert strength.high == pytest.approx(1.0 - chsh.interval.low / IDEAL_CHSH)


def test_required_check_rounds_refuses_a_resolution_it_cannot_decide_with():
    with pytest.raises(ValueError) as excinfo:
        required_check_rounds(
            DEFAULT_PARAMS, qber_resolution=DEFAULT_PARAMS.s_a * 2
        )
    assert "cannot decide" in str(excinfo.value)


def test_a_tighter_ask_costs_more_rounds():
    base = required_check_rounds(DEFAULT_PARAMS)
    tighter = required_check_rounds(
        DEFAULT_PARAMS, qber_resolution=DEFAULT_PARAMS.s_a / 8
    )
    surer = required_check_rounds(DEFAULT_PARAMS, confidence=0.999)
    assert tighter.qber_rounds == 4 * base.qber_rounds
    assert surer.total > base.total
    assert base.fraction == base.total / DEFAULT_PARAMS.key_length


# --------------------------------------------------------------------------- #
# 6. The physics: real pairs, real Born sampling                               #
# --------------------------------------------------------------------------- #


def test_an_honest_channel_yields_chsh_consistent_with_two_root_two():
    rng = np.random.default_rng(201)
    sample = _observe_many(
        bell_state(BellState.PHI_PLUS), 3000, CheckRole.CHSH, rng
    )
    estimate = estimate_chsh(sample)
    assert estimate.consistent_with_ideal
    assert estimate.violates_classical_bound
    assert estimate.statistic == pytest.approx(IDEAL_CHSH, abs=0.15)
    for correlator, expected in zip(
        estimate.correlators, _IDEAL_CORRELATORS, strict=True
    ):
        assert correlator == pytest.approx(expected, abs=0.12)


def test_the_ideal_pair_has_no_qber_in_any_basis():
    rng = np.random.default_rng(202)
    for basis in _BASES:
        sample = _observe_many(
            bell_state(BellState.PHI_PLUS), 200, CheckRole.QBER, rng, basis
        )
        assert estimate_qber(sample).errors == 0


def test_the_y_basis_is_anticorrelated_on_the_ideal_pair():
    """|Phi+> agrees in X and Z and *disagrees* in Y.

    Scoring a Y round as an error whenever the outcomes differ would report a
    flat 1/3 QBER on a perfect channel, which is why the sign lives in a table.
    """
    rng = np.random.default_rng(203)
    pair = bell_state(BellState.PHI_PLUS)
    products = {
        basis: [
            observation.correlation
            for observation in _observe_many(
                pair, 200, CheckRole.QBER, rng, basis
            )
        ]
        for basis in _BASES
    }
    assert set(products[PauliBasis.X]) == {1}
    assert set(products[PauliBasis.Z]) == {1}
    assert set(products[PauliBasis.Y]) == {-1}
    assert IDEAL_PAULI_CORRELATION == {
        PauliBasis.X: 1,
        PauliBasis.Y: -1,
        PauliBasis.Z: 1,
    }


@pytest.mark.parametrize("strength", [0.0, 0.1, 0.2, 0.3, 0.5])
def test_a_depolarised_channel_tracks_the_analytic_chsh_prediction(
    strength: float
):
    """S(p) = (1 - p) 2 sqrt(2), derived from the resource's algebra."""
    rng = np.random.default_rng(204)
    sample = _observe_many(_werner(strength), 2000, CheckRole.CHSH, rng)
    estimate = estimate_chsh(sample, confidence=0.999)
    predicted = depolarising_chsh(strength)
    assert estimate.interval.covers(predicted)
    assert estimate.statistic == pytest.approx(predicted, abs=0.2)
    # The Bell test stops certifying entanglement exactly where the prediction
    # crosses 2, at p = 1 - 1/sqrt(2) = 0.2929.
    if strength < 0.29:
        assert estimate.violates_classical_bound
    else:
        assert not estimate.violates_classical_bound


@pytest.mark.parametrize("strength", [0.0, 0.05, 0.1, 0.2, 0.3])
def test_a_depolarised_channel_tracks_the_analytic_qber_prediction(
    strength: float
):
    """The check-round QBER is p/2 -- the rate ``s_a`` was sized against."""
    rng = np.random.default_rng(205)
    sample = _observe_many(_werner(strength), 2000, CheckRole.QBER, rng)
    estimate = estimate_qber(sample, confidence=0.999)
    predicted = depolarising_error_rate(strength)
    assert estimate.interval.covers(predicted)
    assert estimate.implied_depolarising().covers(strength)


def test_the_check_round_qber_equals_the_key_mismatch_rate_basis_by_basis():
    """The identity of :ref:`check-round-qber-identity`, on a NON-Werner resource.

    A Werner resource gives the same rate in all three bases, so a Werner-only
    test cannot distinguish the per-basis identity from the averaged one. This
    resource gives 0.15, 0.20 and 0.25 in Z, X and Y respectively, and both the
    check round and the teleported key have to reproduce all three.
    """
    resource = _bell_diagonal(_SKEWED_WEIGHTS)
    rounds = 2500
    rng = np.random.default_rng(206)
    for basis in _BASES:
        predicted = _SKEWED_PREDICTION[basis]
        band = _tolerance(predicted, rounds)

        checked = estimate_qber(
            _observe_many(resource, rounds, CheckRole.QBER, rng, basis)
        )
        assert abs(checked.estimate - predicted) < band

        mismatches = 0
        for _ in range(rounds):
            value = 1 if rng.integers(2) == 0 else -1
            hop = teleport(
                KeyElement(basis, value).state(), resource=resource, rng=rng
            )
            outcome = projective_measure(hop.received, 0, basis, rng=rng)
            mismatches += int(outcome.eigenvalue != value)
        assert abs(mismatches / rounds - predicted) < band


def test_a_separable_resource_cannot_violate_the_classical_bound():
    """A classically correlated pair -- what an intercept-resend leaves behind."""
    correlated = DensityMatrix(
        np.diag([0.5, 0.0, 0.0, 0.5]).astype(complex)
    )
    rng = np.random.default_rng(207)
    estimate = estimate_chsh(
        _observe_many(correlated, 3000, CheckRole.CHSH, rng)
    )
    assert not estimate.violates_classical_bound
    assert not estimate.consistent_with_ideal
    assert estimate.interval.excludes(IDEAL_CHSH)
    assert estimate.statistic < CLASSICAL_CHSH_BOUND
    # It still has a perfect Z correlation, so the QBER arm alone would call it
    # healthy in one basis out of three: the two arms answer different questions.
    zed = estimate_qber(
        _observe_many(correlated, 200, CheckRole.QBER, rng, PauliBasis.Z)
    )
    assert zed.errors == 0


def test_the_wings_are_read_in_the_teleportation_convention():
    """D2: resource qubit 0 is Alice's and qubit 1 is the recipient's.

    Pinned with an *asymmetric* resource, because |Phi+> cannot tell the two
    conventions apart, and cross-checked against ``teleport`` itself -- a
    check round that read the pair the other way round would attribute a
    one-sided attack to the wrong party, with nothing failing.
    """
    # Qubit 0 = |0> (sharp in Z), qubit 1 = |+> (sharp in X).
    resource = Statevector.from_label("+0")
    rng = np.random.default_rng(208)

    in_z = _observe_many(resource, 200, CheckRole.QBER, rng, PauliBasis.Z)
    assert {observation.alice_eigenvalue for observation in in_z} == {1}
    assert {observation.recipient_eigenvalue for observation in in_z} == {1, -1}

    in_x = _observe_many(resource, 200, CheckRole.QBER, rng, PauliBasis.X)
    assert {observation.recipient_eigenvalue for observation in in_x} == {1}
    assert {observation.alice_eigenvalue for observation in in_x} == {1, -1}

    # The cross-check: teleport()'s receiver holds resource qubit 1, so a
    # payload sent over this product resource arrives as a Pauli image of |+>,
    # sharp in X and flat in Z.
    hop = teleport(
        KeyElement(PauliBasis.Z, 1).state(), resource=resource, rng=rng
    )
    assert abs(expectation(hop.received, "X")) == pytest.approx(1.0, abs=1e-9)
    assert expectation(hop.received, "Z") == pytest.approx(0.0, abs=1e-9)


def test_a_checked_run_over_a_noisy_link_reports_the_noise_it_was_given():
    """End to end: a plan, a degraded factory, and the number that comes out."""
    strength = 0.2
    params = ProtocolParams(key_length=1200, check_fraction=0.5)
    plan = draw_check_plan(params, rng=np.random.default_rng(209))
    key = generate_private_key(params, 0, rng=np.random.default_rng(210))
    noisy = _werner(strength)

    outcome = distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        resource_factory=lambda: noisy,
        check_plan=plan,
        rng=np.random.default_rng(211),
    )
    qber = estimate_qber(outcome.log.qber, confidence=0.999)
    chsh = estimate_chsh(outcome.log.chsh, confidence=0.999)

    assert qber.interval.covers(depolarising_error_rate(strength))
    assert chsh.interval.covers(depolarising_chsh(strength))
    assert qber.implied_depolarising().covers(strength)
    assert chsh.implied_depolarising().covers(strength)
    # Both arms agree with each other, which is the consistency check Phase 4
    # gets for free from having two of them.
    assert qber.implied_depolarising().covers(
        chsh.implied_depolarising().low
    ) or chsh.implied_depolarising().covers(qber.implied_depolarising().low)
    # And the key that survived is exactly as noisy as the checks predicted.
    sifted_key = plan.sift_key(key)
    matched = [
        index
        for index in range(params.signing_length)
        if outcome.record.bases[index] == sifted_key.bases[index]
    ]
    mismatches = sum(
        outcome.record.eigenvalues[index] != sifted_key.eigenvalues[index]
        for index in matched
    )
    band = _tolerance(depolarising_error_rate(strength), len(matched))
    assert abs(
        mismatches / len(matched) - depolarising_error_rate(strength)
    ) < band


# --------------------------------------------------------------------------- #
# 7. Housekeeping (D5): frozen values, validation, actionable messages          #
# --------------------------------------------------------------------------- #


def test_every_published_object_is_frozen_and_serialisable():
    # Large enough that one link's half of the CHSH arm still lands in all four
    # correlator cells: the arms are dealt between the links, so a per-link
    # sample is half the reserved count (:ref:`check-round-links`).
    params = ProtocolParams(key_length=256, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(301))
    key = generate_private_key(params, 0, rng=np.random.default_rng(302))
    outcome = distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        check_plan=plan,
        rng=np.random.default_rng(303),
    )
    for frozen in (plan, outcome.log, outcome.record, outcome):
        assert dataclasses.is_dataclass(frozen)
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.__setattr__("party", Party.ALICE)
    json.dumps(outcome.log.to_dict())
    json.dumps(plan.to_dict())
    json.dumps(estimate_qber(outcome.log.qber).to_dict())
    json.dumps(estimate_chsh(outcome.log.chsh).to_dict())
    json.dumps(required_check_rounds(params).to_dict())


def test_a_check_log_refuses_to_belong_to_alice():
    with pytest.raises(ValueError) as excinfo:
        CheckLog(Party.ALICE, 0, (), ())
    assert "not to Alice" in str(excinfo.value)


def test_an_observation_refuses_a_boolean_eigenvalue():
    with pytest.raises(ValueError) as excinfo:
        QberObservation(0, PauliBasis.Z, True, 1)
    assert "boolean" in str(excinfo.value)


def test_a_chsh_setting_must_index_one_of_two():
    with pytest.raises(ValueError) as excinfo:
        ChshRound(0, 2, 0)
    assert "two CHSH settings" in str(excinfo.value)
    with pytest.raises(ValueError):
        ChshObservation(0, 0, 3, 1, 1)


def test_a_none_resource_is_refused_rather_than_read_as_ideal():
    with pytest.raises(ValueError) as excinfo:
        observe_qber_round(None, QberRound(0, PauliBasis.Z))
    assert "indistinguishable from a clean channel" in str(excinfo.value)


def test_a_one_qubit_resource_is_refused():
    with pytest.raises(ValueError) as excinfo:
        observe_chsh_round(Statevector.from_label("0"), ChshRound(0, 0, 0))
    assert "two-qubit state" in str(excinfo.value)


def test_the_normal_quantile_is_exact_where_it_is_known():
    assert normal_quantile(0.5) == pytest.approx(0.0, abs=1e-12)
    assert normal_quantile(0.975) == pytest.approx(1.959963984540054, abs=1e-9)
    assert normal_quantile(0.995) == pytest.approx(2.575829303548901, abs=1e-9)
    for probability in (0.0, 1.0, -0.1, 1.5):
        with pytest.raises(ValueError):
            normal_quantile(probability)


def test_the_settings_that_reach_tsirelson_are_the_ones_shipped():
    """cos(alpha - beta) summed with the CHSH signs, computed from the angles."""
    correlators = [
        math.cos(alice - recipient)
        for alice in CHSH_ALICE_ANGLES
        for recipient in CHSH_RECIPIENT_ANGLES
    ]
    statistic = (
        correlators[0] + correlators[1] + correlators[2] - correlators[3]
    )
    assert statistic == pytest.approx(IDEAL_CHSH)
    assert IDEAL_CHSH == pytest.approx(2 * math.sqrt(2))
    assert tuple(correlators) == pytest.approx(_IDEAL_CORRELATORS)


def test_the_demo_checked_set_is_honest_about_being_too_small():
    """A tiny sample must produce a wide interval, not a confident one."""
    assert DEMO_CHECKED_PARAMS.check_count == 24
    assert DEMO_CHECKED_PARAMS.signing_length == 168
    plan = draw_check_plan(
        DEMO_CHECKED_PARAMS, rng=np.random.default_rng(304)
    )
    key = generate_private_key(
        DEMO_CHECKED_PARAMS, 0, rng=np.random.default_rng(305)
    )
    outcome = distribute_to_recipient_with_checks(
        key,
        DEMO_CHECKED_PARAMS,
        party=Party.BOB,
        check_plan=plan,
        rng=np.random.default_rng(306),
    )
    qber = estimate_qber(outcome.log.qber)
    assert qber.errors == 0
    # Perfect channel, and still nowhere near able to certify Bob's budget.
    assert not qber.within_budget(DEFAULT_PARAMS.s_a)
    assert qber.interval.high > DEFAULT_PARAMS.s_v
    assert DEMO_CHECKED_PARAMS.check_count < required_check_rounds(
        DEMO_CHECKED_PARAMS
    ).total
