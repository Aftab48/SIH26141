"""Phase 4 layer two: the structural thresholds, and the four claims they rest on.

This file pins :mod:`sih141.detect.thresholds_structural`, the family of derived
thresholds for aborts, refusals and the shape of a run. It is organised around
the places the family could be wrong while still looking right.

1. **Every threshold is derived, and the derivation is checkable.** Section 1
   re-runs each closed form against its own algebra rather than against a stored
   number: the Chernoff inversion is checked against the protocol's own floor,
   which was derived from the same inequality at the same budget, and the
   evidence-abort union is checked against the three tails it is a union of.
2. **The proven bounds are not violated by honest data.** Section 2 is the
   corollary D7 permits -- *checking* a derived threshold against honest runs is
   allowed, *choosing* one from attack data is not. Sixty honest runs across
   three key lengths raise zero alarms at every budget tried, as the derivation
   says they must; a single alarm here would mean the derivation is wrong and
   the measurement is right.
3. **Refusals are not verdicts, and the API fights back.** Section 3 attacks the
   guards from the wrong side: it *tries* to fold a no-verdict into a rejection,
   in the two shapes a real caller would use, and asserts that both raise. A
   documented rule is a rule somebody breaks at 2am; a :exc:`TypeError` is not.
4. **The alarms fire on the runs the protocol says they must.** Section 4 mounts
   the two adversaries that force an abort deterministically -- the count
   starver and the forging recipient -- and checks the family catches all of
   them, attributes each to the right party, and never reports either as a
   rejection. Section 5 checks the three that do *not* force one, because a
   detector that fired on a depolariser here would be reading a channel signal
   through the wrong statistic.

Notes
-----
Determinism (D3)
    Every session is seeded through an injected
    :class:`numpy.random.Generator`, and every adversary owns a generator whose
    seed has nothing to do with any session's (D6).
No machine learning (D4)
    No number in this file was chosen because it separated the attack data. The
    thresholds are functions of ``(eps, n, |B|)`` computed by the module under
    test; the attack arms below are read afterwards, and if one of them failed
    the answer would be a finding, not a new constant.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from sih141.attacks.channel import DepolarisingChannel, InterceptResend
from sih141.attacks.forgery import OutsideForger, RecipientForger
from sih141.attacks.impersonation import (
    ImpersonationScope,
    Impersonator,
    impersonation_seams,
)
from sih141.attacks.starvation import CountStarver
from sih141.detect.statistics import (
    EVIDENCE_ABORT_REASONS,
    STRUCTURAL_ABORT_REASONS,
    TranscriptStatistics,
    chernoff_deviation_bound,
)
from sih141.detect.thresholds_structural import (
    FLOOR_BUDGET,
    STRUCTURAL_CHECKS,
    NoVerdictCount,
    OutcomeTally,
    RunOutcome,
    StructuralCheck,
    abort_reason_bound,
    attribute_aborts,
    chernoff_lower_tail_count,
    evidence_abort_bound,
    evidence_abort_threshold,
    minimum_sifted_length,
    outcome_of,
    outcomes,
    point_mass_threshold,
    replay_refusal_threshold,
    run_shape_threshold,
    run_shape_violations,
    shortfall_threshold,
    structural_abort_threshold,
    structural_report,
    tally_outcomes,
)
from sih141.protocol.params import DEFAULT_PARAMS, Party, ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
)
from sih141.protocol.tally import no_count_exchange
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    AbortReason,
    MatchedSetTooSmall,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

#: Long enough that both matched-count floors bite -- ``m_min = 22`` and
#: ``M_min = 106`` -- so an abort at this length really is the ``1.6e-19`` event
#: the derivation says it is, and short enough that forty runs finish inside a
#: minute. The crossover for the per-verifier floor is ``273``.
LENGTH = 384

#: Trials per attack arm. Forty because two of the arms are the deterministic
#: ones the module claims force an abort with probability one, and forty
#: consecutive successes is the smallest sample that reads as a rule rather than
#: as luck without costing minutes.
TRIALS = 40

#: Honest control runs per key length in section 2.
HONEST_TRIALS = 20

#: Budgets the honest control is scored at. Spanning fifteen orders of
#: magnitude, because the point of section 2 is that the answer does not move.
BUDGETS = (1e-3, 1e-9, 1e-18)

#: One budget past the wall: below ``3 * 2**-64 = 1.63e-19`` no key length
#: admits the evidence-abort check, so it is withheld rather than fired. The
#: honest answer must be the same either way, which is what section 2 asserts.
TIGHT_BUDGET = 1e-20


def make_stats(
    seed: int, *, length: int = LENGTH, **seams: object
) -> TranscriptStatistics:
    """Run one session and return its statistics, keeping an abort in the file.

    Parameters
    ----------
    seed : int
        The session's seed. Never an adversary's (D6).
    length : int, optional
        Keyword-only key length.
    **seams : object
        Passed straight to :class:`~sih141.protocol.session.QDSSession`.

    Returns
    -------
    TranscriptStatistics
        Extracted through the JSON round trip, like every Phase 4 reader.
    """
    session = QDSSession(
        ProtocolParams(key_length=length),
        rng=np.random.default_rng(seed),
        **seams,
    )
    try:
        transcript = session.run(0)
    except MatchedSetTooSmall:
        # A refusal is recorded before the exception propagates, so the run is
        # still in the transcript. Losing it here would delete exactly the runs
        # this file exists to score.
        transcript = session.transcript()
    return TranscriptStatistics.from_transcript(transcript)


# --------------------------------------------------------------------------- #
# 1. The derivations, checked against their own algebra
# --------------------------------------------------------------------------- #


def test_the_chernoff_inversion_agrees_with_the_protocols_own_floor() -> None:
    """The inversion and ``minimum_matched_count`` are one derivation.

    Both invert ``P[S <= (1-d) mu] <= exp(-d^2 mu / 2)`` at ``eps = 2**-64``;
    the protocol wants the smallest count it will *score* and this wants the
    largest count it may *fire on*, so the two must be adjacent integers. If
    they ever drift apart, one of the two is no longer the derivation it claims
    to be.
    """
    for length in (600, 1200, 6000, 115200):
        params = ProtocolParams(key_length=length)
        largest = chernoff_lower_tail_count(
            length, params.match_probability, FLOOR_BUDGET
        )
        assert largest is not None
        assert largest == minimum_matched_count(params) - 1, (
            f"at L = {length} the inversion gives {largest} and the floor "
            f"{minimum_matched_count(params)}; they invert the same inequality "
            f"at the same budget and must be adjacent."
        )


def test_the_inversion_is_the_closed_form_and_not_a_search() -> None:
    """``c(eps) = floor(mu - sqrt(2 mu ln(1/eps)))``, evaluated directly."""
    for trials, probability, budget in (
        (115200, 1 / 3, 1e-9),
        (384, 1 / 3, 1e-6),
        (5000, 1 / 2, 1e-12),
    ):
        mean = trials * probability
        expected = math.floor(mean - math.sqrt(2 * mean * -math.log(budget)))
        assert (
            chernoff_lower_tail_count(trials, probability, budget) == expected
        )


def test_the_inversion_is_vacuous_rather_than_zero_on_a_small_sample() -> None:
    """A sample too small for a budget gets ``None``, never ``0``.

    Returning ``0`` would smuggle in the claim that firing on an empty matched
    set is inside the budget, which at these sizes it is not:
    ``(2/3)**24 = 5.9e-05`` against a budget of ``1e-09``.
    """
    assert chernoff_lower_tail_count(24, 1 / 3, 1e-9) is None
    assert (2 / 3) ** 24 > 1e-9


def test_the_inverted_threshold_really_is_inside_the_budget() -> None:
    """Forward and backward agree: the bound at ``c(eps)`` is at most ``eps``.

    The inversion is only worth anything if
    :func:`~sih141.detect.statistics.chernoff_deviation_bound` -- the forward
    direction, written by a different hand in a different module -- agrees.
    """
    for trials, probability in ((384, 1 / 3), (115200, 1 / 3), (2048, 1 / 2)):
        for budget in (1e-3, 1e-9, 1e-20, 1e-30):
            largest = chernoff_lower_tail_count(trials, probability, budget)
            if largest is None:
                continue
            bound = chernoff_deviation_bound(
                largest, trials, probability, side="lower"
            )
            assert bound <= budget, (
                f"the inversion offered {largest} at eps = {budget:.1e} but "
                f"the forward bound there is {bound:.3e}."
            )


def test_the_evidence_bound_is_the_union_of_the_three_tails() -> None:
    """``B_evid = 2 b(n, m_min) + b(2n, M_min)``, recomputed independently.

    The union bound is the whole derivation, so it is re-derived here from the
    two regimes rather than compared with a stored number.
    """
    log_budget = -math.log(HONEST_ABORT_BUDGET)

    def term(trials: int, probability: float, floor: int) -> float:
        candidates = []
        if floor <= 1:
            candidates.append((1.0 - probability) ** trials)
        if 2.0 * log_budget < trials * probability:
            candidates.append(HONEST_ABORT_BUDGET)
        return min(candidates) if candidates else 1.0

    for length in (24, 96, 136, 137, 192, 272, 273, 384, 600, 115200):
        params = ProtocolParams(key_length=length)
        probability = params.match_probability
        own = term(length, probability, minimum_matched_count(params))
        pooled = term(
            2 * length, probability, minimum_pooled_matched_count(params)
        )
        assert evidence_abort_bound(params) == pytest.approx(
            2 * own + pooled, rel=1e-12
        , abs=0)
        assert evidence_abort_bound(
            params, counts_exchanged=False
        ) == pytest.approx(2 * own, rel=1e-12, abs=0)


def test_each_abort_reason_carries_its_own_bound_and_they_are_not_summed() -> None:
    """Nine reasons, nine answers, and the union is over three events not nine.

    Summing the nine would count the same two floor events three times and
    quote the weakest bound for the five that cost nothing. The per-reason
    function exists so a report can say how strong *this* abort is.
    """
    params = ProtocolParams(key_length=LENGTH)
    for reason in STRUCTURAL_ABORT_REASONS:
        assert abort_reason_bound(params, reason) == 0.0
    assert abort_reason_bound(
        params, AbortReason.EMPTY_MATCHED_SET
    ) == pytest.approx(
        (2 / 3) ** LENGTH, rel=1e-12, abs=0
    )
    for reason in (
        AbortReason.BELOW_FLOOR,
        AbortReason.COUNTERPART_BELOW_FLOOR,
    ):
        assert abort_reason_bound(params, reason) == HONEST_ABORT_BUDGET
    assert (
        abort_reason_bound(params, AbortReason.POOLED_BELOW_FLOOR)
        == HONEST_ABORT_BUDGET
    )
    # COUNTERPART_BELOW_FLOOR at Bob and BELOW_FLOOR at Charlie are the *same
    # event* seen from two sides, so the nine reason bounds are not a partition
    # to be summed: the run-level union is over the three floor events, and
    # totalling the reasons over-counts.
    assert abort_reason_bound(
        params, AbortReason.COUNTERPART_BELOW_FLOOR
    ) == abort_reason_bound(params, AbortReason.BELOW_FLOOR)
    naive = sum(abort_reason_bound(params, r) for r in AbortReason)
    assert evidence_abort_bound(params) <= naive
    # At a length where the empty-set term is representable the over-count is
    # visible rather than lost in the last bits of a double.
    short = ProtocolParams(key_length=96)
    assert evidence_abort_bound(short) < sum(
        abort_reason_bound(short, r) for r in AbortReason
    )


def test_a_reason_string_is_accepted_and_an_invented_one_is_not() -> None:
    """The reason may arrive as the transcript's own string."""
    params = ProtocolParams(key_length=LENGTH)
    assert abort_reason_bound(
        params, "matched-count-below-floor"
    ) == HONEST_ABORT_BUDGET
    with pytest.raises(ValueError, match="names no AbortReason"):
        abort_reason_bound(params, "a-reason-nobody-derived")


def test_the_evidence_bound_settles_on_three_times_the_floor_budget() -> None:
    """Above both crossovers the closed form is exactly ``3 * 2**-64``.

    That constant is what makes :func:`minimum_sifted_length` answerable: the
    "for every longer key" quantifier needs an asymptote, and this is it.
    """
    for length in (273, 384, 600, 6000, 115200):
        assert evidence_abort_bound(
            ProtocolParams(key_length=length)
        ) == pytest.approx(3 * HONEST_ABORT_BUDGET, rel=1e-12, abs=0)
        assert evidence_abort_bound(
            ProtocolParams(key_length=length), counts_exchanged=False
        ) == pytest.approx(2 * HONEST_ABORT_BUDGET, rel=1e-12, abs=0)


def test_the_evidence_bound_steps_up_where_a_floor_starts_to_bite() -> None:
    """It is not monotone, and the two steps are where the floors cross ``1``.

    An exact ``(1-p)^n`` term is replaced by the much looser Chernoff term the
    moment a floor exceeds ``1``. A :func:`minimum_sifted_length` that assumed
    monotonicity would return a length whose bound a longer key violates, which
    is why that function quantifies over the whole tail.
    """
    assert minimum_matched_count(ProtocolParams(key_length=272)) == 1
    assert minimum_matched_count(ProtocolParams(key_length=273)) == 2
    assert minimum_pooled_matched_count(ProtocolParams(key_length=136)) == 1
    assert minimum_pooled_matched_count(ProtocolParams(key_length=137)) == 2
    for below, above in ((136, 137), (272, 273)):
        assert evidence_abort_bound(
            ProtocolParams(key_length=below)
        ) < evidence_abort_bound(ProtocolParams(key_length=above))


def test_the_exact_bound_is_tighter_than_the_closed_form_everywhere() -> None:
    """``exact=True`` is the probability of the same event, so it can only fall.

    It is a check on the closed form as much as on the exact sum: an upper bound
    that the exact answer exceeded would not be an upper bound.
    """
    for length in (192, 384, 600, 115200):
        params = ProtocolParams(key_length=length)
        assert evidence_abort_bound(
            params, exact=True
        ) <= evidence_abort_bound(params)
    assert evidence_abort_bound(DEFAULT_PARAMS, exact=True) == pytest.approx(
        8.0154e-31, rel=1e-3
    , abs=0)


def test_the_minimum_length_certifies_the_whole_tail_not_one_point() -> None:
    """Every length at or above the answer is inside the budget."""
    for budget in (1e-3, 1e-6, 1e-9, 1e-15):
        length = minimum_sifted_length(budget)
        assert length is not None
        for probe in range(length, 400):
            assert (
                evidence_abort_bound(ProtocolParams(key_length=probe))
                <= budget
            )
        assert (
            evidence_abort_bound(ProtocolParams(key_length=length - 1))
            > budget
        ) or length == 1


def test_no_key_length_reaches_a_budget_below_the_floors_own() -> None:
    """Under ``3 * 2**-64`` the answer is ``None``, not a longer key."""
    assert minimum_sifted_length(3 * HONEST_ABORT_BUDGET) is not None
    assert minimum_sifted_length(2.9 * HONEST_ABORT_BUDGET) is None
    assert (
        minimum_sifted_length(
            2.9 * HONEST_ABORT_BUDGET, counts_exchanged=False
        )
        is not None
    )
    assert (
        minimum_sifted_length(
            1.9 * HONEST_ABORT_BUDGET, counts_exchanged=False
        )
        is None
    )


def test_the_shortfall_threshold_collapses_at_every_practical_budget() -> None:
    """At or above ``2**-64`` the derived shortfall is ``1``, and that is the finding.

    The floors were calibrated at the honest-abort budget, so they already spend
    all of it: the abort *is* the threshold and its magnitude adds nothing. The
    knob only turns below ``2**-64``, and this asserts both halves so that a
    later change to either cannot pass unnoticed.
    """
    for budget in (0.5, 1e-3, 1e-9, 1e-15, FLOOR_BUDGET):
        assert shortfall_threshold(DEFAULT_PARAMS, budget).fires_at == 1
    deeper = shortfall_threshold(DEFAULT_PARAMS, 1e-25).fires_at
    deepest = shortfall_threshold(DEFAULT_PARAMS, 1e-40).fires_at
    assert deeper is not None and deepest is not None
    assert 1 < deeper < deepest


def test_the_shortfall_bound_falls_as_the_shortfall_grows() -> None:
    """A deeper shortfall is a stronger statement, monotonically."""
    bounds = [
        shortfall_threshold(DEFAULT_PARAMS, budget).false_positive_bound
        for budget in (1e-20, 1e-25, 1e-30, 1e-40)
    ]
    assert bounds == sorted(bounds, reverse=True)
    assert bounds[0] <= HONEST_ABORT_BUDGET


def test_the_pooled_shortfall_is_stated_over_twice_the_trials() -> None:
    """``pooled=True`` uses ``Binomial(2n, p)`` and the pooled floor."""
    threshold = shortfall_threshold(DEFAULT_PARAMS, 1e-25, pooled=True)
    assert f"Binomial({2 * DEFAULT_PARAMS.key_length}" in threshold.null
    assert str(minimum_pooled_matched_count(DEFAULT_PARAMS)) in threshold.null


def test_every_threshold_carries_the_four_things_d7_asks_for() -> None:
    """A null, an inequality, a budget and a proven bound, on every one."""
    built = [
        structural_abort_threshold(1e-9),
        replay_refusal_threshold(1e-9),
        run_shape_threshold(1e-9),
        evidence_abort_threshold(DEFAULT_PARAMS, 1e-9),
        shortfall_threshold(DEFAULT_PARAMS, 1e-9),
    ]
    for threshold in built:
        assert threshold.null and threshold.inequality
        assert threshold.derivation and threshold.detail
        assert 0.0 <= threshold.false_positive_bound <= 1.0
        assert 0.0 < threshold.budget < 1.0
        assert json.loads(json.dumps(threshold.to_dict()))["null"]


def test_the_three_point_mass_checks_cost_exactly_zero_at_every_budget() -> None:
    """Not "small": zero, and unchanged across three hundred decades of budget."""
    for build in (
        structural_abort_threshold,
        replay_refusal_threshold,
        run_shape_threshold,
    ):
        for budget in (0.5, 1e-9, 1e-100, 1e-300):
            threshold = build(budget)
            assert threshold.false_positive_bound == 0.0
            assert threshold.fires_at == 1
            assert threshold.admissible
            assert threshold.inequality == "none -- point mass at 0"


def test_the_structural_null_string_counts_the_reasons_it_describes() -> None:
    """The null names a number of reasons, and the set holds a number of them.

    Nothing else in the suite compares the two, so the string went stale the
    day ``UNAUTHORISED_VERIFIER`` joined
    :data:`~sih141.detect.statistics.STRUCTURAL_ABORT_REASONS` and no test
    noticed. The null is quoted verbatim in ``docs/PHASE4.md`` and in two
    recorded transcripts under ``sih141/web/static/data/recorded/``, so a sixth
    member fails here and the fix is a reword plus
    ``python tools/phase6_fixtures.py``.
    """
    words = ("zero", "one", "two", "three", "four", "five", "six", "seven")
    expected = words[len(STRUCTURAL_ABORT_REASONS)]
    assert (
        f"each of the {expected} structural reasons"
        in structural_abort_threshold(1e-9).null
    )


def test_a_withheld_check_abstains_rather_than_firing() -> None:
    """No admissible operating point means no firing, at any observed count."""
    withheld = evidence_abort_threshold(DEFAULT_PARAMS, 1e-20)
    assert not withheld.admissible
    assert withheld.fires_at is None
    assert not withheld.fires(0)
    assert not withheld.fires(2)
    assert "withheld" in withheld.detail
    assert withheld.false_positive_bound == pytest.approx(
        3 * HONEST_ABORT_BUDGET, rel=1e-12
    , abs=0)


def test_a_demonstration_key_cannot_buy_a_serious_budget() -> None:
    """At ``n = 24`` an abort is a ``1.2e-04`` event, and the check says so."""
    short = evidence_abort_threshold(ProtocolParams(key_length=24), 1e-9)
    assert not short.admissible
    assert short.false_positive_bound == pytest.approx(1.1881e-04, rel=1e-3, abs=0)


@pytest.mark.parametrize(
    "bad", [0.0, 1.0, -1e-9, 2.0, float("nan"), float("inf")]
)
def test_a_budget_outside_the_open_unit_interval_is_refused(bad: float) -> None:
    """``eps`` is an operating point, and ``0`` and ``1`` are not ones."""
    with pytest.raises(ValueError, match="budget"):
        structural_abort_threshold(bad)


def test_a_boolean_budget_is_refused_as_a_type_error() -> None:
    """``True`` is an ``int`` and would silently mean a budget of one."""
    with pytest.raises(TypeError, match="real number"):
        structural_abort_threshold(True)


# --------------------------------------------------------------------------- #
# 2. The bounds against honest data -- checking, never choosing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("length", [192, LENGTH, 600])
def test_honest_runs_raise_no_structural_alarm(length: int) -> None:
    """Twenty honest runs, zero alarms, at every budget a report would use.

    The corollary D7 permits: honest data may *check* a derived threshold. The
    derivation says an honest run fires this family with probability at most
    ``1.6e-19``, so a single alarm in twenty runs would mean the derivation is
    wrong -- not that the threshold needs adjusting.

    Each run is scored at all four budgets, which costs nothing: the session is
    what takes the time, and re-reading one transcript at a second budget is the
    cheapest possible check that the answer really does not move.
    """
    for seed in range(HONEST_TRIALS):
        stats = make_stats(3000 + seed, length=length)
        for budget in (*BUDGETS, TIGHT_BUDGET):
            report = structural_report(stats, eps=budget)
            assert not report.alarm_raised, report.summary()
            assert report.alarms == ()
            assert report.attributions == ()
        assert run_shape_violations(stats) == ()


def test_the_honest_answer_does_not_move_with_the_budget() -> None:
    """Fourteen orders of magnitude of budget, one answer.

    Which is the shape of the family: three of the four checks have a bound of
    zero, so no budget can spoil them, and the fourth is either admissible at
    ``1.6e-19`` or withheld outright.
    """
    stats = make_stats(3100)
    for budget in BUDGETS:
        report = structural_report(stats, eps=budget)
        assert not report.alarm_raised
        assert report.withheld == ()
    tight = structural_report(stats, eps=TIGHT_BUDGET)
    assert not tight.alarm_raised
    assert tight.withheld == (StructuralCheck.EVIDENCE_ABORT,)
    assert tight.false_positive_bound == 0.0


def test_a_withheld_check_makes_the_family_bound_smaller_not_larger() -> None:
    """The union is over the checks *applied*, so withholding one removes a term."""
    stats = make_stats(3101)
    applied = structural_report(stats, eps=1e-9)
    withheld = structural_report(stats, eps=1e-20)
    assert applied.false_positive_bound == pytest.approx(
        3 * HONEST_ABORT_BUDGET, rel=1e-12
    , abs=0)
    assert withheld.false_positive_bound == 0.0


def test_the_family_bound_is_the_sum_of_its_applied_checks() -> None:
    """The union bound is arithmetic somebody can check, not a claim."""
    stats = make_stats(3102)
    report = structural_report(stats, eps=1e-9)
    total = sum(
        threshold.false_positive_bound
        for threshold in report.thresholds
        if threshold.admissible
    )
    assert report.false_positive_bound == pytest.approx(total, rel=1e-12, abs=0)


def test_a_run_without_the_count_exchange_bounds_two_events_not_three() -> None:
    """No Phase C' means no pooled check and no counterpart check."""
    stats = make_stats(3103, count_exchange=no_count_exchange)
    assert not stats.counts_exchanged
    report = structural_report(stats, eps=1e-9)
    assert report.false_positive_bound == pytest.approx(
        2 * HONEST_ABORT_BUDGET, rel=1e-12
    , abs=0)
    assert not report.alarm_raised


def test_the_layer_below_now_agrees_and_the_two_share_one_implementation() -> None:
    """The divergence this test used to pin OPEN is closed. Kept as the pin.

    :attr:`~sih141.detect.statistics.AbortStatistics.honest_bound` used to be
    the constant ``2 * HONEST_ABORT_BUDGET``, described as the run-level bound
    on ``evidence > 0``. The run-level union is over **three** events -- both
    per-verifier floors and the pooled floor -- and
    :mod:`sih141.protocol.verify` derives ``3 eps`` for exactly that reason,
    so ``2 eps`` was smaller than the union bound its own derivation supports
    and was not proven. This test asserted the divergence so that it could not
    be fixed silently or forgotten quietly.

    The Phase 4 reconciliation fixed it, and fixed it the right way round: not
    ``2.0 -> 3.0``, but computed from the run's own sifted parameters, because
    the constant was wrong in both directions and only the function is right in
    both. The two modules now share **one** implementation --
    :func:`~sih141.detect.statistics.floor_shortfall_bound` -- so a run cannot
    be handed two different bounds for one event.
    """
    stats = make_stats(3104)
    assert stats.aborts.honest_bound == evidence_abort_bound(stats.params)
    assert evidence_abort_bound(stats.params) == pytest.approx(
        3 * HONEST_ABORT_BUDGET, rel=1e-12
    , abs=0)
    # Three terms, never two.
    assert stats.aborts.honest_bound > 2 * HONEST_ABORT_BUDGET


def test_the_bound_is_a_function_of_n_which_is_why_no_constant_was_right() -> None:
    """At ``n = 96`` the truth is ``2.5e-17``, above the old constant ``1.08e-19``.

    The second half of the same finding, and the reason the fix could not be
    ``2.0 -> 3.0``: the honest-abort probability is a function of ``n``, and a
    constant cannot be right at both ends.
    """
    short = ProtocolParams(key_length=96)
    assert evidence_abort_bound(short) > 2 * HONEST_ABORT_BUDGET
    assert evidence_abort_bound(short) == pytest.approx(2.4904e-17, rel=1e-3, abs=0)


# --------------------------------------------------------------------------- #
# 3. Refusals are not verdicts, enforced from the wrong side
# --------------------------------------------------------------------------- #


def test_a_run_outcome_has_no_truth_value() -> None:
    """``if outcome:`` is the shape that folds a refusal into a rejection."""
    for outcome in RunOutcome:
        with pytest.raises(TypeError, match="no truth value"):
            bool(outcome)
        with pytest.raises(TypeError, match="no truth value"):
            if outcome:  # noqa: SIM103 -- the point is that this raises
                pass


def test_a_run_outcome_still_behaves_like_the_string_it_is() -> None:
    """The guard removes truthiness and nothing else."""
    assert RunOutcome.REFUSED == "refused-to-score"
    assert f"{RunOutcome.ACCEPTED}" == "accepted"
    assert json.loads(json.dumps({"o": RunOutcome.REJECTED}))["o"] == (
        "rejected"
    )
    assert {RunOutcome.NOT_ASKED: 1}[RunOutcome.NOT_ASKED] == 1
    assert len(set(RunOutcome)) == 4


def test_a_no_verdict_count_refuses_to_be_added_to_a_verdict_count() -> None:
    """The arithmetic form of the same mistake, in the three shapes it takes."""
    refusals = NoVerdictCount(2)
    with pytest.raises(TypeError, match="not a rejection"):
        refusals + 1
    with pytest.raises(TypeError, match="not a rejection"):
        1 + refusals
    with pytest.raises(TypeError, match="not a rejection"):
        sum([NoVerdictCount(1), NoVerdictCount(1)])
    assert NoVerdictCount.total([NoVerdictCount(1), NoVerdictCount(1)]) == 2
    assert refusals + NoVerdictCount(3) == 5
    assert int(refusals) + 1 == 3


def test_a_tally_has_no_field_that_sums_a_refusal_into_a_rejection() -> None:
    """Four counts, and no fifth that quietly adds two of them."""
    stats = make_stats(3200)
    tally = tally_outcomes(stats)
    assert (tally.accepted, tally.rejected) == (2, 0)
    assert (tally.refused, tally.not_asked) == (0, 0)
    for forbidden in ("not_accepted", "failures", "rejected_or_aborted"):
        assert not hasattr(tally, forbidden)
    with pytest.raises(TypeError, match="not a rejection"):
        tally.rejected + tally.refused
    assert tally.verdicts == 2
    assert tally.no_verdicts == 0


def test_a_tally_refuses_to_pool_two_count_orderings() -> None:
    """Phase 3's other pooling rule, enforced by the type rather than by prose."""
    zero = NoVerdictCount(0)
    before = OutcomeTally(2, 0, zero, zero, COUNTS_BEFORE_FORWARDING)
    after = OutcomeTally(0, 2, zero, zero, COUNTS_AFTER_FORWARDING)
    with pytest.raises(ValueError, match="two count orderings"):
        before.merge(after)
    merged = before.merge(before)
    assert (merged.accepted, merged.runs) == (4, 2)


def test_asking_for_a_refusing_partys_verdict_still_raises_upstream() -> None:
    """The layer below refuses; this layer answers, and the answers differ.

    :meth:`~sih141.detect.statistics.TranscriptStatistics.verifier` raises for a
    party who reached no verdict, which is right and awkward.
    :func:`outcome_of` answers for every party -- with a value that cannot be
    read as a rejection.
    """
    stats = make_stats(
        3201,
        forwarder=RecipientForger(rng=np.random.default_rng(4242)),
    )
    refusing = sorted(stats.aborts.by_party)
    assert refusing, "this arm is supposed to produce a refusal"
    for party in refusing:
        with pytest.raises(KeyError, match="not a rejection"):
            stats.verifier(party)
        assert outcome_of(stats, party) is RunOutcome.REFUSED
        assert outcome_of(stats, party) is not RunOutcome.REJECTED


def test_outcomes_always_names_both_verifiers() -> None:
    """A party left out of the mapping is a party counted as something else."""
    stats = make_stats(
        3202,
        forwarder=RecipientForger(rng=np.random.default_rng(4243)),
    )
    assert sorted(outcomes(stats)) == ["Bob", "Charlie"]


def test_alice_is_refused_an_outcome() -> None:
    """She signs, reaches no verdict, and is not a fifth outcome."""
    stats = make_stats(3203)
    with pytest.raises(ValueError, match="reaches no verdict"):
        outcome_of(stats, Party.ALICE)
    with pytest.raises(ValueError, match="names no party"):
        outcome_of(stats, "Mallory")


def test_a_structural_alarm_carries_no_acceptance_field() -> None:
    """There is no ``accepted`` on an alarm, and there will not be one."""
    stats = make_stats(
        3204,
        forwarder=RecipientForger(rng=np.random.default_rng(4244)),
    )
    report = structural_report(stats, eps=1e-9)
    assert report.alarms
    for alarm in report.alarms:
        assert not hasattr(alarm, "accepted")
        assert not hasattr(alarm, "rejected")


# --------------------------------------------------------------------------- #
# 4. The adversaries that force an abort, deterministically
# --------------------------------------------------------------------------- #


def test_count_starvation_forces_an_evidence_abort_every_time() -> None:
    """Forty runs, forty refusals, each attributed to the starving counterpart.

    The denial costs one integer and no probability
    (:ref:`sih141.attacks.starvation <starvation-headroom>`), so the module's
    claim is that the reason is forced with probability one. Forty is a check on
    that claim, not the source of it.
    """
    caught = 0
    for seed in range(TRIALS):
        stats = make_stats(
            700_000 + seed,
            count_exchange=CountStarver(
                rng=np.random.default_rng(9001 + seed)
            ),
        )
        report = structural_report(stats, eps=1e-9)
        assert report.alarm_raised
        checks = {alarm.check for alarm in report.alarms}
        assert checks == {StructuralCheck.EVIDENCE_ABORT}
        assert len(report.attributions) == 1
        attribution = report.attributions[0]
        assert attribution.group == "evidence"
        assert attribution.reason == AbortReason.COUNTERPART_BELOW_FLOOR
        # The refusal names the *other* verifier: Bob refuses because Charlie
        # under-declared. Attribution is the whole remaining question once the
        # bound has settled detection.
        assert attribution.short_party != attribution.party
        assert attribution.shortfall >= 1
        assert attribution.false_positive_bound <= HONEST_ABORT_BUDGET
        # And the denied verifier reached no verdict, which is not a rejection.
        assert (
            report.outcomes[attribution.party] is RunOutcome.REFUSED
        )
        assert (
            report.outcomes[attribution.party] is not RunOutcome.REJECTED
        )
        caught += 1
    assert caught == TRIALS


def test_recipient_forgery_forces_a_structural_abort_under_both_orderings() -> None:
    """Forty runs each way, and the alarm's false-positive probability is zero.

    A substituted declaration makes the two Phase C' counts describe two
    declarations, which the digest check refuses outright
    (:attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`).
    That is a *structural* reason, so the bound is exactly zero -- the strongest
    statement in the family, and it costs nothing.

    Grouped by ``count_exchange_timing`` and never averaged over it: the two
    orderings refuse at different verifiers, which is itself the finding.
    """
    refusing_by_timing: dict[str, set[str]] = {}
    for timing, base in (
        (COUNTS_BEFORE_FORWARDING, 800_000),
        (COUNTS_AFTER_FORWARDING, 810_000),
    ):
        caught = 0
        for seed in range(TRIALS):
            stats = make_stats(
                base + seed,
                forwarder=RecipientForger(
                    rng=np.random.default_rng(4242 + seed)
                ),
                count_exchange_timing=timing,
            )
            report = structural_report(stats, eps=1e-9)
            assert report.count_exchange_timing == timing
            assert report.alarm_raised
            assert {alarm.check for alarm in report.alarms} == {
                StructuralCheck.STRUCTURAL_ABORT
            }
            assert all(
                alarm.false_positive_bound == 0.0 for alarm in report.alarms
            )
            assert len(report.attributions) == 1
            attribution = report.attributions[0]
            assert attribution.group == "structural"
            assert (
                attribution.reason == AbortReason.COUNTS_FROM_TWO_DECLARATIONS
            )
            assert attribution.short_party is None
            assert attribution.shortfall == 0
            assert report.outcomes[attribution.party] is RunOutcome.REFUSED
            refusing_by_timing.setdefault(timing, set()).add(
                attribution.party
            )
            caught += 1
        assert caught == TRIALS
    assert refusing_by_timing[COUNTS_BEFORE_FORWARDING] == {"Charlie"}
    assert refusing_by_timing[COUNTS_AFTER_FORWARDING] == {"Bob"}


def test_a_replay_leaves_a_refusal_count_and_no_abort() -> None:
    """Asking twice is refused, the standing verdict survives, and only one field moves.

    The replay defence keeps the verdict rather than replacing it with the
    refusal -- otherwise a replayed presentation could delete the acceptance
    that spent the round -- so the *only* trace is
    ``replay.total_refusals``. A detector that watched the abort field alone
    would see nothing.
    """
    session = QDSSession(
        ProtocolParams(key_length=LENGTH), rng=np.random.default_rng(3300)
    )
    session.run(0)
    for party in ("Bob", "Charlie"):
        with pytest.raises(MatchedSetTooSmall):
            session.verify(party)
    stats = TranscriptStatistics.from_transcript(session.transcript())
    assert stats.replay.total_refusals == 2
    assert stats.aborts.total == 0
    report = structural_report(stats, eps=1e-9)
    assert {alarm.check for alarm in report.alarms} == {
        StructuralCheck.REPLAY_REFUSAL
    }
    assert report.alarms[0].false_positive_bound == 0.0
    # Both verifiers still hold their verdicts; the replay changed no outcome.
    assert report.outcomes == {
        "Bob": RunOutcome.ACCEPTED,
        "Charlie": RunOutcome.ACCEPTED,
    }
    assert run_shape_violations(stats) == ()


# --------------------------------------------------------------------------- #
# 5. The adversaries that do not, and the checks that must stay quiet
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "seam",
    [
        pytest.param(
            lambda seed: {
                "resource_factory": DepolarisingChannel(
                    0.60, target=Party.BOB, rng=np.random.default_rng(6242 + seed)
                ).resource
            },
            id="depolariser",
        ),
        pytest.param(
            lambda seed: {
                "resource_factory": InterceptResend(
                    target=Party.BOB, rng=np.random.default_rng(6342 + seed)
                ).resource
            },
            id="intercept-resend",
        ),
    ],
)
def test_a_channel_adversary_raises_no_structural_alarm(seam) -> None:
    """Correct, and worth pinning: the matched count is about bases, not errors.

    A channel attack corrupts eigenvalues, and the matched set is decided by
    *basis* agreement -- so no floor moves and nothing structural fires. The
    signal for these lives in the verifier mismatch rate and the per-link QBER,
    which are other families' business. A structural alarm here would mean this
    module had found a way to read a channel through a bookkeeping statistic,
    which is not a thing it should be able to do.
    """
    for seed in range(10):
        stats = make_stats(830_000 + seed, **seam(seed))
        report = structural_report(stats, eps=1e-9)
        assert not report.alarm_raised, report.summary()
        assert run_shape_violations(stats) == ()


def test_an_outside_forger_raises_no_structural_alarm() -> None:
    """He guesses a declaration; he does not break anybody's bookkeeping.

    The run is *rejected*, which is a verdict and belongs to the rate family.
    This family stays silent, and the outcomes say rejected rather than refused
    -- the distinction the whole no-verdict apparatus exists to keep.
    """
    seen = set()
    for seed in range(10):
        stats = make_stats(
            820_000 + seed,
            signer=OutsideForger(rng=np.random.default_rng(5242 + seed)),
        )
        report = structural_report(stats, eps=1e-9)
        assert not report.alarm_raised, report.summary()
        seen.add(report.outcomes["Charlie"])
    assert RunOutcome.REJECTED in seen
    assert RunOutcome.REFUSED not in seen


@pytest.mark.parametrize(
    "scope",
    [
        ImpersonationScope.FULL,
        ImpersonationScope.SIGNING,
        ImpersonationScope.DISTRIBUTION,
    ],
)
def test_impersonation_raises_no_structural_alarm(
    scope: ImpersonationScope,
) -> None:
    """Assumption (AUTH), restated as a measurement rather than argued around.

    Full impersonation is inseparable by assumption and this family does not
    pretend otherwise: Mallory's run is *structurally perfect*, because she runs
    the protocol correctly with her own key. Nothing here fires, which is the
    honest answer.
    """
    for seed in range(8):
        mallory = Impersonator(rng=np.random.default_rng(7242 + seed))
        stats = make_stats(
            850_000 + seed, **impersonation_seams(mallory, scope)
        )
        report = structural_report(stats, eps=1e-9)
        assert not report.alarm_raised, report.summary()


# --------------------------------------------------------------------------- #
# 6. The bookkeeping this family owns
# --------------------------------------------------------------------------- #


def test_the_two_abort_groups_partition_the_reasons_and_both_are_attributed() -> None:
    """A reason added upstream fails here rather than joining a group quietly."""
    assert STRUCTURAL_ABORT_REASONS.isdisjoint(EVIDENCE_ABORT_REASONS)
    assert STRUCTURAL_ABORT_REASONS | EVIDENCE_ABORT_REASONS == set(
        AbortReason
    )
    stats = make_stats(3400)
    # Every reason has an attribution entry, checked by driving the private
    # coercion through the public error path for a reason that has none.
    from sih141.detect.thresholds_structural import _FORCED_BY, _SHORT_PARTY

    assert set(_SHORT_PARTY) == set(AbortReason)
    assert set(_FORCED_BY) == set(AbortReason)
    assert structural_report(stats, eps=1e-9).attributions == ()


def test_the_family_list_covers_every_check_exactly_once() -> None:
    """No check silently absent from a report, and none counted twice."""
    assert len(STRUCTURAL_CHECKS) == len(set(STRUCTURAL_CHECKS))
    assert set(STRUCTURAL_CHECKS) == set(StructuralCheck)
    stats = make_stats(3401)
    report = structural_report(stats, eps=1e-9)
    assert tuple(t.check for t in report.thresholds) == STRUCTURAL_CHECKS


def test_run_shape_holds_on_every_run_this_project_produces() -> None:
    """Six equalities, on honest runs and on all five adversary families.

    Measured rather than assumed, because a violation would be a plumbing
    finding about the file and not a detection -- and this file is where that
    distinction has to be true. The replay arm is the interesting one: it is the
    only family that *touches* the ledger, and even it leaves the shape intact,
    because a refusal spends nothing.
    """
    arms = [
        {},
        {"count_exchange": CountStarver(rng=np.random.default_rng(9500))},
        {"forwarder": RecipientForger(rng=np.random.default_rng(4500))},
        {"signer": OutsideForger(rng=np.random.default_rng(5500))},
        {
            "resource_factory": DepolarisingChannel(
                0.60, target=Party.BOB, rng=np.random.default_rng(6500)
            ).resource
        },
        impersonation_seams(
            Impersonator(rng=np.random.default_rng(7500)),
            ImpersonationScope.FULL,
        ),
    ]
    for index, seams in enumerate(arms):
        stats = make_stats(3500 + index, **seams)
        assert run_shape_violations(stats) == (), (
            f"arm {index} broke the run shape: "
            f"{run_shape_violations(stats)}"
        )
        report = structural_report(stats, eps=1e-9)
        assert StructuralCheck.RUN_SHAPE not in {
            alarm.check for alarm in report.alarms
        }
    # The fifth family, which needs a live session rather than a seam.
    session = QDSSession(
        ProtocolParams(key_length=LENGTH), rng=np.random.default_rng(3510)
    )
    session.run(0)
    with pytest.raises(MatchedSetTooSmall):
        session.verify("Bob")
    replayed = TranscriptStatistics.from_transcript(session.transcript())
    assert replayed.replay.total_refusals == 1
    assert run_shape_violations(replayed) == ()


def test_a_run_shape_alarm_is_not_counted_as_a_detection() -> None:
    """It is a statement about the file; the detection column must not hold it.

    Built by hand rather than by an adversary, because no adversary in the
    threat model produces one -- which is the finding.
    """
    import dataclasses

    from sih141.detect.statistics import ReplayStatistics

    honest = make_stats(3600)
    broken = dataclasses.replace(
        honest,
        replay=ReplayStatistics(
            total_refusals=0,
            refusals_by_party={},
            spent_rounds=0,
            distinct_sessions=0,
            distinct_message_bits=0,
            parties_with_spent_rounds=(),
        ),
    )
    assert run_shape_violations(broken)
    report = structural_report(broken, eps=1e-9)
    assert report.alarm_raised
    assert {alarm.check for alarm in report.alarms} == {
        StructuralCheck.RUN_SHAPE
    }
    assert report.detection_alarms == ()


def test_a_report_round_trips_through_json() -> None:
    """The hand-off to Phase 5 and Phase 6, checked with a strict parser."""

    def reject(token: str) -> float:
        raise AssertionError(f"{token} is not JSON")

    stats = make_stats(
        3700,
        count_exchange=CountStarver(rng=np.random.default_rng(9600)),
    )
    report = structural_report(stats, eps=1e-9)
    text = json.dumps(report.to_dict())
    restored = json.loads(text, parse_constant=reject)
    assert restored["alarm_raised"] is True
    assert restored["count_exchange_timing"] == COUNTS_BEFORE_FORWARDING
    assert restored["outcomes"]["Bob"] in {o.value for o in RunOutcome}
    assert restored["attributions"][0]["short_party"] == "Charlie"


def test_the_layer_draws_no_randomness() -> None:
    """D3: two readings of one transcript give one report."""
    stats = make_stats(3800)
    first = structural_report(stats, eps=1e-9)
    second = structural_report(stats, eps=1e-9)
    assert first == second
    assert first.to_dict() == second.to_dict()


def test_the_point_mass_helper_refuses_a_non_check() -> None:
    """The shared derivation is not a place to put an arbitrary label."""
    with pytest.raises(TypeError, match="StructuralCheck"):
        point_mass_threshold(
            "replay-refusal",
            1e-9,
            statistic="x",
            null="y",
            detail="z",
            derivation="w",
        )


def test_an_unknown_abort_reason_is_refused_rather_than_grouped() -> None:
    """A reason with no home cannot be filed under the weaker bound."""
    import dataclasses

    from sih141.detect.statistics import AbortStatistics

    honest = make_stats(3900)
    invented = dataclasses.replace(
        honest,
        aborts=AbortStatistics(
            total=1,
            by_reason={"a-reason-nobody-derived": 1},
            by_party={"Bob": "a-reason-nobody-derived"},
            structural=0,
            evidence=1,
            honest_bound=2 * HONEST_ABORT_BUDGET,
            shortfalls={"Bob": 1},
        ),
    )
    with pytest.raises(ValueError, match="names no AbortReason"):
        attribute_aborts(invented)


def test_the_exact_bound_reaches_budgets_the_closed_form_cannot() -> None:
    """``exact=True`` moves the wall twelve orders of magnitude down.

    A per-run bound quantifies over nothing, so summing the tails exactly is
    available there even though :func:`minimum_sifted_length` cannot use it.
    """
    tight = evidence_abort_threshold(DEFAULT_PARAMS, 1e-25, exact=True)
    assert tight.admissible
    assert tight.false_positive_bound == pytest.approx(8.0154e-31, rel=1e-3, abs=0)
    assert "exact binomial lower tail" in tight.inequality
    assert not evidence_abort_threshold(
        DEFAULT_PARAMS, 1e-33, exact=True
    ).admissible
    # And it flows through the report, tightening the family bound with it.
    stats = make_stats(3950, length=192)
    assert (
        structural_report(stats, eps=1e-9, exact=True).false_positive_bound
        < structural_report(stats, eps=1e-9).false_positive_bound
    )


def test_a_run_with_no_security_claim_withholds_the_evidence_check() -> None:
    """At ``L = 24`` both floors are ``1`` and an abort is a ``1.2e-04`` event.

    The end-to-end shape of :ref:`finding 2 <findings>`: a detector that fired
    on an abort here would be quoting a ``2**-64`` claim it has not got, so the
    report withholds the check and says so on its own summary line.
    """
    stats = make_stats(3960, length=24)
    assert not stats.security_claim
    report = structural_report(stats, eps=1e-9)
    assert report.withheld == (StructuralCheck.EVIDENCE_ABORT,)
    assert report.false_positive_bound == 0.0
    assert "withheld" in report.summary()


def test_the_guards_on_the_public_surface_refuse_the_obvious_mistakes() -> None:
    """Types and ranges, on the four entry points a caller reaches first."""
    stats = make_stats(3970, length=192)
    with pytest.raises(TypeError, match="TranscriptStatistics"):
        run_shape_violations("not a transcript")
    with pytest.raises(TypeError, match="TranscriptStatistics"):
        structural_report("not a transcript", eps=1e-9)
    with pytest.raises(TypeError, match="ProtocolParams"):
        evidence_abort_bound("not params")
    with pytest.raises(ValueError, match="at least 2"):
        minimum_sifted_length(1e-9, alphabet=1)
    threshold = structural_report(stats, eps=1e-9).thresholds[0]
    with pytest.raises(ValueError, match="non-negative"):
        threshold.fires(-1)
    with pytest.raises(TypeError, match="must be an int"):
        threshold.fires(1.5)
    with pytest.raises(TypeError, match="grouping key"):
        OutcomeTally(1, 0, NoVerdictCount(0), NoVerdictCount(0), 7)
    with pytest.raises(ValueError, match="non-negative"):
        OutcomeTally(-1, 0, NoVerdictCount(0), NoVerdictCount(0), "x")
