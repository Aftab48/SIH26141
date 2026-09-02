"""The Phase 4 reconciliation: three families, one surface.

The three threshold families were derived in parallel by three hands, and each
reported the same two integration problems that none of them could fix from
inside a single family: duplicated helpers that nothing pinned against each
other, and conventions that disagree. This file is the pin.

It exists because of a Phase 3 result rather than out of tidiness. Four copies
of a Wilson interval had drifted and **two of them carried a real bug**; the
copy in :mod:`sih141.protocol.checkrounds` was not part of that consolidation
and still carried it when the Phase 4 statistics layer was written, which
reported it rather than reaching across a layer boundary to fix it. Duplication
that nothing compares is not duplication, it is divergence with a delay.

What is asserted here:

1. **All seven Wilson intervals in the tree agree at the endpoint that ships.**
   The endpoint is the part that mattered: every defended result in this project
   is ``0`` successes out of ``N``.
2. **The three Chernoff lower-tail inversions agree with each other and with
   the protocol's own floor**, which is the arithmetic the whole scheme's
   repudiation bound rests on.
3. **The two exact binomial tails agree with each other and with exact rational
   arithmetic**, which is the only check in the tree that does not share a
   floating-point code path with the thing it is checking.
4. **The two evidence-abort bounds are now one implementation**, so a run
   cannot be handed two different bounds for one event.
5. **The conventions translate**, including the one pair that inverts.
6. **Every shipped threshold answers D7's three questions**, mechanically:
   a null is stated, the bound sits inside its own budget, and the critical
   value is a function of the budget unless the null is a point mass -- in
   which case the bound must be exactly zero, which is a stronger property and
   is checked as such.

Nothing here reads attack data. One test *does* import the four attack modules'
Wilson helpers -- to compare arithmetic, never to read a measurement -- because
the whole point of that test is that every copy in the tree agrees. The shipped
detector's own boundary, that :mod:`sih141.detect` has no static edge to
:mod:`sih141.attacks`, is asserted in ``tests/test_detect_statistics.py``.
"""

from __future__ import annotations

import math
from fractions import Fraction

import pytest

from sih141.core.paulis import PauliBasis
from sih141.detect import (
    ThresholdView,
    chsh_threshold,
    declared_count_threshold,
    matched_count_threshold,
    mismatch_rate_threshold,
    pooled_count_threshold,
    qber_threshold,
    replay_refusal_threshold,
    run_shape_threshold,
    structural_abort_threshold,
    threshold_view,
    wilson_interval,
)
from sih141.detect.statistics import (
    evidence_abort_probability_bound,
    floor_shortfall_bound,
)
from sih141.detect.thresholds_channel import (
    concurrence_threshold,
    fidelity_threshold,
    purity_threshold,
)
from sih141.detect.thresholds_rate import _chernoff_critical, binomial_tail_bound
from sih141.detect.thresholds_channel import _binomial_upper_tails
from sih141.detect.thresholds_structural import (
    chernoff_lower_tail_count,
    evidence_abort_bound,
    evidence_abort_threshold,
    shortfall_threshold,
)
from sih141.protocol.checkrounds import (
    QberObservation,
    _wilson_interval,
    estimate_qber,
)
from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

SAMPLE_SIZES = (1, 2, 5, 12, 50, 97, 400, 1000, 4114, 8000)
CONFIDENCE = 0.99
"""The level :func:`sih141.detect.wilson_interval` defaults to. Passed
explicitly to the protocol's copy, which takes it positionally and has no
default -- a difference in *interface* rather than in arithmetic, and worth
having written down once here."""
BUDGETS = (1e-1, 1e-2, 1e-3, 1e-6, 1e-9, 1e-12, 1e-15, 1e-18, 1e-21, 1e-27)


# ==========================================================================
# 1. The two Wilson intervals
# ==========================================================================


def test_the_two_wilson_intervals_agree_to_the_bit_at_both_endpoints() -> None:
    """The endpoint clamp is the half that had the bug, and the half that ships.

    At zero successes the Wilson centre and spread are equal in exact
    arithmetic, so ``centre - spread`` is mathematically zero and evaluates to
    ``6.938893903907228e-18`` in IEEE 754 for some ``n``. A
    ``max(0.0, centre - spread)`` returns the dust, because the dust is
    positive. Every defended result in this project is ``0`` successes out of
    ``N``, so that is precisely the number a published table quotes.

    Both copies now clamp by case. Asserted as exact equality rather than
    ``pytest.approx``, because approximate agreement is what the two had
    before.
    """
    for total in SAMPLE_SIZES:
        ours = wilson_interval(0, total)
        theirs = _wilson_interval(0, total, CONFIDENCE)
        assert ours.low == 0.0 == theirs[0], (
            f"the lower endpoint at 0 successes out of {total} is "
            f"{ours.low!r} here and {theirs[0]!r} in the protocol"
        )
        assert ours.high == theirs[1]

        ours_full = wilson_interval(total, total)
        theirs_full = _wilson_interval(total, total, CONFIDENCE)
        assert ours_full.high == 1.0 == theirs_full[1]
        assert ours_full.low == theirs_full[0]


def test_the_two_wilson_intervals_agree_off_the_endpoints_too() -> None:
    """Agreement away from the clamp, so the fix did not move the closed form."""
    for total in (12, 50, 400, 4114):
        for hits in (1, total // 3, total // 2, total - 1):
            ours = wilson_interval(hits, total)
            theirs = _wilson_interval(hits, total, CONFIDENCE)
            assert ours.low == theirs[0]
            assert ours.high == theirs[1]


def test_every_wilson_interval_in_the_tree_agrees_at_zero_successes() -> None:
    """Seven copies, one endpoint, and it is the endpoint that ships.

    Phase 3 consolidated four copies in :mod:`sih141.attacks` after two of them
    were found to carry the ``max(0.0, centre - spread)`` dust. The copy in
    :mod:`sih141.protocol.checkrounds` was not part of that round and carried it
    until Phase 4. This asserts the whole tree at once, at zero successes --
    which is where **every defended result in this project lands**, so it is the
    number a published table actually quotes.

    Exact equality with ``0.0``, not ``pytest.approx``: approximate agreement is
    what the copies had before, and ``6.9e-18`` passes any tolerance loose
    enough to be worth writing.
    """
    from sih141.attacks.forgery import wilson_interval as forgery_wilson
    from sih141.attacks.impersonation import wilson_interval as impersonation_wilson
    from sih141.attacks.replay import wilson_interval as replay_wilson
    from sih141.attacks.starvation import wilson_interval as starvation_wilson
    from sih141.attacks.statistics import wilson_bounds

    def low(interval: object) -> float:
        return (
            interval.low  # type: ignore[union-attr]
            if hasattr(interval, "low")
            else interval[0]  # type: ignore[index]
        )

    for total in (12, 50, 400, 4114):
        endpoints = {
            "attacks.forgery": low(forgery_wilson(0, total)),
            "attacks.impersonation": low(impersonation_wilson(0, total)),
            "attacks.replay": low(replay_wilson(0, total)),
            "attacks.starvation": low(starvation_wilson(0, total)),
            "attacks.statistics": low(wilson_bounds(0, total)),
            "detect.statistics": low(wilson_interval(0, total, confidence=0.95)),
            "protocol.checkrounds": low(_wilson_interval(0, total, 0.95)),
        }
        assert set(endpoints.values()) == {0.0}, (
            f"at 0 successes out of {total} the tree disagrees: "
            f"{ {k: repr(v) for k, v in endpoints.items() if v != 0.0} }"
        )


def test_a_clean_qber_sample_reports_a_plain_zero() -> None:
    """The end-to-end consequence, on the object a Phase 5 table reads."""
    clean = [QberObservation(i, PauliBasis.Z, 1, 1) for i in range(50)]
    estimate = estimate_qber(clean)
    assert estimate.errors == 0
    assert estimate.interval.low == 0.0
    assert repr(estimate.interval.low) == "0.0"


# ==========================================================================
# 2. Three Chernoff lower tails, and the protocol's own floor
# ==========================================================================


def test_the_three_chernoff_inversions_agree_with_each_other() -> None:
    """Three copies of one inversion, compared for the first time.

    ``thresholds_rate._chernoff_critical``,
    ``thresholds_structural.chernoff_lower_tail_count`` and
    ``protocol.verify._chernoff_floor`` all invert

    .. code-block:: text

        P(S <= (1 - d) mu) <= exp(-d^2 mu / 2),   d = sqrt(2 ln(1/eps) / mu)

    Each family pinned its copy against the protocol's; none could pin them
    against each other, because none owned all three. This does.
    """
    for trials in (192, 384, 600, 4114, 115200, 230400):
        for eps in (HONEST_ABORT_BUDGET, 1e-9, 1e-15):
            rate = _chernoff_critical(trials, 1 / 3, eps=eps, side="lower")
            structural = chernoff_lower_tail_count(trials, 1 / 3, eps)
            # A THIRD spelling of the same fact, found by writing this test:
            # where the multiplicative form has no power the rate family
            # returns -1 and the structural family returns None. Both mean "no
            # count is refusable at this budget and this sample size". They are
            # required to agree on WHEN that happens as well as on the value,
            # because a caller that read -1 as a count would refuse every run.
            assert (rate < 0) == (structural is None), (
                f"the two families disagree about whether the Chernoff lower "
                f"tail has any power at trials={trials}, eps={eps:g}: rate "
                f"says {rate!r}, structural says {structural!r}"
            )
            if structural is None:
                continue
            assert rate == structural, (
                f"the rate family says {rate} and the structural family says "
                f"{structural} for the same Chernoff lower tail at "
                f"trials={trials}, eps={eps:g}"
            )


def test_the_chernoff_inversion_still_reproduces_both_protocol_floors() -> None:
    """The arithmetic the scheme's repudiation bound rests on, at three lengths.

    A floor is ``critical + 1``: the floor is the smallest count that is *not*
    refused, and the critical count is the largest that is.
    """
    for params in (
        DEFAULT_PARAMS,
        ProtocolParams(key_length=600),
        ProtocolParams(key_length=4096),
    ):
        length = params.key_length
        own = chernoff_lower_tail_count(length, 1 / 3, HONEST_ABORT_BUDGET)
        pooled = chernoff_lower_tail_count(2 * length, 1 / 3, HONEST_ABORT_BUDGET)
        assert own is not None and pooled is not None
        assert own + 1 == minimum_matched_count(params)
        assert pooled + 1 == minimum_pooled_matched_count(params)


def test_the_chernoff_inversion_really_sits_inside_its_budget() -> None:
    """The proof, checked against the TRUE tail in exact rational arithmetic.

    An inversion that returned a plausible-looking constant would pass every
    agreement test above -- all three copies would simply be wrong together.
    This computes the exact binomial lower tail at the returned count with
    :class:`fractions.Fraction` and requires it to sit inside the budget the
    inversion was given.
    """
    for trials in (192, 384, 600):
        for eps in (1e-3, 1e-9, HONEST_ABORT_BUDGET):
            count = chernoff_lower_tail_count(trials, 1 / 3, eps)
            if count is None:
                continue
            tail = _exact_tail(count, trials, Fraction(1, 3), side="lower")
            assert float(tail) <= eps, (
                f"the Chernoff inversion returned {count} at eps={eps:g} for "
                f"trials={trials}, whose true lower tail is {float(tail):.4e}"
            )


# ==========================================================================
# 3. Two exact binomial tails, against exact rational arithmetic
# ==========================================================================


def _exact_tail(count: int, trials: int, p: Fraction, *, side: str) -> Fraction:
    """The binomial tail in exact rational arithmetic. No floating point."""
    q = Fraction(1) - p
    lo, hi = (count, trials) if side == "upper" else (0, count)
    lo, hi = max(lo, 0), min(hi, trials)
    return sum(
        (Fraction(math.comb(trials, k)) * p**k * q ** (trials - k)
         for k in range(lo, hi + 1)),
        Fraction(0),
    )


def test_the_two_exact_tail_implementations_agree_with_exact_rationals() -> None:
    """The rate family sums through ``lgamma``; the channel family accumulates.

    Neither shares a code path with the other, and neither shares one with
    :class:`fractions.Fraction`. Agreement to a relative ``1e-12`` across both
    tails is therefore evidence about the arithmetic rather than about one
    implementation reproducing itself.
    """
    trials, p = 200, Fraction(1, 64)
    channel = _binomial_upper_tails(trials, float(p))
    for count in (0, 1, 2, 3, 5, 10, 20, 40):
        truth = float(_exact_tail(count, trials, p, side="upper"))
        rate = binomial_tail_bound(
            count, trials, float(p), side="upper", method="exact"
        )
        assert rate == pytest.approx(truth, rel=1e-12, abs=1e-300)
        assert channel[count] == pytest.approx(truth, rel=1e-12, abs=1e-300)
        assert rate == pytest.approx(channel[count], rel=1e-12, abs=1e-300)


def test_the_exact_lower_tail_agrees_with_exact_rationals() -> None:
    """The other tail, which only one of the two families implements."""
    trials, p = 192, Fraction(1, 3)
    for count in (0, 5, 20, 40, 64, 100):
        truth = float(_exact_tail(count, trials, p, side="lower"))
        got = binomial_tail_bound(
            count, trials, float(p), side="lower", method="exact"
        )
        assert got == pytest.approx(truth, rel=1e-12, abs=1e-300)


# ==========================================================================
# 4. One evidence-abort bound, not two
# ==========================================================================


def test_the_evidence_abort_bound_has_exactly_one_implementation() -> None:
    """The structural family delegates; the statistics layer computes.

    Before the reconciliation there were two answers to one question, and they
    disagreed: :attr:`AbortStatistics.honest_bound` was the constant
    ``2 * 2**-64`` while the structural family derived a union over **three**
    events that is a function of ``n``. The constant was wrong in both
    directions -- smaller than the union bound its own derivation supports,
    and far too small at short key lengths, where an honest abort is not rare
    at all.
    """
    for length in (24, 96, 136, 137, 272, 273, 600, 4096, 115200):
        params = ProtocolParams(key_length=length)
        assert evidence_abort_probability_bound(params) == evidence_abort_bound(
            params
        )
        assert evidence_abort_probability_bound(
            params, counts_exchanged=False
        ) == evidence_abort_bound(params, counts_exchanged=False)


def test_the_evidence_bound_is_three_terms_and_not_two() -> None:
    """It settles on three times the floors' own budget, never two."""
    assert evidence_abort_probability_bound(DEFAULT_PARAMS) == 3 * HONEST_ABORT_BUDGET
    assert (
        evidence_abort_probability_bound(DEFAULT_PARAMS, counts_exchanged=False)
        == 2 * HONEST_ABORT_BUDGET
    )
    # And it is a function of n, not a constant: an honest abort at n = 24 is
    # fifteen orders of magnitude more likely than at DEFAULT_PARAMS.
    short = evidence_abort_probability_bound(ProtocolParams(key_length=24))
    assert short > 1e-5
    assert short > 1e14 * evidence_abort_probability_bound(DEFAULT_PARAMS)


def test_the_shared_floor_term_refuses_to_assert_an_unproven_bound() -> None:
    """Where neither regime applies the honest answer is 1.0, not ``eps0``.

    A sample too small for the Chernoff form to have power, with a floor above
    ``1`` so the event is not ``{count == 0}`` either, has had *nothing*
    proven about it. Returning the budget there would be asserting a bound
    rather than deriving one, which is the exact failure D7 exists to prevent.
    """
    assert floor_shortfall_bound(24, 1 / 3, 3) == 1.0
    assert floor_shortfall_bound(115200, 1 / 3, 36555) == HONEST_ABORT_BUDGET
    # The degenerate floor takes the exact term, and it is far tighter.
    assert floor_shortfall_bound(267, 1 / 3, 1) == pytest.approx((2 / 3) ** 267)
    assert floor_shortfall_bound(267, 1 / 3, 1) < HONEST_ABORT_BUDGET


# ==========================================================================
# 5. The conventions translate, including the pair that inverts
# ==========================================================================


def _one_of_each() -> tuple[object, ...]:
    return (
        matched_count_threshold(192, 1 / 3, eps=1e-9, side="lower"),
        declared_count_threshold(192, 1 / 3, eps=1e-9, side="upper"),
        pooled_count_threshold(192, 1 / 3, eps=1e-9, side="lower"),
        mismatch_rate_threshold(64, eps=1e-9),
        qber_threshold(rounds=24, epsilon=1e-9),
        chsh_threshold(counts=(6, 6, 6, 6), epsilon=1e-9),
        fidelity_threshold(samples=24, epsilon=1e-9),
        purity_threshold(samples=24, epsilon=1e-9),
        concurrence_threshold(samples=24, epsilon=1e-9),
        structural_abort_threshold(1e-9),
        replay_refusal_threshold(1e-9),
        run_shape_threshold(1e-9),
        evidence_abort_threshold(DEFAULT_PARAMS, 1e-9),
        shortfall_threshold(DEFAULT_PARAMS, 1e-9),
    )


def test_every_carrier_reads_through_one_vocabulary() -> None:
    """All three families, one view, and the fields it promises are populated."""
    for threshold in _one_of_each():
        view = threshold_view(threshold)
        assert isinstance(view, ThresholdView)
        assert view.family in {"rate", "channel", "structural"}
        assert view.null.strip(), f"{view.statistic} states no null"
        assert view.inequality.strip()
        assert view.derivation.strip()
        assert 0.0 <= view.false_positive_bound <= 1.0
        assert view.to_dict()["family"] == view.family


def test_the_inverted_convention_reads_the_same_way_round_in_the_view() -> None:
    """``vacuous`` and ``reaches_its_statistic`` are the same fact, inverted.

    This is the trap all three family authors flagged and none could close: a
    combiner reading one where it meant the other flips "this sample can detect
    nothing" into "this sample is fine", silently, in the direction that
    manufactures a clean bill of health.
    """
    silent_rate = matched_count_threshold(8, 1 / 3, eps=1e-30, side="lower")
    assert silent_rate.vacuous is True
    assert threshold_view(silent_rate).can_fire is False

    silent_channel = chsh_threshold(counts=(2, 2, 2, 2), epsilon=1e-9)
    assert silent_channel.reaches_its_statistic is False
    assert threshold_view(silent_channel).can_fire is False

    live_rate = matched_count_threshold(192, 1 / 3, eps=1e-9, side="lower")
    live_channel = chsh_threshold(counts=(6, 6, 6, 6), epsilon=1e-9)
    assert live_rate.vacuous is False
    assert live_channel.reaches_its_statistic is True
    assert threshold_view(live_rate).can_fire is True
    assert threshold_view(live_channel).can_fire is True

    # A structural check spells it a third way -- as None.
    withheld = evidence_abort_threshold(DEFAULT_PARAMS, 1e-20)
    assert withheld.fires_at is None
    assert threshold_view(withheld).can_fire is False


def test_a_certificate_is_the_only_non_alarm_and_the_view_says_so() -> None:
    """Failing to certify is not a detection; the view must not blur the two."""
    from sih141.detect import chsh_certificate_threshold

    certificate = threshold_view(
        chsh_certificate_threshold(counts=(6, 6, 6, 6), epsilon=1e-9)
    )
    assert certificate.is_alarm is False
    assert all(threshold_view(t).is_alarm for t in _one_of_each())


def test_the_view_refuses_to_guess_at_a_foreign_object() -> None:
    """Not duck-typed, on purpose: guessing is how the inverted pair is misread."""
    with pytest.raises(TypeError, match="opposite senses"):
        threshold_view(object())


# ==========================================================================
# 6. D7, asked of every shipped threshold mechanically
# ==========================================================================


def test_every_threshold_states_a_null_and_proves_a_bound_inside_its_budget() -> None:
    """D7 questions one and two, as assertions rather than as prose.

    A threshold that cannot answer these is fitted whatever its docstring says.
    """
    for threshold in _one_of_each():
        view = threshold_view(threshold)
        assert view.null.strip(), f"{view.statistic}: no null stated"
        assert view.inequality.strip(), f"{view.statistic}: no inequality named"
        assert view.false_positive_bound <= view.budget * (1 + 1e-9), (
            f"{view.statistic} proves {view.false_positive_bound:.4e} against "
            f"a budget of {view.budget:.4e}, i.e. it overspends"
        )


@pytest.mark.parametrize(
    ("label", "make", "point_mass"),
    [
        ("matched_count lower",
         lambda e: matched_count_threshold(192, 1 / 3, eps=e, side="lower"), False),
        ("matched_count upper",
         lambda e: matched_count_threshold(192, 1 / 3, eps=e, side="upper"), False),
        ("declared_count lower",
         lambda e: declared_count_threshold(192, 1 / 3, eps=e, side="lower"), False),
        ("pooled_count lower",
         lambda e: pooled_count_threshold(192, 1 / 3, eps=e, side="lower"), False),
        ("pooled_count upper",
         lambda e: pooled_count_threshold(192, 1 / 3, eps=e, side="upper"), False),
        ("mismatch_rate noiseless",
         lambda e: mismatch_rate_threshold(64, eps=e), True),
        ("mismatch_rate p_e=0.01",
         lambda e: mismatch_rate_threshold(200, eps=e, channel_error_rate=0.01), False),
        ("qber noiseless", lambda e: qber_threshold(rounds=24, epsilon=e), True),
        ("qber p0=1/32",
         lambda e: qber_threshold(
             rounds=4114, epsilon=e, tolerated_depolarising=1 / 32), False),
        ("chsh", lambda e: chsh_threshold(counts=(6, 6, 6, 6), epsilon=e), False),
        ("fidelity ideal", lambda e: fidelity_threshold(samples=24, epsilon=e), True),
        ("fidelity p0=1/32",
         lambda e: fidelity_threshold(
             samples=8229, epsilon=e, tolerated_depolarising=1 / 32), False),
        ("purity ideal", lambda e: purity_threshold(samples=24, epsilon=e), True),
        ("concurrence ideal",
         lambda e: concurrence_threshold(samples=24, epsilon=e), True),
        ("structural-abort", structural_abort_threshold, True),
        ("replay-refusal", replay_refusal_threshold, True),
        ("run-shape", run_shape_threshold, True),
    ],
)
def test_a_threshold_is_a_function_of_its_budget_or_a_point_mass(
    label: str, make, point_mass: bool
) -> None:
    """D7's third question in the form a test can ask: does it MOVE with eps?

    A derived threshold is a function of its false-positive budget. A number
    somebody chose is not. Sweeping eps over ten decades separates the two
    without needing a single attack run, which is what makes it the right test
    for this convention: fitting is detected by the shape of the dependence, not
    by comparing against data the detector must never see.

    The exception is a point-mass null, whose critical value cannot move
    because the null puts all its mass on one value. That is not a constant
    smuggled in -- it is a **stronger** claim, and it is asserted as one: the
    proven false-positive bound must be exactly ``0.0`` at every budget.
    """
    views = [threshold_view(make(eps)) for eps in BUDGETS]
    criticals = [v.critical_value for v in views]

    if point_mass:
        assert len(set(criticals)) == 1, (
            f"{label} claims a point-mass null but its critical value moves "
            f"with the budget: {criticals}"
        )
        assert all(v.false_positive_bound == 0.0 for v in views), (
            f"{label} is constant in eps WITHOUT an exactly-zero bound, which "
            f"is the signature of a chosen number rather than a point mass: "
            f"{[v.false_positive_bound for v in views]}"
        )
        return

    assert len(set(criticals)) > 1, (
        f"{label} returns the same critical value {criticals[0]!r} at every "
        f"budget from {BUDGETS[0]:g} to {BUDGETS[-1]:g}, which is what a "
        f"fitted constant looks like"
    )
    # Monotone in the budget: a smaller budget can only move the threshold
    # further from the null's mean, never nearer.
    ordered = criticals if views[0].direction == "upper" else criticals[::-1]
    assert ordered == sorted(ordered), (
        f"{label} is not monotone in its budget: {criticals}"
    )
    assert all(v.false_positive_bound <= v.budget * (1 + 1e-9) for v in views)
