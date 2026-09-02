"""Phase 4 layer two: the rate-and-count thresholds, and the proofs behind them.

This file pins :mod:`sih141.detect.thresholds_rate`, the family convention
**D7** is hardest on: the verifier mismatch rate and the two matched counts are
the strongest and cheapest signals in the scheme, which makes them the ones most
worth fitting and therefore the ones that must most visibly not be fitted. It is
organised around the seven claims the family rests on, because each is a place
the module could be wrong while still producing a table that looked right.

1. **The inversions are certified, and they are tight.** Section 1 checks the
   direction that actually matters -- that the *returned* threshold's tail is at
   or below the budget it was derived at -- for every inequality, both tails and
   a grid of key lengths and budgets. It then checks tightness the only way that
   means anything: one step more sensitive and the same proof fails. The exact
   tail is compared against :class:`fractions.Fraction` rational arithmetic, so
   "exact" is a claim about this code and not only about the mathematics.
2. **The protocol's own floors come back out.** Section 2 reproduces
   :func:`~sih141.protocol.verify.minimum_matched_count` and
   :func:`~sih141.protocol.verify.minimum_pooled_matched_count` to the integer
   through a completely separate code path, at the protocol's own budget and
   inequality. Two implementations of one derivation agreeing is worth more than
   either of them alone, and it is what makes the sharper thresholds in the same
   section a *finding* rather than a discrepancy.
3. **The honest-run false-positive rate respects the proven bound.** Section 3
   is the corollary D7 permits -- checking a derived threshold against honest
   data is allowed, choosing one from attack data is not. It measures at a
   budget loose enough that false positives actually happen, because a
   measurement of "0 out of 100" at ``eps = 1e-9`` cannot distinguish a correct
   derivation from an arithmetic error that made every threshold unreachable.
4. **The separations are the ones Phase 3 measured.** Section 4 confirms
   constraint 5 from the closed form: recipient forgery moves a verifier's
   matched count ``9.80`` honest standard deviations at ``L = 192`` and ``240``
   at :data:`~sih141.protocol.params.DEFAULT_PARAMS`, and pooling the two counts
   costs exactly ``sqrt(2)`` of that.
5. **The family bound is a union bound over a fixed roster.** Section 6 pins the
   roster, the split and the arithmetic, and pins the two refusals that keep the
   bound honest: a family will not score a run drawn from a different null -- a
   threshold applied to the wrong ``n`` carries no bound at all -- and, at a
   positive noise level, will not score a run other than the one its mismatch
   members were *conditioned* on. It also pins the distinction the family
   reports rather than hides: which of the two numbers (the summed bound or
   ``eps``) is the unconditional one.
6. **A flag is not a rejection.** Section 7 pins the relation to ``s_a`` and
   ``s_v``: they are noise and forgery budgets, not false-positive budgets. On
   a noiseless link the detector is stricter than either cut; at the noise level
   the scheme was sized to tolerate the crossover has already passed Bob's tight
   ``s_a`` -- so against him the detector adds nothing there -- while it is
   still on the useful side of Charlie's looser ``s_v``. The crossover belongs
   to the cut, not to the detector, and it is reported per party. Section 8
   pins that a party who reached no verdict contributes nothing to either
   column.
7. **It is measured on attacks, never fitted to them.** Section 10 runs the
   shipped adversaries through the shipped thresholds and records what fires.
   Not one number in :mod:`sih141.detect.thresholds_rate` was chosen by looking
   at these runs, and the tests are written so that a future author who tried
   would have to delete a comment saying so.

Notes
-----
Determinism (D3)
    Every session is seeded through an injected
    :class:`numpy.random.Generator`, adversaries own their own streams (D6), and
    one test asserts the threshold layer itself consumes no randomness.
No machine learning (D4)
    Two named inequalities -- the multiplicative Chernoff bound in both its
    forms and Hoeffding -- plus one exact cdf and one union bound. Not one
    number in the module under test was chosen because it separated the attack
    runs in section 10, and there is no tolerance in this file that was widened
    to make an assertion pass: the false-positive checks compare against a
    surprise computed from the null being tested, every ``pytest.approx`` is
    floating-point equality rather than a band, and the two ``abs=5e-6`` are
    the bisection resolution
    :func:`~sih141.detect.thresholds_rate.dominance_noise_level` was asked for.
"""

from __future__ import annotations

import json
import math
import pathlib
from fractions import Fraction

import numpy as np
import pytest

from sih141.attacks.channel import DepolarisingChannel
from sih141.attacks.forgery import RecipientForger
from sih141.attacks.impersonation import (
    ImpersonationScope,
    Impersonator,
    impersonation_seams,
)
from sih141.attacks.starvation import CountStarver
from sih141.detect.statistics import TranscriptStatistics
from sih141.detect.thresholds_rate import (
    EXACT_TRIALS_LIMIT,
    INEQUALITIES,
    RATE_COUNT_FREE_TESTS,
    RATE_COUNT_ROSTER,
    DerivedThreshold,
    RateCountThresholds,
    binomial_tail_bound,
    critical_count,
    declared_count_threshold,
    dominance_noise_level,
    floor_comparison,
    forgery_separation_sigma,
    matched_count_threshold,
    mismatch_rate_threshold,
    pooled_count_threshold,
)
from sih141.protocol.params import (
    DEFAULT_PARAMS,
    VERIFIERS,
    Party,
    ProtocolParams,
)
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
)
from sih141.protocol.tally import no_count_exchange
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

#: Key length for the honest corpus. Above the ``140`` below which both floors
#: degenerate and a run carries no security claim, and short enough that a
#: hundred runs cost about forty seconds.
LENGTH = 192

#: How many honest runs the false-positive measurement is taken over. Chosen for
#: runtime, and its power is worth stating rather than assuming: at
#: :data:`LOOSE_BUDGET` the family's proven per-run bound is about ``0.39``, and
#: a hundred runs flags a derivation whose true rate is ``0.69`` or worse at a
#: surprise of ``1e-9``. So this corpus catches a badly wrong derivation and
#: would not catch a mildly optimistic one -- which is why the assertion is
#: against the *proven bound* and not against a second measurement.
HONEST_RUNS = 100

#: The budget the loose false-positive measurement is taken at. Deliberately
#: enormous by this project's standards: at ``1e-9`` no honest run in a corpus
#: this size would ever fire, and a measurement of zero cannot tell a correct
#: derivation from thresholds that were accidentally made unreachable.
LOOSE_BUDGET = 0.5

#: The budget the "no honest run is flagged" check is taken at. A serious
#: operating point: the family's proven per-run bound there is a few times
#: ``1e-10``, so a hundred runs should produce exactly no flags and a single one
#: would be outside anything the derivation permits.
SERIOUS_BUDGET = 1e-9

#: How surprising an observation has to be, under its own null, before this file
#: calls it a failure. Not a tuned tolerance: it is a probability the test
#: computes from the null it is testing, so widening it would mean accepting a
#: more surprising result rather than a wider band.
SURPRISE = 1e-9

_MODULE = pathlib.Path(__file__).resolve().parents[1] / "sih141" / "detect"


def _session_rng(index: int) -> np.random.Generator:
    """Return the session's own generator for a seed index.

    Parameters
    ----------
    index : int
        Seed index.

    Returns
    -------
    numpy.random.Generator
    """
    return np.random.default_rng(70_000 + index)


def _attack_rng(index: int) -> np.random.Generator:
    """Return an adversary's own generator, disjoint from the session's (D6).

    Parameters
    ----------
    index : int
        Seed index.

    Returns
    -------
    numpy.random.Generator
    """
    return np.random.default_rng(910_000 + index)


_CORPUS: dict[tuple[int, str], list[TranscriptStatistics]] = {}


def _honest_corpus(
    runs: int = HONEST_RUNS,
    length: int = LENGTH,
    timing: str = COUNTS_BEFORE_FORWARDING,
) -> tuple[TranscriptStatistics, ...]:
    """Return a cached prefix of a corpus of honest runs, as layer-one statistics.

    Cached and *grown* rather than rebuilt, because the sessions are the
    expensive part of this file and a caller who wants twenty runs should get
    the first twenty of the hundred somebody else already paid for. Keyed on
    the run shape and indexed by seed, so a prefix is always the same prefix:
    every section scores the *same* honest arm and a discrepancy between two
    sections is a real discrepancy rather than two different samples.

    The two count-exchange orderings get separate caches and are never mixed,
    for the reason Phase 3's constraint 6 gives.

    Parameters
    ----------
    runs : int, optional
        How many.
    length : int, optional
        Key length.
    timing : str, optional
        Which count-exchange ordering. Never pooled with the other one.

    Returns
    -------
    tuple of TranscriptStatistics
    """
    key = (length, timing)
    built = _CORPUS.setdefault(key, [])
    for index in range(len(built), runs):
        built.append(
            TranscriptStatistics.from_transcript(
                QDSSession(
                    ProtocolParams(key_length=length),
                    count_exchange_timing=timing,
                    rng=_session_rng(index),
                ).run(index % 2)
            )
        )
    return tuple(built[:runs])


def _rational_tail(
    count: int, trials: int, numerator: int, denominator: int, side: str
) -> float:
    """Return a binomial tail computed in exact rational arithmetic.

    The independent check behind the word "exact". Rational throughout, summed
    over every term, and converted to a float only at the end.

    Parameters
    ----------
    count : int
        The tail's endpoint, included.
    trials : int
        Trial count.
    numerator, denominator : int
        The success probability as an exact fraction.
    side : {'lower', 'upper'}
        Which tail.

    Returns
    -------
    float
    """
    probability = Fraction(numerator, denominator)
    complement = 1 - probability
    span = (
        range(0, count + 1) if side == "lower" else range(count, trials + 1)
    )
    total = sum(
        math.comb(trials, index)
        * probability**index
        * complement ** (trials - index)
        for index in span
    )
    return float(total)


def _surprise(observed: int, runs: int, bound: float) -> float:
    """Return an upper bound on ``P(at least this many fires)`` under the bound.

    Each honest run fires with probability at most ``bound`` and the runs are
    independent, so the number of fires is stochastically dominated by
    ``Binomial(runs, bound)`` and its upper tail bounds the surprise. Using the
    module's own tail here is deliberate: section 1 has already checked that
    function against exact rational arithmetic, so it is a checked tool by the
    time this section leans on it.

    Parameters
    ----------
    observed : int
        Fires counted.
    runs : int
        Corpus size.
    bound : float
        The proven per-run firing probability.

    Returns
    -------
    float
    """
    if bound <= 0.0:
        return 0.0 if observed > 0 else 1.0
    return binomial_tail_bound(observed, runs, bound, side="upper")


# --------------------------------------------------------------------------- #
# 1. The inversions are certified, and tight
# --------------------------------------------------------------------------- #

_GRID = [
    pytest.param(trials, budget, method, id=f"n{trials}-e{budget:g}-{method}")
    for trials in (48, 192, 600, 4096)
    for budget in (1e-2, 1e-6, 1e-12, HONEST_ABORT_BUDGET)
    for method in (*INEQUALITIES, "sharpest")
]


@pytest.mark.parametrize(("trials", "budget", "method"), _GRID)
def test_a_lower_threshold_is_certified_at_its_own_budget(
    trials, budget, method
):
    """``P(S <= k) <= eps``, checked at the ``k`` the inversion returned.

    The direction that matters. Deriving ``k`` from an inequality and then
    *evaluating* that inequality at the realised integer ``k`` closes the gap
    a floor or a ceiling opens: it is where an off-by-one in D-1 would live.
    """
    found = critical_count(
        trials, 1 / 3, eps=budget, side="lower", method=method
    )
    if found < 0:
        return  # vacuous: the detector is silent, and silence cannot misfire
    assert (
        binomial_tail_bound(found, trials, 1 / 3, side="lower", method="exact")
        <= budget
    )


@pytest.mark.parametrize(("trials", "budget", "method"), _GRID)
def test_an_upper_threshold_is_certified_at_its_own_budget(
    trials, budget, method
):
    """``P(S >= k) <= eps``, checked at the ``k`` the inversion returned."""
    found = critical_count(
        trials, 1 / 3, eps=budget, side="upper", method=method
    )
    if found > trials:
        return  # vacuous
    assert (
        binomial_tail_bound(found, trials, 1 / 3, side="upper", method="exact")
        <= budget
    )


@pytest.mark.parametrize("trials", [48, 192, 600, 4096])
@pytest.mark.parametrize("budget", [1e-2, 1e-6, 1e-12])
def test_the_exact_inversion_cannot_be_pushed_one_step_further(
    trials, budget
):
    """One count more sensitive and the exact tail exceeds the budget.

    Certification alone is satisfied by a threshold that never fires, so this
    is the other half: the returned count is the *extreme* admissible one, and
    a Phase 5 ROC built on it is not leaving power on the table.
    """
    low = critical_count(trials, 1 / 3, eps=budget, side="lower", method="exact")
    assert (
        binomial_tail_bound(
            low + 1, trials, 1 / 3, side="lower", method="exact"
        )
        > budget
    )
    high = critical_count(
        trials, 1 / 3, eps=budget, side="upper", method="exact"
    )
    assert (
        binomial_tail_bound(
            high - 1, trials, 1 / 3, side="upper", method="exact"
        )
        > budget
    )


@pytest.mark.parametrize("count", [0, 11, 26, 48, 64, 70, 100, 106, 128])
def test_the_exact_tail_agrees_with_rational_arithmetic(count):
    """"Exact" is a claim about this code, not only about the mathematics.

    Both tails at ``n = 192`` against :class:`fractions.Fraction`, summed over
    every term with no early exit and no floating point until the last line.
    The residual is ordinary ``lgamma`` error, and pinning its size is what
    lets the module's docstring say how exact "exact" is instead of implying
    it is exact to the bit.
    """
    for side in ("lower", "upper"):
        reference = _rational_tail(count, 192, 1, 3, side)
        ours = binomial_tail_bound(
            count, 192, 1 / 3, side=side, method="exact"
        )
        assert reference > 0.0
        assert abs(ours - reference) <= 1e-12 * reference


@pytest.mark.parametrize("count", [0, 20, 64, 90, 128, 160])
@pytest.mark.parametrize("side", ["lower", "upper"])
def test_no_bound_ever_falls_below_the_true_tail(count, side):
    """Every inequality over-states the tail, which is the safe direction.

    A bound that dipped below the truth would let a derived threshold quote a
    false-positive probability the run does not have, which is the one kind of
    error a security claim cannot absorb.
    """
    truth = _rational_tail(count, 192, 1, 3, side)
    for method in INEQUALITIES:
        bound = binomial_tail_bound(
            count, 192, 1 / 3, side=side, method=method
        )
        assert bound >= truth * (1.0 - 1e-9)


@pytest.mark.parametrize(("trials", "budget", "method"), _GRID)
def test_sharpest_is_never_beaten_by_the_proof_it_chose_over(
    trials, budget, method
):
    """``"sharpest"`` dominates every single inequality, on both tails.

    D-5: the selection is over *proofs*, each admissible on its own before any
    data exists, so taking the best of them is not fitting. What this pins is
    that it really does take the best.
    """
    for side in ("lower", "upper"):
        sharp = critical_count(
            trials, 1 / 3, eps=budget, side=side, method="sharpest"
        )
        single = critical_count(
            trials, 1 / 3, eps=budget, side=side, method=method
        )
        if side == "lower":
            assert sharp >= single
        else:
            assert sharp <= single


def test_neither_closed_form_dominates_the_other_which_is_why_both_are_kept():
    """The ordering of Hoeffding and Chernoff reverses with the null's ``q``.

    At the matched count's ``q = 1/3`` the distribution-free Hoeffding bound is
    the sharper of the two -- which is finding F1 about the protocol's own
    floors. At the mismatch null's ``q = p_e``, a per-cent-scale error rate,
    the multiplicative form is tuned for exactly that regime and wins by an
    order of magnitude. ``"sharpest"`` does not need to know which is which,
    and this test is what stops a later simplification from dropping "the one
    that never wins".
    """
    at_a_third = {
        method: critical_count(
            600, 1 / 3, eps=1e-9, side="lower", method=method
        )
        for method in ("hoeffding", "chernoff")
    }
    assert at_a_third["hoeffding"] > at_a_third["chernoff"]

    at_a_small_rate = {
        method: critical_count(
            38400, 0.001, eps=1e-9, side="upper", method=method
        )
        for method in ("hoeffding", "chernoff")
    }
    assert at_a_small_rate["chernoff"] < at_a_small_rate["hoeffding"]
    assert (
        at_a_small_rate["hoeffding"] > 5 * at_a_small_rate["chernoff"]
    ), "and by an order of magnitude, not a hair"


def test_sharpest_picks_the_exact_tail_and_names_it():
    """The honest description of what ``"sharpest"`` does, asserted.

    The exact tail inverts the cdf rather than a bound on it, so it dominates
    by construction and ``"sharpest"`` selects it whenever it is computable.
    Saying so in a test stops the default from quietly meaning something else.
    """
    threshold = matched_count_threshold(600, 1 / 3, eps=1e-9, side="lower")
    assert threshold.inequality == "exact binomial tail"
    assert 600 <= EXACT_TRIALS_LIMIT


@pytest.mark.parametrize("side", ["lower", "upper"])
@pytest.mark.parametrize("method", [*INEQUALITIES, "sharpest"])
def test_a_tighter_budget_never_buys_a_more_sensitive_threshold(side, method):
    """``eps`` is a monotone knob, which is what makes it a ROC axis.

    A Phase 5 curve swept over ``eps`` is only a curve if the operating point
    moves in one direction. Non-monotonicity would mean two budgets crossing,
    and a "better" point that was really an arithmetic accident.
    """
    budgets = (1e-1, 1e-2, 1e-4, 1e-8, 1e-16, HONEST_ABORT_BUDGET)
    found = [
        critical_count(600, 1 / 3, eps=budget, side=side, method=method)
        for budget in budgets
    ]
    if side == "lower":
        assert found == sorted(found, reverse=True)
    else:
        assert found == sorted(found)


def test_a_point_mass_null_is_answered_exactly_in_both_directions():
    """``p_e = 0`` is a point mass, and the module says so rather than dividing.

    Seven of layer one's seventeen nulls are point masses and this is the one
    this family leans on hardest: firing on ``e_R >= 1`` costs exactly nothing
    from the budget, and the cost is that it is a claim about a noiseless link.
    """
    clean = mismatch_rate_threshold(59, eps=1e-9)
    assert clean.critical_count == 1
    assert clean.false_positive_bound == 0.0
    assert clean.inequality == "point mass at 0"
    assert clean.fires(1) and not clean.fires(0)


# --------------------------------------------------------------------------- #
# 2. The protocol's own floors, reproduced and then compared
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("length", [360, 600, 1200, 4800, 115200])
def test_the_chernoff_inversion_reproduces_both_protocol_floors(length):
    """Two implementations of one derivation, agreeing to the integer.

    :mod:`sih141.protocol.verify` computes ``max(1, ceil((1 - d) mu))`` and
    aborts strictly below it; this module computes ``floor((1 - d) mu)`` and
    fires at or below it. Those are the same rule wherever ``(1 - d) mu`` is
    not an integer, and this asserts they land on the same count at every
    length where the Chernoff form has any power at all.
    """
    params = ProtocolParams(key_length=length)
    matched = matched_count_threshold(
        params.signing_length,
        params.match_probability,
        eps=HONEST_ABORT_BUDGET,
        side="lower",
        method="chernoff",
    )
    pooled = pooled_count_threshold(
        params.signing_length,
        params.match_probability,
        eps=HONEST_ABORT_BUDGET,
        side="lower",
        method="chernoff",
    )
    assert matched.critical_count == minimum_matched_count(params) - 1
    assert pooled.critical_count == minimum_pooled_matched_count(params) - 1
    assert pooled.trials == 2 * params.signing_length


@pytest.mark.parametrize("length", [360, 600, 1200, 115200])
def test_the_derived_detector_fires_on_everything_the_floor_aborts_on(length):
    """A superset, never a subset -- the containment ``ceil(x) - 1 <= floor(x)``.

    If the derived threshold were ever *below* the protocol's floor there would
    be counts the verifier refuses to score and the detector calls clean, which
    is the one relation between the two rules that would be indefensible.
    """
    params = ProtocolParams(key_length=length)
    for method in (*INEQUALITIES, "sharpest"):
        derived = critical_count(
            params.signing_length,
            params.match_probability,
            eps=HONEST_ABORT_BUDGET,
            side="lower",
            method=method,
        )
        assert derived >= minimum_matched_count(params) - 1


@pytest.mark.parametrize("length", [192, 360, 600, 1200, 115200])
def test_the_protocol_floors_use_the_loosest_of_the_three_proofs(length):
    """Finding F1, as an assertion rather than as prose.

    At ``q = 1/3`` the multiplicative Chernoff lower tail is dominated by the
    exact tail at every length, and by Hoeffding at every length where either
    closed form has any power at all (at ``L = 192`` both are silent and the
    comparison is vacuous), so a floor derived from either would be strictly
    higher at the *same* ``2**-64`` budget. Not a defect -- a looser
    floor aborts honest runs less often and every published bound stands -- but
    the margin that closes the split-coin route is bought at the loosest
    available exchange rate, and at ``L = 192`` the shipped per-verifier floor
    degenerates to "abort only on an empty matched set" where the exact tail
    still certifies a real one. The fix belongs in
    :mod:`sih141.protocol.verify`, which layer two does not own; this test
    exists so the finding cannot be lost.
    """
    row = floor_comparison(ProtocolParams(key_length=length))
    assert row["protocol_matched"] == row["chernoff_matched"] or (
        row["chernoff_matched"] < 0 and row["protocol_matched"] == 0
    )
    assert row["exact_matched"] > row["protocol_matched"]
    assert row["exact_pooled"] > row["protocol_pooled"]
    assert row["exact_matched"] >= row["hoeffding_matched"]


def test_the_floor_comparison_table_is_the_one_in_the_docstring():
    """The module docstring's F1 table, recomputed.

    Prose is the one thing ``--doctest-modules`` cannot check, and five wrong
    prose numbers have already shipped in this project. The table is small
    enough to pin whole.
    """
    expected = {
        # L: (protocol, hoeffding, exact, exact pooled) -- all critical counts
        192: (0, -1, 11, 49),
        360: (16, 30, 44, 130),
        600: (66, 84, 100, 256),
        115200: (36554, 36801, 36951, 74749),
    }
    for length, row_expected in expected.items():
        row = floor_comparison(ProtocolParams(key_length=length))
        assert (
            row["protocol_matched"],
            row["hoeffding_matched"],
            row["exact_matched"],
            row["exact_pooled"],
        ) == row_expected
    # And the units really are critical counts, not floors, in every column.
    assert (
        floor_comparison(DEFAULT_PARAMS)["protocol_matched"]
        == minimum_matched_count(DEFAULT_PARAMS) - 1
    )
    assert (
        floor_comparison(DEFAULT_PARAMS)["protocol_pooled"]
        == minimum_pooled_matched_count(DEFAULT_PARAMS) - 1
    )


# --------------------------------------------------------------------------- #
# 3. Honest runs: the measured rate against the proven bound
# --------------------------------------------------------------------------- #


def test_a_serious_budget_flags_no_honest_run():
    """At ``eps = 1e-9``, a hundred honest runs produce nothing.

    The operating point a Phase 5 table would actually quote. The family's
    proven per-run bound at this budget is a few times ``1e-10``, so a single
    fire over a hundred runs would sit outside anything the derivation
    permits -- and the derivation, not the measurement, would be the thing that
    was wrong.
    """
    corpus = _honest_corpus()
    flagged = []
    for stats in corpus:
        family = RateCountThresholds.for_transcript(
            stats, eps=SERIOUS_BUDGET
        )
        verdict = family.evaluate(stats)
        if verdict.flagged:
            flagged.append(verdict.fired)
    assert flagged == [], f"honest runs flagged at eps={SERIOUS_BUDGET}: {flagged}"


def test_a_loose_budget_fires_on_honest_runs_but_stays_inside_its_bound():
    """The measurement that can actually fail, taken where firing is possible.

    A false-positive rate measured at ``1e-9`` over a hundred runs is ``0`` for
    a correct derivation *and* for one whose thresholds are unreachable, so it
    distinguishes nothing. This measures at ``eps = 0.5``, where the family's
    proven per-run bound is a few tenths and honest runs really do trip
    members, and then asks whether what was seen is surprising under that
    bound. It is one-sided on purpose: the bound is a bound, so the measured
    rate coming in comfortably *below* it is expected -- a union bound over
    twelve integer thresholds is loose by construction. What would be a failure
    is the measured rate coming in above what the derivation permits, and then
    the derivation is wrong and the measurement is right.
    """
    corpus = _honest_corpus()
    fires = 0
    bound = 0.0
    for stats in corpus:
        family = RateCountThresholds.for_transcript(stats, eps=LOOSE_BUDGET)
        bound = max(bound, family.false_positive_bound)
        if family.evaluate(stats).flagged:
            fires += 1
    assert bound <= LOOSE_BUDGET
    assert fires > 0, (
        "at a budget this loose the family must be able to fire on honest "
        "data; zero fires would mean the thresholds are unreachable and the "
        "serious-budget measurement above proves nothing"
    )
    assert _surprise(fires, len(corpus), bound) >= SURPRISE, (
        f"{fires}/{len(corpus)} honest runs flagged against a proven "
        f"per-run bound of {bound:.4f}; that is more surprising than "
        f"{SURPRISE:g} under the derivation, so the derivation is wrong"
    )


@pytest.mark.parametrize(
    "name",
    [
        "matched_count_low:Bob",
        "matched_count_high:Bob",
        "declared_count_high:Charlie",
        "pooled_count_low",
        "pooled_count_high",
    ],
)
def test_one_members_measured_rate_respects_its_own_bound(name):
    """Per member, not only per family, at a budget where it can fire.

    The union bound hides a member whose own derivation is wrong behind eleven
    that are right, so the members that see the most traffic are scored alone
    against their own proven bounds. Every one of these does fire on honest
    data at this budget, which is what makes the assertion capable of failing.
    """
    corpus = _honest_corpus()
    fires = 0
    bound = 0.0
    for stats in corpus:
        family = RateCountThresholds.for_transcript(stats, eps=LOOSE_BUDGET)
        threshold = family.threshold(name)
        bound = max(bound, threshold.false_positive_bound)
        observed = family.evaluate(stats).observations.get(name)
        if observed is not None and threshold.fires(observed):
            fires += 1
    assert _surprise(fires, len(corpus), bound) >= SURPRISE, (
        f"{name}: {fires}/{len(corpus)} fires against a proven bound of "
        f"{bound:.4f}"
    )


def test_the_noiseless_mismatch_threshold_never_fires_on_an_honest_run():
    """Zero mismatches on a noiseless link, every time, not "close to zero".

    The point-mass null is the strongest claim in the family and the easiest to
    break by accident: one unmatched position counted into the mismatch set and
    an honest run sits at ``(1 - 1/|B|)/2``. The check is exact equality,
    because the null is.
    """
    for stats in _honest_corpus():
        for name, verifier in stats.verifiers.items():
            threshold = mismatch_rate_threshold(
                verifier.matched.count, eps=SERIOUS_BUDGET, party=name
            )
            assert verifier.mismatch.count == 0
            assert not threshold.fires(verifier.mismatch.count)


@pytest.mark.parametrize(
    "timing", [COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING]
)
def test_the_declaration_gap_is_zero_on_every_honest_run(timing):
    """The free structural test, at both orderings, never grouped across them.

    ``declaration_gap`` costs no budget because its false-positive probability
    is exactly zero, and "exactly zero" is a claim that has to hold under both
    count-exchange orderings separately -- they are different experiments, and a
    test that pooled them would be averaging two.
    """
    corpus = _honest_corpus(runs=20, timing=timing)
    for stats in corpus:
        family = RateCountThresholds.for_transcript(
            stats, eps=SERIOUS_BUDGET
        )
        verdict = family.evaluate(stats)
        assert verdict.observations.get("declaration_gap") == 0
        assert "declaration_gap" not in verdict.fired
        assert verdict.grouping_key[0] == timing


# --------------------------------------------------------------------------- #
# 4. What the thresholds separate: Phase 3's constraint 5, from the closed form
# --------------------------------------------------------------------------- #


def test_the_forgery_separation_is_the_one_phase_three_measured():
    """``9.80`` sigma at ``L = 192`` and ``240`` at DEFAULT_PARAMS.

    Constraint 5. ``transcript.repudiated`` cannot separate signer misbehaviour
    from channel noise or from recipient forgery -- plain depolarising noise at
    ``p = 0.10`` produced ``repudiated == True`` with a completely honest Alice
    -- and the discriminator that works is the matched count. This confirms the
    separation from the closed form, which is where a threshold may look.
    """
    assert forgery_separation_sigma(192, 1 / 3) == pytest.approx(
        9.797958971132712, rel=1e-12
    )
    assert (
        forgery_separation_sigma(
            DEFAULT_PARAMS.signing_length, DEFAULT_PARAMS.match_probability
        )
        == 240.0
    )
    assert forgery_separation_sigma(192, 1 / 3) == pytest.approx(
        math.sqrt(192 / 2), rel=1e-12
    )

    # The forger's scored fraction is recomputed here from ``(1 + p) / 2``
    # rather than read off the parameter set, so that this module's separation
    # cannot drift from the protocol's own definition without something
    # failing. If the protocol ever changes the fraction, this is where it is
    # noticed.
    for params in (ProtocolParams(key_length=192), DEFAULT_PARAMS):
        chance = params.match_probability
        assert (1.0 + chance) / 2.0 == params.forger_scored_fraction
        shift = params.signing_length * (
            params.forger_scored_fraction - chance
        )
        spread = math.sqrt(params.signing_length * chance * (1.0 - chance))
        assert forgery_separation_sigma(
            params.signing_length, chance
        ) == pytest.approx(shift / spread, rel=1e-12)


@pytest.mark.parametrize("length", [192, 600, 4800, 115200])
def test_pooling_costs_exactly_root_two(length):
    """Finding F2, at every key length.

    A recipient forgery moves one verifier's count and the pooled total by the
    same absolute amount, while the pooled null's spread is larger by
    ``sqrt(2)``. So pooling is strictly worse against anything one party does
    alone -- and it is kept because it is the count every repudiation bound is
    exponential in, not because of this. Neither statistic is folded into the
    other, for the same reason layer one refuses to pool the two links' check
    logs.
    """
    per = forgery_separation_sigma(length, 1 / 3)
    both = forgery_separation_sigma(length, 1 / 3, pooled=True)
    assert per / both == pytest.approx(math.sqrt(2), rel=1e-12)


def test_the_upper_matched_threshold_sits_between_the_two_hypotheses():
    """A derived threshold, not a chosen one, still lands where it must.

    At ``L = 192`` and ``eps = 1e-9`` the upper matched threshold is ``106``,
    strictly above the honest mean ``64`` and strictly below the forger's mean
    ``128``. Nothing chose that; it fell out of D-2. The test records that the
    derivation happens to be useful, which is a different sentence from the
    threshold having been picked because it was.
    """
    params = ProtocolParams(key_length=192)
    threshold = matched_count_threshold(
        params.signing_length,
        params.match_probability,
        eps=1e-9,
        side="upper",
    )
    honest_mean = params.signing_length * params.match_probability
    forger_mean = params.signing_length * params.forger_scored_fraction
    assert honest_mean < threshold.critical_count < forger_mean
    assert threshold.false_positive_bound <= 1e-9


# --------------------------------------------------------------------------- #
# 5. The pooled null is exact by conservation, and doubled once
# --------------------------------------------------------------------------- #


def test_the_pooled_count_follows_binomial_over_two_n_on_honest_runs():
    """Checked against the law, over the corpus, at the *predicted* parameters.

    Exactness comes from conservation: the symmetrisation coins re-assign a
    fixed multiset of ``2n`` entries, so ``M`` cannot move. Convolving the two
    marginals would land on the same answer and prove nothing, since given the
    records ``m_C = M - m_B`` with correlation ``-1``.
    """
    corpus = _honest_corpus()
    trials = 2 * LENGTH
    mean = trials / 3.0
    spread = math.sqrt(trials * (1 / 3) * (2 / 3))
    counts = [
        stats.pooled.pooled.count
        for stats in corpus
        if stats.pooled.pooled is not None
    ]
    assert len(counts) == len(corpus)
    observed = sum(counts) / len(counts)
    # Standard error of the corpus mean under the predicted law, never under
    # the sample's own spread: the hypothesis is that the derivation is right.
    assert abs(observed - mean) <= 5.0 * spread / math.sqrt(len(counts))
    for stats in corpus:
        assert stats.pooled.pooled.trials == trials


def test_the_declared_count_shares_the_matched_null_and_not_its_roster_slot():
    """One derivation, two observables, and they are never merged.

    A starver moves the integer he puts on the wire while leaving the count his
    own verdict scored alone, so the two statistics fail differently and get
    separate roster entries -- and separate shares of the budget. They share a
    null because on an honest run they are the same integer.
    """
    matched = matched_count_threshold(
        600, 1 / 3, eps=1e-9, side="lower", party="Charlie"
    )
    declared = declared_count_threshold(
        600, 1 / 3, eps=1e-9, side="lower", party="Charlie"
    )
    assert matched.critical_count == declared.critical_count
    assert matched.trials == declared.trials == 600
    assert matched.false_positive_bound == declared.false_positive_bound
    assert matched.name != declared.name
    assert matched.statistic != declared.statistic
    assert "Binomial(600, 1/3)" in matched.null
    assert "Binomial(600, 1/3)" in declared.null


def test_the_pooled_threshold_doubles_exactly_once():
    """``n`` in, ``2n`` trials out, and no route that doubles twice.

    A caller who passed ``2n`` by hand would get a null over ``4n`` and a bound
    that claimed twice the evidence the run holds; the doubling lives in one
    place so that cannot happen.
    """
    assert pooled_count_threshold(192, 1 / 3, eps=1e-9, side="lower").trials == 384
    family = RateCountThresholds.for_params(
        ProtocolParams(key_length=192), eps=1e-9
    )
    assert family.threshold("pooled_count_low").trials == 384
    assert family.threshold("matched_count_low:Bob").trials == 192


# --------------------------------------------------------------------------- #
# 6. The family: a fixed roster and a union bound
# --------------------------------------------------------------------------- #


def test_the_roster_is_fixed_complete_and_disjoint_from_the_free_tests():
    """D-4 is a union bound over a constant, and the constant is checked here.

    A roster sized to the run would make each member's budget a function of the
    data; a roster that drifted out of step with the constructor would make the
    bound a statement about a set nobody computed. Both are pinned.
    """
    family = RateCountThresholds.for_params(DEFAULT_PARAMS, eps=1e-9)
    assert tuple(sorted(family.thresholds)) == tuple(sorted(RATE_COUNT_ROSTER))
    assert len(RATE_COUNT_ROSTER) == 12
    assert len(set(RATE_COUNT_ROSTER)) == len(RATE_COUNT_ROSTER)
    assert set(RATE_COUNT_ROSTER).isdisjoint(RATE_COUNT_FREE_TESTS)
    assert family.per_test_budget == 1e-9 / len(RATE_COUNT_ROSTER)
    for name in RATE_COUNT_ROSTER:
        assert family.threshold(name).budget == family.per_test_budget

    # The summed bound is over what was BUILT and the split is over the
    # ROSTER, so the two sets have to be the same one. An extra member would
    # be summed in without a budget of its own; a missing one would make the
    # bound a claim about a set nobody computed. The constructor refuses both
    # directions, and this asserts the invariant it is protecting.
    assert set(family.thresholds) == set(RATE_COUNT_ROSTER)
    assert math.fsum(
        family.threshold(name).budget for name in RATE_COUNT_ROSTER
    ) == pytest.approx(family.eps, rel=1e-12)


@pytest.mark.parametrize("budget", [1e-2, 1e-6, 1e-9, HONEST_ABORT_BUDGET])
@pytest.mark.parametrize("length", [192, 600, 115200])
def test_the_family_bound_is_the_sum_and_never_exceeds_the_budget(
    budget, length
):
    """The union bound, arithmetic and all.

    ``P(any member fires) <= sum of member bounds <= 12 * (eps / 12) = eps``.
    The middle term is what the family reports, so it is at most the budget and
    usually well under it -- an integer threshold rarely lands on its budget
    exactly, and the two mismatch members contribute exactly zero under the
    noiseless null.
    """
    params = ProtocolParams(key_length=length)
    family = RateCountThresholds.for_params(params, eps=budget)
    total = math.fsum(
        family.threshold(name).false_positive_bound
        for name in RATE_COUNT_ROSTER
    )
    assert family.false_positive_bound == pytest.approx(total, rel=1e-12)
    assert family.false_positive_bound <= budget
    for name in RATE_COUNT_ROSTER:
        threshold = family.threshold(name)
        assert threshold.false_positive_bound <= threshold.budget


def test_the_family_says_when_its_bound_needs_conditioning():
    """Ten members are constants of the parameter set; two are not.

    The matched, declared and pooled thresholds are functions of ``(n, 1/|B|,
    eps)`` and nothing else, so their bounds are constants and the sum is an
    unconditional statement. The two mismatch members are functions of the
    observed ``|M_R|``, so at a positive noise level the sum bounds the firing
    probability *given the matched counts* -- still correct, still derived,
    and a different sentence. ``eps`` is what stays unconditionally true, and a
    Phase 5 curve plotted at the wrong one of the two would be wrong in a way
    nothing else would flag.
    """
    params = ProtocolParams(key_length=600)
    quiet = RateCountThresholds.for_params(params, eps=1e-9)
    assert quiet.bound_is_unconditional
    assert quiet.threshold("mismatch_rate:Bob").false_positive_bound == 0.0

    noisy = RateCountThresholds.for_params(
        params, eps=1e-9, channel_error_rate=0.01
    )
    assert not noisy.bound_is_unconditional
    assert noisy.threshold("mismatch_rate:Bob").false_positive_bound > 0.0
    assert noisy.false_positive_bound <= noisy.eps
    assert noisy.to_dict()["bound_is_unconditional"] is False

    # The ten count members are untouched by the noise level, which is what
    # makes their terms constants of the family rather than of the run.
    for name in RATE_COUNT_ROSTER:
        if name.startswith("mismatch_rate:"):
            continue
        assert (
            quiet.threshold(name).critical_count
            == noisy.threshold(name).critical_count
        )


def test_a_count_threshold_never_moves_with_the_observed_counts():
    """The ten count members are derived before the run, and stay derived.

    Two different honest runs of the same parameter set must produce the same
    ten thresholds. If any of them moved with what the run happened to contain,
    that would be fitting -- a threshold chosen by the data it is applied to --
    however innocently it arrived.
    """
    corpus = _honest_corpus()
    first = corpus[0]
    baseline = first.verifier("Bob").matched.count
    second = next(
        stats
        for stats in corpus[1:]
        if stats.verifier("Bob").matched.count != baseline
    )
    left = RateCountThresholds.for_transcript(first, eps=1e-9)
    right = RateCountThresholds.for_transcript(second, eps=1e-9)

    for name in RATE_COUNT_ROSTER:
        if name.startswith("mismatch_rate:"):
            # Deliberately excluded: this one *does* move, with the
            # conditioning variable and with nothing else (D-3). It is the one
            # member the exclusion is about, so it gets its own assertion.
            continue
        assert (
            left.threshold(name).to_dict() == right.threshold(name).to_dict()
        ), f"{name} moved between two honest runs of the same parameter set"

    for party in ("Bob", "Charlie"):
        member = f"mismatch_rate:{party}"
        assert left.threshold(member).trials == first.verifier(
            party
        ).matched.count
        # It tracks |M_R| and nothing else: same conditioning variable, same
        # threshold, whatever the mismatch counts were.
        assert left.threshold(member).critical_count == mismatch_rate_threshold(
            first.verifier(party).matched.count,
            eps=left.per_test_budget,
            party=party,
        ).critical_count


def test_the_family_bound_is_monotone_in_the_budget():
    """A smaller budget buys a smaller proven bound, which is the ROC axis."""
    bounds = [
        RateCountThresholds.for_params(
            ProtocolParams(key_length=600), eps=budget
        ).false_positive_bound
        for budget in (1e-1, 1e-3, 1e-6, 1e-12)
    ]
    assert bounds == sorted(bounds, reverse=True)


def test_a_family_refuses_a_run_drawn_from_a_different_null():
    """A threshold applied to the wrong ``n`` carries no bound at all.

    The failure this stops is silent: every number would compute, the table
    would render, and the quoted false-positive probability would describe an
    experiment nobody ran.
    """
    family = RateCountThresholds.for_params(
        ProtocolParams(key_length=192), eps=1e-9
    )
    other = _honest_corpus(runs=1, length=600)[0]
    with pytest.raises(ValueError, match="carries no bound"):
        family.evaluate(other)


def test_a_noisy_family_refuses_a_run_it_was_not_conditioned_on():
    """The other half of D-3, and the one that could have gone wrong quietly.

    The mismatch threshold's bound holds *given* the matched-set size it was
    derived at. Applying one derived at ``|M_R| = 200`` to a run holding
    ``|M_R| = 69`` bounds nothing at all -- and every number would still
    compute, which is exactly why it is refused rather than reported.

    At the default noiseless ``channel_error_rate`` the threshold is ``e_R >=
    1`` for every possible matched count, so any conditioning variable gives
    the same rule and there is nothing to refuse. The guard therefore appears
    exactly where it is needed and nowhere else.
    """
    stats = _honest_corpus(runs=1)[0]
    apriori_quiet = RateCountThresholds.for_params(
        ProtocolParams(key_length=LENGTH), eps=1e-9
    )
    # Noiseless: the a-priori family scores the run happily and soundly.
    assert apriori_quiet.threshold("mismatch_rate:Bob").trials != stats.verifier(
        "Bob"
    ).matched.count
    assert not apriori_quiet.evaluate(stats).flagged

    apriori_noisy = RateCountThresholds.for_params(
        ProtocolParams(key_length=LENGTH), eps=1e-9, channel_error_rate=0.01
    )
    with pytest.raises(ValueError, match="conditionally on"):
        apriori_noisy.evaluate(stats)

    # Built from the run it is going to score, the same noisy family is fine.
    fitted = RateCountThresholds.for_transcript(
        stats, eps=1e-9, channel_error_rate=0.01
    )
    assert fitted.threshold("mismatch_rate:Bob").trials == stats.verifier(
        "Bob"
    ).matched.count
    assert not fitted.evaluate(stats).flagged


def test_the_family_reads_the_sifted_length_not_the_nominal_one():
    """A checked run's nulls are stated over ``n``, never over ``L``.

    At ``check_fraction = 0.25`` a null over ``L`` would claim a third more
    evidence than the run has, and every bound in the scheme is exponential in
    that count.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=400, check_fraction=0.25),
            rng=_session_rng(500),
        ).run(0)
    )
    family = RateCountThresholds.for_transcript(stats, eps=1e-9)
    assert stats.nominal_key_length == 400
    assert family.signing_length == stats.key_length == 300
    assert family.threshold("matched_count_low:Bob").trials == 300
    assert family.threshold("pooled_count_low").trials == 600


def test_the_conditioning_variable_is_the_matched_count_not_the_mismatch():
    """D-3, asserted where it could go wrong.

    The mismatch threshold is a function of ``|M_R|`` and of ``eps``, never of
    ``e_R``. Two runs with the same matched count get the same threshold
    whatever their mismatch counts are, which is the property the tower rule
    needs and the property a fitted threshold would not have.
    """
    first = mismatch_rate_threshold(
        64, eps=1e-9, channel_error_rate=0.01
    )
    second = mismatch_rate_threshold(
        64, eps=1e-9, channel_error_rate=0.01
    )
    assert first == second
    assert (
        mismatch_rate_threshold(
            65, eps=1e-9, channel_error_rate=0.01
        ).trials
        == 65
    )


# --------------------------------------------------------------------------- #
# 7. Relative to s_a and s_v: a flag is not a rejection
# --------------------------------------------------------------------------- #


def test_the_dominance_crossover_sits_below_the_design_noise_level():
    """The ``r_R`` detector is dominated at the noise ``s_a`` was sized for.

    ``s_a = 1/64`` is a noise budget: it permits ``2 s_a = 3.125%`` depolarising
    noise in the resource. The largest link error rate at which the derived
    threshold still sits at or below that cut is ``0.012119`` -- below the
    design level -- so on a link running as noisy as the scheme allows, every
    run the detector flags Bob has already rejected and its marginal
    information is zero. All of the detector's power comes from assuming the
    link is quieter than the protocol assumes, and that sentence belongs next to
    every detection rate published from it.
    """
    design_noise = 2.0 * (1 / 64)
    against_bob = dominance_noise_level(38400, 1 / 64, eps=1e-9)
    assert against_bob == pytest.approx(0.012119, abs=5e-6)
    assert against_bob < design_noise, (
        "against Bob's cut the detector is dominated at the design noise level"
    )

    # Charlie's looser cut moves the crossover to the far side of the design
    # noise level, so against *him* the detector still adds information there
    # -- with a factor of about 1.8 in hand. The crossover is a property of the
    # cut and not of the detector, which is why it is reported per party and
    # why the tighter cut is the one that squeezes the detector out.
    against_charlie = dominance_noise_level(38400, 1 / 16, eps=1e-9)
    assert against_charlie == pytest.approx(0.055355, abs=5e-6)
    assert against_charlie > design_noise > against_bob


def test_the_noiseless_threshold_is_stricter_than_the_protocols_own_cut():
    """A run the protocol accepts can be flagged, and that is not a rejection.

    Under the noiseless null the detector fires at one mismatch, a rate of
    ``1/|M_R|``, which at ``|M_R| = 64`` is exactly ``s_a``. So a run Bob
    accepts on the boundary is flagged here. The flag says the channel departed
    from the null; the verdict says the signature met the scheme's noise budget.
    They are different questions and the module keeps them in different objects.
    """
    threshold = mismatch_rate_threshold(64, eps=1e-9)
    assert threshold.critical_rate == pytest.approx(1 / 64)
    assert threshold.critical_rate == pytest.approx(DEFAULT_PARAMS.s_a)
    assert threshold.fires(1)


def test_a_verdict_carries_no_accept_or_reject_field():
    """Structural, so no caller can read a flag as a rejection by accident.

    Constraint 4 one layer out: layer one keeps refusals out of verdicts by
    type, and this layer keeps *flags* out of verdicts the same way. The run's
    own acceptance decisions stay on the statistics object and are not copied
    here, so there is nowhere for the two to be summed.
    """
    stats = _honest_corpus(runs=1)[0]
    verdict = RateCountThresholds.for_transcript(
        stats, eps=1e-9
    ).evaluate(stats)
    payload = verdict.to_dict()
    assert "accepted" not in payload
    assert "rejected" not in payload
    assert set(payload) == {
        "flagged",
        "fired",
        "false_positive_bound",
        "observations",
        "not_scored",
        "grouping_key",
    }
    assert stats.verifier("Bob").accepted is True
    assert verdict.flagged is False


def test_the_grouping_key_marks_the_variant_and_is_never_averaged():
    """Group by ``count_exchange_timing``; never average over it.

    The two orderings give different answers to the same attack, so a table
    mixing them averages a forgery rate with a denial-of-service rate. The
    verdict carries the markers rather than aggregating anything, and nothing
    in the layer sums across them.
    """
    keys = set()
    for timing in (COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING):
        stats = _honest_corpus(runs=1, timing=timing)[0]
        verdict = RateCountThresholds.for_transcript(
            stats, eps=1e-9
        ).evaluate(stats)
        keys.add(verdict.grouping_key)
        assert verdict.grouping_key[0] == timing
    assert len(keys) == 2, "the two orderings must not collapse to one key"


# --------------------------------------------------------------------------- #
# 8. Refusals are never verdicts, and never non-detections either
# --------------------------------------------------------------------------- #


def test_a_refusing_party_contributes_nothing_to_either_column():
    """A verifier who reached no verdict is listed, and scored nowhere.

    Counting his refusal as a clean run would deflate a false-positive rate;
    counting it as a detection would inflate a detection rate. He appears in
    ``not_scored`` and in no observation, which is the third outcome spelled
    out.
    """
    transcript = QDSSession(
        ProtocolParams(key_length=600),
        count_exchange=CountStarver(party=Party.CHARLIE, rng=_attack_rng(1)),
        rng=_session_rng(801),
    ).run(0)
    stats = TranscriptStatistics.from_transcript(transcript)
    refusing = set(stats.aborts.by_party)
    assert refusing, "a starved run should leave somebody without a verdict"

    family = RateCountThresholds.for_transcript(stats, eps=1e-9)
    verdict = family.evaluate(stats)
    assert set(verdict.not_scored) == refusing
    for name in refusing:
        assert f"mismatch_rate:{name}" not in verdict.observations
        assert f"matched_count_low:{name}" not in verdict.observations
        assert f"matched_count_low:{name}" not in verdict.fired


def test_a_run_where_nobody_reached_a_verdict_scores_nothing_at_all():
    """Zero verdicts is a third outcome, not a clean run and not a detection.

    At a key length where both floors bite, both verifiers refuse and there is
    nothing to score. The family produces no observations, lists both parties
    as unscored, and flags nothing -- and ``security_claim`` is ``False``, so a
    Phase 5 aggregator can drop the run rather than counting it as a
    true negative. Counting it as one would deflate a false-positive rate with
    runs that were never tested.
    """
    # Scanned rather than hard-coded: at n = 6 both matched sets are empty
    # with probability ``(2/3)**12 ~ 0.008``, so the seed that exhibits the
    # shape is found by looking rather than by remembering. Deterministic, and
    # it costs about a fifth of a second.
    stats = next(
        candidate
        for candidate in (
            TranscriptStatistics.from_transcript(
                QDSSession(
                    ProtocolParams(key_length=6), rng=_session_rng(index)
                ).run(0)
            )
            for index in range(200)
        )
        if not candidate.verifiers
    )
    family = RateCountThresholds.for_transcript(stats, eps=1e-9)
    verdict = family.evaluate(stats)

    assert stats.verifiers == {}
    assert stats.aborts.total == 2
    assert not stats.security_claim
    assert set(verdict.not_scored) == {"Bob", "Charlie"}
    assert verdict.observations == {}
    assert verdict.fired == ()
    assert not verdict.flagged
    # Every threshold is silent at this length, so the family's proven bound
    # is exactly zero -- true, and useless, and both halves are visible.
    assert family.false_positive_bound == 0.0
    assert all(
        family.threshold(name).vacuous or name.startswith("mismatch_rate:")
        for name in RATE_COUNT_ROSTER
    )
    json.loads(json.dumps(verdict.to_dict()))


def test_a_pre_pooled_run_has_no_declared_members_to_evaluate():
    """No count exchange, no wire integers, and no manufactured zeros.

    Recording a missing declaration as ``0`` would trip the starvation member
    on every run of the pre-pooled variant, which is a detection of the variant
    rather than of an attack.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=LENGTH),
            count_exchange=no_count_exchange,
            rng=_session_rng(802),
        ).run(0)
    )
    family = RateCountThresholds.for_transcript(stats, eps=1e-9)
    verdict = family.evaluate(stats)
    assert not stats.counts_exchanged
    assert "declared_count_low:Bob" not in verdict.observations
    assert "declaration_gap" not in verdict.observations
    assert not verdict.flagged
    # The roster is still complete: the union bound is over the roster, not
    # over the members this particular run could evaluate.
    assert len(family.thresholds) == len(RATE_COUNT_ROSTER)


# --------------------------------------------------------------------------- #
# 9. What it refuses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("call", "exception", "match"),
    [
        pytest.param(
            lambda: critical_count(192, 1 / 3, eps=0.0, side="lower"),
            ValueError,
            "false-positive budget",
            id="zero-budget",
        ),
        pytest.param(
            lambda: critical_count(192, 1 / 3, eps=1.0, side="lower"),
            ValueError,
            "false-positive budget",
            id="unit-budget",
        ),
        pytest.param(
            lambda: critical_count(192, 1 / 3, eps=1e-9, side="both"),
            ValueError,
            "must name the tail",
            id="two-sided",
        ),
        pytest.param(
            lambda: critical_count(
                192, 1 / 3, eps=1e-9, side="lower", method="bayes"
            ),
            ValueError,
            "method must be one of",
            id="unknown-proof",
        ),
        pytest.param(
            lambda: critical_count(192, 1.5, eps=1e-9, side="lower"),
            ValueError,
            "must lie in",
            id="probability-above-one",
        ),
        pytest.param(
            lambda: critical_count(192.0, 1 / 3, eps=1e-9, side="lower"),
            TypeError,
            "must be an int",
            id="float-trials",
        ),
        pytest.param(
            lambda: binomial_tail_bound(300, 192, 1 / 3, side="upper"),
            ValueError,
            "counting error upstream",
            id="count-above-trials",
        ),
        pytest.param(
            lambda: forgery_separation_sigma(0, 1 / 3),
            ValueError,
            "at least 1",
            id="no-positions",
        ),
        pytest.param(
            lambda: dominance_noise_level(0, 1 / 64, eps=1e-9),
            ValueError,
            "at least 1",
            id="empty-matched-set",
        ),
        pytest.param(
            lambda: RateCountThresholds.for_params("nope", eps=1e-9),
            TypeError,
            "must be a ProtocolParams",
            id="not-params",
        ),
        pytest.param(
            lambda: RateCountThresholds.for_transcript("nope", eps=1e-9),
            TypeError,
            "must be a TranscriptStatistics",
            id="not-statistics",
        ),
        pytest.param(
            lambda: floor_comparison("nope"),
            TypeError,
            "must be a ProtocolParams",
            id="floor-not-params",
        ),
        pytest.param(
            lambda: RateCountThresholds.for_params(
                DEFAULT_PARAMS, eps=1e-9, matched_counts={"Alice": 10}
            ),
            ValueError,
            "not verifiers",
            id="non-verifier-matched-count",
        ),
    ],
)
def test_bad_arguments_are_refused_with_a_reason(call, exception, match):
    """Every refusal says what to pass instead, in the house style."""
    with pytest.raises(exception, match=match):
        call()


def test_a_threshold_whose_bound_exceeds_its_budget_cannot_be_built():
    """The self-check that would catch an arithmetic error in this module.

    A ``DerivedThreshold`` whose proven bound was above the budget it claims to
    have been derived at is not a weak threshold, it is a contradiction: the
    derivation and the arithmetic disagree. Refused at construction, where it is
    still a bug, rather than downstream where it would be a published number.
    """
    with pytest.raises(ValueError, match="exceeds its budget"):
        DerivedThreshold(
            name="fake",
            statistic="x",
            null="Binomial(10, 1/2)",
            inequality="wishful thinking",
            side="upper",
            budget=1e-9,
            trials=10,
            null_probability=0.5,
            critical_count=5,
            false_positive_bound=0.5,
            derivation="none",
            vacuous=False,
        )


def test_a_non_integer_threshold_is_refused_rather_than_truncated():
    """``5.7`` quietly becoming ``5`` is a different rule, not a rounding.

    A truncated critical count changes the false-positive probability the
    object claims to have been derived at, and nothing downstream would notice.
    """
    with pytest.raises(TypeError, match="critical_count must be an int"):
        DerivedThreshold(
            name="fake",
            statistic="x",
            null="Binomial(10, 1/2)",
            inequality="exact binomial tail",
            side="upper",
            budget=1e-9,
            trials=10,
            null_probability=0.5,
            critical_count=5.7,
            false_positive_bound=0.0,
            derivation="none",
            vacuous=False,
        )


def test_a_threshold_with_no_written_null_cannot_be_built():
    """D7 as a constructor check.

    A number with neither a null nor a derivation is a constant somebody chose,
    and there is no way to tell it apart from one afterwards. The empty string
    is refused so the field cannot be satisfied by leaving it blank.
    """
    with pytest.raises(ValueError, match="must carry both its null"):
        DerivedThreshold(
            name="fake",
            statistic="x",
            null="",
            inequality="none",
            side="upper",
            budget=1e-9,
            trials=10,
            null_probability=0.5,
            critical_count=11,
            false_positive_bound=0.0,
            derivation="none",
            vacuous=True,
        )


def test_a_vacuous_threshold_is_silent_and_says_so():
    """No power, no false positives, and both halves reported.

    Where the multiplicative Chernoff form is vacuous the honest answer is an
    unreachable count, not a clamp: a clamped threshold looks like a working
    one, and this one cannot be mistaken for anything.
    """
    threshold = matched_count_threshold(
        192,
        1 / 3,
        eps=HONEST_ABORT_BUDGET,
        side="lower",
        method="chernoff",
    )
    assert threshold.vacuous
    assert threshold.critical_count == -1
    assert threshold.false_positive_bound == 0.0
    assert not any(threshold.fires(count) for count in range(0, 193))
    # Both halves said out loud, and no inequality credited for a threshold
    # nothing certified: a silent detector cannot false-alarm and cannot
    # detect, and a claim that mentioned only the first would read like a
    # strong result.
    claim = threshold.claim()
    assert "never fires" in claim
    assert "no inequality certifies a threshold" in claim
    assert "detects nothing" in claim
    assert "Unreachable critical count" in claim


def test_an_empty_matched_set_produces_a_silent_threshold_not_a_zero():
    """No trials is the absence of a denominator, not a small one.

    :func:`~sih141.protocol.verify.verify` refuses to score an empty matched set
    at all, so this should never arrive from a run; if it does, the honest
    answer is an unreachable count and an inequality named for the fact that
    nothing was applied, rather than a rate of ``0/0`` dressed as a threshold.
    """
    threshold = mismatch_rate_threshold(0, eps=1e-9)
    assert threshold.trials == 0
    assert threshold.critical_rate is None
    assert threshold.vacuous
    assert threshold.false_positive_bound == 0.0
    assert "no trials" in threshold.inequality
    assert not threshold.fires(0)


def test_a_degenerate_null_at_probability_one_is_answered_exactly():
    """The mirror of the point mass at zero, for completeness of the branch.

    Nothing in the scheme has a null at ``p = 1``, and that is precisely why it
    is worth pinning: an untested branch of an exact-case handler is where a
    later alphabet change would land.
    """
    low = critical_count(50, 1.0, eps=1e-9, side="lower")
    high = critical_count(50, 1.0, eps=1e-9, side="upper")
    assert (low, high) == (49, 51)
    assert binomial_tail_bound(49, 50, 1.0, side="lower") == 0.0
    assert binomial_tail_bound(50, 50, 1.0, side="lower") == 1.0


def test_an_unknown_roster_name_is_refused_with_the_roster():
    """The KeyError names the roster rather than shrugging."""
    family = RateCountThresholds.for_params(DEFAULT_PARAMS, eps=1e-9)
    with pytest.raises(KeyError, match="roster is fixed"):
        family.threshold("mismatch_rate:Alice")


# --------------------------------------------------------------------------- #
# 10. Measured on attacks. Measured, never fitted.
#
# NOT ONE NUMBER in sih141/detect/thresholds_rate.py was chosen by looking at
# anything below this line. Every threshold in this section comes out of D-1,
# D-2 or D-3 at a budget the caller named, and these tests record what those
# thresholds happen to do. If a future author changes a threshold to make one
# of these assertions pass, that is fitting, and it is the exact thing the
# problem statement forbids -- delete the assertion instead and report the
# gap as a finding.
# --------------------------------------------------------------------------- #


def test_recipient_forgery_trips_the_upper_matched_threshold():
    """The discriminator Phase 3 named, at a threshold derived from D-2 alone.

    The forger supplied half the second verifier's evidence himself, so his
    count moves from ``n/3`` to ``2n/3``. ``transcript.repudiated`` is
    ``False`` here and correctly so -- the hop altered the declaration, which
    makes this a forgery experiment and not a repudiation -- which is exactly
    why the count and not the flag is the signal.
    """
    params = ProtocolParams(key_length=600)
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            params,
            forwarder=RecipientForger(rng=_attack_rng(2)),
            count_exchange_timing=COUNTS_AFTER_FORWARDING,
            rng=_session_rng(901),
        ).run(0)
    )
    family = RateCountThresholds.for_transcript(stats, eps=SERIOUS_BUDGET)
    verdict = family.evaluate(stats)
    assert "matched_count_high:Charlie" in verdict.fired
    assert not stats.repudiated
    assert verdict.grouping_key[0] == COUNTS_AFTER_FORWARDING
    # And the bound the flag is entitled to quote is the derived one, not a
    # measured separation.
    assert (
        family.threshold("matched_count_high:Charlie").false_positive_bound
        <= family.per_test_budget
    )


def test_count_starvation_trips_the_declared_tail_or_the_free_gap():
    """Either the wire integer is implausibly low, or it contradicts the log.

    Both are in the family and they cost differently: the declared tail spends
    a twelfth of the budget, and the gap costs nothing because a declared count
    that disagrees with the count its own verifier scored is not a deviation
    under any null.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=600),
            count_exchange=CountStarver(
                party=Party.CHARLIE, rng=_attack_rng(3)
            ),
            rng=_session_rng(902),
        ).run(0)
    )
    family = RateCountThresholds.for_transcript(stats, eps=SERIOUS_BUDGET)
    verdict = family.evaluate(stats)
    declared = stats.pooled.declared_charlie
    assert declared is not None
    assert declared.count < declared.expected
    assert "declared_count_low:Charlie" in verdict.fired

    # The refusal is a separate outcome and is reported as one -- and it lands
    # on the *other* recipient. Charlie understates his own count so that the
    # pooled floor fails for Bob, so Charlie scores and Bob is the one denied a
    # verdict. Nothing counts Bob's refusal as either a detection or a clean
    # run: he has no observation anywhere in the verdict.
    assert set(verdict.not_scored) == {"Bob"}
    assert "matched_count_low:Bob" not in verdict.observations
    # The free structural test cannot be evaluated here and is absent rather
    # than zero: without Bob's verdict there is no pooled total to compare the
    # wire integers against, and a manufactured zero would read as "the
    # declarations agreed".
    assert stats.pooled.declaration_gap is None
    assert "declaration_gap" not in verdict.observations


def test_impersonation_on_the_signing_seam_trips_the_mismatch_threshold():
    """The channel says nothing and the mismatch rate says everything.

    Phase 3 measured this: an impersonator on a seam leaves the channel reading
    perfectly clean while ``r_R`` goes to ``1/2`` at both verifiers. The
    noiseless-null mismatch threshold fires at one mismatch, which is the
    weakest possible thing to ask of it and it is not close.
    """
    mallory = Impersonator(rng=_attack_rng(4))
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=LENGTH),
            rng=_session_rng(903),
            **impersonation_seams(mallory, ImpersonationScope.SIGNING),
        ).run(0)
    )
    family = RateCountThresholds.for_transcript(stats, eps=SERIOUS_BUDGET)
    verdict = family.evaluate(stats)
    fired = set(verdict.fired)
    assert any(name.startswith("mismatch_rate:") for name in fired)
    for name in stats.verifiers:
        assert stats.verifiers[name].mismatch.count > 0


def test_the_mismatch_rate_detects_a_targeted_channel_but_cannot_attribute_it():
    """Finding F5: the party in a roster name is the verifier, not the link.

    Phase 3's constraint 3 forbids pooling the two links' *check logs*, because
    per-link QBER is the only statistic that both detects a party-targeted
    channel attack and attributes it. The mismatch rate is a worse case: it is
    already pooled, by the protocol, and no option restores the attribution.
    Phase A' swaps records between the recipients, so a record damaged on Bob's
    link is held by Charlie half the time -- while the check logs are never
    swapped.

    With a depolariser aimed at Bob's link alone the check-round QBER names the
    link on every run, and the two mismatch counts do not: on at least one run
    Charlie's is the larger of the two. A Phase 5 table reading
    ``mismatch_rate:Bob`` as "Eve was on Bob's link" would be reporting which
    recipient the coins handed a damaged record to.
    """
    charlie_larger = 0
    runs = 8
    for index in range(runs):
        stats = TranscriptStatistics.from_transcript(
            QDSSession(
                ProtocolParams(key_length=384, check_fraction=0.25),
                resource_factory=DepolarisingChannel(
                    0.30, target=Party.BOB, rng=_attack_rng(950 + index)
                ).resource,
                rng=_session_rng(950 + index),
            ).run(0)
        )
        # The check logs attribute, on every single run, and are never pooled.
        assert stats.link("Bob", 0).errors.count > 0
        assert stats.link("Charlie", 0).errors.count == 0
        bob = stats.verifier("Bob").mismatch.count
        charlie = stats.verifier("Charlie").mismatch.count
        assert bob > 0 and charlie > 0, (
            "symmetrisation smears the records across both verifiers, so a "
            "one-link attack shows up at both"
        )
        if charlie > bob:
            charlie_larger += 1
    assert charlie_larger > 0, (
        "if the mismatch counts always ranked the touched link first, the "
        "statistic would attribute after all and F5 would be wrong -- which "
        "would be worth knowing, and would be a finding rather than a fix"
    )


def test_an_in_spec_noisy_link_is_accepted_and_flagged_at_once():
    """Finding F6: the cost of the noiseless null, as a measurement.

    ``s_a`` permits ``2 s_a = 3.125%`` depolarising noise in the resource. At
    ``p = 0.03``, just inside that budget, runs are accepted by both verifiers
    and flagged by the noiseless-null mismatch threshold. Each flag is a true
    statement -- the link is not the noiseless link the null describes -- and
    none of them is a rejection. This is the concrete answer to "what does it
    mean to flag a run the protocol accepted", and it is why
    ``channel_error_rate`` is an argument rather than a default nobody reads.
    """
    accepted_and_flagged = 0
    runs = 12
    for index in range(runs):
        stats = TranscriptStatistics.from_transcript(
            QDSSession(
                ProtocolParams(key_length=384, check_fraction=0.25),
                resource_factory=DepolarisingChannel(
                    0.03, target=Party.BOB, rng=_attack_rng(850 + index)
                ).resource,
                rng=_session_rng(850 + index),
            ).run(0)
        )
        verdict = RateCountThresholds.for_transcript(
            stats, eps=SERIOUS_BUDGET
        ).evaluate(stats)
        everyone_accepted = len(stats.verifiers) == len(VERIFIERS) and all(
            verifier.accepted for verifier in stats.verifiers.values()
        )
        if everyone_accepted and verdict.flagged:
            accepted_and_flagged += 1
            assert all(
                name.startswith("mismatch_rate:") for name in verdict.fired
            )
    assert accepted_and_flagged > 0, (
        "at the noise level the scheme tolerates, the noiseless null must "
        "flag accepted runs; if it stopped doing so the null would have "
        "quietly become something else"
    )
    # Handing the same threshold the noise level it is actually running at
    # removes the flag, which is the whole point of the argument existing.
    quiet = mismatch_rate_threshold(
        96, eps=SERIOUS_BUDGET, channel_error_rate=0.03125
    )
    assert quiet.critical_count > 1
    assert not quiet.fires(1)


def test_the_two_orderings_answer_differently_and_are_never_averaged():
    """Finding F7, and Phase 3's constraint 6 measured through this family.

    A recipient forgery at ``L = 600``. Under ``COUNTS_AFTER_FORWARDING`` Bob
    refuses and Charlie reaches a verdict this family flags on all three of his
    members. Under ``COUNTS_BEFORE_FORWARDING`` it is Charlie who refuses, Bob
    reaches a verdict whose numbers are indistinguishable from honest, and the
    family flags nothing -- correctly, because in that arm the attack is a
    denial of service against Charlie and not a forgery that reached anybody.

    Averaging the two arms would publish a fifty per cent detection rate for an
    experiment that is a hundred per cent detection in one arm and a hundred
    per cent denial-of-service in the other. The ``grouping_key`` makes the
    grouping mechanical instead of remembered.
    """
    outcome = {}
    for timing, base in (
        (COUNTS_AFTER_FORWARDING, 100),
        (COUNTS_BEFORE_FORWARDING, 200),
    ):
        flagged = 0
        refusing: set[str] = set()
        runs = 6
        for index in range(runs):
            stats = TranscriptStatistics.from_transcript(
                QDSSession(
                    ProtocolParams(key_length=600),
                    forwarder=RecipientForger(rng=_attack_rng(base + index)),
                    count_exchange_timing=timing,
                    rng=_session_rng(base + index),
                ).run(0)
            )
            verdict = RateCountThresholds.for_transcript(
                stats, eps=SERIOUS_BUDGET
            ).evaluate(stats)
            assert verdict.grouping_key[0] == timing
            flagged += verdict.flagged
            refusing.update(verdict.not_scored)
        outcome[timing] = (flagged, runs, frozenset(refusing))

    after_flagged, runs, after_refusing = outcome[COUNTS_AFTER_FORWARDING]
    before_flagged, _, before_refusing = outcome[COUNTS_BEFORE_FORWARDING]
    assert after_flagged == runs, "the forgery reaches Charlie and is caught"
    assert before_flagged == 0, "in this arm nothing forged reaches a verifier"
    assert after_refusing == {"Bob"}
    assert before_refusing == {"Charlie"}


def test_full_impersonation_is_inseparable_and_the_family_says_nothing():
    """Assumption (AUTH), stated rather than detected.

    With both seams Mallory runs a complete, internally consistent honest
    protocol under her own key. There is nothing in a transcript to see, and
    the correct behaviour of a derived detector is to see nothing. Phase 3's
    constraint 7: do not invent a detector for this; state the assumption.
    """
    mallory = Impersonator(rng=_attack_rng(5))
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=LENGTH),
            rng=_session_rng(904),
            **impersonation_seams(mallory, ImpersonationScope.FULL),
        ).run(0)
    )
    verdict = RateCountThresholds.for_transcript(
        stats, eps=SERIOUS_BUDGET
    ).evaluate(stats)
    assert not verdict.flagged, (
        "full impersonation is out of model by (AUTH); a family that flagged "
        "it would be flagging a run that is byte-identical to an honest one"
    )
    assert not ImpersonationScope.FULL.in_model


# --------------------------------------------------------------------------- #
# 11. Determinism, serialisation and the boundary
# --------------------------------------------------------------------------- #


def test_the_layer_consumes_no_randomness_and_is_deterministic():
    """D3: twice over the same statistics gives the same objects.

    Nothing here has an ``rng`` argument because nothing here has anything to
    draw for; this asserts the property rather than the absence of the keyword.
    """
    stats = _honest_corpus(runs=1)[0]
    first = RateCountThresholds.for_transcript(stats, eps=1e-9)
    second = RateCountThresholds.for_transcript(stats, eps=1e-9)
    assert first.to_dict() == second.to_dict()
    assert first.evaluate(stats).to_dict() == second.evaluate(stats).to_dict()


def test_everything_serialises_as_strict_json():
    """No ``NaN``, no ``Infinity``, on any run shape.

    Both tokens are valid Python and neither is JSON, and a
    :func:`json.dumps` that writes one is how a downstream parser gets a
    surprise. ``parse_constant`` raising is the only way to check it.
    """

    def refuse(token: str) -> float:
        raise AssertionError(f"non-JSON token {token!r} in the payload")

    shapes = [
        _honest_corpus(runs=1)[0],
        TranscriptStatistics.from_transcript(
            QDSSession(
                ProtocolParams(key_length=600),
                count_exchange=CountStarver(
                    party=Party.CHARLIE, rng=_attack_rng(6)
                ),
                rng=_session_rng(905),
            ).run(0)
        ),
        TranscriptStatistics.from_transcript(
            QDSSession(
                ProtocolParams(key_length=400, check_fraction=0.25),
                rng=_session_rng(906),
            ).run(1)
        ),
    ]
    for stats in shapes:
        family = RateCountThresholds.for_transcript(stats, eps=1e-9)
        for payload in (family.to_dict(), family.evaluate(stats).to_dict()):
            json.loads(json.dumps(payload), parse_constant=refuse)


def test_every_member_prints_the_sentence_d7_asks_for():
    """Each threshold carries its own proof, as one readable line.

    "Under the null, this fires with probability at most X, and here is why."
    If a member could not produce that sentence it would be a constant, and the
    difference is the submission's whole argument.
    """
    family = RateCountThresholds.for_params(DEFAULT_PARAMS, eps=1e-9)
    claims = family.claims()
    assert len(claims) == len(RATE_COUNT_ROSTER)
    for claim in claims:
        assert "fires with probability at most" in claim
        assert "under " in claim
        assert "at a budget of" in claim
    for name in RATE_COUNT_ROSTER:
        threshold = family.threshold(name)
        assert threshold.null
        assert "mu = " in threshold.derivation
        assert "ln(1/eps) = " in threshold.derivation

    # And at a key too short for most of the roster to be certifiable at all,
    # where nine of the twelve go silent. Every one still produces a sentence
    # a reader can act on, and the silent ones say they detect nothing rather
    # than quoting a zero that looks like a strong bound.
    degenerate = RateCountThresholds.for_params(
        ProtocolParams(key_length=12), eps=1e-9
    )
    silent = [
        name
        for name in RATE_COUNT_ROSTER
        if degenerate.threshold(name).vacuous
    ]
    assert silent, "a 12-position key should not certify most of the roster"
    for name in RATE_COUNT_ROSTER:
        claim = degenerate.threshold(name).claim()
        assert "at a budget of" in claim
        if name in silent:
            assert "detects nothing" in claim
        else:
            assert "fires with probability at most" in claim


def test_the_threshold_layer_never_reaches_for_the_adversary():
    """The shipped detector must build without the attacks package.

    A static import edge from the detector to the adversary suite would mean a
    detection rate measured by something that could, in principle, see the
    ground truth.

    ``tests/test_detect_statistics.py`` already globs the same package and
    asserts the same thing, and this is a deliberate second copy rather than an
    oversight: the guard protects a property of the *package*, three modules
    now live in it that did not when layer one was written, and a boundary
    check that lives in only one file is one deletion away from being a
    boundary check about nothing. Cheap -- four small files read -- and it
    fails in whichever suite is run.
    """
    for path in sorted(_MODULE.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                assert "sih141.attacks" not in stripped, (
                    f"{path.name} imports the adversary suite: {stripped}"
                )


def test_both_verifiers_get_the_same_null_and_different_roster_entries():
    """One null, two parties, and no way to score one against the other's.

    ``s_a`` and ``s_v`` differ, but the matched-count null does not: both
    recipients draw their bases the same way. The thresholds are therefore
    identical and the roster entries are not.

    What the separate entries buy differs by member, and it is worth being
    precise about which. For the **matched count** the party is a real
    attribution: a recipient forger's own count moves and his counterpart's
    does not, which is why ``matched_count_high:Charlie`` fires on a recipient
    forgery and Bob's member stays silent. For the **mismatch rate** it is not
    -- symmetrisation smears damaged records across both recipients, so the
    party there names the verifier who scored and nothing about the link
    (finding F5). Same shape of roster name, two different meanings, and only
    one of them is an attribution.
    """
    family = RateCountThresholds.for_params(
        ProtocolParams(key_length=600), eps=1e-9
    )
    names = [str(party) for party in VERIFIERS]
    assert names == ["Bob", "Charlie"]
    bob = family.threshold("matched_count_low:Bob")
    charlie = family.threshold("matched_count_low:Charlie")
    assert bob.critical_count == charlie.critical_count
    assert bob.name != charlie.name
