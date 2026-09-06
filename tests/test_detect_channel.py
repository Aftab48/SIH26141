"""Phase 4: the channel threshold family, and the claims it is allowed to make.

This file pins :mod:`sih141.detect.thresholds_channel`, whose whole content is
five derivations. A threshold family can be wrong in three quite different
ways, and the sections are one per way.

1. **The algebra could be wrong.** Section 1 recomputes every shipped bound
   from the inequality the object says it used, independently of the code that
   produced it, and checks the two agree. It also checks the properties a
   correct inversion must have and an incorrect one usually does not: the
   critical value moves the right way as ``eps`` shrinks, the exact binomial
   threshold is the *smallest* count meeting its budget rather than merely a
   count that meets it, and no member ever reports a bound above its own
   budget. The sharpest of these is
   ``test_the_exact_inversion_agrees_with_rational_arithmetic_at_every_count``,
   which computes the binomial tail in :class:`fractions.Fraction` -- no
   floating point anywhere -- feeds each exact tail back in as the budget, and
   demands the inversion return exactly that count. The whole shipped
   guarantee is that arithmetic, so it is pinned against a construction that
   cannot round.
2. **The null could be wrong.** Section 2 is the corollary convention **D7**
   permits: *checking* a derived law against honest data is allowed, *choosing*
   a number from attack data is not. The three Werner closed forms are checked
   against the shipped
   :class:`~sih141.protocol.session.ChannelSample`'s own eigendecomposition;
   the check-round error rate on an honest link running at depolarising
   strength ``p`` is checked against ``p/2``; and ``S`` is checked against
   ``(1 - p) 2 sqrt(2)``. No adversary appears anywhere in this file. Every
   noisy run here is an **honest** run over a noisy channel, which is a
   different thing and is the only kind of data a threshold may be measured
   against.
3. **The bound could be right and the code could still fire.** Section 3
   measures the false-positive rate over honest runs and checks it against the
   *proven* bound. If a measurement ever exceeds a derivation, the derivation
   is wrong and the measurement is right.

Then the three things this family must refuse to do:

4. **Section 4** pins the dealing arithmetic against the dealer that actually
   deals, because :func:`~sih141.detect.thresholds_channel.link_check_rounds`
   is a restatement of somebody else's rule and a restatement is exactly the
   kind of prose number this project has shipped wrong before.
5. **Section 5** pins the refusals: a missing observation is not a passing one,
   an unmonitored link is unavailable rather than clean, a certificate is not
   an alarm, and a threshold whose bound exceeds its budget cannot be built at
   all.
6. **Section 6** pins the cost of the point-mass nulls. "It is a claim about a
   noiseless link" is prose until an honest run over a noisy link fires every
   one of them, which is what that section shows.

Notes
-----
Determinism (D3)
    Every session is seeded through an injected
    :class:`numpy.random.Generator`, and the threshold layer itself draws no
    randomness at all -- a test asserts that screening the same link twice
    gives the same answer.
No machine learning (D4)
    Nothing in this file selects a number. The bands in section 2 are standard
    errors of the law under test, computed from that law's own parameters, and
    the budgets in section 3 are stated up front and never adjusted.
Attack randomness (D6)
    Not applicable: there is no adversary in this file. The noisy links are
    honest links with a noisy ``resource_factory``, which is a seam the session
    owns.
"""

from __future__ import annotations

import dataclasses
import json
import math
from fractions import Fraction

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix

from sih141.core.states import BellState, bell_state
from sih141.detect.statistics import (
    IDEAL_TOLERANCE,
    LinkStatistics,
    ResourceStatistics,
    TranscriptStatistics,
)
from sih141.detect.thresholds_channel import (
    CHANNEL_STATISTICS,
    CONCURRENCE_RANGE,
    FIDELITY_RANGE,
    PURITY_RANGE,
    ChannelScreen,
    ChannelThreshold,
    bounded_mean_threshold,
    chsh_certificate_threshold,
    chsh_threshold,
    concurrence_threshold,
    divide_budget,
    fidelity_threshold,
    link_check_rounds,
    purity_threshold,
    qber_threshold,
    screen_link,
    werner_concurrence,
    werner_fidelity,
    werner_purity,
)
from sih141.protocol.checkrounds import (
    CHECK_CHSH_WEIGHT,
    CLASSICAL_CHSH_BOUND,
    IDEAL_CHSH,
    ChshRound,
    QberRound,
    draw_check_plan,
    estimate_chsh,
    observe_chsh_round,
)
from sih141.protocol.distribute import ResourceContext
from sih141.protocol.params import CHECKED_PARAMS, Party, ProtocolParams
from sih141.protocol.session import ChannelSample, QDSSession

#: Long enough that each link gets twenty-four QBER and twenty-four CHSH
#: rounds, short enough that a dozen runs finish in ten seconds. Carries no
#: security claim at this length and none is made from it: what is tested is
#: the *arithmetic* of the thresholds and the *shape* of the nulls, neither of
#: which depends on the floors biting.
LENGTH = 384

#: The check fraction every run here uses. A quarter rather than
#: :data:`~sih141.protocol.params.DEFAULT_CHECK_FRACTION` so that a short run
#: still produces a Bell sample with all four cells occupied most of the time.
CHECK_FRACTION = 0.25

#: Honest, noiseless runs behind section 3's false-positive measurement.
HONEST_SEEDS = tuple(range(12))

#: Honest runs over a *noisy* channel, for the null checks and for section 6.
NOISY_SEEDS = tuple(range(5))

#: The two depolarising strengths section 2 checks the laws at. One inside the
#: scheme's own noise budget's neighbourhood and one well outside it, so a law
#: that happened to hold only near zero would fail.
NOISE_LEVELS = (0.1, 0.3)

#: Band half-width for the law checks in section 2, in standard errors of the
#: law being tested. Five rather than two because the file makes several such
#: comparisons and a two-sigma band would be expected to fail about once per
#: run on correct code; five is a per-comparison false-alarm probability of
#: ``5.7e-07`` and is still far tighter than any defect these derivations can
#: produce, which are wrong by factors rather than by three standard errors.
SIGMAS = 5.0

#: Budgets swept wherever a property has to hold at every operating point
#: rather than at one, in decreasing order so a monotonicity check can walk
#: them. Phase 5 draws a ROC curve by sweeping exactly this way. All of them
#: sit above the exact inversion's arithmetic floor of ``1e-300``, so every
#: member of the family is exercised at every entry.
BUDGETS = (0.5, 1e-02, 1e-04, 1e-09, 1e-15, 1e-40)

_PHI_PLUS = DensityMatrix(bell_state(BellState.PHI_PLUS)).data


def _session_rng(index: int) -> np.random.Generator:
    """Return the session generator for one run.

    Parameters
    ----------
    index : int
        Which run.

    Returns
    -------
    numpy.random.Generator
    """
    return np.random.default_rng(20_260_141 + index)


def _werner(strength: float) -> DensityMatrix:
    """Return the Werner resource ``(1 - p) |Phi+><Phi+| + p I/4``.

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.

    Returns
    -------
    qiskit.quantum_info.DensityMatrix
    """
    return DensityMatrix(
        (1.0 - strength) * _PHI_PLUS + strength * np.eye(4) / 4.0
    )


def _werner_factory(strength: float):
    """Return a ``resource_factory`` seam that emits a Werner pair every call.

    An **honest** noisy channel, not an adversary: the seam draws no randomness
    of its own, closes over no session state and treats every position alike,
    so a run through it is an honest run over a depolarising link.

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.

    Returns
    -------
    callable
    """
    state = _werner(strength)
    return lambda: state


def _links(transcript) -> list[LinkStatistics]:
    """Return every link of one transcript, through the JSON boundary.

    Parameters
    ----------
    transcript : SessionTranscript
        The run.

    Returns
    -------
    list of LinkStatistics
    """
    statistics = TranscriptStatistics.from_transcript(transcript)
    return list(statistics.links.values())


@pytest.fixture(scope="module")
def honest_links() -> tuple[LinkStatistics, ...]:
    """Return every link of twelve honest, noiseless, checked runs.

    Returns
    -------
    tuple of LinkStatistics
    """
    collected: list[LinkStatistics] = []
    for index in HONEST_SEEDS:
        collected.extend(
            _links(
                QDSSession(
                    ProtocolParams(
                        key_length=LENGTH, check_fraction=CHECK_FRACTION
                    ),
                    rng=_session_rng(index),
                ).run(0)
            )
        )
    return tuple(collected)


@pytest.fixture(scope="module")
def noisy_links() -> dict[float, tuple[LinkStatistics, ...]]:
    """Return every link of honest runs over depolarising channels.

    Returns
    -------
    dict
        Keyed by depolarising strength.
    """
    collected: dict[float, tuple[LinkStatistics, ...]] = {}
    for strength in NOISE_LEVELS:
        links: list[LinkStatistics] = []
        for index in NOISY_SEEDS:
            links.extend(
                _links(
                    QDSSession(
                        ProtocolParams(
                            key_length=LENGTH, check_fraction=CHECK_FRACTION
                        ),
                        rng=_session_rng(500 + index),
                        resource_factory=_werner_factory(strength),
                    ).run(0)
                )
            )
        collected[strength] = tuple(links)
    return collected


# =========================================================================== #
# 1. The algebra: every bound recomputed from the inequality it names
# =========================================================================== #


def _binomial_upper_tail(critical: int, trials: int, rate: float) -> float:
    """Return ``P(X >= critical)`` for ``X ~ Binomial(trials, rate)``.

    Built from the **ratio recurrence**
    ``pmf(j) = pmf(j-1) (n - j + 1)/j * q/(1-q)`` in log space, starting from
    ``pmf(0) = (1-q)^n``. Deliberately a different construction from the
    module's own table, which reaches each term through :func:`math.lgamma`, so
    that the two are a genuine cross-check rather than the same expression
    written twice. A closed form with :func:`math.comb` would be the third
    obvious route and is not usable here: ``comb(4114, 2000)`` is an integer of
    twelve hundred digits and overflows on conversion to a float.

    Parameters
    ----------
    critical : int
        The count the tail starts at.
    trials : int
        ``n``.
    rate : float
        ``q``, strictly inside ``(0, 1)``.

    Returns
    -------
    float
    """
    if critical > trials:
        return 0.0
    log_odds = math.log(rate) - math.log1p(-rate)
    log_mass = trials * math.log1p(-rate)
    terms: list[float] = []
    for hits in range(trials + 1):
        if hits:
            log_mass += (
                math.log(trials - hits + 1) - math.log(hits) + log_odds
            )
        if hits >= critical:
            terms.append(math.exp(log_mass) if log_mass > -745.0 else 0.0)
    return min(1.0, math.fsum(terms))


@pytest.mark.parametrize("budget", BUDGETS)
def test_the_noiseless_qber_threshold_is_one_error_at_every_budget(budget):
    """A point-mass null has nothing left for a budget to buy.

    ``E >= 0`` and ``E[E] = 0`` force ``E = 0`` almost surely, so ``P(E >= 1)``
    is zero exactly and no inequality can improve on it. The budget is
    therefore not consulted, and the threshold is the same number at ``0.5`` as
    at ``1e-40``.
    """
    threshold = qber_threshold(rounds=1000, epsilon=budget)
    assert threshold.critical_value == 1.0
    assert threshold.false_positive_bound == 0.0
    assert threshold.inequality == "point mass (exact)"


@pytest.mark.parametrize("method", ["exact", "chernoff", "hoeffding"])
@pytest.mark.parametrize("budget", [1e-02, 1e-09, 1e-15])
@pytest.mark.parametrize("rounds", [24, 400, 4114])
def test_every_qber_threshold_really_holds_its_budget(method, budget, rounds):
    """The exact tail at the shipped threshold is at or below the budget.

    The claim each of the three inversions makes is a claim about the *true*
    binomial tail, so the test evaluates that tail rather than the inequality
    the inversion used. A loose inequality is allowed to overshoot; none of
    them is allowed to undershoot.
    """
    threshold = qber_threshold(
        rounds=rounds,
        epsilon=budget,
        tolerated_depolarising=1 / 32,
        method=method,
    )
    tail = _binomial_upper_tail(
        int(threshold.critical_value), rounds, 1 / 64
    )
    assert tail <= budget
    assert threshold.false_positive_bound <= budget


@pytest.mark.parametrize("budget", [1e-02, 1e-09, 1e-15])
@pytest.mark.parametrize("rounds", [24, 400, 4114])
def test_the_exact_qber_threshold_is_the_smallest_one_that_holds(
    budget, rounds
):
    """Not merely *a* threshold meeting the budget, but the tightest.

    A derivation that overshot by one would still satisfy every bound in this
    file while throwing away detection power, and nothing else here would
    notice. The check is the definition: one count lower must break the budget.
    """
    threshold = qber_threshold(
        rounds=rounds,
        epsilon=budget,
        tolerated_depolarising=1 / 32,
        method="exact",
    )
    critical = int(threshold.critical_value)
    assert _binomial_upper_tail(critical, rounds, 1 / 64) <= budget
    assert _binomial_upper_tail(critical - 1, rounds, 1 / 64) > budget


@pytest.mark.parametrize("rounds", [1, 2, 5, 12, 40, 120])
@pytest.mark.parametrize(
    "rate", [Fraction(1, 64), Fraction(1, 8), Fraction(1, 2)]
)
def test_the_exact_inversion_agrees_with_rational_arithmetic_at_every_count(
    rounds, rate
):
    """The strongest form of the sharpness check: exact rationals, every ``k``.

    The binomial tail is a finite sum of rationals, so it can be computed with
    no floating point at all. For each ``k`` this feeds the *exact* tail back
    in as the budget and demands that the inversion return exactly ``k``: any
    smaller threshold would break the budget and any larger one would be
    leaving detection power on the table. Doing it through the public entry
    point rather than the private table means what is tested is the number the
    detector will actually use.

    The whole shipped guarantee -- "under the null this fires with probability
    at most ``eps``" -- is this arithmetic, so it is worth pinning against a
    construction that cannot round.
    """
    tolerated = 2 * rate  # q0 = p0 / 2, so p0 = 2 q0
    if tolerated > 1:
        pytest.skip("a depolarising strength above one is not a channel")
    exact = [Fraction(0)] * (rounds + 2)
    accumulated = Fraction(0)
    for hits in range(rounds, -1, -1):
        accumulated += (
            Fraction(math.comb(rounds, hits))
            * rate**hits
            * (1 - rate) ** (rounds - hits)
        )
        exact[hits] = accumulated
    for critical in range(1, rounds + 1):
        budget = float(exact[critical]) * (1.0 + 1e-09)
        if not 0.0 < budget < 1.0:
            continue
        threshold = qber_threshold(
            rounds=rounds,
            epsilon=budget,
            tolerated_depolarising=float(tolerated),
            method="exact",
        )
        assert threshold.critical_value == float(critical)
        assert threshold.false_positive_bound == pytest.approx(
            float(exact[critical]), rel=1e-09
        , abs=0)


def test_the_three_qber_inversions_are_ordered_by_how_much_they_waste():
    """Exact is tightest, Chernoff close behind, Hoeffding far away.

    The ordering is a property of the inequalities, not of any data: the
    additive form is charged for a variance of ``n/4`` where the truth is
    ``n q0 (1 - q0)``, which at a QBER's small ``q0`` is most of the sample
    thrown away. The numbers are worth pinning because a report that quoted
    Hoeffding's threshold as "the" threshold would be understating this
    scheme's channel sensitivity by a factor of more than two.
    """
    values = {
        method: qber_threshold(
            rounds=4114,
            epsilon=1e-09,
            tolerated_depolarising=1 / 32,
            method=method,
        ).critical_value
        for method in ("exact", "chernoff", "hoeffding")
    }
    assert values == {"exact": 118.0, "chernoff": 128.0, "hoeffding": 271.0}
    assert values["exact"] < values["chernoff"] < values["hoeffding"]


@pytest.mark.parametrize("method", ["exact", "chernoff", "hoeffding"])
def test_a_smaller_qber_budget_never_lowers_the_threshold(method):
    """Monotonicity in ``eps``, which is what makes a ROC curve a curve.

    A sweep that moved the threshold the wrong way would draw a curve that
    doubled back, and the defect would look like a modelling subtlety rather
    than like the inversion error it is.
    """
    previous = 0.0
    for budget in BUDGETS:
        value = qber_threshold(
            rounds=4114,
            epsilon=budget,
            tolerated_depolarising=1 / 32,
            method=method,
        ).critical_value
        assert value >= previous
        previous = value


@pytest.mark.parametrize("budget", BUDGETS)
@pytest.mark.parametrize(
    "counts", [(6, 6, 6, 6), (4, 5, 8, 7), (1028, 1029, 1029, 1029)]
)
def test_the_chsh_half_width_is_the_mcdiarmid_inversion(budget, counts):
    """Recompute ``t`` from the bounded differences, not from the code.

    Flipping one round of cell ``c`` moves ``S`` by ``2/n_c``, so
    ``sum_i c_i^2 = 4 sum_c 1/n_c`` and McDiarmid gives
    ``exp(-t^2 / (2 sum_c 1/n_c))``. The test rebuilds that exponent from the
    counts alone and checks the shipped threshold sits exactly there.
    """
    threshold = chsh_threshold(counts=counts, epsilon=budget)
    half_width = IDEAL_CHSH - threshold.critical_value
    reciprocal = sum(1.0 / count for count in counts)
    exponent = math.exp(-half_width * half_width / (2.0 * reciprocal))
    assert exponent == pytest.approx(budget, rel=1e-12, abs=0)
    assert threshold.false_positive_bound <= budget


def test_bounding_s_directly_beats_summing_four_per_cell_bounds():
    """Why the protocol's own Hoeffding CHSH interval is not inverted here.

    :func:`~sih141.protocol.checkrounds.estimate_chsh`'s ``"hoeffding"`` method
    bounds each correlator separately and sums four half-widths under a union
    bound over four cells and two tails, which is the right shape for a
    two-sided *reporting* interval on all four numbers at once. A threshold
    needs one bound on one number in one direction, and McDiarmid gives it
    directly. The comparison is made against the shipped implementation rather
    than against a restatement of its formula, so that a change upstream is
    caught here.
    """
    rng = np.random.default_rng(20_260_141)
    state = _werner(0.0)
    sample = [
        observe_chsh_round(
            state, ChshRound(index, index // 2 % 2, index % 2), rng=rng
        )
        for index in range(4000)
    ]
    theirs = estimate_chsh(sample, method="hoeffding")
    assert theirs.counts == (1000, 1000, 1000, 1000)
    mine = chsh_threshold(counts=theirs.counts, epsilon=(1 - 0.99) / 2)
    ours = IDEAL_CHSH - mine.critical_value
    assert theirs.interval.half_width / ours == pytest.approx(2.25, abs=0.01)


@pytest.mark.parametrize("budget", BUDGETS)
def test_the_chsh_certificate_sits_the_same_half_width_above_two(budget):
    """Same inequality, other tail, different null.

    The certificate is not the detector with a sign flipped: its null is "the
    true statistic is at most the classical bound", which is a statement about
    a *resource* rather than about a channel. What the two share is the
    bounded-difference constant, and the test pins that they share exactly it.
    """
    counts = (1028, 1029, 1029, 1029)
    detector = chsh_threshold(counts=counts, epsilon=budget)
    certificate = chsh_certificate_threshold(counts=counts, epsilon=budget)
    assert certificate.critical_value - CLASSICAL_CHSH_BOUND == pytest.approx(
        IDEAL_CHSH - detector.critical_value, rel=1e-12
    , abs=0)
    assert certificate.is_alarm is False
    assert detector.is_alarm is True


@pytest.mark.parametrize("budget", BUDGETS)
@pytest.mark.parametrize("samples", [1, 24, 48, 4114])
def test_the_bounded_mean_half_width_is_the_hoeffding_inversion(
    budget, samples
):
    """``t = (b - a) sqrt(ln(1/eps) / (2n))``, recomputed from the span.

    And the span matters: a two-qubit purity charged for ``[0, 1]`` instead of
    ``[1/4, 1]`` gets a half-width a third too wide, which is a third of the
    sensitivity given away for a range the quantity cannot reach.
    """
    for span, honest in (
        (FIDELITY_RANGE, 0.9),
        (PURITY_RANGE, 0.85),
        (CONCURRENCE_RANGE, 0.8),
    ):
        threshold = bounded_mean_threshold(
            samples=samples,
            epsilon=budget,
            honest_mean=honest,
            span=span,
            statistic="mean_x",
            quantity="x",
        )
        width = span[1] - span[0]
        expected = width * math.sqrt(-math.log(budget) / (2.0 * samples))
        assert honest - threshold.critical_value == pytest.approx(
            expected, rel=1e-12
        , abs=0)
        assert threshold.false_positive_bound <= budget


def test_the_purity_span_is_a_quarter_narrower_than_the_naive_one():
    """``[1/4, 1]`` against ``[0, 1]``, as the number it is worth.

    Not a tuning choice: ``Tr(rho^2) >= 1/d`` is a theorem for a
    ``d``-dimensional state, and ``d = 4`` here.
    """
    narrow = purity_threshold(
        samples=48, epsilon=1e-09, tolerated_depolarising=0.1
    )
    wide = bounded_mean_threshold(
        samples=48,
        epsilon=1e-09,
        honest_mean=werner_purity(0.1),
        span=(0.0, 1.0),
        statistic="mean_purity",
        quantity="purity",
    )
    narrow_gap = werner_purity(0.1) - narrow.critical_value
    wide_gap = werner_purity(0.1) - wide.critical_value
    assert narrow_gap / wide_gap == pytest.approx(0.75, rel=1e-12, abs=0)


@pytest.mark.parametrize("budget", BUDGETS)
def test_no_member_of_the_family_ever_exceeds_its_own_budget(budget):
    """The invariant the carrier enforces, exercised across the family.

    Every threshold this module builds must satisfy
    ``false_positive_bound <= epsilon``. The constructor raises if it does not,
    so this test is really asking whether every construction site has actually
    proved what it claims.
    """
    built = [
        qber_threshold(rounds=48, epsilon=budget),
        qber_threshold(
            rounds=48,
            epsilon=budget,
            tolerated_depolarising=1 / 32,
            method="chernoff",
        ),
        qber_threshold(
            rounds=48,
            epsilon=budget,
            tolerated_depolarising=1 / 32,
            method="hoeffding",
        ),
        chsh_threshold(counts=(12, 12, 12, 12), epsilon=budget),
        chsh_certificate_threshold(counts=(12, 12, 12, 12), epsilon=budget),
        fidelity_threshold(samples=48, epsilon=budget),
        purity_threshold(samples=48, epsilon=budget),
        concurrence_threshold(samples=48, epsilon=budget),
        fidelity_threshold(
            samples=48, epsilon=budget, tolerated_depolarising=0.2
        ),
        purity_threshold(
            samples=48, epsilon=budget, tolerated_depolarising=0.2
        ),
        concurrence_threshold(
            samples=48, epsilon=budget, tolerated_depolarising=0.2
        ),
    ]
    for threshold in built:
        assert threshold.false_positive_bound <= threshold.epsilon
        assert 0.0 <= threshold.false_positive_bound <= 1.0


def test_a_threshold_whose_bound_exceeds_its_budget_cannot_be_built():
    """The tripwire for a future derivation that does not deliver.

    Not a tolerance and not a clamp: every construction site proves its bound
    analytically before the object is made, so a value above the budget means
    an inversion is wrong. A contributor who ships one finds out here rather
    than in a Phase 5 table.
    """
    with pytest.raises(ValueError, match="has not been derived"):
        ChannelThreshold(
            statistic="qber_errors",
            direction="upper",
            critical_value=3.0,
            epsilon=1e-09,
            false_positive_bound=1e-06,
            null="Binomial(48, 1/64)",
            inequality="wishful thinking",
            sample_size=48,
            derivation="none",
        )


# =========================================================================== #
# 2. The nulls, checked against honest data (the corollary D7 permits)
# =========================================================================== #


@pytest.mark.parametrize(
    "strength", [0.0, 1 / 32, 0.1, 0.3, 0.5, 2 / 3, 0.9, 1.0]
)
def test_the_three_werner_closed_forms_match_the_shipped_diagnostics(strength):
    """The nulls' arithmetic against the transcript's own eigendecomposition.

    :func:`~sih141.detect.thresholds_channel.werner_fidelity`,
    ``werner_purity`` and ``werner_concurrence`` are the closed forms every
    noise-tolerant resource threshold is stated at. They are checked against
    :class:`~sih141.protocol.session.ChannelSample`, which computes the same
    three quantities numerically from the four-by-four density matrix by a
    completely separate path. A drift here would move three thresholds at once
    and nothing else in the project would notice.
    """
    context = ResourceContext(party=Party.BOB, message_bit=0, position=3)
    sample = ChannelSample.of(
        _werner(strength), context, QberRound(3, "Z")
    )
    assert sample.fidelity == pytest.approx(
        werner_fidelity(strength), abs=1e-12
    )
    assert sample.purity == pytest.approx(werner_purity(strength), abs=1e-12)
    assert sample.concurrence == pytest.approx(
        werner_concurrence(strength), abs=1e-12
    )


def test_concurrence_and_fidelity_agree_through_the_two_f_minus_one_identity():
    """``C = max(0, 2F - 1)`` on the Werner family, as a second route.

    Two closed forms tied to each other, so a typo in one has to be matched by
    a compensating typo in the other to go unnoticed.
    """
    for strength in (0.0, 0.1, 0.4, 2 / 3, 0.8):
        assert werner_concurrence(strength) == pytest.approx(
            max(0.0, 2.0 * werner_fidelity(strength) - 1.0), abs=1e-12
        )


def test_the_ideal_resource_null_is_a_point_mass_on_every_honest_run(
    honest_links,
):
    """Not "close to one": exactly one, on every monitored round.

    This is the fact the exactly-zero false-positive bound rests on, and it is
    the one that would quietly stop being true if a resource factory or a
    monitor changed. Checked to :data:`IDEAL_TOLERANCE`, the same slack the
    thresholds sit at.
    """
    assert honest_links
    for link in honest_links:
        resource = link.resource
        assert resource.samples > 0
        assert resource.min_fidelity >= 1.0 - IDEAL_TOLERANCE
        assert resource.min_purity >= 1.0 - IDEAL_TOLERANCE
        assert resource.min_concurrence >= 1.0 - IDEAL_TOLERANCE
        assert link.errors.count == 0


@pytest.mark.parametrize("strength", NOISE_LEVELS)
def test_the_check_round_error_rate_is_the_stated_p_over_two(
    noisy_links, strength
):
    """The QBER null, measured on honest runs over a depolarising link.

    ``q0 = p/2`` is the protocol's own identity -- the check-round error rate
    in a basis equals the key mismatch rate in that basis, exactly, for every
    Bell-diagonal resource -- and it is the number every noise-tolerant QBER
    threshold is stated at. If it is wrong the whole family is stated at the
    wrong place.

    The two links are pooled *for this law check only*, and that is not the
    pooling Phase 3 forbids: there is no attack here to attribute, and both
    links run through the same honest channel by construction, so they share a
    law. Pooling to *detect* would still be wrong and the module offers no way
    to do it.
    """
    links = noisy_links[strength]
    errors = sum(link.errors.count for link in links)
    rounds = sum(link.errors.trials for link in links)
    assert rounds > 0
    expected = strength / 2.0
    spread = math.sqrt(rounds * expected * (1.0 - expected))
    assert abs(errors - rounds * expected) <= SIGMAS * spread


@pytest.mark.parametrize("strength", NOISE_LEVELS)
def test_the_chsh_null_is_the_depolarising_law(noisy_links, strength):
    """``E[S] = (1 - p) 2 sqrt(2)``, measured on honest noisy links.

    Each link is standardised by **its own** null variance
    ``sum_c (1 - E_c^2)/n_c`` computed from the predicted correlators, not from
    the measured ones, and the standardised deviations are averaged. Using the
    measured correlators would let a badly wrong ``S`` widen its own band until
    it fitted.
    """
    links = [
        link for link in noisy_links[strength] if link.chsh is not None
    ]
    assert links
    predicted = (1.0 - strength) * IDEAL_CHSH
    correlator = (1.0 - strength) / math.sqrt(2.0)
    standardised = []
    for link in links:
        variance = sum(
            (1.0 - correlator * correlator) / count
            for count in link.chsh.counts
        )
        standardised.append(
            (link.chsh.statistic - predicted) / math.sqrt(variance)
        )
    average = sum(standardised) / len(standardised)
    assert abs(average) <= SIGMAS / math.sqrt(len(standardised))


def test_the_chsh_null_holds_on_a_large_direct_sample():
    """The same law again, away from the session, at a sample that resolves it.

    A per-link Bell sample is two dozen rounds, so the session-level check
    above has a standard error of a few tenths. This one drives
    :func:`~sih141.protocol.checkrounds.observe_chsh_round` directly at four
    thousand rounds per noise level, where the prediction is resolved to about
    two hundredths and a wrong law could not hide.
    """
    rng = np.random.default_rng(20_260_141)
    for strength in (0.0, 0.3):
        state = _werner(strength)
        sample = [
            observe_chsh_round(
                state,
                ChshRound(
                    index, int(rng.integers(2)), int(rng.integers(2))
                ),
                rng=rng,
            )
            for index in range(4000)
        ]
        estimate = estimate_chsh(sample)
        predicted = (1.0 - strength) * IDEAL_CHSH
        correlator = (1.0 - strength) / math.sqrt(2.0)
        spread = math.sqrt(
            sum(
                (1.0 - correlator * correlator) / count
                for count in estimate.counts
            )
        )
        assert abs(estimate.statistic - predicted) <= SIGMAS * spread


# =========================================================================== #
# 3. The measured false-positive rate against the proven bound
# =========================================================================== #


@pytest.mark.parametrize("budget", [1e-15, 1e-09, 1e-03, 1e-02])
def test_no_honest_link_trips_the_screen_at_any_budget(honest_links, budget):
    """The measurement the derivations have to survive.

    Forty-eight honest links, four budgets spanning thirteen orders of
    magnitude, and nothing fires. The claim is quantitative rather than
    hopeful: the test also sums the proven bound over every screen it ran and
    checks that total is far below one, so that "nothing fired" is what the
    derivations *predict* rather than a happy accident of the seeds. If this
    ever fires, the derivation is wrong and the measurement is right.
    """
    screens = [screen_link(link, epsilon=budget) for link in honest_links]
    fired = [screen for screen in screens if screen.detected]
    assert not fired, [screen.summary() for screen in fired]
    total = math.fsum(screen.false_positive_bound for screen in screens)
    # Only CHSH costs anything: the other four nulls are point masses whose
    # bound is exactly zero, so the whole sample's expected false-alarm count
    # is the sum of one member's share per screen -- and at the loosest budget
    # here that is under a tenth of one alarm, which is why zero is what the
    # derivations predict rather than what the seeds happened to give.
    assert total == pytest.approx(
        math.fsum(
            budget / screen.evaluated
            for screen in screens
            if "chsh" in screen.thresholds
        ),
        rel=1e-12,
        abs=0,
    )
    assert total <= budget * len(screens)
    assert total < 0.1


def test_the_screen_bound_is_not_the_budget_because_most_nulls_are_exact(
    honest_links,
):
    """At ``1e-09`` the whole five-member screen costs ``2e-10``.

    Four of the five nulls are point masses whose bound is exactly zero, so the
    screen costs precisely what its one non-degenerate member -- CHSH -- costs,
    which is one fifth of the budget. Reporting the budget instead would
    overstate the family's own false-positive rate by a factor of five, in the
    direction that looks conservative and is simply wrong.
    """
    for link in honest_links[:8]:
        screen = screen_link(link, epsilon=1e-09)
        if screen.evaluated != len(CHANNEL_STATISTICS):  # pragma: no cover
            continue
        assert screen.false_positive_bound == pytest.approx(2e-10, rel=1e-12, abs=0)
        exact = [
            name
            for name, threshold in screen.thresholds.items()
            if threshold.false_positive_bound == 0.0
        ]
        assert len(exact) == 4


@pytest.mark.parametrize("budget", [1e-15, 1e-09, 1e-03])
def test_every_evaluated_threshold_can_actually_fire(honest_links, budget):
    """Zero false alarms would be trivial if nothing could ever fire.

    So the same screens are checked for *power*: each threshold is fed an
    observation one step past its own critical value and must fire. No attack
    data is involved -- the probe is derived from the threshold itself -- and
    the check is what stops a derivation that quietly returns an unreachable
    number from passing section 3 by doing nothing at all.
    """
    for link in honest_links[:8]:
        screen = screen_link(link, epsilon=budget)
        for name, threshold in screen.thresholds.items():
            if not threshold.reaches_its_statistic:
                continue
            if threshold.direction == "upper":
                probe = threshold.critical_value + 1.0
            else:
                probe = threshold.critical_value - 1e-06
            assert threshold.fires(probe), name
            assert not threshold.fires(
                threshold.critical_value + (
                    -1.0 if threshold.direction == "upper" else 1e-06
                )
            ), name


def test_the_screens_union_bound_is_the_sum_of_its_members(honest_links):
    """The union bound is arithmetic, and the arithmetic is checked.

    ``P(any of m fires) <= sum_j eps_j`` with ``eps_j = eps/m``, so the screen's
    reported bound must be the sum of the bounds its members prove and must sit
    at or below the budget. A screen that reported its budget instead would
    overstate its own false-positive rate by whatever the point masses save.
    """
    for link in honest_links:
        screen = screen_link(link, epsilon=1e-09)
        assert screen.false_positive_bound == pytest.approx(
            math.fsum(
                threshold.false_positive_bound
                for threshold in screen.thresholds.values()
            ),
            rel=1e-12,
            abs=0,
        )
        assert screen.false_positive_bound <= screen.epsilon
        assert screen.evaluated + len(screen.unavailable) == len(
            CHANNEL_STATISTICS
        )


def test_a_run_level_budget_has_to_be_divided_before_it_reaches_a_link():
    """Four screens at ``eps`` apiece is a run-level rate of ``4 eps``.

    The division is one line and is the step a Phase 5 author skips; the helper
    exists so the arithmetic is written down once rather than guessed four
    times.
    """
    assert divide_budget(1e-08, 4) == 2.5e-09
    assert divide_budget(0.05, 5) == pytest.approx(0.01)
    with pytest.raises(ValueError, match="at least 1"):
        divide_budget(1e-09, 0)


def test_screening_is_deterministic_and_draws_no_randomness(honest_links):
    """D3, as a property of the answer rather than of the imports.

    Two screens of the same link at the same budget must be equal in every
    field. A threshold layer that consulted a generator would be a threshold
    layer whose published operating point depended on when it ran.
    """
    link = honest_links[0]
    first = screen_link(link, epsilon=1e-09)
    second = screen_link(link, epsilon=1e-09)
    assert first == second
    assert first.to_dict() == second.to_dict()


def test_every_shipped_object_survives_strict_json(honest_links):
    """No ``NaN``, no ``Infinity``: a dashboard's parser must not be surprised.

    ``json.dumps`` writes both as bare tokens that are valid Python and are not
    JSON, which is how a downstream reader gets a document it rejects. The
    ``parse_constant`` hook turns either into a failure here instead.
    """

    def refuse(token: str) -> float:
        """Raise on a non-JSON constant.

        Parameters
        ----------
        token : str
            The offending token.

        Returns
        -------
        float
            Never returns.

        Raises
        ------
        AssertionError
            Always.
        """
        raise AssertionError(f"not JSON: {token}")

    for link in honest_links[:4]:
        screen = screen_link(link, epsilon=1e-09)
        text = json.dumps(screen.to_dict())
        assert json.loads(text, parse_constant=refuse) == screen.to_dict()
    for threshold in (
        qber_threshold(rounds=0, epsilon=1e-09),
        chsh_threshold(counts=(6, 6, 6, 6), epsilon=1e-09),
        purity_threshold(samples=0, epsilon=1e-09, tolerated_depolarising=0.1),
    ):
        text = json.dumps(threshold.to_dict())
        assert json.loads(text, parse_constant=refuse) == threshold.to_dict()


# =========================================================================== #
# 4. The dealing arithmetic, against the dealer that actually deals
# =========================================================================== #


@pytest.mark.parametrize("weight", [0.0, 0.25, CHECK_CHSH_WEIGHT, 0.75])
@pytest.mark.parametrize(
    "length, fraction",
    [(120, 0.125), (192, 0.25), (384, 0.25), (1000, 0.1), (2401, 0.125)],
)
def test_the_link_shares_match_the_plan_the_dealer_draws(
    length, fraction, weight
):
    """A restatement of somebody else's rule, checked against the rule.

    :func:`~sih141.detect.thresholds_channel.link_check_rounds` exists so a
    threshold can be sized without drawing a plan, which means it is a copy of
    :func:`~sih141.protocol.checkrounds.draw_check_plan`'s dealing logic. The
    copy is worth exactly as much as this test: five lengths, four weights, and
    the counter that runs on across the two arms so neither link collects both
    leftovers.
    """
    params = ProtocolParams(key_length=length, check_fraction=fraction)
    plan = draw_check_plan(
        params, rng=np.random.default_rng(7), chsh_weight=weight
    )
    shares = link_check_rounds(params, chsh_weight=weight)
    for share in shares:
        assert share.qber_rounds == sum(
            1 for entry in plan.qber_rounds if entry.party is share.party
        )
        assert share.chsh_rounds == sum(
            1 for entry in plan.chsh_rounds if entry.party is share.party
        )
    assert sum(share.total for share in shares) == params.check_count


def test_a_link_measures_half_the_reserved_set_and_pays_root_two_for_it():
    """The ``sqrt(2)`` a naive reading of ``check_count`` throws away.

    Every half-width in the family falls off as ``1/sqrt(n)``, so deriving a
    threshold from the run's arm total where the link's share belongs
    understates it by exactly ``sqrt(2)``. The claim is arithmetic and is
    stated as arithmetic.
    """
    shares = link_check_rounds(CHECKED_PARAMS)
    assert sum(share.total for share in shares) == CHECKED_PARAMS.check_count
    for share in shares:
        assert share.total * 2 == pytest.approx(
            CHECKED_PARAMS.check_count, abs=1
        )
    naive = chsh_threshold(counts=(2057, 2057, 2057, 2058), epsilon=1e-09)
    real = chsh_threshold(counts=(1028, 1029, 1029, 1029), epsilon=1e-09)
    naive_width = IDEAL_CHSH - naive.critical_value
    real_width = IDEAL_CHSH - real.critical_value
    assert real_width / naive_width == pytest.approx(math.sqrt(2.0), rel=1e-03, abs=0)


def test_the_sizing_figures_come_from_the_parameter_set_not_from_a_typist():
    """The module's sizing section quotes ``4114`` and ``8229``; here is why.

    Those are one link's QBER rounds and one link's total reserved positions at
    :data:`~sih141.protocol.params.CHECKED_PARAMS`, and the whole point of the
    section is that they are four orders of magnitude away from a toy run's
    twenty-four. A figure typed rather than derived is how this project has
    shipped wrong numbers before, so the two are tied together here.
    """
    bob, charlie = link_check_rounds(CHECKED_PARAMS)
    assert (bob.qber_rounds, bob.chsh_rounds, bob.total) == (4114, 4115, 8229)
    assert (charlie.qber_rounds, charlie.chsh_rounds) == (4115, 4114)
    share = divide_budget(1e-09, len(CHANNEL_STATISTICS))
    toy = qber_threshold(
        rounds=24, epsilon=share, tolerated_depolarising=0.05
    )
    real = qber_threshold(
        rounds=bob.qber_rounds, epsilon=share, tolerated_depolarising=0.05
    )
    # Both hold the same proven budget; only the fraction of the sample they
    # spend differs, and that is the sizing claim in one line.
    assert toy.critical_value / 24 > 0.4
    assert real.critical_value / bob.qber_rounds < 0.05
    assert toy.false_positive_bound <= share
    assert real.false_positive_bound <= share


def test_a_run_without_check_rounds_measures_nothing_and_says_so():
    """All-zero shares rather than an exception, because zero is the answer.

    Different from :func:`~sih141.protocol.checkrounds.draw_check_plan`, which
    raises: an empty *plan* would let a caller believe estimation was
    happening, while an empty *share* is the honest report that this run
    measured no channel at all.
    """
    shares = link_check_rounds(ProtocolParams(key_length=192))
    assert [share.total for share in shares] == [0, 0]


# =========================================================================== #
# 5. What the family refuses to do
# =========================================================================== #


def test_a_missing_observation_is_not_a_passing_one():
    """``None`` raises rather than reading as "did not fire".

    An unmonitored link has no value to compare, and silently clearing it is
    how a screen reports a channel as clean because nobody looked at it.
    """
    threshold = purity_threshold(samples=48, epsilon=1e-09)
    with pytest.raises(TypeError, match="not a passing one"):
        threshold.fires(None)
    with pytest.raises(ValueError, match="must be finite"):
        threshold.fires(float("nan"))


def test_an_unmonitored_link_is_unavailable_and_never_cleared(honest_links):
    """"We could not look" must not be recorded as "we looked and it was fine".

    The channel-family form of Phase 3's rule that a refusal is never a
    rejection, and the single most likely way for a Phase 5 table to report a
    detection -- or a clean bill -- that never happened.
    """
    blind = dataclasses.replace(
        honest_links[0],
        resource=ResourceStatistics(
            samples=0,
            qber_samples=0,
            chsh_samples=0,
            mean_fidelity=None,
            min_fidelity=None,
            mean_purity=None,
            min_purity=None,
            mean_concurrence=None,
            min_concurrence=None,
            mean_alice_purity=None,
            mean_recipient_purity=None,
            ideal_samples=honest_links[0].resource.ideal_samples,
            extra_keys=(),
        ),
    )
    screen = screen_link(blind, epsilon=1e-09)
    assert set(screen.unavailable) == {"fidelity", "purity", "concurrence"}
    for reason in screen.unavailable.values():
        assert "not a clean one" in reason
    assert not any(
        name in screen.cleared
        for name in ("min_fidelity", "min_purity", "min_concurrence")
    )
    assert screen.evaluated == 2
    assert screen.detected is False


def test_an_undefined_chsh_statistic_is_unavailable_rather_than_derived():
    """An empty cell has no correlator, so it has no threshold either.

    The bounded-difference constant for a cell is ``2/n_c``, which is infinite
    at ``n_c = 0``. The module refuses to derive from it and the screen records
    the refusal, carrying the transcript's own explanation forward rather than
    inventing one.
    """
    statistics = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=192, check_fraction=0.25),
            rng=np.random.default_rng(2),
        ).run(0)
    )
    link = statistics.link("Bob", 1)
    assert link.chsh is None
    screen = screen_link(link, epsilon=1e-09)
    assert "chsh" in screen.unavailable
    assert "chsh" not in screen.cleared
    assert screen.evaluated == len(CHANNEL_STATISTICS) - 1
    with pytest.raises(ValueError, match="hold no rounds"):
        chsh_threshold(counts=(0, 4, 4, 4), epsilon=1e-09)


def test_a_certificate_is_not_an_alarm_and_the_screen_will_not_take_one():
    """Failing to certify is not a detection.

    A short sample cannot certify anything, so a screen that counted a missing
    certificate as an alarm would publish a detection rate equal to its own
    sample-size problem. The type carries the distinction and the screen checks
    it.
    """
    certificate = chsh_certificate_threshold(
        counts=(6, 6, 6, 6), epsilon=1e-09
    )
    assert certificate.is_alarm is False
    assert certificate.direction == "upper"
    assert certificate.reaches_its_statistic is False
    assert certificate.critical_value > IDEAL_CHSH
    long = chsh_certificate_threshold(
        counts=(1028, 1029, 1029, 1029), epsilon=1e-09
    )
    assert long.reaches_its_statistic is True
    assert long.critical_value > CLASSICAL_CHSH_BOUND


def test_a_threshold_over_no_samples_cannot_fire_on_the_range_it_bounds():
    """A placeholder threshold must not turn a real observation into an alarm.

    With no monitored rounds the mean does not exist, so the threshold is
    placed strictly *below* the quantity's floor rather than on it: a
    concurrence of ``0`` is a real value a separable pair produces, and a
    threshold sitting exactly on the floor would fire on it.
    """
    for builder, floor in (
        (purity_threshold, PURITY_RANGE[0]),
        (concurrence_threshold, CONCURRENCE_RANGE[0]),
        (fidelity_threshold, FIDELITY_RANGE[0]),
    ):
        threshold = builder(
            samples=0, epsilon=1e-09, tolerated_depolarising=0.1
        )
        assert threshold.reaches_its_statistic is False
        assert threshold.critical_value < floor
        assert not threshold.fires(floor)
        assert threshold.false_positive_bound == 0.0


def test_a_separable_honest_null_is_unavailable_rather_than_an_exception():
    """A screen at a separable noise level drops concurrence, and says why.

    The decision is made from the stated ``p0`` alone, never from the
    observation, so the budget split stays independent of the data -- which is
    what makes the union bound's even division legitimate.
    """
    statistics = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=192, check_fraction=CHECK_FRACTION),
            rng=_session_rng(1),
        ).run(0)
    )
    screen = screen_link(
        statistics.link("Bob", 0), epsilon=1e-09, tolerated_depolarising=0.8
    )
    assert "concurrence" in screen.unavailable
    assert "separable" in screen.unavailable["concurrence"]
    assert "concurrence" not in screen.cleared
    assert "mean_concurrence" not in screen.thresholds


def test_a_separable_honest_null_has_no_lower_tail_to_bound():
    """A Werner resource is separable from ``p = 2/3``, where ``C`` is zero.

    Refusing is the honest answer: there is no deviation below zero, so there
    is no threshold, and returning ``0`` would be a threshold that fires on
    every run.
    """
    assert werner_concurrence(2 / 3) == 0.0
    with pytest.raises(ValueError, match="bottom of span"):
        concurrence_threshold(
            samples=48, epsilon=1e-09, tolerated_depolarising=0.7
        )
    # Fidelity and purity keep a tail there, because neither reaches its floor.
    assert (
        purity_threshold(
            samples=48, epsilon=1e-09, tolerated_depolarising=0.7
        ).critical_value
        < werner_purity(0.7)
    )


def test_the_family_offers_no_pooled_entry_point():
    """Per link, per message bit, never pooled -- enforced by absence.

    Phase 3's third constraint. The module exports nothing that takes more than
    one link's sample, so a caller who wants a pooled rate has to go through
    :func:`~sih141.detect.statistics.pooled_check_qber`, which makes the
    decision visible at the call site and says what it costs.
    """
    from sih141.detect import thresholds_channel

    assert not [
        name
        for name in thresholds_channel.__all__
        if "pool" in name.lower()
    ]
    assert "wings" not in " ".join(thresholds_channel.__all__).lower()


def test_a_screen_refuses_anything_that_is_not_a_link_statistic():
    """The boundary, at the entry point.

    The detector reads a JSON-round-tripped transcript through
    :class:`~sih141.detect.statistics.TranscriptStatistics` and nothing else;
    duck-typing the argument would let a harness object in through the front
    door.
    """
    with pytest.raises(TypeError, match="must be a LinkStatistics"):
        screen_link(object(), epsilon=1e-09)
    with pytest.raises(ValueError, match="strictly inside"):
        qber_threshold(rounds=24, epsilon=0.0)
    with pytest.raises(ValueError, match="strictly inside"):
        qber_threshold(rounds=24, epsilon=1.0)
    with pytest.raises(TypeError, match="must be a real number"):
        qber_threshold(rounds=24, epsilon=True)
    with pytest.raises(ValueError, match="method must be one of"):
        qber_threshold(rounds=24, epsilon=1e-09, method="eyeball")


def test_the_exact_inversion_refuses_a_budget_its_arithmetic_cannot_hold():
    """Below ``1e-300`` the binomial tail underflows, so the search is refused.

    Reporting a rounded-down ``0.0`` as a proven bound would be the one kind of
    error a security claim cannot absorb. The closed forms have no such floor
    and the message names them.
    """
    with pytest.raises(ValueError, match="method='exact' needs epsilon"):
        qber_threshold(
            rounds=48, epsilon=1e-320, tolerated_depolarising=1 / 32
        )
    for method in ("chernoff", "hoeffding"):
        threshold = qber_threshold(
            rounds=48,
            epsilon=1e-320,
            tolerated_depolarising=1 / 32,
            method=method,
        )
        assert threshold.critical_value == 49.0
        assert threshold.reaches_its_statistic is False
        assert threshold.false_positive_bound == 0.0


# =========================================================================== #
# 6. What the point-mass nulls cost, as a measurement rather than as prose
# =========================================================================== #


@pytest.mark.parametrize("strength", NOISE_LEVELS)
def test_a_noiseless_claim_fires_on_an_honest_but_noisy_link(
    noisy_links, strength
):
    """"A claim about a noiseless link" is prose until this test runs.

    Every point-mass threshold in the family fires on **every** link of an
    honest run over a depolarising channel, because that is exactly what the
    null says: on a noiseless link the resource summaries are ``1`` with
    probability one, and a link that is not noiseless violates it. The
    false-positive bound is still exactly zero -- *under that null* -- and the
    honest reading is that the null was the wrong one for this deployment, not
    that the detector misfired.
    """
    links = noisy_links[strength]
    assert links
    for link in links:
        screen = screen_link(link, epsilon=1e-09)
        assert screen.detected
        assert {"min_fidelity", "min_purity", "min_concurrence"} <= set(
            screen.fired
        )


@pytest.mark.parametrize("strength", NOISE_LEVELS)
def test_the_same_links_are_clean_once_the_null_is_stated_at_their_noise(
    noisy_links, strength
):
    """Hand the family the noise level and the same runs stop firing.

    Which is the point of ``tolerated_depolarising`` and the content of
    :ref:`finding 2 <findings>`: the transcript cannot say what the honest
    channel should have looked like, so a deployment with noisy pairs has to
    say it. A generous budget of ``0.05`` is used deliberately -- a threshold
    that survives a loose budget on honest data is a stronger statement than
    one that survives a tight one.
    """
    for link in noisy_links[strength]:
        screen = screen_link(
            link, epsilon=0.05, tolerated_depolarising=strength
        )
        assert not screen.detected, screen.summary()


def test_the_noise_tolerant_screen_reads_means_and_the_ideal_one_reads_minima(
    honest_links,
):
    """Which field a resource threshold names is a consequence of its null.

    Under the point mass the minimum carries the same exactly-zero bound and is
    sharper -- an attack touching one round in a thousand moves it and barely
    moves the mean. Under a Hoeffding null only the mean has a law that follows
    from the stated mean alone, so the minimum is not available there at any
    price.
    """
    link = honest_links[0]
    ideal = screen_link(link, epsilon=1e-09)
    noisy = screen_link(link, epsilon=1e-09, tolerated_depolarising=0.1)
    assert {"min_fidelity", "min_purity", "min_concurrence"} <= set(
        ideal.thresholds
    )
    assert {"mean_fidelity", "mean_purity", "mean_concurrence"} <= set(
        noisy.thresholds
    )
    for threshold in ideal.thresholds.values():
        if threshold.statistic.startswith("min_"):
            assert threshold.inequality == "point mass (exact)"
            assert threshold.false_positive_bound == 0.0
    for threshold in noisy.thresholds.values():
        if threshold.statistic.startswith("mean_"):
            assert threshold.inequality.startswith("Hoeffding")


def test_the_screen_carries_its_conditioning_where_a_reader_will_find_it():
    """(NO-TIMING) is documented at the module, not left to a reader's memory.

    Every statistic in this family is a check-round statistic, so every claim
    from it is conditioned on the adversary being unable to infer the check set
    from timing. A conditioned claim stated is rigour; the same claim unstated
    is an overclaim, and the assumption is load-bearing enough that its absence
    should fail a test rather than pass a review.
    """
    from sih141.detect import thresholds_channel

    text = thresholds_channel.__doc__ or ""
    assert "(NO-TIMING)" in text
    assert "channel-no-timing" in text
    for function in (chsh_threshold, screen_link, qber_threshold):
        assert "NO-TIMING" in (function.__doc__ or "")
    # And the Bell test's own second caveat, which is a different assumption
    # and is the one a CHSH number is most often quoted without: this is not a
    # device-independent certificate, it certifies under (AUTH).
    certificate = chsh_certificate_threshold.__doc__ or ""
    assert "device-independent" in certificate
    assert "(AUTH)" in certificate


def test_the_screen_summary_names_every_number_behind_it(honest_links):
    """A one-line account a reviewer can read without opening the object.

    The bound, the budget, how many statistics were evaluated and how many
    could not be -- the last of which is the one a summary that folded
    unavailable into cleared would silently drop.
    """
    screen = screen_link(honest_links[0], epsilon=1e-09)
    line = screen.summary()
    assert "nothing fired" in line
    assert "unavailable" in line
    assert "P(any fire | honest)" in line
    assert isinstance(screen, ChannelScreen)
    threshold = screen.thresholds["qber_errors"]
    assert "point mass" in threshold.summary()
    assert "n = 24" in threshold.summary()
