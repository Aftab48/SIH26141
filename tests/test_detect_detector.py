"""Phase 4 layer three: the composite rule, and the error rate of the family.

This file pins :mod:`sih141.detect.detector`. It is organised around the ways a
composite detector can be wrong while every component it is built from is
right, because that is the failure this layer exists to prevent: an OR of a
dozen individually-sound thresholds has a false-positive rate far worse than any
of them, and nothing inside a component would ever say so.

1. **The correction is derived and the arithmetic is checkable.** Section 1
   re-does the allocation of :ref:`C-2 <sih141.detect.detector:c2>` against its
   own algebra, recomputes the composite bound from the three families
   independently of :func:`~sih141.detect.detector.detect`, and -- the point of
   the whole layer -- measures what an *uncorrected* OR would have proven, so
   that "we applied a correction" is a number rather than a claim.
2. **The proven bound is not violated by honest data.** Section 2 is the
   corollary D7 permits: *checking* a derived bound against honest runs is
   allowed, *choosing* one from attack data is not. Honest corpora at two
   configurations, scored across fifteen orders of magnitude of budget, raise
   zero alarms; and at a deliberately loose budget where the derivation says
   alarms are *expected*, the observed rate is required to sit inside the bound
   by a binomial tail rather than by eyeball.
3. **A detector that cannot fire would pass section 2 too.** Section 3 is the
   companion power check: every threshold the composite builds is required to
   fire on an observation one step past its own critical value, and a
   hand-broken transcript is required to be detected. Zero alarms then means
   something.
4. **The deduction table is total, self-consistent, and cannot exclude on
   noise.** Section 4 attacks the table from the wrong side: it tries to build
   rows that would let a noisy honest link rule an adversary out, and requires
   the constructor to refuse.
5. **The boundary holds.** Section 5 checks the three doors agree and that
   nothing but a JSON-round-tripped transcript gets in.
6. **Then, and only then, the measurement.** Section 6 runs the five adversary
   families and reports what the frozen detector does with them. Nothing in
   sections 1-5 depends on it, no number in the module was chosen from it, and
   where an arm is not separated the test asserts that it is *reported* as not
   separated rather than guessed at.

Notes
-----
Determinism (D3)
    Every session is seeded through an injected
    :class:`numpy.random.Generator`, and every adversary owns a generator whose
    seed has nothing to do with any session's (D6).
No machine learning (D4)
    No number in this file was chosen because it separated the attack data. The
    thresholds and the allocation are computed by the module under test; the
    arms in section 6 are read afterwards, and if one of them disappointed the
    answer would be a finding about the protocol's observability, not a new
    constant.
"""

from __future__ import annotations

import dataclasses
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
from sih141.attacks.replay import ReplayingForwarder
from sih141.attacks.starvation import CountStarver
from sih141.detect.detector import (
    DETECTOR_FAMILIES,
    HYPOTHESES,
    HYPOTHESIS_TABLE,
    LINK_ROSTER,
    SIGNATURE_SUBSTITUTION_GROUP,
    Detection,
    Hypothesis,
    HypothesisPredicate,
    Signal,
    SignalKind,
    Support,
    detect,
    family_budget,
)
from sih141.detect.statistics import TranscriptStatistics
from sih141.detect.thresholds_channel import screen_link
from sih141.detect.thresholds_rate import (
    RATE_COUNT_FREE_TESTS,
    RATE_COUNT_ROSTER,
    RateCountThresholds,
)
from sih141.detect.thresholds_structural import (
    RunOutcome,
    evidence_abort_bound,
    structural_report,
)
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
)
from sih141.protocol.verify import AbortReason, MatchedSetTooSmall

#: Key length for every run in this file that does not publish check rounds.
#: Both matched-count floors are non-degenerate here -- the per-verifier floor
#: bites from a sifted length of ``273`` -- so an abort really is the rare event
#: the derivation says it is, and a run still finishes in under a second.
LENGTH = 384

#: The checked configuration: same nominal length, a quarter of the positions
#: spent on check rounds, so ``n = 288`` and all four links publish statistics.
#: The one arrangement in which the channel family is evaluable at all.
CHECK_FRACTION = 0.25

#: Honest runs in the plain corpus. Forty is enough that the loose-budget test
#: of section 2 has a binomial tail worth computing, and small enough that the
#: corpus costs about fifteen seconds.
HONEST_TRIALS = 40

#: Honest runs in the checked corpus. Fewer because each costs twice as much and
#: because the checked configuration is exercised for its *channel* members,
#: which are point masses and cannot fire on a noiseless honest link at all.
CHECKED_TRIALS = 16

#: Runs per adversary arm in section 6.
ARM_TRIALS = 8

#: Budgets the honest corpora are scored at. Fifteen orders of magnitude,
#: because the point of section 2 is that the answer does not move.
BUDGETS = (1e-3, 1e-6, 1e-9, 1e-18)

#: A deliberately loose budget. A bound survived at ``0.5`` is a stronger
#: statement than one survived at ``1e-9``, where nothing could fire anyway.
LOOSE = 0.5

#: How surprising an honest-corpus observation is allowed to be under its own
#: proven bound before the test calls it a violation. Not a threshold anyone
#: tuned: it is the same ``1e-9`` the sibling families use, and it is a
#: statement about the *binomial tail* of the derived bound, not about the data.
SURPRISE = 1e-9


# --------------------------------------------------------------------------- #
# 0. Corpora, built once
# --------------------------------------------------------------------------- #


def run_session(seed: int, *, length: int = LENGTH, check: float = 0.0, **seams):
    """Run one session and keep the transcript even when a verifier refuses.

    Parameters
    ----------
    seed : int
        The **session's** seed. Never an adversary's (D6).
    length : int, optional
        Keyword-only nominal key length.
    check : float, optional
        Keyword-only check-round fraction.
    **seams : object
        Passed straight to :class:`~sih141.protocol.session.QDSSession`.

    Returns
    -------
    SessionTranscript
    """
    session = QDSSession(
        ProtocolParams(key_length=length, check_fraction=check),
        rng=np.random.default_rng(seed),
        **seams,
    )
    try:
        return session.run(0)
    except MatchedSetTooSmall:
        # A refusal is recorded before the exception propagates, so the run is
        # still in the transcript. Losing it here would delete exactly the runs
        # this file exists to score.
        return session.transcript()


_PLAIN: list[TranscriptStatistics] = []
_CHECKED: list[TranscriptStatistics] = []


def honest_plain() -> list[TranscriptStatistics]:
    """Return the honest corpus with no check rounds, built once.

    Returns
    -------
    list of TranscriptStatistics
    """
    if not _PLAIN:
        _PLAIN.extend(
            TranscriptStatistics.from_transcript(run_session(100_000 + seed))
            for seed in range(HONEST_TRIALS)
        )
    return _PLAIN


def honest_checked() -> list[TranscriptStatistics]:
    """Return the honest corpus that publishes check rounds, built once.

    Returns
    -------
    list of TranscriptStatistics
    """
    if not _CHECKED:
        _CHECKED.extend(
            TranscriptStatistics.from_transcript(
                run_session(200_000 + seed, check=CHECK_FRACTION)
            )
            for seed in range(CHECKED_TRIALS)
        )
    return _CHECKED


def binomial_upper_tail(count: int, trials: int, probability: float) -> float:
    """Return ``P(S >= count)`` for ``S ~ Binomial(trials, probability)``.

    Written out rather than imported so this file's own surprise check does not
    depend on the module it is checking.

    Parameters
    ----------
    count : int
        The observed number of firings.
    trials : int
        The corpus size.
    probability : float
        The proven per-run bound.

    Returns
    -------
    float
    """
    if count <= 0:
        return 1.0
    if probability <= 0.0:
        return 0.0
    total = 0.0
    for successes in range(count, trials + 1):
        total += (
            math.comb(trials, successes)
            * probability**successes
            * (1.0 - probability) ** (trials - successes)
        )
    return min(1.0, total)


# --------------------------------------------------------------------------- #
# 1. The correction, checked against its own algebra
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "eps", [1e-30, 1e-19, 1e-18, 1e-12, 1e-9, 1e-6, 1e-3, 0.1, 0.5, 0.9]
)
@pytest.mark.parametrize("length", [192, 384, 115200])
def test_the_three_shares_sum_to_the_budget(eps: float, length: int) -> None:
    """The union bound is a bound on ``eps`` only if the shares sum to it.

    Checked at ten budgets spanning thirty orders of magnitude and three key
    lengths, including the one where the structural cap binds and the one where
    it does not, because the two branches of the allocation are different
    arithmetic.
    """
    params = ProtocolParams(key_length=length)
    split = family_budget(params, eps=eps)
    assert math.isclose(
        split.rate + split.structural + split.channel, eps, rel_tol=1e-12
    )
    assert split.rate == split.channel
    assert split.per_link * len(LINK_ROSTER) == pytest.approx(split.channel)


@pytest.mark.parametrize("eps", [1e-30, 1e-19, 1e-9, 1e-3, 0.9])
def test_the_structural_family_is_charged_what_it_can_prove(eps: float) -> None:
    """``min(B_evid(n), eps/3)``, and never a share that buys it nothing.

    The structural family's proven bound is a function of ``n`` alone, so its
    share decides only whether the evidence-abort check is *admissible*. Giving
    it more than ``B_evid`` is budget spent on nothing, and the cap at a third
    is what keeps the split from ever being worse than the even one.
    """
    params = ProtocolParams(key_length=LENGTH)
    split = family_budget(params, eps=eps)
    expected = min(evidence_abort_bound(params), eps / 3.0)
    assert split.structural == pytest.approx(expected, rel=1e-12)
    assert split.evidence_bound == evidence_abort_bound(params)
    # Never worse than the even split, for either of the other two.
    assert split.rate >= eps / 3.0
    assert split.channel >= eps / 3.0


def test_the_structural_share_keeps_its_own_check_admissible() -> None:
    """Charging exactly ``B_evid`` is enough, which is the whole trick.

    ``evidence_abort_threshold`` is admissible iff ``B_evid <= share``, so the
    share the allocation hands over is the smallest one that keeps the check
    alive. One unit less and the family would go silent, which is why the
    equality is pinned rather than assumed.
    """
    params = ProtocolParams(key_length=LENGTH)
    split = family_budget(params, eps=1e-9)
    stats = honest_plain()[0]
    report = structural_report(stats, eps=split.structural)
    assert report.withheld == ()
    assert report.false_positive_bound == pytest.approx(split.evidence_bound)


def test_the_composite_bound_is_the_sum_of_the_three_families() -> None:
    """Recomputed from the families directly, without going through ``detect``.

    If this ever drifts, the number the submission quotes and the number the
    detector is actually running at are two different numbers, and nothing else
    in the project would notice.
    """
    for stats in (honest_plain()[0], honest_checked()[0]):
        result = detect(stats, eps=1e-9)
        split = family_budget(
            stats.params, eps=1e-9, counts_exchanged=stats.counts_exchanged
        )
        family = RateCountThresholds.for_transcript(stats, eps=split.rate)
        expected = (
            family.evaluate(stats).false_positive_bound
            + structural_report(
                stats, eps=split.structural
            ).false_positive_bound
            + math.fsum(
                screen_link(
                    stats.links[link], epsilon=split.per_link
                ).false_positive_bound
                for link in LINK_ROSTER
                if link in stats.links
            )
        )
        assert result.false_positive_bound == pytest.approx(expected, rel=1e-12)


def test_the_correction_is_doing_work_and_here_is_how_much() -> None:
    """An uncorrected OR of the same three families would exceed its own budget.

    This is the reason the layer exists, as a measurement rather than as a
    warning. Score every member at the **full** ``eps`` -- which is exactly what
    an OR of individually-sound thresholds is -- and the proven bounds add to
    more than ``eps``: the honest-run false-positive rate a report would then be
    quoting is wrong in the direction that matters. The corrected split proves a
    number several times inside the budget instead.
    """
    stats = honest_checked()[0]
    eps = 1e-9
    naive = (
        RateCountThresholds.for_transcript(stats, eps=eps)
        .evaluate(stats)
        .false_positive_bound
        + structural_report(stats, eps=eps).false_positive_bound
        + math.fsum(
            screen_link(stats.links[link], epsilon=eps).false_positive_bound
            for link in LINK_ROSTER
            if link in stats.links
        )
    )
    corrected = detect(stats, eps=eps).false_positive_bound
    assert naive > eps, (
        "the naive OR is supposed to overspend its budget; if it no longer "
        "does, the families have changed and this file's premise needs "
        "restating rather than deleting"
    )
    assert corrected <= eps
    assert corrected < naive


@pytest.mark.parametrize("eps", [1e-18, 1e-9, 1e-3, LOOSE])
def test_the_proven_bound_never_exceeds_the_budget(eps: float) -> None:
    """On every honest run in both corpora, at four budgets."""
    for stats in honest_plain() + honest_checked():
        result = detect(stats, eps=eps)
        assert result.false_positive_bound <= eps
        assert result.slack_factor >= 1.0


def test_the_link_roster_is_fixed_and_not_sized_to_the_run() -> None:
    """Four links whether the run publishes four or none.

    A roster sized to the run would make each screen's budget a function of the
    data; the price is that a run with no check rounds leaves half the budget
    unspendable, which is finding G1 and is reported rather than reclaimed.
    """
    assert len(LINK_ROSTER) == 4
    assert set(LINK_ROSTER) == {
        (str(party), bit) for party in (Party.BOB, Party.CHARLIE) for bit in (0, 1)
    }
    plain = honest_plain()[0]
    checked = honest_checked()[0]
    assert plain.links == {}
    assert set(checked.links) == set(LINK_ROSTER)
    # Same budget, same per-link share, whether or not the links exist.
    assert family_budget(plain.params, eps=1e-9).per_link == pytest.approx(
        family_budget(checked.params, eps=1e-9).per_link, rel=1e-12
    )
    bare = detect(plain, eps=1e-9)
    assert any("no check rounds" in item for item in bare.withheld)


def test_every_family_a_signal_can_carry_is_on_the_roster() -> None:
    """A family off the roster would be summed in without a budget of its own."""
    assert DETECTOR_FAMILIES == ("rate", "structural", "channel")
    with pytest.raises(ValueError, match="family must be one of"):
        Signal(
            name="mystery:thing",
            family="mystery",
            kind=SignalKind.MISMATCH,
            statistic="x",
            observed=1.0,
            critical=1.0,
            false_positive_bound=0.0,
            claim="",
        )


def test_a_split_that_does_not_sum_to_its_budget_is_refused() -> None:
    """The union bound is only a bound on ``eps`` when the shares sum to it."""
    from sih141.detect.detector import FamilyBudget

    with pytest.raises(ValueError, match="shares sum to"):
        FamilyBudget(
            eps=1e-9,
            rate=1e-9,
            structural=1e-9,
            channel=1e-9,
            evidence_bound=0.0,
            derivation="deliberately wrong",
        )


# --------------------------------------------------------------------------- #
# 2. The family-wise error rate, measured on honest runs only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("eps", BUDGETS)
def test_no_honest_run_is_detected_at_any_tight_budget(eps: float) -> None:
    """Forty plain runs and sixteen checked ones, at four budgets: zero alarms.

    The derivation says the composite fires on an honest run with probability at
    most a few times ``1e-10`` at ``eps = 1e-9``; no sample this size could
    distinguish that from zero, which is exactly why the *number* is the
    derivation and the sample is only a check that nothing is grossly wrong.
    """
    for stats in honest_plain() + honest_checked():
        result = detect(stats, eps=eps)
        assert not result.detected, result.summary()
        assert result.signals == ()
        assert result.named == (Hypothesis.HONEST,)


def test_the_loose_budget_rate_sits_inside_the_bound_it_proves() -> None:
    """A budget of ``0.5``, where alarms are *expected*, and the tail check.

    A bound survived at ``1e-9`` is nearly free -- almost nothing can fire. This
    is the version with teeth: at ``eps = 0.5`` the composite's own proven bound
    is a fraction of a per cent to a few per cent, several members are live, and
    the observed firing rate over the honest corpus is required to be no more
    surprising than ``1e-9`` under ``Binomial(trials, bound)``. The bound comes
    from the module; nothing here was chosen to make the assertion pass.
    """
    for label, corpus in (("plain", honest_plain()), ("checked", honest_checked())):
        results = [detect(stats, eps=LOOSE) for stats in corpus]
        fired = sum(1 for result in results if result.detected)
        bound = max(result.false_positive_bound for result in results)
        assert bound <= LOOSE
        surprise = binomial_upper_tail(fired, len(results), bound)
        assert surprise > SURPRISE, (
            f"{label}: {fired}/{len(results)} honest runs fired against a "
            f"proven per-run bound of {bound:.4e}; that observation has "
            f"probability {surprise:.3e} under the bound, which is not a "
            f"looser threshold to reach for but a derivation to re-check"
        )


def test_an_honest_run_is_not_flagged_and_is_not_rejected_either() -> None:
    """The two are different fields with different types, one layer further out.

    Phase 3's constraint 4. A verdict lives on :attr:`Detection.outcomes` in a
    type with no truth value; the detection lives on
    :attr:`Detection.detected`. Nothing in this layer can average one into the
    other, and this test is where an attempt to would fail.
    """
    result = detect(honest_plain()[0], eps=1e-9)
    assert not result.detected
    assert set(result.outcomes) == {"Bob", "Charlie"}
    for outcome in result.outcomes.values():
        assert outcome is RunOutcome.ACCEPTED
    assert not hasattr(result, "accepted")
    assert not hasattr(result, "rejected")
    with pytest.raises(TypeError, match="no truth value"):
        bool(result.outcomes["Bob"])


def test_the_bound_is_flagged_conditional_only_when_it_is() -> None:
    """At a positive ``p_e`` the mismatch members are conditioned, and it shows.

    The distinction decides which of two numbers a Phase 5 ROC point is plotted
    at, and the rate family's tower-rule argument is what carries the
    unconditional guarantee across.
    """
    stats = honest_plain()[0]
    assert detect(stats, eps=1e-9).bound_is_unconditional
    noisy = detect(stats, eps=1e-9, channel_error_rate=0.01)
    assert not noisy.bound_is_unconditional
    assert noisy.false_positive_bound <= 1e-9


# --------------------------------------------------------------------------- #
# 3. Power: a detector that could not fire would pass section 2 too
# --------------------------------------------------------------------------- #


def test_every_rate_member_the_composite_builds_can_actually_fire() -> None:
    """Each threshold fires on an observation one step past its critical value.

    Zero honest alarms is only evidence if the thresholds are reachable. Ten of
    the twelve budgeted members are non-vacuous at this length and budget; the
    two mismatch members sit at ``e_R >= 1`` under the noiseless null, which is
    as reachable as a threshold gets.
    """
    stats = honest_checked()[0]
    split = family_budget(
        stats.params, eps=1e-9, counts_exchanged=stats.counts_exchanged
    )
    family = RateCountThresholds.for_transcript(stats, eps=split.rate)
    for name in RATE_COUNT_ROSTER:
        threshold = family.threshold(name)
        assert not threshold.vacuous, f"{name} cannot fire at all"
        assert threshold.fires(threshold.critical_count), name
        step = -1 if threshold.side == "lower" else 1
        assert threshold.fires(max(0, threshold.critical_count + step)), name


def test_every_channel_member_the_composite_builds_can_actually_fire() -> None:
    """The same check for the per-link screen, one step past each critical value."""
    stats = honest_checked()[0]
    split = family_budget(
        stats.params, eps=1e-9, counts_exchanged=stats.counts_exchanged
    )
    for link in LINK_ROSTER:
        screen = screen_link(stats.links[link], epsilon=split.per_link)
        assert screen.thresholds, link
        for threshold in screen.thresholds.values():
            assert threshold.reaches_its_statistic, threshold.statistic
            step = 1.0 if threshold.direction == "upper" else -1.0
            assert threshold.fires(threshold.critical_value)
            assert threshold.fires(threshold.critical_value + step)


def test_a_hand_broken_transcript_is_detected() -> None:
    """One mismatch inserted into an otherwise honest run, and the composite fires.

    The transcript is broken by hand rather than by an adversary on purpose:
    this is a check that the plumbing carries a firing threshold all the way to
    :attr:`Detection.detected`, and it must not depend on any attack arm being
    available or behaving in any particular way.
    """
    stats = honest_plain()[0]
    verifier = stats.verifiers["Bob"]
    broken = dataclasses.replace(
        stats,
        verifiers={
            **stats.verifiers,
            "Bob": dataclasses.replace(
                verifier,
                mismatch=dataclasses.replace(verifier.mismatch, count=1),
            ),
        },
    )
    result = detect(broken, eps=1e-9)
    assert result.detected
    assert [signal.name for signal in result.signals] == [
        "rate:mismatch_rate:Bob"
    ]
    assert result.signal("rate:mismatch_rate:Bob").kind is SignalKind.MISMATCH
    # Under the noiseless null this member's bound is exactly zero, so the
    # evidence bound is too: an honest noiseless link cannot produce it at all.
    assert result.evidence_bound == 0.0
    assert result.attribution(Hypothesis.HONEST).status is Support.EXCLUDED


# --------------------------------------------------------------------------- #
# 4. The deduction table
# --------------------------------------------------------------------------- #


def test_the_table_names_every_hypothesis_exactly_once() -> None:
    """A hypothesis missing from a report reads as one that was ruled out."""
    assert len(HYPOTHESES) == len(set(HYPOTHESES))
    assert set(HYPOTHESES) == set(Hypothesis)
    assert set(HYPOTHESIS_TABLE) == set(Hypothesis)
    result = detect(honest_plain()[0], eps=1e-9)
    assert tuple(item.hypothesis for item in result.attributions) == HYPOTHESES


def test_every_row_is_internally_consistent() -> None:
    """``requires`` inside ``predicts``, and ``predicts`` disjoint from the rest."""
    for hypothesis, row in HYPOTHESIS_TABLE.items():
        assert row.requires <= row.predicts, hypothesis
        assert not (row.predicts & row.leaves_intact), hypothesis
        assert row.mechanism, hypothesis
        assert SignalKind.FILE_SHAPE not in row.predicts
        assert SignalKind.FILE_SHAPE not in row.leaves_intact


def test_no_adversary_row_can_be_excluded_by_noise() -> None:
    """The rule that keeps the channel's noise level out of an attribution.

    A merely noisy honest link fires ``MISMATCH`` and ``CHANNEL``. A row that
    excluded a position on either would be excluding it on the link's noise,
    which is finding F6 of the rate family made into a bug. The **null** row is
    the one exception, because for the null those signals are the departure the
    threshold was built to bound.
    """
    for hypothesis, row in HYPOTHESIS_TABLE.items():
        noisy = row.leaves_intact & {SignalKind.MISMATCH, SignalKind.CHANNEL}
        if hypothesis is Hypothesis.HONEST:
            assert row.is_null
            assert noisy == {SignalKind.MISMATCH, SignalKind.CHANNEL}
        else:
            assert not row.is_null, hypothesis
            assert not noisy, hypothesis


def test_the_constructor_refuses_the_two_rows_that_would_be_wrong() -> None:
    """Documented rules get broken at 2am; a ``ValueError`` does not."""
    with pytest.raises(ValueError, match="noise level"):
        HypothesisPredicate(
            predicts=frozenset({SignalKind.COUNT_HIGH}),
            leaves_intact=frozenset({SignalKind.MISMATCH}),
            mechanism="excluding an adversary on a noisy link",
        )
    with pytest.raises(ValueError, match="both produce and leave intact"):
        HypothesisPredicate(
            predicts=frozenset({SignalKind.COUNT_HIGH}),
            leaves_intact=frozenset({SignalKind.COUNT_HIGH}),
            mechanism="evidence for and against at once",
        )
    with pytest.raises(ValueError, match="subset of predicts"):
        HypothesisPredicate(
            predicts=frozenset(),
            requires=frozenset({SignalKind.COUNT_HIGH}),
            leaves_intact=frozenset(),
            mechanism="required but not produced",
        )
    with pytest.raises(ValueError, match="mechanism"):
        HypothesisPredicate(
            predicts=frozenset(),
            leaves_intact=frozenset(),
            mechanism="",
        )


def test_every_abort_reason_has_a_kind() -> None:
    """A reason added upstream fails here rather than arriving unclassified."""
    from sih141.detect.detector import _RATE_KINDS, _REASON_KINDS

    assert set(_REASON_KINDS) == set(AbortReason)
    roster_bases = {name.partition(":")[0] for name in RATE_COUNT_ROSTER}
    assert roster_bases | set(RATE_COUNT_FREE_TESTS) == set(_RATE_KINDS)


def test_full_impersonation_is_undetectable_on_every_run_by_construction() -> None:
    """Constraint 7, kept as a row in the report rather than as a hole in it.

    Never supported, never excluded, on an honest run and on a run where
    everything else fires. A hypothesis that quietly disappeared from the table
    when the evidence got strong would read as one that had been ruled out.
    """
    honest = detect(honest_plain()[0], eps=1e-9)
    forged = detect(
        run_session(
            310_000,
            forwarder=RecipientForger(rng=np.random.default_rng(4711)),
            count_exchange_timing=COUNTS_AFTER_FORWARDING,
        ),
        eps=1e-9,
    )
    assert forged.detected
    for result in (honest, forged):
        attribution = result.attribution(Hypothesis.IMPERSONATION_FULL)
        assert attribution.status is Support.UNDETECTABLE
        assert attribution.false_positive_bound is None
        assert "(AUTH)" in attribution.rationale
        assert Hypothesis.IMPERSONATION_FULL not in result.named
        assert Hypothesis.IMPERSONATION_FULL not in result.excluded
        assert "undetectable by construction (AUTH)" in result.summary()


def test_the_three_substitution_hypotheses_say_they_are_not_separable() -> None:
    """One signature, three positions, and the report names the group.

    :class:`~sih141.attacks.impersonation.ImpersonationScope` says the signing
    scope *is* the external forger reached by seizing a seam, so the three are
    the same experiment from a transcript. A table that reported one of them as
    if the transcript had picked it out would be inventing an attribution.
    """
    assert len(SIGNATURE_SUBSTITUTION_GROUP) == 3
    rows = {HYPOTHESIS_TABLE[item] for item in SIGNATURE_SUBSTITUTION_GROUP}
    assert len(rows) == 1, "the three must share one predicate, not three copies"
    result = detect(
        run_session(320_000, signer=OutsideForger(rng=np.random.default_rng(5711))),
        eps=1e-9,
    )
    assert result.detected
    for item in SIGNATURE_SUBSTITUTION_GROUP:
        attribution = result.attribution(item)
        assert attribution.status is Support.SUPPORTED
        assert set(attribution.indistinguishable_from) == set(
            SIGNATURE_SUBSTITUTION_GROUP
        ) - {item}
    assert "not separable" in result.summary()


def test_a_file_shape_violation_is_carried_but_is_not_a_detection() -> None:
    """C-7: a statement about the transcript file, not about an adversary.

    A run-shape signal must not set :attr:`Detection.detected` and must not
    reach the deduction table, or it would inflate a Phase 5 detection column
    with a plumbing fact.
    """
    with pytest.raises(ValueError, match="not a detection"):
        Signal(
            name="structural:run-shape",
            family="structural",
            kind=SignalKind.FILE_SHAPE,
            statistic="run_shape_violations",
            observed=1.0,
            critical=1.0,
            false_positive_bound=0.0,
            claim="",
            is_detection=True,
        )
    shape = Signal(
        name="structural:run-shape",
        family="structural",
        kind=SignalKind.FILE_SHAPE,
        statistic="run_shape_violations",
        observed=1.0,
        critical=1.0,
        false_positive_bound=0.0,
        claim="",
        is_detection=False,
    )
    result = detect(honest_plain()[0], eps=1e-9)
    with_shape = dataclasses.replace(
        result, signals=(shape,), detected=bool(())
    )
    assert with_shape.signals == (shape,)
    assert with_shape.detection_signals == ()
    assert not with_shape.detected


def test_an_exclusion_carries_a_bound_and_a_support_does_not_pretend_to() -> None:
    """The asymmetry :ref:`C-6 <sih141.detect.detector:c6>` insists on.

    Excluding a hypothesis is a derived act: under it, each excluding signal
    fires with at most its own proven bound. *Naming* one is not, because
    "adversary A rather than adversary B" has no null. The two numbers live on
    the same field and the rationale says which is which, so this test reads
    the rationale.
    """
    result = detect(
        run_session(
            330_000,
            count_exchange=CountStarver(rng=np.random.default_rng(9711)),
        ),
        eps=1e-9,
    )
    assert result.detected
    honest = result.attribution(Hypothesis.HONEST)
    assert honest.status is Support.EXCLUDED
    assert honest.false_positive_bound is not None
    assert "mistaken with probability at most" in honest.rationale
    for item in result.named:
        attribution = result.attribution(item)
        assert "not a bound on having named the wrong adversary" in (
            attribution.rationale
        )


# --------------------------------------------------------------------------- #
# 5. The boundary
# --------------------------------------------------------------------------- #


def test_the_three_doors_agree_and_nothing_else_gets_in() -> None:
    """A transcript, its JSON text, and layer one's extraction of it."""
    transcript = run_session(340_000)
    text = transcript.to_json()
    results = [
        detect(transcript, eps=1e-9),
        detect(text, eps=1e-9),
        detect(TranscriptStatistics.from_json(text), eps=1e-9),
    ]
    assert results[0].to_dict() == results[1].to_dict() == results[2].to_dict()
    with pytest.raises(TypeError, match="reads a JSON round-tripped"):
        detect(object(), eps=1e-9)
    with pytest.raises(ValueError, match="strictly inside"):
        detect(transcript, eps=0.0)
    with pytest.raises(TypeError, match="real number"):
        detect(transcript, eps="tight")


def test_the_whole_verdict_survives_json() -> None:
    """The hand-off to Phase 5 and Phase 6, checked rather than assumed."""
    result = detect(honest_checked()[0], eps=1e-9)
    blob = json.loads(json.dumps(result.to_dict()))
    assert blob["false_positive_bound"] == result.false_positive_bound
    assert blob["named"] == ["honest"]
    assert blob["budget"]["link_roster"] == [list(item) for item in LINK_ROSTER]
    assert len(blob["attributions"]) == len(HYPOTHESES)
    assert blob["grouping_key"][0] == "before-forwarding"


def test_the_detector_reads_no_adversary_and_has_nowhere_to_put_one() -> None:
    """``detect`` takes a transcript and a budget, and no seam for a harness."""
    import inspect

    signature = inspect.signature(detect)
    assert list(signature.parameters) == [
        "transcript",
        "eps",
        "channel_error_rate",
        "tolerated_depolarising",
        "method",
        "qber_method",
    ]
    assert "rng" not in signature.parameters


# --------------------------------------------------------------------------- #
# 6. The measurement, once every threshold is frozen
# --------------------------------------------------------------------------- #


def score_arm(base_seed: int, builder, *, trials: int = ARM_TRIALS, **fixed):
    """Run one adversary arm and return its detections.

    Parameters
    ----------
    base_seed : int
        First **session** seed. The adversaries get their own, unrelated (D6).
    builder : callable
        ``builder(index) -> mapping`` of seams for that run.
    trials : int, optional
        Keyword-only.
    **fixed : object
        Seams and session options that do not vary across the arm.

    Returns
    -------
    list of Detection
    """
    return [
        detect(
            run_session(base_seed + index, **fixed, **builder(index)), eps=1e-9
        )
        for index in range(trials)
    ]


def test_count_starvation_is_detected_and_uniquely_attributed() -> None:
    """The denial costs one integer and no probability, so it is forced.

    Two signals, both derived: the wire count in its lower tail, and the
    counterpart's evidence abort. Every other in-model position leaves at least
    one of those nulls intact, so the attribution is unique -- and it is unique
    by the mechanics of who holds the count-exchange seam, not by anything
    tuned.
    """
    results = score_arm(
        400_000,
        lambda i: {
            "count_exchange": CountStarver(rng=np.random.default_rng(9001 + i))
        },
    )
    assert all(result.detected for result in results)
    for result in results:
        assert result.named == (Hypothesis.COUNT_STARVATION,), result.summary()
        assert SignalKind.EVIDENCE_SHORTFALL in result.kinds
        assert Hypothesis.HONEST in result.excluded
        assert Hypothesis.CHANNEL_MANIPULATION in result.excluded
        # A refusal, never a rejection.
        assert RunOutcome.REJECTED not in set(result.outcomes.values())
        assert RunOutcome.REFUSED in set(result.outcomes.values())


def test_recipient_forgery_after_forwarding_is_named_alone() -> None:
    """Charlie's matched count, which is the discriminator Phase 3 named.

    Constraint 5: ``transcript.repudiated`` cannot tell a forging recipient from
    channel noise, and the matched count can -- at ``sqrt(n/2)`` standard
    deviations. Here that separation is what leaves exactly one hypothesis
    standing: ``COUNT_HIGH`` excludes the channel, the substitution group and
    the count starver, and the forwarding-tamper signal excludes them again.
    """
    results = score_arm(
        410_000,
        lambda i: {
            "forwarder": RecipientForger(rng=np.random.default_rng(4001 + i))
        },
        count_exchange_timing=COUNTS_AFTER_FORWARDING,
    )
    assert all(result.detected for result in results)
    for result in results:
        assert result.named == (Hypothesis.RECIPIENT_FORGERY,), result.summary()
        assert SignalKind.COUNT_HIGH in result.kinds
        assert "rate:matched_count_high:Charlie" in {
            signal.name for signal in result.signals
        }
        for ruled_out in (
            Hypothesis.HONEST,
            Hypothesis.CHANNEL_MANIPULATION,
            Hypothesis.COUNT_STARVATION,
            Hypothesis.OUTSIDE_FORGERY,
            Hypothesis.REPLAY,
        ):
            assert ruled_out in result.excluded, result.summary()


def test_the_two_count_exchange_orderings_are_scored_apart() -> None:
    """Constraint 6, as a measurement: the same attack, two different answers.

    Under ``COUNTS_AFTER_FORWARDING`` Charlie scores the forgery and the count
    signal fires. Under ``COUNTS_BEFORE_FORWARDING`` he refuses and the attack
    is a denial of service; the composite still detects it -- on the structural
    forwarding-tamper signal, which the rate family alone would have missed --
    but names two positions instead of one, because both of them hold the
    forwarding hop. A table that averaged the two arms would be averaging a
    forgery rate with a denial-of-service rate.
    """
    after = score_arm(
        420_000,
        lambda i: {
            "forwarder": RecipientForger(rng=np.random.default_rng(4101 + i))
        },
        count_exchange_timing=COUNTS_AFTER_FORWARDING,
        trials=4,
    )
    before = score_arm(
        430_000,
        lambda i: {
            "forwarder": RecipientForger(rng=np.random.default_rng(4201 + i))
        },
        count_exchange_timing=COUNTS_BEFORE_FORWARDING,
        trials=4,
    )
    assert all(result.detected for result in after + before)
    assert {result.grouping_key[0] for result in after} == {"after-forwarding"}
    assert {result.grouping_key[0] for result in before} == {"before-forwarding"}
    for result in after:
        assert SignalKind.COUNT_HIGH in result.kinds
        assert result.outcomes["Charlie"] is not RunOutcome.REFUSED
    for result in before:
        assert result.kinds == (SignalKind.FORWARDING_TAMPER,), result.summary()
        assert result.outcomes["Charlie"] is RunOutcome.REFUSED
        assert set(result.named) == {
            Hypothesis.RECIPIENT_FORGERY,
            Hypothesis.REPLAY,
        }, result.summary()
        assert not result.requirements_enforced


@pytest.mark.parametrize(
    ("label", "builder"),
    [
        (
            "outside-forgery",
            lambda i: {
                "signer": OutsideForger(rng=np.random.default_rng(5001 + i))
            },
        ),
        (
            "impersonation-signing",
            lambda i: impersonation_seams(
                Impersonator(rng=np.random.default_rng(7001 + i)),
                ImpersonationScope.SIGNING,
            ),
        ),
        (
            "impersonation-distribution",
            lambda i: impersonation_seams(
                Impersonator(rng=np.random.default_rng(7101 + i)),
                ImpersonationScope.DISTRIBUTION,
            ),
        ),
    ],
)
def test_a_substituted_declaration_is_detected_and_reported_as_unseparated(
    label: str, builder
) -> None:
    """Detected every time, and the report names what it cannot tell apart.

    The mismatch signal is *required* rather than merely predicted: a
    declaration drawn independently of the records survives a matched position
    with probability ``1/2``, so the mismatch count is zero with probability
    ``2**-|M_R|``. What the transcript cannot do is say which of the three
    positions produced it -- and the two positions it *can* rule out are the
    two that would have moved a count.
    """
    results = score_arm(440_000, builder)
    assert all(result.detected for result in results), label
    for result in results:
        assert SignalKind.MISMATCH in result.kinds
        assert set(SIGNATURE_SUBSTITUTION_GROUP) <= set(result.named)
        assert Hypothesis.HONEST in result.excluded
        assert Hypothesis.COUNT_STARVATION not in result.named
        assert Hypothesis.RECIPIENT_FORGERY not in result.named


@pytest.mark.parametrize(
    ("label", "builder"),
    [
        (
            "depolariser",
            lambda i: {
                "resource_factory": DepolarisingChannel(
                    0.60, target=Party.BOB, rng=np.random.default_rng(6001 + i)
                ).resource
            },
        ),
        (
            "intercept-resend",
            lambda i: {
                "resource_factory": InterceptResend(
                    target=Party.BOB, rng=np.random.default_rng(6101 + i)
                ).resource
            },
        ),
    ],
)
def test_a_channel_adversary_is_detected_and_never_named_a_recipient_forgery(
    label: str, builder
) -> None:
    """Constraint 5 working in the other direction, which is the harder one.

    Phase 3 measured plain depolarising noise producing ``repudiated == True``
    with a completely honest Alice. The composite must not repeat that: a
    channel adversary moves no basis, so no count moves, so the recipient-forgery
    hypothesis -- which *requires* an inflated count -- goes unsupported rather
    than being named. That is the whole content of "Charlie's matched count is
    the discriminator", stated as a property of the detector.
    """
    results = score_arm(450_000, builder)
    assert all(result.detected for result in results), label
    for result in results:
        assert SignalKind.MISMATCH in result.kinds
        assert Hypothesis.CHANNEL_MANIPULATION in result.named
        assert Hypothesis.RECIPIENT_FORGERY not in result.named
        assert Hypothesis.COUNT_STARVATION not in result.named
        assert result.requirements_enforced
        missing = result.attribution(Hypothesis.RECIPIENT_FORGERY)
        assert missing.status is Support.UNSUPPORTED
        assert SignalKind.COUNT_HIGH in missing.missing_requirements


def test_the_channel_family_supports_but_never_excludes() -> None:
    """A channel screen separates in one direction only, and finding G2 says so.

    With check rounds a depolariser fires the per-link members and a signer-seam
    forger does not, so the *evidence* for a channel cause is different in the
    two arms. It does not become an exclusion: a merely noisy honest link fires
    the same members, so ruling the forger out on them would be ruling him out
    on the link's noise level.
    """
    depolarised = detect(
        run_session(
            460_000,
            check=CHECK_FRACTION,
            resource_factory=DepolarisingChannel(
                0.60, target=Party.BOB, rng=np.random.default_rng(6601)
            ).resource,
        ),
        eps=1e-9,
    )
    substituted = detect(
        run_session(
            460_000,
            check=CHECK_FRACTION,
            signer=OutsideForger(rng=np.random.default_rng(5601)),
        ),
        eps=1e-9,
    )
    assert depolarised.detected and substituted.detected
    assert SignalKind.CHANNEL in depolarised.kinds
    assert SignalKind.CHANNEL not in substituted.kinds
    # The evidence differs; the exclusion set does not gain a member from it.
    assert len(
        depolarised.attribution(Hypothesis.CHANNEL_MANIPULATION).supporting
    ) > len(
        substituted.attribution(Hypothesis.CHANNEL_MANIPULATION).supporting
    )
    for result in (depolarised, substituted):
        assert set(SIGNATURE_SUBSTITUTION_GROUP) <= set(result.named)


def test_a_replaying_forwarder_is_detected_and_reported_as_unseparated() -> None:
    """He alters the declaration on the hop, and that is what the transcript sees.

    The session rebinds whatever a forwarder returns to the live round
    (:class:`~sih141.attacks.replay.ReplayingForwarder` says so itself), so a
    stale declaration reaches Charlie carrying the live identifier and no ledger
    entry is ever spent twice. ``LEDGER`` is therefore predicted and **not**
    required, and this arm is named alongside recipient forgery -- both hold the
    Bob-to-Charlie hop, and from a transcript that is all there is to say.
    """
    results = score_arm(
        470_000,
        lambda i: {
            "forwarder": ReplayingForwarder(
                rng=np.random.default_rng(8001 + i),
                captures=None,
                replay_probability=1.0,
            )
        },
        length=24,
        trials=4,
    )
    assert all(result.detected for result in results)
    for result in results:
        assert Hypothesis.REPLAY in result.named, result.summary()
        assert Hypothesis.HONEST in result.excluded
        assert not result.security_claim, (
            "the capture is taken at L = 24, which carries no security claim; "
            "the Detection must say so rather than let a table quote it"
        )


def test_full_impersonation_is_not_detected_and_that_is_correct() -> None:
    """Zero out of eight, reported as an assumption rather than as a miss.

    Mallory runs the protocol correctly with her own key, so the transcript is
    drawn from the honest law and no derived threshold can fire. A detector that
    reported anything here would be reporting its own noise.
    """
    results = score_arm(
        480_000,
        lambda i: impersonation_seams(
            Impersonator(rng=np.random.default_rng(7201 + i)),
            ImpersonationScope.FULL,
        ),
    )
    assert not any(result.detected for result in results)
    for result in results:
        assert result.signals == ()
        assert result.named == (Hypothesis.HONEST,)
        assert (
            result.attribution(Hypothesis.IMPERSONATION_FULL).status
            is Support.UNDETECTABLE
        )


def test_the_summary_reads_as_a_report_and_not_as_a_verdict() -> None:
    """The demonstration surface, pinned so it cannot quietly become a boolean."""
    result = detect(
        run_session(
            490_000,
            forwarder=RecipientForger(rng=np.random.default_rng(4901)),
            count_exchange_timing=COUNTS_AFTER_FORWARDING,
        ),
        eps=1e-9,
    )
    text = result.summary()
    assert "consistent with: recipient-forgery" in text
    assert "ruled out:" in text
    assert "each wrongly with probability at most" in text
    assert "P(any signal | honest) <=" in text
    assert "outcomes:" in text
    assert isinstance(result, Detection)
