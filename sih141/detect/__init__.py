"""Phase 4: detection, and the boundary that makes a detection rate mean something.

The detector reads a :class:`~sih141.protocol.session.SessionTranscript` **that
has been round-tripped through JSON**, and nothing else. Not the session
object, not the adversary, not any harness state. This is not a style
preference. A detection rate measured by something that can see the
adversary's log is not a detection rate, it is a restatement of the ground
truth, and Phase 3 paid for that lesson twice: once in
:mod:`sih141.attacks.isolation` (convention **D6** -- every adversary owns its
randomness and never reads the session's) and once in the prototype threshold
detector, which adopted the transcript-only rule voluntarily and separated four
of five adversaries on the verifier mismatch rate alone.

The package is layered, and the layers are strictly one-directional:

:mod:`sih141.detect.statistics`
    Everything a detector may legitimately read, extracted from a JSON
    transcript. Each statistic carries the honest-run null it is read against,
    because convention **D7** requires every Phase 4 threshold to come from a
    stated null and a concentration inequality applied to it -- never from a
    number that separated the attack data somebody happened to have. A
    statistic whose null cannot be written down cannot carry a derived
    threshold, and this layer reports that rather than hiding it.

The three threshold families -- rate-and-count, structural, channel
    Derived thresholds over those nulls, each family with its own union bound.
    They read
    :class:`~sih141.detect.statistics.TranscriptStatistics`; they do not read
    transcripts, and they never read an adversary.

:mod:`sih141.detect.detector`
    The composite rule, and the family-wise error rate. Firing when **any**
    threshold fires has a false-positive rate far worse than any single
    threshold's, so the three families' budgets are split by a written-down
    allocation and recombined by a union bound. :func:`detect` takes a
    false-positive **budget** rather than a pile of constants, reports which
    signals fired and what each one proves, and names the hypotheses the
    evidence supports -- or, where the transcript cannot separate them, says
    so and names the group instead of picking one.

The one entry point most callers want:

>>> import numpy as np
>>> from sih141.detect import detect
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> result = detect(
...     QDSSession(
...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
...     ).run(0),
...     eps=1e-9,
... )
>>> result.detected, f"{result.false_positive_bound:.4e}"
(False, '2.6499e-10')

.. _d7-in-one-paragraph:

The rule this whole phase exists to obey
----------------------------------------
If you find yourself choosing a number because it separates the attack data in
front of you, stop. That is fitting, and fitting is machine learning wearing a
different hat -- the exact thing the problem statement forbids, and a silent cap
on the scheme's information-theoretic security at "whatever our test set
happened to contain". A fitted detector can say "97% accurate on our data". This
one has to be able to say "the probability of being fooled is at most
``1.4139e-09``, and here is the derivation". You may look at honest-run data to
**check** a derived threshold behaves as derived; you may not look at attack
data to **choose** one.

Notes
-----
Determinism (D3)
    Nothing in this package draws randomness. It has no ``rng`` argument
    anywhere because it has nothing to draw for.
No machine learning (D4)
    Counting, closed forms and concentration inequalities. There is no fitted
    quantity in this package and no place to put one.

Examples
--------
>>> import numpy as np
>>> from sih141.detect import TranscriptStatistics
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> stats = TranscriptStatistics.from_transcript(
...     QDSSession(
...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
...     ).run(0)
... )
>>> stats.verifier("Bob").matched.count
59
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


from sih141.detect.detector import (
    DETECTOR_FAMILIES,
    HYPOTHESES,
    HYPOTHESIS_TABLE,
    LINK_ROSTER,
    SIGNATURE_SUBSTITUTION_GROUP,
    Attribution,
    Detection,
    FamilyBudget,
    Hypothesis,
    HypothesisPredicate,
    Signal,
    SignalKind,
    Support,
    detect,
    family_budget,
)
from sih141.detect.statistics import (
    EVIDENCE_ABORT_REASONS,
    IDEAL_TOLERANCE,
    STRUCTURAL_ABORT_REASONS,
    AbortStatistics,
    CountStatistic,
    DeclarationStatistics,
    LinkStatistics,
    PooledStatistics,
    RecordStatistics,
    ReplayStatistics,
    ResourceStatistics,
    TranscriptStatistics,
    VerifierStatistics,
    chernoff_deviation_bound,
    pooled_check_qber,
    why_wings_agree_is_absent,
    wilson_interval,
)
from sih141.detect.thresholds_channel import (
    CHANNEL_STATISTICS,
    CONCURRENCE_RANGE,
    FIDELITY_RANGE,
    PURITY_RANGE,
    ChannelScreen,
    ChannelThreshold,
    CheckRoundShare,
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
from sih141.detect.thresholds_rate import (
    EXACT_TRIALS_LIMIT,
    INEQUALITIES,
    RATE_COUNT_FREE_TESTS,
    RATE_COUNT_ROSTER,
    DerivedThreshold,
    RateCountThresholds,
    RateCountVerdict,
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
from sih141.detect.thresholds_structural import (
    FLOOR_BUDGET,
    STRUCTURAL_CHECKS,
    AbortAttribution,
    NoVerdictCount,
    OutcomeTally,
    RunOutcome,
    StructuralAlarm,
    StructuralCheck,
    StructuralReport,
    StructuralThreshold,
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


# --------------------------------------------------------------------------- #
# One vocabulary over three carrier types                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ThresholdView:
    """One reading of any shipped threshold, whichever family produced it.

    The three families were derived in parallel and ship three carrier types --
    :class:`~sih141.detect.thresholds_rate.DerivedThreshold`,
    :class:`~sih141.detect.thresholds_channel.ChannelThreshold` and
    :class:`~sih141.detect.thresholds_structural.StructuralThreshold`. They
    agree on ``statistic``, ``null``, ``inequality``,
    ``false_positive_bound`` and ``derivation``, and disagree on everything
    else:

    ==================  =================  ======================  ==============
    meaning             rate               channel                 structural
    ==================  =================  ======================  ==============
    the budget          ``budget``         ``epsilon``             ``budget``
    the critical value  ``critical_count`` ``critical_value``      ``fires_at``
    which tail          ``side``           ``direction``           *absent*
    can it fire?        ``vacuous``        ``reaches_its_``        ``fires_at``
                                           ``statistic``           ``is None``
    ==================  =================  ======================  ==============

    **The last row is the dangerous one and it is why this class exists.**
    ``vacuous`` and ``reaches_its_statistic`` describe the same fact in
    opposite senses: ``vacuous=True`` and ``reaches_its_statistic=False`` both
    mean *this threshold cannot fire at this sample size and budget*. A caller
    that read one field where it meant the other would turn "this sample can
    detect nothing" into "this sample is fine", silently, in the direction that
    manufactures a clean bill of health. :attr:`can_fire` is that fact with one
    name and one sense throughout, and
    ``tests/test_detect_reconciliation.py`` pins the translation against all
    three families rather than trusting this table.

    Attributes
    ----------
    family : str
        ``"rate"``, ``"channel"`` or ``"structural"``.
    statistic : str
        What is being read.
    null : str
        The honest-run law it is read against. Never empty: a statistic whose
        null nobody wrote down cannot carry a derived threshold (**D7**).
    inequality : str
        The named inequality inverted to get the critical value, or the words
        saying none was needed because the null is a point mass.
    budget : float
        The false-positive budget this member was derived at -- its own share,
        not the family's.
    critical_value : float or None
        Where it fires. ``None`` for a structural check that was **withheld**
        because no key length reaches the budget.
    false_positive_bound : float
        What the inequality actually **proves** at that critical value, which
        is at or below :attr:`budget` and is usually well below it. This is
        the number to publish, never the budget.
    direction : str or None
        ``"lower"``, ``"upper"``, or ``None`` for a structural check, whose
        statistic is a count of things that must not happen at all.
    can_fire : bool
        One sense, everywhere: ``True`` when an observation exists that would
        trip this threshold. ``False`` is a fact about the run's sample size,
        not a defect in the derivation, and a threshold that cannot fire has a
        false-positive probability of exactly zero **and no power at all** --
        both halves need saying.
    is_alarm : bool
        ``False`` only for
        :func:`~sih141.detect.thresholds_channel.chsh_certificate_threshold`,
        which licenses a positive claim about the resource rather than
        reporting a departure from the null. Failing to certify is not a
        detection, and a table that counted one would be publishing its own
        sample-size problem as a result.
    derivation : str
        Where the algebra is written down.

    Examples
    --------
    The same three questions, asked of all three families in one vocabulary:

    >>> from sih141.detect import (
    ...     ThresholdView, chsh_threshold, matched_count_threshold,
    ...     qber_threshold, structural_abort_threshold, threshold_view,
    ... )
    >>> rate = threshold_view(
    ...     matched_count_threshold(192, 1 / 3, eps=1e-9, side="lower"))
    >>> rate.family, rate.direction, rate.critical_value, rate.can_fire
    ('rate', 'lower', 26, True)
    >>> channel = threshold_view(qber_threshold(rounds=24, epsilon=1e-9))
    >>> channel.family, channel.direction, channel.critical_value
    ('channel', 'upper', 1.0)
    >>> structural = threshold_view(structural_abort_threshold(1e-9))
    >>> structural.family, structural.direction, structural.can_fire
    ('structural', None, True)

    Every one of them that CAN FIRE proves a bound at or inside its own
    budget, which is the property a family-wise union bound is entitled to
    assume:

    >>> all(v.false_positive_bound <= v.budget
    ...     for v in (rate, channel, structural))
    True

    The ``can_fire`` qualifier is load-bearing, not a hedge. A threshold whose
    sample cannot reach its own statistic reports the bound it would prove if
    it could, and that bound may exceed the budget -- the check is inadmissible
    rather than unsound, and :func:`detect` is unaffected because
    ``structural_report`` skips inadmissible checks. But a caller that walks
    several families and SUMS ``false_positive_bound`` without first consulting
    ``can_fire`` would publish a family-wise bound above its own budget:

    >>> from sih141.detect.thresholds_structural import evidence_abort_threshold
    >>> from sih141.protocol.params import ProtocolParams
    >>> bad = threshold_view(evidence_abort_threshold(
    ...     ProtocolParams(key_length=384), 1.6e-19))
    >>> bad.can_fire, bad.false_positive_bound > bad.budget
    (False, True)

    Audit 3 of Phase 4 named this the likeliest way a Phase 5 walker goes
    wrong, so the guard is stated here and pinned above rather than left to
    the reader.

    And the trap the class exists for. A threshold that cannot fire reports
    ``can_fire=False`` whichever family it came from, although the two
    families spell the underlying field in opposite senses:

    >>> thin = threshold_view(chsh_threshold(counts=(2, 2, 2, 2), epsilon=1e-9))
    >>> thin.can_fire, thin.raw.reaches_its_statistic
    (False, False)
    >>> silent = threshold_view(
    ...     matched_count_threshold(8, 1 / 3, eps=1e-30, side="lower"))
    >>> silent.can_fire, silent.raw.vacuous
    (False, True)
    """

    family: str
    statistic: str
    null: str
    inequality: str
    budget: float
    critical_value: float | None
    false_positive_bound: float
    direction: str | None
    can_fire: bool
    is_alarm: bool
    derivation: str
    raw: Any

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view, without the carrier it came from.

        Returns
        -------
        dict
        """
        return {
            "family": self.family,
            "statistic": self.statistic,
            "null": self.null,
            "inequality": self.inequality,
            "budget": self.budget,
            "critical_value": self.critical_value,
            "false_positive_bound": self.false_positive_bound,
            "direction": self.direction,
            "can_fire": self.can_fire,
            "is_alarm": self.is_alarm,
            "derivation": self.derivation,
        }


def threshold_view(threshold: Any) -> ThresholdView:
    """Read any family's threshold through one vocabulary.

    Parameters
    ----------
    threshold : DerivedThreshold or ChannelThreshold or StructuralThreshold
        A threshold from any of the three families.

    Returns
    -------
    ThresholdView
        The same threshold, with the conventions reconciled. See that class
        for the translation table and for the one row that inverts.

    Raises
    ------
    TypeError
        If ``threshold`` is not one of the three carrier types. Deliberately
        not duck-typed: two of the three carry a "can it fire" field under
        different names *and opposite senses*, so guessing from the attributes
        present is exactly how a caller would read one as the other.

    Examples
    --------
    >>> from sih141.detect import pooled_count_threshold, threshold_view
    >>> view = threshold_view(
    ...     pooled_count_threshold(192, 1 / 3, eps=1e-9, side="upper"))
    >>> view.family, view.statistic.startswith("M ="), view.direction
    ('rate', True, 'upper')
    >>> f"{view.false_positive_bound:.4e}" , view.budget <= 1e-9
    ('6.8419e-10', True)
    """
    if isinstance(threshold, DerivedThreshold):
        return ThresholdView(
            family="rate",
            statistic=threshold.statistic,
            null=threshold.null,
            inequality=threshold.inequality,
            budget=threshold.budget,
            critical_value=threshold.critical_count,
            false_positive_bound=threshold.false_positive_bound,
            direction=threshold.side,
            # INVERTED against the channel family's spelling. This is the
            # single line the class exists to make impossible to get wrong.
            can_fire=not threshold.vacuous,
            is_alarm=True,
            derivation=threshold.derivation,
            raw=threshold,
        )
    if isinstance(threshold, ChannelThreshold):
        return ThresholdView(
            family="channel",
            statistic=threshold.statistic,
            null=threshold.null,
            inequality=threshold.inequality,
            budget=threshold.epsilon,
            critical_value=threshold.critical_value,
            false_positive_bound=threshold.false_positive_bound,
            direction=threshold.direction,
            can_fire=threshold.reaches_its_statistic,
            is_alarm=threshold.is_alarm,
            derivation=threshold.derivation,
            raw=threshold,
        )
    if isinstance(threshold, StructuralThreshold):
        return ThresholdView(
            family="structural",
            statistic=threshold.statistic,
            null=threshold.null,
            inequality=threshold.inequality,
            budget=threshold.budget,
            critical_value=threshold.fires_at,
            false_positive_bound=threshold.false_positive_bound,
            # A structural check counts things that must not happen at all, so
            # there is no tail to name. None rather than "upper": inventing a
            # direction would suggest a two-sided question exists.
            direction=None,
            can_fire=threshold.fires_at is not None,
            is_alarm=True,
            derivation=threshold.derivation,
            raw=threshold,
        )
    raise TypeError(
        f"threshold must be a DerivedThreshold, a ChannelThreshold or a "
        f"StructuralThreshold, got {type(threshold).__name__}. The three "
        f"carriers are not duck-typed on purpose: two of them spell 'can this "
        f"fire' under different names and opposite senses, so a structural "
        f"guess from the attributes present is how a caller reads one as the "
        f"other."
    )

__all__ = [
    "AbortAttribution",
    "AbortStatistics",
    "Attribution",
    "CHANNEL_STATISTICS",
    "CONCURRENCE_RANGE",
    "ChannelScreen",
    "ChannelThreshold",
    "CheckRoundShare",
    "CountStatistic",
    "DETECTOR_FAMILIES",
    "DeclarationStatistics",
    "DerivedThreshold",
    "Detection",
    "EVIDENCE_ABORT_REASONS",
    "EXACT_TRIALS_LIMIT",
    "FIDELITY_RANGE",
    "FLOOR_BUDGET",
    "FamilyBudget",
    "HYPOTHESES",
    "HYPOTHESIS_TABLE",
    "Hypothesis",
    "HypothesisPredicate",
    "IDEAL_TOLERANCE",
    "INEQUALITIES",
    "LINK_ROSTER",
    "LinkStatistics",
    "NoVerdictCount",
    "OutcomeTally",
    "PURITY_RANGE",
    "PooledStatistics",
    "RATE_COUNT_FREE_TESTS",
    "RATE_COUNT_ROSTER",
    "RateCountThresholds",
    "RateCountVerdict",
    "RecordStatistics",
    "ReplayStatistics",
    "ResourceStatistics",
    "RunOutcome",
    "SIGNATURE_SUBSTITUTION_GROUP",
    "STRUCTURAL_ABORT_REASONS",
    "STRUCTURAL_CHECKS",
    "Signal",
    "SignalKind",
    "StructuralAlarm",
    "StructuralCheck",
    "StructuralReport",
    "StructuralThreshold",
    "Support",
    "ThresholdView",
    "TranscriptStatistics",
    "VerifierStatistics",
    "abort_reason_bound",
    "attribute_aborts",
    "binomial_tail_bound",
    "bounded_mean_threshold",
    "chernoff_deviation_bound",
    "chernoff_lower_tail_count",
    "chsh_certificate_threshold",
    "chsh_threshold",
    "concurrence_threshold",
    "critical_count",
    "declared_count_threshold",
    "detect",
    "detector",
    "divide_budget",
    "dominance_noise_level",
    "evidence_abort_bound",
    "evidence_abort_threshold",
    "family_budget",
    "fidelity_threshold",
    "floor_comparison",
    "forgery_separation_sigma",
    "link_check_rounds",
    "matched_count_threshold",
    "minimum_sifted_length",
    "mismatch_rate_threshold",
    "outcome_of",
    "outcomes",
    "point_mass_threshold",
    "pooled_check_qber",
    "pooled_count_threshold",
    "purity_threshold",
    "qber_threshold",
    "replay_refusal_threshold",
    "run_shape_threshold",
    "run_shape_violations",
    "screen_link",
    "shortfall_threshold",
    "statistics",
    "structural_abort_threshold",
    "structural_report",
    "tally_outcomes",
    "threshold_view",
    "thresholds_channel",
    "thresholds_rate",
    "thresholds_structural",
    "werner_concurrence",
    "werner_fidelity",
    "werner_purity",
    "why_wings_agree_is_absent",
    "wilson_interval",
]
