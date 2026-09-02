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

__all__ = [
    "DETECTOR_FAMILIES",
    "EVIDENCE_ABORT_REASONS",
    "HYPOTHESES",
    "HYPOTHESIS_TABLE",
    "IDEAL_TOLERANCE",
    "LINK_ROSTER",
    "SIGNATURE_SUBSTITUTION_GROUP",
    "STRUCTURAL_ABORT_REASONS",
    "AbortStatistics",
    "Attribution",
    "CountStatistic",
    "DeclarationStatistics",
    "Detection",
    "FamilyBudget",
    "Hypothesis",
    "HypothesisPredicate",
    "LinkStatistics",
    "PooledStatistics",
    "RecordStatistics",
    "ReplayStatistics",
    "ResourceStatistics",
    "Signal",
    "SignalKind",
    "Support",
    "TranscriptStatistics",
    "VerifierStatistics",
    "chernoff_deviation_bound",
    "detect",
    "detector",
    "family_budget",
    "pooled_check_qber",
    "statistics",
    "thresholds_channel",
    "thresholds_rate",
    "thresholds_structural",
    "why_wings_agree_is_absent",
    "wilson_interval",
]
