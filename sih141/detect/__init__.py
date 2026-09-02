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

The package is layered, and this file only owns the first layer:

:mod:`sih141.detect.statistics`
    Everything a detector may legitimately read, extracted from a JSON
    transcript. Each statistic carries the honest-run null it is read against,
    because convention **D7** requires every Phase 4 threshold to come from a
    stated null and a concentration inequality applied to it -- never from a
    number that separated the attack data somebody happened to have. A
    statistic whose null cannot be written down cannot carry a derived
    threshold, and this layer reports that rather than hiding it.

Later layers derive thresholds from those nulls and combine them into a
verdict. They read :class:`~sih141.detect.statistics.TranscriptStatistics`;
they do not read transcripts, and they never read an adversary.

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
    "EVIDENCE_ABORT_REASONS",
    "IDEAL_TOLERANCE",
    "STRUCTURAL_ABORT_REASONS",
    "AbortStatistics",
    "CountStatistic",
    "DeclarationStatistics",
    "LinkStatistics",
    "PooledStatistics",
    "RecordStatistics",
    "ReplayStatistics",
    "ResourceStatistics",
    "TranscriptStatistics",
    "VerifierStatistics",
    "chernoff_deviation_bound",
    "pooled_check_qber",
    "statistics",
    "why_wings_agree_is_absent",
    "wilson_interval",
]
