"""Phase 4 layer one: the boundary, the nulls, and what the transcript hides.

This file pins :mod:`sih141.detect.statistics`, which is the module that decides
what the rest of Phase 4 is allowed to see. It is organised around the six
claims the layer rests on, because each is a place the layer could be wrong
while still looking right.

1. **The boundary is the code, not a convention.**
   :meth:`~sih141.detect.statistics.TranscriptStatistics.from_transcript` is
   defined as ``from_json(transcript.to_json())`` and section 1 asserts the
   equality directly, on honest and attacked runs alike. It also asserts the
   *static* half: the package's own source names :mod:`sih141.attacks` nowhere,
   so the shipped detector can be built without the adversary suite. A detector
   that can see the adversary is not measuring a detection rate, it is
   restating the ground truth.
2. **Every null is arithmetic somebody can check.** Section 2 pins the two
   closed forms -- the Wilson interval against the protocol's own
   implementation to the last bit, and the Chernoff bounds against their
   algebra -- and the degenerate cases that a two-line ``max``/``min`` would
   get subtly wrong: a point-mass null answers ``0`` or ``1`` exactly, a
   zero-variance z-score is ``0`` or ``+-inf`` rather than a division error,
   and a one-sided bound is not charged for the tail it never looks at.
3. **The honest-run laws hold on honest runs.** Section 3 is the corollary D7
   permits: *checking* a derived law against honest data is allowed, *choosing*
   a number from attack data is not. Matched counts over twenty seeds are
   compared with ``Binomial(n, 1/|B|)``, the pooled count with ``Binomial(2n,
   1/|B|)``, the unmatched agreements with ``Binomial(n - |M_R|, 1/2)``, and
   the mismatch count with the point mass at ``0`` -- which on a noiseless run
   is not "close to zero" but exactly zero, every time.
4. **Refusals are never verdicts.** Section 4 pins the separation from both
   sides: an aborting run's refusal appears in
   :class:`~sih141.detect.statistics.AbortStatistics` and nowhere else, asking
   for its verifier raises rather than returning a rejection, and the two abort
   groups partition :class:`~sih141.protocol.verify.AbortReason` exactly, so a
   reason added upstream fails a test here instead of silently joining the
   group with the weaker bound.
5. **Two links are two channels.** Section 5 mounts a depolariser aimed at one
   recipient and checks that the layer keeps the two links apart well enough to
   *see* it on one and not the other -- and that pooling them, which averages
   the two, has to be asked for in as many words.
6. **What it will not do.** Section 6 pins the refusals and the absences:
   ``wings_agree`` is not exposed, an unfinished run produces statistics rather
   than an exception, and a run without check rounds says it has no channel
   estimate rather than manufacturing one.

Notes
-----
Determinism (D3)
    Every session here is seeded through an injected
    :class:`numpy.random.Generator`, and one test asserts the statistics layer
    itself consumes no randomness at all -- twice over the same transcript
    gives the same object.
No machine learning (D4)
    Counting, two closed forms and two concentration inequalities. No number in
    this file was chosen because it separated attack data; the two tolerances
    that appear are standard errors of the binomial law being tested, computed
    from that law's own parameters.
"""

from __future__ import annotations

import json
import math
import pathlib

import numpy as np
import pytest

from sih141.attacks.channel import DepolarisingChannel, InterceptResend
from sih141.attacks.forgery import OutsideForger, RecipientForger
from sih141.attacks.starvation import CountStarver
from sih141.core.paulis import PauliBasis
from sih141.detect import statistics as statistics_module
from sih141.detect.statistics import (
    EVIDENCE_ABORT_REASONS,
    STRUCTURAL_ABORT_REASONS,
    AbortStatistics,
    CountStatistic,
    TranscriptStatistics,
    chernoff_deviation_bound,
    evidence_abort_probability_bound,
    pooled_check_qber,
    why_wings_agree_is_absent,
    wilson_interval,
)
from sih141.protocol.checkrounds import (
    QberObservation,
    estimate_qber,
    normal_quantile,
)
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    QDSSession,
    SessionTranscript,
)
from sih141.protocol.symmetrise import no_symmetrisation
from sih141.protocol.tally import no_count_exchange
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    AbortReason,
    MatchedSetTooSmall,
)

#: Short enough that twenty runs finish in a few seconds, long enough that the
#: binomial laws in section 3 have something to say. Carries no security claim
#: at this length and none is made from it: what is tested is the *arithmetic*
#: of the nulls, which does not depend on the floors biting.
LENGTH = 96

#: Seeds for the honest-law sample. Twenty runs, two verifiers each.
HONEST_SEEDS = tuple(range(20))

#: Band half-width for the two law checks in section 3, in standard errors of
#: the binomial being tested. Five rather than two because the file makes
#: several such comparisons and a two-sigma band would be expected to fail
#: about once per run on correct code; five is a per-comparison false-alarm
#: probability of ``5.7e-07`` and is still far tighter than any defect these
#: extractions can produce, which are wrong by factors (``2/3`` against
#: ``1/3``) rather than by three standard errors.
SIGMAS = 5.0


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


def _attack_rng(index: int) -> np.random.Generator:
    """Return an adversary's own generator, disjoint from the session's (D6).

    Parameters
    ----------
    index : int
        Which run.

    Returns
    -------
    numpy.random.Generator
    """
    return np.random.default_rng(770_000 + index)


def _honest(length: int = LENGTH, index: int = 0, **kwargs) -> SessionTranscript:
    """Run one honest session and return its transcript.

    Parameters
    ----------
    length : int, optional
        ``L``.
    index : int, optional
        Seed index.
    **kwargs
        Extra :class:`~sih141.protocol.session.QDSSession` keywords.

    Returns
    -------
    SessionTranscript
    """
    return QDSSession(
        ProtocolParams(key_length=length, **kwargs.pop("params_kwargs", {})),
        rng=_session_rng(index),
        **kwargs,
    ).run(0)


def _band(probability: float, trials: int) -> float:
    """Return the ``SIGMAS``-wide agreement band for a binomial count.

    Parameters
    ----------
    probability : float
        The null's per-trial success probability.
    trials : int
        The null's trial count.

    Returns
    -------
    float
        ``SIGMAS * sqrt(n p (1 - p))``, in counts. Computed at the *predicted*
        ``p``, never at the measurement: the hypothesis under test is that the
        derivation is right, and an estimator's own value has no business
        setting the width of its own acceptance band.
    """
    return SIGMAS * math.sqrt(trials * probability * (1.0 - probability))


# --------------------------------------------------------------------------- #
# 1. The boundary
# --------------------------------------------------------------------------- #


def test_the_two_doors_agree_on_an_honest_run():
    """``from_transcript`` is ``from_json(to_json())``, and says so."""
    transcript = _honest()
    through_object = TranscriptStatistics.from_transcript(transcript)
    through_text = TranscriptStatistics.from_json(transcript.to_json())
    assert through_object == through_text


@pytest.mark.parametrize(
    "builder",
    [
        pytest.param(lambda: _honest(), id="honest"),
        pytest.param(
            lambda: QDSSession(
                ProtocolParams(key_length=LENGTH),
                signer=OutsideForger(rng=_attack_rng(1)),
                rng=_session_rng(1),
            ).run(0),
            id="outside-forgery",
        ),
        pytest.param(
            lambda: QDSSession(
                ProtocolParams(key_length=LENGTH),
                symmetriser=no_symmetrisation,
                rng=_session_rng(2),
            ).run(0),
            id="unsymmetrised",
        ),
        pytest.param(
            lambda: QDSSession(
                ProtocolParams(key_length=LENGTH),
                count_exchange=no_count_exchange,
                rng=_session_rng(3),
            ).run(0),
            id="pre-pooled",
        ),
        pytest.param(
            lambda: QDSSession(
                ProtocolParams(key_length=LENGTH, check_fraction=0.25),
                rng=_session_rng(4),
            ).run(0),
            id="checked",
        ),
    ],
)
def test_the_two_doors_agree_on_every_variant(builder):
    """The equality is a property of the code, not of the honest arm."""
    transcript = builder()
    assert TranscriptStatistics.from_transcript(
        transcript
    ) == TranscriptStatistics.from_json(transcript.to_json())


def test_the_detect_package_never_imports_the_attack_suite():
    """The static half of the boundary, checked in the source.

    An import edge from the detector to the adversaries would mean the shipped
    detector could not be built without them -- and would put an object on the
    same import graph as the ground truth it is supposed to be measured
    against. The arithmetic that would justify the import (one Wilson interval)
    is reimplemented instead, and
    ``test_the_wilson_interval_agrees_with_the_protocols`` is what stops the
    two copies drifting.
    """
    package = pathlib.Path(__file__).resolve().parents[1] / "sih141" / "detect"
    sources = sorted(package.glob("*.py"))
    assert sources, "the detect package has no modules to check"
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                assert "sih141.attacks" not in stripped, (
                    f"{source.name} imports the attack suite: {stripped!r}. "
                    f"The detector must be buildable without the adversaries."
                )


def test_a_live_object_that_is_not_a_transcript_is_refused():
    """Not duck-typed: the round trip is the guarantee."""

    class Pretender:
        """A stand-in with the right method and none of the guarantees."""

        def to_json(self) -> str:
            """Return something that looks like a transcript and is not."""
            return "{}"

    with pytest.raises(TypeError, match="must be a SessionTranscript"):
        TranscriptStatistics.from_transcript(Pretender())


def test_from_json_refuses_something_that_is_not_text():
    """The canonical door takes text, and says what to pass instead."""
    with pytest.raises(TypeError, match="JSON transcript text"):
        TranscriptStatistics.from_json({"message_bit": 0})


def test_the_layer_draws_no_randomness():
    """D3: reading the same transcript twice gives the same answer.

    The layer takes no ``rng`` because it has nothing to draw for. If a future
    edit introduced a sampled estimate, this is what would catch it.
    """
    transcript = _honest()
    first = TranscriptStatistics.from_transcript(transcript)
    second = TranscriptStatistics.from_transcript(transcript)
    assert first == second
    assert json.dumps(first.to_dict()) == json.dumps(second.to_dict())


def test_everything_extracted_survives_json():
    """The hand-off to Phase 5 and Phase 6 is a JSON document."""
    stats = TranscriptStatistics.from_transcript(
        _honest(params_kwargs={"check_fraction": 0.25})
    )
    blob = json.loads(json.dumps(stats.to_dict()))
    assert blob["message_bit"] == 0
    assert blob["links"], "a checked run should publish per-link statistics"
    assert set(blob["verifiers"]) == {"Bob", "Charlie"}
    # Tuple keys are joined rather than stringified, so a downstream parser
    # never sees "('Bob', 0)".
    assert all("|" in key for key in blob["links"])
    assert all("|" in key for key in blob["records"])


def _strict_json(payload: dict) -> dict:
    """Serialise and re-read, refusing the non-JSON constants Python allows.

    :func:`json.dumps` writes ``NaN`` and ``Infinity`` as bare tokens by
    default. Both are valid Python and neither is JSON, so a Phase 6 dashboard
    parsing this document in a browser would reject it. This helper is how the
    file asserts the document is a document.

    Parameters
    ----------
    payload : dict
        The statistics dictionary.

    Returns
    -------
    dict
        The same, round-tripped.

    Raises
    ------
    ValueError
        If a non-JSON constant appears anywhere in the document.
    """
    text = json.dumps(payload)

    def refuse(constant: str) -> float:
        raise ValueError(f"non-JSON constant in the document: {constant}")

    return json.loads(text, parse_constant=refuse)


@pytest.mark.parametrize(
    "builder",
    [
        pytest.param(lambda: _honest(), id="honest"),
        pytest.param(
            lambda: _honest(params_kwargs={"check_fraction": 0.25}),
            id="checked",
        ),
        pytest.param(
            lambda: QDSSession(
                ProtocolParams(key_length=LENGTH),
                signer=OutsideForger(rng=_attack_rng(5)),
                rng=_session_rng(5),
            ).run(0),
            id="outside-forgery",
        ),
    ],
)
def test_the_document_is_json_on_every_variant(builder):
    """No ``NaN``, no ``Infinity``, anywhere, on any run shape."""
    stats = TranscriptStatistics.from_transcript(builder())
    assert _strict_json(stats.to_dict())["message_bit"] == 0


def test_an_unmonitored_link_reports_no_fidelity_rather_than_a_broken_one():
    """A checked run whose channel seam was never called has no resource data.

    ``None`` rather than ``0.0``, which would read as a maximally broken
    channel, and rather than ``nan``, which is not JSON. The shape arises for
    real: a transcript written before the monitor existed, or an adversary who
    substitutes his own states and consumes no entanglement, publishes check
    logs with an empty channel array.
    """
    blob = _honest(params_kwargs={"check_fraction": 0.25}).to_dict()
    blob["channel"] = []
    stats = TranscriptStatistics.from_json(json.dumps(blob))

    assert not stats.channel_monitored
    assert stats.has_check_rounds
    resource = stats.link("Bob", 0).resource
    assert resource.samples == 0
    assert resource.mean_fidelity is None
    assert resource.min_concurrence is None
    assert resource.mean_alice_purity is None
    assert resource.ideal_samples.trials == 0
    assert resource.ideal_samples.rate is None
    # The QBER arm still works: it needs the published log, not the monitor.
    assert stats.link("Bob", 0).errors.trials > 0
    _strict_json(stats.to_dict())


def test_no_infinity_reaches_the_json():
    """``Infinity`` is not JSON, and a z-score can be infinite.

    A point-mass null forbids its own violation outright, so the z-score there
    is ``+-inf``. :meth:`CountStatistic.to_dict` writes ``None`` instead, and
    the tail bound -- which is a plain ``0.0`` -- carries the information.
    """
    forbidden = CountStatistic("e", 3, 40, 0.0, "point mass at 0")
    assert math.isinf(forbidden.z_score)
    blob = forbidden.to_dict()
    assert blob["z_score"] is None
    assert blob["tail_bound"] == 0.0
    assert "Infinity" not in json.dumps(blob)


# --------------------------------------------------------------------------- #
# 2. The arithmetic behind every null
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("errors", "rounds"), [(7, 50), (43, 50), (50, 50), (1, 3), (200, 401)]
)
def test_the_wilson_interval_agrees_with_the_protocols(errors, rounds):
    """The third copy of the closed form matches the protocol's, to the bit.

    The detector reimplements the Wilson interval rather than importing
    :mod:`sih141.attacks.statistics`, for the reason
    ``test_the_detect_package_never_imports_the_attack_suite`` states. This is
    the check that keeps the copies from drifting: both are driven from the
    same counts through completely separate code paths. Zero successes is
    excluded here and gets its own test below, because the two copies differ
    there on purpose.
    """
    sample = [
        QberObservation(index, PauliBasis.Z, 1, -1 if index < errors else 1)
        for index in range(rounds)
    ]
    theirs = estimate_qber(sample)
    assert theirs.errors == errors
    ours = wilson_interval(errors, rounds)
    assert (ours.low, ours.high) == (theirs.interval.low, theirs.interval.high)
    assert ours.method == "wilson"
    assert ours.confidence == theirs.interval.confidence


def test_the_wilson_endpoints_are_exact_not_merely_small():
    """``0`` successes gives exactly ``0.0``, not ``6.9e-18``.

    In exact arithmetic the Wilson lower bound at zero successes is the
    difference of two equal expressions; in IEEE 754 they differ by about
    ``1e-18``, so a ``max(0.0, centre - spread)`` returns the dust. Every
    defended result in this project is ``0`` successes out of ``N`` -- ``0/48``
    check-round errors on a clean link, ``0`` mismatches on an honest run -- so
    the dust lands on exactly the numbers a reader most needs to read plainly,
    and ``low == 0.0`` would be ``False`` in a test that ought to pass. This
    copy clamps by case instead.
    """
    assert wilson_interval(0, 8000).low == 0.0
    assert wilson_interval(0, 50).low == 0.0
    assert wilson_interval(8000, 8000).high == 1.0


def test_the_protocols_own_wilson_no_longer_carries_the_float_dust():
    """The finding this test used to pin open is now closed. Kept as the pin.

    :mod:`sih141.attacks.statistics` was written because four copies of this
    interval had drifted and two carried this exact bug. The copy inside
    :func:`~sih141.protocol.checkrounds.estimate_qber` was not part of that
    consolidation and clamped with ``max``/``min``, so at zero errors its lower
    endpoint was ``6.938893903907228e-18`` rather than ``0.0``. This test
    formerly asserted that divergence, so that it could not be fixed silently
    or forgotten quietly; the Phase 4 reconciliation fixed it, and the test now
    asserts the agreement instead.

    It is worth keeping in this direction rather than deleting, because every
    defended result in this project is ``0`` successes out of ``N`` -- so the
    endpoint this covers is the one a published table quotes.
    """
    clean = [QberObservation(index, PauliBasis.Z, 1, 1) for index in range(50)]
    assert estimate_qber(clean).interval.low == 0.0
    assert wilson_interval(0, 50).low == 0.0
    assert estimate_qber(clean).interval.low == wilson_interval(0, 50).low


def test_the_wilson_quantile_is_the_projects_own():
    """No second normal quantile: the interval uses ``normal_quantile``.

    Checked by reconstructing the closed form from that function and comparing.
    """
    successes, trials, confidence = 12, 200, 0.95
    z = normal_quantile(0.5 + confidence / 2.0)
    z2 = z * z
    denominator = trials + z2
    centre = (successes + z2 / 2.0) / denominator
    spread = (
        z
        / denominator
        * math.sqrt(successes * (trials - successes) / trials + z2 / 4.0)
    )
    interval = wilson_interval(successes, trials, confidence=confidence)
    assert interval.low == pytest.approx(centre - spread, rel=0, abs=1e-15)
    assert interval.high == pytest.approx(centre + spread, rel=0, abs=1e-15)


@pytest.mark.parametrize(
    ("successes", "trials", "match"),
    [
        (5, 0, "trials must be at least 1"),
        (5, 4, "exceeds trials"),
    ],
)
def test_the_wilson_interval_refuses_impossible_counts(
    successes, trials, match
):
    """A rate over no trials is not a wide interval; it is no measurement."""
    with pytest.raises(ValueError, match=match):
        wilson_interval(successes, trials)


def test_the_chernoff_bounds_are_their_own_algebra():
    """Both tails equal the closed forms in the docstring, not something near.

    ``exp(-d^2 mu / 2)`` below and ``exp(-d^2 mu / (2 + d))`` above, at the
    observed relative deviation. Recomputed here rather than compared with a
    stored constant, so a mutation of either exponent fails.
    """
    trials, probability, count = 192, 1 / 3, 32
    mean = trials * probability
    d = abs(count - mean) / mean
    lower = math.exp(-d * d * mean / 2.0)
    upper = math.exp(-d * d * mean / (2.0 + d))
    assert chernoff_deviation_bound(
        count, trials, probability, side="lower"
    ) == pytest.approx(lower, rel=1e-15, abs=0)
    assert chernoff_deviation_bound(
        count, trials, probability, side="upper"
    ) == pytest.approx(1.0)
    assert chernoff_deviation_bound(count, trials, probability) == pytest.approx(
        lower + upper, rel=1e-15
    , abs=0)


def test_a_one_sided_bound_is_not_charged_for_the_other_tail():
    """The tail a starvation detector tests is far tighter than the pair.

    At a matched count of zero the two-sided bound is dominated by an upper
    tail nobody is testing. Quoting it would over-state a starvation detector's
    false-positive rate by more than four orders of magnitude, which is the
    wrong kind of conservatism: it does not make the claim safer, it makes the
    scheme look worse than the derivation supports.
    """
    two_sided = chernoff_deviation_bound(0, 192, 1 / 3)
    lower = chernoff_deviation_bound(0, 192, 1 / 3, side="lower")
    assert lower < two_sided
    assert two_sided / lower > 1e4
    assert chernoff_deviation_bound(0, 192, 1 / 3, side="upper") == 1.0


def test_a_point_mass_null_answers_exactly():
    """``p = 0`` and ``p = 1`` are exact, not bounded.

    These are the nulls of the mismatch count and the check-round error count
    on a noiseless link, so getting them approximately right would put a fuzzy
    number on the sharpest statement in the whole layer.
    """
    assert chernoff_deviation_bound(0, 5000, 0.0) == 1.0
    assert chernoff_deviation_bound(1, 5000, 0.0) == 0.0
    assert chernoff_deviation_bound(5000, 5000, 1.0) == 1.0
    assert chernoff_deviation_bound(4999, 5000, 1.0) == 0.0
    # A positive count is above the mean, so only the upper tail is a tail.
    assert chernoff_deviation_bound(1, 5000, 0.0, side="lower") == 1.0
    assert chernoff_deviation_bound(1, 5000, 0.0, side="upper") == 0.0


def test_the_bound_is_a_probability_at_every_deviation():
    """It never leaves ``[0, 1]``, including where the two tails would sum past 1."""
    for count in range(0, 41):
        value = chernoff_deviation_bound(count, 40, 0.5)
        assert 0.0 <= value <= 1.0


def test_chernoff_refuses_an_unknown_side():
    """A misspelled side is refused rather than silently made two-sided."""
    with pytest.raises(ValueError, match="side must be one of"):
        chernoff_deviation_bound(1, 10, 0.5, side="left")


def test_a_zero_variance_z_score_is_signed_infinity_not_a_crash():
    """An outcome the null forbids is infinitely surprising under it."""
    on_the_mass = CountStatistic("e", 0, 59, 0.0, "point mass at 0")
    assert on_the_mass.z_score == 0.0
    above = CountStatistic("e", 4, 59, 0.0, "point mass at 0")
    assert above.z_score == math.inf
    below = CountStatistic("e", 10, 59, 1.0, "point mass at 59")
    assert below.z_score == -math.inf


def test_a_statistic_over_no_trials_reports_no_rate():
    """``None`` rather than ``0.0``: a rate over nothing is undefined."""
    empty = CountStatistic("x", 0, 0, 0.5, "Binomial(0, 1/2)")
    assert empty.rate is None
    assert empty.interval() is None
    assert empty.z_score == 0.0
    assert empty.tail_bound == 1.0
    assert "undefined" in empty.summary()


def test_a_statistic_must_name_its_null():
    """D7 as a constructor check: no null, no statistic."""
    with pytest.raises(ValueError, match="null must be a non-empty sentence"):
        CountStatistic("x", 1, 10, 0.5, "")


def test_a_statistic_cannot_exceed_its_own_denominator():
    """A count above its trials is a wiring error, not a large deviation."""
    with pytest.raises(ValueError, match="exceeds trials"):
        CountStatistic("x", 11, 10, 0.5, "Binomial(10, 1/2)")


def test_the_null_table_counts_what_it_says_it_counts():
    """The module's own summary of its nulls is a checked number, not prose.

    Six wrong prose numbers have shipped in this project, which is why D5 puts
    load-bearing figures in doctests. The null table is a docstring rather than
    an expression, so its two claims -- seventeen rows, seven of them a point
    mass -- are pinned here instead. Add a statistic without adding a row, or
    change a null without changing the sentence, and this fails.
    """
    doc = statistics_module.__doc__
    assert doc is not None
    lines = doc.splitlines()
    rulers = [
        index for index, line in enumerate(lines) if line.startswith("======")
    ]
    assert len(rulers) == 3, "the null table has exactly three ruler lines"
    rows = [
        line for line in lines[rulers[1] + 1 : rulers[2]] if line.strip()
    ]
    assert len(rows) == 17
    assert sum(1 for row in rows if "point mass" in row) == 7


# --------------------------------------------------------------------------- #
# 3. The honest-run laws, checked against honest runs
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def honest_sample() -> tuple[TranscriptStatistics, ...]:
    """Twenty honest runs at ``LENGTH``, extracted through the JSON boundary.

    Module-scoped: the runs are the slow part and nothing in section 3 mutates
    them, since every object in the layer is frozen.
    """
    return tuple(
        TranscriptStatistics.from_transcript(_honest(index=index))
        for index in HONEST_SEEDS
    )


def test_the_matched_count_follows_the_binomial_law(honest_sample):
    """``|M_R| ~ Binomial(n, 1/|B|)``, pooled over forty verifier-runs.

    The corollary D7 permits: honest data may be used to *check* a derived law.
    The band is five standard errors of the law being tested, computed from its
    own parameters -- not from the measurement, and not from anything an
    adversary produced.
    """
    probability = 1.0 / 3.0
    trials = 0
    observed = 0
    for stats in honest_sample:
        for name in ("Bob", "Charlie"):
            statistic = stats.verifier(name).matched
            assert statistic.trials == LENGTH
            assert statistic.null_probability == pytest.approx(probability)
            observed += statistic.count
            trials += statistic.trials
    expected = trials * probability
    assert abs(observed - expected) <= _band(probability, trials), (
        f"matched counts {observed}/{trials} against a predicted "
        f"{expected:.1f}; the law is Binomial(n, 1/|B|) per verifier"
    )


def test_the_pooled_count_follows_the_doubled_binomial_law(honest_sample):
    """``M = m_B + m_C ~ Binomial(2n, 1/|B|)``, exactly.

    Exact rather than approximate because the symmetrisation coins re-assign a
    fixed multiset of ``2n`` entries and cannot move the total, so no
    independence assumption about the two verifiers is needed -- and none is
    available, since conditionally on the records ``m_C = M - m_B``.
    """
    probability = 1.0 / 3.0
    trials = 0
    observed = 0
    for stats in honest_sample:
        pooled = stats.pooled.pooled
        assert pooled is not None
        assert pooled.trials == 2 * LENGTH
        assert pooled.count == (
            stats.verifier("Bob").matched.count
            + stats.verifier("Charlie").matched.count
        )
        observed += pooled.count
        trials += pooled.trials
    expected = trials * probability
    assert abs(observed - expected) <= _band(probability, trials)


def test_an_honest_run_produces_no_mismatch_at_all(honest_sample):
    """``e_R = 0`` exactly, on every run, for both verifiers.

    Not "close to zero": on a noiseless honest link every matched position
    reproduces the declared eigenvalue with probability one, so the null is a
    point mass and the observation is the mass. This is what licenses the
    zero-false-positive claim on ``e_R > 0``, and it is the single most
    load-bearing empirical statement in the layer.
    """
    for stats in honest_sample:
        for name in ("Bob", "Charlie"):
            statistic = stats.verifier(name).mismatch
            assert statistic.count == 0
            assert statistic.null_probability == 0.0
            assert statistic.rate == 0.0
            assert statistic.z_score == 0.0
            assert statistic.tail_bound == 1.0
            assert statistic.upper_tail_bound == 1.0


def test_the_unmatched_positions_are_fair_coins(honest_sample):
    """Unmatched agreements follow ``Binomial(n - |M_R|, 1/2)``, exactly.

    The three Paulis pairwise anticommute, so a measurement in a basis other
    than the declared one on an eigenstate of the declared one is a fair coin,
    independent of the declared sign. This is the statistic that reads ``1.0``
    for a record copied off the declaration, and it costs nothing.
    """
    trials = 0
    observed = 0
    for stats in honest_sample:
        for name in ("Bob", "Charlie"):
            verifier = stats.verifier(name)
            statistic = verifier.unmatched_agreement
            assert verifier.recomputed
            assert statistic.trials == LENGTH - verifier.matched.count
            assert statistic.null_probability == 0.5
            observed += statistic.count
            trials += statistic.trials
    expected = trials * 0.5
    assert abs(observed - expected) <= _band(0.5, trials), (
        f"unmatched agreements {observed}/{trials} against a predicted "
        f"{expected:.1f}; the law is Binomial(n - |M_R|, 1/2)"
    )


def test_the_declared_bases_are_uniform_over_the_alphabet(honest_sample):
    """Each symbol follows ``Binomial(n, 1/|B|)``, and they sum to ``n``."""
    probability = 1.0 / 3.0
    per_symbol = {"X": 0, "Y": 0, "Z": 0}
    trials = 0
    for stats in honest_sample:
        declaration = stats.declarations["Bob"]
        assert declaration.off_alphabet == 0
        assert sum(
            statistic.count for statistic in declaration.basis_counts.values()
        ) == LENGTH
        for symbol, statistic in declaration.basis_counts.items():
            per_symbol[symbol] += statistic.count
        trials += LENGTH
    for symbol, observed in per_symbol.items():
        expected = trials * probability
        assert abs(observed - expected) <= _band(probability, trials), symbol


def test_the_declared_eigenvalues_are_a_fair_coin(honest_sample):
    """``+1`` outcomes follow ``Binomial(n, 1/2)``: Alice draws them uniformly."""
    observed = 0
    trials = 0
    for stats in honest_sample:
        statistic = stats.declarations["Bob"].positive_eigenvalues
        assert statistic.null_probability == 0.5
        observed += statistic.count
        trials += statistic.trials
    assert abs(observed - trials * 0.5) <= _band(0.5, trials)


def test_a_records_bases_are_uniform_too(honest_sample):
    """The recipients draw freely, and Phase A' swaps whole entries.

    So the law survives the exchange, and it holds on the *unsigned* bit's
    records as well -- which the transcript carries and this layer extracts,
    because hiding them would be an editorial choice rather than an extraction.
    """
    probability = 1.0 / 3.0
    observed = 0
    trials = 0
    for stats in honest_sample:
        for bit in (0, 1):
            for party in ("Bob", "Charlie"):
                record = stats.record(party, bit)
                assert record.off_alphabet == 0
                assert record.symmetrised is True
                assert record.signed_bit == (bit == stats.message_bit)
                observed += record.basis_counts["X"].count
                trials += LENGTH
    assert abs(observed - trials * probability) <= _band(probability, trials)


def test_the_verdicts_are_reproducible_from_the_transcript(honest_sample):
    """The recomputed counts agree with the counts the verdicts claim.

    A disagreement is not a probabilistic event: it means the transcript
    contradicts itself, which no adversary in the Phase 3 threat model can
    cause. Recomputing is what makes the layer an audit rather than a copy.
    """
    for stats in honest_sample:
        for name in ("Bob", "Charlie"):
            verifier = stats.verifier(name)
            assert verifier.recomputed
            assert verifier.consistent
            assert verifier.matched.count == verifier.reported_matched
            assert verifier.mismatch.count == verifier.reported_mismatches


def test_an_honest_run_declares_the_counts_it_scored(honest_sample):
    """Phase C' put the same integers on the wire that the verdicts used."""
    for stats in honest_sample:
        assert stats.pooled.counts_exchanged
        assert stats.pooled.declaration_gap == 0
        assert stats.pooled.declaration_digest_present
        assert stats.pooled.declared_bob.count == (
            stats.verifier("Bob").matched.count
        )
        assert stats.pooled.matched_floor_bound == HONEST_ABORT_BUDGET


def test_an_honest_run_spends_two_rounds_and_refuses_none(honest_sample):
    """Point-mass nulls: two spent rounds, one session, zero refusals."""
    for stats in honest_sample:
        assert stats.replay.total_refusals == 0
        assert stats.replay.refusals_by_party == {}
        assert stats.replay.spent_rounds == 2
        assert stats.replay.distinct_sessions == 1
        assert stats.replay.distinct_message_bits == 1
        assert stats.replay.parties_with_spent_rounds == ("Bob", "Charlie")


def test_the_honest_margin_is_the_threshold_itself(honest_sample):
    """With ``r_R`` exactly zero the whole noise budget is unspent."""
    for stats in honest_sample:
        for name in ("Bob", "Charlie"):
            verifier = stats.verifier(name)
            assert verifier.margin == verifier.threshold
            assert verifier.accepted


# --------------------------------------------------------------------------- #
# 4. Refusals are never verdicts
# --------------------------------------------------------------------------- #


def test_the_two_abort_groups_partition_every_reason():
    """Adding a reason upstream fails here rather than joining a group quietly.

    The two groups carry *different provable bounds* -- exactly zero for the
    structural four against ``2**-64`` for the evidence four -- so a reason
    that fell into the wrong one, or into neither, would have a table quoting
    the weaker bound for both.
    """
    assert STRUCTURAL_ABORT_REASONS.isdisjoint(EVIDENCE_ABORT_REASONS)
    assert (
        STRUCTURAL_ABORT_REASONS | EVIDENCE_ABORT_REASONS
    ) == set(AbortReason)


def test_a_starved_run_files_the_refusal_apart_from_the_verdict():
    """One verifier accepts, the other reaches no verdict, and never both.

    The refusal appears in :class:`AbortStatistics`; asking for that verifier's
    statistics raises rather than returning a rejection. Folding the two
    together is the single most likely way for a Phase 5 table to report a
    detection that never happened.
    """
    transcript = QDSSession(
        ProtocolParams(key_length=600),
        count_exchange=CountStarver(party=Party.CHARLIE, rng=_attack_rng(9)),
        rng=_session_rng(9),
    ).run(0)
    stats = TranscriptStatistics.from_transcript(transcript)
    assert stats.aborted
    assert stats.aborts.total >= 1
    assert stats.aborts.evidence >= 1
    assert stats.aborts.structural == 0
    refusing = set(stats.aborts.by_party)
    assert refusing, "a starved run should leave somebody without a verdict"
    assert refusing.isdisjoint(set(stats.verifiers))
    for name in refusing:
        with pytest.raises(KeyError, match="not a rejection"):
            stats.verifier(name)


def test_a_starved_run_shows_the_gap_between_wire_and_log():
    """The declared count is not the count the log supports, and it shows.

    Count starvation is exactly this gap. It is not a probabilistic event under
    any null -- a recipient chose to put a different integer on the wire -- so
    the layer reports it as a signed difference rather than as a z-score of
    something.
    """
    transcript = QDSSession(
        ProtocolParams(key_length=600),
        count_exchange=CountStarver(party=Party.CHARLIE, rng=_attack_rng(10)),
        rng=_session_rng(10),
    ).run(0)
    stats = TranscriptStatistics.from_transcript(transcript)
    declared = stats.pooled.declared_charlie
    assert declared is not None
    honest_mean = declared.expected
    assert declared.count < honest_mean
    assert declared.z_score < 0.0
    # The tail a starvation detector actually tests, and it is the tight one.
    assert declared.lower_tail_bound < declared.tail_bound


def test_the_honest_abort_bound_is_a_function_of_n_and_not_a_constant():
    """It used to be ``2 * 2**-64``. That was wrong in both directions.

    The run-level union is over **three** events -- both per-verifier floors
    *and* the pooled floor -- and :mod:`sih141.protocol.verify` derives
    ``3 eps`` itself, so two terms was smaller than the union bound its own
    derivation supports, i.e. **optimistic**. And a constant is wrong at the
    short end regardless: at ``n = 24`` an honest evidence abort has
    probability ``1.19e-04``, fifteen orders of magnitude above ``2 eps0``.

    It is now :func:`~sih141.detect.statistics.evidence_abort_probability_bound`
    of the run's own **sifted** parameters, and the structural threshold family
    delegates to the same implementation rather than keeping a second copy --
    pinned in ``tests/test_detect_reconciliation.py``.
    """
    # With no parameter set there is no honest number to put there, so the
    # field says so rather than guessing one.
    empty = AbortStatistics.empty()
    assert empty.honest_bound is None
    assert empty.total == empty.structural == empty.evidence == 0

    # A real run carries the bound its own sifted parameters imply.
    stats = TranscriptStatistics.from_transcript(_honest())
    assert stats.aborts.total == 0
    assert stats.aborts.honest_bound == evidence_abort_probability_bound(
        stats.params
    )

    # The value is a function of n, and the point of the fix is that no single
    # constant is right along it. At LENGTH = 96 the honest probability is
    # 2.49e-17 -- five hundred times LARGER than the 2 * eps0 the field used to
    # report, so the old constant was optimistic here; above n = 273 it settles
    # on 3 * eps0, which is LARGER than 2 * eps0 for the different reason that
    # the union is over three floor events and not two.
    assert stats.params.key_length == 96
    assert stats.aborts.honest_bound == pytest.approx(2.4904e-17, rel=1e-3, abs=0)
    assert stats.aborts.honest_bound > 2 * HONEST_ABORT_BUDGET

    settled = evidence_abort_probability_bound(ProtocolParams(key_length=384))
    assert settled == pytest.approx(3 * HONEST_ABORT_BUDGET, rel=1e-12, abs=0)
    assert settled > 2 * HONEST_ABORT_BUDGET

    short = evidence_abort_probability_bound(ProtocolParams(key_length=24))
    assert short > 1e-5
    assert short > 1e12 * settled


def test_a_replay_against_a_live_session_is_counted_not_scored():
    """Refusals are counted beside the verdict, never in place of it.

    Recording a replay refusal as the verifier's outcome would let a replayed
    presentation *delete* the acceptance that spent the round -- a larger hole
    than the ledger closes -- so the count is the only trace, and this layer
    surfaces it without touching the verdict.
    """
    session = QDSSession(ProtocolParams(key_length=LENGTH), rng=_session_rng(11))
    session.run(0)
    for _ in range(3):
        with pytest.raises(MatchedSetTooSmall):
            session.verify(Party.BOB)
    stats = TranscriptStatistics.from_transcript(session.transcript())
    assert stats.replay.total_refusals == 3
    assert stats.replay.refusals_by_party == {"Bob": 3}
    assert stats.verifier("Bob").accepted
    assert stats.aborts.total == 0


def test_a_forging_hop_is_visible_as_two_declarations_and_a_matched_count():
    """The discriminator Phase 3 named, surfaced by the layer.

    A recipient forger supplies half of the second verifier's evidence himself,
    so the declaration he forwards is matched at those positions with
    probability one and Charlie's matched count moves from ``n/|B|`` to
    ``n (1 + 1/|B|) / 2``. Both are closed forms on
    :class:`~sih141.protocol.params.ProtocolParams`, so the assertion is
    against the *prediction*, not against a number read off this run.

    ``transcript.repudiated`` is **not** the discriminator and this test says
    so: it cannot separate signer misbehaviour from channel noise or from
    recipient forgery, and the layer carries it only with that warning.
    """
    params = ProtocolParams(key_length=600)
    transcript = QDSSession(
        params,
        forwarder=RecipientForger(rng=_attack_rng(12)),
        count_exchange_timing=COUNTS_AFTER_FORWARDING,
        rng=_session_rng(12),
    ).run(0)
    stats = TranscriptStatistics.from_transcript(transcript)

    assert stats.forwarding_altered_signature
    assert set(stats.declarations) == {"Bob", "Charlie"}
    assert (
        stats.declarations["Bob"].session_id
        == stats.declarations["Charlie"].session_id
    ), "a forged declaration keeps the round it was forged inside"

    charlie = stats.verifier("Charlie")
    predicted = params.key_length * params.forger_scored_fraction
    assert abs(charlie.matched.count - predicted) <= _band(
        params.forger_scored_fraction, params.key_length
    )
    honest_mean = charlie.matched.expected
    assert charlie.matched.count > honest_mean
    assert charlie.matched.upper_tail_bound < 1e-9
    assert not stats.repudiated, (
        "a run whose forwarding hop altered the declaration is a forgery "
        "experiment, not a repudiation; counting it as one would inflate a "
        "Phase 5 repudiation rate by one per attempted forgery"
    )


def test_an_outside_forgery_shows_up_in_the_rate_and_not_in_the_counts():
    """Her declaration is independent of the logs, so ``|M_R|`` is untouched.

    What moves is ``e_R``, from a point mass at zero to about half the matched
    set. This is the separation the Phase 3 prototype achieved on the rate
    alone, with no check rounds at all, and the layer surfaces both halves.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=600),
            signer=OutsideForger(rng=_attack_rng(13)),
            rng=_session_rng(13),
        ).run(0)
    )
    for name in ("Bob", "Charlie"):
        verifier = stats.verifier(name)
        assert not verifier.accepted
        assert verifier.mismatch.count > 0
        assert verifier.mismatch.upper_tail_bound == 0.0, (
            "under the noiseless honest null a single mismatch has "
            "probability exactly zero"
        )
        assert abs(verifier.matched.z_score) < SIGMAS, (
            "an outside forger cannot move the matched count: she has not "
            "seen the logged bases"
        )


# --------------------------------------------------------------------------- #
# 5. Two links are two channels
# --------------------------------------------------------------------------- #


def test_a_targeted_channel_attack_moves_one_link_and_not_the_other():
    """Per-link statistics detect *and* attribute; a pooled one would do neither.

    A depolariser aimed at Bob's link raises his QBER and drops his resource
    fidelity while Charlie's stay where they were. Nothing here derives a
    threshold: what is asserted is that the *extraction* keeps the two links
    apart, which is the property a threshold would later be applied to.

    Everything on this test is conditioned on (NO-TIMING): the adversary cannot
    infer the check set from timing and so cannot spare the watched rounds.
    """
    attack = DepolarisingChannel(
        0.60, target=Party.BOB, rng=_attack_rng(14)
    )
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=384, check_fraction=0.25),
            resource_factory=attack.resource,
            rng=_session_rng(14),
        ).run(0)
    )
    assert stats.has_check_rounds
    bob = stats.link("Bob", 0)
    charlie = stats.link("Charlie", 0)

    assert bob.errors.count > 0
    assert charlie.errors.count == 0
    assert bob.resource.mean_fidelity < charlie.resource.mean_fidelity
    assert charlie.resource.mean_fidelity == pytest.approx(1.0, abs=1e-9)
    assert bob.resource.ideal_samples.count < bob.resource.samples
    assert charlie.resource.ideal_samples.count == charlie.resource.samples

    # A Pauli twirl is a *unitary*, so the pair stays pure and maximally
    # entangled and only the fidelity to Phi+ moves. Reading purity or
    # concurrence alone would report this link as clean, which is precisely the
    # reason ChannelSample keeps all three rather than summarising them.
    assert bob.resource.mean_purity == pytest.approx(1.0, abs=1e-9)
    assert bob.resource.mean_concurrence == pytest.approx(1.0, abs=1e-9)

    # The wing purities are two numbers and not a boolean, deliberately.
    assert bob.resource.mean_alice_purity == pytest.approx(
        bob.resource.mean_recipient_purity, abs=1e-9
    ), (
        "a twirl on one leg leaves both marginals maximally mixed, which is "
        "exactly why wings_agree is not a detector"
    )

    # Pooling the two would average the disturbance away and lose the
    # attribution entirely -- which is what constraint 3 is about.
    pooled = pooled_check_qber(
        [
            log
            for log in SessionTranscript.from_json(
                QDSSession(
                    ProtocolParams(key_length=384, check_fraction=0.25),
                    resource_factory=DepolarisingChannel(
                        0.60, target=Party.BOB, rng=_attack_rng(14)
                    ).resource,
                    rng=_session_rng(14),
                )
                .run(0)
                .to_json()
            ).check_logs
            if log.message_bit == 0
        ],
        pool=True,
    )
    assert pooled.errors == bob.errors.count + charlie.errors.count
    assert pooled.rounds == bob.errors.trials + charlie.errors.trials
    assert pooled.estimate < bob.errors.rate


def test_an_intercept_resend_moves_both_wings_together():
    """Constraint 2, measured rather than quoted.

    An intercept-resend acts on exactly one leg and destroys the entanglement
    outright -- concurrence goes to ``0`` and fidelity to ``1/2`` -- and yet
    the *two wing purities move together*, both to ``1.0``. A detector reading
    ``wings_agree`` would call this link clean. That is why the layer exposes
    the two purities as numbers and refuses to expose the boolean that compares
    them.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=384, check_fraction=0.25),
            resource_factory=InterceptResend(
                target=Party.BOB, rng=_attack_rng(23)
            ).resource,
            rng=_session_rng(23),
        ).run(0)
    )
    bob = stats.link("Bob", 0).resource
    charlie = stats.link("Charlie", 0).resource

    assert bob.mean_concurrence == pytest.approx(0.0, abs=1e-9)
    assert bob.mean_fidelity == pytest.approx(0.5, abs=1e-9)
    assert charlie.mean_concurrence == pytest.approx(1.0, abs=1e-9)

    # Both wings, together, on the attacked link -- so the boolean that
    # compares them says "agree" and reports nothing.
    assert bob.mean_alice_purity == pytest.approx(1.0, abs=1e-9)
    assert bob.mean_recipient_purity == pytest.approx(1.0, abs=1e-9)
    assert bob.mean_alice_purity == pytest.approx(
        bob.mean_recipient_purity, abs=1e-9
    )

    # What does see it: the per-link QBER, which needs no resource monitor at
    # all and is the statistic Phase 3 named as the cheapest channel signal.
    assert stats.link("Bob", 0).errors.count > 0
    assert stats.link("Charlie", 0).errors.count == 0


def test_pooling_two_links_must_be_asked_for_in_as_many_words():
    """The default is per link; pooling is an opt-in the reviewer can see."""
    transcript = SessionTranscript.from_json(
        _honest(params_kwargs={"check_fraction": 0.25}).to_json()
    )
    with pytest.raises(ValueError, match="deliberate choice"):
        pooled_check_qber(transcript.check_logs, pool=False)
    estimate = pooled_check_qber(transcript.check_logs, pool=True)
    assert estimate.errors == 0
    assert estimate.rounds > 0


def test_pooling_nothing_is_refused_rather_than_reported_as_clean():
    """An empty sample is the absence of a measurement, not a clean channel."""
    with pytest.raises(ValueError, match="no QBER rounds"):
        pooled_check_qber([], pool=True)


def test_a_clean_checked_run_sits_on_every_ideal_value():
    """Point-mass nulls: fidelity, purity and concurrence at ``1``, wings at ``1/2``."""
    stats = TranscriptStatistics.from_transcript(
        _honest(params_kwargs={"check_fraction": 0.25})
    )
    assert stats.channel_monitored
    for (party, bit), link in stats.links.items():
        assert link.errors.count == 0, (party, bit)
        assert link.resource.samples > 0
        assert link.resource.ideal_samples.count == link.resource.samples
        assert link.resource.mean_fidelity == pytest.approx(1.0, abs=1e-9)
        assert link.resource.mean_purity == pytest.approx(1.0, abs=1e-9)
        assert link.resource.mean_concurrence == pytest.approx(1.0, abs=1e-9)
        assert link.resource.mean_alice_purity == pytest.approx(0.5, abs=1e-9)
        assert link.resource.mean_recipient_purity == pytest.approx(
            0.5, abs=1e-9
        )
        assert link.resource.extra_keys == ()
        assert (
            link.resource.qber_samples + link.resource.chsh_samples
            == link.resource.samples
        )


def test_each_check_arm_carries_a_calibrated_interval_and_a_real_bound():
    """Two different questions, two answers, both labelled.

    ``'wilson'`` and ``'normal'`` are *calibrated*: coverage close to nominal,
    the right thing to report. ``'hoeffding'`` is a genuine distribution-free
    *bound*: coverage at least the stated level at every ``n``, and the one a
    D7 threshold is entitled to quote. A report that mixed them without saying
    which is which would not be reporting a confidence level at all, so the
    layer carries both and names them.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=384, check_fraction=0.25),
            rng=_session_rng(24),
        ).run(0)
    )
    for link in stats.links.values():
        assert link.qber.interval.method == "wilson"
        assert link.qber_bound.method == "hoeffding"
        assert link.qber_bound.high >= link.qber.interval.high
        assert link.qber_bound.confidence == link.qber.interval.confidence
        if link.chsh is not None:
            assert link.chsh.interval.method == "normal"
            assert link.chsh_bound.method == "hoeffding"
            assert link.chsh_bound.width >= link.chsh.interval.width
        else:
            assert link.chsh_bound is None


def test_the_chsh_z_uses_the_nulls_variance_not_the_measurements():
    """``(S - 2 sqrt(2)) / sqrt(sum_c 1/(2 n_c))``, recomputed here.

    The variance comes from the ideal null's own correlators,
    ``|E_c| = 1/sqrt(2)``, and not from the measured ones. The hypothesis under
    test is that the ideal analysis is right, and an estimator's own value has
    no business setting the width of its own acceptance band -- the same rule
    :mod:`sih141.attacks.statistics` states for agreement tolerances.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=384, check_fraction=0.25),
            rng=_session_rng(25),
        ).run(0)
    )
    ideal = 2.0 * math.sqrt(2.0)
    for link in stats.links.values():
        if link.chsh is None:
            assert link.chsh_z is None
            continue
        variance = sum(1.0 / (2.0 * count) for count in link.chsh.counts)
        expected = (link.chsh.statistic - ideal) / math.sqrt(variance)
        assert link.chsh_z == pytest.approx(expected, rel=1e-12, abs=0)
        # A clean run sits near the ideal; nothing here is a threshold.
        assert abs(link.chsh_z) < SIGMAS


def test_a_chsh_arm_too_small_for_four_cells_says_so_rather_than_failing():
    """"No Bell test here" and "a Bell test that failed" are different answers.

    A correlator with no rounds behind it is undefined, and treating it as zero
    would report a two-setting experiment as a Bell test. The layer records
    which of the two happened, so a table can never render the first as the
    second.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=24, check_fraction=0.25),
            rng=_session_rng(15),
        ).run(0)
    )
    for link in stats.links.values():
        if link.chsh is None:
            assert link.chsh_unavailable is not None
            assert link.violates_classical_bound is None
            assert link.consistent_with_ideal is None
        else:
            assert link.chsh_unavailable is None
            assert -4.0 <= link.chsh.statistic <= 4.0


# --------------------------------------------------------------------------- #
# 6. What the layer will not do
# --------------------------------------------------------------------------- #


def test_wings_agree_is_nowhere_in_the_layer():
    """Constraint 2, enforced in the source rather than remembered.

    Phase 3 measured that no channel adversary in the threat model moves it, so
    a detector built on it reports a clean link under all three. The reason is
    importable so that it cannot be deleted by accident while the statistic is
    re-added.
    """
    package = pathlib.Path(__file__).resolve().parents[1] / "sih141" / "detect"
    for source in package.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("#", '"', "'", "*", "-", ":")):
                continue
            assert ".wings_agree" not in stripped, (
                f"{source.name} reads wings_agree: {stripped!r}"
            )
    assert "no detection power" in why_wings_agree_is_absent()


def test_a_run_without_check_rounds_says_it_has_no_channel_estimate():
    """No manufactured interval, and the reason is on the object.

    A run with ``check_fraction = 0`` carries no independent estimate of the
    link's error rate, so the only defensible null for ``r_R`` is the noiseless
    one -- and a downstream threshold that wants a noise-tolerant null has to
    be handed the noise level from outside the transcript.
    """
    stats = TranscriptStatistics.from_transcript(_honest())
    assert not stats.has_check_rounds
    assert not stats.channel_monitored
    assert stats.links == {}
    with pytest.raises(KeyError, match="has_check_rounds"):
        stats.link("Bob", 0)


def test_an_unfinished_run_produces_statistics_rather_than_an_exception():
    """A run abandoned after signing is a legitimate thing to read.

    Phase 3 experiments abandon runs on purpose, and "no verdict yet" has to be
    representable without pretending a verdict happened.
    """
    session = QDSSession(ProtocolParams(key_length=LENGTH), rng=_session_rng(16))
    session.distribute()
    session.sign(0)
    stats = TranscriptStatistics.from_transcript(session.transcript())
    assert stats.verifiers == {}
    assert not stats.is_complete
    assert not stats.aborted
    assert stats.pooled.pooled is None
    assert stats.replay.spent_rounds == 0
    assert "no pooled matched count" in stats.summary()
    with pytest.raises(KeyError, match="no verdict"):
        stats.verifier("Bob")


def test_an_unsymmetrised_run_is_flagged_and_quotes_no_pooled_count():
    """Provenance the data does not carry, and a bound that does not apply.

    Without Phase A' there is no non-repudiation claim at any key length, and
    :attr:`pooled_matched_count` is deliberately unavailable: the coins are the
    only randomness the bound uses and without them there are none.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=LENGTH),
            symmetriser=no_symmetrisation,
            rng=_session_rng(17),
        ).run(0)
    )
    assert not stats.symmetrised
    assert stats.pooled.pooled is None
    assert stats.repudiation_guarantee is None
    for bit in (0, 1):
        for party in ("Bob", "Charlie"):
            assert not stats.record(party, bit).symmetrised


def test_a_pre_pooled_run_says_the_recipients_never_compared_counts():
    """``counts_exchanged`` is False, and the declared statistics are absent.

    Such a run enforces the per-verifier floor alone and has no unconditional
    non-repudiation guarantee below ``1/2``. Its *observed* ``M`` still exists,
    because a run produces one whether or not the recipients compared notes;
    what the exchange changes is which totals were reachable.
    """
    stats = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=LENGTH),
            count_exchange=no_count_exchange,
            rng=_session_rng(18),
        ).run(0)
    )
    assert not stats.counts_exchanged
    assert stats.pooled.declared_bob is None
    assert stats.pooled.declared_pooled is None
    assert stats.pooled.declaration_gap is None
    assert not stats.pooled.declaration_digest_present
    assert stats.pooled.pooled is not None


def test_the_sifted_length_is_the_one_every_null_is_stated_over():
    """Check positions carry no key, so no null may count them as trials.

    At the quarter check fraction used here a null stated over ``L`` would
    claim ``64`` expected matched positions where the truth is ``48`` -- a
    third more evidence than the run has -- and every bound in the scheme is
    exponential in that count. Erring in the flattering direction is the
    failure mode this project has already shipped more than once.
    """
    params = ProtocolParams(key_length=192, check_fraction=0.25)
    stats = TranscriptStatistics.from_transcript(
        QDSSession(params, rng=_session_rng(19)).run(0)
    )
    assert stats.nominal_key_length == 192
    assert stats.key_length == params.signing_length == 144
    for name in ("Bob", "Charlie"):
        assert stats.verifier(name).matched.trials == 144
    assert stats.pooled.pooled.trials == 288
    assert stats.declarations["Bob"].length == 144


def test_the_count_exchange_ordering_is_recorded_and_never_averaged():
    """Group by it; do not average over it.

    The two orderings give different answers to the same attack, so a table
    mixing them would average a forgery rate with a denial-of-service rate. The
    layer's job is to make the label impossible to lose.
    """
    before = TranscriptStatistics.from_transcript(_honest(index=20))
    after = TranscriptStatistics.from_transcript(
        QDSSession(
            ProtocolParams(key_length=LENGTH),
            count_exchange_timing=COUNTS_AFTER_FORWARDING,
            rng=_session_rng(20),
        ).run(0)
    )
    assert before.count_exchange_timing == "before-forwarding"
    assert after.count_exchange_timing == "after-forwarding"
    assert before.count_exchange_timing != after.count_exchange_timing


def test_the_security_claim_flag_follows_the_floors():
    """Below a sifted length of ``137`` both floors collapse to ``1``.

    Every number in the layer still computes there, which is exactly why the
    flag exists: a demo-length run must not be quoted as if a rule had been in
    force.
    """
    short = TranscriptStatistics.from_transcript(
        QDSSession(ProtocolParams(key_length=24), rng=_session_rng(21)).run(0)
    )
    assert not short.security_claim
    long = TranscriptStatistics.from_transcript(
        QDSSession(ProtocolParams(key_length=192), rng=_session_rng(22)).run(0)
    )
    assert long.security_claim


def test_the_layer_is_frozen_end_to_end():
    """Nothing downstream can edit a statistic after the fact."""
    stats = TranscriptStatistics.from_transcript(_honest())
    with pytest.raises(Exception):
        stats.message_bit = 1
    with pytest.raises(Exception):
        stats.verifier("Bob").matched.count = 0
