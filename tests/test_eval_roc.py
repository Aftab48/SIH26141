"""Tests for the Phase 5 ROC family, written so that each one could fail.

Phase 6 shipped four defects behind four passing tests, and all four had the
same shape: the test asserted that a string was present in a file. That is the
right check for "has someone deleted this" and no check at all for "does this
do anything". An evaluation family is even easier to test vacuously, because
its output is a table and a table that exists looks like a table that is right.

So the rule here is the one the brief states: for every property claimed, ask
what observation would differ if the property were false, and measure that.
Concretely, and each of these is a named section below:

* the eps ladder is checked by asserting the verdict and the bound **move**
  with the budget, not that a ladder-shaped object came back;
* the reduction is checked against the verdict the sweep stored, by a
  different code path in a different process -- and there is a test that
  corrupts a record to prove the cross-check bites;
* every table cell that matters is recomputed by hand from the records and
  compared;
* the chart is checked by inverting its own geometry -- a plotted circle's
  ``cy`` must map back to the measured rate -- rather than by looking for
  words in the markup;
* an arm that reports zero detections is checked for whether it acted at all,
  which is the Phase 4 replay-arm failure;
* and the guards -- the missing-trial check, the registration collision
  refusal, the up-set check -- are each shown to fire on an input that should
  trip them.

Runtime is dominated by real sessions at ``L = 384`` (about 0.8 s each), so the
corpus is built once per module and shared, and every test names which records
it needs rather than rebuilding them.
"""

from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import replace
from typing import Any

import numpy as np
import pytest

from sih141.detect.detector import detect
from sih141.detect.statistics import wilson_interval
from sih141.eval import roc
from sih141.eval.experiments import EXPERIMENTS, SCENARIOS, Cell, experiment, run_trial
from sih141.eval.records import UNDETECTABLE_BY_CONSTRUCTION, TrialRecord
from sih141.eval.reduce import CONFIDENCE, EXTRA_CHARTS, EXTRA_REDUCTIONS, NOT_EVALUATED
from sih141.eval.roc import (
    EPS_LADDER,
    monotonicity_violations,
    reconciliation,
    roc_chart_svg,
    roc_envelope_table,
    roc_points,
    roc_prototype_table,
    roc_reduction,
    roc_table,
    score_ladder,
)
from sih141.eval.seeds import trial_seeds
from sih141.eval.store import ResultStore
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import COUNTS_AFTER_FORWARDING, COUNTS_BEFORE_FORWARDING
from sih141.protocol.verify import (
    AbortReason,
    MatchedSetTooSmall,
    VerificationAbort,
)

SVG = "{http://www.w3.org/2000/svg}"

#: How many trials of each cell the corpus holds. Four, because the selective
#: starver has to be able to skip one and still leave three attacked, and
#: because a Wilson interval on four is still a Wilson interval.
CORPUS_TRIALS = 4

#: The cells the corpus covers. Not all fifteen: each of these is here because
#: some test below needs the thing only it produces -- a withheld family, an
#: assumption-excluded hypothesis, a second count ordering, a mixed
#: engaged/not-engaged cell, or a curve with a shape.
CORPUS_CELLS = (
    "honest",
    "honest-unchecked",
    "outside-forgery",
    "recipient-forgery",
    "recipient-forgery-after",
    "starvation-selective",
    "impersonation-full",
    "tol-p35",
)

_CORPUS: dict[str, list[TrialRecord]] = {}


def corpus(cell: str, trials: int = CORPUS_TRIALS) -> list[TrialRecord]:
    """Return this cell's records, running them once and caching.

    Parameters
    ----------
    cell : str
        A cell of the ``roc`` experiment.
    trials : int, optional
        How many. Cached per cell, so asking twice for different counts
        returns a prefix rather than re-running.

    Returns
    -------
    list of TrialRecord
    """
    have = _CORPUS.setdefault(cell, [])
    exp = experiment("roc")
    while len(have) < trials:
        have.append(run_trial(exp, cell, len(have)))
    return have[:trials]


@pytest.fixture(scope="module")
def all_records() -> list[TrialRecord]:
    """Return the whole corpus, every cell, as one list.

    Returns
    -------
    list of TrialRecord
    """
    return [record for cell in CORPUS_CELLS for record in corpus(cell)]


@pytest.fixture(scope="module")
def stored(tmp_path_factory: pytest.TempPathFactory, all_records) -> ResultStore:
    """Return a store holding the whole corpus, for the reduce-path tests.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Pytest's factory.
    all_records : list of TrialRecord
        The corpus.

    Returns
    -------
    ResultStore
    """
    store = ResultStore(tmp_path_factory.mktemp("rocstore"))
    for record in all_records:
        store.write(record)
    return store


def _cell_of(table: Any, row_index: int, column: str) -> Any:
    """Return one cell of a table by column name.

    Parameters
    ----------
    table : Table
        The table.
    row_index : int
        Which row.
    column : str
        Column header.

    Returns
    -------
    object
    """
    return table.rows[row_index][table.columns.index(column)]


# --------------------------------------------------------------------------- #
# 1. Registration: the family is wired in, and the wiring refuses to collide
# --------------------------------------------------------------------------- #


def test_the_experiment_and_its_scenarios_are_registered() -> None:
    """The ROC family reaches the sweep's registries at import."""
    assert "roc" in EXPERIMENTS
    for name in roc.ROC_SCENARIOS:
        assert SCENARIOS[name] is roc.ROC_SCENARIOS[name]
    assert EXTRA_REDUCTIONS["roc"] is roc.roc_reduction
    assert EXTRA_CHARTS["roc"] is roc.roc_charts


def test_registering_over_someone_elses_scenario_is_refused() -> None:
    """A collision is loud, because a silent one runs the wrong adversary.

    Two Phase 5 families are being written at once against one flat registry.
    If ``register`` merely assigned, the family that imported second would win
    and the first family's cells would keep running the second's adversary
    under the first's ground-truth label -- a mislabelled table with nothing
    anywhere to give it away.
    """
    with pytest.raises(RuntimeError, match="already registered"):
        roc.register(scenarios={"roc-replay": len}, experiments={})


def test_a_taken_experiment_name_is_refused_rather_than_yielded() -> None:
    """The other half of the collision, and the half easy to get wrong.

    A guard that refuses to overwrite but silently yields -- ``setdefault``,
    or ``if key not in registry`` -- leaves this family registered nowhere and
    its cells never run, which from the outside looks exactly like a family
    nobody wrote. Both directions have to raise.
    """
    with pytest.raises(RuntimeError, match="experiment 'roc' is already"):
        roc.register(scenarios={}, experiments={"roc": "someone else's"})


def test_registering_twice_is_a_no_op() -> None:
    """Import order must not matter; ``register`` is idempotent."""
    before = dict(SCENARIOS), dict(EXPERIMENTS)
    roc.register()
    assert (dict(SCENARIOS), dict(EXPERIMENTS)) == before


def test_every_roc_cell_keeps_its_transcript_and_runs_at_the_anchor() -> None:
    """The two preconditions the reduce-time ladder rests on.

    Without the transcript there is no ladder; without the anchor budget on
    the ladder there is no cross-check against what the sweep stored.
    """
    for cell in experiment("roc").cells:
        assert cell.retain_transcript, cell.name
        assert cell.eps in EPS_LADDER, cell.name


# --------------------------------------------------------------------------- #
# 2. The ladder is real: the verdict and the bound move with the budget
# --------------------------------------------------------------------------- #


def test_the_bound_falls_as_the_budget_tightens() -> None:
    """Every rung proves a strictly smaller bound than the one above it.

    This is what fails if the ladder is wired to a constant, if the reduction
    caches one verdict and relabels it, or if ``eps`` stops reaching
    ``detect``. It is the difference between a curve and fifteen copies of one
    point.
    """
    points = score_ladder(corpus("honest", 1)[0])
    bounds = [point.false_positive_bound for point in points]
    assert len(bounds) == len(EPS_LADDER)
    assert all(a > b for a, b in zip(bounds, bounds[1:])), bounds
    for point in points:
        assert point.false_positive_bound <= point.eps


def test_the_anchor_bound_matches_the_number_phase_4_published() -> None:
    """At ``eps = 1e-9`` this family proves what ``docs/PHASE4.md`` printed.

    An external cross-check, and the cheapest one available: Phase 4 published
    ``3.1464e-10`` or ``3.3964e-10`` on the checked arm and ``2.7818e-10`` on
    the unchecked one, computed by different code at a different time from a
    different seed set. If the ladder were passing the wrong budget, or the
    reduction were reading the wrong field, these would not land on a number
    someone else already wrote down.

    The two checked values are both correct and differ per run: a run whose
    own check plan leaves a channel member unevaluable spends less of the
    budget and proves a smaller number.
    """
    checked = score_ladder(corpus("honest", 1)[0], eps_values=(1e-9,))[0]
    assert checked.false_positive_bound in (
        pytest.approx(3.1464e-10, rel=1e-4, abs=0),
        pytest.approx(3.3964e-10, rel=1e-4, abs=0),
    )
    unchecked = score_ladder(corpus("honest-unchecked", 1)[0], eps_values=(1e-9,))[0]
    assert unchecked.false_positive_bound == pytest.approx(2.7818e-10, rel=1e-4, abs=0)
    assert unchecked.withheld, "the unchecked arm cannot score the channel family"


def test_a_verdict_actually_changes_across_the_ladder() -> None:
    """On the shaped arm the detected flag is not constant.

    A ladder whose verdict never moves proves nothing about ``eps`` reaching
    the thresholds. ``tol-p35`` is the cell where it does move, and the
    movement is in the right direction: fired at the loose end, silent at the
    tight one.
    """
    fired = [
        [point.detected for point in score_ladder(record)]
        for record in corpus("tol-p35")
    ]
    assert any(len(set(row)) > 1 for row in fired), fired
    for row in fired:
        assert row[0] >= row[-1]


def test_the_ladder_is_not_frozen_at_run_time() -> None:
    """A budget nobody committed can still be scored, without re-running.

    The whole reason the ladder lives in the reduction: a reviewer who wants
    an operating point between two of ours re-reduces. If the points were
    baked into the record at sweep time this would be impossible, and this
    test is what tells the difference.
    """
    record = corpus("tol-p35", 1)[0]
    off_ladder = 3.7e-5
    assert off_ladder not in EPS_LADDER
    point = score_ladder(record, eps_values=(off_ladder,))[0]
    assert point.eps == off_ladder
    neighbours = score_ladder(record, eps_values=(1e-4, 1e-5))
    assert neighbours[1].false_positive_bound < point.false_positive_bound
    assert point.false_positive_bound < neighbours[0].false_positive_bound


def test_a_record_without_a_transcript_refuses_rather_than_returns_nothing() -> None:
    """No transcript is a missing input, not a measurement of zero."""
    stripped = replace(corpus("honest", 1)[0], transcript_json=None)
    with pytest.raises(ValueError, match="retain_transcript"):
        score_ladder(stripped)


def test_the_memo_is_keyed_on_the_record_not_on_its_name() -> None:
    """A record that changed gets a fresh ladder, not the cached one.

    A memo keyed only on identity would hand a mutated record the previous
    record's answers, which is the most comfortable possible way for a
    reduction to keep publishing a stale number.
    """
    record = corpus("honest", 1)[0]
    first = score_ladder(record, eps_values=(1e-6,))
    altered = TrialRecord.from_dict(
        {
            **record.to_dict(),
            "transcript_json": corpus("outside-forgery", 1)[0].transcript_json,
        }
    )
    second = score_ladder(altered, eps_values=(1e-6,))
    assert altered.identity == record.identity
    assert second[0].detected != first[0].detected


# --------------------------------------------------------------------------- #
# 3. The cross-check against what the sweep stored, and proof that it bites
# --------------------------------------------------------------------------- #


def test_the_reduction_agrees_with_the_verdict_the_sweep_stored(all_records) -> None:
    """Two routes to the anchor budget, and they must give one answer.

    The record's verdict was computed in the worker from a live
    ``TranscriptStatistics``; this recomputes it from the stored JSON. A
    disagreement means one of them is wrong.
    """
    assert reconciliation(all_records) == ()


def test_the_cross_check_reports_a_corrupted_record() -> None:
    """Flip one stored verdict and the reconciliation must say so.

    Without this the previous test would pass just as happily if
    ``reconciliation`` compared a value with itself.
    """
    record = corpus("honest", 1)[0]
    corrupted = TrialRecord.from_dict(
        {**record.to_dict(), "detection": {**record.detection, "detected": True}}
    )
    problems = reconciliation([corrupted])
    assert len(problems) == 1
    assert "detected" in problems[0]


def test_the_cross_check_reports_a_bound_that_moved() -> None:
    """A silently changed bound is caught too, not only a flipped flag."""
    record = corpus("honest", 1)[0]
    corrupted = TrialRecord.from_dict(
        {
            **record.to_dict(),
            "detection": {
                **record.detection,
                "false_positive_bound": record.detection["false_positive_bound"] * 2,
            },
        }
    )
    problems = reconciliation([corrupted])
    assert len(problems) == 1
    assert "false_positive_bound" in problems[0]


def test_a_record_off_the_ladder_is_named_rather_than_skipped() -> None:
    """"Checked nothing" and "checked everything and found nothing" differ."""
    record = corpus("honest", 1)[0]
    off = TrialRecord.from_dict({**record.to_dict(), "eps": 1.234e-7})
    problems = reconciliation([off])
    assert len(problems) == 1
    assert "cross-checks nothing" in problems[0]


def test_the_reduction_refuses_to_publish_over_a_disagreement() -> None:
    """``roc_reduction`` raises rather than returning tables built on sand."""
    record = corpus("honest", 1)[0]
    corrupted = TrialRecord.from_dict(
        {**record.to_dict(), "detection": {**record.detection, "detected": True}}
    )
    with pytest.raises(RuntimeError, match="the ladder cannot be trusted"):
        roc_reduction([corrupted])


# --------------------------------------------------------------------------- #
# 4. Ground truth: scored against the harness's label, never the detector's
# --------------------------------------------------------------------------- #


def test_an_arm_reporting_zero_detections_can_prove_it_acted() -> None:
    """Phase 4's replay arm reported a clean 0/40 while forwarding honestly.

    ``impersonation-full`` reports no detections by construction, so it is
    exactly the shape of arm that can be silently inert. Its adversary's own
    log has to show she seized the seams.
    """
    records = corpus("impersonation-full")
    for record in records:
        assert record.truth.engaged is True
        assert (record.truth.engaged_count or 0) > 0
        assert record.detection["detected"] is False


def test_every_attack_cell_in_the_corpus_actually_engaged() -> None:
    """No attack cell here is inert; each adversary's own tally says so."""
    for cell in ("outside-forgery", "recipient-forgery", "tol-p35"):
        counts = [record.truth.engaged_count for record in corpus(cell)]
        assert all(count and count > 0 for count in counts), (cell, counts)


def test_a_skipped_run_is_labelled_honest_and_lands_in_the_clean_column() -> None:
    """The selective starver leaves some runs alone, and those are honest runs.

    Constraint 4. Such a run is byte-identical to an honest one; scoring it as
    a miss would report a detection rate whose denominator counts runs on
    which nothing happened.
    """
    records = corpus("starvation-selective")
    engaged = [record for record in records if record.truth.attacked]
    skipped = [record for record in records if not record.truth.attacked]
    assert engaged and skipped, [r.truth.engaged_count for r in records]
    for record in skipped:
        assert record.truth.engaged_count == 0
    point = roc_points(records, eps_values=(1e-9,))[0]
    assert point.attacked == len(engaged)
    assert point.clean == len(skipped)
    assert point.attacked + point.clean == len(records)


def test_the_detection_numerator_counts_only_engaged_runs() -> None:
    """Recomputed by hand from the records, not read back off the table."""
    records = corpus("starvation-selective")
    point = roc_points(records, eps_values=(1e-9,))[0]
    by_hand = sum(
        1
        for record in records
        if record.truth.attacked
        and detect(record.transcript_json or "", eps=1e-9).detected
    )
    assert point.detected == by_hand
    assert point.detected <= point.attacked


# --------------------------------------------------------------------------- #
# 5. Denominators, refusals and missing trials -- constraint 1
# --------------------------------------------------------------------------- #


def test_refusals_are_counted_apart_and_added_to_nothing() -> None:
    """A no-verdict is neither a rejection nor a miss.

    ``recipient-forgery`` under the shipped ordering leaves Charlie with no
    verdict at all. The count has to appear in its own column and must not
    move either rate.
    """
    records = corpus("recipient-forgery")
    point = roc_points(records, eps_values=(1e-9,))[0]

    # Counted by a second route: the reduction reads the transcript's verdicts,
    # and the detector reaches the same conclusion through its own outcome
    # layer and records it as `not_scored`. Recomputing the reduction's own
    # expression here would have cross-checked nothing.
    by_detector = sum(1 for record in records if record.detection["not_scored"])
    assert by_detector > 0, "this cell is supposed to produce refusals"
    assert point.refusals == by_detector

    # The refusals moved neither rate: the denominator is still every attacked
    # run, and the numerator is still what the detector flagged on them.
    assert point.attacked == len(records)
    assert point.clean == 0
    by_hand = sum(
        1
        for record in records
        if detect(record.transcript_json or "", eps=1e-9).detected
    )
    assert point.detected == by_hand

    # And the sharp form: the same runs are refused AND flagged. A refusal is
    # not a rejection, and it is not a non-detection either -- the detector
    # scored every one of them, so none was dropped from the denominator.
    both = [
        record
        for record in records
        if record.detection["not_scored"] and record.detection["detected"]
    ]
    assert both, "a run a verifier refused must still be scored by the detector"


def test_an_empty_denominator_says_so_instead_of_printing_zero() -> None:
    """``no trials``, never ``0.000``: an absence is not a measurement."""
    table = roc_table(corpus("honest"), eps_values=(1e-9,))
    assert _cell_of(table, 0, "attacked") == 0
    assert _cell_of(table, 0, "detected (measured)") == "no trials"
    assert _cell_of(table, 0, "false alarms (measured)").startswith("0/4")


def test_a_missing_trial_index_is_named_in_the_table(all_records) -> None:
    """A trial that never reached disk must not shrink a denominator quietly.

    A scenario that raised is caught by the runner, counted, and leaves no
    file. The reduction therefore checks the index sequence for gaps, and
    this proves the check fires rather than always printing the reassuring
    line.

    The note now comes from :func:`~sih141.eval.reduce.completeness_note`, so
    the intact case says what it could and could not check: without a store to
    read manifests from, this table can only see interior gaps, and a cell
    short by its *last* trials looks intact here. That half of the check lives
    on the outcome table, which is built with the store in hand. The wording
    is asserted because the difference between "nothing is missing" and "I
    could only check for one of the two ways things go missing" is the whole
    point of the change.
    """
    ladder = (1e-9,)
    intact = roc_table(all_records, eps_values=ladder)
    assert any("only interior gaps were" in note for note in intact.notes)
    assert not any("No trial index is missing" in note for note in intact.notes)

    gapped = [r for r in all_records if not (r.cell == "honest" and r.index == 1)]
    holed = roc_table(gapped, eps_values=ladder)
    complaint = [note for note in holed.notes if "INCOMPLETE" in note]
    assert len(complaint) == 1
    assert "honest is missing index [1]" in complaint[0]


def test_the_measured_interval_is_the_wilson_interval() -> None:
    """Recomputed from the definition, not from the same helper the table uses.

    ``(k + z^2/2)/(n + z^2) +- z/(n + z^2) sqrt(k(n-k)/n + z^2/4)``.
    """
    table = roc_table(corpus("outside-forgery"), eps_values=(1e-9,))
    text = _cell_of(table, 0, "detected (measured)")
    match = re.fullmatch(
        r"(\d+)/(\d+) = ([\d.]+) \[([\d.]+), ([\d.]+)\]", str(text)
    )
    assert match is not None, text
    successes, trials = int(match.group(1)), int(match.group(2))
    z = 2.5758293035489004  # two-sided 99%
    centre = (successes + z * z / 2) / (trials + z * z)
    half = (
        z
        / (trials + z * z)
        * math.sqrt(
            successes * (trials - successes) / trials + z * z / 4
        )
    )
    assert float(match.group(3)) == pytest.approx(successes / trials, abs=5e-4)
    assert float(match.group(4)) == pytest.approx(max(0.0, centre - half), abs=1e-3)
    assert float(match.group(5)) == pytest.approx(min(1.0, centre + half), abs=1e-3)
    library = wilson_interval(successes, trials, confidence=CONFIDENCE)
    assert library.low == pytest.approx(centre - half, abs=1e-9)


# --------------------------------------------------------------------------- #
# 6. The audit constraints, each on the cell that instantiates it
# --------------------------------------------------------------------------- #


def test_full_impersonation_is_named_not_zeroed() -> None:
    """Constraint 5: never a blank, a dash or a zero.

    The measured rate over those runs really is ``0/4``. Printing that would
    read as a detector that tried and failed, when the truth is that (AUTH)
    rules the hypothesis out. The clean column would still be a measurement if
    there were clean runs, because the assumption is about the attack.
    """
    records = corpus("impersonation-full")
    table = roc_table(records, eps_values=(1e-9,))
    text = str(_cell_of(table, 0, "detected (measured)"))
    assert text == UNDETECTABLE_BY_CONSTRUCTION
    assert "0/" not in text and text not in ("", "-", "0", "0.000")
    envelope = roc_envelope_table(records, eps_values=EPS_LADDER)
    assert _cell_of(envelope, 0, "breaks at") == UNDETECTABLE_BY_CONSTRUCTION
    # ... and the raw measurement really was a zero, so the label is doing work
    point = roc_points(records, eps_values=(1e-9,))[0]
    assert point.detected == 0 and point.attacked == len(records)


def test_an_unmonitored_link_is_reported_as_not_evaluated() -> None:
    """Constraint 8: withheld is not passed.

    The unchecked cell publishes no channel statistics at all, so the whole
    channel family is unevaluable. The table has to say that rather than
    leaving the column empty, which reads as a family that was scored and
    found clean.
    """
    records = corpus("honest-unchecked")
    point = roc_points(records, eps_values=(1e-9,))[0]
    assert point.withheld, "the unchecked cell must withhold the channel family"
    assert any("channel" in item for item in point.withheld), point.withheld
    table = roc_table(records, eps_values=(1e-9,))
    assert str(_cell_of(table, 0, "withheld")).startswith(NOT_EVALUATED)
    checked = roc_points(corpus("honest"), eps_values=(1e-9,))[0]
    assert checked.withheld == ()


def test_a_structural_member_loses_its_operating_point_below_5e_19() -> None:
    """The ``can_fire`` boundary, found by sweeping rather than asserted.

    Constraint 10. ``structural:evidence-abort`` is scored at ``1e-18`` and
    withheld at ``1e-24``, and bisecting puts the crossover at about
    ``4.9e-19`` -- above ``2**-64``, the smallest budget this project quotes.
    So at the tightest budget anyone here would ask for, that member has no
    admissible operating point and the table must say ``not evaluated``.

    Both ends of the bracket are asserted, because only the pair rules out a
    detector that withholds everywhere or nothing.
    """
    record = corpus("honest", 1)[0]
    scored, withheld = score_ladder(record, eps_values=(1e-18, 1e-24))
    assert "structural:evidence-abort" not in scored.withheld
    assert "structural:evidence-abort" in withheld.withheld

    lo, hi = -21.0, -18.0
    for _ in range(30):
        mid = (lo + hi) / 2
        if score_ladder(record, eps_values=(10.0**mid,))[0].withheld:
            lo = mid
        else:
            hi = mid
    crossover = 10.0**hi
    assert crossover == pytest.approx(4.9e-19, rel=0.02, abs=0)
    assert crossover > 2.0**-64


def test_the_two_count_orderings_are_two_rows_and_two_answers() -> None:
    """Constraint 2: the ordering is a column, never averaged over.

    And it is load-bearing here rather than ceremonial: the same forger is a
    rejection under one ordering and a denial of transfer under the other.
    """
    both = corpus("recipient-forgery") + corpus("recipient-forgery-after")
    table = roc_table(both, eps_values=(1e-9,))
    timings = {row[table.columns.index("count_exchange_timing")] for row in table.rows}
    assert timings == {COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING}
    assert len(table.rows) == 2

    before = corpus("recipient-forgery")[0].transcript_summary["verdicts"]
    after = corpus("recipient-forgery-after")[0].transcript_summary["verdicts"]
    assert before != after
    assert "refused" in before.values() and "refused" in after.values()
    assert set(before) == set(after) == {"Bob", "Charlie"}


def test_the_null_is_a_column_and_both_values_appear() -> None:
    """Constraint 9: a row scored against a null nobody stated is a false claim."""
    both = corpus("honest") + corpus("tol-p35")
    table = roc_table(both, eps_values=(1e-9,))
    column = table.columns.index("null_is_noiseless")
    values = {row[column] for row in table.rows}
    assert values == {"yes", "no"}
    assert all(
        point.dominance_noise_level is not None
        for point in roc_points(both, eps_values=(1e-9,))
    )


def test_the_dominance_level_matches_the_shipped_function() -> None:
    """Recomputed against ``dominance_noise_level`` at the same arguments.

    Constraint 9 asks for this number beside every mismatch-rate detection
    rate; a column carrying something else would satisfy the letter of that
    and none of the point.
    """
    from sih141.detect.thresholds_rate import dominance_noise_level

    records = corpus("honest")
    point = roc_points(records, eps_values=(1e-9,))[0]
    counts = sorted(
        int(value)
        for record in records
        for value in record.transcript_summary["matched"].values()
    )
    expected = dominance_noise_level(
        counts[len(counts) // 2], float(records[0].params["s_a"]), eps=1e-9
    )
    assert point.dominance_noise_level == pytest.approx(expected)


def test_measured_and_proven_never_share_a_column() -> None:
    """Constraint 6, checked on the headers rather than trusted to prose."""
    table = roc_table(corpus("honest"), eps_values=(1e-9,))
    measured = [c for c in table.columns if "measured" in c]
    proven = [c for c in table.columns if "proven" in c]
    assert measured and proven
    assert not set(measured) & set(proven)
    for column in measured:
        assert "bound" not in column
    for column in proven:
        assert "measured" not in column


# --------------------------------------------------------------------------- #
# 7. Monotonicity: the up-set property, and proof that the checker bites
# --------------------------------------------------------------------------- #


def test_the_up_set_property_holds_on_the_corpus(all_records) -> None:
    """No run fires at a tighter budget without firing at every looser one."""
    assert monotonicity_violations(all_records) == ()


def test_the_up_set_checker_reports_a_violation(monkeypatch) -> None:
    """Feed it a non-monotone ladder and it must complain.

    Nothing in the shipped detector produces one, which is the result -- and
    which is also exactly why the checker has to be shown to work on an input
    that should trip it. Otherwise "no violations" is indistinguishable from
    "no check".
    """
    record = corpus("honest", 1)[0]
    crafted = (
        roc.OperatingPoint(
            eps=1e-1,
            detected=False,
            false_positive_bound=1e-2,
            bound_is_unconditional=True,
            null_is_noiseless=True,
            security_claim=True,
            withheld=(),
            kinds=(),
        ),
        roc.OperatingPoint(
            eps=1e-9,
            detected=True,
            false_positive_bound=1e-10,
            bound_is_unconditional=True,
            null_is_noiseless=True,
            security_claim=True,
            withheld=(),
            kinds=(),
        ),
    )
    monkeypatch.setattr(roc, "score_ladder", lambda rec, *, eps_values: crafted)
    problems = monotonicity_violations([record], eps_values=(1e-1, 1e-9))
    assert len(problems) == 1
    assert "fires at eps=1e-09" in problems[0]
    assert "not at the looser eps=0.1" in problems[0]


def test_the_up_set_checker_refuses_a_ladder_in_the_wrong_order() -> None:
    """The claim is stated relative to an order, so the order is enforced."""
    with pytest.raises(ValueError, match="strictly decreasing"):
        monotonicity_violations(corpus("honest", 1), eps_values=(1e-9, 1e-3))


def test_the_envelope_reports_a_violation_it_is_given(monkeypatch) -> None:
    """A ``no`` in the ``up-set holds`` column, and the lines quoted verbatim."""
    records = corpus("tol-p35", 2)
    real = roc.score_ladder

    def flipped(rec, *, eps_values):
        """Return the real ladder with the last two verdicts swapped."""
        points = list(real(rec, eps_values=eps_values))
        points[-1] = replace(points[-1], detected=True)
        points[-2] = replace(points[-2], detected=False)
        return tuple(points)

    monkeypatch.setattr(roc, "score_ladder", flipped)
    table = roc_envelope_table(records, eps_values=EPS_LADDER)
    assert _cell_of(table, 0, "up-set holds") == "no"
    assert any("Up-set violations, verbatim" in note for note in table.notes)


# --------------------------------------------------------------------------- #
# 8. The envelope's five answers, each on a cell that produces it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "cell, expected",
    [
        ("honest", "no attacked runs"),
        ("outside-forgery", "never below 1.0"),
        ("impersonation-full", UNDETECTABLE_BY_CONSTRUCTION),
        ("tol-p35", "1e-04"),
    ],
)
def test_breaks_at_says_which_of_five_things_happened(cell, expected) -> None:
    """A budget value, a ceiling, an absence and an assumption read differently.

    Collapsing them -- printing ``5e-01`` for a hypothesis ruled out by
    assumption, say, which is what this column did before -- turns four facts
    into one misleading number.
    """
    table = roc_envelope_table(corpus(cell), eps_values=EPS_LADDER)
    assert _cell_of(table, 0, "breaks at") == expected


def test_the_shaped_arm_breaks_where_the_grid_says_it_does() -> None:
    """The envelope's summary agrees with the grid it summarises.

    Two routes to one fact: the envelope computes it from ``RocPoint``
    objects, and this reads it back out of the rendered grid rows.
    """
    records = corpus("tol-p35")
    grid = roc_table(records, eps_values=EPS_LADDER)
    rendered = [
        (
            str(_cell_of(grid, i, "eps")),
            str(_cell_of(grid, i, "detected (measured)")),
        )
        for i in range(len(grid.rows))
    ]
    first_below = next(
        eps for eps, text in rendered if not text.startswith(f"{len(records)}/")
    )
    envelope = roc_envelope_table(records, eps_values=EPS_LADDER)
    assert _cell_of(envelope, 0, "breaks at") == first_below


# --------------------------------------------------------------------------- #
# 9. The prototype comparison
# --------------------------------------------------------------------------- #


def test_the_prototype_row_keeps_observation_and_bound_apart(all_records) -> None:
    """``0/80`` and a proven bound are different kinds of claim.

    They live in different columns, the words are on the headers, and the note
    says in as many words that a lower rate from a derived threshold is the
    better result.
    """
    table = roc_prototype_table(all_records)
    assert table.columns.index("false alarms (measured)") != table.columns.index(
        "false-alarm bound (proven)"
    )
    assert roc.PROTOTYPE_FALSE_ALARMS in str(table.rows[0][2])
    assert "none" in str(table.rows[0][3])
    joined = " ".join(table.notes)
    assert (
        "A lower detection rate from a derived threshold is a better "
        "result than a higher rate from a tuned one" in joined
    )


def test_a_comparison_at_an_unscored_budget_says_so(all_records) -> None:
    """No anchor on the ladder means no comparison, and the row says which.

    Dropping the detector's row and leaving the prototype's would read as a
    detector that had been measured and found wanting.
    """
    table = roc_prototype_table(all_records, eps_values=(1e-4,))
    assert len(table.rows) == 2
    assert NOT_EVALUATED in str(table.rows[1][1])
    assert "not on the ladder" in str(table.rows[1][1])


def test_the_two_nulls_are_not_pooled_into_one_headline(all_records) -> None:
    """The noiseless and true-rate rosters get a row each, never an average.

    Pooling them would average a detector that saw everything with one that
    was asked to ignore the noise the attack was hiding in.
    """
    table = roc_prototype_table(all_records)
    labels = [str(row[0]) for row in table.rows]
    assert sum(1 for label in labels if "noiseless null" in label) == 1
    assert sum(1 for label in labels if "true rate as null" in label) == 1
    noiseless = next(row for row in table.rows if "noiseless null" in str(row[0]))
    true_rate = next(row for row in table.rows if "true rate as null" in str(row[0]))

    # Recomputed by a second route: straight off the points, not off the row.
    anchored = [
        point
        for point in roc_points(all_records, eps_values=(1e-9,))
        if point.attacked > 0 and point.detectable
    ]
    quiet = [p for p in anchored if p.null_is_noiseless]
    noisy = [p for p in anchored if not p.null_is_noiseless]
    assert len(quiet) == 4 and len(noisy) == 1, (len(quiet), len(noisy))
    assert str(noiseless[1]).startswith(
        f"{sum(1 for p in quiet if p.detection_rate == 1.0)} of {len(quiet)}"
    )
    assert str(true_rate[1]).startswith(
        f"{sum(1 for p in noisy if p.detection_rate == 1.0)} of {len(noisy)}"
    )
    # The pooled headline would have been "4 of 5"; the split is what stops it.
    assert str(noiseless[1]).startswith("4 of 4")
    assert str(true_rate[1]).startswith("0 of 1")


# --------------------------------------------------------------------------- #
# 10. The chart, checked by its geometry rather than by its words
# --------------------------------------------------------------------------- #


def _series_circles(svg: str) -> dict[str, list[tuple[float, float]]]:
    """Return each series' plotted points, keyed by legend colour.

    Parameters
    ----------
    svg : str
        The chart.

    Returns
    -------
    dict
        Colour to ``(cx, cy)`` pairs, in document order.
    """
    root = ElementTree.fromstring(svg)
    out: dict[str, list[tuple[float, float]]] = {}
    for circle in root.iter(f"{SVG}circle"):
        out.setdefault(circle.get("fill", ""), []).append(
            (float(circle.get("cx", "0")), float(circle.get("cy", "0")))
        )
    return out


def test_the_chart_plots_the_measured_rate_on_the_vertical_axis() -> None:
    """Invert the chart's own y mapping and land on the measured rate.

    The Phase 6 projector-mode defect passed a test asserting a CSS
    declaration was in the stylesheet while the feature was inert. The
    equivalent here would be asserting that the SVG contains circles. So this
    reads a circle's ``cy`` back through the axis and compares it with the
    rate the table reports -- a chart plotting the bound on both axes, or the
    rate upside down, fails.
    """
    records = corpus("tol-p35")
    ladder = (5e-1, 1e-4, 1e-9)
    svg = roc_chart_svg(records, eps_values=ladder, command="test")
    points = roc_points(records, eps_values=ladder)
    series = _series_circles(svg)
    assert len(series) == 1, "one attacked cell, so one colour"
    plotted = next(iter(series.values()))
    assert len(plotted) == len(points)
    for (_, cy), point in zip(plotted, points):
        assert point.detection_rate is not None
        span = roc._CHART_HEIGHT - roc._CHART_TOP - roc._CHART_BOTTOM
        recovered = 1.0 - (cy - roc._CHART_TOP) / span
        assert recovered == pytest.approx(point.detection_rate, abs=2e-3)
    assert len({cy for _, cy in plotted}) > 1, "a flat line would prove nothing"


def test_the_chart_plots_the_proven_bound_on_the_horizontal_axis() -> None:
    """Invert the x mapping and land on the bound, not on eps.

    They are different numbers -- the bound sits a factor of two to fourteen
    inside the budget -- so plotting eps and labelling it "proven bound" is a
    mistake this catches.
    """
    records = corpus("tol-p35")
    ladder = (5e-1, 1e-4, 1e-9)
    svg = roc_chart_svg(records, eps_values=ladder, command="test")
    points = roc_points(records, eps_values=ladder)
    plotted = next(iter(_series_circles(svg).values()))
    bounds = [p.proven_bound for p in points]
    lo, hi = math.floor(math.log10(min(bounds))), math.ceil(math.log10(max(bounds)))
    span = roc._CHART_WIDTH - roc._CHART_LEFT - roc._CHART_RIGHT
    for (cx, _), point in zip(plotted, points):
        recovered = 10 ** (lo + (cx - roc._CHART_LEFT) / span * (hi - lo))
        assert recovered == pytest.approx(point.proven_bound, rel=2e-2, abs=0)
        assert recovered != pytest.approx(point.eps, rel=1e-3, abs=0)


def test_the_chart_error_bars_are_the_wilson_interval() -> None:
    """Each vertical bar spans the interval its point's rate carries."""
    records = corpus("tol-p35")
    ladder = (1e-4,)
    svg = roc_chart_svg(records, eps_values=ladder, command="test")
    point = roc_points(records, eps_values=ladder)[0]
    interval = wilson_interval(point.detected, point.attacked, confidence=CONFIDENCE)
    root = ElementTree.fromstring(svg)
    span = roc._CHART_HEIGHT - roc._CHART_TOP - roc._CHART_BOTTOM
    bars = [
        line
        for line in root.iter(f"{SVG}line")
        if line.get("x1") == line.get("x2")
        and line.get("stroke", "").startswith("#")
        and line.get("opacity") is not None
    ]
    assert len(bars) == 1
    top = 1.0 - (float(bars[0].get("y1", "0")) - roc._CHART_TOP) / span
    bottom = 1.0 - (float(bars[0].get("y2", "0")) - roc._CHART_TOP) / span
    assert top == pytest.approx(interval.low, abs=2e-3)
    assert bottom == pytest.approx(interval.high, abs=2e-3)
    assert interval.high - interval.low > 0.05, "a degenerate bar proves nothing"


def test_the_chart_axis_labels_carry_which_kind_of_number_each_axis_is() -> None:
    """Constraint 6 has to survive the chart being screenshotted."""
    svg = roc_chart_svg(corpus("tol-p35"), eps_values=(1e-4,), command="c")
    root = ElementTree.fromstring(svg)
    labels = [element.text or "" for element in root.iter(f"{SVG}text")]
    assert any(text.startswith("PROVEN false-positive bound") for text in labels)
    assert any(text.startswith("MEASURED detection rate") for text in labels)


def test_the_chart_names_an_excluded_hypothesis_instead_of_drawing_a_zero_line() -> None:
    """A line along the x axis reads as a detector that tried and failed."""
    svg = roc_chart_svg(
        corpus("impersonation-full"), eps_values=(1e-4, 1e-9), command="c"
    )
    root = ElementTree.fromstring(svg)
    labels = [element.text or "" for element in root.iter(f"{SVG}text")]
    assert any(UNDETECTABLE_BY_CONSTRUCTION in text for text in labels)
    assert not list(root.iter(f"{SVG}polyline"))
    assert not list(root.iter(f"{SVG}circle"))


def test_everything_the_chart_draws_stays_inside_the_canvas(all_records) -> None:
    """No point outside the plot area, no legend entry off the bottom.

    A figure that renders is not a figure that reads: the legend grows one
    line per cell, and this family is one cell away from a plot whose last
    series is drawn past the edge of the page. Checked on every cell in the
    corpus rather than on the two-series charts the other tests use.
    """
    svg = roc_chart_svg(all_records, eps_values=EPS_LADDER, command="c")
    root = ElementTree.fromstring(svg)
    right = roc._CHART_WIDTH - roc._CHART_RIGHT
    bottom = roc._CHART_HEIGHT - roc._CHART_BOTTOM
    for circle in root.iter(f"{SVG}circle"):
        x, y = float(circle.get("cx", "0")), float(circle.get("cy", "0"))
        assert roc._CHART_LEFT - 1 <= x <= right + 1, x
        assert roc._CHART_TOP - 1 <= y <= bottom + 1, y
    legend = [
        element
        for element in root.iter(f"{SVG}text")
        if element.get("x") and float(element.get("x", "0")) > right
    ]
    assert len(legend) == len({(r.cell, r.count_exchange_timing) for r in all_records})
    assert max(float(element.get("y", "0")) for element in legend) < bottom

    # The legend gutter has to be wide enough for the longest label, and no
    # font metrics are available here -- so estimate at 5.6 px per character
    # for the 11 px face, which is generous for a serif at that size, and fail
    # if a longer cell name is added without widening _CHART_RIGHT.
    for element in legend:
        width = 5.6 * len(element.text or "")
        assert float(element.get("x", "0")) + width <= roc._CHART_WIDTH, element.text


def test_every_drawn_series_is_visually_distinct(all_records) -> None:
    """No two adversaries share a colour and a dash pattern.

    Eight colours and fifteen groups: a legend keyed by colour alone would
    make three pairs of adversaries indistinguishable, and three of the cells
    have no attacked runs, so the counter has to skip them rather than let
    them consume a colour.
    """
    svg = roc_chart_svg(all_records, eps_values=EPS_LADDER, command="c")
    root = ElementTree.fromstring(svg)
    styles = [
        (line.get("stroke"), line.get("stroke-dasharray"))
        for line in root.iter(f"{SVG}polyline")
    ]
    assert styles, "there must be some series to distinguish"
    assert len(set(styles)) == len(styles), styles


def test_a_chart_with_no_command_says_it_is_not_reproducible() -> None:
    """D9 applies to figures, and silence is the wrong failure mode."""
    svg = roc_chart_svg(corpus("honest"), eps_values=(1e-9,))
    assert "NO COMMAND RECORDED" in svg


def test_the_chart_is_deterministic() -> None:
    """Same records, same bytes -- so a redraw is a diff of nothing."""
    records = corpus("honest")
    first = roc_chart_svg(records, eps_values=(1e-3, 1e-9), command="c")
    second = roc_chart_svg(list(reversed(records)), eps_values=(1e-3, 1e-9), command="c")
    assert first == second
    ElementTree.fromstring(first)


# --------------------------------------------------------------------------- #
# 11. Scenario obligations: D3, D6, and the abort guard
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "cell",
    ["outside-forgery", "recipient-forgery", "replay", "starvation",
     "impersonation-signing"],
)
def test_a_scenario_is_a_pure_function_of_its_seeds(cell) -> None:
    """Run it twice, get the same run. D3, and the whole D9 corollary."""
    exp = experiment("roc")
    first, first_truth = SCENARIOS[exp.cell(cell).scenario](
        exp.cell(cell), trial_seeds("roc", cell, 0)
    )
    second, second_truth = SCENARIOS[exp.cell(cell).scenario](
        exp.cell(cell), trial_seeds("roc", cell, 0)
    )
    assert first.to_json() == second.to_json()
    assert first_truth == second_truth


@pytest.mark.parametrize(
    "cell, draws",
    [
        ("outside-forgery", True),
        ("starvation", True),
        ("impersonation-signing", True),
        # The optimal recipient forger draws nothing at all: his declaration is
        # a deterministic reading of his own log, which is why
        # sih141.attacks.isolation's check (b) reports one distinct decision
        # for him. Nothing about the run may move when only his seed does --
        # and that is a property to assert, not one to work around by giving
        # him a guess_probability the measured rate is not taken at.
        ("recipient-forgery", False),
    ],
)
def test_only_the_adversarys_own_stream_can_move_the_run(cell, draws) -> None:
    """Change only the adversary's seed and see whether the run follows.

    D6 says every adversary owns its randomness and never reads the session's.
    A scenario that quietly handed the adversary the session's generator would
    still pass the determinism test above; it fails here, because swapping one
    seed while holding the other would then change nothing for a randomised
    adversary and everything for the session.
    """
    exp = experiment("roc")
    scenario = SCENARIOS[exp.cell(cell).scenario]
    base = trial_seeds("roc", cell, 0)
    other = trial_seeds("roc", cell, 7)

    swapped_adversary = replace(base, adversary=other.adversary)
    assert swapped_adversary.session == base.session
    assert swapped_adversary.adversary != base.adversary
    baseline = scenario(exp.cell(cell), base)[0].to_json()
    moved = scenario(exp.cell(cell), swapped_adversary)[0].to_json()
    assert (moved != baseline) is draws

    # Either way the session's own stream must still be reaching the protocol,
    # or the test above would pass for a scenario that ignored both seeds.
    swapped_session = replace(base, session=other.session)
    assert scenario(exp.cell(cell), swapped_session)[0].to_json() != baseline


def test_the_replaying_forwarder_draws_from_its_own_stream() -> None:
    """The replay arm's coin and relabelling come from the adversary's rng.

    Checked on the adversary rather than on the transcript, because the
    session rebinds whatever a forwarder returns to the live round, so a
    relabelled opening can be overwritten before it reaches the transcript --
    the attack acted, and the transcript is entitled not to show which draw it
    made. Asserting on the transcript here would have been a test of the
    rebinding, dressed up as a test of D6.
    """
    exp = experiment("roc")
    cell = replace(
        exp.cell("replay"),
        scenario_options={**exp.cell("replay").scenario_options,
                          "replay_probability": 0.5},
    )
    engaged = {
        index: roc.replay_scenario(cell, trial_seeds("roc", "replay", index))[
            1
        ].engaged_count
        for index in range(8)
    }
    assert set(engaged.values()) == {0, 1}, engaged


def test_no_scenario_touches_the_global_generators() -> None:
    """D3: randomness is injected, so the globals must not move."""
    exp = experiment("roc")
    before = (np.random.get_state()[1][0], np.random.get_state()[2])
    for cell in ("outside-forgery", "starvation", "impersonation-signing"):
        SCENARIOS[exp.cell(cell).scenario](
            exp.cell(cell), trial_seeds("roc", cell, 3)
        )
    after = (np.random.get_state()[1][0], np.random.get_state()[2])
    assert after == before


def test_the_impersonation_scenario_refuses_a_cell_with_no_scope() -> None:
    """A defaulted scope would run an honest session under an attack label."""
    cell = Cell(
        name="oops",
        params=ProtocolParams(key_length=96),
        scenario="roc-impersonation",
    )
    with pytest.raises(KeyError, match="names no 'scope'"):
        roc.impersonation_scenario(cell, trial_seeds("d", "oops", 0))


def test_an_unknown_count_ordering_is_refused() -> None:
    """Neither ordering silently, because a typo would pick one."""
    cell = Cell(
        name="oops2",
        params=ProtocolParams(key_length=96),
        scenario="roc-outside-forgery",
        scenario_options={"count_exchange_timing": "whenever"},
    )
    with pytest.raises(ValueError, match="count_exchange_timing"):
        roc.outside_forgery_scenario(cell, trial_seeds("d", "oops2", 0))


def test_a_refusal_raised_out_of_the_session_still_leaves_a_transcript(
    monkeypatch,
) -> None:
    """The guard that keeps a starved run on disk instead of losing it.

    ``QDSSession.run`` catches this at both Phase C steps, so no shipped cell
    reaches the guard -- which is exactly why it needs a test that forces it.
    A trial that raises leaves no file, and a reduction over the survivors
    reports a rate whose denominator quietly shrank.
    """
    sentinel = object()
    refusal = VerificationAbort(
        party=Party.BOB,
        reason=AbortReason.BELOW_FLOOR,
        matched_count=3,
        minimum_matched=36,
        expected_matched=96.0,
        key_length=384,
        message_bit=0,
    )

    class Raising:
        """A session that refuses at a phase ``run`` does not wrap."""

        def __init__(self, *args, **kwargs) -> None:
            """Accept and ignore whatever the scenario passes."""

        def run(self, message_bit: int) -> Any:
            """Raise the refusal the guard exists for."""
            raise MatchedSetTooSmall(refusal)

        def transcript(self) -> Any:
            """Return what the guard must hand back."""
            return sentinel

    monkeypatch.setattr(roc, "QDSSession", Raising)
    cell = experiment("roc").cell("starvation")
    assert roc._run(cell, trial_seeds("roc", "starvation", 0)) is sentinel


# --------------------------------------------------------------------------- #
# 12. The end-to-end reduce path, through the store the CLI uses
# --------------------------------------------------------------------------- #


def test_reduce_experiment_emits_the_roc_tables(stored) -> None:
    """``tools/sweep.py reduce roc`` gets them with no CLI change."""
    from sih141.eval.reduce import reduce_experiment

    tables = reduce_experiment(stored, "roc", command="python tools/sweep.py reduce roc")
    slugs = [table.slug for table in tables]
    assert slugs == ["outcomes", "detection", "timing", "roc", "roc-envelope",
                     "roc-prototype"]
    for table in tables:
        assert table.command, table.slug
        assert "no command recorded" not in table.to_markdown()


def test_a_table_without_a_command_refuses_loudly(stored) -> None:
    """D9: a figure nobody can regenerate must not look publishable."""
    table = roc_table(list(stored.read_experiment("roc")), eps_values=(1e-9,))
    assert "not reproducible and must not be published" in table.to_markdown()


def test_the_tables_survive_a_json_round_trip(stored) -> None:
    """``--format json`` must not lose a cell to a non-serialisable type."""
    tables = roc_reduction(list(stored.read_experiment("roc")), command="c")
    payload = json.dumps([table.to_dict() for table in tables], sort_keys=True)
    assert json.loads(payload)[0]["slug"] == "roc"


def test_the_grid_has_one_row_per_group_and_budget(stored) -> None:
    """Row count is a product, and a missing budget would show up here."""
    records = list(stored.read_experiment("roc"))
    table = roc_table(records, eps_values=EPS_LADDER)
    groups = {(r.cell, r.count_exchange_timing) for r in records}
    assert len(table.rows) == len(groups) * len(EPS_LADDER)


def test_reduction_does_not_depend_on_record_order(stored) -> None:
    """A reduction that sorted by arrival would differ run to run."""
    records = list(stored.read_experiment("roc"))
    forward = roc_table(records, eps_values=(1e-9,)).rows
    backward = roc_table(list(reversed(records)), eps_values=(1e-9,)).rows
    assert forward == backward


def test_rows_follow_the_registry_order_not_the_alphabet(stored) -> None:
    """A ROC sorted by name reads channel-bob, honest, honest-unchecked..."""
    records = list(stored.read_experiment("roc"))
    order = experiment("roc").cell_names
    table = roc_table(records, cell_order=order, eps_values=(1e-9,))
    seen = [row[0] for row in table.rows]
    assert seen == sorted(seen, key=order.index)
    assert seen != sorted(seen)
