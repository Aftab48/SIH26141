"""Tests for the Phase 5 security-curve family.

Written against one question throughout: **what observation would differ if the
property were false?** An evaluation family's whole product is numbers, so a
test that a function exists, is exported, or that a docstring contains a figure
proves nothing about the figure. Every claim here is checked against a value
derived by a different route.

The three that carry the most weight:

* **The attack is really mounted.** A rung of the repudiation curve that reports
  ``0/400`` is only evidence if the same adversary succeeds where it should. So
  the positive control is a test, not a footnote: the same tilt against the
  variant with no symmetrisation exchange must repudiate on every seed. Phase
  4's replay arm reported a clean ``0/40`` while having forwarded honestly, and
  that defect had a green test.
* **The bounds are recomputed from the inequality.** ``averaged_bound_log10``
  is written from ``(1 - p + p exp(-x)) ** n`` rather than called from
  :mod:`sih141.protocol.analysis`, and the two are asserted equal wherever the
  library's float exists. Where it does not -- the outside forger at
  ``L = 115200`` underflows to ``0.0`` -- the test asserts the table refuses to
  print a bound of exactly zero.
* **The tables are recomputed by hand.** One cell of each published table is
  rebuilt from the raw records through a different field, with the Wilson
  interval evaluated from its own definition, and the two are asserted equal.
"""

from __future__ import annotations

import math
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import numpy as np
import pytest

from sih141.attacks.isolation import same_stream
from sih141.detect.detector import detect
from sih141.detect.statistics import TranscriptStatistics, wilson_interval
from sih141.detect.thresholds_rate import dominance_noise_level
from sih141.eval.experiments import (
    EXPERIMENTS,
    SCENARIO_PROBE_OPTIONS,
    SCENARIOS,
    Cell,
    experiment,
    run_trial,
)
from sih141.eval.records import GroundTruth, TrialRecord
from sih141.eval.reduce import reduce_experiment
from sih141.eval.runner import run_experiment
from sih141.eval.security import (
    CONTROL_TILT,
    _repudiation_notes,
    FLOOR_CROSSOVER,
    FLOOR_LADDER,
    PER_VERIFIER_CROSSOVER,
    RECIPIENT_LADDER,
    REPUDIATION_LADDER,
    SECURITY_PROBE_OPTIONS,
    SECURITY_SCENARIOS,
    VERIFIER_CUTS,
    LoggingOutsideForger,
    LoggingRecipientForger,
    TiltingPreparation,
    averaged_bound_log10,
    enforced_bound_log10,
    floor_table,
    forgery_table,
    gap_table,
    optimal_tilt,
    orthogonal_state,
    outside_forgery_bound_log10,
    recipient_forgery_bound_log10,
    register,
    repudiated_from_verdicts,
    repudiation_curve_table,
    security_charts,
    security_claim_at,
)
from sih141.eval.seeds import trial_seeds
from sih141.eval.store import ResultStore
from sih141.protocol.analysis import (
    binary_kl_divergence,
    forgery_bound,
    recipient_forgery_bound,
    recipient_forgery_probability,
    repudiation_probability,
)
from sih141.protocol.keys import KeyElement
from sih141.protocol.params import DEFAULT_PARAMS, Party, ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
)
from sih141.protocol.symmetrise import no_symmetrisation
from sih141.protocol.verify import (
    enforced_repudiation_bound,
    guaranteed_pooled_matched_count,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

REPUDIATION = "repudiation-curve"
FORGERY = "forgery-curve"


# --------------------------------------------------------------------------- #
# 1. The adversaries act, and their logs say what they did                     #
# --------------------------------------------------------------------------- #


def test_orthogonal_state_is_the_opposite_eigenstate_in_every_basis() -> None:
    """The flip is exactly "send the other eigenvalue", basis-free.

    Checked against the key element the protocol would have prepared for the
    opposite eigenvalue, not against a formula restated from the source: the
    overlap with what was sent is zero and the fidelity with the opposite
    eigenstate is one, in all six cases.
    """
    for basis in ("X", "Y", "Z"):
        for eigenvalue in (1, -1):
            sent = np.asarray(KeyElement(basis, eigenvalue).state().data)
            flipped = np.asarray(orthogonal_state(KeyElement(basis, eigenvalue).state()).data)
            opposite = np.asarray(KeyElement(basis, -eigenvalue).state().data)
            assert abs(np.vdot(sent, flipped)) == pytest.approx(0.0, abs=1e-12)
            assert abs(np.vdot(opposite, flipped)) == pytest.approx(1.0, abs=1e-12)


def test_the_tilt_flips_exactly_the_positions_it_says_it_did() -> None:
    """At strength one every candidate is flipped and nothing else is.

    The counter is what :class:`~sih141.eval.records.GroundTruth` is told, so a
    counter that over- or under-reported would publish a detection rate over
    the wrong denominator. Three arms: both recipients, one recipient, and the
    other message bit -- each with an independently known expected count.
    """
    params = ProtocolParams(key_length=48)

    both = TiltingPreparation(1.0, rng=np.random.default_rng(1), message_bit=0)
    QDSSession(params, payload_map=both, rng=np.random.default_rng(2)).run(0)
    assert both.calls == 4 * params.key_length  # two recipients, two bits
    assert both.flips == 2 * params.key_length  # one bit, two recipients
    assert both.flips_by_party == {"Bob": 48, "Charlie": 48}

    aimed = TiltingPreparation(
        1.0, rng=np.random.default_rng(1), message_bit=0, target=Party.CHARLIE
    )
    QDSSession(params, payload_map=aimed, rng=np.random.default_rng(2)).run(0)
    assert aimed.flips == params.key_length
    assert aimed.flips_by_party == {"Charlie": 48}

    other_bit = TiltingPreparation(
        1.0, rng=np.random.default_rng(1), message_bit=1
    )
    QDSSession(params, payload_map=other_bit, rng=np.random.default_rng(2)).run(0)
    assert other_bit.flips == 2 * params.key_length
    assert other_bit.calls == 4 * params.key_length


def test_the_tilt_draws_once_per_call_whatever_it_decides() -> None:
    """Its stream length is a constant of the run and carries no information.

    A seam whose generator advanced only on the positions it cared about would
    publish those positions as the gaps in its consumption, which is the leak
    :mod:`sih141.protocol.distribute` closes for the resource seam. The
    observation that would differ: two tilts of very different strengths, given
    the same seed, must leave their generators at the same point.
    """
    params = ProtocolParams(key_length=48)
    ends = []
    for strength in (0.0, 0.5, 1.0):
        rng = np.random.default_rng(7)
        alice = TiltingPreparation(strength, rng=rng, message_bit=0, target="Bob")
        QDSSession(params, payload_map=alice, rng=np.random.default_rng(8)).run(0)
        ends.append(rng.bit_generator.state["state"]["state"])
        assert alice.calls == 4 * params.key_length
    assert len(set(ends)) == 1, (
        "the tilt's generator finished in three different places for three "
        "strengths, so its stream length depends on what it decided"
    )


def test_a_zero_strength_tilt_produces_an_honest_run() -> None:
    """Nothing flipped is an honest run, and the label refuses to pretend otherwise.

    An untargeted run is byte-identical to an honest one and must be scored as
    one; a cell that labelled every trial 'attacked' would publish a detection
    rate whose denominator counted runs where nothing happened.
    """
    params = ProtocolParams(key_length=48)
    quiet = TiltingPreparation(0.0, rng=np.random.default_rng(3), message_bit=0)
    tilted = QDSSession(
        params, payload_map=quiet, rng=np.random.default_rng(4)
    ).run(0)
    honest = QDSSession(params, rng=np.random.default_rng(4)).run(0)
    assert quiet.flips == 0
    assert tilted.to_json() == honest.to_json()
    assert GroundTruth(
        hypothesis="repudiation", engaged=quiet.flips > 0, engaged_count=quiet.flips
    ).attacked is False


def test_the_forgers_log_a_footprint_and_it_is_not_zero() -> None:
    """Both forgers substitute a declaration, and both can prove it.

    ``engaged`` is read off these counters. An arm reporting zero acceptances
    must be able to show it forged something -- the failure this guards against
    is a forger that quietly forwarded honestly and reported a clean sweep.
    """
    params = ProtocolParams(key_length=48)

    eve = LoggingOutsideForger(rng=np.random.default_rng(1))
    QDSSession(params, signer=eve, rng=np.random.default_rng(2)).run(0)
    assert eve.calls == 1
    # An independent draw over a three-basis alphabet agrees at a position only
    # when the basis and the eigenvalue both coincide, so about 1/6 of them.
    assert 20 <= eve.substituted_positions <= 48

    bob = LoggingRecipientForger(rng=np.random.default_rng(1))
    run = QDSSession(
        params,
        forwarder=bob,
        count_exchange_timing=COUNTS_AFTER_FORWARDING,
        rng=np.random.default_rng(2),
    ).run(0)
    assert bob.calls == 1
    assert bob.substituted_positions > 0
    assert run.forwarding_altered_signature


def test_the_tilt_refuses_to_run_without_its_own_generator() -> None:
    """No default generator: a silent entropy draw would break D9.

    A trial whose adversary seeded itself is not reproducible from its recorded
    seed, and the failure would be invisible -- the sweep would run, the tables
    would print, and nobody could regenerate a row.
    """
    with pytest.raises(TypeError, match="must be a numpy.random.Generator"):
        TiltingPreparation(0.5, rng=None, message_bit=0)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a numpy.random.Generator"):
        LoggingOutsideForger(rng=object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a numpy.random.Generator"):
        LoggingRecipientForger(rng=object())  # type: ignore[arg-type]


def test_each_scenario_keeps_the_two_seed_streams_apart() -> None:
    """D6: the adversary never draws from the session's stream.

    Compared by realised draws (:func:`~sih141.attacks.isolation.same_stream`),
    not by object identity -- two generators built from one seed are different
    objects and the same randomness, which is the leak the function exists to
    catch.
    """
    seeds = trial_seeds(REPUDIATION, "l24", 0)
    assert not same_stream(seeds.session_rng(), seeds.adversary_rng())
    assert seeds.session != seeds.adversary


def test_a_trial_depends_on_its_adversary_seed_and_its_session_seed() -> None:
    """Both halves are load-bearing, which is what makes the seed rule a rule.

    If the tilt secretly drew from the session's generator the first pair would
    agree; if the session ignored its own the second pair would.
    """
    params = ProtocolParams(key_length=96)

    def run(session_seed: int, adversary_seed: int) -> str:
        alice = TiltingPreparation(
            0.25, rng=np.random.default_rng(adversary_seed), message_bit=0
        )
        return QDSSession(
            params, payload_map=alice, rng=np.random.default_rng(session_seed)
        ).run(0).to_json()

    assert run(11, 22) == run(11, 22)
    assert run(11, 22) != run(11, 23)
    assert run(11, 22) != run(12, 22)


# --------------------------------------------------------------------------- #
# 2. The positive control: a zero is only evidence if the attack works         #
# --------------------------------------------------------------------------- #


def test_the_unsymmetrised_control_repudiates_and_the_shipped_one_does_not() -> None:
    """The control that makes every zero in the curve mean something.

    One adversary, one strength, one key length, two protocols. Against the
    variant with no symmetrisation exchange the repudiation succeeds on every
    seed; against the shipped protocol it succeeds on none of them at this
    strength. A change that broke the attack would flip the first assertion,
    which is the observation a check on the second alone would miss entirely.
    """
    params = ProtocolParams(key_length=192)
    trials = 12
    stripped = 0
    shipped = 0
    for seed in range(trials):
        control = TiltingPreparation(
            CONTROL_TILT,
            rng=np.random.default_rng(500 + seed),
            message_bit=0,
            target=Party.CHARLIE,
        )
        stripped += QDSSession(
            params,
            payload_map=control,
            symmetriser=no_symmetrisation,
            rng=np.random.default_rng(900 + seed),
        ).run(0).repudiated
        guarded = TiltingPreparation(
            CONTROL_TILT,
            rng=np.random.default_rng(500 + seed),
            message_bit=0,
            target=Party.CHARLIE,
        )
        shipped += QDSSession(
            params, payload_map=guarded, rng=np.random.default_rng(900 + seed)
        ).run(0).repudiated
        assert control.flips > 0 and guarded.flips > 0

    assert stripped == trials, (
        f"the unsymmetrised control repudiated only {stripped}/{trials} times; "
        f"the attack is no longer being mounted, so every zero in the "
        f"symmetrised curve would be uninterpretable"
    )
    assert shipped == 0, (
        f"the shipped protocol was repudiated {shipped}/{trials} times at a "
        f"tilt this coarse, which would be a real non-repudiation failure"
    )


def test_the_measured_rate_tracks_the_exact_in_model_probability() -> None:
    """The curve is checked against a closed form, not against itself.

    ``repudiation_probability`` is the exact probability for this adversary's
    own family -- a signer tilting both deliveries independently at rate ``q``
    -- and it is computed by code that knows nothing about the simulator. At
    ``L = 48`` the closed form is ``0.157``; ninety runs put the measurement
    inside a 99% interval around it. A simulator that had stopped flipping, or
    a tilt whose realised rate was not ``q``, would fall outside.
    """
    params = ProtocolParams(key_length=48)
    strength = dict(REPUDIATION_LADDER)[48]
    exact = repudiation_probability(params, mismatch_probability=strength)
    trials = 90
    successes = 0
    for seed in range(trials):
        alice = TiltingPreparation(
            strength, rng=np.random.default_rng(2000 + seed), message_bit=0
        )
        successes += QDSSession(
            params, payload_map=alice, rng=np.random.default_rng(6000 + seed)
        ).run(0).repudiated
    interval = wilson_interval(successes, trials, confidence=0.99)
    assert interval.low <= exact <= interval.high, (
        f"measured {successes}/{trials} = {successes / trials:.3f}, whose 99% "
        f"interval [{interval.low:.3f}, {interval.high:.3f}] excludes the "
        f"exact in-model probability {exact:.3f}"
    )


# --------------------------------------------------------------------------- #
# 3. The count ordering changes the answer, and the table has to show it       #
# --------------------------------------------------------------------------- #


def test_the_count_ordering_changes_what_the_recipient_forgery_does() -> None:
    """Constraint 2, as a measurement rather than a rule.

    Same attack, same code, same key length. Before forwarding, the pooled
    matched count is undefined once Bob has substituted the declaration, both
    verifiers refuse and the attack is a denial of transfer. After forwarding,
    Charlie scores it and it sometimes succeeds. Pooling the two would publish
    a rate describing neither run, which is why the ordering is a grouping key
    on every table in this family.
    """
    params = ProtocolParams(key_length=96)
    trials = 20
    outcomes: dict[str, dict[str, int]] = {}
    for timing in (COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING):
        tally = {"accepted": 0, "rejected": 0, "no verdict": 0}
        for seed in range(trials):
            bob = LoggingRecipientForger(rng=np.random.default_rng(70 + seed))
            run = QDSSession(
                params,
                forwarder=bob,
                count_exchange_timing=timing,
                rng=np.random.default_rng(300 + seed),
            ).run(0)
            assert bob.substituted_positions > 0
            charlie = run.charlie
            if charlie is None:
                tally["no verdict"] += 1
            elif charlie.accepted:
                tally["accepted"] += 1
            else:
                tally["rejected"] += 1
        outcomes[timing] = tally

    assert outcomes[COUNTS_BEFORE_FORWARDING]["no verdict"] == trials
    assert outcomes[COUNTS_BEFORE_FORWARDING]["accepted"] == 0
    assert outcomes[COUNTS_AFTER_FORWARDING]["no verdict"] == 0
    assert outcomes[COUNTS_AFTER_FORWARDING]["accepted"] > 0, (
        "the after-forwarding arm accepted nothing, so the two orderings would "
        "look alike and the constraint this family demonstrates would be "
        "untestable"
    )


def test_the_forgery_cells_cover_both_orderings_at_every_recipient_rung() -> None:
    """A ladder that ran one ordering could not carry the column at all."""
    forgery = experiment(FORGERY)
    for length in RECIPIENT_LADDER:
        for suffix, timing in (
            ("before", COUNTS_BEFORE_FORWARDING),
            ("after", COUNTS_AFTER_FORWARDING),
        ):
            cell = forgery.cell(f"bob{length}{suffix}")
            assert cell.params.key_length == length
            assert cell.scenario_options["count_exchange_timing"] == timing


# --------------------------------------------------------------------------- #
# 4. Bounds recomputed from the inequality                                     #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("key_length", [30, 96, 192, 768, 4800])
def test_the_log_space_bounds_agree_with_the_library(key_length: int) -> None:
    """The second route to every proven column in these tables.

    ``averaged_bound_log10`` is written from ``(1 - p + p exp(-x)) ** n``; the
    library computes the same bound by its own path. Where both are
    representable they must agree to floating-point noise.
    """
    params = ProtocolParams(key_length=key_length)
    threshold = params.threshold_for(Party.CHARLIE)

    mine = averaged_bound_log10(
        trials=params.key_length,
        match_probability=params.match_probability,
        exponent=binary_kl_divergence(threshold, 0.5),
    )
    assert mine == pytest.approx(
        math.log10(forgery_bound(params, method="kl")), abs=1e-9
    )
    assert mine == pytest.approx(outside_forgery_bound_log10(params), abs=1e-12)

    recipient = averaged_bound_log10(
        trials=params.key_length,
        match_probability=params.forger_scored_fraction,
        exponent=binary_kl_divergence(threshold, params.forger_floor),
    )
    assert recipient == pytest.approx(
        math.log10(recipient_forgery_bound(params, method="kl")), abs=1e-9
    )
    assert recipient == pytest.approx(
        recipient_forgery_bound_log10(params), abs=1e-12
    )


@pytest.mark.parametrize("key_length", [24, 137, 192, 4800, 115200])
def test_the_enforced_bound_is_recomputed_from_the_floors(key_length: int) -> None:
    """``exp(-max(2 m_min, M_min) gap^2 / 8)``, from the floors, in log space."""
    params = ProtocolParams(key_length=key_length)
    floor = guaranteed_pooled_matched_count(params)
    by_hand = -floor * params.gap**2 / 8.0 / math.log(10.0)
    assert enforced_bound_log10(params) == pytest.approx(by_hand, abs=1e-12)
    assert enforced_bound_log10(params) == pytest.approx(
        math.log10(enforced_repudiation_bound(params)), abs=1e-9
    )


def test_a_bound_that_underflows_is_never_printed_as_zero() -> None:
    """The reason the tables carry log10 rather than the library's float.

    ``forgery_bound`` returns ``0.0`` at the shipped parameter set. Printing
    that would state a bound of exactly zero -- a claim no proof in this
    package makes -- so the table prints ``10^-6553`` instead, and this test
    fails if it ever prints a zero.
    """
    assert forgery_bound(DEFAULT_PARAMS, method="kl") == 0.0
    log10 = outside_forgery_bound_log10(DEFAULT_PARAMS)
    assert log10 == pytest.approx(-6553.3157, abs=1e-3)

    rows = floor_table([]).rows
    row = next(r for r in rows if r[0] == DEFAULT_PARAMS.key_length)
    assert row[8].startswith("10^-6553")
    assert not any(
        isinstance(cell, str) and cell.startswith("0.000e") for cell in row
    )
    # The recipient forger's bound at the same parameters is the 1e-103 the
    # project publishes, and it is representable, so it prints as a float.
    assert recipient_forgery_bound_log10(DEFAULT_PARAMS) == pytest.approx(
        -102.9493, abs=1e-3
    )
    assert row[7].startswith("1.12")


# --------------------------------------------------------------------------- #
# 5. The floors, measured against a running protocol                           #
# --------------------------------------------------------------------------- #


def test_the_crossovers_are_where_the_constants_say_they_are() -> None:
    """Scanned, not asserted: the first key length at which each floor bites.

    A constant that had drifted would be found here rather than in a caption.
    """
    first_pooled = next(
        L
        for L in range(1, 400)
        if minimum_pooled_matched_count(ProtocolParams(key_length=L)) > 1
    )
    first_local = next(
        L
        for L in range(1, 400)
        if minimum_matched_count(ProtocolParams(key_length=L)) > 1
    )
    assert first_pooled == FLOOR_CROSSOVER == 137
    assert first_local == PER_VERIFIER_CROSSOVER == 273
    assert not security_claim_at(FLOOR_CROSSOVER - 1)
    assert security_claim_at(FLOOR_CROSSOVER)


def test_the_security_claim_column_agrees_with_a_run_that_actually_happened() -> None:
    """The column is checked against the transcript, not against its own formula.

    ``security_claim_at`` is a function of the key length;
    :attr:`~sih141.detect.statistics.TranscriptStatistics.security_claim` is
    read off a run the protocol really executed. Two rungs of the ladder
    straddle the crossover and the two routes must agree on both.
    """
    for key_length, expected in ((132, False), (138, True)):
        params = ProtocolParams(key_length=key_length)
        transcript = QDSSession(params, rng=np.random.default_rng(17)).run(0)
        stats = TranscriptStatistics.from_json(transcript.to_json())
        assert stats.security_claim is expected
        assert security_claim_at(key_length) is expected


def test_the_ladder_straddles_the_crossover() -> None:
    """A curve starting at L=192 would hide the most interesting part."""
    lengths = [length for length, _ in REPUDIATION_LADDER]
    assert any(not security_claim_at(L) for L in lengths)
    assert any(security_claim_at(L) for L in lengths)
    assert min(lengths) < FLOOR_CROSSOVER < max(lengths)
    assert FLOOR_CROSSOVER in FLOOR_LADDER
    assert FLOOR_CROSSOVER - 1 in FLOOR_LADDER
    assert PER_VERIFIER_CROSSOVER in FLOOR_LADDER


def test_the_floor_table_reports_the_step_rather_than_smoothing_it() -> None:
    """The two crossover rows, and their predecessors, by value."""
    rows = {row[0]: row for row in floor_table([]).rows}
    assert rows[136][1:5] == (1, 1, 2, "no")
    assert rows[137][1:5] == (1, 2, 2, "yes")
    assert rows[272][1:5] == (1, 55, 55, "yes")
    assert rows[273][1:5] == (2, 55, 55, "yes")
    assert rows[DEFAULT_PARAMS.key_length][1:5] == (36555, 74190, 74190, "yes")


def test_the_tilt_strengths_are_the_best_move_available() -> None:
    """Every rung's ``q`` beats half and twice itself, and the cheap ones exactly.

    D7 forbids tuning a *threshold* on attack data; choosing the strongest move
    in a modelled adversary's family is the opposite, and publishing a weaker
    Alice's rate would overstate the scheme. The full grid search is rerun only
    at the cheap rungs -- it costs ``O(L^2)`` per evaluation -- and every rung
    is checked for being a local maximum, which is the property the published
    number actually needs.
    """
    for key_length, strength in REPUDIATION_LADDER:
        params = ProtocolParams(key_length=key_length)
        best = repudiation_probability(params, mismatch_probability=strength)
        for factor in (0.5, 2.0):
            worse = repudiation_probability(
                params, mismatch_probability=strength * factor
            )
            assert worse < best, (
                f"at L={key_length} a tilt of {strength * factor} beats the "
                f"published {strength}, so the curve reports a weaker Alice "
                f"than the family contains"
            )
        if key_length <= 192:
            assert optimal_tilt(params) == strength


# --------------------------------------------------------------------------- #
# 6. The tables, recomputed by a second route                                  #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def repudiation_store(tmp_path_factory: pytest.TempPathFactory) -> ResultStore:
    """Run a reduced repudiation sweep once and share it across the table tests.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Pytest's per-module temporary directory factory.

    Returns
    -------
    ResultStore
        Six trials each of ``l24``, ``l96`` and ``unsym192``: two rungs of the
        ladder, so the chart has a curve rather than a point, and one control
        that repudiates every time, so the tests below have a saturated row as
        well as sparse ones.
    """
    root = tmp_path_factory.mktemp("repudiation")
    store = ResultStore(root)
    run_experiment(
        experiment(REPUDIATION),
        store,
        trials=6,
        cells=["l24", "l96", "unsym192"],
        workers=1,
        in_process=True,
        quiet=True,
    )
    return store


def test_both_routes_to_the_repudiation_event_agree_on_every_record(
    repudiation_store: ResultStore,
) -> None:
    """The transcript's own property against the recorded verdicts.

    ``transcript_summary["repudiated"]`` is computed inside the session from
    its :class:`~sih141.protocol.verify.VerificationResult` objects;
    :func:`repudiated_from_verdicts` rebuilds the event from the verdict
    strings the summary wrote separately. A cross-check between two fields
    written by one line of code would be vacuous; these are written by two.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    assert records
    seen = set()
    for record in records:
        rebuilt = repudiated_from_verdicts(record)
        assert rebuilt == bool(record.transcript_summary["repudiated"]), (
            f"{record.identity} disagrees: verdicts say {rebuilt}"
        )
        seen.add(rebuilt)
    assert seen == {True, False}, (
        "every record agreed on the same answer, so the comparison could not "
        "have failed either way"
    )


def test_the_repudiation_table_cell_is_recomputed_by_hand(
    repudiation_store: ResultStore,
) -> None:
    """One published cell, rebuilt from the raw records through the other field.

    The table counts through :func:`repudiated_from_verdicts`; this counts
    through ``transcript_summary["repudiated"]`` and evaluates the Wilson
    interval from its own definition rather than calling the same helper.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    table = repudiation_curve_table(records, command="test")
    row = next(r for r in table.rows if r[0] == "unsym192")

    group = [r for r in records if r.cell == "unsym192"]
    engaged = [r for r in group if r.truth.attacked]
    successes = sum(
        1 for r in engaged if bool(r.transcript_summary["repudiated"])
    )
    trials = len(engaged)

    # Wilson, from the definition, with no call into detect.statistics.
    z = 2.5758293035489004  # two-sided 99%
    phat = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denominator
    half = (
        z
        * math.sqrt(phat * (1.0 - phat) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    expected = (
        f"{successes}/{trials} = {phat:.4f} "
        f"[{max(0.0, centre - half):.4f}, {min(1.0, centre + half):.4f}]"
    )
    assert row[8] == expected
    assert row[5] == len(group)
    assert row[6] == trials
    assert row[7] == len(group) - trials


def test_the_repudiation_row_never_folds_a_refusal_into_a_result(
    repudiation_store: ResultStore,
) -> None:
    """Constraint 1: the aborts are their own column and are in the denominator.

    A run that reached no verdict is not a repudiation -- Bob did not accept --
    and the row has to be able to say how many there were. This asserts the
    arithmetic that makes that checkable rather than trusted.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    table = repudiation_curve_table(records, command="test")
    for row in table.rows:
        cell, engaged, measured, refusals = row[0], row[6], row[8], row[9]
        group = [r for r in records if r.cell == cell and r.truth.attacked]
        assert engaged == len(group)
        assert refusals == sum(
            1 for r in group if bool(r.transcript_summary["aborted"])
        )
        successes = int(str(measured).split("/")[0])
        assert successes + refusals <= engaged
        # A repudiation and a refusal are disjoint: an aborted run has no
        # accepting Bob, so no row can double-count one as the other.
        assert not any(
            bool(r.transcript_summary["aborted"])
            and repudiated_from_verdicts(r)
            for r in group
        )
    assert any("no verdict" in note or "ABORTS" in note for note in table.notes)


def test_the_repudiation_table_keeps_measured_and_proven_apart(
    repudiation_store: ResultStore,
) -> None:
    """Three probability columns, three different kinds of claim, three labels."""
    table = repudiation_curve_table(
        list(repudiation_store.read_experiment(REPUDIATION)), command="test"
    )
    assert "repudiated (measured)" in table.columns
    assert "exact in-model P (closed form)" in table.columns
    assert "enforced bound (proven)" in table.columns
    measured_index = table.columns.index("repudiated (measured)")
    proven_index = table.columns.index("enforced bound (proven)")
    assert measured_index != proven_index
    row = next(r for r in table.rows if r[0] == "l24")
    assert "/" in str(row[measured_index]) and "[" in str(row[measured_index])
    assert float(str(row[proven_index])) == pytest.approx(
        enforced_repudiation_bound(ProtocolParams(key_length=24)), rel=1e-3
    , abs=0)


def test_the_curve_says_where_a_demo_scale_run_cannot_demonstrate_anything(
    repudiation_store: ResultStore,
) -> None:
    """The limitation is a footnote on the table, not a thing a reader must infer.

    Built from the rows rather than written out, so a table with no zero rung
    does not carry a note claiming one.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    saturated = repudiation_curve_table(
        [r for r in records if r.cell == "unsym192"], command="test"
    )
    assert not any("DEMO-SCALE" in note for note in saturated.notes)

    zeroed = repudiation_curve_table(
        [r for r in records if r.cell == "l24"], command="test"
    )
    has_zero = any(str(row[8]).startswith("0/") for row in zeroed.rows)
    assert has_zero == any("DEMO-SCALE" in note for note in zeroed.notes)


def test_the_forgery_table_columns_sum_to_the_denominator(
    tmp_path: Path,
) -> None:
    """Accepted + rejected + no verdict = engaged, exactly, on every row.

    The arithmetic that makes constraint 1 checkable for this arm. A refusal
    folded into a rejection would leave the sum intact but move the acceptance
    rate's meaning, so the test also asserts the before-forwarding rows are all
    refusals and none of them are rejections.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment(FORGERY),
        store,
        trials=6,
        cells=["eve24", "bob96before", "bob96after"],
        workers=1,
        in_process=True,
        quiet=True,
    )
    records = list(store.read_experiment(FORGERY))
    table = forgery_table(records, command="test")
    for row in table.rows:
        engaged = row[5]
        accepted = int(str(row[6]).split("/")[0])
        assert accepted + row[7] + row[8] == engaged
        assert engaged + row[9] == row[4]

    before = next(r for r in table.rows if r[0] == "bob96before")
    assert before[7] == 0 and before[8] == before[5] and before[8] > 0
    after = next(r for r in table.rows if r[0] == "bob96after")
    assert after[8] == 0
    eve = next(r for r in table.rows if r[0] == "eve24")
    assert eve[10] != "forger" and "/" in str(eve[10])
    assert before[10] == "forger"


def test_the_forgery_table_quotes_the_right_closed_form_per_adversary(
    tmp_path: Path,
) -> None:
    """Eve's exact probability is not the recipient's, and the row says which."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment(FORGERY),
        store,
        trials=2,
        cells=["bob192after"],
        workers=1,
        in_process=True,
        quiet=True,
    )
    table = forgery_table(list(store.read_experiment(FORGERY)), command="test")
    row = table.rows[0]
    params = ProtocolParams(key_length=192)
    # Printed to four significant figures, so the tolerance is the printing's
    # and not the arithmetic's.
    assert float(row[11]) == pytest.approx(
        recipient_forgery_probability(params), rel=1e-4
    , abs=0)
    assert float(row[12]) == pytest.approx(
        10.0 ** recipient_forgery_bound_log10(params), rel=1e-3
    , abs=0)
    assert float(row[11]) < float(row[12]), (
        "the exact acceptance probability exceeds its own upper bound, which "
        "would mean one of the two is wrong"
    )


# --------------------------------------------------------------------------- #
# 7. The ground-truth wall                                                     #
# --------------------------------------------------------------------------- #


def test_the_detector_reaches_the_same_verdict_from_the_transcript_alone() -> None:
    """Nothing in the label can have reached the detector.

    The record's ``detection`` is rebuilt here by calling
    :func:`~sih141.detect.detector.detect` on the transcript's JSON with no
    label anywhere in scope, and the two are compared field by field. A
    detector that had read the ground truth would disagree.
    """
    forgery = experiment(FORGERY)
    record = run_trial(forgery, "bob96after", 0, retain_transcript=True)
    assert record.transcript_json is not None
    independent = detect(
        record.transcript_json,
        eps=record.eps,
        channel_error_rate=0.0,
        tolerated_depolarising=0.0,
    )
    assert independent.to_dict() == record.detection
    assert record.truth.engaged_count is not None
    assert str(record.truth.engaged_count) not in record.transcript_json[:0] + ""
    for key in ("engaged", "engaged_count", "targeted_link", "hypothesis"):
        assert key not in record.detection


def test_ground_truth_refuses_an_arm_that_reports_no_action() -> None:
    """The contradiction Phase 4's replay arm shipped is refused, not recorded."""
    with pytest.raises(ValueError, match="engaged=True with engaged_count=0"):
        GroundTruth(hypothesis="repudiation", engaged=True, engaged_count=0)


# --------------------------------------------------------------------------- #
# 8. The chart                                                                 #
# --------------------------------------------------------------------------- #


def test_the_chart_is_well_formed_and_carries_its_command(
    repudiation_store: ResultStore,
) -> None:
    """Parsed as XML, not searched for a substring.

    A figure that renders a broken document would pass a "contains <svg>"
    check; this one has to be a document. The regenerating command is on the
    figure because D9 applies to a published chart exactly as it does to a
    published table.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    charts = security_charts(records, command="python tools/sweep.py reduce x")
    assert sorted(charts) == ["repudiation-curve.svg"]
    svg = charts["repudiation-curve.svg"]
    root = ElementTree.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "python tools/sweep.py reduce x" in svg
    assert "PROVEN" in svg and "measured" in svg


def test_a_chart_without_a_command_says_it_is_not_publishable(
    repudiation_store: ResultStore,
) -> None:
    """Silence about provenance is louder than a warning, so there is a warning."""
    records = list(repudiation_store.read_experiment(REPUDIATION))
    svg = security_charts(records, command="")["repudiation-curve.svg"]
    ElementTree.fromstring(svg)
    assert "not" in svg and "D9" in svg


def test_the_chart_plots_only_the_ladder(repudiation_store: ResultStore) -> None:
    """The controls are not points on this curve and are not drawn on it.

    ``unsym192`` repudiates every time; plotted beside the shipped protocol's
    rungs it would read as a measurement of the shipped protocol.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    only_control = [r for r in records if r.cell == "unsym192"]
    assert only_control
    assert security_charts(only_control, command="x") == {}


# --------------------------------------------------------------------------- #
# 9. Registration and the end-to-end reduction                                 #
# --------------------------------------------------------------------------- #


def test_the_family_is_registered_under_prefixed_scenario_names() -> None:
    """A shared registry means a collision is silent unless somebody refuses one."""
    for name, function in SECURITY_SCENARIOS.items():
        assert name.startswith("security-")
        assert SCENARIOS[name] is function
    assert REPUDIATION in EXPERIMENTS and FORGERY in EXPERIMENTS
    register()  # idempotent
    assert SCENARIOS["security-tilt"] is SECURITY_SCENARIOS["security-tilt"]
    with pytest.raises(RuntimeError, match="already registered"):
        register(scenarios={"security-tilt": len}, experiments={})


def test_reduce_produces_this_family_s_tables_with_the_command_attached(
    tmp_path: Path,
) -> None:
    """``tools/sweep.py reduce`` regenerates the published tables from disk.

    The three standard tables plus this family's own, each stamped with the
    command that produced it -- D9's requirement that the command be printed
    next to the table.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment(REPUDIATION),
        store,
        trials=2,
        cells=["l24"],
        workers=1,
        in_process=True,
        quiet=True,
    )
    command = f"python tools/sweep.py reduce {REPUDIATION}"
    tables = reduce_experiment(store, REPUDIATION, command=command)
    slugs = [table.slug for table in tables]
    assert slugs == [
        "outcomes",
        "detection",
        "timing",
        "repudiation-curve",
        "security-floors",
        "security-gap",
    ]
    for table in tables:
        assert table.command == command
        assert f"Regenerate: `{command}`" in table.to_markdown()


def test_the_reduction_is_a_pure_function_of_what_is_on_disk(
    tmp_path: Path,
) -> None:
    """Reduced twice, byte-identical: a table nobody can redraw is not evidence."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment(FORGERY),
        store,
        trials=2,
        cells=["eve15"],
        workers=1,
        in_process=True,
        quiet=True,
    )
    first = [t.to_markdown() for t in reduce_experiment(store, FORGERY, command="c")]
    second = [t.to_markdown() for t in reduce_experiment(store, FORGERY, command="c")]
    assert first == second


def test_a_cell_that_has_left_the_registry_still_appears(tmp_path: Path) -> None:
    """Ordering by the registry must not become filtering by it.

    A record whose cell was renamed after the sweep ran still has to be
    reducible; the column that needed the cell's tilt strength says so instead
    of guessing one.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment(REPUDIATION),
        store,
        trials=2,
        cells=["l24"],
        workers=1,
        in_process=True,
        quiet=True,
    )
    records = list(store.read_experiment(REPUDIATION))
    stranded = [
        TrialRecord.from_dict({**record.to_dict(), "cell": "gone"})
        for record in records
    ]
    table = repudiation_curve_table(stranded, command="c")
    assert table.rows[0][0] == "gone"
    assert "unknown" in str(table.rows[0][12])


def test_the_exact_column_is_blank_on_rows_that_ran_another_family(
    repudiation_store: ResultStore,
) -> None:
    """A closed form on a row it does not describe reads as a contradiction.

    ``repudiation_probability`` is the exact probability for a signer who tilts
    **both** deliveries independently against the **symmetrised** protocol. The
    ``unsym*`` rows run neither, and printing the number there put ``2.3e-09``
    next to a measured ``8/8`` -- arithmetically true of a different experiment
    and false of this one. Rows that do run the family still get their number,
    so the column has not simply been emptied.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    table = repudiation_curve_table(records, command="test")
    exact = table.columns.index("exact in-model P (closed form)")

    control = next(r for r in table.rows if r[0] == "unsym192")
    assert str(control[exact]).startswith("n/a")
    assert control[3] == "no"  # symmetrised

    rung = next(r for r in table.rows if r[0] == "l24")
    assert float(rung[exact]) == pytest.approx(
        repudiation_probability(
            ProtocolParams(key_length=24), mismatch_probability=0.085
        ),
        rel=1e-3
    , abs=0)


def test_the_demo_scale_note_quotes_the_longest_key_that_measured_zero(
    repudiation_store: ResultStore,
) -> None:
    """The widest gap between what a sample can see and where the claim lives.

    Quoting the first zero row instead of the last would understate the point
    by whatever the ladder happens to be ordered by.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    table = repudiation_curve_table(records, command="test")
    zeros = [
        row
        for row in table.rows
        if str(row[8]).startswith("0/") and not str(row[12]).startswith("n/a")
    ]
    notes = [n for n in table.notes if "DEMO-SCALE" in n]
    assert bool(zeros) == bool(notes), (
        "the note claiming a rung measured zero must appear exactly when one "
        "did"
    )
    if zeros:
        longest = max(zeros, key=lambda row: int(row[1]))
        assert f"the {longest[0]} row" in notes[0]


def test_the_demo_scale_note_picks_the_longest_key_deterministically() -> None:
    """The selection logic, on rows chosen rather than sampled.

    The integration test above can only check the note against whatever the
    sweep happened to produce; this hands the builder three zero rows and one
    that is not comparable, and asserts it quotes the longest key of the three
    that are.
    """
    def row(cell: str, key_length: int, measured: str, exact: str):
        return (
            cell, key_length, COUNTS_BEFORE_FORWARDING, "yes", "0.040", 8, 8,
            0, measured, 0, 0, "1.0", exact, "9.0e-01", "yes",
        )

    notes = _repudiation_notes(
        [
            row("l96", 96, "0/8 = 0.0000 [0.0000, 0.4534]", "6.6e-02"),
            row("l768", 768, "0/8 = 0.0000 [0.0000, 0.4534]", "5.8e-04"),
            row("l192", 192, "1/8 = 0.1250 [0.0148, 0.5752]", "3.0e-02"),
            # Longest key of all, but its column does not apply, so it is not
            # a rung of this curve and the note must not quote it.
            row("unsym9999", 9999, "0/8 = 0.0000 [0.0000, 0.4534]", "n/a: ..."),
        ]
    )
    note = next(n for n in notes if "DEMO-SCALE" in n)
    assert "the l768 row" in note
    assert "unsym9999" not in note


def test_no_demo_scale_note_when_no_rung_measured_zero() -> None:
    """A caveat about a zero row must not appear on a table without one."""
    notes = _repudiation_notes(
        [
            (
                "l24", 24, COUNTS_BEFORE_FORWARDING, "yes", "0.085", 8, 8, 0,
                "3/8 = 0.3750 [0.1008, 0.7625]", 0, 6, "4.1", "2.5e-01",
                "9.995e-01", "no",
            )
        ]
    )
    assert not any("DEMO-SCALE" in note for note in notes)


def test_the_chart_geometry_stays_on_the_canvas_and_falls_with_key_length(
    repudiation_store: ResultStore,
) -> None:
    """The figure is checked by its coordinates, not by its markup.

    A chart whose series ran off the canvas, or whose exact curve rose with key
    length, would still be a well-formed SVG containing every string a
    substring test looks for. So this parses the two polylines and asserts what
    a reader would see: every point inside the frame, and the exact
    probability falling monotonically as ``L`` grows.
    """
    records = list(repudiation_store.read_experiment(REPUDIATION))
    svg = security_charts(records, command="c")["repudiation-curve.svg"]
    root = ElementTree.fromstring(svg)
    width = float(root.attrib["width"])
    height = float(root.attrib["height"])

    polylines = [
        [
            tuple(float(value) for value in pair.split(","))
            for pair in element.attrib["points"].split()
        ]
        for element in root
        if element.tag.endswith("polyline")
    ]
    assert len(polylines) == 2, "expected the proven and the exact series"
    for series in polylines:
        assert len(series) >= 2
        for x, y in series:
            assert 0.0 <= x <= width and 0.0 <= y <= height

    exact_series = min(polylines, key=lambda s: s[0][1])
    ys = [y for _x, y in exact_series]
    assert ys == sorted(ys), (
        "the exact probability does not fall monotonically down the ladder, so "
        "the curve is drawn against the wrong key lengths"
    )
    assert all(x1 < x2 for (x1, _), (x2, _) in zip(exact_series, exact_series[1:]))


def test_the_dominance_note_reproduces_the_published_crossover(
    repudiation_store: ResultStore,
) -> None:
    """Constraint 9's number, checked against the one the project already quotes.

    At ``DEFAULT_PARAMS``, ``eps = 1e-9`` and Bob's own cut the crossover is
    ``0.012119`` -- below the design noise level ``2 s_a = 0.03125``, which is
    why the mismatch detector adds nothing over Bob's cut on a link as noisy as
    the scheme tolerates. Reproducing that here says the call this family makes
    is the same call, so the numbers it prints for short keys mean what the
    published one means.
    """
    assert dominance_noise_level(
        38400, DEFAULT_PARAMS.s_a, eps=1e-9
    ) == pytest.approx(0.012119, abs=1e-6)
    assert 2 * DEFAULT_PARAMS.s_a == 0.03125

    records = list(repudiation_store.read_experiment(REPUDIATION))
    table = repudiation_curve_table(records, command="test")
    note = next(n for n in table.notes if "DOMINANCE" in n)
    counts = [
        int(v)
        for record in records
        for v in record.transcript_summary["matched"].values()
        if int(v) > 0
    ]
    params = ProtocolParams.from_dict(records[0].params)
    for count in (min(counts), max(counts)):
        expected = dominance_noise_level(count, params.s_v, eps=records[0].eps)
        assert f"{expected:.6f}" in note
    assert f"|M_R| from {min(counts)} to {max(counts)}" in note


def test_the_gap_table_recomputes_both_bounds_from_the_parameters() -> None:
    """Every cell of the gap table, against the library's own closed forms.

    The table is entirely analytic, so there is no sampling noise to hide
    behind: each row's two bounds are recomputed here by calling the protocol's
    own functions on the same parameter set, and the two must agree to the
    printing's precision.
    """
    table = gap_table([])
    for row in table.rows:
        knob, s_a, s_v = row[0], float(row[1]), float(row[2])
        params = DEFAULT_PARAMS.with_changes(s_a=s_a, s_v=s_v)
        assert float(row[3]) == pytest.approx(params.gap, abs=1e-6)
        assert float(row[4]) == pytest.approx(
            enforced_repudiation_bound(params), rel=1e-3
        , abs=0)
        if recipient_forgery_bound_log10(params) > -300.0:
            assert float(row[5]) == pytest.approx(
                recipient_forgery_bound(params, method="kl"), rel=1e-3
            , abs=0)
        else:
            assert row[5].startswith("10^-")
        # Both columns are rounded for printing, so the tolerance is the
        # coarser of the two roundings and not the arithmetic's.
        assert float(row[6]) == pytest.approx(2.0 * s_a, abs=1e-5)
        assert knob in ("s_a", "s_v")


def test_the_gap_table_shows_the_price_of_widening_the_gap() -> None:
    """Both bounds move, in opposite directions, and the table says so.

    The whole point of the table: pushing ``s_v`` up improves the repudiation
    bound monotonically and degrades the forgery bound monotonically, and the
    shipped cut sits where both are still small. A table that showed only the
    repudiation column would make the widest gap look like the best choice.
    """
    rows = [row for row in gap_table([]).rows if row[0] == "s_v"]
    cuts = [float(row[2]) for row in rows]
    assert cuts == sorted(cuts)

    repudiation = [enforced_bound_log10(DEFAULT_PARAMS.with_changes(s_v=c)) for c in cuts]
    forgery = [
        recipient_forgery_bound_log10(DEFAULT_PARAMS.with_changes(s_v=c))
        for c in cuts
    ]
    assert repudiation == sorted(repudiation, reverse=True), (
        "the repudiation bound does not improve monotonically as the gap widens"
    )
    assert forgery == sorted(forgery), (
        "the forgery bound does not degrade monotonically as s_v climbs "
        "towards the forger floor, so the table's whole tension is missing"
    )
    # The shipped cut is not an endpoint: both neighbours are worse in one of
    # the two columns, which is what "three quarters of the floor" means.
    shipped = cuts.index(DEFAULT_PARAMS.s_v)
    assert 0 < shipped < len(cuts) - 1
    assert forgery[shipped + 1] > forgery[shipped]
    assert repudiation[shipped - 1] > repudiation[shipped]


def test_the_gap_ladder_stops_below_the_forger_floor() -> None:
    """The parameter set refuses a cut at or above 1/12, so the ladder must too.

    A rung above the floor would not merely be a worse choice; it would be a
    parameter set with no forgery guarantee at all, and ProtocolParams declines
    to build one.
    """
    for cut in VERIFIER_CUTS:
        assert cut < DEFAULT_PARAMS.forger_floor
        assert not DEFAULT_PARAMS.with_changes(s_v=cut).is_forgeable
    with pytest.raises(ValueError, match="strictly below the forger floor"):
        DEFAULT_PARAMS.with_changes(s_v=DEFAULT_PARAMS.forger_floor)


def test_every_cell_carries_every_option_its_scenario_demands() -> None:
    """No cell relies on a default, because this family has none.

    ``_require`` raises for a missing option rather than defaulting it, so a
    cell that omitted one would fail on its first trial -- six hours into a
    sweep, if the option were only needed by a late cell. This checks the
    registry instead, cell by cell, against what each scenario actually asks
    for.
    """
    demanded = {
        "security-tilt": ("strength", "symmetrised", "count_exchange_timing"),
        "security-outside-forgery": ("count_exchange_timing",),
        "security-recipient-forgery": ("count_exchange_timing",),
    }
    for name in (REPUDIATION, FORGERY):
        for cell in experiment(name).cells:
            assert cell.scenario in demanded, cell.scenario
            for option in demanded[cell.scenario]:
                assert option in cell.scenario_options, (
                    f"{name}/{cell.name} omits {option!r}, which its scenario "
                    f"refuses to default"
                )
            timing = cell.scenario_options["count_exchange_timing"]
            assert timing in (COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING)
            assert cell.params.check_fraction == 0.0, (
                "this family measures signing statistics, so a check round is "
                "a position spent on a question it does not ask"
            )


def test_the_family_registers_its_own_probe_options() -> None:
    """The generic contract test can construct all three scenarios.

    A scenario that refuses a missing option cannot be exercised generically
    unless somebody says how to build one, and a scenario nobody can construct
    is a scenario nobody has checked. The probe options live beside the
    scenarios they describe rather than in the shared registry, and
    ``register`` copies them across.
    """
    for name, options in SECURITY_PROBE_OPTIONS.items():
        assert name in SECURITY_SCENARIOS
        assert SCENARIO_PROBE_OPTIONS[name] == options
        # Building the cell is the check that would fail if an option were
        # missing or misspelled.
        probe = Cell(
            name="probe",
            params=ProtocolParams(key_length=48),
            scenario=name,
            scenario_options=options,
        )
        transcript, truth = SCENARIOS[name](
            probe, trial_seeds("probe", "probe", 0)
        )
        assert transcript.is_complete or transcript.aborted
        assert truth.hypothesis
