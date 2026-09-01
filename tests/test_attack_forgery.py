"""Tests for :mod:`sih141.attacks.forgery`.

Four things are pinned here, in this order of importance.

1. **D6.** Both adversaries are put through
   :func:`~sih141.attacks.isolation.check_attack_isolation`. The outside forger
   passes both halves; the recipient forger passes check (a) outright and check
   (b) only in his deliberately degraded form, because the optimal one is a
   deterministic reading of his own view -- which is asserted here as a
   *property*, so that a future edit that quietly makes him random is caught.
2. **The threat model.** He declares his own raw log and nothing else; he is
   refused a view that is not Bob's; he is mounted on the forwarding hop, and
   the run is recorded as a forgery rather than as a repudiation.
3. **The rates.** Measured, with intervals, against the analytic predictions in
   :mod:`sih141.protocol.analysis`. Trial counts are chosen so the statistics
   are meaningful and the suite still finishes; the key lengths are small and
   carry no security claim, which is what
   :ref:`sih141.attacks.forgery <forgery-scaling>` is about.
4. **The Phase A' demonstration.** ``1/12`` with the exchange, ``1/3`` without,
   from the same forger and the same code path.

Every measurement here is seeded twice over -- once for the adversary and once
for the harness, never the same generator -- so a failure reproduces exactly.
"""

from __future__ import annotations

import math
from functools import partial

import numpy as np
import pytest

from sih141.attacks.forgery import (
    OUTSIDE_FORGER_MISMATCH_RATE,
    RECIPIENT_FORGER_MISMATCH_RATE,
    UNSYMMETRISED_FORGER_MISMATCH_RATE,
    ForgeryMeasurement,
    OutsideForger,
    RecipientForger,
    forwarder_probe,
    measure_outside_forgery,
    measure_recipient_forgery,
    wilson_interval,
)
from sih141.attacks.isolation import (
    assert_attack_isolated,
    check_attack_isolation,
    signer_probe,
    signer_scenario,
)
from sih141.protocol.analysis import (
    forgery_probability,
    recipient_forgery_probability,
)
from sih141.protocol.keys import KeyElement, PrivateKey, generate_key_pair
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.records import RecipientView
from sih141.protocol.session import NO_RECIPIENT_LOGS, QDSSession
from sih141.protocol.signature import Signature
from sih141.protocol.tally import no_count_exchange

# Small on purpose. Below L = 140 both matched-count floors degenerate, so
# nothing measured here is a security claim; what is measured is a per-position
# rate, and that is what scales (:ref:`forgery-scaling`).
STATISTICS_LENGTH = 48
OUTSIDE_LENGTH = 30
QUICK_LENGTH = 24


def params_of(key_length: int) -> ProtocolParams:
    """Return an unchecked parameter set of the given length."""
    return ProtocolParams(key_length=key_length)


def scenario_view() -> RecipientView:
    """Return Bob's frozen view from the shared isolation scenario."""
    return signer_scenario().views[Party.BOB]


def scenario_declaration() -> Signature:
    """Return Alice's genuine declaration for the shared scenario."""
    scenario = signer_scenario()
    return Signature(scenario.message_bit, scenario.keys[scenario.message_bit])


# --------------------------------------------------------------------------- #
# 1. D6
# --------------------------------------------------------------------------- #


def test_the_outside_forger_owns_its_randomness() -> None:
    """Eve passes both halves of the isolation check on the signer seam."""
    report = assert_attack_isolated(OutsideForger, signer_probe())
    assert report.isolated
    assert not report.reads_the_session
    assert report.distinct_decisions == len(report.attack_seeds)
    # She takes no session_seed argument at all, which is the stronger of the
    # two positions the check distinguishes.
    assert not report.session_seed_offered


def test_the_recipient_forger_owns_its_randomness() -> None:
    """A randomised forger passes both halves on the forwarding seam."""
    report = assert_attack_isolated(
        partial(RecipientForger, guess_probability=0.25),
        forwarder_probe(),
        name="RecipientForger",
    )
    assert report.isolated
    assert report.distinct_decisions > 1


def test_the_optimal_recipient_forger_is_deterministic_not_leaky() -> None:
    """The ``1/12`` forger reads nothing of the session and draws nothing.

    Check (b) cannot pass for him, and that is a fact about the adversary
    rather than a defect: declaring his own raw log beats every randomised
    alternative at every position. What *can* be asserted -- and is, because it
    is the half D6 is about -- is that his declaration does not move with the
    session seed.
    """
    report = check_attack_isolation(RecipientForger, forwarder_probe())
    assert not report.reads_the_session
    assert report.offending_session_seeds == ()
    assert report.distinct_decisions == 1
    assert not report.isolated  # by check (b), and only by check (b)


def test_measurement_refuses_one_generator_for_attack_and_session() -> None:
    """Sharing a generator is the D6 defect, and is refused with an explanation."""
    shared = np.random.default_rng(1)
    with pytest.raises(ValueError, match="the same stream"):
        measure_outside_forgery(
            params_of(QUICK_LENGTH), trials=1, rng=shared, session_rng=shared
        )
    with pytest.raises(ValueError, match="symmetrisation coin"):
        measure_recipient_forgery(
            params_of(QUICK_LENGTH), trials=1, rng=shared, session_rng=shared
        )


def test_measurement_refuses_two_generators_built_from_one_seed() -> None:
    """The defect as it actually arrives: one seed constant, used twice.

    Two ``default_rng(1)`` calls are two objects and one stream. The adversary
    can then redraw the session's 32-byte material and rebuild every private
    symmetrisation coin, so a rate measured that way is fiction -- which the
    object-identity test that shipped here could not see.
    """
    with pytest.raises(ValueError, match="the same stream"):
        measure_outside_forgery(
            params_of(QUICK_LENGTH),
            trials=1,
            rng=np.random.default_rng(1),
            session_rng=np.random.default_rng(1),
        )
    with pytest.raises(ValueError, match="the same stream"):
        measure_recipient_forgery(
            params_of(QUICK_LENGTH),
            trials=1,
            rng=np.random.default_rng(1),
            session_rng=np.random.default_rng(1),
        )
    # Advancing one of them does not make it a different stream either.
    used = np.random.default_rng(1)
    _ = used.random(64)
    with pytest.raises(ValueError, match="the same stream"):
        measure_outside_forgery(
            params_of(QUICK_LENGTH),
            trials=1,
            rng=used,
            session_rng=np.random.default_rng(1),
        )


# --------------------------------------------------------------------------- #
# 2. The threat model
# --------------------------------------------------------------------------- #


def test_the_outside_forger_ignores_the_keys_she_is_shown() -> None:
    """Her declaration is a function of her generator and the length alone."""
    params = params_of(12)
    alice = generate_key_pair(params, rng=np.random.default_rng(1))
    other = generate_key_pair(params, rng=np.random.default_rng(2))
    first = OutsideForger(rng=np.random.default_rng(7))(
        0, alice, params, records=NO_RECIPIENT_LOGS
    )
    second = OutsideForger(rng=np.random.default_rng(7))(
        0, other, params, records=NO_RECIPIENT_LOGS
    )
    assert first == second
    assert first.declared_key != alice[0]
    assert len(first.declared_key) == params.key_length


def test_the_outside_forger_ignores_recipient_logs_when_offered_them() -> None:
    """Even a session that over-provisions the signer seam moves her not at all."""
    params = params_of(QUICK_LENGTH)
    session = QDSSession(params, rng=np.random.default_rng(3))
    session.distribute()
    keys = session.signing_keys
    with_logs = OutsideForger(rng=np.random.default_rng(9))(
        0, keys, params, records=session.raw_records
    )
    without = OutsideForger(rng=np.random.default_rng(9))(
        0, keys, params, records=NO_RECIPIENT_LOGS
    )
    assert with_logs == without


def test_the_recipient_forger_declares_his_own_raw_log_verbatim() -> None:
    """The optimal strategy, element for element."""
    view = scenario_view()
    forged = RecipientForger(rng=np.random.default_rng(5))(
        scenario_declaration(), signer_scenario().params, view=view
    )
    assert [
        (element.basis, element.eigenvalue) for element in forged.declared_key
    ] == [(entry.basis, entry.eigenvalue) for entry in view.raw_record.entries]
    assert forged.declared_key != scenario_declaration().declared_key


def test_the_recipient_forger_refuses_a_view_that_is_not_bobs() -> None:
    """Charlie owns no forwarding hop; a view filed there is a wiring error."""
    scenario = signer_scenario()
    charlie_view = scenario.views[Party.CHARLIE]
    with pytest.raises(ValueError, match="forwarding hop is Bob's"):
        RecipientForger(rng=np.random.default_rng(1))(
            scenario_declaration(), scenario.params, view=charlie_view
        )


def test_the_recipient_forger_refuses_a_view_from_the_other_run() -> None:
    """One declaration is scored against one distribution, never the other."""
    scenario = signer_scenario()
    other_bit = 1 - scenario.message_bit
    crossed = RecipientView.for_party(
        Party.BOB,
        other_bit,
        raw_records=scenario.raw_records,
        records=scenario.records,
    )
    with pytest.raises(ValueError, match="share no key"):
        RecipientForger(rng=np.random.default_rng(1))(
            scenario_declaration(), scenario.params, view=crossed
        )


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"signature": object()}, "must be a Signature"),
        ({"params": object()}, "must be a ProtocolParams"),
        ({"view": object()}, "must be a RecipientView"),
    ],
)
def test_the_recipient_forger_refuses_malformed_arguments(
    kwargs: dict[str, object], expected: str
) -> None:
    """Each seam argument is checked, and the message says what belongs there."""
    scenario = signer_scenario()
    call = {
        "signature": scenario_declaration(),
        "params": scenario.params,
        "view": scenario_view(),
    }
    call.update(kwargs)
    forger = RecipientForger(rng=np.random.default_rng(1))
    with pytest.raises(TypeError, match=expected):
        forger(call["signature"], call["params"], view=call["view"])


def test_guess_probability_replaces_positions_and_costs_the_forger() -> None:
    """The knob does what it says, and it is a cost rather than a strategy."""
    scenario = signer_scenario()
    view = scenario_view()
    forger = RecipientForger(rng=np.random.default_rng(4), guess_probability=1.0)
    forged = forger(scenario_declaration(), scenario.params, view=view)
    assert forger.guessed_positions == len(view.raw_record)
    assert forger.calls == 1
    changed = sum(
        (element.basis, element.eigenvalue) != (entry.basis, entry.eigenvalue)
        for element, entry in zip(
            forged.declared_key, view.raw_record.entries, strict=True
        )
    )
    # Every position was redrawn; most land somewhere else, none is guaranteed to.
    assert changed > 0
    untouched = RecipientForger(rng=np.random.default_rng(4))
    untouched(scenario_declaration(), scenario.params, view=view)
    assert untouched.guessed_positions == 0


@pytest.mark.parametrize("bad", [-0.1, 1.5, float("nan")])
def test_guess_probability_is_range_checked(bad: float) -> None:
    """A probability outside ``[0, 1]`` is refused with the reason."""
    with pytest.raises(ValueError, match="probability in"):
        RecipientForger(rng=np.random.default_rng(1), guess_probability=bad)


def test_the_forger_is_recorded_as_a_forgery_and_not_a_repudiation() -> None:
    """Bob accepts Alice's declaration; the transcript says who substituted what.

    The distinction the whole seam choice turns on: "Bob accepted and Charlie
    rejected" names a repudiation only when both scored the *same* declaration.
    """
    session = QDSSession(
        params_of(STATISTICS_LENGTH),
        forwarder=RecipientForger(rng=np.random.default_rng(6)),
        count_exchange=no_count_exchange,
        rng=np.random.default_rng(60),
    )
    transcript = session.run(0)
    assert transcript.bob is not None and transcript.bob.accepted
    assert transcript.forwarding_altered_signature
    assert not transcript.repudiated
    assert transcript.forwarded_signature is not None
    assert transcript.forwarded_signature != transcript.signature


def test_the_signer_route_would_have_bob_reject_his_own_forgery() -> None:
    """Why :class:`RecipientForger` is a forwarder: the wrong route, measured once.

    A declaration built from Bob's log and mounted on the *signer* seam reaches
    Bob as well, and he scores it against the log it came from: his matched
    count inflates and he rejects. One fixed seed is enough -- this is a
    structural claim, not a rate.
    """
    params = params_of(STATISTICS_LENGTH)
    session = QDSSession(
        params,
        signer_sees_recipient_logs=True,
        signer=lambda bit, keys, prm, *, records: Signature(
            bit,
            PrivateKey(
                bit,
                [
                    KeyElement(entry.basis, entry.eigenvalue)
                    for entry in records[bit][Party.BOB].entries
                ],
            ),
        ),
        count_exchange=no_count_exchange,
        rng=np.random.default_rng(61),
    )
    transcript = session.run(0)
    assert transcript.bob is not None
    assert not transcript.bob.accepted
    # Inflated to about 2L/3 rather than the honest L/3: the declaration is
    # built from a recipient's log, so on the half of positions the exchange
    # swapped it names the very basis Bob now holds.
    assert transcript.bob.matched_count > params.key_length / 2


# --------------------------------------------------------------------------- #
# 3. The rates
# --------------------------------------------------------------------------- #


def test_outside_forger_matches_the_analytic_prediction() -> None:
    """Eve: a fair coin on a third of the positions, and the exact sum."""
    params = params_of(OUTSIDE_LENGTH)
    blocks = measure_outside_forgery(
        params,
        trials=100,
        rng=np.random.default_rng(101),
        session_rng=np.random.default_rng(102),
    )
    assert sorted(blocks) == list(VERIFIERS)
    for party, block in blocks.items():
        assert block.trials == 100
        assert block.no_verdict == 0
        assert block.predicted == forgery_probability(params, party=party)
        assert block.agrees_with_prediction
        # The per-position statistics, which are what carry to L = 115200.
        low, high = block.mismatch_interval
        assert low <= OUTSIDE_FORGER_MISMATCH_RATE <= high
        assert block.scored_fraction_within(params.match_probability, 0.03)


def test_recipient_forger_reaches_the_one_twelfth_floor() -> None:
    """Bob, symmetrised: two thirds of the positions scored, ``1/12`` wrong."""
    params = params_of(STATISTICS_LENGTH)
    block = measure_recipient_forgery(
        params,
        trials=60,
        rng=np.random.default_rng(111),
        session_rng=np.random.default_rng(112),
    )
    assert block.party is Party.CHARLIE
    assert block.symmetrised
    assert block.no_verdict == 0
    assert block.bob_accepted == block.trials
    low, high = block.mismatch_interval
    assert low <= RECIPIENT_FORGER_MISMATCH_RATE <= high
    assert block.scored_fraction_within(params.forger_scored_fraction, 0.03)
    assert block.predicted == recipient_forgery_probability(params)
    assert block.agrees_with_prediction


def test_recipient_forgery_collapses_to_one_third_unsymmetrised() -> None:
    """The demonstration: the same forger, the same code, no exchange.

    ``1/12`` becomes ``1/3`` and two thirds of the positions become one third.
    This is the figure Phase 5 should draw, and the two arms differ in one
    callable and in nothing else.
    """
    params = params_of(STATISTICS_LENGTH)
    stripped = measure_recipient_forgery(
        params,
        trials=60,
        rng=np.random.default_rng(121),
        session_rng=np.random.default_rng(122),
        symmetrised=False,
    )
    assert not stripped.symmetrised
    low, high = stripped.mismatch_interval
    assert low <= UNSYMMETRISED_FORGER_MISMATCH_RATE <= high
    assert stripped.scored_fraction_within(params.match_probability, 0.03)
    assert stripped.predicted == recipient_forgery_probability(
        params, symmetrised=False
    )
    assert stripped.agrees_with_prediction

    symmetrised = measure_recipient_forgery(
        params,
        trials=60,
        rng=np.random.default_rng(111),
        session_rng=np.random.default_rng(112),
    )
    # The whole point, as one comparison: the exchange costs the forger a
    # factor of four in his per-position error rate, and the intervals are
    # nowhere near each other.
    assert symmetrised.mismatch_interval[1] < stripped.mismatch_interval[0]
    assert symmetrised.rate > stripped.rate


def test_the_pooled_rule_denies_transfer_not_detects_the_forgery() -> None:
    """Under Phase C' Charlie reaches no verdict, and it is not a rejection.

    Reported in its own field precisely so that a Phase 4 table cannot read it
    as a detection: he learned that two counts disagree about their provenance,
    and nothing at all about the signature.
    """
    block = measure_recipient_forgery(
        params_of(QUICK_LENGTH),
        trials=6,
        rng=np.random.default_rng(131),
        session_rng=np.random.default_rng(132),
        pooled_counts=True,
    )
    assert block.no_verdict == block.trials
    assert block.accepted == 0
    assert block.rejected == 0
    assert block.bob_accepted == block.trials
    assert math.isnan(block.mismatch_rate)
    # No prediction is attached to a block nothing predicts: quoting the
    # pre-pooled acceptance probability here would print a disagreement at a
    # comparison that was never made.
    assert block.predicted is None
    assert block.predicted_mismatch_rate is None
    assert "nothing was scored" in block.summary()


def test_a_degraded_forger_reports_no_prediction() -> None:
    """No closed form covers a deliberately noisy forger, so none is claimed."""
    block = measure_recipient_forgery(
        params_of(QUICK_LENGTH),
        trials=4,
        rng=np.random.default_rng(141),
        session_rng=np.random.default_rng(142),
        guess_probability=0.5,
    )
    assert block.predicted is None
    assert block.predicted_mismatch_rate is None
    assert not block.agrees_with_prediction
    assert block.mismatch_rate > RECIPIENT_FORGER_MISMATCH_RATE


@pytest.mark.parametrize(
    ("trials", "expected"),
    [(0, "trials must be positive"), (-1, "trials must be non-negative")],
)
def test_measurements_refuse_an_empty_block(trials: int, expected: str) -> None:
    """A block of no runs is the absence of a measurement, not a wide one."""
    with pytest.raises(ValueError, match=expected):
        measure_outside_forgery(
            params_of(QUICK_LENGTH),
            trials=trials,
            rng=np.random.default_rng(1),
            session_rng=np.random.default_rng(2),
        )


def test_measurements_refuse_a_non_parameter_set() -> None:
    """The parameter set is the one argument with no sensible default here."""
    with pytest.raises(TypeError, match="must be a ProtocolParams"):
        measure_recipient_forgery(
            object(),
            trials=1,
            rng=np.random.default_rng(1),
            session_rng=np.random.default_rng(2),
        )


# --------------------------------------------------------------------------- #
# 4. The reporting types
# --------------------------------------------------------------------------- #


def test_wilson_interval_keeps_width_at_the_endpoints() -> None:
    """The reason it is Wilson: ``0/n`` and ``n/n`` still have an interval."""
    low, high = wilson_interval(0, 200)
    assert low == pytest.approx(0.0, abs=1e-12)
    assert 0.0 < high < 0.03
    low, high = wilson_interval(200, 200)
    assert high == pytest.approx(1.0, abs=1e-12)
    assert 0.97 < low < 1.0
    low, high = wilson_interval(100, 200)
    assert low < 0.5 < high


@pytest.mark.parametrize(
    ("successes", "trials", "expected"),
    [
        (1, 0, "trials must be positive"),
        (5, 4, "exceeds trials"),
        (-1, 4, "must be non-negative"),
    ],
)
def test_wilson_interval_refuses_impossible_counts(
    successes: int, trials: int, expected: str
) -> None:
    """Counts that cannot describe a run are refused, with the reason."""
    with pytest.raises(ValueError, match=expected):
        wilson_interval(successes, trials)


def test_wilson_interval_refuses_a_float_count() -> None:
    """A float count is usually a rate that has already been divided once."""
    with pytest.raises(TypeError, match="must be an int"):
        wilson_interval(1.0, 10)


def test_measurement_refuses_inconsistent_counts() -> None:
    """A run ends in exactly one of accepted, rejected, no-verdict."""
    with pytest.raises(ValueError, match="exceeds trials"):
        ForgeryMeasurement(
            "x", Party.BOB, 24, trials=10, accepted=8, no_verdict=5
        )
    with pytest.raises(ValueError, match="counted within the matched set"):
        ForgeryMeasurement(
            "x", Party.BOB, 24, trials=10, accepted=1,
            scored_positions=3, mismatches=4,
        )


def test_measurement_refuses_alice() -> None:
    """A forgery measurement is about a verifier's decision."""
    with pytest.raises(ValueError, match="Alice reaches none"):
        ForgeryMeasurement("x", Party.ALICE, 24, trials=1, accepted=0)


def test_measurement_refuses_a_party_that_is_not_one() -> None:
    """The label is coerced, and a bad one names the verifiers it could be."""
    with pytest.raises(ValueError, match="names nobody in the protocol"):
        ForgeryMeasurement("x", "Dave", 24, trials=1, accepted=0)
    with pytest.raises(TypeError, match="must be a Party or its label"):
        ForgeryMeasurement("x", 3, 24, trials=1, accepted=0)


def test_measurement_rates_and_summary_are_derived_from_the_counts() -> None:
    """Rates are properties, so two blocks can be pooled by adding counts."""
    block = ForgeryMeasurement(
        label="outside forger",
        party=Party.CHARLIE,
        key_length=30,
        trials=1000,
        accepted=4,
        no_verdict=6,
        scored_positions=10000,
        mismatches=5010,
        predicted=0.004211,
        predicted_mismatch_rate=0.5,
    )
    assert block.rate == pytest.approx(0.004)
    assert block.rejected == 990
    assert block.scored_runs == 994
    assert block.mismatch_rate == pytest.approx(0.501)
    assert block.agrees_with_prediction
    text = block.summary()
    assert "outside forger vs Charlie" in text
    assert "no verdict 6 runs, 990 rejections" in text


def test_measurement_without_a_prediction_agrees_with_nothing() -> None:
    """An absent prediction is not a passed comparison."""
    block = ForgeryMeasurement("x", Party.BOB, 24, trials=10, accepted=1)
    assert block.predicted is None
    assert not block.agrees_with_prediction
    assert math.isnan(block.mismatch_rate)
    assert not block.mismatch_rate_within(0.5, 1.0)


def test_forwarder_probe_refuses_a_non_scenario() -> None:
    """The probe's fixed half must be a frozen scenario, not an arbitrary object."""
    with pytest.raises(TypeError, match="must be a SignerScenario"):
        forwarder_probe(object())
