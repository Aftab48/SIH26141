"""Tests for the count-starvation adversary.

Three things are pinned here and they are different kinds of claim.

*The mechanism.* A starving declaration denies the counterpart a verdict, the
denial is recorded as an abort and never as a rejection, and it is one-sided:
the starver still scores his own log. Those are exact statements about single
runs and are asserted.

*The arithmetic of the headroom.* :func:`~sih141.attacks.starvation.denial_headroom`
is the boundary between "denies" and "does not", and it is checked against the
protocol's own :func:`~sih141.protocol.verify.verify` at the boundary rather
than against a restatement of the formula -- a test that re-derives the rule it
is testing proves nothing.

*The threat model.* The adversary is one recipient. It must not edit the
counterpart's count, the floors or the declaration digest, and it must own its
randomness (D6, via :func:`~sih141.attacks.isolation.assert_attack_isolated`).

Key lengths are chosen for speed: ``L = 600`` where both floors are
non-degenerate, ``L = 192`` where they are not. Neither is a security claim --
below ``L = 140`` the floors carry none at all, and even at ``L = 600`` the
statistics here are about a *deterministic* denial, so the trial counts are
small on purpose. The measured rates that Phase 5 quotes come from
:func:`~sih141.attacks.starvation.measure_starvation` runs at a scale this suite
does not pay for.
"""

from __future__ import annotations

import numpy as np
import pytest

from sih141.attacks.isolation import assert_attack_isolated
from sih141.attacks.starvation import (
    CountStarver,
    StarvationDecision,
    StarvationMeasurement,
    StarvationMode,
    declaration_z_score,
    declared_versus_scored,
    denial_headroom,
    least_implausible_z,
    measure_starvation,
    pooled_branch_requirement,
    probe_messages,
    starvation_probe,
    wilson_interval,
)
from sih141.protocol.params import DEMO_PARAMS, Party, ProtocolParams
from sih141.protocol.session import QDSSession
from sih141.protocol.tally import (
    MatchedCountMessage,
    exchange_matched_counts,
)
from sih141.protocol.verify import (
    AbortReason,
    MatchedSetTooSmall,
    minimum_matched_count,
    minimum_pooled_matched_count,
    verify,
)

L600 = ProtocolParams(key_length=600)


def _run(params, *, session_seed, starver=None, message_bit=0):
    """Run one session, honest or starved, and return its transcript."""
    session = QDSSession(
        params,
        rng=np.random.default_rng(session_seed),
        count_exchange=exchange_matched_counts if starver is None else starver,
    )
    return session.run(message_bit)


# --------------------------------------------------------------------------- #
# D6: the adversary owns its randomness
# --------------------------------------------------------------------------- #


def test_adversary_is_isolated_from_the_session():
    """The shipped default passes both halves of the D6 check."""
    report = assert_attack_isolated(CountStarver, starvation_probe())
    assert report.isolated
    # Structural, not merely observed: the constructor has no way to take it.
    assert not report.session_seed_offered


def test_isolation_holds_for_the_selective_policy_too():
    """The selectivity coin is the adversary's own, not the session's."""

    def build(*, rng):
        return CountStarver(rng=rng, denial_probability=0.5, jitter=0)

    report = assert_attack_isolated(
        build, starvation_probe(), name="SelectiveCountStarver"
    )
    assert report.isolated
    assert report.distinct_decisions > 1


def test_two_starvers_on_one_generator_seed_agree():
    """Determinism (D3): the adversary's own seed fixes its whole trace."""
    frozen = probe_messages()
    first = CountStarver(rng=np.random.default_rng(5))
    second = CountStarver(rng=np.random.default_rng(5))
    assert [first(frozen, L600).charlie_count for _ in range(12)] == [
        second(frozen, L600).charlie_count for _ in range(12)
    ]


def test_starver_refuses_a_generator_it_was_not_given():
    """D6 is a constructor requirement, and the message says so."""
    with pytest.raises(TypeError, match="D6"):
        CountStarver(rng=12345)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The headroom, checked against verify() rather than against its own formula
# --------------------------------------------------------------------------- #


def _verdict_reached(own_count, counterpart_count, params):
    """Return whether verify() would reach a verdict on these two counts.

    The answer comes from the protocol's own rule, applied through the public
    API only: a synthetic record whose matched set against a synthetic
    declaration has exactly ``own_count`` positions, and a counterpart count
    delivered the way Phase C' delivers one. A test that re-derived the floor
    arithmetic here would be checking
    :func:`~sih141.attacks.starvation.denial_headroom` against a copy of
    itself.
    """
    from sih141.protocol.keys import KeyElement, PrivateKey
    from sih141.protocol.records import RecipientRecord
    from sih141.protocol.signature import sign
    from sih141.protocol.tally import matched_count_message

    length = params.key_length
    declared = PrivateKey(0, tuple(KeyElement("X", 1) for _ in range(length)))
    signature = sign(0, declared, params)
    # The first `own_count` positions match the declared basis; the rest do not.
    bases = ["X"] * own_count + ["Y"] * (length - own_count)
    record = RecipientRecord.from_measurements("Bob", 0, bases, [1] * length)
    own_message = matched_count_message(signature, record, params)
    assert own_message.matched_count == own_count
    counterpart_message = MatchedCountMessage(
        Party.CHARLIE,
        0,
        counterpart_count,
        length,
        own_message.declaration_digest,
    )
    pooled = exchange_matched_counts(
        {Party.BOB: own_message, Party.CHARLIE: counterpart_message}, params
    )
    try:
        verify(
            signature,
            record,
            params,
            counterpart_matched=pooled.counterpart_of(Party.BOB),
        )
    except MatchedSetTooSmall:
        return False
    return True


@pytest.mark.parametrize("own", [200, 180, 160, 145, 140, 100])
def test_headroom_is_exactly_the_boundary_verify_applies(own):
    """At the headroom the run is denied; one above it, a verdict is reached.

    ``own`` is the *victim's* count, which is what the pooled branch of the
    headroom is measured against, so the sweep crosses from the branch that
    ignores him to the branch that does not.
    """
    headroom = denial_headroom(own, L600)
    assert not _verdict_reached(own, headroom, L600)
    assert _verdict_reached(own, headroom + 1, L600)


def test_headroom_takes_the_larger_of_the_two_branches():
    """A counterpart starved of his own evidence widens the window."""
    m_min = minimum_matched_count(L600)
    M_min = minimum_pooled_matched_count(L600)
    assert denial_headroom(200, L600) == m_min - 1
    low = M_min - m_min - 1        # counterpart below M_min - m_min
    assert denial_headroom(low, L600) == M_min - low - 1
    assert denial_headroom(low, L600) > m_min - 1


def test_pooled_branch_needs_a_counterpart_the_starver_cannot_arrange():
    """The only route to a declaration above m_min is rare and not chosen."""
    threshold, probability = pooled_branch_requirement(L600)
    assert threshold == minimum_pooled_matched_count(
        L600
    ) - minimum_matched_count(L600)
    assert 0.0 < probability < 1e-5
    # And it is exactly the condition under which the branch is the larger one.
    assert denial_headroom(threshold, L600) == minimum_matched_count(L600) - 1
    assert denial_headroom(threshold - 1, L600) > minimum_matched_count(
        L600
    ) - 1


def test_headroom_degenerates_at_demo_scale():
    """Below L = 140 both floors degenerate and only a zero denies."""
    assert minimum_matched_count(DEMO_PARAMS) == 1
    assert denial_headroom(64, DEMO_PARAMS) == 0


def test_headroom_rejects_an_impossible_counterpart():
    with pytest.raises(ValueError, match="cannot exceed key_length"):
        denial_headroom(601, L600)


# --------------------------------------------------------------------------- #
# The mechanism, on real sessions
# --------------------------------------------------------------------------- #


def test_starving_charlie_denies_bob_a_verdict():
    """The core claim, at a key length where both floors are live."""
    starver = CountStarver(rng=np.random.default_rng(2026))
    transcript = _run(L600, session_seed=7, starver=starver)
    assert not transcript.is_complete
    assert not transcript.transferable
    assert [abort.party for abort in transcript.aborts] == [Party.BOB]


def test_the_denial_is_an_abort_and_never_a_rejection():
    """A denied run must not enter any statistic as a rejection."""
    starver = CountStarver(rng=np.random.default_rng(3))
    transcript = _run(L600, session_seed=11, starver=starver)
    assert transcript.aborts
    assert all(
        abort.reason
        in (
            AbortReason.POOLED_BELOW_FLOOR,
            AbortReason.COUNTERPART_BELOW_FLOOR,
        )
        for abort in transcript.aborts
    )
    # No rejection anywhere: every verdict reached was an acceptance.
    assert all(result.accepted for result in transcript.results)


def test_the_denial_is_one_sided_and_the_starver_still_scores():
    """Charlie denies Bob and reaches his own verdict on his own log."""
    starver = CountStarver(rng=np.random.default_rng(2026))
    transcript = _run(L600, session_seed=7, starver=starver)
    scoring = [result.party for result in transcript.results]
    assert scoring == [Party.CHARLIE]
    declared, scored = declared_versus_scored(transcript, Party.CHARLIE)
    assert declared < minimum_matched_count(L600) <= scored


def test_starving_bob_denies_charlie():
    """The attack is symmetric in the two verifiers."""
    starver = CountStarver(rng=np.random.default_rng(4), party=Party.BOB)
    transcript = _run(L600, session_seed=13, starver=starver)
    assert not transcript.is_complete
    assert [abort.party for abort in transcript.aborts] == [Party.CHARLIE]
    assert [result.party for result in transcript.results] == [Party.BOB]


def test_zero_mode_reproduces_the_audit_observation_at_demo_scale():
    """The variant the Phase 2 audit measured, at the length it measured it."""
    starver = CountStarver(
        rng=np.random.default_rng(9), mode=StarvationMode.ZERO
    )
    arm = measure_starvation(
        DEMO_PARAMS, 12, label="zero", starver=starver, session_seed_start=800
    )
    assert arm.denied == arm.trials
    assert arm.complete == 0
    assert set(arm.declared_counts) == {0}


def test_honest_control_arm_completes():
    """The same sessions, with the shipped exchange, reach verdicts."""
    arm = measure_starvation(
        DEMO_PARAMS, 12, label="control", starver=None, session_seed_start=800
    )
    assert arm.complete == arm.trials
    assert arm.denied == 0
    assert arm.declared_counts == ()


def test_selective_denial_leaves_untargeted_runs_alone():
    """Bit-selective censorship: bit 1 is denied, bit 0 goes through."""
    starver = CountStarver(rng=np.random.default_rng(17), target_bits=(1,))
    denied_bits = []
    for index, bit in enumerate((0, 1, 0, 1)):
        transcript = _run(
            DEMO_PARAMS, session_seed=900 + index, starver=starver, message_bit=bit
        )
        denied_bits.append((bit, transcript.is_complete))
    assert denied_bits == [(0, True), (1, False), (0, True), (1, False)]
    assert [decision.starved for decision in starver.log] == [
        False,
        True,
        False,
        True,
    ]


def test_probabilistic_selectivity_denies_some_and_not_others():
    """A coin in (0, 1) produces both outcomes from one adversary."""
    starver = CountStarver(
        rng=np.random.default_rng(21), denial_probability=0.5
    )
    arm = measure_starvation(
        DEMO_PARAMS, 24, label="selective", starver=starver,
        session_seed_start=1000,
    )
    assert 0 < arm.starved_exchanges < arm.trials
    assert arm.denied == arm.starved_exchanges
    assert arm.complete == arm.trials - arm.starved_exchanges


def test_measurement_agrees_with_the_adversarys_own_prediction():
    """Every run the adversary predicted it would deny was denied."""
    starver = CountStarver(
        rng=np.random.default_rng(23), denial_probability=0.5
    )
    arm = measure_starvation(
        DEMO_PARAMS, 16, label="prediction", starver=starver,
        session_seed_start=1100,
    )
    predicted = sum(1 for decision in starver.log if decision.denies)
    assert predicted == arm.denied


# --------------------------------------------------------------------------- #
# The threat model: what the adversary must not touch
# --------------------------------------------------------------------------- #


def test_the_counterpart_count_is_passed_through_untouched():
    """A recipient controls his own message and nobody else's."""
    frozen = probe_messages()
    starver = CountStarver(rng=np.random.default_rng(29))
    pooled = starver(frozen, L600)
    assert pooled.bob_count == frozen[Party.BOB].matched_count
    assert pooled.charlie_count < frozen[Party.CHARLIE].matched_count


def test_the_floors_and_the_digest_are_left_alone():
    """Everything a transcript re-derives is left exactly as the honest run has it."""
    frozen = probe_messages()
    starver = CountStarver(rng=np.random.default_rng(31))
    pooled = starver(frozen, L600)
    assert pooled.minimum_matched == minimum_matched_count(L600)
    assert pooled.minimum_pooled == minimum_pooled_matched_count(L600)
    assert pooled.declaration_digest == frozen[Party.BOB].declaration_digest
    assert pooled.key_length == L600.key_length


def test_the_starver_never_over_reports():
    """Under-reporting only: inflation is a different attack and not made here."""
    starver = CountStarver(rng=np.random.default_rng(37))
    frozen = probe_messages(counts=(198, 40))     # a genuinely thin Charlie
    pooled = starver(frozen, L600)
    assert pooled.charlie_count <= 40
    assert all(
        decision.declared_count <= decision.true_count
        for decision in starver.log
    )


def test_alice_cannot_be_the_starver():
    with pytest.raises(ValueError, match="not in Phase C'"):
        CountStarver(rng=np.random.default_rng(0), party=Party.ALICE)


def test_a_starving_run_still_produces_a_serialisable_transcript():
    """A denied run has to survive the Phase 4/5 hand-off boundary."""
    starver = CountStarver(rng=np.random.default_rng(41))
    transcript = _run(DEMO_PARAMS, session_seed=1200, starver=starver)
    restored = type(transcript).from_json(transcript.to_json())
    assert restored == transcript
    assert restored.pooled is not None
    assert restored.pooled.charlie_count == 0


# --------------------------------------------------------------------------- #
# The detector signals Phase 4 will consume
# --------------------------------------------------------------------------- #


def test_every_denying_declaration_is_far_into_the_honest_lower_tail():
    """The Phase 4 signal, stated as a property of the whole denying region."""
    for counterpart in (200, 180, 160, 145):
        headroom = denial_headroom(counterpart, L600)
        assert declaration_z_score(headroom, L600) < -4.7
    # And the quietest of them all is the L-independent constant.
    assert least_implausible_z(L600) == pytest.approx(-11.6047, abs=1e-4)
    assert least_implausible_z(ProtocolParams(key_length=115200)) == (
        pytest.approx(-11.5375, abs=1e-4)
    )


def test_the_z_score_is_computable_from_the_transcript_alone():
    """Nothing but the published transcript is needed for the signal."""
    starver = CountStarver(rng=np.random.default_rng(43))
    transcript = _run(L600, session_seed=17, starver=starver)
    assert transcript.counts_exchanged
    declared = transcript.pooled.charlie_count
    assert declaration_z_score(declared, transcript.params) < -11.0


def test_the_within_run_contradiction_is_visible():
    """Declared count and scored count are both in one transcript, and disagree."""
    starver = CountStarver(rng=np.random.default_rng(47))
    transcript = _run(L600, session_seed=19, starver=starver)
    declared, scored = declared_versus_scored(transcript, Party.CHARLIE)
    assert scored - declared > 100
    # Bob reached no verdict, so no true count of his was published.
    assert declared_versus_scored(transcript, Party.BOB) is None


def test_declared_versus_scored_is_none_without_an_exchange():
    """A pre-pooled run publishes no counts, so the signal is unavailable."""
    from sih141.protocol.tally import no_count_exchange

    session = QDSSession(
        DEMO_PARAMS,
        rng=np.random.default_rng(1300),
        count_exchange=no_count_exchange,
    )
    transcript = session.run(0)
    assert not transcript.counts_exchanged
    assert declared_versus_scored(transcript, Party.CHARLIE) is None


# --------------------------------------------------------------------------- #
# Small pieces
# --------------------------------------------------------------------------- #


def test_wilson_interval_brackets_the_rate():
    for successes, trials in ((0, 20), (7, 20), (20, 20)):
        low, high = wilson_interval(successes, trials)
        assert 0.0 <= low <= successes / trials <= high <= 1.0


def test_wilson_interval_refuses_an_empty_denominator():
    with pytest.raises(ValueError, match="denominator"):
        wilson_interval(0, 0)


def test_decision_record_reports_its_own_prediction():
    decision = StarvationDecision(
        party=Party.CHARLIE,
        message_bit=0,
        true_count=203,
        declared_count=66,
        counterpart_count=198,
        headroom=66,
        starved=True,
    )
    assert decision.denies
    assert decision.understatement == 137


def test_measurement_summary_reports_numerator_and_denominator():
    arm = StarvationMeasurement(
        "zero", 192, 20, 20, 0, 0, 20, 20, (0,) * 20, (64,) * 20, ()
    )
    line = arm.summary()
    assert "20/20" in line and "complete 0/20" in line


def test_probe_messages_are_one_declaration():
    messages = probe_messages()
    assert (
        messages[Party.BOB].declaration_digest
        == messages[Party.CHARLIE].declaration_digest
    )
    # And the honest exchange accepts them, so the attack arm and the control
    # arm differ in one integer and nothing else.
    pooled = exchange_matched_counts(messages, L600)
    assert pooled.meets_every_floor


def test_measure_starvation_refuses_a_non_starver():
    with pytest.raises(TypeError, match="CountStarver or None"):
        measure_starvation(
            DEMO_PARAMS, 1, label="bad", starver=object()  # type: ignore[arg-type]
        )


def test_message_replacement_keeps_the_message_well_formed():
    """The doctored message is still a MatchedCountMessage, so it is validated."""
    frozen = probe_messages()
    starver = CountStarver(rng=np.random.default_rng(53))
    starver(frozen, L600)
    decision = starver.log[0]
    rebuilt = MatchedCountMessage(
        Party.CHARLIE,
        decision.message_bit,
        decision.declared_count,
        L600.key_length,
        frozen[Party.CHARLIE].declaration_digest,
    )
    assert rebuilt.matched_count == decision.declared_count
