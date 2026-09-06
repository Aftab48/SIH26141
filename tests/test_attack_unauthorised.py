"""Tests for the three routes to an unauthorised verdict.

Three kinds of claim are pinned here, and they need different kinds of test.

*The mechanism, per run.* A fabricated log clears the matched-count floor and is
scored, the fabricator rejects a genuine declaration, and the owner accepts the
same declaration at a rate of exactly zero. Those are exact statements about
single runs and are asserted directly. The control is not decoration: without it
"the outsider rejected" says nothing, because a run in which everybody rejects
looks the same.

*The arithmetic.* The matched fraction sits on ``1/3`` and the mismatch rate on
``1/2``, and both are tested through
:func:`~sih141.attacks.statistics.agrees_within` at a band computed from the
sampling distribution rather than at a tolerance chosen by eye. The failure mode
these have to catch is a rate wrong by a *factor* -- ``1/3`` where ``1/2``
belongs, which is what scoring unmatched positions would produce -- and a
four-sigma band at these sample sizes catches that with room left over.

*The threat model.* The fabricator draws from his own generator and nothing else
(D3, through :func:`~sih141.attacks.isolation.assert_attack_isolated`), the
harness refuses an adversary seeded from a session seed, and the harness's own
control declaration comes off a third stream so that his log is the first thing
his generator produces.

The U2 holder is tested differently, and less. He has no randomness to isolate
and nothing about him is measured: his verdict is the owner's three arguments
through a pure function, so an equality between the two is a restatement of that
purity rather than an observation, and no count of it is published
(:ref:`u2-leak`). What is pinned here is the interface -- that he reaches a
verdict at all, that the record he presents names its owner, and that
:func:`~sih141.attacks.unauthorised.verdict_digest` compares whole verdicts
rather than accept/reject bits.

``L = 192`` throughout, which is the length
:data:`~sih141.attacks.unauthorised.MEASURED` was taken at. It carries no
security claim: the acceptance probabilities of
:mod:`sih141.protocol.analysis` are exponentials in ``L`` and say nothing at 192.
What it exhibits is a per-position rate, and a per-position rate does not depend
on ``L``. Trial counts are small on purpose; the published table is the
200-trial run recorded on :data:`~sih141.attacks.unauthorised.MEASURED`, and this
suite does not pay for it again.
"""

from __future__ import annotations

import dataclasses

import numpy as np
import pytest

from sih141.attacks.channel import (
    PAULI_AXES,
    collapse_tensor,
    qber_from_tensor,
)
from sih141.attacks.isolation import assert_attack_isolated
from sih141.attacks.statistics import agrees_within
from sih141.attacks.unauthorised import (
    ATTACK_SEED,
    FABRICATED_MATCHED_FRACTION,
    FABRICATED_MISMATCH_RATE,
    MEASURED,
    MEASUREMENT_PARAMS,
    TAPPED_LINK_QBER,
    UnauthorisedFabricator,
    UnauthorisedHolder,
    UnauthorisedMeasurement,
    UnauthorisedTrial,
    _pool,
    fabricator_probe,
    measure_unauthorised,
    run_unauthorised,
    shipped_summary,
    tapped_record_reduction,
    verdict_digest,
)
from sih141.protocol.keys import generate_private_key
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.records import RecipientRecord
from sih141.protocol.session import QDSSession
from sih141.protocol.signature import sign
from sih141.protocol.verify import (
    MatchedSetTooSmall,
    VerificationResult,
    verify,
    verify_or_abort,
)

#: Enough matched positions (about 768 per verifier) to separate ``1/2`` from
#: ``1/3`` at four sigma several times over, and few enough to run in seconds.
ARM_TRIALS = 12


@pytest.fixture(scope="module")
def arms():
    """One measured arm per verifier, shared by every statistical test here."""
    return measure_unauthorised(
        MEASUREMENT_PARAMS,
        trials=ARM_TRIALS,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )


def _honest_round(seed=900_000, message_bit=0):
    """Return ``(session, declaration, scored_params)`` for one honest round."""
    session = QDSSession(
        MEASUREMENT_PARAMS, rng=np.random.default_rng(seed)
    )
    session.distribute()
    return session, session.sign(message_bit), session.scored_params


# --------------------------------------------------------------------------- #
# D3: the fabricator owns its randomness
# --------------------------------------------------------------------------- #


def test_fabricator_is_isolated_from_the_session():
    """Both halves of the D3 check pass, and the seed is never offered."""
    report = assert_attack_isolated(UnauthorisedFabricator, fabricator_probe())
    assert report.isolated
    # Structural rather than merely observed: the constructor has no way to
    # take a session seed, so there is no construction-time channel to close.
    assert not report.session_seed_offered


def test_fabricated_record_is_a_function_of_its_own_seed():
    """One seed, one log; a different seed, a different log."""
    params = ProtocolParams(key_length=48)
    first = UnauthorisedFabricator(rng=np.random.default_rng(11)).fabricate(
        params, message_bit=0
    )
    twin = UnauthorisedFabricator(rng=np.random.default_rng(11)).fabricate(
        params, message_bit=0
    )
    other = UnauthorisedFabricator(rng=np.random.default_rng(12)).fabricate(
        params, message_bit=0
    )
    assert first == twin
    assert first != other


def test_harness_refuses_an_adversary_seeded_from_a_session_seed():
    """One integer used for both roles is one stream read twice (D3)."""
    with pytest.raises(ValueError, match="D3"):
        run_unauthorised(
            MEASUREMENT_PARAMS,
            session_seed=900_000,
            attack_rng=np.random.default_rng(900_000),
        )
    # And the whole seed list is checked before the first session is spent.
    with pytest.raises(ValueError, match="900007"):
        measure_unauthorised(
            MEASUREMENT_PARAMS,
            trials=200,
            attack_rng=np.random.default_rng(900_007),
        )


def test_integer_seeds_are_refused():
    """An adversary built from an int is one call away from the session's int."""
    with pytest.raises(TypeError, match="D3"):
        UnauthorisedFabricator(rng=7)


def test_the_harness_draws_nothing_from_the_adversarys_stream():
    """His log is the first thing his generator produces, and stays that way.

    The harness needs a key of its own for the declaration nobody distributed
    states for. Taking it off ``attack_rng`` would leave the control arm and the
    fabricated record on consecutive draws of one stream, so a change to how
    many values the control arm wants would move every fabricated record after
    it. This fails if that coupling comes back.
    """
    seed, attack_seed = 900_014, 5150
    assert VERIFIERS[0] is Party.BOB
    row = run_unauthorised(
        MEASUREMENT_PARAMS,
        session_seed=seed,
        attack_rng=np.random.default_rng(attack_seed),
    )[Party.BOB]

    session, declaration, scored = _honest_round(seed=seed)
    solo = UnauthorisedFabricator(
        rng=np.random.default_rng(attack_seed), claims=Party.BOB
    ).fabricate(scored, message_bit=0, session_id=declaration.session_id)
    outcome = verify(declaration, solo, scored)
    assert (row.fabricated_matched, row.fabricated_mismatches) == (
        outcome.matched_count,
        outcome.mismatches,
    )


# --------------------------------------------------------------------------- #
# U1: the fabricated record
# --------------------------------------------------------------------------- #


def test_fabricated_record_is_scored_and_rejected_while_the_owner_accepts():
    """The mechanism, in one run, with the control that makes it non-vacuous."""
    session, declaration, scored = _honest_round()
    owned = session.records[0][Party.BOB]

    control = verify(declaration, owned, scored)
    assert control.accepted
    assert control.rate == 0.0

    invented = UnauthorisedFabricator(rng=np.random.default_rng(3)).fabricate(
        scored, message_bit=0, session_id=declaration.session_id
    )
    outcome = verify(declaration, invented, scored)
    # He is scored, not refused: an invented log matches as often as a real one.
    assert outcome.matched_count > 0
    assert not outcome.accepted
    assert outcome.rate > scored.threshold_for(Party.BOB)


def test_fabricated_record_matches_at_one_third_and_misses_at_one_half(arms):
    """The two per-position rates, at a band computed from the sampling law."""
    for party in VERIFIERS:
        arm = arms[party]
        positions = arm.scored_trials * arm.key_length
        matched = agrees_within(
            arm.fabricated_matched, positions, FABRICATED_MATCHED_FRACTION
        )
        assert matched.agrees, f"{party}: {matched.summary()}"
        mismatch = agrees_within(
            arm.fabricated_mismatches,
            arm.fabricated_matched,
            FABRICATED_MISMATCH_RATE,
        )
        assert mismatch.agrees, f"{party}: {mismatch.summary()}"


def test_the_band_would_catch_a_rate_wrong_by_a_factor(arms):
    """The failure mode these tests exist for is not a near miss."""
    arm = arms[Party.BOB]
    wrong = agrees_within(
        arm.fabricated_mismatches,
        arm.fabricated_matched,
        FABRICATED_MATCHED_FRACTION,
    )
    assert not wrong.agrees
    assert abs(wrong.z_score) > 4.0


def test_the_fabricators_verdict_does_not_depend_on_the_declaration(arms):
    """U1's finding: his rate on a genuine declaration equals his rate on a forged one.

    The point is not that he rejects. It is that he rejects a real signature and
    an invented one at the same rate, so his accept/reject bit is a reading of
    his own coins and not of the declaration.
    """
    for party in VERIFIERS:
        arm = arms[party]
        assert arm.fabricated_accepted == 0
        assert arm.verdict_independent_of_declaration
        assert arm.forged_matched > 0


def test_a_forged_declaration_against_a_real_record_lands_on_the_same_half():
    """The same ``1/2``, read from the declaration's side rather than the log's.

    :mod:`sih141.attacks.forgery` owns the outside forger's rate. This is here
    only to check that the two readings of independence really are the same
    arithmetic, so that :ref:`u1-void`'s cross-reference is not decorative.
    """
    session, _, scored = _honest_round(seed=900_010)
    owned = session.records[0][Party.BOB]
    forged = sign(
        0,
        session.keys[0],
        scored,
        session_opening=session.opening_for(0),
    )
    # A declaration of Alice's own key against Alice's own round accepts; the
    # comparison below is against a key drawn independently of the round.
    assert verify(forged, owned, scored).accepted

    stranger = sign(
        0,
        generate_private_key(scored, 0, rng=np.random.default_rng(77)),
        scored,
        session_opening=session.opening_for(0),
    )
    outcome = verify(stranger, owned, scored)
    verdict = agrees_within(
        outcome.mismatches, outcome.matched_count, FABRICATED_MISMATCH_RATE
    )
    assert verdict.agrees, verdict.summary()


def test_an_unstamped_fabricated_log_is_scored_just_the_same():
    """The round binding names a round, not a person, on either route.

    Copying the publicly announced identifier passes the check; leaving it off
    makes the check inert, because it compares a declaration against the
    *record's* stamp. Neither is an authorisation check, and the verdict is the
    same both ways.
    """
    session, declaration, scored = _honest_round(seed=900_011)
    stamped = UnauthorisedFabricator(rng=np.random.default_rng(9)).fabricate(
        scored, message_bit=0, session_id=declaration.session_id
    )
    bare = UnauthorisedFabricator(rng=np.random.default_rng(9)).fabricate(
        scored, message_bit=0
    )
    assert stamped.session_id == declaration.session_id
    assert bare.session_id is None
    assert verdict_digest(verify(declaration, stamped, scored)) == (
        verdict_digest(verify(declaration, bare, scored))
    )


# --------------------------------------------------------------------------- #
# U2: the leaked record
# --------------------------------------------------------------------------- #


def test_the_thief_reaches_a_verdict_and_it_is_the_owners():
    """The route works, and the equality is structural rather than measured.

    This is an interface test and is not evidence of anything: the thief calls
    :func:`~sih141.protocol.verify.verify` on the owner's three arguments, so
    agreement is what a pure function does. It is here because a route that
    silently stopped working would leave (RECORD SECRECY) pointing at nothing.
    It is the only form the U2 claim takes in this suite: there is no count of
    it in :data:`~sih141.attacks.unauthorised.MEASURED` and none should appear.

    The second half is the part that could fail: a *different* record gives a
    different verdict, so :func:`verdict_digest` distinguishes verdicts at all.
    """
    session, declaration, scored = _honest_round(seed=900_012)
    owned = session.records[0][Party.BOB]
    thief = UnauthorisedHolder(owned)
    assert thief.verify(declaration, scored).accepted
    assert thief.verifications == 1
    assert verdict_digest(thief.verify(declaration, scored)) == verdict_digest(
        verify(declaration, owned, scored)
    )
    # The record he holds names its owner because the session refuses a
    # distribution tagged otherwise. Asserted once, here, rather than counted:
    # it is an invariant of QDSSession, not an outcome of the theft.
    assert thief.claims is owned.party is Party.BOB

    invented = UnauthorisedFabricator(rng=np.random.default_rng(4)).fabricate(
        scored, message_bit=0, session_id=declaration.session_id
    )
    assert verdict_digest(
        UnauthorisedHolder(invented).verify(declaration, scored)
    ) != verdict_digest(verify(declaration, owned, scored))


def test_the_only_identity_available_is_self_declared():
    """A record carries the party its builder wrote, and nothing else."""
    params = ProtocolParams(key_length=24)
    impostor = UnauthorisedFabricator(
        rng=np.random.default_rng(1), claims=Party.CHARLIE
    )
    assert impostor.fabricate(params, message_bit=0).party is Party.CHARLIE
    # The authorised set is the whole vocabulary the type admits; a party
    # outside it is not representable, which is why an authorisation check
    # tests a claim rather than a fact.
    with pytest.raises(ValueError):
        UnauthorisedFabricator(rng=np.random.default_rng(1), claims=Party.ALICE)
    with pytest.raises(ValueError):
        UnauthorisedFabricator(rng=np.random.default_rng(1), claims="Dave")


def test_a_mis_wired_call_naming_a_set_is_still_a_wiring_error():
    """A record outside ``params`` raises; it does not come back as a refusal.

    The authorisation check runs before everything that reads the evidence, but
    after every check that raises, so a caller who passes the wrong parameter
    set gets the ``ValueError`` the Raises block of
    :func:`~sih141.protocol.verify.verify` promises rather than
    ``unauthorised-verifier``. Pinned here because the two orderings differ only
    on a call that names a set, which is this module's parameter and nothing
    else's: ``MatchedSetTooSmall`` is a ``ValueError`` subclass, so the type
    alone does not separate them, and :func:`verify_or_abort` swallows one and
    not the other.
    """
    signed = ProtocolParams(key_length=24)
    wrong = ProtocolParams(key_length=32)
    declaration = sign(
        0, generate_private_key(signed, 0, rng=np.random.default_rng(5)), signed
    )
    # Charlie is outside the set as well, so the call qualifies for both
    # outcomes and the order is what decides which one it gets.
    record = UnauthorisedFabricator(
        rng=np.random.default_rng(6), claims=Party.CHARLIE
    ).fabricate(signed, message_bit=0)
    authorised = frozenset({Party.BOB})

    with pytest.raises(ValueError) as raised:
        verify(declaration, record, wrong, authorised=authorised)
    assert not isinstance(raised.value, MatchedSetTooSmall)
    with pytest.raises(ValueError):
        verify_or_abort(declaration, record, wrong, authorised=authorised)

    # Same record, same set, the parameters it does belong to: now the refusal.
    outcome = verify_or_abort(
        declaration, record, signed, authorised=authorised
    )
    assert outcome.reason.value == "unauthorised-verifier"


def test_verdict_digest_covers_every_field():
    """A field added to the verdict must appear in the comparison, not slip past."""
    session, declaration, scored = _honest_round(seed=900_013)
    result = verify(declaration, session.records[0][Party.BOB], scored)
    digest = verdict_digest(result)
    for field in dataclasses.fields(VerificationResult):
        assert f'"{field.name}"' in digest


def test_verdict_digest_refuses_a_non_verdict():
    """It is a comparison of verdicts, not of anything that has a repr."""
    with pytest.raises(TypeError, match="VerificationResult"):
        verdict_digest("accepted")


def test_holder_refuses_a_non_record():
    """This adversary is defined by holding a genuine log."""
    with pytest.raises(TypeError, match="RecipientRecord"):
        UnauthorisedHolder("Bob's log")


# --------------------------------------------------------------------------- #
# U3: the reduction, which is argued and not measured end to end
# --------------------------------------------------------------------------- #


def test_the_tapped_link_qber_is_computed_and_not_quoted():
    """The one number the reduction turns on comes from the channel module."""
    reduction = tapped_record_reduction()
    assert reduction["qber"] == qber_from_tensor(collapse_tensor(PAULI_AXES))
    assert reduction["qber"] == pytest.approx(TAPPED_LINK_QBER)
    assert reduction["reduces_to"] == "sih141.attacks.channel.InterceptResend"


def test_the_tapped_link_qber_is_far_above_the_tighter_threshold():
    """A third against a noise budget of a sixty-fourth is not a close call."""
    assert TAPPED_LINK_QBER > 20 * MEASUREMENT_PARAMS.threshold_for(Party.BOB)


def test_the_reduction_says_which_half_is_argued():
    """The step from no-cloning to intercept-resend is an argument. It says so."""
    reduction = tapped_record_reduction()
    assert "argument, not a measurement" in reduction["argued"]
    assert "qber_from_tensor" in reduction["measured"]


# --------------------------------------------------------------------------- #
# The shipped table
# --------------------------------------------------------------------------- #


def test_shipped_table_is_internally_consistent():
    """Every published row recomputes from its own counts."""
    for party in VERIFIERS:
        arm = MEASURED[party]
        assert arm.party is party
        assert arm.key_length == MEASUREMENT_PARAMS.key_length
        assert arm.trials == 200
        assert arm.owner_accepted == arm.trials
        assert arm.fabricated_accepted == 0
        assert arm.fabricated_no_verdict == 0
        assert arm.forged_no_verdict == 0
        assert arm.fabricated_acceptance_rate == 0.0
        assert arm.fabricated_acceptance_interval[0] == 0.0


def test_shipped_table_agrees_with_the_analytic_rates():
    """The two published rates sit on ``1/3`` and ``1/2`` at a computed band."""
    for party in VERIFIERS:
        arm = MEASURED[party]
        positions = arm.trials * arm.key_length
        assert agrees_within(
            arm.fabricated_matched, positions, FABRICATED_MATCHED_FRACTION
        ).agrees
        assert agrees_within(
            arm.fabricated_mismatches,
            arm.fabricated_matched,
            FABRICATED_MISMATCH_RATE,
        ).agrees
        assert agrees_within(
            arm.forged_mismatches, arm.forged_matched, FABRICATED_MISMATCH_RATE
        ).agrees
        assert arm.verdict_independent_of_declaration


def test_shipped_summary_prints_the_counts_it_claims():
    """The published lines are built from the published counts, not typed."""
    lines = shipped_summary()
    assert len(lines) == len(VERIFIERS)
    for party, line in zip(VERIFIERS, lines, strict=True):
        arm = MEASURED[party]
        assert line.startswith(f"{party!s} L={arm.key_length} n={arm.trials}")
        assert f"owner {arm.owner_accepted}/{arm.trials}" in line
        assert f"{arm.fabricated_accepted}/{arm.trials} accepted" in line
        # No U2 count is published, and the line is where one would show up.
        assert "leaked" not in line


# --------------------------------------------------------------------------- #
# The record types refuse rows that cannot be real
# --------------------------------------------------------------------------- #


def test_measurement_refuses_impossible_counts():
    """Counts that contradict each other are a counting error upstream."""
    base = dict(
        party=Party.BOB,
        key_length=192,
        trials=10,
        owner_accepted=10,
        fabricated_accepted=0,
        fabricated_no_verdict=0,
        fabricated_matched=640,
        fabricated_mismatches=320,
        forged_no_verdict=0,
        forged_matched=640,
        forged_mismatches=320,
    )
    assert UnauthorisedMeasurement(**base).fabricated_rate == 0.5

    with pytest.raises(ValueError, match="0 <= n <= trials"):
        UnauthorisedMeasurement(**{**base, "owner_accepted": 11})
    with pytest.raises(ValueError, match="0 <= n <= trials"):
        UnauthorisedMeasurement(**{**base, "forged_no_verdict": 11})
    with pytest.raises(ValueError, match="0 <= e <= "):
        UnauthorisedMeasurement(**{**base, "fabricated_mismatches": 641})
    with pytest.raises(ValueError, match="more"):
        UnauthorisedMeasurement(**{**base, "fabricated_matched": 20_000})
    with pytest.raises(ValueError):
        UnauthorisedMeasurement(**{**base, "party": Party.ALICE})
    with pytest.raises(ValueError, match="at least 1"):
        UnauthorisedMeasurement(**{**base, "trials": 0})


def test_measurement_reports_no_independence_when_nothing_was_scored():
    """An arm that scored nothing agrees with nothing."""
    arm = UnauthorisedMeasurement(
        party=Party.BOB,
        key_length=192,
        trials=1,
        owner_accepted=1,
        fabricated_accepted=0,
        fabricated_no_verdict=1,
        fabricated_matched=0,
        fabricated_mismatches=0,
        forged_no_verdict=1,
        forged_matched=0,
        forged_mismatches=0,
    )
    assert not arm.verdict_independent_of_declaration
    assert arm.matched_fraction != arm.matched_fraction  # nan
    assert arm.fabricated_rate != arm.fabricated_rate


def test_a_refusal_on_either_arm_stops_the_comparison():
    """One arm refused the floor is one denominator short, not a near miss.

    Both arms score the same fabricated log, so a refusal on one of them is a
    trial that contributed positions to the other and none here. The rates would
    still overlap and the overlap would be about two different samples, so the
    property declines instead. At ``L = 192`` with ``m_min = 1`` this never
    fires; at the lengths this module advertises for probes it can.
    """
    base = dict(
        party=Party.BOB,
        key_length=12,
        trials=10,
        owner_accepted=10,
        fabricated_accepted=0,
        fabricated_no_verdict=0,
        fabricated_matched=40,
        fabricated_mismatches=20,
        forged_no_verdict=0,
        forged_matched=40,
        forged_mismatches=20,
    )
    assert UnauthorisedMeasurement(**base).verdict_independent_of_declaration
    for refused in ("fabricated_no_verdict", "forged_no_verdict"):
        arm = UnauthorisedMeasurement(**{**base, refused: 1})
        assert not arm.verdict_independent_of_declaration


def test_a_refused_forged_arm_is_counted_when_the_trials_are_pooled():
    """The refusal has to survive pooling, or the denominator shrinks silently."""
    scored = UnauthorisedTrial(
        party=Party.BOB,
        session_seed=900_030,
        key_length=12,
        message_bit=0,
        owner_accepted=True,
        fabricated_accepted=False,
        fabricated_matched=4,
        fabricated_mismatches=2,
        forged_matched=None,
        forged_mismatches=None,
    )
    assert scored.reached_verdict
    assert not scored.forged_scored
    # _pool is private and is the only place these two counts are formed.
    arm = _pool(Party.BOB, [scored, dataclasses.replace(scored)])
    assert arm.fabricated_no_verdict == 0
    assert arm.forged_no_verdict == 2
    assert arm.forged_matched == 0
    assert not arm.verdict_independent_of_declaration


def test_trial_rows_are_json_safe():
    """A list of trials is a Phase 5 table already."""
    rows = run_unauthorised(
        MEASUREMENT_PARAMS,
        session_seed=900_020,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    row = rows[Party.BOB].to_dict()
    assert row["party"] == "Bob"
    assert isinstance(rows[Party.BOB], UnauthorisedTrial)
    assert row["owner_accepted"] is True
    assert row["fabricated_accepted"] is False

    arm = MEASURED[Party.CHARLIE].to_dict()
    assert arm["party"] == "Charlie"
    assert arm["verdict_independent_of_declaration"] is True


def test_fabricate_refuses_a_record_it_could_not_present():
    """Wiring errors are refused where they happen, not scored as noise."""
    outsider = UnauthorisedFabricator(rng=np.random.default_rng(1))
    with pytest.raises(TypeError, match="ProtocolParams"):
        outsider.fabricate(192, message_bit=0)
    with pytest.raises(ValueError, match="0 or 1"):
        outsider.fabricate(ProtocolParams(key_length=12), message_bit=2)


def test_fabricated_record_is_a_well_formed_recipient_record():
    """It has to be, or verification refuses it before any counting happens."""
    params = ProtocolParams(key_length=36)
    record = UnauthorisedFabricator(rng=np.random.default_rng(2)).fabricate(
        params, message_bit=1
    )
    assert isinstance(record, RecipientRecord)
    assert len(record) == params.key_length
    assert record.message_bit == 1
    assert record.symmetrised
    assert {entry.eigenvalue for entry in record.entries} <= {1, -1}
    assert {entry.basis for entry in record.entries} <= set(params.bases)
    record.check_against(params)
