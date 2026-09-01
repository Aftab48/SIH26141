"""Tests for :mod:`sih141.attacks.impersonation`.

Three things are being tested here and they are worth naming separately, since
only the first is about the protocol at all:

1. **D6.** Mallory's choices move with her own generator and not with the
   session's, checked behaviourally on *each* seam through
   :func:`sih141.attacks.isolation.assert_attack_isolated`.
2. **The contrast.** One seam is caught cold; two seams are accepted with
   probability one. Both halves are run live rather than asserted from the
   shipped table.
3. **The invisibles.** Under the distribution scope the matched sets are
   identical position for position to the control at the same session seed, so
   the mismatch rate really is the only signal there is.

Key lengths in this file are small so the suite stays runnable, and a small key
length **carries no security claim**: below ``L = 140`` both evidence floors
degenerate. What the small runs demonstrate is mechanism -- which seam produces
which rate -- and the per-position argument of
:ref:`sih141.attacks.impersonation <half-a-half>` is what carries that to
``L = 115200``, because ``P(o_i != v_i | scored) = 1/2`` is a statement about one
position and does not mention ``L``. The published rates at ``L = 192`` live in
:data:`~sih141.attacks.impersonation.MEASURED` and are checked here for internal
consistency and against the analytic ``1/2``.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from sih141.attacks.impersonation import (
    DEMO_MEASUREMENT_PARAMS,
    FIRST_SESSION_SEED,
    MATCHED_IDENTICAL_TRIALS,
    MEASURED,
    MEASUREMENT_PARAMS,
    ImpersonationMeasurement,
    ImpersonationScope,
    ImpersonationTrial,
    Impersonator,
    MeasuredRun,
    detector_signals,
    distributor_probe,
    impersonation_seams,
    matched_sets_identical,
    measure_impersonation,
    run_impersonation,
    session_seeds,
    shipped_summary,
    signing_probe,
    wilson_interval,
)
from sih141.attacks.isolation import AttackIsolationError, assert_attack_isolated
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import QDSSession
from sih141.protocol.verify import (
    minimum_matched_count,
    minimum_pooled_matched_count,
)

#: Cheap enough for a live arm, large enough for a rate. No security claim.
LIVE_PARAMS = ProtocolParams(key_length=96)

#: How many sessions each live arm runs.
LIVE_TRIALS = 30

#: Mallory's seed everywhere in this file. Never a session seed, anywhere.
ATTACK_SEED = 4242


# --------------------------------------------------------------------------- #
# D6
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "probe"),
    [("signing", signing_probe()), ("distribution", distributor_probe())],
)
def test_impersonator_owns_its_randomness_on_each_seam(label, probe):
    """Each seam's decisions move with Mallory's generator and not the session's.

    Run per seam rather than once for the object, because the two seams could
    fail differently: the signing seam is a pure function of her cache, while
    the distribution seam is handed the session's Alice-side stream and could
    read it.
    """
    report = assert_attack_isolated(Impersonator, probe, name=f"Impersonator.{label}")
    assert report.isolated
    assert not report.reads_the_session
    assert report.uses_its_own_generator


def test_isolation_check_would_catch_a_session_reading_impersonator():
    """The D6 check is not vacuous: a peeking variant is rejected by it.

    A test that only ever sees passes proves the candidate is fine or proves
    the check is broken, and cannot tell which.
    """

    class PeekingImpersonator(Impersonator):
        """Mallory rebuilt from the harness seed -- exactly the D6 defect."""

        def __init__(
            self, *, rng: np.random.Generator, session_seed: int
        ) -> None:
            del rng
            super().__init__(rng=np.random.default_rng(session_seed))

    with pytest.raises(AttackIsolationError) as excinfo:
        assert_attack_isolated(PeekingImpersonator, signing_probe())
    assert "reads the session's randomness" in str(excinfo.value)


def test_the_measurements_refuse_one_seed_for_mallory_and_the_session():
    """The guard this module had none of, and the form the defect really takes.

    ``session_seed`` and ``attack_rng`` are separate arguments so that a caller
    cannot pass one number and get both -- but nothing stopped
    ``session_seed=7`` beside ``attack_rng=default_rng(7)``, which is the same
    number written twice and gives Mallory the very stream ``QDSSession``
    derives all three of its own from. Every acceptance rate measured that way
    would be a statement about a correlation rather than about the attack.
    """
    with pytest.raises(ValueError, match="the stream session seed 7 produces"):
        run_impersonation(
            ImpersonationScope.SIGNING,
            DEMO_MEASUREMENT_PARAMS,
            session_seed=7,
            attack_rng=np.random.default_rng(7),
        )
    # The arm-level guard runs over the whole seed list before the first trial,
    # so a collision at trial 137 of 200 does not cost 136 sessions first.
    with pytest.raises(ValueError, match="measure_impersonation"):
        measure_impersonation(
            ImpersonationScope.FULL,
            DEMO_MEASUREMENT_PARAMS,
            trials=4,
            attack_rng=np.random.default_rng(FIRST_SESSION_SEED + 2),
        )
    # An unrelated seed is accepted, so the guard is not refusing everything.
    trial = run_impersonation(
        ImpersonationScope.SIGNING,
        DEMO_MEASUREMENT_PARAMS,
        session_seed=7,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    assert trial.session_seed == 7


def test_impersonator_refuses_an_integer_seed():
    """An adversary built from an int is one step from the harness's int."""
    with pytest.raises(TypeError) as excinfo:
        Impersonator(rng=7)  # type: ignore[arg-type]
    assert "numpy.random.Generator" in str(excinfo.value)
    assert "D6" in str(excinfo.value)


def test_the_attack_does_not_disturb_the_sessions_streams():
    """A signing impersonation leaves the distribution bit-for-bit unchanged.

    Mallory draws from her own generator, so the session's Alice-side and
    recipient-side streams advance identically whether she is present or not.
    If that were false, every paired comparison in this file would be comparing
    two different distributions and the matched-count claims would be noise.
    """
    params = DEMO_MEASUREMENT_PARAMS
    honest = QDSSession(params, rng=np.random.default_rng(31))
    honest.distribute()
    mallory = Impersonator(rng=np.random.default_rng(ATTACK_SEED))
    attacked = QDSSession(
        params, rng=np.random.default_rng(31), signer=mallory.sign
    )
    attacked.distribute()
    for bit in (0, 1):
        for party in (Party.BOB, Party.CHARLIE):
            assert honest.records[bit][party] == attacked.records[bit][party]


# --------------------------------------------------------------------------- #
# The adversary's own behaviour
# --------------------------------------------------------------------------- #


def test_both_seams_of_one_impersonator_declare_the_same_key():
    """The distributor and the signer must agree, or FULL is two weak attacks."""
    params = ProtocolParams(key_length=12)
    mallory = Impersonator(rng=np.random.default_rng(1))
    sent = mallory.key_for(0, params)
    declared = mallory.sign(0, (), params, records={}).declared_key
    assert declared is sent


def test_mallory_ignores_alices_key_entirely():
    """She substitutes an identity; copying Alice's key would not be one."""
    params = ProtocolParams(key_length=24)
    mallory = Impersonator(rng=np.random.default_rng(2))
    alice = QDSSession(params, rng=np.random.default_rng(3))
    alice.distribute()
    declared = mallory.sign(0, alice.keys, params, records={}).declared_key
    assert declared != alice.keys[0]


def test_key_for_caches_per_bit_and_per_length():
    """Check rounds distribute at one length and declare at another."""
    mallory = Impersonator(rng=np.random.default_rng(4))
    short = mallory.key_for(0, ProtocolParams(key_length=12))
    long = mallory.key_for(0, ProtocolParams(key_length=24))
    other_bit = mallory.key_for(1, ProtocolParams(key_length=12))
    assert short is not long
    assert short is not other_bit
    assert sorted(mallory.keys) == [(0, 12), (0, 24), (1, 12)]


def test_full_impersonation_survives_check_rounds():
    """The sifted key filed by the distributor is the one the signer declares.

    Without the sifting step in :meth:`Impersonator.distribute` the signer would
    draw a *second*, unrelated key at the sifted length and FULL would collapse
    into a signing-only impersonation -- silently, and looking like a security
    result.
    """
    params = ProtocolParams(key_length=96, check_fraction=0.25)
    mallory = Impersonator(rng=np.random.default_rng(5))
    transcript = QDSSession(
        params,
        rng=np.random.default_rng(6),
        distributor=mallory.distribute,
        signer=mallory.sign,
    ).run(0)
    assert transcript.bob.rate == 0.0
    assert transcript.charlie.rate == 0.0
    assert transcript.transferable


def test_impersonation_seams_names_the_right_seams():
    """One place decides what 'partial' means."""
    mallory = Impersonator(rng=np.random.default_rng(7))
    assert impersonation_seams(mallory, ImpersonationScope.NONE) == {}
    assert set(impersonation_seams(mallory, "signing")) == {"signer"}
    assert set(impersonation_seams(mallory, "distribution")) == {"distributor"}
    assert set(impersonation_seams(mallory, ImpersonationScope.FULL)) == {
        "distributor",
        "signer",
    }


def test_unknown_scope_is_refused_with_the_alternatives():
    """A typo'd scope changes the answer completely, so it must not pass."""
    mallory = Impersonator(rng=np.random.default_rng(8))
    with pytest.raises(ValueError) as excinfo:
        impersonation_seams(mallory, "partial")
    assert "distribution" in str(excinfo.value)
    assert "signing" in str(excinfo.value)


def test_scope_flags_agree_with_the_seams_they_install():
    """``is_partial`` must mean 'exactly one seam', not 'not full'."""
    mallory = Impersonator(rng=np.random.default_rng(9))
    for scope in ImpersonationScope:
        installed = len(impersonation_seams(mallory, scope))
        assert scope.is_partial == (installed == 1)
        assert scope.in_model == (scope is not ImpersonationScope.FULL)


# --------------------------------------------------------------------------- #
# The contrast, measured live
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def live_arms():
    """Run all four arms once, over one shared seed sequence.

    Module-scoped because the four arms cost about a minute between them and
    every comparison below wants the same runs. One seed sequence for all four
    is what makes the arms *paired*.
    """
    seeds = session_seeds(LIVE_TRIALS, first=770_000)
    return {
        scope: measure_impersonation(
            scope,
            LIVE_PARAMS,
            seeds=seeds,
            attack_rng=np.random.default_rng(ATTACK_SEED),
        )
        for scope in ImpersonationScope
    }


def test_the_control_arm_is_clean(live_arms):
    """Without it, 'the attack was rejected' could just mean 'the run broke'."""
    control = live_arms[ImpersonationScope.NONE]
    assert control.successes == control.trial_count
    assert control.mismatch_rate(Party.BOB) == 0.0
    assert control.mismatch_rate(Party.CHARLIE) == 0.0
    assert control.aborts == 0


def test_full_impersonation_is_accepted_every_time(live_arms):
    """(AUTH) has a price and this is it, stated as a rate rather than prose.

    Not a break of the protocol: Mallory is running it correctly with her own
    key, and the recipients' logs contain nothing to disagree with. It is the
    cost of the assumption, and it is exactly ``1``.
    """
    arm = live_arms[ImpersonationScope.FULL]
    assert arm.successes == arm.trial_count
    assert arm.mismatch_rate(Party.BOB) == 0.0
    assert arm.mismatch_rate(Party.CHARLIE) == 0.0
    assert arm.aborts == 0
    assert not ImpersonationScope.FULL.in_model


@pytest.mark.parametrize(
    "scope", [ImpersonationScope.SIGNING, ImpersonationScope.DISTRIBUTION]
)
def test_partial_impersonation_is_never_accepted(live_arms, scope):
    """One seam is not enough, at either seam, in every single run."""
    arm = live_arms[scope]
    assert arm.successes == 0
    assert arm.accepted_by(Party.BOB) == 0
    assert arm.accepted_by(Party.CHARLIE) == 0
    assert arm.aborts == 0


@pytest.mark.parametrize(
    "scope", [ImpersonationScope.SIGNING, ImpersonationScope.DISTRIBUTION]
)
@pytest.mark.parametrize("party", [Party.BOB, Party.CHARLIE])
def test_partial_mismatch_rate_agrees_with_the_analytic_half(
    live_arms, scope, party
):
    """The measured pooled rate must cover ``1/2``, the per-position prediction.

    The interval is over pooled *positions*, not over runs, because ``1/2`` is a
    per-position Bernoulli parameter (see :ref:`half-a-half`); an interval over
    per-run rates would be estimating a different quantity.
    """
    arm = live_arms[scope]
    interval = arm.mismatch_interval(party)
    assert interval.covers(0.5), (
        f"{scope!s}/{party!s} pooled rate {arm.mismatch_rate(party):.4f} "
        f"({arm.mismatch_total(party)}/{arm.matched_total(party)}) has "
        f"95% interval [{interval.low:.4f}, {interval.high:.4f}], which "
        f"excludes the predicted 1/2"
    )


def test_partial_rates_are_far_above_both_thresholds(live_arms):
    """A rate near 1/2 against cuts of 1/64 and 1/16 is not a near miss.

    Four times the looser of the two cuts, and thirty times the tighter one, at
    the *lower* end of the interval. Stated as a multiple of the threshold
    rather than as an absolute number so the test says what it means: the
    partial impersonator is not close to passing at either verifier.
    """
    for scope in (ImpersonationScope.SIGNING, ImpersonationScope.DISTRIBUTION):
        arm = live_arms[scope]
        for party in (Party.BOB, Party.CHARLIE):
            assert (
                arm.mismatch_interval(party).low
                > 4 * LIVE_PARAMS.threshold_for(party)
            )


# --------------------------------------------------------------------------- #
# The invisibles
# --------------------------------------------------------------------------- #


def test_distribution_impersonation_leaves_the_matched_sets_identical(live_arms):
    """The sharp form of 'matched counts are unchanged'.

    Alice declares the key she always would and the recipients draw the same
    bases from the same stream, so ``{i : c_i == d_i}`` cannot move. This is the
    reason the evidence floors are not an impersonation detector.
    """
    assert matched_sets_identical(
        live_arms[ImpersonationScope.NONE],
        live_arms[ImpersonationScope.DISTRIBUTION],
    )


def test_signing_impersonation_moves_the_matched_set_but_not_its_size(live_arms):
    """Mallory's declared bases pick a *different* subset of the same law.

    So the exact-equality check fails -- and must, or the previous test would be
    passing for a trivial reason -- while the counts stay Binomial(L, 1/3) and
    every floor stays comfortably satisfied.
    """
    control = live_arms[ImpersonationScope.NONE]
    signing = live_arms[ImpersonationScope.SIGNING]
    assert not matched_sets_identical(control, signing)

    floor = minimum_matched_count(LIVE_PARAMS)
    pooled_floor = minimum_pooled_matched_count(LIVE_PARAMS)
    for trial in signing.trials:
        assert trial.bob_matched >= floor
        assert trial.charlie_matched >= floor
        assert trial.bob_matched + trial.charlie_matched >= pooled_floor

    expected = LIVE_PARAMS.expected_matched
    for arm in (control, signing):
        for party in (Party.BOB, Party.CHARLIE):
            mean = arm.matched_total(party) / arm.trial_count
            # Binomial(L, 1/3): sd of the mean over the arm.
            sd = math.sqrt(2 * LIVE_PARAMS.key_length / 9 / arm.trial_count)
            assert abs(mean - expected) < 4 * sd


def test_matched_sets_identical_refuses_unpaired_arms():
    """Comparing arms run at different seeds answers a question nobody asked."""
    left = measure_impersonation(
        ImpersonationScope.NONE,
        DEMO_MEASUREMENT_PARAMS,
        seeds=(1, 2, 3),
        attack_rng=np.random.default_rng(0),
    )
    right = measure_impersonation(
        ImpersonationScope.NONE,
        DEMO_MEASUREMENT_PARAMS,
        seeds=(4, 5, 6),
        attack_rng=np.random.default_rng(0),
    )
    with pytest.raises(ValueError) as excinfo:
        matched_sets_identical(left, right)
    assert "different session seeds" in str(excinfo.value)


def test_detector_signals_says_only_the_rate_moves():
    """The Phase 4 deliverable, checked as data rather than trusted as prose."""
    signals = detector_signals()
    assert all(entry["reachable"] for entry in signals.values())
    moved = {
        name
        for name, entry in signals.items()
        if entry["partial"] != entry["honest"]
    }
    assert moved == {"mismatch_rate"}
    assert all(
        entry["full"] == entry["honest"]
        for name, entry in signals.items()
        if name != "mismatch_rate"
    )


# --------------------------------------------------------------------------- #
# Determinism, reduction, and the shipped table
# --------------------------------------------------------------------------- #


def test_an_arm_is_reproducible_from_its_two_seed_sources():
    """Same session seeds and same attack seed, same numbers -- twice."""
    seeds = session_seeds(3, first=555_000)
    first = measure_impersonation(
        ImpersonationScope.SIGNING,
        DEMO_MEASUREMENT_PARAMS,
        seeds=seeds,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    second = measure_impersonation(
        ImpersonationScope.SIGNING,
        DEMO_MEASUREMENT_PARAMS,
        seeds=seeds,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    assert [t.to_dict() for t in first.trials] == [
        t.to_dict() for t in second.trials
    ]


def test_a_trial_records_its_key_length():
    """A rate without an ``L`` is the defect this module was asked to fix."""
    trial = run_impersonation(
        ImpersonationScope.SIGNING,
        DEMO_MEASUREMENT_PARAMS,
        session_seed=99,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    assert trial.key_length == DEMO_MEASUREMENT_PARAMS.key_length
    assert trial.session_seed == 99
    assert trial.to_dict()["key_length"] == DEMO_MEASUREMENT_PARAMS.key_length


def test_a_checked_run_reports_the_scored_length_not_the_nominal_one():
    """The rate is over the sifted key, so that is the length to record."""
    params = ProtocolParams(key_length=96, check_fraction=0.25)
    trial = run_impersonation(
        ImpersonationScope.NONE,
        params,
        session_seed=12,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    assert trial.key_length == params.sifted().key_length
    assert trial.key_length < params.key_length


def test_an_arm_refuses_to_mix_scopes():
    """An arm that averages two experiments describes neither."""
    rows = (
        ImpersonationTrial(
            scope=ImpersonationScope.SIGNING,
            session_seed=1,
            key_length=48,
            message_bit=0,
            bob_matched=16,
            charlie_matched=16,
            bob_mismatches=8,
            charlie_mismatches=8,
            bob_accepted=False,
            charlie_accepted=False,
            transferable=False,
        ),
    )
    with pytest.raises(ValueError) as excinfo:
        ImpersonationMeasurement(ImpersonationScope.FULL, 48, rows)
    assert "mixing scopes" in str(excinfo.value)


def test_a_trial_with_no_verdict_is_not_scored_as_a_rejection():
    """'No verdict' and 'rejected' are different outcomes and stay different."""
    trial = ImpersonationTrial(
        scope=ImpersonationScope.SIGNING,
        session_seed=1,
        key_length=48,
        message_bit=0,
        bob_matched=None,
        charlie_matched=12,
        bob_mismatches=None,
        charlie_mismatches=6,
        bob_accepted=None,
        charlie_accepted=False,
        transferable=False,
    )
    assert not trial.reached_verdicts
    assert trial.bob_rate is None
    assert trial.charlie_rate == 0.5
    assert not trial.accepted_by_both


@pytest.mark.parametrize("scope", list(ImpersonationScope))
def test_the_shipped_table_records_its_key_length_and_its_counts(scope):
    """Every published row carries ``L``, ``n``, and the counts behind the rate."""
    row = MEASURED[scope]
    assert row.key_length == MEASUREMENT_PARAMS.key_length == 192
    assert row.trials == 200
    assert row.bob_matched > 0 and row.charlie_matched > 0
    assert row.success_rate == row.successes / row.trials
    assert str(row.key_length) in row.summary()


def test_the_shipped_partial_rows_cover_the_analytic_half():
    """The published partial rates must agree with ``1/2`` or one of them is wrong.

    A failure here is a finding about the measurement, not about the theory: the
    per-position argument of :ref:`half-a-half` is elementary and the
    measurement is the thing that could be miswired.
    """
    for scope in (ImpersonationScope.SIGNING, ImpersonationScope.DISTRIBUTION):
        row = MEASURED[scope]
        assert row.successes == 0
        for party in (Party.BOB, Party.CHARLIE):
            assert row.interval_for(party).covers(0.5), (
                f"{scope!s}/{party!s}: {row.rate_for(party):.4f} does not "
                f"cover 1/2"
            )


def test_the_shipped_end_to_end_rows_are_exactly_clean():
    """Full impersonation and the control are both indistinguishable from honest."""
    for scope in (ImpersonationScope.NONE, ImpersonationScope.FULL):
        row = MEASURED[scope]
        assert row.successes == row.trials
        assert row.bob_rate == 0.0
        assert row.charlie_rate == 0.0
        assert row.success_interval.low > 0.98


def test_a_measured_row_refuses_impossible_counts():
    """The table is a checked record, not a place to type a number."""
    with pytest.raises(ValueError):
        MeasuredRun(
            scope=ImpersonationScope.FULL,
            key_length=192,
            trials=10,
            successes=11,
            bob_mismatches=0,
            bob_matched=100,
            charlie_mismatches=0,
            charlie_matched=100,
        )
    with pytest.raises(ValueError):
        MeasuredRun(
            scope=ImpersonationScope.FULL,
            key_length=192,
            trials=10,
            successes=10,
            bob_mismatches=101,
            bob_matched=100,
            charlie_mismatches=0,
            charlie_matched=100,
        )


# --------------------------------------------------------------------------- #
# The interval helper
# --------------------------------------------------------------------------- #


def test_wilson_interval_is_exact_at_the_ends():
    """Zero successes must print zero, not float dust."""
    assert wilson_interval(0, 200).low == 0.0
    assert wilson_interval(200, 200).high == 1.0


def test_wilson_interval_narrows_with_more_trials():
    """A sanity check that it is an interval and not a constant."""
    wide = wilson_interval(50, 100)
    narrow = wilson_interval(5000, 10000)
    assert narrow.half_width < wide.half_width
    assert wide.covers(0.5) and narrow.covers(0.5)


@pytest.mark.parametrize(
    ("successes", "trials"), [(-1, 10), (11, 10), (0, 0)]
)
def test_wilson_interval_refuses_impossible_counts(successes, trials):
    """A rate outside ``[0, 1]`` is a bug upstream, not a number to report."""
    with pytest.raises(ValueError):
        wilson_interval(successes, trials)


def test_mismatch_rate_refuses_an_arm_that_scored_nothing():
    """A rate with a zero denominator is not zero, it is absent."""
    rows = (
        ImpersonationTrial(
            scope=ImpersonationScope.SIGNING,
            session_seed=1,
            key_length=48,
            message_bit=0,
            bob_matched=None,
            charlie_matched=None,
            bob_mismatches=None,
            charlie_mismatches=None,
            bob_accepted=None,
            charlie_accepted=None,
            transferable=False,
        ),
    )
    arm = ImpersonationMeasurement(ImpersonationScope.SIGNING, 48, rows)
    assert arm.aborts == 1
    with pytest.raises(ValueError) as excinfo:
        arm.mismatch_rate(Party.BOB)
    assert "no positions were scored" in str(excinfo.value)


def test_alice_has_no_rate():
    """She signs and keeps no record; asking for her rate is a category error."""
    row = MEASURED[ImpersonationScope.FULL]
    with pytest.raises(ValueError) as excinfo:
        row.rate_for(Party.ALICE)
    assert "keeps no record" in str(excinfo.value)


def test_shipped_summary_names_every_scope_and_its_key_length():
    """The four published lines are generated from the table, never retyped."""
    lines = shipped_summary()
    assert len(lines) == len(ImpersonationScope)
    for scope in ImpersonationScope:
        assert any(line.startswith(f"{scope!s} L=192 n=200:") for line in lines)


def test_matched_identical_counts_are_consistent_with_the_scopes():
    """Only the distribution scope leaves the matched set untouched.

    A table saying otherwise would contradict :ref:`impersonation-invisibles`,
    and the live paired arms above are what establish the direction.
    """
    assert MATCHED_IDENTICAL_TRIALS[ImpersonationScope.DISTRIBUTION] == 200
    assert MATCHED_IDENTICAL_TRIALS[ImpersonationScope.NONE] == 200
    assert MATCHED_IDENTICAL_TRIALS[ImpersonationScope.SIGNING] == 0
    assert MATCHED_IDENTICAL_TRIALS[ImpersonationScope.FULL] == 0


def test_the_documented_reproduction_recipe_reproduces_a_prefix():
    """Ten trials of the shipped arm, run exactly as :data:`MEASURED` says.

    The whole table is 800 sessions and does not belong in a unit suite, but a
    recipe nobody ever executes is a recipe that rots. This runs the documented
    seeds and the documented attack seed over a prefix and checks the two things
    the arm claims: nothing accepted, and the matched sets untouched.
    """
    prefix = session_seeds(10, first=FIRST_SESSION_SEED)
    control = measure_impersonation(
        ImpersonationScope.NONE,
        MEASUREMENT_PARAMS,
        seeds=prefix,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    swapped = measure_impersonation(
        ImpersonationScope.DISTRIBUTION,
        MEASUREMENT_PARAMS,
        seeds=prefix,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    assert control.successes == 10
    assert swapped.successes == 0
    assert matched_sets_identical(control, swapped)
    assert swapped.key_length == MEASURED[ImpersonationScope.DISTRIBUTION].key_length
