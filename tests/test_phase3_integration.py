"""Every Phase 3 adversary, mounted end to end, against its analytic prediction.

Each attack module tests itself. This file tests the *join*: the adversary
wired onto the shipped seams of a real
:class:`~sih141.protocol.session.QDSSession`, the rate read off the transcripts
that session produced, and the comparison made against the closed form in
:mod:`sih141.protocol.analysis` that is supposed to predict it. A module can be
green while its attack no longer composes with the protocol, and that is the
gap this closes.

Tolerances are computed, never guessed
--------------------------------------
Every comparison here goes through
:func:`sih141.attacks.statistics.agrees_within`, whose band is
``4 * sqrt(p(1-p)/n)`` at the **predicted** ``p`` -- predicted rather than
measured, because the hypothesis under test is that the analysis is right and an
estimator has no business setting the width of its own acceptance band. Four
standard errors is a per-comparison false-alarm rate of ``6.3e-05``, chosen
against the roughly twenty comparisons this file makes rather than out of
timidity, and it is still far tighter than the failure modes these attacks can
actually produce: a broken attack lands on ``1/2`` where ``1/12`` was predicted,
or ``2/3`` where ``1/3`` was, never three standard errors out.

Two consequences worth stating before a reader is surprised by them.

*Rules are not rates.* A defence that refuses ``400/400`` presentations is a
rule, and it is asserted as ``successes == 0`` rather than compared against a
probability, because there is no sampling distribution to compare against.
Mixing the two is how a denial of service gets counted as a detection.

*Small key lengths are for statistics, not for security.* Nothing here runs at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`, where the predicted acceptance
of the sharpest attack is about ``1e-103`` and no number of trials would see
one. Below ``L = 140`` neither matched-count floor carries a security claim at
all. What carries from these lengths to that one is the *per-position* statistic
-- the scored fraction and the mismatch rate -- which follows from the Born rule
and a uniform basis draw and does not mention ``L``; the acceptance rates
measured here are the check that the harness composes those per-position
statistics the way the analysis says it does.
"""

from __future__ import annotations

import numpy as np
import pytest

from sih141.attacks import (
    CountStarver,
    DepolarisingChannel,
    Impersonator,
    InterceptResend,
    KeptShareSwap,
    OutsideForger,
    RecipientForger,
    agrees_within,
    chsh_from_tensor,
    collapse_tensor,
    denial_headroom,
    depolarising_tensor,
    impersonation_seams,
    least_implausible_z,
    measure_chsh,
    measure_cross_session_pairing,
    measure_qber,
    measure_straight_replay,
    qber_from_tensor,
    wilson_bounds,
)
from sih141.protocol.analysis import (
    depolarising_error_rate,
    forgery_probability,
    recipient_forgery_probability,
)
from sih141.protocol.checkrounds import estimate_qber
from sih141.protocol.params import DEFAULT_PARAMS, Party, ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
)
from sih141.protocol.symmetrise import no_symmetrisation
from sih141.protocol.tally import no_count_exchange
from sih141.protocol.verify import MatchedSetTooSmall, minimum_matched_count

# --------------------------------------------------------------------------- #
# Trial counts and seeds. Session seeds and attack seeds are drawn from
# disjoint ranges throughout, so that no run can accidentally give an adversary
# the seed its session was built from -- which is convention D6 as an arithmetic
# fact about this file rather than a promise about it.
# --------------------------------------------------------------------------- #

SESSION_SEEDS = 400_000
"""Base of the session seed range. Disjoint from :data:`ATTACK_SEEDS`."""

ATTACK_SEEDS = 900_000
"""Base of the adversary seed range. Disjoint from :data:`SESSION_SEEDS`."""


def _session_rng(index: int) -> np.random.Generator:
    """Return the generator for session ``index``."""
    return np.random.default_rng(SESSION_SEEDS + index)


def _attack_rng(index: int) -> np.random.Generator:
    """Return the generator for adversary ``index``, from the other range."""
    return np.random.default_rng(ATTACK_SEEDS + index)


class _Tally:
    """Running counts for one arm: acceptances, and pooled matched positions.

    Pooled over positions rather than averaged over per-run rates, because the
    mismatch rate every prediction in this file names is a *per-position*
    Bernoulli parameter. A mean of per-run rates weights a run with three scored
    positions as heavily as one with three hundred and estimates something
    nobody predicted.
    """

    def __init__(self) -> None:
        self.trials = 0
        self.accepted = 0
        self.scored = 0
        self.no_verdict = 0
        self.matched = 0
        self.mismatches = 0
        self.positions = 0

    def add(self, transcript, party: Party, key_length: int) -> None:
        """Fold one transcript's verdict for ``party`` into the tally."""
        self.trials += 1
        self.positions += key_length
        verdict = transcript.results_by_party.get(party)
        if verdict is None:
            self.no_verdict += 1
            return
        self.scored += 1
        self.accepted += int(verdict.accepted)
        self.matched += verdict.matched_count
        self.mismatches += verdict.mismatches


# --------------------------------------------------------------------------- #
# 1. Forgery on the signer seam: Eve substitutes Alice's declaration outright.
# --------------------------------------------------------------------------- #

OUTSIDE_TRIALS = 800
OUTSIDE_LENGTH = 30


@pytest.fixture(scope="module")
def outside_forgery() -> dict[Party, _Tally]:
    """Run the outside forger against both verifiers in one pass.

    Mounted on the ``signer`` seam rather than the hop, deliberately: her
    declaration then reaches *both* verifiers, so one batch of runs measures her
    against ``s_a`` and ``s_v`` at once, and unlike a recipient she is neither
    verifier, so there is no self-verification problem.
    """
    params = ProtocolParams(key_length=OUTSIDE_LENGTH)
    tallies = {party: _Tally() for party in (Party.BOB, Party.CHARLIE)}
    for index in range(OUTSIDE_TRIALS):
        session = QDSSession(
            params,
            signer=OutsideForger(rng=_attack_rng(index)),
            rng=_session_rng(index),
        )
        transcript = session.run(0)
        for party, tally in tallies.items():
            tally.add(transcript, party, OUTSIDE_LENGTH)
    return tallies


@pytest.mark.parametrize("party", [Party.BOB, Party.CHARLIE])
def test_outside_forgery_acceptance_matches_the_closed_form(
    outside_forgery, party
):
    """Her acceptance rate agrees with ``analysis.forgery_probability``."""
    tally = outside_forgery[party]
    params = ProtocolParams(key_length=OUTSIDE_LENGTH)
    predicted = forgery_probability(params, party=party)
    verdict = agrees_within(tally.accepted, tally.trials, predicted)
    assert verdict.agrees, verdict.summary()


@pytest.mark.parametrize("party", [Party.BOB, Party.CHARLIE])
def test_outside_forgery_mismatch_rate_is_the_fair_coin_the_bound_assumes(
    outside_forgery, party
):
    """Per scored position she disagrees with probability ``1/2``.

    The sharp half of the outside-forgery measurement, and the one that carries
    to ``L = 115200``: the acceptance rate is an exponential in the matched
    count and is only ever a few successes at these lengths, while this is a
    per-position Bernoulli parameter estimated over ~``8000`` positions. It is
    also the exact assumption ``forgery_probability`` is built on, so a harness
    that composed the seams wrongly would show up here first.
    """
    tally = outside_forgery[party]
    verdict = agrees_within(tally.mismatches, tally.matched, 0.5)
    assert verdict.agrees, verdict.summary()


def test_outside_forgery_leaves_the_matched_count_alone(outside_forgery):
    """A forged declaration scores a third of the key, exactly like an honest one.

    The matched set depends only on the declared bases and the recipients' own
    uniform draws, so no declaration can move it. This is why the matched-count
    floors are an evidence-liveness control and not a forgery detector, and it
    is asserted rather than repeated.
    """
    for party, tally in outside_forgery.items():
        scored_fraction = tally.matched / tally.positions
        verdict = agrees_within(tally.matched, tally.positions, 1 / 3)
        assert verdict.agrees, f"{party}: {verdict.summary()}"
        assert 0.30 < scored_fraction < 0.37


# --------------------------------------------------------------------------- #
# 2. Forgery on the forwarding hop: Bob declares his own log to Charlie.
# --------------------------------------------------------------------------- #

RECIPIENT_TRIALS = 300
RECIPIENT_LENGTH = 60
UNSYMMETRISED_TRIALS = 120


def _run_recipient_forgery(
    trials: int, *, symmetrised: bool, timing: str
) -> _Tally:
    """Mount :class:`RecipientForger` on the hop and tally Charlie's verdicts."""
    params = ProtocolParams(key_length=RECIPIENT_LENGTH)
    tally = _Tally()
    for index in range(trials):
        session = QDSSession(
            params,
            forwarder=RecipientForger(rng=_attack_rng(5_000 + index)),
            count_exchange_timing=timing,
            symmetriser=None if symmetrised else no_symmetrisation,
            rng=_session_rng(5_000 + index),
        )
        tally.add(session.run(0), Party.CHARLIE, RECIPIENT_LENGTH)
    return tally


@pytest.fixture(scope="module")
def recipient_forgery_shipped() -> _Tally:
    """The forging hop under the **shipped pooled rule**, deployment ordering.

    This arm did not exist until the count exchange grew an ordering. Under
    :data:`~sih141.protocol.session.COUNTS_BEFORE_FORWARDING` Charlie's own
    count was taken against the declaration Alice signed while he is looking at
    the one the hop delivered, so he refuses on provenance and never scores --
    50/50 runs, measured in Phase 3, which is a denial of transfer and not a
    detection, and has no acceptance probability attached to it because the
    prediction describes a Charlie who scores.
    """
    return _run_recipient_forgery(
        RECIPIENT_TRIALS, symmetrised=True, timing=COUNTS_AFTER_FORWARDING
    )


def test_recipient_forgery_acceptance_matches_the_closed_form(
    recipient_forgery_shipped,
):
    """Charlie's acceptance rate agrees with ``recipient_forgery_probability``.

    The headline of the integration pass, because it is the first measurement of
    the *shipped* protocol's recipient-forgery rate rather than of the
    pre-pooled variant.
    """
    tally = recipient_forgery_shipped
    assert tally.no_verdict == 0, (
        "Charlie reached no verdict on some runs, so this arm is measuring a "
        "denial of transfer rather than a forgery rate"
    )
    predicted = recipient_forgery_probability(
        ProtocolParams(key_length=RECIPIENT_LENGTH)
    )
    verdict = agrees_within(tally.accepted, tally.trials, predicted)
    assert verdict.agrees, verdict.summary()


def test_recipient_forgery_hits_the_symmetrisation_floor(
    recipient_forgery_shipped,
):
    """His per-position mismatch rate sits on ``1/12``, the Phase A' floor."""
    tally = recipient_forgery_shipped
    verdict = agrees_within(tally.mismatches, tally.matched, 1 / 12)
    assert verdict.agrees, verdict.summary()


def test_recipient_forgery_scores_two_thirds_of_the_key(
    recipient_forgery_shipped,
):
    """A forging recipient matches ``2/3`` where an honest run matches ``1/3``.

    Not a rate the security argument uses, but the single clearest
    transcript-level signature of this attack, and Phase 4 is told to use it:
    a depolarising channel can raise Charlie's mismatch rate and cannot move his
    matched count, which depends only on basis draws.
    """
    tally = recipient_forgery_shipped
    verdict = agrees_within(tally.matched, tally.positions, 2 / 3)
    assert verdict.agrees, verdict.summary()


@pytest.mark.parametrize(
    ("symmetrised", "floor"), [(True, 1 / 12), (False, 1 / 3)]
)
def test_symmetrisation_is_the_difference_between_one_twelfth_and_one_third(
    recipient_forgery_shipped, symmetrised, floor
):
    """Phase A' costs the forging recipient a factor of four, measured.

    Same adversary, same code path, one seam swapped. The two intervals do not
    come close to touching, and that gap is what the key length pays for.
    """
    tally = (
        recipient_forgery_shipped
        if symmetrised
        else _run_recipient_forgery(
            UNSYMMETRISED_TRIALS,
            symmetrised=False,
            timing=COUNTS_AFTER_FORWARDING,
        )
    )
    verdict = agrees_within(tally.mismatches, tally.matched, floor)
    assert verdict.agrees, verdict.summary()
    low, high = wilson_bounds(tally.mismatches, tally.matched)
    if symmetrised:
        assert high < 1 / 3, "the symmetrised floor must clear 1/3 outright"
    else:
        assert low > 1 / 12, "the unsymmetrised floor must clear 1/12 outright"


def test_the_shipped_ordering_denies_the_transfer_instead_of_detecting_it():
    """Under the default ordering Charlie reaches no verdict at all.

    Recorded as its own outcome, and asserted, because it is the exact shape of
    a result that must never be counted as a caught forgery: no verdict is
    neither an acceptance nor a rejection, and a Phase 5 table that folded it
    into the rejection column would report a detection that never happened.
    """
    tally = _run_recipient_forgery(
        12, symmetrised=True, timing=COUNTS_BEFORE_FORWARDING
    )
    assert tally.scored == 0
    assert tally.no_verdict == tally.trials


# --------------------------------------------------------------------------- #
# 3. Impersonation on Alice's two seams.
# --------------------------------------------------------------------------- #

IMPERSONATION_TRIALS = 40
IMPERSONATION_LENGTH = 96


@pytest.fixture(scope="module")
def impersonation() -> dict[str, dict[Party, _Tally]]:
    """Run the control and both partial scopes through the shipped seams."""
    params = ProtocolParams(key_length=IMPERSONATION_LENGTH)
    arms: dict[str, dict[Party, _Tally]] = {}
    for scope in ("none", "signing", "distribution"):
        tallies = {party: _Tally() for party in (Party.BOB, Party.CHARLIE)}
        for index in range(IMPERSONATION_TRIALS):
            mallory = Impersonator(rng=_attack_rng(10_000 + index))
            session = QDSSession(
                params,
                **impersonation_seams(mallory, scope),
                rng=_session_rng(10_000 + index),
            )
            transcript = session.run(0)
            for party, tally in tallies.items():
                tally.add(transcript, party, IMPERSONATION_LENGTH)
        arms[scope] = tallies
    return arms


@pytest.mark.parametrize("scope", ["signing", "distribution"])
@pytest.mark.parametrize("party", [Party.BOB, Party.CHARLIE])
def test_partial_impersonation_is_rejected_at_a_coin_flip(
    impersonation, scope, party
):
    """Seizing one of Alice's two seams leaves a mismatch rate of ``1/2``.

    A declaration uncorrelated with the states the recipients measured, which is
    the external forger of the analysis under a different name.
    """
    tally = impersonation[scope][party]
    assert tally.accepted == 0
    verdict = agrees_within(tally.mismatches, tally.matched, 0.5)
    assert verdict.agrees, f"{scope}/{party}: {verdict.summary()}"


@pytest.mark.parametrize("scope", ["signing", "distribution"])
def test_partial_impersonation_acceptance_agrees_with_the_forgery_bound(
    impersonation, scope
):
    """``0`` acceptances is what a prediction of ``~1e-08`` looks like."""
    params = ProtocolParams(key_length=IMPERSONATION_LENGTH)
    for party in (Party.BOB, Party.CHARLIE):
        tally = impersonation[scope][party]
        predicted = forgery_probability(params, party=party)
        verdict = agrees_within(tally.accepted, tally.trials, predicted)
        assert verdict.agrees, f"{scope}/{party}: {verdict.summary()}"


def test_impersonation_never_moves_the_matched_count(impersonation):
    """Every scope scores ``L/3``, control included -- so QBER is the only signal.

    This is why the two evidence floors are an evidence-liveness control rather
    than an impersonation detector, and it is the assertion that makes that
    sentence checkable.
    """
    for scope, tallies in impersonation.items():
        for party, tally in tallies.items():
            verdict = agrees_within(tally.matched, tally.positions, 1 / 3)
            assert verdict.agrees, f"{scope}/{party}: {verdict.summary()}"


def test_the_honest_control_accepts_everything_at_zero_mismatches(
    impersonation,
):
    """Without the control, the arms above measure nothing in particular."""
    for party, tally in impersonation["none"].items():
        assert tally.accepted == tally.trials, party
        assert tally.mismatches == 0, party


# --------------------------------------------------------------------------- #
# 4. Replay: the session binding and the consumed-records ledger.
# --------------------------------------------------------------------------- #

REPLAY_LENGTH = 12
REPLAY_TRIALS = 400


@pytest.mark.parametrize("defended", [True, False])
def test_straight_re_verification_is_a_rule_not_a_rate(defended):
    """Re-presenting one declaration: ``0/100`` defended, ``100/100`` not.

    Asserted as counts rather than compared against a probability, because the
    scoring rule is a pure function of the declaration and the record: it cannot
    tell a second call from a first, and the ledger that can is a rule with no
    sampling distribution behind it.
    """
    outcome = measure_straight_replay(
        params=ProtocolParams(key_length=24),
        trials=100,
        rng=_attack_rng(20_000),
        defended=defended,
    )
    assert outcome.successes == (0 if defended else outcome.trials)


def test_cross_session_pairing_undefended_agrees_with_the_forgery_bound():
    """Without the binding, a stale declaration is exactly an outside forgery.

    Which is the point: the identifier does not make a cross-round pairing
    *harder to forge*, it makes it refuse to be scored at all. Undefended, the
    rate must land on ``forgery_probability`` -- and ``L = 12`` is chosen so the
    prediction is ``0.104`` rather than ``0.013``, giving a sharp comparison in
    a few hundred trials instead of a few thousand.
    """
    params = ProtocolParams(key_length=REPLAY_LENGTH)
    outcome = measure_cross_session_pairing(
        params=params,
        trials=REPLAY_TRIALS,
        rng=_attack_rng(21_000),
        defended=False,
    )
    predicted = forgery_probability(params, party=Party.BOB)
    verdict = agrees_within(outcome.successes, outcome.trials, predicted)
    assert verdict.agrees, verdict.summary()


def test_cross_session_pairing_defended_is_refused_before_a_position_is_counted():
    """With the binding, the same pairing never reaches a rate at all."""
    outcome = measure_cross_session_pairing(
        params=ProtocolParams(key_length=REPLAY_LENGTH),
        trials=100,
        rng=_attack_rng(22_000),
        defended=True,
    )
    assert outcome.successes == 0


def test_the_ledger_state_is_reachable_from_the_transcript():
    """Phase 4 asked for the spent rounds and could not get them.

    :attr:`~sih141.protocol.session.SessionTranscript.spent_rounds` is what a
    detector needs in order to say "this verifier decided a round he was never
    presented with", and until Phase 3 it lived only on an object the verifier
    holds. One entry per verifier per round actually decided.
    """
    session = QDSSession(
        ProtocolParams(key_length=24), rng=_session_rng(23_000)
    )
    transcript = session.run(0)
    spent = transcript.spent_rounds
    assert len(spent) == 2
    parties = {entry[0] for entry in spent}
    assert parties == {Party.BOB.value, Party.CHARLIE.value}
    rounds = {entry[1] for entry in spent}
    assert rounds == {session.session_ids[0]}
    assert all(entry[2] == 0 for entry in spent)


def test_a_replay_against_a_live_session_leaves_a_trace_in_the_transcript():
    """The other half of the same Phase 4 request.

    A replay refusal must not be filed as the verifier's outcome -- doing so
    would let a replayed presentation *delete* the acceptance that spent the
    round, a larger hole than the ledger closes -- so it used to leave no trace
    at all, and a detector wanting replay statistics had nothing to read.
    :attr:`~sih141.protocol.session.SessionTranscript.replay_refusals` counts
    them beside the verdict instead of in place of it.
    """
    session = QDSSession(
        ProtocolParams(key_length=24), rng=_session_rng(24_000)
    )
    honest = session.run(0)
    assert honest.replay_refusals == ()
    for _ in range(3):
        with pytest.raises(MatchedSetTooSmall):
            session.verify(Party.BOB)
    replayed = session.transcript()
    assert replayed.replay_refusals == (("Bob", 3),)
    assert replayed.verdict_for(Party.BOB).accepted, (
        "the standing verdict must survive the replay that was refused"
    )


# --------------------------------------------------------------------------- #
# 5. Channel manipulation, on the resource line and the payload line.
# --------------------------------------------------------------------------- #

CHANNEL_ROUNDS = 8000
CHANNEL_STRENGTH = 0.2


@pytest.mark.parametrize(
    ("label", "build", "tensor"),
    [
        (
            "depolarising",
            lambda rng: DepolarisingChannel(CHANNEL_STRENGTH, rng=rng),
            depolarising_tensor(CHANNEL_STRENGTH),
        ),
        (
            "intercept-resend",
            lambda rng: InterceptResend(rng=rng),
            collapse_tensor(),
        ),
        ("kept-share", lambda rng: KeptShareSwap(rng=rng), collapse_tensor()),
    ],
)
def test_channel_qber_matches_the_correlation_tensor(label, build, tensor):
    """One tensor predicts the published QBER for every channel adversary.

    ``QBER = mean_b (1 - s_b T_bb) / 2``. The three attacks differ only in the
    tensor they produce, so a single identity covers a Pauli twirl, an
    intercept-resend and a kept share alike.
    """
    attack = build(np.random.default_rng(ATTACK_SEEDS + 30_000))
    estimate = measure_qber(
        attack.resource,
        rounds=CHANNEL_ROUNDS,
        rng=np.random.default_rng(SESSION_SEEDS + 30_000),
    )
    predicted = qber_from_tensor(tensor)
    verdict = agrees_within(estimate.errors, estimate.rounds, predicted)
    assert verdict.agrees, f"{label}: {verdict.summary()}"


def test_the_depolarising_qber_agrees_with_the_protocols_own_closed_form():
    """The attack's prediction and the protocol's must not be allowed to drift.

    :func:`~sih141.protocol.analysis.depolarising_error_rate` and
    :func:`~sih141.attacks.channel.qber_from_tensor` are two derivations of one
    quantity, written by different agents on different sides of the package
    boundary. Pinning them against each other is what stops a future edit to one
    silently invalidating every measurement checked against the other.
    """
    for strength in (0.0, 0.05, 0.14, 0.3, 0.5, 1.0):
        assert qber_from_tensor(depolarising_tensor(strength)) == pytest.approx(
            depolarising_error_rate(strength), abs=1e-12
        )


def test_the_depolarising_sampler_is_unbiased_at_p_equals_one_half():
    """Settles the one reported disagreement in the Phase 3 attack tables.

    A published batch measured ``0.2635`` on ``8000`` rounds against an exact
    prediction of ``0.2500``, with a 99% interval that excluded it -- a ``2.8``
    sigma draw, one miss in twelve comparisons at 99%. The question it raised is
    whether the *sampler* is biased, and that is settled by sample size rather
    than by a different seed: a bias survives a fortyfold increase in ``n`` and a
    fluctuation does not. Pooled over ``80000`` rounds the rate is within one
    standard error of ``p/2``.
    """
    predicted = qber_from_tensor(depolarising_tensor(0.5))
    assert predicted == 0.25
    errors = rounds = 0
    for offset in range(10):
        attack = DepolarisingChannel(
            0.5, rng=np.random.default_rng(ATTACK_SEEDS + 31_000 + offset)
        )
        estimate = measure_qber(
            attack.resource,
            rounds=CHANNEL_ROUNDS,
            rng=np.random.default_rng(SESSION_SEEDS + 31_000 + offset),
        )
        errors += estimate.errors
        rounds += estimate.rounds
    verdict = agrees_within(errors, rounds, predicted, sigmas=3.0)
    assert verdict.agrees, verdict.summary()
    assert abs(verdict.z_score) < 3.0, verdict.summary()


def test_the_kept_share_chsh_is_root_two_and_not_the_classical_bound():
    """The corrected reference value, pinned so it cannot rot back.

    A Phase 3 audit quoted ``2.0000`` for an eavesdropper keeping a share of a
    GHZ state. The kept-share marginal of ``(|000> + |111>)/sqrt(2)`` is
    ``(|00><00| + |11><11|)/2``, whose only surviving correlator is
    ``T_zz = 1``, so ``S = sqrt(2) = 1.4142``. ``2.0000`` is the *classical
    bound* -- what a separable resource may not exceed -- and is also exactly
    ``depolarising_chsh(1 - 1/sqrt(2))``, which is the likely transposition. The
    correction is operational: a detector thresholding on "does this link still
    violate the classical bound" has ``0.59`` of margin against a kept share,
    not ``0.00``.
    """
    predicted = chsh_from_tensor(collapse_tensor(("Z",)))
    assert predicted == pytest.approx(2**0.5, abs=1e-12)
    attack = KeptShareSwap(
        rng=np.random.default_rng(ATTACK_SEEDS + 32_000), axes=("Z",)
    )
    estimate = measure_chsh(
        attack.resource,
        rounds=CHANNEL_ROUNDS,
        rng=np.random.default_rng(SESSION_SEEDS + 32_000),
    )
    low, high = estimate.interval.low, estimate.interval.high
    assert low <= predicted <= high, (predicted, low, high)
    assert high < 2.0, "the measured interval must exclude the classical bound"


def test_a_one_link_channel_attack_is_attributable_from_the_check_logs():
    """Which link is compromised, end to end through a real session.

    The one statistic that both detects a party-targeted channel attack and
    *names the party*, because check logs are built inside ``distribute()`` and
    never reach the symmetriser -- so unlike the records they are not smeared
    across the two recipients. Phase 4 must estimate per link and never pool the
    two.

    The figures this asserts are the ones ``docs/PHASE3.md`` §4 quotes, and the
    length is twice what it was: a plan now deals its reserved rounds between
    the two links (:ref:`sih141.protocol.checkrounds <check-round-links>`), so a
    fixed ``(L, check_fraction)`` puts half as many rounds on each link as it
    used to and every per-link interval is ``sqrt(2)`` wider. At the old
    ``L = 384`` the two intervals now overlap on two session seeds in eight --
    the attack is still detected, and no longer reliably *attributed*. Doubling
    ``L`` buys the sample back.
    """
    # The sample size is the point of the test rather than an inconvenience:
    # attribution is a sample-size property. At L = 96 the same attack is
    # plainly *detected* on Bob's link and the two links' 99% intervals still
    # overlap, so a detector could not name the compromised party. The
    # check-round arm has to be sized for the question being asked of it, which
    # is what :func:`~sih141.protocol.checkrounds.required_check_rounds` is for.
    params = ProtocolParams(key_length=768, check_fraction=0.5)
    attack = DepolarisingChannel(
        0.3, rng=np.random.default_rng(ATTACK_SEEDS + 33_000), target=Party.BOB
    )
    session = QDSSession(
        params,
        resource_factory=attack.resource,
        rng=np.random.default_rng(SESSION_SEEDS + 33_000),
    )
    transcript = session.run(0)
    per_party = {}
    for party in (Party.BOB, Party.CHARLIE):
        observations = [
            observation
            for bit in (0, 1)
            for observation in transcript.check_log_for(party, bit).qber
        ]
        estimate = estimate_qber(observations)
        per_party[party] = (estimate.errors, estimate.rounds)

    bob_errors, bob_rounds = per_party[Party.BOB]
    charlie_errors, charlie_rounds = per_party[Party.CHARLIE]
    assert bob_rounds > 0 and charlie_rounds > 0
    assert bob_rounds == charlie_rounds, (
        "the deal must give the two links equal-sized samples, or one link's "
        "interval is wider than the other's for a reason a reader cannot see"
    )
    # The arithmetic the sample size rests on, stated so that a future change to
    # the deal fails here and not two paragraphs of prose away: each link
    # measures half of `check_count` reserved positions per message bit, and
    # those halves are split again between the QBER and the CHSH arm.
    assert 2 * bob_rounds + 2 * len(
        [
            observation
            for bit in (0, 1)
            for observation in transcript.check_log_for(Party.BOB, bit).chsh
        ]
    ) == 2 * params.check_count, (
        "Bob's QBER and CHSH observations, over both message bits, must "
        "account for exactly half the run's reserved positions"
    )
    assert charlie_errors == 0, "Charlie's link was never touched"
    verdict = agrees_within(bob_errors, bob_rounds, 0.15)
    assert verdict.agrees, verdict.summary()
    bob_low, _ = wilson_bounds(bob_errors, bob_rounds, z=2.5758293035489004)
    _, charlie_high = wilson_bounds(
        charlie_errors, charlie_rounds, z=2.5758293035489004
    )
    assert bob_low > charlie_high, (
        "the two links' 99% intervals must be disjoint, or the attack is "
        "detected but not attributed"
    )
    # Pinned exactly, because docs/PHASE3.md quotes them and a figure that only
    # lives in prose is the failure mode this project has already shipped five
    # times.
    assert (bob_errors, bob_rounds) == (33, 192), (bob_errors, bob_rounds)
    assert (charlie_errors, charlie_rounds) == (0, 192)
    assert f"{bob_low:.4f}" == "0.1130"
    assert f"{charlie_high:.4f}" == "0.0334"


def test_the_payload_line_is_invisible_to_the_check_round_arm():
    """A limitation, asserted rather than described.

    A check round teleports no payload, so what ``payload_map`` returns there is
    thrown away: an adversary on the payload line wrecks the key while the
    published QBER reports a perfect channel. A Phase 4 detector keyed off
    channel quality alone sees nothing here; the signal that survives is the
    verifiers' own mismatch rate.

    The seam *is* called on a check round -- at every position, key round and
    check round alike, so that its call sequence carries nothing about the plan
    (:ref:`sih141.protocol.distribute <payload-seam>`). It is the result that
    never reaches the published statistics, not the call, and this test is about
    the result.
    """
    params = ProtocolParams(key_length=96, check_fraction=0.5)
    attack = InterceptResend(rng=np.random.default_rng(ATTACK_SEEDS + 34_000))
    session = QDSSession(
        params,
        payload_map=attack.payload,
        rng=np.random.default_rng(SESSION_SEEDS + 34_000),
    )
    transcript = session.run(0)
    published = [
        estimate_qber(transcript.check_log_for(party, bit).qber)
        for party in (Party.BOB, Party.CHARLIE)
        for bit in (0, 1)
    ]
    assert published, "the run must have published check statistics at all"
    assert all(estimate.errors == 0 for estimate in published)
    bob = transcript.results_by_party.get(Party.BOB)
    assert bob is not None
    assert not bob.accepted
    assert bob.rate > 0.2, "the key really was wrecked while the link looked clean"


# --------------------------------------------------------------------------- #
# 6. Count starvation on the count-exchange seam.
# --------------------------------------------------------------------------- #

STARVATION_TRIALS = 20
STARVATION_LENGTH = 192


@pytest.fixture(scope="module")
def starvation() -> dict[str, list]:
    """Run the honest control and the starving arm through the shipped seam."""
    params = ProtocolParams(key_length=STARVATION_LENGTH)
    arms: dict[str, list] = {}
    for label, seam in (
        ("control", None),
        ("starving", "attack"),
    ):
        transcripts = []
        for index in range(STARVATION_TRIALS):
            starver = (
                None
                if seam is None
                else CountStarver(rng=_attack_rng(40_000 + index))
            )
            session = QDSSession(
                params,
                count_exchange=starver,
                rng=_session_rng(40_000 + index),
            )
            transcripts.append(session.run(0))
        arms[label] = transcripts
    return arms


def test_count_starvation_denies_a_verdict_deterministically(starvation):
    """A rule, not a rate: every starving run denies, every control run does not.

    The denial is exact arithmetic on two floors, so it is not a probability and
    is not compared against one. It costs the adversary one integer -- no key
    material, no quantum resource, no computation.
    """
    for transcript in starvation["control"]:
        assert transcript.is_complete
        assert not transcript.aborts
    for transcript in starvation["starving"]:
        assert not transcript.is_complete
        assert Party.BOB in transcript.aborts_by_party


def test_the_starver_keeps_his_own_verdict(starvation):
    """The denial is one-sided, and the transcript shows the contradiction.

    A starving Charlie still reaches his own verdict -- his own count comes from
    his own record and only the counterpart's comes over the exchange -- so one
    transcript holds a declared count far below the floor beside a scored
    matched count of roughly ``L/3``. He cannot suppress it from inside this
    seam, which makes it a transferability inversion: the starver keeps an
    acceptance the party Alice signed to cannot get.
    """
    for transcript in starvation["starving"]:
        charlie = transcript.results_by_party.get(Party.CHARLIE)
        assert charlie is not None and charlie.accepted
        assert transcript.pooled is not None
        declared = transcript.pooled.count_for(Party.CHARLIE)
        assert declared < charlie.matched_count


def test_every_starving_declaration_lands_inside_the_detectable_region(
    starvation,
):
    """He cannot look normal, and that is a theorem rather than a measurement.

    Both floors are the same Chernoff tail, so the quietest *denying*
    declaration sits a fixed number of honest standard deviations below the mean
    whatever the key length -- converging on ``-11.54``. Here every declaration
    is checked to be below ``m_min``, which is where
    :func:`~sih141.attacks.starvation.denial_headroom` says it must be, and the
    ``L``-independence is checked at :data:`DEFAULT_PARAMS` where no session
    could be run.
    """
    params = ProtocolParams(key_length=STARVATION_LENGTH)
    floor = minimum_matched_count(params)
    for transcript in starvation["starving"]:
        assert transcript.pooled is not None
        declared = transcript.pooled.count_for(Party.CHARLIE)
        assert declared <= denial_headroom(
            transcript.pooled.count_for(Party.BOB), params
        )
        assert declared < floor
    # The L-independence claim is about lengths at which the floors are live.
    # At L = 192 both are degenerate -- m_min is a handful of positions -- and
    # the quietest denying declaration is only -9.80 sd out; the constant is
    # approached from below as L grows, and DEFAULT_PARAMS is where it matters.
    assert least_implausible_z(ProtocolParams(key_length=600)) < -11.5
    assert least_implausible_z(ProtocolParams(key_length=1200)) < -11.5
    assert least_implausible_z(DEFAULT_PARAMS) < -11.5
    assert least_implausible_z(params) < -9.0


# --------------------------------------------------------------------------- #
# 7. The honest baseline every arm above is a departure from.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "timing", [COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING]
)
def test_an_unattacked_run_is_transferable_under_either_ordering(timing):
    """No arm above means anything without this one.

    The two orderings differ only in which declaration Phase C' counted, and on
    an honest run there is only one declaration, so they must agree on every
    number the run produced. If they did not, the ordering would be changing the
    protocol rather than naming an experiment.
    """
    params = ProtocolParams(key_length=192)
    for index in range(8):
        session = QDSSession(
            params, count_exchange_timing=timing, rng=_session_rng(50_000 + index)
        )
        transcript = session.run(0)
        assert transcript.transferable
        assert not transcript.repudiated
        assert not transcript.aborted
        for party in (Party.BOB, Party.CHARLIE):
            assert transcript.verdict_for(party).rate == 0.0


def test_the_two_orderings_agree_position_for_position_on_an_honest_run():
    """Same seed, same records, same verdicts -- the ordering names an experiment.

    Asserted on the transcripts rather than on a summary statistic, because a
    difference in the pooled count or a verdict would be exactly the kind of
    silent divergence that makes two arms incomparable.
    """
    params = ProtocolParams(key_length=192)
    before = QDSSession(
        params,
        count_exchange_timing=COUNTS_BEFORE_FORWARDING,
        rng=_session_rng(51_000),
    ).run(0)
    after = QDSSession(
        params,
        count_exchange_timing=COUNTS_AFTER_FORWARDING,
        rng=_session_rng(51_000),
    ).run(0)
    assert before.records == after.records
    assert before.signature == after.signature
    assert before.results == after.results
    assert before.pooled == after.pooled
    assert before.spent_rounds == after.spent_rounds
    assert before.count_exchange_timing != after.count_exchange_timing


def test_the_pre_pooled_arm_is_labelled_in_the_transcript_it_produces():
    """An insecure arm has to be unmistakable in the record it leaves.

    ``no_count_exchange`` is a legitimate Phase 3 configuration and a broken
    protocol, so the transcript of a run made with it must not be quotable as
    describing the shipped scheme. ``pooled is None`` is that label.
    """
    session = QDSSession(
        ProtocolParams(key_length=192),
        count_exchange=no_count_exchange,
        rng=_session_rng(52_000),
    )
    transcript = session.run(0)
    assert transcript.pooled is None
    assert not transcript.counts_exchanged
    # pooled_matched_count is derived from the two verdicts and survives, which
    # is right -- the evidence base existed, the recipients simply never
    # compared it. `pooled is None` is the label that says the floor was not
    # applied, and it is the one a Phase 5 table must read.
    assert transcript.pooled_matched_count is not None
