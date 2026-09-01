"""Tests for :mod:`sih141.attacks.channel` -- the eavesdropper on the wire.

Four things have to hold, and they are different in kind.

1. **D6.** Every adversary here owns its randomness. This is not asserted by
   reading the source; it is established behaviourally by
   :func:`sih141.attacks.isolation.assert_attack_isolated` against a probe that
   wires the attack into a real :class:`~sih141.protocol.session.QDSSession`,
   holds everything the adversary legitimately observes fixed, and varies the
   two seeds independently.
2. **The physics is what the module says it is.** Every rate the module predicts
   is predicted from a three-number correlation tensor, and every predicted rate
   is checked against a measured one at a sample size where the interval is
   narrow enough for the comparison to mean something. A prediction that only
   ever agrees with itself is not a prediction.
3. **The reference values.** A previous auditor recorded four CHSH figures. Three
   are confirmed here; ``2.0000`` for a kept GHZ share is **corrected** to
   ``sqrt(2) = 1.4142``, with the derivation pinned so the correction cannot
   silently rot back.
4. **Attribution.** Symmetrisation smears a one-link attack across both records.
   The check logs are not symmetrised, so per-link attribution survives in them.
   Both halves of that are measured.

Sample sizes here are chosen for statistics at a demo scale and are stated as
such: no number in this file is a security claim, and at ``L`` below ``140``
neither floor of the protocol carries one either.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from sih141.attacks.channel import (
    IDEAL_TENSOR,
    PAULI_AXES,
    AttackDecision,
    ChannelAttack,
    DepolarisingChannel,
    InterceptResend,
    KeptShareSwap,
    attribution_survives_symmetrisation,
    chsh_from_tensor,
    collapse_tensor,
    depolarising_tensor,
    measure_chsh,
    measure_qber,
    payload_line_is_unwatched,
    qber_from_tensor,
)
from sih141.attacks.isolation import assert_attack_isolated
from sih141.core.states import as_density, concurrence, purity
from sih141.protocol.checkrounds import (
    CLASSICAL_CHSH_BOUND,
    IDEAL_CHSH,
    depolarising_chsh,
)
from sih141.protocol.distribute import ResourceContext, ideal_resource
from sih141.protocol.keys import KeyElement
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import QDSSession

# --------------------------------------------------------------------------- #
# Sample sizes and seeds                                                       #
# --------------------------------------------------------------------------- #

CAMPAIGN_ROUNDS = 4000
"""Rounds per arm for a prediction-versus-measurement comparison.

Enough that the Wilson half-width on a rate near ``1/3`` is about ``0.019`` and
the normal half-width on ``S`` is about ``0.10``, so an interval covering the
prediction is evidence rather than a formality; small enough that the whole file
runs in well under a minute.
"""

ATTACK_SEED = 24601
"""Eve's own seed. Never the session's -- that is the whole of D6."""

SESSION_SEED = 90210
"""The harness's seed, deliberately different from :data:`ATTACK_SEED`."""

HOP = ResourceContext(party=Party.BOB, message_bit=0, position=0)
"""One hop, for tests that only need to see what a single call produces."""


def _hops(count: int, party: Party = Party.BOB) -> list[ResourceContext]:
    """Return ``count`` consecutive hop contexts on one link."""
    return [
        ResourceContext(party=party, message_bit=0, position=index)
        for index in range(count)
    ]


# ==========================================================================
# 1. D6: every adversary owns its randomness
# ==========================================================================


def _resource_probe(attack: ChannelAttack, session_seed: int) -> object:
    """Wire the attack onto ``resource_factory`` and read back its own log.

    A real session, because the point of the check is that the *wiring* does not
    leak: an attack that reached the session's generator through the seam would
    be caught here and nowhere else.
    """
    params = ProtocolParams(key_length=24, check_fraction=0.25)
    session = QDSSession(
        params,
        resource_factory=attack.resource,
        rng=np.random.default_rng(session_seed),
    )
    session.distribute()
    return attack.decisions()


def _payload_probe(attack: ChannelAttack, session_seed: int) -> object:
    """Wire the attack onto ``payload_map`` and read back its own log.

    ``check_fraction`` is **zero** here, and that is not an arbitrary choice. The
    payload seam is called on key rounds only, and which positions are key rounds
    is decided by the recipients' check plan, which is drawn from the session's
    generator. So the *set of positions the seam is offered* legitimately moves
    with the session seed even for a perfectly isolated adversary, and a probe
    that reported those positions would fail an honest attack. With no check
    rounds every position is a key round and the call set is fixed, leaving only
    the adversary's own choices to vary. See the module's seam notes.
    """
    params = ProtocolParams(key_length=24)
    session = QDSSession(
        params,
        payload_map=attack.payload,
        rng=np.random.default_rng(session_seed),
    )
    session.distribute()
    return attack.decisions()


ADVERSARIES = {
    "depolarising": lambda *, rng: DepolarisingChannel(0.14, rng=rng),
    "intercept_resend": lambda *, rng: InterceptResend(rng=rng),
    "kept_share": lambda *, rng: KeptShareSwap(rng=rng),
    "targeted_depolarising": lambda *, rng: DepolarisingChannel(
        0.14, rng=rng, target=Party.BOB
    ),
}
"""Every adversary in the module, in the configuration it is measured in."""


@pytest.mark.parametrize("name", sorted(ADVERSARIES))
@pytest.mark.parametrize(
    "probe", [_resource_probe, _payload_probe], ids=["resource", "payload"]
)
def test_every_adversary_owns_its_randomness(name, probe):
    """D6, behaviourally, on both seams and for every attack in the module."""
    report = assert_attack_isolated(ADVERSARIES[name], probe, name=name)
    assert report.isolated
    assert not report.reads_the_session
    assert report.uses_its_own_generator


def test_the_isolation_check_would_catch_a_session_seed_peeker():
    """The negative control, so the check above is not passing vacuously.

    An adversary that seeds itself from the session is exactly the defect D6
    forbids, and it must be caught *through this module's own seam*, not only in
    :mod:`sih141.attacks.isolation`'s toy setting.
    """

    def build(*, rng: np.random.Generator, session_seed: int):
        del rng  # The whole point: it is ignored in favour of the session's.
        return DepolarisingChannel(
            0.5, rng=np.random.default_rng(session_seed)
        )

    from sih141.attacks.isolation import check_attack_isolation

    report = check_attack_isolation(build, _resource_probe, name="peeker")
    assert report.session_seed_offered
    assert report.reads_the_session
    assert not report.isolated


def test_the_constructor_refuses_a_missing_generator():
    """``rng`` is required, and ``None`` is not a shortcut to one."""
    with pytest.raises(TypeError, match="owns its randomness"):
        DepolarisingChannel(0.1, rng=None)  # type: ignore[arg-type]


# ==========================================================================
# 2. The tensor identity, and the predictions that come out of it
# ==========================================================================


def test_the_chsh_identity_agrees_with_the_protocols_own_prediction():
    """``sqrt(2)(T_zz + T_xx)`` must reproduce ``depolarising_chsh`` exactly."""
    for step in range(21):
        strength = step / 20
        assert chsh_from_tensor(depolarising_tensor(strength)) == pytest.approx(
            depolarising_chsh(strength), abs=1e-12
        )


def test_the_qber_identity_agrees_with_the_protocols_own_prediction():
    """A Werner resource of strength ``p`` mismatches at ``p / 2``."""
    from sih141.protocol.analysis import depolarising_error_rate

    for step in range(21):
        strength = step / 20
        assert qber_from_tensor(depolarising_tensor(strength)) == pytest.approx(
            depolarising_error_rate(strength), abs=1e-12
        )


def test_the_ideal_tensor_is_anticorrelated_in_y():
    """The sign that decides whether a clean channel reads ``0`` or ``1/3``."""
    assert IDEAL_TENSOR == (1.0, -1.0, 1.0)
    assert qber_from_tensor(IDEAL_TENSOR) == 0.0
    assert chsh_from_tensor(IDEAL_TENSOR) == pytest.approx(IDEAL_CHSH)


def test_a_y_axis_defect_is_invisible_to_the_bell_test():
    """The CHSH settings lie in the x-z plane, so ``T_yy`` cannot reach ``S``.

    Stated as a test because it is a real blind spot of the check-round design
    and Phase 4 must not assume the Bell arm sees everything the QBER arm does.
    """
    defect = (1.0, 0.0, 1.0)
    assert chsh_from_tensor(defect) == chsh_from_tensor(IDEAL_TENSOR)
    assert qber_from_tensor(defect) > qber_from_tensor(IDEAL_TENSOR)


def test_the_collapse_tensor_is_the_mean_of_signed_unit_tensors():
    """Both collapse attacks share one prediction, and this is it."""
    assert collapse_tensor(("Z",)) == (0.0, 0.0, 1.0)
    assert collapse_tensor(("X",)) == (1.0, 0.0, 0.0)
    assert collapse_tensor(("Y",)) == (0.0, -1.0, 0.0)
    assert collapse_tensor() == pytest.approx((1 / 3, -1 / 3, 1 / 3))


# ==========================================================================
# 3. What each attack actually delivers, one round at a time
# ==========================================================================


def test_an_untargeted_hop_is_delivered_clean():
    """A link the attack is not aimed at gets the ideal pair, unchanged."""
    attack = DepolarisingChannel(
        1.0, rng=np.random.default_rng(ATTACK_SEED), target=Party.BOB
    )
    charlie = ResourceContext(
        party=Party.CHARLIE, message_bit=0, position=0
    )
    delivered = as_density(attack.resource(charlie))
    assert delivered == as_density(ideal_resource())
    assert attack.log[0].engaged is False
    assert attack.engaged_count == 0


def test_intercept_resend_leaves_a_pure_product_state():
    """Its fingerprint: purity ``1``, concurrence ``0``, both wings pure."""
    from qiskit.quantum_info import partial_trace

    attack = InterceptResend(rng=np.random.default_rng(ATTACK_SEED))
    for hop in _hops(12):
        delivered = as_density(attack.resource(hop))
        assert purity(delivered) == pytest.approx(1.0)
        assert concurrence(delivered) == pytest.approx(0.0, abs=1e-9)
        assert purity(partial_trace(delivered, [1])) == pytest.approx(1.0)
        assert purity(partial_trace(delivered, [0])) == pytest.approx(1.0)


def test_a_kept_share_leaves_a_rank_two_mixture_with_maximally_mixed_wings():
    """Its fingerprint, and the one thing that tells it from intercept-resend."""
    from qiskit.quantum_info import partial_trace

    attack = KeptShareSwap(rng=np.random.default_rng(ATTACK_SEED))
    for hop in _hops(12):
        delivered = as_density(attack.resource(hop))
        assert purity(delivered) == pytest.approx(0.5)
        assert concurrence(delivered) == pytest.approx(0.0, abs=1e-9)
        assert purity(partial_trace(delivered, [1])) == pytest.approx(0.5)
        assert purity(partial_trace(delivered, [0])) == pytest.approx(0.5)


def test_the_two_collapse_attacks_are_indistinguishable_to_any_correlator():
    """Same tensor, different purity. The whole of the Phase 4 story in one test.

    Averaging intercept-resend's pure outputs over its own randomness gives
    exactly the kept share's mixed output, so no correlator -- QBER or CHSH, at
    any sample size -- can separate them. Only
    :attr:`~sih141.protocol.session.ChannelSample.purity` can.
    """
    intercept = InterceptResend(rng=np.random.default_rng(7), axes=("Z",))
    kept = KeptShareSwap(rng=np.random.default_rng(7), axes=("Z",))
    assert intercept.tensor == kept.tensor

    average = np.zeros((4, 4), dtype=complex)
    trials = 2000
    for hop in _hops(trials):
        average += np.asarray(as_density(intercept.resource(hop)).data)
    average /= trials
    kept_state = np.asarray(as_density(kept.resource(HOP)).data)
    # Monte Carlo over Eve's own outcomes, so the agreement is statistical: at
    # 2000 rounds the standard error on a diagonal entry is 0.011, and the
    # tolerance is three of those. The *ensemble* identity is exact.
    assert np.allclose(average, kept_state, atol=0.034)

    assert purity(as_density(intercept.resource(HOP))) == pytest.approx(1.0)
    assert purity(as_density(kept.resource(HOP))) == pytest.approx(0.5)


def test_a_pauli_twirl_leaves_the_pair_maximally_entangled_every_round():
    """The depolariser hides from purity and concurrence, and only from them.

    A twirled Bell pair is still a Bell pair, so a channel monitor watching
    purity, concurrence or wing symmetry sees nothing at all. Fidelity to
    ``|Phi+>`` is the one built-in summary that moves, and it moves to ``0`` on
    the engaged rounds rather than drifting.
    """
    from sih141.core.states import BellState, bell_state, fidelity

    attack = DepolarisingChannel(1.0, rng=np.random.default_rng(ATTACK_SEED))
    reference = bell_state(BellState.PHI_PLUS)
    seen = set()
    for hop in _hops(40):
        delivered = as_density(attack.resource(hop))
        assert purity(delivered) == pytest.approx(1.0)
        assert concurrence(delivered) == pytest.approx(1.0)
        seen.add(round(fidelity(delivered, reference), 9))
    assert seen == {0.0, 1.0}


# ==========================================================================
# 4. Prediction versus measurement, and the four reference values
# ==========================================================================


CAMPAIGNS = [
    ("ideal", lambda: None, IDEAL_TENSOR, IDEAL_CHSH),
    (
        "depolarising p=0.3",
        lambda: DepolarisingChannel(0.3, rng=np.random.default_rng(31)),
        depolarising_tensor(0.3),
        1.9799,
    ),
    (
        "intercept-resend",
        lambda: InterceptResend(rng=np.random.default_rng(32)),
        collapse_tensor(),
        0.9428,
    ),
    (
        "kept GHZ share",
        lambda: KeptShareSwap(rng=np.random.default_rng(33), axes=("Z",)),
        collapse_tensor(("Z",)),
        math.sqrt(2.0),
    ),
]
"""The four configurations whose CHSH values a previous auditor recorded."""


@pytest.mark.parametrize(
    "name,build,tensor,expected", CAMPAIGNS, ids=[row[0] for row in CAMPAIGNS]
)
def test_the_measured_statistics_cover_the_predictions(
    name, build, tensor, expected
):
    """Measure both arms and require both intervals to cover the prediction."""
    del name
    attack = build()
    factory = (
        (lambda context: ideal_resource())
        if attack is None
        else attack.resource
    )
    qber = measure_qber(
        factory, rounds=CAMPAIGN_ROUNDS, rng=np.random.default_rng(9001)
    )
    chsh = measure_chsh(
        factory, rounds=CAMPAIGN_ROUNDS, rng=np.random.default_rng(9002)
    )
    assert qber.interval.covers(qber_from_tensor(tensor))
    assert chsh.interval.covers(chsh_from_tensor(tensor))
    assert chsh.interval.covers(expected)
    assert chsh_from_tensor(tensor) == pytest.approx(expected, abs=5e-5)


def test_the_kept_share_reference_value_of_two_is_wrong():
    """A kept GHZ share gives ``1.4142``, not ``2.0000``. Correction, pinned.

    ``2.0000`` is :data:`~sih141.protocol.checkrounds.CLASSICAL_CHSH_BOUND`, and
    also the value :func:`~sih141.protocol.checkrounds.depolarising_chsh`
    returns at ``p = 1 - 1/sqrt(2)``. It is what a separable resource cannot
    *exceed*; it is not what this one attains. The marginal of the GHZ state is
    ``(|00><00| + |11><11|)/2``, whose only surviving correlator is
    ``T_zz = 1``, so ``S = sqrt(2)``.

    The distinction matters operationally: a detector thresholding at "does the
    link still violate the classical bound" would flag this attack with ``0.59``
    of margin, not with ``0``.
    """
    predicted = chsh_from_tensor(collapse_tensor(("Z",)))
    assert predicted == pytest.approx(math.sqrt(2.0), abs=1e-12)
    assert predicted < CLASSICAL_CHSH_BOUND
    assert not math.isclose(predicted, 2.0, abs_tol=0.5)

    attack = KeptShareSwap(rng=np.random.default_rng(34), axes=("Z",))
    measured = measure_chsh(
        attack.resource,
        rounds=CAMPAIGN_ROUNDS,
        rng=np.random.default_rng(9003),
    )
    assert measured.interval.covers(predicted)
    assert measured.interval.excludes(2.0)


def test_a_random_axis_kept_share_is_weaker_still():
    """Drawing the axis costs Eve entanglement she was not using anyway."""
    fixed = chsh_from_tensor(collapse_tensor(("Z",)))
    drawn = chsh_from_tensor(collapse_tensor())
    assert drawn < fixed < CLASSICAL_CHSH_BOUND
    assert qber_from_tensor(collapse_tensor(("Z",))) == pytest.approx(
        qber_from_tensor(collapse_tensor())
    )


# ==========================================================================
# 5. Party targeting, and what survives symmetrisation
# ==========================================================================


def test_targeting_engages_on_one_link_only():
    """The attack acts iff ``context.party`` is the target."""
    attack = DepolarisingChannel(
        1.0, rng=np.random.default_rng(ATTACK_SEED), target=Party.CHARLIE
    )
    for party in (Party.BOB, Party.CHARLIE):
        for hop in _hops(10, party=party):
            attack.resource(hop)
    engaged = {
        entry.party for entry in attack.log if entry.engaged
    }
    assert engaged == {Party.CHARLIE}


def test_a_targeted_attack_separates_the_two_links_in_the_check_arms():
    """The unsymmetrised, per-link view: one link damaged, the other pristine."""
    attack = DepolarisingChannel(
        0.3, rng=np.random.default_rng(ATTACK_SEED), target=Party.BOB
    )
    rates = {}
    for party in (Party.BOB, Party.CHARLIE):
        rates[party] = measure_qber(
            attack.resource,
            rounds=CAMPAIGN_ROUNDS,
            rng=np.random.default_rng(9004),
            party=party,
        )
    assert rates[Party.BOB].interval.covers(0.15)
    assert rates[Party.CHARLIE].errors == 0
    assert rates[Party.BOB].interval.low > rates[Party.CHARLIE].interval.high


def test_targeting_alice_is_refused():
    """She is the far end of both links, so she names no link."""
    with pytest.raises(ValueError, match="far end of both links"):
        DepolarisingChannel(
            0.1, rng=np.random.default_rng(1), target=Party.ALICE
        )


def test_check_logs_keep_the_attribution_that_the_records_lose():
    """The headline: symmetrisation smears records and does not touch logs.

    Both halves in one run. In the records the damaged link and the clean one
    land on top of each other at roughly half the one-link rate each, which is
    exactly the ``q`` -> ``q/2`` smearing the brief describes. In the check logs
    the two are still separated, with disjoint intervals.
    """
    outcome = attribution_survives_symmetrisation()

    # Records: smeared. The unsymmetrised companion shows what was smeared.
    assert not outcome.records_attributable(margin=0.02)
    unsymmetrised = sorted(outcome.unsymmetrised_rate.values())
    assert unsymmetrised[0] == 0.0
    assert unsymmetrised[1] > 0.03
    smeared = sorted(outcome.record_rate.values())
    assert smeared[0] > 0.0
    assert max(smeared) < unsymmetrised[1]

    # Check logs: not smeared, and the separation is interval-disjoint.
    assert outcome.attributable(margin=0.02)
    assert outcome.intervals_disjoint()
    assert outcome.check_qber[Party.CHARLIE] == 0.0
    assert outcome.check_qber[Party.BOB] > 0.03


def test_the_two_seeds_must_differ():
    """A campaign run from one seed would be a campaign Eve already knew."""
    with pytest.raises(ValueError, match="must differ"):
        attribution_survives_symmetrisation(attack_seed=5, session_seed=5)
    with pytest.raises(ValueError, match="must differ"):
        payload_line_is_unwatched(attack_seed=5, session_seed=5)


# ==========================================================================
# 6. The payload line, and why the check rounds cannot see it
# ==========================================================================


def test_the_payload_seam_is_never_offered_a_check_round():
    """The structural fact the next test measures the consequence of."""
    params = ProtocolParams(key_length=64, check_fraction=0.25)
    attack = InterceptResend(rng=np.random.default_rng(ATTACK_SEED))
    session = QDSSession(
        params,
        payload_map=attack.payload,
        rng=np.random.default_rng(SESSION_SEED),
    )
    session.distribute()
    for bit, plan in session.check_plans.items():
        offered = {
            entry.position
            for entry in attack.log
            if entry.message_bit == bit
        }
        assert offered.isdisjoint(set(plan.positions))
        assert offered == set(plan.signing_positions)


def test_a_payload_attack_wrecks_the_key_and_moves_no_statistic():
    """The Phase 4 blocker, measured rather than asserted.

    The same adversary on the two seams does comparable damage to the key. On
    the resource line both published statistics collapse. On the payload line
    the QBER arm reports a *perfect* channel and the Bell test still violates
    the classical bound at close to Tsirelson.
    """
    seen = payload_line_is_unwatched()

    assert seen["resource_record_rate"] > 0.25
    assert seen["payload_record_rate"] > 0.25

    assert seen["resource_qber"] > 0.25
    assert seen["resource_chsh"] < CLASSICAL_CHSH_BOUND

    assert seen["payload_qber"] == 0.0
    assert seen["payload_chsh"] > CLASSICAL_CHSH_BOUND
    assert seen["payload_chsh"] == pytest.approx(IDEAL_CHSH, abs=0.15)


def test_the_payload_line_reproduces_its_predicted_error_rate():
    """A payload attack's damage is the same tensor arithmetic as a channel's."""
    from sih141.core.measure import projective_measure

    trials = 3000
    for attack, predicted in (
        (DepolarisingChannel(0.3, rng=np.random.default_rng(41)), 0.15),
        (InterceptResend(rng=np.random.default_rng(42)), 1 / 3),
        (KeptShareSwap(rng=np.random.default_rng(43)), 1 / 3),
    ):
        rng = np.random.default_rng(9005)
        errors = 0
        for index in range(trials):
            basis = PAULI_AXES[int(rng.integers(3))]
            eigenvalue = 1 if rng.integers(2) else -1
            element = KeyElement(basis, eigenvalue)
            hop = ResourceContext(
                party=Party.BOB, message_bit=0, position=index
            )
            sent = attack.payload(element.state(), hop)
            outcome = projective_measure(
                as_density(sent), 0, basis, rng=rng
            )
            errors += outcome.eigenvalue != eigenvalue
        rate = errors / trials
        assert rate == pytest.approx(predicted, abs=0.03)


# ==========================================================================
# 7. Wiring, validation and the log
# ==========================================================================


def test_both_seams_accept_the_bound_methods_they_are_given():
    """The attack must mount without a wrapper on either seam."""
    from sih141.protocol.distribute import _accepts_context

    attack = KeptShareSwap(rng=np.random.default_rng(ATTACK_SEED))
    assert _accepts_context(attack.resource) is True

    params = ProtocolParams(key_length=32, check_fraction=0.25)
    session = QDSSession(
        params,
        resource_factory=attack.resource,
        payload_map=attack.payload,
        rng=np.random.default_rng(SESSION_SEED),
    )
    session.distribute()
    assert attack.engaged_count == len(attack.log)
    assert len(attack.log) > 0


def test_the_log_records_every_hop_in_call_order():
    """One entry per offered hop, engaged or not, in the order they arrived."""
    attack = DepolarisingChannel(
        0.5, rng=np.random.default_rng(ATTACK_SEED), target=Party.BOB
    )
    hops = _hops(5, party=Party.BOB) + _hops(5, party=Party.CHARLIE)
    for hop in hops:
        attack.resource(hop)
    assert len(attack.log) == len(hops)
    assert [entry.position for entry in attack.log] == [
        hop.position for hop in hops
    ]
    assert all(isinstance(entry, AttackDecision) for entry in attack.log)
    assert attack.decisions()[0][0] == Party.BOB.value


def test_the_log_distinguishes_an_identity_twirl_from_an_untouched_hop():
    """Both leave the state alone; only one of them consumed a decision."""
    attack = DepolarisingChannel(1.0, rng=np.random.default_rng(2))
    for hop in _hops(60):
        attack.resource(hop)
    choices = {entry.choice for entry in attack.log}
    assert "I" in choices
    assert "pass" not in choices
    assert attack.engaged_count == 60


@pytest.mark.parametrize("bad", [-0.1, 1.5, float("nan")])
def test_a_strength_outside_the_unit_interval_is_refused(bad):
    """It is the fraction of hops attacked, so it is a probability."""
    with pytest.raises(ValueError, match="probability"):
        DepolarisingChannel(bad, rng=np.random.default_rng(1))


def test_a_boolean_strength_is_refused():
    """``True`` is not ``1.0`` here; it is a typo."""
    with pytest.raises(TypeError, match="boolean"):
        DepolarisingChannel(True, rng=np.random.default_rng(1))


def test_an_empty_axis_alphabet_is_refused():
    """An eavesdropper with no basis to guess in is not an attack."""
    with pytest.raises(ValueError, match="at least one measurement axis"):
        InterceptResend(rng=np.random.default_rng(1), axes=())


def test_a_bare_string_axis_alphabet_is_refused():
    """``"XY"`` would iterate character by character and silently mean two."""
    with pytest.raises(TypeError, match="not the string"):
        KeptShareSwap(rng=np.random.default_rng(1), axes="XY")


def test_an_unknown_axis_is_refused():
    """The alphabet is the protocol's, and nothing else is in it."""
    with pytest.raises(ValueError, match="Pauli bases"):
        InterceptResend(rng=np.random.default_rng(1), axes=("W",))


def test_the_base_class_refuses_to_be_mounted():
    """``ChannelAttack`` holds the shared machinery and no physics."""
    attack = ChannelAttack(rng=np.random.default_rng(1))
    with pytest.raises(NotImplementedError, match="_act_on_resource"):
        attack.resource(HOP)
    with pytest.raises(NotImplementedError, match="_act_on_payload"):
        attack.payload(KeyElement("Z", 1).state(), HOP)


def test_measure_helpers_refuse_a_sample_that_cannot_carry_an_estimate():
    """A rate needs a denominator and a CHSH statistic needs four cells."""
    with pytest.raises(ValueError, match="at least 1"):
        measure_qber(lambda context: ideal_resource(), rounds=0)
    with pytest.raises(ValueError, match="at least 4"):
        measure_chsh(lambda context: ideal_resource(), rounds=3)
    with pytest.raises(TypeError, match="bound method"):
        measure_qber(object(), rounds=10)


def test_the_repr_names_the_target_and_the_engagement():
    """Debug output has to say which link, or it says nothing useful."""
    attack = InterceptResend(
        rng=np.random.default_rng(1), target=Party.CHARLIE
    )
    attack.resource(HOP)
    text = repr(attack)
    assert "InterceptResend" in text
    assert "Charlie" in text
    assert "0 of 1" in text


# ==========================================================================
# 8. The ChannelSample fingerprints Phase 4 will threshold on
# ==========================================================================


SIGNATURES = [
    ("clean", None, 1.0, 1.0, 1.0),
    (
        "depolarising p=0.3",
        lambda: DepolarisingChannel(0.3, rng=np.random.default_rng(51)),
        1.0 - 3 * 0.3 / 4,
        1.0,
        1.0,
    ),
    (
        "intercept-resend",
        lambda: InterceptResend(rng=np.random.default_rng(52)),
        0.5,
        1.0,
        0.0,
    ),
    (
        "kept share",
        lambda: KeptShareSwap(rng=np.random.default_rng(53)),
        0.5,
        0.5,
        0.0,
    ),
]
"""Mean fidelity, purity and concurrence over one link's check rounds."""


@pytest.mark.parametrize(
    "name,build,fidelity,pure,entangled",
    SIGNATURES,
    ids=[row[0] for row in SIGNATURES],
)
def test_the_channel_samples_fingerprint_each_attack(
    name, build, fidelity, pure, entangled
):
    """The three built-in summaries separate what the correlators cannot.

    They are recorded on every checked run, with or without a
    ``channel_monitor``: the monitor only adds ``extra``. Purity and concurrence
    are blind to the depolariser -- a twirled Bell pair is still a Bell pair --
    and fidelity is blind to nothing.
    """
    del name
    import statistics

    params = ProtocolParams(key_length=256, check_fraction=0.25)
    attack = None if build is None else build()
    session = QDSSession(
        params,
        rng=np.random.default_rng(SESSION_SEED),
        **({} if attack is None else {"resource_factory": attack.resource}),
    )
    session.distribute()
    samples = [
        sample for sample in session.channel if sample.party is Party.BOB
    ]
    assert samples
    assert statistics.fmean(s.fidelity for s in samples) == pytest.approx(
        fidelity, abs=0.06
    )
    assert statistics.fmean(s.purity for s in samples) == pytest.approx(
        pure, abs=1e-9
    )
    assert statistics.fmean(s.concurrence for s in samples) == pytest.approx(
        entangled, abs=1e-9
    )


def test_wing_asymmetry_detects_none_of_these_attacks():
    """``wings_agree`` is not a channel-attack detector on a maximally entangled pair.

    It is documented as the signature of something that acted on one leg, and
    every attack here does act on one leg -- but collapsing or mixing one half
    of a maximally entangled pair disturbs the other half exactly as much, so
    the two wing purities stay equal throughout. A Phase 4 detector that leaned
    on this would have no power against any of them.
    """
    params = ProtocolParams(key_length=128, check_fraction=0.25)
    for build in (
        lambda: DepolarisingChannel(0.4, rng=np.random.default_rng(61)),
        lambda: InterceptResend(rng=np.random.default_rng(62)),
        lambda: KeptShareSwap(rng=np.random.default_rng(63)),
    ):
        attack = build()
        session = QDSSession(
            params,
            resource_factory=attack.resource,
            rng=np.random.default_rng(SESSION_SEED),
        )
        session.distribute()
        assert all(sample.wings_agree for sample in session.channel)
