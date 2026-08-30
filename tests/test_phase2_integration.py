"""End-to-end Phase 2: the whole protocol, run rather than reasoned about.

Every other protocol test file exercises one module against its own
specification. This one runs :class:`~sih141.protocol.session.QDSSession`
from entanglement to a transferred signature and asserts the properties the
*scheme* claims, which is the only place they are all visible at once:

* **Correctness.** A noiseless honest run gives ``r_B = r_C = 0`` *exactly*, not
  approximately, at both verifiers and for both message bits. Teleportation over
  a clean pair is exact, so a matched position re-measures the very observable
  the state is an eigenstate of; anything above zero means a real defect
  somewhere in a chain of six modules.
* **Reproducibility (D3).** One seed reproduces the entire run byte for byte
  through ``to_json``, including the symmetrisation coins.
* **Transferability.** Over many independent runs, Bob accepting implies Charlie
  accepting -- the property the ``s_a < s_v`` gap exists to deliver.
* **Degradation.** The mismatch rate rises monotonically with the noise
  parameter of the entanglement resource, tracking the analytic ``p_e = p/2`` of
  :func:`~sih141.protocol.analysis.depolarising_error_rate`. Phase 4's detector
  is calibrated on that line, so a non-monotone or mis-scaled response here
  would invalidate it before it is written. The same line is pinned
  quantitatively end to end, at both verifiers and with a band *computed* from
  the pooled binomial standard error rather than guessed, by
  :func:`test_a_werner_resource_pins_both_verifiers_rates_to_half_its_parameter`.
  That test is what keeps the teleportation step inside the data path at all:
  on a clean pair, teleporting Alice's state and simply handing it to the
  recipient produce identical records, so only a noisy-resource assertion can
  distinguish them, and it asserts its own non-vacuity at every noisy level.
* **The two security properties, as executable statements.** Unforgeability
  against the binding recipient forger, and non-repudiation against the
  asymmetric Alice that motivated the symmetrisation step -- each measured with
  the step in place and with it removed, so the tests show *why* the step is
  there rather than asserting that it is.

Costs are kept honest: the runs use short keys, and every claim that needs
statistics says how many runs it is averaging and why that many.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix

from sih141.core.states import BellState, as_density, bell_state
from sih141.protocol.analysis import (
    depolarising_error_rate,
    recipient_forgery_probability,
)
from sih141.protocol.distribute import ResourceContext, ideal_resource
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import QDSSession, SessionTranscript
from sih141.protocol.signature import Signature
from sih141.protocol.symmetrise import no_symmetrisation

#: Short enough to run dozens of sessions in seconds, long enough that the
#: matched set is ~L/3 = 40 and a rate has three usable digits.  No security
#: claim attaches to it; the claims are made by the analysis module, and what is
#: checked here is that the *implementation* behaves the way those claims assume.
SHORT_L = 120

#: Even shorter, for the tests that need many independent runs.
TINY_L = 60


def werner(p: float) -> DensityMatrix:
    """Return the Werner resource ``(1 - p)|Phi+><Phi+| + p I/4``.

    Teleportation through it is the depolarising channel of strength ``p``, so
    a matched position is recorded with the wrong sign with probability exactly
    ``p / 2`` (:func:`~sih141.protocol.analysis.depolarising_error_rate`).
    """
    phi = np.asarray(as_density(bell_state(BellState.PHI_PLUS)).data, dtype=complex)
    return DensityMatrix((1.0 - p) * phi + p * np.eye(4, dtype=complex) / 4.0)


#: Width of every *computed* proportion band in this file, in standard errors.
#: At four sigmas a correct implementation fails a given assertion with
#: probability about ``6e-5``, and the seeds are fixed, so the suite is
#: deterministic.
SIGMAS = 4.0


def tolerance(probability: float, count: int, sigmas: float = SIGMAS) -> float:
    """Return ``sigmas`` times the binomial standard error of a proportion.

    Parameters
    ----------
    probability : float
        The proportion under the null hypothesis -- here always ``q / 2``.
    count : int
        Number of independent Bernoulli trials the observed proportion was
        pooled from: the total matched-position count, not the number of runs.
    sigmas : float, optional
        Width in standard errors, default :data:`SIGMAS`.

    Returns
    -------
    float
        ``sigmas * sqrt(p * (1 - p) / n)``.

    Raises
    ------
    AssertionError
        If ``count`` is not positive; an empty sample has no standard error and
        a band derived from one would be silently vacuous.
    """
    assert count > 0, "cannot form a standard error from an empty sample"
    return sigmas * math.sqrt(probability * (1.0 - probability) / count)


# --------------------------------------------------------------------------- #
# 1. An honest noiseless run                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("message_bit", [0, 1])
def test_honest_run_is_accepted_by_both_verifiers_at_rate_exactly_zero(
    message_bit: int,
) -> None:
    """The correctness statement of the whole phase, for both message bits.

    ``rate == 0.0`` is asserted as an exact float, not with a tolerance. On an
    ideal resource the hop is exact and a matched position reproduces the
    declared eigenvalue with probability one, so any non-zero rate here is a bug
    -- in the correction table, the basis bookkeeping, the matched/unmatched
    split or the exchange -- and not noise. A tolerance would hide all four.
    """
    params = ProtocolParams(key_length=SHORT_L)
    transcript = QDSSession(params, rng=np.random.default_rng(2026)).run(
        message_bit
    )

    assert transcript.is_complete
    assert transcript.transferable
    assert not transcript.repudiated
    for party in (Party.BOB, Party.CHARLIE):
        verdict = transcript.verdict_for(party)
        assert verdict.accepted
        assert verdict.rate == 0.0
        assert verdict.mismatches == 0
        # The evidence base is real: roughly L/3 positions survive the split,
        # and the rest were discarded rather than scored as agreements.
        assert 0 < verdict.matched_count < params.key_length
        assert verdict.unmatched_count == params.key_length - verdict.matched_count
    assert transcript.bob.threshold == params.s_a
    assert transcript.charlie.threshold == params.s_v
    assert transcript.symmetrised


def test_honest_run_discards_about_two_thirds_of_the_positions() -> None:
    """``E[|M_R|] = L / |B|``, checked across runs rather than within one.

    The matched count is ``Binomial(L, 1/3)``; over 40 independent sessions the
    mean of 80 verdicts has standard error ``sqrt(L * 2/9 / 80) ~ 0.58``
    positions, so a five-sigma band is under 3 positions out of 40. This is what
    makes "the useful length of a key is a third of its nominal length" a
    measured statement rather than an assumption.
    """
    params = ProtocolParams(key_length=SHORT_L)
    matched: list[int] = []
    for seed in range(40):
        transcript = QDSSession(params, rng=np.random.default_rng(300 + seed)).run(0)
        matched.extend(
            transcript.verdict_for(party).matched_count
            for party in (Party.BOB, Party.CHARLIE)
        )

    expected = params.expected_matched
    band = 5.0 * np.sqrt(
        params.key_length
        * params.match_probability
        * (1.0 - params.match_probability)
        / len(matched)
    )
    assert abs(float(np.mean(matched)) - expected) < band


# --------------------------------------------------------------------------- #
# 2. Reproducibility (D3)                                                      #
# --------------------------------------------------------------------------- #


def test_the_same_seed_reproduces_the_entire_run_byte_for_byte() -> None:
    """One seed, two derived streams, one reproducible transcript.

    The session draws material once from the caller's generator and derives an
    Alice stream and a recipient stream from it, so the coins no longer come off
    the same object the distribution seam is handed. Determinism survives that
    split: one seed still fixes both streams and therefore the whole run.

    Asserted at three strengths: equal transcripts, equal JSON, and a *different*
    transcript from a different seed. The last one matters because "equal" would
    also pass if the session ignored the seed entirely and produced a constant.
    """
    params = ProtocolParams(key_length=SHORT_L)
    first = QDSSession(params, rng=np.random.default_rng(555)).run(1)
    second = QDSSession(params, rng=np.random.default_rng(555)).run(1)
    other = QDSSession(params, rng=np.random.default_rng(556)).run(1)

    assert first == second
    assert first.to_json() == second.to_json()
    assert first != other

    restored = SessionTranscript.from_json(first.to_json())
    assert restored == first
    assert restored.symmetrised


def test_the_symmetrisation_coins_are_part_of_what_the_seed_fixes() -> None:
    """Changing only the exchange's randomness changes the logs but not the keys.

    A session draws the keys first and the coins last, so two runs that share a
    generator up to the exchange must agree on the declaration and disagree on
    who holds which record. Pinning this separates "the seed reproduces the run"
    from "the run does not depend on the coins at all", which would mean the
    exchange was a no-op.
    """
    params = ProtocolParams(key_length=SHORT_L)
    baseline = QDSSession(params, rng=np.random.default_rng(11)).run(0)
    shuffled = QDSSession(
        params,
        symmetriser=no_symmetrisation,
        rng=np.random.default_rng(11),
    ).run(0)

    assert baseline.signature == shuffled.signature
    baseline_bob = baseline.records_for(0)[Party.BOB]
    shuffled_bob = shuffled.records_for(0)[Party.BOB]
    assert baseline_bob != shuffled_bob
    # Both still accept: the exchange moves evidence, it does not corrupt it.
    assert baseline.transferable and shuffled.transferable


# --------------------------------------------------------------------------- #
# 3. Transferability                                                           #
# --------------------------------------------------------------------------- #


def test_every_signature_bob_accepts_is_one_charlie_accepts() -> None:
    """Transferability over 60 independent runs, both message bits.

    The scheme's claim is conditional -- *if* Bob accepts, Charlie does -- so
    the assertion is an implication counted over runs, not a rate. On a noiseless
    channel both rates are exactly zero and the implication holds with no slack
    at all, which is the strongest form the statement takes; the interesting
    version with slack is the degraded-channel test below.
    """
    params = ProtocolParams(key_length=TINY_L)
    accepted_by_bob = 0
    for seed in range(60):
        transcript = QDSSession(
            params, rng=np.random.default_rng(9000 + seed)
        ).run(seed % 2)
        assert transcript.is_complete
        if transcript.bob.accepted:
            accepted_by_bob += 1
            assert transcript.charlie.accepted
            assert transcript.transferable
        assert not transcript.repudiated
    assert accepted_by_bob == 60


def test_transferability_survives_a_channel_noisy_enough_to_be_visible() -> None:
    """The gap doing its job: noise Bob tolerates, Charlie tolerates easily.

    At ``p = 0.02`` the matched-position error rate is ``p_e = 0.01``, below
    Bob's ``s_a = 0.015625`` but not by much: with ``m ~ 100`` he tolerates one
    mismatch and accepts about three runs in four, so his verdicts genuinely
    straddle nothing but the boundary. Charlie, cutting at ``0.0625``, tolerates
    six, and ``P(e > 6)`` is about ``2e-5``. So every signature Bob accepts is
    one Charlie accepts, with margin -- which is what ``s_a < s_v`` buys and is
    invisible on a clean channel where both rates are zero.
    """
    params = ProtocolParams(key_length=300)
    resource = werner(0.02)

    accepted_by_bob = 0
    for seed in range(30):
        transcript = QDSSession(
            params,
            resource_factory=lambda: resource,
            rng=np.random.default_rng(4100 + seed),
        ).run(0)
        if transcript.bob.accepted:
            accepted_by_bob += 1
            assert transcript.charlie.accepted, transcript.summary()
        assert transcript.charlie.accepted, transcript.summary()
        assert not transcript.repudiated, transcript.summary()

    # Sanity: the noise level really is near Bob's cut, so this test is
    # exercising the boundary rather than a clean channel by another name.
    assert 5 <= accepted_by_bob <= 29


# --------------------------------------------------------------------------- #
# 4. Degradation: the mismatch rate tracks the channel                         #
# --------------------------------------------------------------------------- #


def test_mismatch_rate_rises_monotonically_with_resource_noise() -> None:
    """``r`` increases with ``p`` and sits on the analytic ``p / 2`` line.

    Two claims in one experiment, because they constrain each other. Monotonicity
    is what Phase 4's threshold rests on -- more channel noise must never look
    *less* suspicious -- and the ``p/2`` calibration is what turns an observed
    rate back into a channel parameter. Averaging 12 runs per noise level gives
    each point about ``sqrt(p/2 * (1 - p/2) / (12 * 40))`` of standard error,
    i.e. under 0.02 across the range, so the 0.05 band below is a little over
    two standard errors and the monotonicity check uses well-separated levels.
    """
    params = ProtocolParams(key_length=SHORT_L)
    levels = [0.0, 0.1, 0.25, 0.5, 0.75, 1.0]
    runs_per_level = 12

    observed: list[float] = []
    for index, p in enumerate(levels):
        resource = werner(p)
        rates: list[float] = []
        for seed in range(runs_per_level):
            transcript = QDSSession(
                params,
                resource_factory=lambda resource=resource: resource,
                rng=np.random.default_rng(6000 + 100 * index + seed),
            ).run(0)
            rates.extend(
                transcript.verdict_for(party).rate
                for party in (Party.BOB, Party.CHARLIE)
            )
        observed.append(float(np.mean(rates)))

    # The exact line, from the module that will calibrate Phase 4's detector.
    for p, rate in zip(levels, observed):
        assert rate == pytest.approx(depolarising_error_rate(p), abs=0.05)

    # Strictly increasing, with a margin far larger than the sampling error.
    for earlier, later in zip(observed, observed[1:]):
        assert later > earlier + 0.02

    assert observed[0] == 0.0  # a clean channel is exact, not merely close
    assert observed[-1] == pytest.approx(0.5, abs=0.05)


#: Werner parameters swept end to end by
#: :func:`test_a_werner_resource_pins_both_verifiers_rates_to_half_its_parameter`.
#: ``0.125`` puts the rate exactly on Charlie's ``s_v``, which is where the
#: calibration has to be right for Phase 4 to mean anything.
E2E_WERNER_LEVELS = (0.0, 0.125, 0.5, 1.0)

#: Key length of each pooled session.  Each session yields one verdict per
#: verifier, and about ``E2E_WERNER_LENGTH / 3`` of a verdict's positions are
#: matched and so contribute to a rate.
E2E_WERNER_LENGTH = 240

#: Floor on the number of pooled sessions per level.
E2E_WERNER_MIN_RUNS = 3


def runs_for_resolution(level: float, matched_per_run: float) -> int:
    """Sessions needed to resolve ``level / 2`` to half its own size.

    Derived from the same binomial standard error :func:`tolerance` returns
    rather than picked.  Requiring the ``SIGMAS``-wide band around the predicted
    rate ``e = q / 2`` to be at most ``e / 2``,

        SIGMAS * sqrt(e (1 - e) / n)  <=  e / 2,

    gives ``n >= (2 * SIGMAS)**2 * (1 - e) / e`` pooled matched positions.  The
    cost therefore falls where the resolution is hard -- small ``q``, where the
    predicted rate is nearest the zero a bypassed teleportation would report --
    instead of every level paying the smallest level's price.

    Parameters
    ----------
    level : float
        The Werner parameter ``q``.  ``0.0`` is exact rather than statistical
        and returns the floor.
    matched_per_run : float
        Expected matched positions one session contributes to one verifier,
        ``L / |B|``.

    Returns
    -------
    int
        At least :data:`E2E_WERNER_MIN_RUNS`.
    """
    if level <= 0.0:
        return E2E_WERNER_MIN_RUNS
    expected = level / 2.0
    required = (2.0 * SIGMAS) ** 2 * (1.0 - expected) / expected
    return max(E2E_WERNER_MIN_RUNS, math.ceil(required / matched_per_run))


def test_a_werner_resource_pins_both_verifiers_rates_to_half_its_parameter() -> None:
    """``q / 2`` through the whole stack, with the band computed, not guessed.

    The derivation is the same one
    :func:`tests.test_protocol_distribute.test_a_werner_resource_pins_the_mismatch_rate_to_half_its_parameter`
    makes at the unit level: teleportation is linear in the resource and every
    Bell outcome stays equiprobable across both components of
    ``rho(q) = (1 - q)|Phi+><Phi+| + q I/4``, so the receiver holds
    ``(1 - q)|psi><psi| + q I/2`` and a matched position reports Alice's
    declared eigenvalue with Born probability ``1 - q/2``.  Hence
    ``P(mismatch | matched) = q / 2``.

    Asserting it *here* as well is not duplication.  Between
    ``distribute_to_recipient`` and a verdict sit the recipients' symmetrisation
    exchange, the signature, and the matched/unmatched split in
    :mod:`sih141.protocol.verify`.  The exchange permutes which raw record each
    verifier ends up holding, and the two links carry the same ``q`` here, so
    the prediction is unchanged and both verifiers must land on the same line --
    which is exactly the statement that the exchange redistributes evidence
    without manufacturing or destroying any.

    The band comes from the *observed* pooled matched count via
    :func:`tolerance`, and how many sessions are pooled to reach that count is
    itself derived from the same standard error by
    :func:`runs_for_resolution`.  The test asserts at every noisy level that the
    band excludes zero.  That is what makes the assertion bite: on an ideal resource
    a genuine hop and a bypassed one are observationally identical, so only a
    noisy resource can hold the teleportation step inside the data path, and
    only a band narrower than ``q / 2`` can tell the two apart.

    Counts are pooled rather than rates averaged.  ``matched_count`` varies run
    to run, so a mean of per-run rates is a ratio estimator with a different
    variance than the binomial band being computed; summing mismatches and
    matched positions separately is the estimator the band actually describes.
    """
    params = ProtocolParams(key_length=E2E_WERNER_LENGTH)
    matched_per_run = E2E_WERNER_LENGTH / len(params.bases)

    for index, level in enumerate(E2E_WERNER_LEVELS):
        resource = werner(level)
        pooled: dict[Party, list[int]] = {
            Party.BOB: [0, 0],
            Party.CHARLIE: [0, 0],
        }
        for seed in range(runs_for_resolution(level, matched_per_run)):
            transcript = QDSSession(
                params,
                resource_factory=lambda resource=resource: resource,
                rng=np.random.default_rng(11_000 + 100 * index + seed),
            ).run(seed % 2)
            assert transcript.is_complete
            assert transcript.symmetrised
            for party in (Party.BOB, Party.CHARLIE):
                verdict = transcript.verdict_for(party)
                pooled[party][0] += verdict.mismatches
                pooled[party][1] += verdict.matched_count

        expected = level / 2.0
        for party, (mismatches, matched) in pooled.items():
            observed = mismatches / matched
            if level == 0.0:
                # Clean pairs teleport exactly; nothing here is statistical.
                assert observed == 0.0, f"{party} on a clean channel: {observed}"
                continue
            band = tolerance(expected, matched)
            assert expected - band > 0.0, (
                f"pooled matched sample of {matched} at {party} is too small "
                f"for q={level}: the {SIGMAS}-sigma band {band} around "
                f"{expected} still contains 0.0, so the assertion below would "
                f"pass on a run whose teleportation result was discarded"
            )
            assert observed == pytest.approx(expected, abs=band), (
                f"q={level} at {party}: pooled rate {observed} over {matched} "
                f"matched positions is more than {SIGMAS} sigma from the "
                f"predicted q/2={expected}"
            )
            # The analysis module the Phase 4 detector will be calibrated on
            # must name the same line.
            assert depolarising_error_rate(level) == pytest.approx(expected)


def test_a_noisy_channel_is_rejected_by_both_verifiers_together() -> None:
    """Heavy noise fails at both cuts, and fails as a *rejection*, not a crash.

    The other half of the degradation story: the protocol must not merely notice
    noise, it must reach a verdict about it. A channel at ``p = 0.75``
    (``p_e = 0.375``) is far above both thresholds, so both verifiers reject and
    the run is neither transferable nor a repudiation -- Bob did not accept, so
    there is nothing for him to fail to pass on.
    """
    params = ProtocolParams(key_length=SHORT_L)
    resource = werner(0.75)
    transcript = QDSSession(
        params,
        resource_factory=lambda: resource,
        rng=np.random.default_rng(7007),
    ).run(0)

    assert not transcript.bob.accepted
    assert not transcript.charlie.accepted
    assert not transcript.transferable
    assert not transcript.repudiated
    assert transcript.summary().splitlines()[-1].startswith("REJECTED")


def test_noise_aimed_at_one_recipient_is_visible_at_both() -> None:
    """A targeted channel attack cannot separate the two verdicts.

    The ``ResourceContext`` seam lets an attacker degrade Charlie's link alone,
    which before the symmetrisation step separated the verdicts perfectly. Now
    the damaged records are split between the two verifiers, so both rates rise
    together.

    The predicted rate is ``1/4`` at *both* verifiers, and it is worth deriving
    rather than measuring blind. Each verifier ends up holding half good records
    and half records from the dead link. A good record contributes a matched
    position with probability ``1/3`` and never a mismatch; a dead one is
    matched with probability ``1/3`` -- Charlie still drew a basis -- and then
    mismatches with probability ``1/2``. So the rate is
    ``(1/2)(1/3)(1/2) / (1/3) = 1/4`` for each. The assertions are that both
    means land there, that both verifiers reject, and that no run repudiates.
    """
    params = ProtocolParams(key_length=300)
    clean = ideal_resource()
    dirty = werner(1.0)

    def targeted(context: ResourceContext) -> object:
        return dirty if context.party is Party.CHARLIE else clean

    bob_rates: list[float] = []
    charlie_rates: list[float] = []
    for seed in range(12):
        transcript = QDSSession(
            params,
            resource_factory=targeted,
            rng=np.random.default_rng(8100 + seed),
        ).run(0)
        assert not transcript.repudiated, transcript.summary()
        assert not transcript.bob.accepted
        assert not transcript.charlie.accepted
        bob_rates.append(transcript.bob.rate)
        charlie_rates.append(transcript.charlie.rate)

    # ~1200 scored positions behind each mean, so the standard error is about
    # 0.0125 and a 0.04 band is over three of them.
    assert float(np.mean(bob_rates)) == pytest.approx(0.25, abs=0.04)
    assert float(np.mean(charlie_rates)) == pytest.approx(0.25, abs=0.04)


# --------------------------------------------------------------------------- #
# 5. Unforgeability, measured                                                  #
# --------------------------------------------------------------------------- #


def _recipient_forger(party: Party):
    """Return a signer that declares everything ``party`` recorded.

    The compliant recipient forgery, and by the POVM argument in
    :mod:`sih141.protocol.params` the optimal one: at a position the forger
    supplied to the other verifier during the exchange, his own record *is* the
    other's, so declaring it is matched with probability one and mismatches with
    probability zero; elsewhere he is guessing.
    """

    def signer(message_bit, keys, params, *, records):
        record = records[message_bit][party]
        return Signature(
            message_bit,
            PrivateKey(
                message_bit,
                tuple(
                    KeyElement(basis, value)
                    for basis, value in zip(record.bases, record.eigenvalues)
                ),
            ),
        )

    return signer


def test_a_recipient_forgery_lands_near_the_forger_floor_and_is_rejected() -> None:
    """Bob forging to Charlie: rate near ``1/12``, above ``s_v``, always rejected.

    The number is the point. ``forger_floor = (|B| - 1) / (2|B|(|B| + 1)) =
    1/12`` is derived in :mod:`sih141.protocol.params` from the exchange's
    structure -- half the target's evidence came from the forger himself -- and
    it is what ``s_v`` is set below. Measuring it end to end is what makes the
    derivation a claim about this code rather than about a paper.

    30 runs at ``L = 120`` give ~80 scored positions each; the mean rate has
    standard error ``sqrt(1/12 * 11/12 / (30 * 80)) ~ 0.006``, so the 0.02 band
    is over three standard errors while still excluding both ``s_v = 1/16`` and
    the unsymmetrised ``1/3``.

    How often the forgery is *accepted* is not asserted as "never": at
    ``L = 120`` it is not never, and pretending otherwise would misrepresent
    what short keys buy. It is asserted against
    :func:`~sih141.protocol.analysis.recipient_forgery_probability`, which is
    the sharper statement -- the end-to-end run and the closed form have to
    agree -- and the closed form is separately shown to decay exponentially in
    ``L`` in ``tests/test_protocol_analysis.py``.
    """
    params = ProtocolParams(key_length=SHORT_L)
    runs = 30
    rates: list[float] = []
    accepted = 0
    for seed in range(runs):
        transcript = QDSSession(
            params,
            signer=_recipient_forger(Party.BOB),
            rng=np.random.default_rng(5200 + seed),
        ).run(0)
        rates.append(transcript.charlie.rate)
        accepted += transcript.charlie.accepted

    mean_rate = float(np.mean(rates))
    assert mean_rate == pytest.approx(params.forger_floor, abs=0.02)
    assert mean_rate > params.s_v

    predicted = recipient_forgery_probability(params)
    band = 5.0 * np.sqrt(predicted * (1.0 - predicted) / runs)
    assert abs(accepted / runs - predicted) <= band, (
        f"{accepted}/{runs} accepted against a predicted {predicted:.4f}"
    )
    # And the number shrinks exponentially in L -- 0.268 at 120, 0.014 at 1200,
    # 1e-103 at the shipped 115200. The decay is slow at these thresholds
    # (lambda ~ 0.00206 per position), which is precisely why the shipped key
    # is long; a toy key buys a toy guarantee and this test says so.
    assert predicted < 0.5
    assert recipient_forgery_probability(
        params.with_changes(key_length=10 * SHORT_L)
    ) < predicted / 10.0


def test_the_forger_floor_is_four_times_lower_than_without_the_exchange() -> None:
    """The exchange's price, measured on the same forger.

    Without symmetrisation the recipient forger has no privileged knowledge of
    the target's log and sits at ``(1 - 1/|B|)/2 = 1/3``; with it he sits at
    ``1/12``. That factor of four is why ``s_v`` had to drop from ``1/6`` to
    ``1/16`` and why the key length grew, and it is the honest cost of
    non-repudiation. Both numbers are asserted so neither can drift unnoticed.
    """
    params = ProtocolParams(key_length=SHORT_L)
    with_exchange: list[float] = []
    without: list[float] = []
    for seed in range(30):
        with_exchange.append(
            QDSSession(
                params,
                signer=_recipient_forger(Party.BOB),
                rng=np.random.default_rng(5300 + seed),
            )
            .run(0)
            .charlie.rate
        )
        without.append(
            QDSSession(
                params,
                signer=_recipient_forger(Party.BOB),
                symmetriser=no_symmetrisation,
                rng=np.random.default_rng(5300 + seed),
            )
            .run(0)
            .charlie.rate
        )

    assert float(np.mean(with_exchange)) == pytest.approx(
        params.forger_floor, abs=0.02
    )
    assert float(np.mean(without)) == pytest.approx(
        params.unmatched_noise_rate, abs=0.03
    )


# --------------------------------------------------------------------------- #
# 6. Non-repudiation, measured -- with and without the exchange                #
# --------------------------------------------------------------------------- #


def _asymmetric_alice(fraction: float):
    """Return a resource factory that delivers Charlie a useless state.

    A completely mixed resource teleports to ``I/2``, so Charlie's outcome on
    those positions is a fair coin while Bob's is exact. That is ``q_B = 0``,
    ``q_C = 1/2`` on the attacked fraction -- outside the single-common-``q``
    family the in-model repudiation analysis describes, and the family that
    matters.
    """
    clean = ideal_resource()
    dirty = werner(1.0)

    def factory(context: ResourceContext) -> object:
        if context.party is Party.CHARLIE and context.position < int(
            fraction * SHORT_L
        ):
            return dirty
        return clean

    return factory


def test_asymmetric_alice_repudiates_when_the_exchange_is_removed() -> None:
    """The defect the exchange fixes, kept as a running demonstration.

    With ``symmetriser=no_symmetrisation`` the session runs the variant this
    package shipped before Phase A' existed. The attack succeeds on every seed:
    the repudiation event is not rare, it is certain, which is why no key length
    repaired it.
    """
    params = ProtocolParams(key_length=SHORT_L)
    repudiations = 0
    for seed in range(20):
        transcript = QDSSession(
            params,
            resource_factory=_asymmetric_alice(0.9),
            symmetriser=no_symmetrisation,
            rng=np.random.default_rng(7300 + seed),
        ).run(0)
        assert transcript.bob.rate == 0.0
        repudiations += transcript.repudiated
        assert not transcript.symmetrised
        assert "UNSYMMETRISED" in transcript.summary()
    assert repudiations == 20


def test_the_exchange_prevents_the_same_repudiation() -> None:
    """The fix, on the identical attack and the identical seeds.

    Nothing changes but the ``symmetriser`` argument. The damaged records are
    now split between the two verifiers, so Bob's rate rises with Charlie's and
    the gap between the verdicts closes: over 20 runs the repudiation event does
    not occur once, and Bob's rate is no longer zero, which is the mechanism made
    visible.
    """
    params = ProtocolParams(key_length=SHORT_L)
    repudiations = 0
    for seed in range(20):
        transcript = QDSSession(
            params,
            resource_factory=_asymmetric_alice(0.9),
            rng=np.random.default_rng(7300 + seed),
        ).run(0)
        repudiations += transcript.repudiated
        assert transcript.bob.rate > params.s_a, transcript.summary()
        assert transcript.symmetrised
    assert repudiations == 0


# --------------------------------------------------------------------------- #
# 7. The transcript as the Phase 4-6 hand-off                                  #
# --------------------------------------------------------------------------- #


def test_a_transcript_survives_json_and_refuses_a_rewritten_threshold() -> None:
    """The persistence boundary carries the run *and* guards it.

    A round trip must be lossless, and a tampered transcript must not
    reconstruct: rewriting each verdict's threshold to ``s_v`` and recomputing
    ``accepted`` leaves a blob that is internally consistent in every field, and
    used to restore into a transcript reporting ``transferable=True`` for a run
    Bob rejected. It is now refused, because the threshold is re-derived from
    ``params`` and the party rather than believed.
    """
    params = ProtocolParams(key_length=300)
    resource = werner(0.08)  # p_e = 0.04: above s_a, below s_v
    transcript = QDSSession(
        params,
        resource_factory=lambda: resource,
        run_id="phase2-integration-7",
        rng=np.random.default_rng(9191),
    ).run(0)

    assert not transcript.bob.accepted
    assert transcript.charlie.accepted
    assert not transcript.transferable
    assert transcript.run_id == "phase2-integration-7"
    assert SessionTranscript.from_json(transcript.to_json()) == transcript

    blob = json.loads(transcript.to_json())
    for entry in blob["results"]:
        entry["threshold"] = params.s_v
        entry["accepted"] = entry["rate"] <= params.s_v
    with pytest.raises(ValueError, match="carries threshold"):
        SessionTranscript.from_json(json.dumps(blob))
