"""Tests for :mod:`sih141.protocol.distribute` -- Phase A of the QDS run.

Four things are pinned here, in order of how badly they fail silently.

1. **The teleportation is genuinely in the data path.** ``distribute_to_recipient``
   would look perfectly healthy on an ideal channel if it secretly re-prepared
   each eigenstate at the recipient instead of teleporting it -- every honest
   test would still pass, and Phase 3 would then measure the effect of its
   attacks on nothing at all. So the ``resource_factory`` seam is attacked here:
   a Werner resource of parameter ``p`` must raise the matched-position mismatch
   rate to ``p / 2``, quantitatively, at three values of ``p``; a maximally mixed
   resource must drive it to chance; and the generator must be advanced by the
   Bell measurement's own variate. A stub cannot pass any of the three.
   :func:`test_a_werner_resource_pins_the_mismatch_rate_to_half_its_parameter`
   states that as the standing invariant: it derives ``P(mismatch | matched) =
   q / 2`` from the Born rule, sweeps five values of ``q``, pools independent
   runs so the band is narrow, and -- because on an *ideal* resource a real hop
   and a bypassed one are observationally identical -- asserts at every noisy
   level that the four-sigma band excludes zero, so the test cannot be satisfied
   by a record that never went through a teleportation.
2. **The matched/unmatched split.** The matched fraction is asserted to converge
   to ``1/|B| = 1/3`` with a tolerance *computed* from the binomial standard
   error of the sample, not guessed. Unmatched positions are asserted to be fair
   coins, and the classic implementation bug -- counting them -- is demonstrated
   explicitly to produce a rate of ``1/3`` that sits above ``s_v`` and would
   reject every honest signature.
3. **No quantum memory.** The returned record is asserted to hold nothing but
   integers, enum members and tuples, and to survive a round trip through
   :func:`json.dumps`. That is the design rationale of the whole scheme, and it
   is a property of the *return type*, so it is checked on the object rather
   than argued in a docstring.
4. **Determinism and validation (D3, D5).** One seed reproduces a run exactly;
   exactly three variates are consumed per key position; and every refusal
   (Alice, a foreign key, a ``None`` resource) fires with an actionable message.

Statistical tolerances
----------------------
Every proportion assertion goes through :func:`_tolerance`, which returns
``sigmas * sqrt(p * (1 - p) / n)`` for the *actual* sample size ``n`` of that
assertion. At the default four sigmas a correct implementation fails a given
assertion with probability about ``6e-5``, and the seeds are fixed anyway, so
the suite is deterministic.
"""

from __future__ import annotations

import dataclasses
import json
import math
import os
import traceback
from collections import Counter

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix, Statevector

from sih141.core.states import BellState, bell_state
from sih141.protocol import (
    DEFAULT_S_A,
    DEFAULT_S_V,
    VERIFIERS,
    Party,
    PrivateKey,
    ProtocolParams,
    RecipientRecord,
    ResourceContext,
    distribute_public_key,
    distribute_to_recipient,
    generate_private_key,
    ideal_resource,
)
from sih141.core.paulis import PauliBasis
from sih141.core.teleport import teleport
from sih141.protocol.checkrounds import CheckRoundPlan, draw_check_plan
from sih141.protocol.distribute import (
    _adopt_state,
    _map_payload,
    distribute_to_recipient_with_checks,
)

SEED = 20260141
"""Base seed for key generation; distribution uses ``SEED + _DIST_OFFSET``."""

_DIST_OFFSET = 900_000
"""Offset keeping the distribution stream disjoint from the key stream."""

SAMPLE_RUNS = 30
SAMPLE_LENGTH = 80
SAMPLE_POSITIONS = SAMPLE_RUNS * SAMPLE_LENGTH  # 2400

SIGMAS = 4.0
"""Tolerance width for every proportion assertion; ~6e-5 false-failure rate."""


# ==========================================================================
# Helpers
# ==========================================================================


def _params(length: int = 24, **changes: object) -> ProtocolParams:
    """Build a small valid parameter set."""
    return ProtocolParams(key_length=length, **changes)  # type: ignore[arg-type]


def _key(params: ProtocolParams, message_bit: int = 0, seed: int = SEED) -> PrivateKey:
    """Draw a private key from its own dedicated stream."""
    return generate_private_key(
        params, message_bit, rng=np.random.default_rng(seed)
    )


def _distribute(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    party: Party | str = Party.BOB,
    resource_factory: object = None,
    seed: int = SEED + _DIST_OFFSET,
) -> RecipientRecord:
    """Run one distribution on a freshly seeded generator."""
    return distribute_to_recipient(
        key,
        params,
        party=party,
        resource_factory=resource_factory,  # type: ignore[arg-type]
        rng=np.random.default_rng(seed),
    )


def _matched_positions(key: PrivateKey, record: RecipientRecord) -> tuple[int, ...]:
    """Positions where the recipient's basis equals Alice's declared one."""
    return tuple(
        index
        for index in range(len(key))
        if record.bases[index] == key.bases[index]
    )


def _unmatched_positions(key: PrivateKey, record: RecipientRecord) -> tuple[int, ...]:
    """Positions where the recipient measured a conjugate observable."""
    matched = set(_matched_positions(key, record))
    return tuple(index for index in range(len(key)) if index not in matched)


def _disagreements(
    key: PrivateKey, record: RecipientRecord, positions: tuple[int, ...]
) -> int:
    """Count positions whose measured eigenvalue differs from the declared one."""
    return sum(
        1
        for index in positions
        if record.eigenvalues[index] != key.eigenvalues[index]
    )


def _mismatch_rate(key: PrivateKey, record: RecipientRecord) -> float:
    """The protocol's rate ``r_R``: disagreements over *matched* positions only."""
    matched = _matched_positions(key, record)
    assert matched, "sample too small: no matched positions to compute a rate"
    return _disagreements(key, record, matched) / len(matched)


def _tolerance(probability: float, count: int, sigmas: float = SIGMAS) -> float:
    """Return the binomial standard error of a proportion, times ``sigmas``.

    Parameters
    ----------
    probability : float
        The proportion under the null hypothesis.
    count : int
        The number of independent Bernoulli trials the observed proportion was
        computed from.
    sigmas : float, optional
        Width in standard errors, default :data:`SIGMAS`.

    Returns
    -------
    float
        ``sigmas * sqrt(p * (1 - p) / n)``.
    """
    assert count > 0, "cannot form a standard error from an empty sample"
    return sigmas * math.sqrt(probability * (1.0 - probability) / count)


def _werner(p: float) -> DensityMatrix:
    """Return the Werner state ``(1 - p) |Phi+><Phi+| + p I/4``.

    Teleporting a pure payload over it applies a depolarising channel of
    strength ``p``, so a matched position disagrees with the declared eigenvalue
    with probability exactly ``p / 2``. That closed form is what makes the
    degraded-resource tests quantitative rather than merely directional.
    """
    phi = DensityMatrix(bell_state(BellState.PHI_PLUS)).data
    return DensityMatrix((1.0 - p) * phi + p * np.eye(4) / 4.0)


@pytest.fixture(scope="module")
def ideal_sample() -> tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]]:
    """Many independent, seeded, noiseless distribution runs.

    Shared by the statistical tests so that ~2400 teleportations are paid for
    once. Keys and distributions draw from disjoint streams, as the module
    docstring of :mod:`sih141.protocol.distribute` recommends.
    """
    params = _params(SAMPLE_LENGTH)
    pairs = []
    for run in range(SAMPLE_RUNS):
        key = _key(params, message_bit=run % 2, seed=SEED + run)
        record = _distribute(
            key,
            params,
            party=VERIFIERS[run % 2],
            seed=SEED + _DIST_OFFSET + run,
        )
        pairs.append((key, record))
    return params, tuple(pairs)


# ==========================================================================
# Shape of the returned record
# ==========================================================================


def test_record_has_one_entry_per_key_position_indexed_in_order() -> None:
    """The log is ``L`` entries long, indexed ``0 .. L-1`` ascending."""
    params = _params(16)
    key = _key(params)
    record = _distribute(key, params)
    assert len(record) == params.key_length == len(key)
    assert tuple(entry.index for entry in record) == tuple(range(len(key)))


def test_record_is_tagged_with_the_party_and_the_keys_message_bit() -> None:
    """The record carries the verifier it belongs to and the bit it was for."""
    params = _params(8)
    key = _key(params, message_bit=1)
    record = _distribute(key, params, party="charlie")
    assert record.party is Party.CHARLIE
    assert record.message_bit == 1


def test_record_accepts_the_same_params_it_was_produced_under() -> None:
    """``check_against`` is the reverse of this module and must agree with it."""
    params = _params(12)
    record = _distribute(_key(params), params)
    assert record.check_against(params) is None


def test_recipient_bases_come_from_the_declared_alphabet_only() -> None:
    """A two-basis parameter set produces a two-basis log."""
    params = _params(60, bases=(PauliBasis.X, PauliBasis.Z))
    record = _distribute(_key(params), params)
    assert set(record.bases) <= {PauliBasis.X, PauliBasis.Z}
    assert record.check_against(params) is None


def test_measured_values_are_pauli_eigenvalues_not_bits() -> None:
    """The log stores ``+1``/``-1``; the ``bits`` view does the 0/1 mapping."""
    record = _distribute(_key(_params(16)), _params(16))
    assert set(record.eigenvalues) <= {1, -1}
    assert record.bits == tuple(
        (1 - value) // 2 for value in record.eigenvalues
    )


# ==========================================================================
# No quantum memory -- the design rationale of the whole scheme
# ==========================================================================


def test_record_retains_no_quantum_state() -> None:
    """Nothing in the returned record is a state vector, density matrix or array.

    This is the property the scheme is chosen *for*: Gottesman-Chuang QDS needs
    long-lived quantum memory at every recipient, and measuring on receipt is
    what removes it. It is a property of the object, so it is asserted on the
    object.
    """
    record = _distribute(_key(_params(8)), _params(8))
    forbidden = (Statevector, DensityMatrix, np.ndarray)

    def _walk(obj: object) -> None:
        assert not isinstance(obj, forbidden), (
            f"the recipient record retains a quantum object of type "
            f"{type(obj).__name__}; recipients must keep a classical log only"
        )
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            for field in dataclasses.fields(obj):
                _walk(getattr(obj, field.name))
        elif isinstance(obj, (tuple, list)):
            for item in obj:
                _walk(item)

    _walk(record)


def test_record_survives_a_json_round_trip() -> None:
    """A purely classical log serialises with no bespoke encoder."""
    record = _distribute(_key(_params(8)), _params(8))
    restored = RecipientRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert restored == record


# ==========================================================================
# The physics of an ideal run
# ==========================================================================


def test_ideal_run_reproduces_every_declared_eigenvalue_on_matched_positions(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """A noiseless honest run gives ``r_R = 0`` exactly, not merely nearly.

    Teleportation over a clean pair is exact, so on a matched position the
    recipient re-measures the very observable the state is an eigenstate of and
    gets the declared eigenvalue with probability one. Every acceptance
    threshold in the scheme is a noise budget measured from this zero.
    """
    _, pairs = ideal_sample
    for key, record in pairs:
        matched = _matched_positions(key, record)
        assert matched
        assert _disagreements(key, record, matched) == 0
    assert all(_mismatch_rate(key, record) == 0.0 for key, record in pairs)


def test_ideal_run_is_accepted_by_both_thresholds(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """``0 <= s_a < s_v``, so an honest run clears the tighter cut as well."""
    _, pairs = ideal_sample
    for key, record in pairs:
        rate = _mismatch_rate(key, record)
        assert rate <= DEFAULT_S_A
        assert rate <= DEFAULT_S_V


def test_matched_fraction_converges_to_one_over_the_alphabet_size(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """Matched positions occur at rate ``1/|B| = 1/3``, within the binomial SE.

    The recipient draws his basis uniformly and independently of Alice, so each
    position is an independent Bernoulli trial with success probability
    ``params.match_probability``. This is the number ``expected_matched`` -- and
    therefore every security bound in :mod:`sih141.protocol.params` -- rests on.
    """
    params, pairs = ideal_sample
    matched = sum(len(_matched_positions(key, record)) for key, record in pairs)
    total = sum(len(record) for _, record in pairs)
    assert total == SAMPLE_POSITIONS

    expected = params.match_probability
    tolerance = _tolerance(expected, total)
    assert tolerance < expected / 2.0, "tolerance too loose to be meaningful"
    assert matched / total == pytest.approx(expected, abs=tolerance)


def test_matched_count_tracks_expected_matched(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """The mean matched count per run agrees with ``params.expected_matched``."""
    params, pairs = ideal_sample
    mean_matched = sum(
        len(_matched_positions(key, record)) for key, record in pairs
    ) / len(pairs)
    # Standard error of a mean of SAMPLE_RUNS binomial(L, 1/3) counts.
    per_run = SAMPLE_LENGTH * _tolerance(
        params.match_probability, SAMPLE_LENGTH
    )
    assert mean_matched == pytest.approx(
        params.expected_matched, abs=per_run / math.sqrt(len(pairs))
    )


def test_recipient_bases_are_uniform_over_the_alphabet(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """Each of the three bases is chosen about a third of the time."""
    params, pairs = ideal_sample
    counts = Counter(basis for _, record in pairs for basis in record.bases)
    total = sum(counts.values())
    assert set(counts) == set(params.bases)
    tolerance = _tolerance(params.match_probability, total)
    for basis in params.bases:
        assert counts[basis] / total == pytest.approx(
            params.match_probability, abs=tolerance
        )


# ==========================================================================
# The classic bug: counting unmatched positions
# ==========================================================================


def test_unmatched_positions_are_fair_coins(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """On a conjugate basis the outcome agrees with the declaration half the time.

    Which is to say: it carries exactly zero bits about the key, honest run or
    not, and is therefore evidence of nothing.
    """
    _, pairs = ideal_sample
    unmatched_total = 0
    disagreements = 0
    for key, record in pairs:
        positions = _unmatched_positions(key, record)
        unmatched_total += len(positions)
        disagreements += _disagreements(key, record, positions)

    assert unmatched_total > 0
    tolerance = _tolerance(0.5, unmatched_total)
    assert disagreements / unmatched_total == pytest.approx(0.5, abs=tolerance)


def test_counting_unmatched_positions_would_reject_every_honest_signature(
    ideal_sample: tuple[ProtocolParams, tuple[tuple[PrivateKey, RecipientRecord], ...]],
) -> None:
    """The classic implementation bug, demonstrated with its exact symptom.

    A verifier that forgets to discard unmatched positions divides by ``L``
    instead of ``|M_R|`` and sees ``(1 - 1/|B|) / 2 = 1/3`` on a *perfect*
    channel. That is above ``s_v``, so both verifiers reject honest signatures,
    and the failure looks like a hardware noise problem rather than a logic
    error. The correct rate on the very same records is exactly zero.
    """
    params, pairs = ideal_sample
    total = sum(len(record) for _, record in pairs)
    buggy = sum(
        _disagreements(key, record, tuple(range(len(record))))
        for key, record in pairs
    )
    buggy_rate = buggy / total

    tolerance = _tolerance(params.unmatched_noise_rate, total)
    assert buggy_rate == pytest.approx(params.unmatched_noise_rate, abs=tolerance)
    assert buggy_rate > DEFAULT_S_V > DEFAULT_S_A
    assert all(_mismatch_rate(key, record) == 0.0 for key, record in pairs)


# ==========================================================================
# The resource_factory seam -- the teleportation must be real
# ==========================================================================


def test_ideal_resource_is_phi_plus() -> None:
    """The documented default really is the clean Bell pair, freshly built."""
    first, second = ideal_resource(), ideal_resource()
    assert first is not second
    assert np.allclose(first.data, bell_state(BellState.PHI_PLUS).data)


def test_default_factory_matches_an_explicit_ideal_factory() -> None:
    """Omitting ``resource_factory`` is the same run as passing the ideal one."""
    params = _params(24)
    key = _key(params)
    default = _distribute(key, params)
    explicit = _distribute(key, params, resource_factory=ideal_resource)
    assert default == explicit


def test_resource_factory_is_called_once_per_key_position() -> None:
    """A fresh entangled pair is consumed per qubit, never reused."""
    params = _params(20)
    key = _key(params)
    calls = 0

    def counting_factory() -> Statevector:
        nonlocal calls
        calls += 1
        return ideal_resource()

    _distribute(key, params, resource_factory=counting_factory)
    assert calls == params.key_length


def test_degraded_resource_raises_the_mismatch_rate() -> None:
    """The seam is load-bearing: attack the channel, watch the rate move.

    If this test can pass with the teleportation stubbed out -- with the
    eigenstate simply re-prepared at the recipient -- then ``resource_factory``
    is decoration and Phase 3 has nothing to attack. A maximally mixed resource
    carries no entanglement, so the receiver's qubit is ``I/2`` regardless of
    the payload and a matched position becomes a fair coin.
    """
    params = _params(300)
    key = _key(params)

    clean = _distribute(key, params)
    attacked = _distribute(key, params, resource_factory=lambda: _werner(1.0))

    clean_rate = _mismatch_rate(key, clean)
    attacked_rate = _mismatch_rate(key, attacked)
    matched = len(_matched_positions(key, attacked))

    assert clean_rate == 0.0
    assert attacked_rate == pytest.approx(0.5, abs=_tolerance(0.5, matched))
    assert attacked_rate > DEFAULT_S_V > DEFAULT_S_A


@pytest.mark.parametrize("werner_p", [0.25, 0.5, 1.0])
def test_mismatch_rate_equals_half_the_werner_parameter(werner_p: float) -> None:
    """Quantitative, not directional: a Werner-``p`` pair gives rate ``p/2``.

    Teleportation through ``(1 - p)|Phi+><Phi+| + p I/4`` is a depolarising
    channel of strength ``p``, so the received state is
    ``(1 - p)|psi><psi| + p I/2`` and a matched measurement disagrees with
    probability ``p/2``. Reproducing that closed form at three values of ``p``
    is what proves the resource really is being consumed by a teleportation
    rather than ignored.
    """
    params = _params(600)
    key = _key(params, seed=SEED + 41)
    record = _distribute(
        key,
        params,
        resource_factory=lambda: _werner(werner_p),
        seed=SEED + _DIST_OFFSET + 41,
    )
    matched = len(_matched_positions(key, record))
    expected = werner_p / 2.0
    assert _mismatch_rate(key, record) == pytest.approx(
        expected, abs=_tolerance(expected, matched)
    )


#: Werner parameters swept by
#: :func:`test_a_werner_resource_pins_the_mismatch_rate_to_half_its_parameter`.
#: ``0.0`` is the ideal pair, ``0.125`` sits near the protocol's own operating
#: range (``q / 2 = 0.0625 = DEFAULT_S_V``), and ``1.0`` is the dead link.
WERNER_LEVELS = (0.0, 0.125, 0.25, 0.5, 1.0)

#: Key length of each pooled run.  About ``WERNER_LENGTH / 3`` of its positions
#: are matched and so contribute to a rate.
WERNER_LENGTH = 600

#: Floor on the number of pooled runs, for the levels whose resolution
#: requirement is met by a single run.
WERNER_MIN_RUNS = 3


def _runs_for_resolution(level: float, matched_per_run: float) -> int:
    """Pooled runs needed to resolve ``level / 2`` to half its own size.

    The sample size is derived rather than guessed, from the same binomial
    standard error the assertion's tolerance uses.  Requiring the ``SIGMAS``-wide
    band to be at most half of the predicted rate ``e = q / 2``,

        SIGMAS * sqrt(e (1 - e) / n)  <=  e / 2,

    gives ``n >= (2 * SIGMAS)**2 * (1 - e) / e``.  That is a stronger demand than
    mere non-vacuity (``band < e``, i.e. a factor of ``SIGMAS**2``), and it is
    the reason the small-``q`` levels are pooled over more runs than the large
    ones instead of every level paying the worst case's price.

    Parameters
    ----------
    level : float
        The Werner parameter ``q``.  ``0.0`` needs no statistics -- a clean pair
        teleports exactly -- and returns the floor.
    matched_per_run : float
        Expected matched positions contributed by one run, ``L / |B|``.

    Returns
    -------
    int
        At least :data:`WERNER_MIN_RUNS`.
    """
    if level <= 0.0:
        return WERNER_MIN_RUNS
    expected = level / 2.0
    required = (2.0 * SIGMAS) ** 2 * (1.0 - expected) / expected
    return max(WERNER_MIN_RUNS, math.ceil(required / matched_per_run))


def test_a_werner_resource_pins_the_mismatch_rate_to_half_its_parameter() -> None:
    """The invariant that forces the teleportation into the data path.

    Derivation, not folklore.  Teleportation is linear in the resource, and
    every Bell outcome is equiprobable for both components of
    ``rho(q) = (1 - q)|Phi+><Phi+| + q I/4``, so conditioning on the Bell result
    does not reweight the mixture.  The ``|Phi+>`` component transmits the
    payload exactly and the ``I/4`` component leaves the receiver holding
    ``I/2`` whatever the payload was, so the corrected received state is the
    depolarising image

        E_q(|psi><psi|) = (1 - q) |psi><psi| + q I/2.

    On a *matched* position the recipient measures the very observable
    ``|psi>`` is an eigenstate of, so the Born probability of Alice's declared
    eigenvalue is ``(1 - q) * 1 + q * (1/2) = 1 - q/2`` and

        P(mismatch | matched) = q / 2,

    independently of the basis, the eigenvalue and the position.  This is the
    same line as :func:`sih141.core.teleport.teleport_channel`'s
    ``F(q) = 1 - q/2``, arrived at through the Born rule rather than through the
    fidelity, and it is the *only* observable that separates a real hop from a
    bypassed one: on an ideal resource (``q = 0``) teleporting Alice's state and
    simply handing it over are observationally identical, so no clean-channel
    assertion can ever pin the hop down.  Every claim below is therefore made at
    ``q > 0``.

    Three properties are asserted per level:

    * the pooled rate sits within a *computed* four-sigma binomial band,
      ``SIGMAS * sqrt((q/2)(1 - q/2) / m)`` for the observed matched count ``m``,
      not a guessed constant.  How many runs are pooled to reach that ``m`` is
      derived from the same standard error by :func:`_runs_for_resolution`, so
      the small-``q`` levels -- where ``q / 2`` is closest to the zero a
      bypassed hop would report -- get the extra sampling they need and the
      large ones do not pay for it;
    * that band excludes zero, so the assertion cannot be satisfied by an
      implementation that discards the teleportation result -- the test is
      checked for non-vacuity in the test itself, at every level;
    * the matched *index sets* are identical across all levels, because the
      recipient's basis draw is the first of three variates consumed per
      position whatever the channel does.  So ``q`` moved the eigenvalues and
      nothing else, and the pooled rates are comparable level by level.
    """
    params = _params(WERNER_LENGTH)
    matched_per_run = WERNER_LENGTH / len(params.bases)
    runs_for = {
        level: _runs_for_resolution(level, matched_per_run)
        for level in WERNER_LEVELS
    }
    keys = tuple(
        _key(params, message_bit=run % 2, seed=SEED + 700 + run)
        for run in range(max(runs_for.values()))
    )

    matched_sets: dict[float, tuple[tuple[int, ...], ...]] = {}
    for level in WERNER_LEVELS:
        resource = _werner(level)
        pooled_matched = 0
        pooled_mismatches = 0
        per_run_matched: list[tuple[int, ...]] = []
        for run, key in enumerate(keys[: runs_for[level]]):
            record = _distribute(
                key,
                params,
                resource_factory=lambda resource=resource: resource,
                seed=SEED + _DIST_OFFSET + 700 + run,
            )
            matched = _matched_positions(key, record)
            per_run_matched.append(matched)
            pooled_matched += len(matched)
            pooled_mismatches += _disagreements(key, record, matched)
        matched_sets[level] = tuple(per_run_matched)

        expected = level / 2.0
        observed = pooled_mismatches / pooled_matched
        if level == 0.0:
            # A clean pair is exact, so this one is an equality, not a band.
            assert observed == 0.0
            continue

        band = _tolerance(expected, pooled_matched)
        # Non-vacuity, asserted rather than argued: a run that never teleported
        # would report 0.0, which must lie outside the band this test accepts.
        assert expected - band > 0.0, (
            f"pooled matched sample of {pooled_matched} is too small at q="
            f"{level}: the {SIGMAS}-sigma band {band} around {expected} still "
            f"contains 0.0, so the assertion below would pass on a record that "
            f"never went through a teleportation"
        )
        assert observed == pytest.approx(expected, abs=band), (
            f"q={level}: pooled rate {observed} over {pooled_matched} matched "
            f"positions is more than {SIGMAS} sigma from the predicted q/2="
            f"{expected}"
        )

    # Levels are pooled over different numbers of runs, so compare the runs
    # they share: run ``r`` uses the same key seed and the same distribution
    # seed at every level.
    shared = min(len(sets) for sets in matched_sets.values())
    reference = matched_sets[WERNER_LEVELS[0]][:shared]
    for level in WERNER_LEVELS[1:]:
        assert matched_sets[level][:shared] == reference, (
            f"q={level} changed which positions are matched; the basis draw "
            f"must not depend on the resource, or the pooled rates are not "
            f"comparable across levels"
        )


def test_a_position_dependent_attack_shows_up_in_exactly_those_positions() -> None:
    """The factory is per-position, so an intermittent attacker is expressible."""
    params = _params(200)
    key = _key(params)
    half = params.key_length // 2
    calls = 0

    def intermittent() -> DensityMatrix | Statevector:
        nonlocal calls
        position, calls = calls, calls + 1
        return _werner(1.0) if position < half else ideal_resource()

    record = _distribute(key, params, resource_factory=intermittent)
    matched = _matched_positions(key, record)
    early = tuple(index for index in matched if index < half)
    late = tuple(index for index in matched if index >= half)

    assert early and late
    assert _disagreements(key, record, late) == 0
    early_rate = _disagreements(key, record, early) / len(early)
    assert early_rate == pytest.approx(0.5, abs=_tolerance(0.5, len(early)))


def test_chosen_bases_do_not_depend_on_the_resource() -> None:
    """A fixed seed gives the same basis sequence under any resource.

    Exactly three variates are consumed per position whatever the channel does,
    so an attacked run is comparable to a clean one position by position -- only
    the outcomes move. Phase 3 relies on this to attribute a rate change to the
    attack rather than to a reshuffled matched set.
    """
    params = _params(120)
    key = _key(params)
    clean = _distribute(key, params)
    attacked = _distribute(key, params, resource_factory=lambda: _werner(1.0))

    assert clean.bases == attacked.bases
    assert clean.eigenvalues != attacked.eigenvalues


def test_exactly_three_variates_are_consumed_per_key_position() -> None:
    """Basis choice, Bell measurement, projective measurement -- in that order.

    The middle draw belongs to the teleportation. An implementation that
    prepared the state at the recipient instead of teleporting it would consume
    two variates per position and fail here, so this is the second, purely
    structural guard that the hop is real.
    """
    params = _params(12)
    key = _key(params)
    generator = np.random.default_rng(SEED)
    distribute_to_recipient(key, params, party=Party.BOB, rng=generator)

    shadow = np.random.default_rng(SEED)
    for _ in range(params.key_length):
        shadow.integers(len(params.bases))  # the recipient's basis choice
        shadow.random()  # Alice's Bell measurement, inside teleport()
        shadow.random()  # the recipient's projective measurement
    assert generator.bit_generator.state == shadow.bit_generator.state

    stub = np.random.default_rng(SEED)
    for _ in range(params.key_length):
        stub.integers(len(params.bases))
        stub.random()
    assert generator.bit_generator.state != stub.bit_generator.state


def test_resource_factory_returning_none_is_refused() -> None:
    """``None`` means "ideal" to ``teleport``; forwarding it would hide an attack."""
    params = _params(4)
    with pytest.raises(ValueError, match="returned None for key position"):
        _distribute(_key(params), params, resource_factory=lambda: None)


def test_resource_factory_returning_a_one_qubit_state_is_refused() -> None:
    """The resource is an entangled *pair*; anything else is rejected loudly."""
    params = _params(4)
    with pytest.raises(ValueError, match="two-qubit state"):
        _distribute(
            _key(params), params, resource_factory=lambda: Statevector([1, 0])
        )


def test_non_callable_resource_factory_is_refused() -> None:
    """Passing a bare pair is the likely mistake; the message says how to fix it."""
    params = _params(4)
    with pytest.raises(TypeError, match="must be a callable"):
        _distribute(_key(params), params, resource_factory=ideal_resource())


# ==========================================================================
# Determinism (D3)
# ==========================================================================


def test_same_seed_reproduces_the_record_exactly() -> None:
    """One seed, one run: the log is bit-for-bit reproducible."""
    params = _params(32)
    key = _key(params)
    assert _distribute(key, params) == _distribute(key, params)


def test_different_seeds_give_different_records() -> None:
    """Distinct streams give distinct bases; the draws are genuinely random."""
    params = _params(32)
    key = _key(params)
    first = _distribute(key, params, seed=1)
    second = _distribute(key, params, seed=2)
    assert first.bases != second.bases


def test_bob_and_charlie_measure_independently() -> None:
    """Two recipients, two independent basis sequences, both exact on matches."""
    params = _params(64)
    key = _key(params)
    bob = _distribute(key, params, party=Party.BOB, seed=11)
    charlie = _distribute(key, params, party=Party.CHARLIE, seed=12)

    assert bob.bases != charlie.bases
    assert _mismatch_rate(key, bob) == 0.0
    assert _mismatch_rate(key, charlie) == 0.0


def test_an_unseeded_run_still_works() -> None:
    """``rng=None`` draws fresh entropy rather than failing (D3).

    The only unseeded test in the file, so it asserts nothing that could fail by
    luck: the matched set is whatever this run's entropy produced, possibly
    empty, and the disagreement count over it is zero either way.
    """
    params = _params(32)
    key = _key(params)
    record = distribute_to_recipient(key, params, party=Party.BOB)
    assert len(record) == params.key_length
    assert _disagreements(key, record, _matched_positions(key, record)) == 0


def test_integer_seeds_are_refused() -> None:
    """``resolve_rng`` rejects seeds; a seed would restart the stream each call."""
    params = _params(4)
    with pytest.raises(TypeError):
        distribute_to_recipient(
            _key(params), params, party=Party.BOB, rng=1234  # type: ignore[arg-type]
        )


# ==========================================================================
# Validation (D5)
# ==========================================================================


def test_alice_cannot_receive_a_public_key() -> None:
    """She signs; she keeps no record. The refusal names both facts."""
    params = _params(4)
    with pytest.raises(ValueError, match="cannot distribute a public key to Alice"):
        _distribute(_key(params), params, party=Party.ALICE)


def test_alice_is_refused_before_any_teleportation_happens() -> None:
    """The party check precedes the loop, so nothing is computed for nothing."""
    params = _params(4)
    calls = 0

    def counting_factory() -> Statevector:
        nonlocal calls
        calls += 1
        return ideal_resource()

    with pytest.raises(ValueError):
        _distribute(
            _key(params), params, party="Alice", resource_factory=counting_factory
        )
    assert calls == 0


def test_unknown_party_is_refused() -> None:
    """A typo in a party name fails loudly."""
    params = _params(4)
    with pytest.raises(ValueError, match="unknown party"):
        _distribute(_key(params), params, party="Dave")


def test_key_from_another_parameter_set_is_refused() -> None:
    """A length mismatch means the key and the record came from different runs."""
    key = _key(_params(8))
    with pytest.raises(ValueError, match="params.key_length"):
        _distribute(key, _params(16))


def test_key_using_a_foreign_basis_is_refused() -> None:
    """The alphabet fixes the match probability, so a stray basis is fatal."""
    params = _params(8)
    key = _key(params)
    restricted = _params(8, bases=(PauliBasis.X, PauliBasis.Z))
    if PauliBasis.Y not in key.bases:  # pragma: no cover - seed-dependent guard
        pytest.skip("this seed drew no Y basis")
    with pytest.raises(ValueError, match="not in params.bases"):
        _distribute(key, restricted)


def test_non_private_key_is_refused() -> None:
    """The message points at ``generate_private_key``."""
    with pytest.raises(TypeError, match="key must be a PrivateKey"):
        distribute_to_recipient(
            [("X", 1)], _params(1), party=Party.BOB  # type: ignore[arg-type]
        )


def test_non_params_is_refused() -> None:
    """A dictionary of parameters is not a validated parameter set."""
    params = _params(4)
    with pytest.raises(TypeError, match="params must be a ProtocolParams"):
        distribute_to_recipient(
            _key(params), {"key_length": 4}, party=Party.BOB  # type: ignore[arg-type]
        )


# ==========================================================================
# distribute_public_key -- both recipients, which is the point of Charlie
# ==========================================================================


def test_distribute_public_key_serves_both_verifiers() -> None:
    """One record per verifier, keyed by party, both exact on matched positions."""
    params = _params(48)
    key = _key(params)
    records = distribute_public_key(key, params, rng=np.random.default_rng(SEED))

    assert set(records) == set(VERIFIERS)
    for party, record in records.items():
        assert record.party is party
        assert record.message_bit == key.message_bit
        assert record.check_against(params) is None
        assert _mismatch_rate(key, record) == 0.0


def test_distribute_public_key_gives_the_two_recipients_independent_records() -> None:
    """Two independent preparations and two independent basis draws.

    Alice prepares each eigenstate afresh from its classical label, once per
    recipient; that is state preparation, not cloning. The two logs must
    therefore differ in their bases even though the declared key is the same.
    """
    params = _params(64)
    key = _key(params)
    records = distribute_public_key(key, params, rng=np.random.default_rng(SEED))
    assert records[Party.BOB].bases != records[Party.CHARLIE].bases


def test_distribute_public_key_consumes_a_pair_per_qubit_per_recipient() -> None:
    """``len(parties) * L`` fresh Bell pairs -- one per hop, never shared."""
    params = _params(16)
    key = _key(params)
    calls = 0

    def counting_factory() -> Statevector:
        nonlocal calls
        calls += 1
        return ideal_resource()

    distribute_public_key(
        key,
        params,
        resource_factory=counting_factory,
        rng=np.random.default_rng(SEED),
    )
    assert calls == len(VERIFIERS) * params.key_length


def test_distribute_public_key_is_deterministic_under_a_seed() -> None:
    """One seed reproduces the whole distribution phase, both recipients."""
    params = _params(24)
    key = _key(params)
    first = distribute_public_key(key, params, rng=np.random.default_rng(SEED))
    second = distribute_public_key(key, params, rng=np.random.default_rng(SEED))
    assert first == second


def test_distribute_public_key_honours_the_party_order_given() -> None:
    """The order matters to a stateful factory, so it is the caller's to choose."""
    params = _params(12)
    key = _key(params)
    records = distribute_public_key(
        key,
        params,
        parties=(Party.CHARLIE, Party.BOB),
        rng=np.random.default_rng(SEED),
    )
    assert list(records) == [Party.CHARLIE, Party.BOB]


def test_distribute_public_key_rejects_a_repeated_party() -> None:
    """A repeat would silently overwrite one recipient's record."""
    params = _params(4)
    with pytest.raises(ValueError, match="must be distinct"):
        distribute_public_key(
            _key(params),
            params,
            parties=(Party.BOB, Party.BOB),
            rng=np.random.default_rng(SEED),
        )


def test_distribute_public_key_rejects_an_empty_party_list() -> None:
    """Distributing to nobody produces nothing to verify."""
    params = _params(4)
    with pytest.raises(ValueError, match="at least one recipient"):
        distribute_public_key(
            _key(params), params, parties=(), rng=np.random.default_rng(SEED)
        )


def test_distribute_public_key_rejects_alice() -> None:
    """The signer is not a recipient, here as everywhere else."""
    params = _params(4)
    with pytest.raises(ValueError, match="cannot distribute a public key to Alice"):
        distribute_public_key(
            _key(params),
            params,
            parties=(Party.BOB, Party.ALICE),
            rng=np.random.default_rng(SEED),
        )


def test_distribute_public_key_rejects_a_non_sequence_of_parties() -> None:
    """A bare string is not a sequence of parties, however much it looks like one."""
    params = _params(4)
    with pytest.raises(TypeError, match="parties must be a sequence"):
        distribute_public_key(
            _key(params),
            params,
            parties="Bob",  # type: ignore[arg-type]
            rng=np.random.default_rng(SEED),
        )


# --------------------------------------------------------------------------- #
# The ResourceContext form of the seam                                         #
#                                                                              #
# A zero-argument factory cannot say which hop it is being asked for, so an     #
# attack aimed at one recipient used to have to reverse-engineer the call order #
# from the loops in distribute_public_key and QDSSession.distribute. That order #
# is documented but is not a contract: swapping the two entries of VERIFIERS    #
# would have redirected every party-targeted attack at the wrong party with no  #
# error and no test failure, because the only thing asserted was the total call #
# count. The context makes the seam self-describing.                           #
# --------------------------------------------------------------------------- #


def test_context_factory_is_told_the_party_bit_and_position() -> None:
    """Every call names its hop, in distribution order."""
    params = _params(4)
    key = generate_private_key(params, 1, rng=np.random.default_rng(1))
    seen: list[tuple[Party, int, int]] = []

    def watcher(context: ResourceContext) -> Statevector:
        seen.append((context.party, context.message_bit, context.position))
        return ideal_resource()

    distribute_public_key(
        key, params, resource_factory=watcher, rng=np.random.default_rng(2)
    )

    assert seen == [
        (party, 1, position)
        for party in (Party.BOB, Party.CHARLIE)
        for position in range(4)
    ]


def test_a_party_targeted_attack_needs_no_knowledge_of_the_call_order() -> None:
    """Degrading one recipient's link, keyed on the context rather than a counter.

    The attack is expressed as "if the party is Charlie", so it stays aimed at
    Charlie however the loops are ordered. The check is behavioural: Bob's
    record reproduces the key exactly on his matched positions, Charlie's does
    not.
    """
    params = _params(120)
    key = generate_private_key(params, 0, rng=np.random.default_rng(3))
    clean = ideal_resource()
    dead = DensityMatrix(np.eye(4, dtype=complex) / 4.0)

    def targeted(context: ResourceContext) -> object:
        return dead if context.party is Party.CHARLIE else clean

    records = distribute_public_key(
        key, params, resource_factory=targeted, rng=np.random.default_rng(4)
    )

    def mismatch_rate(record) -> float:
        matched = [
            index
            for index in range(len(key))
            if record.bases[index] == key.bases[index]
        ]
        assert matched
        wrong = sum(
            record.eigenvalues[index] != key.eigenvalues[index]
            for index in matched
        )
        return wrong / len(matched)

    assert mismatch_rate(records[Party.BOB]) == 0.0
    assert mismatch_rate(records[Party.CHARLIE]) > 0.25


def test_a_zero_argument_factory_is_still_called_with_no_arguments() -> None:
    """Backwards compatibility, including the closed-over-default idiom.

    ``lambda pair=pair: pair`` *accepts* one positional argument although it
    wants none. Deciding the shape by "can it accept one?" would hand it a
    ResourceContext, which ``teleport`` would then reject as a state -- so the
    rule is "can it be called with none?" instead, and this pins it.
    """
    params = _params(4)
    key = generate_private_key(params, 0, rng=np.random.default_rng(5))
    pair = ideal_resource()

    calls = {"n": 0}

    def plain() -> Statevector:
        calls["n"] += 1
        return ideal_resource()

    for factory in (plain, lambda pair=pair: pair):
        record = distribute_to_recipient(
            key,
            params,
            party=Party.BOB,
            resource_factory=factory,
            rng=np.random.default_rng(6),
        )
        assert len(record) == 4
    assert calls["n"] == 4


def test_a_factory_of_the_wrong_arity_is_refused_before_any_qubit_moves() -> None:
    """Neither shape means a wiring error, and it fails at resolution time."""
    params = _params(4)
    key = generate_private_key(params, 0, rng=np.random.default_rng(7))

    def two_arguments(context, extra):  # noqa: ANN001, ANN201
        return ideal_resource()

    with pytest.raises(TypeError, match="accepts neither"):
        distribute_to_recipient(
            key,
            params,
            party=Party.BOB,
            resource_factory=two_arguments,
            rng=np.random.default_rng(8),
        )


def test_resource_context_is_frozen_and_made_of_plain_values() -> None:
    """It can be logged or accumulated by an attack without being editable."""
    context = ResourceContext(party=Party.CHARLIE, message_bit=1, position=7)
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.position = 8  # type: ignore[misc]
    assert (context.party, context.message_bit, context.position) == (
        Party.CHARLIE,
        1,
        7,
    )


# --------------------------------------------------------------------------- #
# What the protocol DOES with what a seam returned                             #
#                                                                              #
# The seams above are called identically on both branches. That is necessary   #
# and it is not sufficient: with the calls equalised, what the loop then did    #
# with the returned object still differed, and a seam returning an instrumented #
# state read the check set off its own tally. This is the distribute-level half #
# of that -- the payload seam, whose answer used to be read by teleport() on a  #
# key round and by nothing at all on a check round. The resource seam's half is #
# only visible with the session's channel tap in place, and lives in            #
# tests/test_protocol_session.py alongside the monitor's.                       #
# --------------------------------------------------------------------------- #


class _CountingStatevector(Statevector):
    """A pure state that tallies every read of its amplitudes.

    A subclass rather than a wrapper so that it passes every ``isinstance``
    check and every coercion the protocol makes: what is being measured is the
    protocol's read pattern, not a rejection path.
    """

    def __init__(self, data: object, tally: Counter, position: int) -> None:
        super().__init__(data)
        object.__setattr__(self, "_tally", tally)
        object.__setattr__(self, "_position", position)

    @property
    def data(self) -> object:  # noqa: D102 -- overrides a qiskit property
        self._tally[self._position] += 1
        return self._data


def test_the_payload_seams_answer_is_read_once_on_both_branches() -> None:
    """Being *used* was the signal, once being *called* stopped being one.

    ``_map_payload`` is called at every position, check rounds included. Its
    answer, though, was read by :func:`~sih141.core.teleport.teleport` on a key
    round and by nothing at all on a check round, so a map returning an
    instrumented state saw a tally of ``1`` at exactly the signing positions
    and ``0`` at exactly the watched ones -- the whole check set, complemented,
    in one pass. It is now adopted the moment it is returned, so the tally is
    ``1`` everywhere.

    Asserted here without the session, because the leak is in this module's own
    loop: one link, one message bit, one plan.
    """
    params = _params(64, check_fraction=0.25)
    plan = draw_check_plan(params, rng=np.random.default_rng(SEED + 90))
    key = _key(params)
    tally: Counter = Counter()

    def payload(state: object, context: ResourceContext) -> Statevector:
        return _CountingStatevector(
            Statevector(state).data, tally, context.position
        )

    distribute_to_recipient_with_checks(
        key,
        params,
        party=Party.BOB,
        payload_map=payload,
        check_plan=plan,
        rng=np.random.default_rng(SEED + 91),
    )

    watched = set(plan.rounds_by_position(Party.BOB))
    assert watched, "the plan must designate something for this link"
    assert set(tally) == set(range(params.key_length))
    assert set(tally.values()) == {1}, (
        f"the payload seam's answer is read {sorted(set(tally.values()))} "
        f"times depending on the position, so its read tally is the check set: "
        f"{sorted(position for position in tally if tally[position] == 0)}"
    )

    # Positive control on the same instrument and the same plan: a tally with
    # the pre-fix shape must give the check set back exactly, so a probe that
    # has quietly stopped counting cannot pass the assertion above.
    pre_fix = Counter(
        {
            position: (0 if position in watched else 1)
            for position in range(params.key_length)
        }
    )
    assert {
        position for position in pre_fix if pre_fix[position] == 0
    } == watched


def test_adopt_state_keeps_the_state_and_drops_the_object() -> None:
    """The adoption must be invisible to the physics and total for the object.

    Three properties, and all three are load-bearing. The numbers survive, or
    every attack this project measures would change. The representation
    survives -- a pure state stays a :class:`~qiskit.quantum_info.Statevector`
    -- because that is :func:`~sih141.core.teleport.teleport`'s exact fidelity
    path for a pure payload, and silently moving honest runs off it would be a
    change of physics disguised as a change of plumbing (D1). And the returned
    object shares no memory with the one handed in, which is what makes the
    read tally a constant and, incidentally, stops a seam writing through to a
    pair it has already delivered.
    """
    pair = ideal_resource()
    adopted = _adopt_state(pair)
    assert isinstance(adopted, Statevector) and adopted is not pair
    assert np.allclose(adopted.data, pair.data)
    assert adopted.dims() == pair.dims()

    mixed = _werner(0.3)
    adopted_mixed = _adopt_state(mixed)
    assert isinstance(adopted_mixed, DensityMatrix)
    assert np.allclose(adopted_mixed.data, mixed.data)
    assert adopted_mixed.dims() == mixed.dims()

    # No shared memory in either representation.
    adopted.data[0] = 0.0
    adopted_mixed.data[0, 0] = 0.0
    assert np.allclose(ideal_resource().data, pair.data)
    assert np.allclose(_werner(0.3).data, mixed.data)

    # Exactly one read, whatever the representation.
    tally: Counter = Counter()
    _adopt_state(_CountingStatevector(pair.data, tally, 0))
    assert tally == Counter({0: 1})

    # A raw array is adopted too -- a seam may return one (D1) and an ndarray
    # subclass can count reads as readily as a state can.
    raw = _adopt_state([1.0, 0.0])
    assert isinstance(raw, np.ndarray) and raw.dtype == np.complex128

    # Anything that is not a state at all passes through untouched, so the
    # validator downstream still produces its own message rather than one here.
    sentinel = object()
    assert _adopt_state(sentinel) is sentinel  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Route H, and the invariant behind the whole family                           #
#                                                                              #
# Four hardening rounds have now each closed the current spelling of one idea:  #
# a seam being CALLED (routes A-C), the answer it returned being READ (D, E),   #
# a mapping being CONSUMED (F), and whether the run SURVIVED (H). Each time a   #
# spelling was closed the next one appeared, which is the signature of patching #
# instances rather than the family.                                             #
#                                                                              #
# The general statement is that an adversary at a seam observes the protocol    #
# ONLY through that seam's interaction trace -- the calls it receives, the      #
# reads made of the objects it hands over, and how the run terminated -- so:    #
#                                                                              #
#     BRANCH-BLINDNESS. For every seam and every probe, the interaction trace   #
#     at a position must not depend on the role the plan gave that position.    #
#     Equivalently: over the positions of one link the trace takes exactly ONE  #
#     distinct value. A constant carries no bits.                               #
#                                                                              #
# test_a_seams_interaction_trace_is_constant_over_the_positions_of_a_link       #
# asserts that directly, over both state seams and over both axes of the trace, #
# rather than asserting the current spelling. Its limits are stated in its own  #
# docstring and they are real: it quantifies over the probes we can write, not  #
# over every observable, and it deliberately says nothing about wall-clock time #
# (route G, docs/PHASE3.md section 12).                                         #
# --------------------------------------------------------------------------- #


_MALFORMED_PAYLOADS: dict[str, object] = {
    "two-qubit state": Statevector([1.0, 0.0, 0.0, 0.0]),
    "unnormalised statevector": Statevector(np.array([2.0, 0.0])),
    "non-Hermitian density matrix": DensityMatrix(
        np.array([[0.5, 1.0], [0.0, 0.5]])
    ),
    "negative-eigenvalue density matrix": DensityMatrix(np.diag([2.0, -1.0])),
    "non-finite amplitude": np.array([np.nan, 0.0], dtype=complex),
    "dimension three": np.array([1.0, 0.0, 0.0]),
    "not a state at all": "not a state at all",
}
"""Every malformation :func:`~sih141.core.teleport.teleport` refuses.

Route H was reported as the first of these, but the asymmetry was never about
shape -- it was that validation happened on the key branch **only**, so each of
these recovered the check set at precision ``1.0000`` and recall ``1.0000`` at
``L = 32``, ``check_fraction = 0.25``, session seed ``555``, against a per-link
base rate of ``0.1250``. Seven spellings, one cause.
"""

_MALFORMED_RESOURCES: dict[str, object] = {
    "one-qubit resource": Statevector([1.0, 0.0]),
    "unnormalised pair": Statevector(np.array([2.0, 0.0, 0.0, 0.0])),
    "negative-eigenvalue pair": DensityMatrix(
        np.diag([2.0, 0.0, 0.0, -1.0])
    ),
    "non-finite pair": np.full(4, np.nan, dtype=complex),
    "not a state at all": "not a state at all",
}
"""The same families on the *other* state seam, which never had the oracle.

A malformed resource already raised on both branches -- ``teleport`` on a key
round and ``observe_qber_round`` on a check one -- so there was nothing to
close here. It is probed anyway, because "the fix left the resource seam
undisturbed" is a claim, and a claim about a side channel is worth measuring
rather than assuming.
"""


def _checked_link_plan(
    params: ProtocolParams, seed: int
) -> tuple[CheckRoundPlan, frozenset[int]]:
    """Draw a plan and return it with the positions it reserved for Bob."""
    plan = draw_check_plan(params, rng=np.random.default_rng(seed))
    watched = frozenset(plan.rounds_by_position(Party.BOB))
    assert watched, "the plan must designate something for this link to hide"
    assert len(watched) < params.key_length, "and must not reserve everything"
    return plan, watched


def _terminal_event(
    params: ProtocolParams,
    plan: CheckRoundPlan,
    *,
    payload_map: object = None,
    resource_factory: object = None,
    seed: int = SEED,
) -> str:
    """Distribute one link once and report only how the run TERMINATED.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set, which must reserve check rounds.
    plan : CheckRoundPlan
        The plan whose branch assignment is the secret under test.
    payload_map, resource_factory : callable or None, optional
        Keyword-only. The seam being probed; the other is left honest.
    seed : int, optional
        Keyword-only. The distribution stream's seed.

    Returns
    -------
    str
        ``"survived"``, or ``"raised:<class>:<module>:<function>"`` -- the
        terminal event as an adversary at a seam reads it, *including where the
        refusal came from*, because a refusal that moves between two raise
        sites is still a two-valued observable even when its type does not
        change.
    """
    kwargs: dict[str, object] = {}
    if payload_map is not None:
        kwargs["payload_map"] = payload_map
    if resource_factory is not None:
        kwargs["resource_factory"] = resource_factory
    try:
        distribute_to_recipient_with_checks(
            _key(params),
            params,
            party=Party.BOB,
            check_plan=plan,
            rng=np.random.default_rng(seed),
            **kwargs,  # type: ignore[arg-type]
        )
    except Exception as exc:  # noqa: BLE001 -- the probe reads exactly this
        frame = traceback.extract_tb(exc.__traceback__)[-1]
        return (
            f"raised:{type(exc).__name__}:"
            f"{os.path.basename(frame.filename)}:{frame.name}"
        )
    return "survived"


def test_a_malformed_payload_no_longer_says_which_branch_a_position_took() -> None:
    """Route H, closed: the terminal event is constant over the positions.

    A payload seam returning one malformed state at one position used to turn
    *did the run raise* into a clean read of that position's branch, because a
    key round handed the mapped payload to
    :func:`~sih141.core.teleport.teleport`, which validated it, while a check
    round discarded it unexamined. One exact bit per run, with no
    instrumentation and no statistics.

    The payload precondition is now enforced in
    :func:`~sih141.protocol.distribute._map_payload`, above the branch, so
    every position of the link terminates identically. The assertion is on the
    *number of distinct outcomes* rather than on which outcome, because that is
    what closes the route: it would be equally closed if every position
    survived.

    Both readings of the constant are scored, which is the part that keeps the
    result honest -- "precision fell" must not be an artefact of the adversary
    having been made to guess the wrong side of a signal that is still there.
    """
    params = _params(48, check_fraction=0.25)
    plan, watched = _checked_link_plan(params, SEED + 130)
    positions = frozenset(range(params.key_length))

    for name, bad in _MALFORMED_PAYLOADS.items():
        outcomes = {
            position: _terminal_event(
                params,
                plan,
                payload_map=(
                    lambda state, context, position=position, bad=bad: (
                        bad if context.position == position else state
                    )
                ),
            )
            for position in positions
        }
        distinct = set(outcomes.values())
        assert len(distinct) == 1, (
            f"the terminal event under a {name} payload takes "
            f"{len(distinct)} values over one link's positions, so it names "
            f"the branch: "
            f"{sorted(p for p in outcomes if outcomes[p] == 'survived')}"
        )
        assert distinct == {"raised:ValueError:distribute.py:_map_payload"}, (
            f"a {name} payload must be refused at the seam, above the branch; "
            f"got {distinct}"
        )

        # Both ways round, scored against ground truth the probe may not read.
        survivors = frozenset(p for p in outcomes if outcomes[p] == "survived")
        assert not survivors, f"a {name} payload still survives somewhere"
        complement = positions - survivors
        assert len(complement & watched) / len(complement) == pytest.approx(
            len(watched) / params.key_length
        ), "guessing the other way round must land exactly on the base rate"

    # Positive control on the same scorer. The PRE-FIX shape of this
    # observable must hand the check set straight back, so a probe that has
    # quietly stopped distinguishing anything cannot pass the assertions above
    # by observing nothing -- which is exactly how one isolation check failed
    # silently for a whole phase (docs/PHASE3.md section 7).
    pre_fix = {
        position: ("survived" if position in watched else "raised")
        for position in positions
    }
    assert {p for p in pre_fix if pre_fix[p] == "survived"} == watched


def test_the_resource_seam_refuses_a_malformed_pair_from_one_place() -> None:
    """Route I: the resource seam's raise SITE named the branch. Now closed.

    The previous round checked that a malformed resource raises on **both**
    branches and concluded the resource line carried no equivalent of route H.
    The first half is true and this test still asserts it. The second half did
    not follow, and the branch-blindness probe below found the gap on its first
    run: both branches raised ``ValueError``, but from two different functions,
    because they spell the *arity* half of one shared precondition in two
    places -- :func:`~sih141.core.teleport._resource_density` on a key round
    and :func:`~sih141.protocol.checkrounds._as_resource` on a check one. An
    adversary holding this seam is code in the same process and reads a
    traceback in three lines.

    Measured before the fix, at ``L = 32``, ``check_fraction = 0.25``, session
    seed ``555``: a one-qubit resource refused from ``teleport`` at every key
    position and from ``session._as_pair`` at every check position --
    precision ``1.0000``, recall ``1.0000`` against a base rate of ``0.1250``.
    Confirmed present at ``HEAD`` before this round touched anything, so it was
    found rather than introduced.

    It was one family wide where route H was seven, because the *physicality*
    half of the precondition already routed through one shared helper on both
    branches. Hoisting the arity check to the seam introduces no new rule and
    changes no accepted input.

    The raise *site* is therefore part of what is asserted, not just the
    exception class: a refusal that moves between two functions is a
    two-valued observable however uniform its type.
    """
    params = _params(48, check_fraction=0.25)
    plan, watched = _checked_link_plan(params, SEED + 133)

    for name, bad in _MALFORMED_RESOURCES.items():
        outcomes = {
            position: _terminal_event(
                params,
                plan,
                resource_factory=(
                    lambda context, position=position, bad=bad: (
                        bad if context.position == position else ideal_resource()
                    )
                ),
            )
            for position in range(params.key_length)
        }
        distinct = set(outcomes.values())
        assert len(distinct) == 1, (
            f"a {name} names the branch through its terminal event: "
            f"{sorted(distinct)}"
        )
        assert distinct == {"raised:ValueError:distribute.py:_draw_resource"}, (
            f"a {name} must be refused at the seam, above the branch, so that "
            f"the traceback is the same object on both; got {distinct}"
        )
        # The route-H half of the claim, which was always true here: nothing
        # malformed survives either branch.
        assert "survived" not in distinct

    # Positive control: the PRE-FIX shape of this observable -- the same
    # exception class from two different sites -- must hand the check set back.
    pre_fix = {
        position: (
            "raised:ValueError:session.py:_as_pair"
            if position in watched
            else "raised:ValueError:teleport.py:_resource_density"
        )
        for position in range(params.key_length)
    }
    assert len(set(pre_fix.values())) == 2
    assert {
        p for p in pre_fix if pre_fix[p].endswith("_as_pair")
    } == watched


def test_the_payload_precondition_is_the_one_teleport_enforces() -> None:
    """The seam refuses exactly what ``teleport`` refuses -- no more, no less.

    A *narrower* check leaves the route open in every spelling it does not
    cover, which is what a bare shape check would have done: six of the seven
    malformations in :data:`_MALFORMED_PAYLOADS` are not shape errors. A
    *wider* one refuses payloads the protocol may legitimately send -- a mixed
    preparation, say -- and would silently delete an attack Phase 3 relies on
    being expressible.

    So the rule is not restated in ``distribute``; ``_map_payload`` calls the
    very function ``teleport`` calls, and this pins the agreement both ways.
    """
    context = ResourceContext(party=Party.BOB, message_bit=0, position=3)
    honest = Statevector([1.0, 0.0])

    for name, bad in _MALFORMED_PAYLOADS.items():
        with pytest.raises(ValueError, match="teleport cannot send"):
            _map_payload(lambda state, ctx, bad=bad: bad, honest, context)
        with pytest.raises(ValueError):
            teleport(bad, resource=ideal_resource())  # type: ignore[arg-type]
        assert name  # carried for the failure message only

    # Everything teleport accepts still goes through untouched, mixed states
    # included: a maximally mixed payload is how Phase 3 expresses an imperfect
    # source, and it must not have become an error.
    for good in (
        honest,
        Statevector(np.array([1.0, 1.0]) / math.sqrt(2.0)),
        DensityMatrix(np.eye(2) / 2.0),
    ):
        sent = _map_payload(lambda state, ctx, good=good: good, honest, context)
        assert np.allclose(np.asarray(sent.data), np.asarray(good.data))
        teleport(sent, resource=ideal_resource(), rng=np.random.default_rng(1))


def test_the_seam_is_still_read_exactly_once_after_the_new_check() -> None:
    """The new validation must not put the read tally back where route E was.

    ``_map_payload`` adopts first and validates the **copy**, so the seam's own
    object is still touched exactly once. Validating the seam's object instead
    would have been the natural way to write it and would have restored a tally
    of two -- constant, so not a leak in itself, but one edit away from being
    one again, and it would have thrown away the property adoption exists to
    give.
    """
    params = _params(64, check_fraction=0.25)
    plan, _ = _checked_link_plan(params, SEED + 131)
    tally: Counter = Counter()

    def payload(state: object, context: ResourceContext) -> Statevector:
        return _CountingStatevector(
            Statevector(state).data, tally, context.position
        )

    distribute_to_recipient_with_checks(
        _key(params),
        params,
        party=Party.BOB,
        payload_map=payload,
        check_plan=plan,
        rng=np.random.default_rng(SEED + 132),
    )
    assert set(tally) == set(range(params.key_length))
    assert set(tally.values()) == {1}, (
        f"the payload seam's answer is now read {sorted(set(tally.values()))} "
        f"times; adoption must remain the only read of the seam's own object"
    )


class _TracingStatevector(Statevector):
    """A state that records the **name** of every public attribute touched.

    Strictly wider than :class:`_CountingStatevector`, which counts reads of
    ``data`` alone. An adversary does not have to instrument the attribute the
    last round happened to leak through: ``dims()``, ``num_qubits``,
    ``purity()`` and ``to_operator()`` are all reads, and a branch that touched
    any one of them and no other would be just as legible as a branch that read
    ``data`` twice. Recording the ordered sequence of names makes the probe
    independent of which spelling comes next.

    A subclass rather than a wrapper, so it passes every ``isinstance`` check
    and every coercion the protocol makes: what is under test is the read
    pattern, not a rejection path.
    """

    def __init__(self, data: object, trace: list[str]) -> None:
        object.__setattr__(self, "_trace", trace)
        super().__init__(data)

    def __getattribute__(self, name: str) -> object:
        if not name.startswith("_"):
            try:
                object.__getattribute__(self, "_trace").append(name)
            except AttributeError:  # during __init__, before _trace exists
                pass
        return object.__getattribute__(self, name)


def test_a_seams_interaction_trace_is_constant_over_the_positions_of_a_link() -> None:
    """BRANCH-BLINDNESS, asserted directly instead of one more instance of it.

    Routes A-F and H are one statement in four spellings: an adversary at a
    seam observes the protocol only through that seam's **interaction trace**
    -- which calls it received, what was read of the objects it handed over,
    and how the run terminated -- and any component of that trace which varies
    with the branch is a channel of exactly the width of its variation. So the
    property to assert is not "the payload is read once" or "a malformed
    payload raises on both branches" but:

        over the positions of one link, the trace takes exactly ONE value.

    A constant carries no bits, whatever an adversary does with it, so a test
    that pins constancy needs no threshold and cannot be satisfied by a
    detector that merely got harder to read.

    Two axes are swept, on both state seams:

    * **reads** -- a probe recording the ordered sequence of every public
      attribute name the protocol touches, which subsumes the ``data`` counter
      that found routes D and E without presupposing that ``data`` is the
      attribute the next leak arrives through;
    * **termination** -- routes of the shape of H, covered by the malformed
      families above and asserted again here through the same scorer, so both
      axes are stated in one place.

    Limits, stated because a general-sounding test that quietly is not one is
    worse than an honest instance:

    1. It quantifies over the probes that can be **written here**, not over
       every observable. It is a test, not an impossibility proof. A genuinely
       new *kind* of observable -- one that is neither a call, nor a read of a
       handed-over object, nor the run's terminal event -- needs a new probe,
       and the invariant would then be asserted over that too.
    2. It says nothing about **wall-clock time**. The trace is causal, not
       temporal, by construction. Route G is excluded here for the same reason
       it is excluded in ``docs/PHASE3.md`` section 12, and an assertion about
       a timing gap would be an assertion about the machine the suite runs on.
    3. It is per-link and per-run. Correlations *across* runs of a session are
       a different observable and are not in scope.
    """
    params = _params(48, check_fraction=0.25)
    plan, watched = _checked_link_plan(params, SEED + 134)
    positions = frozenset(range(params.key_length))

    # -- axis 1: reads, on both state seams ------------------------------- #
    for seam in ("payload_map", "resource_factory"):
        traces: dict[int, list[str]] = {
            position: [] for position in positions
        }

        def payload(state: object, context: ResourceContext) -> Statevector:
            return _TracingStatevector(
                Statevector(state).data, traces[context.position]
            )

        def factory(context: ResourceContext) -> Statevector:
            return _TracingStatevector(
                ideal_resource().data, traces[context.position]
            )

        distribute_to_recipient_with_checks(
            _key(params),
            params,
            party=Party.BOB,
            check_plan=plan,
            rng=np.random.default_rng(SEED + 135),
            **{seam: payload if seam == "payload_map" else factory},
        )

        distinct = {tuple(trace) for trace in traces.values()}
        assert len(distinct) == 1, (
            f"the {seam} seam's object is read differently depending on the "
            f"branch, so the read trace names the check set. Traces seen: "
            f"{sorted(distinct)}; the positions with the minority trace are "
            f"{sorted(p for p in traces if tuple(traces[p]) != max(distinct, key=lambda t: sum(tuple(v) == t for v in map(tuple, traces.values()))))}"
        )
        assert distinct != {()}, (
            f"the {seam} probe recorded nothing at all, so its constancy is "
            f"vacuous -- the seam must be read at least once per position"
        )

    # -- axis 2: termination, on both state seams ------------------------- #
    for label, seam, bad in (
        ("payload", "payload_map", Statevector([1.0, 0.0, 0.0, 0.0])),
        ("resource", "resource_factory", Statevector([1.0, 0.0])),
    ):
        outcomes = {
            position: _terminal_event(
                params,
                plan,
                **{
                    seam: (
                        (
                            lambda state, context, position=position, bad=bad: (
                                bad if context.position == position else state
                            )
                        )
                        if seam == "payload_map"
                        else (
                            lambda context, position=position, bad=bad: (
                                bad
                                if context.position == position
                                else ideal_resource()
                            )
                        )
                    )
                },
            )
            for position in positions
        }
        assert len(set(outcomes.values())) == 1, (
            f"the {label} seam's terminal event names the branch: "
            f"{sorted(set(outcomes.values()))}"
        )

    # -- the control, for both axes at once ------------------------------- #
    #
    # Each axis is scored by "how many distinct values did this observable
    # take", so a probe that has stopped observing scores 1 and passes. The
    # control is the same scorer applied to a synthetic PRE-FIX trace, which
    # must take two values and must hand back exactly the check set.
    pre_fix = {
        position: ("watched" if position in watched else "signing")
        for position in positions
    }
    assert len(set(pre_fix.values())) == 2
    assert {p for p in pre_fix if pre_fix[p] == "watched"} == watched
