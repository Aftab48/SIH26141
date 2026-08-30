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
