"""Tests for :mod:`sih141.protocol.symmetrise`.

The exchange is three lines of bookkeeping carrying one security property, so
the tests here are of two kinds:

* **Structural.** The multiset of entries is conserved exactly, each verifier
  keeps one entry per position, the coins are the only randomness and one seed
  reproduces them, and every malformed input is refused with a message that says
  which invariant it broke. Conservation is not decoration: the whole
  non-repudiation argument rests on ``e_B + e_C`` and ``m_B + m_C`` being
  coin-independent constants.

* **Behavioural, against the attack the step exists for.** A dishonest Alice who
  sends Bob the eigenstate she declares and Charlie its orthogonal partner
  repudiates with probability ``1`` when the exchange is skipped, and never once
  it is applied. That pair of assertions is the point of the module and is
  written here rather than in a docstring.
"""

from __future__ import annotations

import numpy as np
import pytest

from sih141.core.paulis import PauliBasis
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.records import RecipientRecord
from sih141.protocol.signature import Signature
from sih141.protocol.symmetrise import (
    no_symmetrisation,
    symmetrise_records,
)
from sih141.protocol.verify import verify, verify_all

BASES = (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)


def raw_pair(
    length: int, *, message_bit: int = 0, rng: np.random.Generator | None = None
) -> dict[Party, RecipientRecord]:
    """Build a pair of distinct raw records without running the quantum phase."""
    generator = np.random.default_rng(0) if rng is None else rng
    made: dict[Party, RecipientRecord] = {}
    for party in (Party.BOB, Party.CHARLIE):
        bases = [BASES[int(generator.integers(3))] for _ in range(length)]
        values = [int(1 - 2 * generator.integers(2)) for _ in range(length)]
        made[party] = RecipientRecord.from_measurements(
            party, message_bit, bases, values
        )
    return made


# --------------------------------------------------------------------------- #
# Structure: what the exchange must preserve                                   #
# --------------------------------------------------------------------------- #


def test_exchange_conserves_every_entry_position_by_position() -> None:
    """At each position the two entries are the same pair, possibly swapped.

    This is the conservation the Hoeffding argument of section 4b rests on:
    because the coins only re-assign a fixed collection, ``m_B + m_C`` and
    ``e_B + e_C`` are constants and repudiation needs a large deviation of the
    *split*. If an entry could be dropped, duplicated or altered here, the bound
    would be about a different random variable than the protocol produces.
    """
    raw = raw_pair(64, rng=np.random.default_rng(11))
    swapped = symmetrise_records(raw, rng=np.random.default_rng(12))

    for index in range(64):
        before = {
            raw[Party.BOB].entries[index],
            raw[Party.CHARLIE].entries[index],
        }
        after = {
            swapped[Party.BOB].entries[index],
            swapped[Party.CHARLIE].entries[index],
        }
        assert before == after


def test_exchange_actually_swaps_about_half_the_positions() -> None:
    """The coins are fair, so roughly half of Bob's entries came from Charlie.

    A five-sigma band on ``Binomial(n, 1/2)``. Asserted because "conserves the
    multiset" is also satisfied by doing nothing at all, and doing nothing is
    exactly the failure mode this module exists to prevent.
    """
    length = 2000
    raw = raw_pair(length, rng=np.random.default_rng(21))
    swapped = symmetrise_records(raw, rng=np.random.default_rng(22))

    moved = sum(
        swapped[Party.BOB].entries[index] != raw[Party.BOB].entries[index]
        for index in range(length)
    )
    # Entries can coincide by chance (same basis and eigenvalue), which only
    # ever makes `moved` an undercount, so the lower band is the binding one.
    band = 5.0 * np.sqrt(length * 0.25)
    assert length / 2 - band - length / 6 <= moved <= length / 2 + band


def test_exchange_keeps_one_entry_per_position_for_each_verifier() -> None:
    """Both logs stay ``L`` long with indices ``0..L-1``, so nothing downstream
    changes shape."""
    raw = raw_pair(30, message_bit=1, rng=np.random.default_rng(31))
    swapped = symmetrise_records(raw, rng=np.random.default_rng(32))

    for party in (Party.BOB, Party.CHARLIE):
        record = swapped[party]
        assert len(record) == 30
        assert record.party is party
        assert record.message_bit == 1
        assert [entry.index for entry in record.entries] == list(range(30))
        assert record.symmetrised is True


def test_exchange_is_reproducible_under_a_seed() -> None:
    """D3: the coins come from the injected generator and nowhere else."""
    raw = raw_pair(40, rng=np.random.default_rng(41))
    first = symmetrise_records(raw, rng=np.random.default_rng(7))
    second = symmetrise_records(raw, rng=np.random.default_rng(7))
    third = symmetrise_records(raw, rng=np.random.default_rng(8))

    assert first == second
    assert first != third


def test_exchange_consumes_one_draw_whatever_the_key_length() -> None:
    """One array draw per call, so the stream position does not depend on ``L``.

    The original reason for this pin no longer applies: the coins now come off the
    session's *recipient* stream while the distributions come off its *Alice*
    stream, so a per-position draw here can no longer shift the distributions at
    all. The property is still worth pinning, for a narrower reason -- it keeps the
    recipient stream's position after the first message bit independent of ``L``,
    so the second bit's coins stay reproducible from the seed alone rather than
    from the seed plus the key length.
    """
    reference = np.random.default_rng(99)
    reference.integers(0, 2, size=17)
    expected = reference.random()

    generator = np.random.default_rng(99)
    symmetrise_records(raw_pair(17, rng=np.random.default_rng(5)), rng=generator)
    assert generator.random() == expected


def test_no_symmetrisation_returns_the_same_objects_and_no_flag() -> None:
    """The Phase 3 seam is the identity, and says so in the record's provenance."""
    raw = raw_pair(12, rng=np.random.default_rng(51))
    kept = no_symmetrisation(raw)

    assert kept[Party.BOB] is raw[Party.BOB]
    assert kept[Party.CHARLIE] is raw[Party.CHARLIE]
    assert not kept[Party.BOB].symmetrised
    assert not kept[Party.CHARLIE].symmetrised


def test_no_symmetrisation_consumes_no_randomness() -> None:
    """The insecure arm leaves the session's stream where the secure one found it.

    Not a nicety: it is what makes an attacked run and a clean run differ in one
    callable rather than in every subsequent draw.
    """
    generator = np.random.default_rng(3)
    expected = np.random.default_rng(3).random()
    no_symmetrisation(raw_pair(9, rng=np.random.default_rng(4)), rng=generator)
    assert generator.random() == expected


# --------------------------------------------------------------------------- #
# Refusals                                                                     #
# --------------------------------------------------------------------------- #


def test_exchange_refuses_a_single_recipient() -> None:
    """With one recipient there is nothing to exchange and nothing to protect."""
    raw = raw_pair(6, rng=np.random.default_rng(61))
    with pytest.raises(ValueError, match="both verifiers"):
        symmetrise_records({Party.BOB: raw[Party.BOB]})


def test_exchange_refuses_a_mislabelled_record() -> None:
    """The key selects who ends up holding what, so it has to match the record."""
    raw = raw_pair(6, rng=np.random.default_rng(62))
    with pytest.raises(ValueError, match="keyed by"):
        symmetrise_records(
            {
                Party.BOB: raw[Party.CHARLIE],
                Party.CHARLIE: raw[Party.CHARLIE],
            }
        )


def test_exchange_refuses_records_of_different_lengths() -> None:
    """The exchange is positional."""
    short = raw_pair(6, rng=np.random.default_rng(63))
    long = raw_pair(7, rng=np.random.default_rng(64))
    with pytest.raises(ValueError, match="different lengths"):
        symmetrise_records(
            {Party.BOB: short[Party.BOB], Party.CHARLIE: long[Party.CHARLIE]}
        )


def test_exchange_refuses_records_from_different_message_bits() -> None:
    """Swapping across bits would hand a verifier evidence about another key."""
    zero = raw_pair(6, message_bit=0, rng=np.random.default_rng(65))
    one = raw_pair(6, message_bit=1, rng=np.random.default_rng(66))
    with pytest.raises(ValueError, match="different distribution runs"):
        symmetrise_records(
            {Party.BOB: zero[Party.BOB], Party.CHARLIE: one[Party.CHARLIE]}
        )


def test_exchange_refuses_to_run_twice() -> None:
    """A second round re-randomises an assignment Alice is already committed to."""
    raw = raw_pair(8, rng=np.random.default_rng(67))
    once = symmetrise_records(raw, rng=np.random.default_rng(1))
    with pytest.raises(ValueError, match="already been symmetrised"):
        symmetrise_records(once, rng=np.random.default_rng(2))


def test_exchange_refuses_a_non_mapping() -> None:
    """The input is the mapping distribute_public_key returns."""
    with pytest.raises(TypeError, match="mapping of Party"):
        symmetrise_records([1, 2])  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The attack the exchange exists for                                           #
# --------------------------------------------------------------------------- #


def _orthogonal_delivery_pair(
    key: PrivateKey, *, attacked: np.ndarray
) -> dict[Party, RecipientRecord]:
    """Records for an Alice who delivers Charlie the *orthogonal* state.

    Written directly rather than simulated: every recipient is given the basis
    Alice declares (so every position is matched, which is the worst case for
    her) and the declared eigenvalue, except that Charlie's copy is flipped on
    the ``attacked`` positions. That is exactly ``q_B = 0``, ``q_C = 1`` there --
    the strategy family the old i.i.d.-``q`` repudiation model cannot express.
    """
    bob = RecipientRecord.from_measurements(
        Party.BOB, key.message_bit, key.bases, key.eigenvalues
    )
    charlie = RecipientRecord.from_measurements(
        Party.CHARLIE,
        key.message_bit,
        key.bases,
        [
            -value if flipped else value
            for value, flipped in zip(key.eigenvalues, attacked)
        ],
    )
    return {Party.BOB: bob, Party.CHARLIE: charlie}


@pytest.mark.parametrize("fraction", [0.30, 0.50, 1.00])
def test_asymmetric_alice_repudiates_without_the_exchange(
    fraction: float,
) -> None:
    """The attack, unmitigated: Bob accepts at rate 0, Charlie rejects, always.

    This is the defect the exchange was added to fix, kept as an executable
    statement of it. Note the failure is not statistical -- it succeeds on every
    seed, at every key length -- which is why no amount of ``L`` repaired it and
    why the fix had to be structural.
    """
    params = ProtocolParams(key_length=300)
    generator = np.random.default_rng(int(fraction * 1000))
    key = PrivateKey(
        0,
        tuple(
            KeyElement(
                BASES[int(generator.integers(3))],
                int(1 - 2 * generator.integers(2)),
            )
            for _ in range(params.key_length)
        ),
    )
    attacked = generator.random(params.key_length) < fraction
    raw = _orthogonal_delivery_pair(key, attacked=attacked)
    declaration = Signature(0, key)

    results = verify_all(
        declaration, raw, params, require_symmetrised=False
    )
    assert results[Party.BOB].accepted
    assert results[Party.BOB].rate == 0.0
    assert not results[Party.CHARLIE].accepted
    assert results[Party.CHARLIE].rate > params.s_v


@pytest.mark.parametrize("fraction", [0.30, 0.50, 1.00])
def test_the_exchange_defeats_the_same_attack(fraction: float) -> None:
    """With the exchange, the two rates move together and Bob rejects first.

    The mechanism, visible in the assertion: after the swap each verifier holds
    the good copy at about half the attacked positions and the bad copy at the
    other half, so ``r_B`` and ``r_C`` both concentrate near ``fraction / 2``.
    Alice cannot push one across ``s_v`` without pushing the other across the
    much tighter ``s_a``, and repudiation -- Bob accepting what Charlie
    rejects -- never happens.
    """
    params = ProtocolParams(key_length=300)
    repudiations = 0
    for seed in range(30):
        generator = np.random.default_rng(1000 + seed)
        key = PrivateKey(
            0,
            tuple(
                KeyElement(
                    BASES[int(generator.integers(3))],
                    int(1 - 2 * generator.integers(2)),
                )
                for _ in range(params.key_length)
            ),
        )
        attacked = generator.random(params.key_length) < fraction
        raw = _orthogonal_delivery_pair(key, attacked=attacked)
        exchanged = symmetrise_records(raw, rng=generator)
        results = verify_all(Signature(0, key), exchanged, params)

        if results[Party.BOB].accepted and not results[Party.CHARLIE].accepted:
            repudiations += 1
        # Both rates sit near fraction/2 -- the attack is split evenly rather
        # than aimed -- so with s_a well below that, Bob rejects too.
        assert abs(results[Party.BOB].rate - fraction / 2) < 0.12
        assert abs(results[Party.CHARLIE].rate - fraction / 2) < 0.12

    assert repudiations == 0


def test_verify_all_refuses_an_unsymmetrised_pair_by_default() -> None:
    """The provenance check, at the one place both verdicts are produced."""
    params = ProtocolParams(key_length=30)
    generator = np.random.default_rng(77)
    key = PrivateKey(
        0,
        tuple(
            KeyElement(
                BASES[int(generator.integers(3))],
                int(1 - 2 * generator.integers(2)),
            )
            for _ in range(params.key_length)
        ),
    )
    raw = _orthogonal_delivery_pair(
        key, attacked=np.zeros(params.key_length, dtype=bool)
    )
    declaration = Signature(0, key)

    with pytest.raises(ValueError, match="has not been symmetrised"):
        verify_all(declaration, raw, params)

    # ... but a single verdict makes no cross-party claim, so verify() itself
    # scores a raw record without complaint.
    assert verify(declaration, raw[Party.BOB], params).accepted
