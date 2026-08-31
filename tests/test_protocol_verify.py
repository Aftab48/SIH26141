"""Tests for :mod:`sih141.protocol.signature` and :mod:`sih141.protocol.verify`.

Phases B and C: Alice declares the private key, and each recipient scores it
against the classical log it made back in Phase A.

What is pinned here, in order of how badly it fails silently.

1. **Only matched positions may be scored.** This is *the* correctness point of
   the phase and the classic bug in this protocol family. It is attacked from
   both sides: a crafted record whose unmatched positions **all** contradict the
   declaration must still verify at rate ``0.0``
   (:func:`test_unmatched_positions_are_discarded_even_when_all_of_them_disagree`),
   and the same record scored the buggy way is shown to produce a rate above
   ``s_v`` that would reject an honest signature at both verifiers. An
   implementation that divided by ``L`` instead of ``|M_R|`` cannot pass either.
2. **The empty matched set.** ``|M_R| == 0`` makes the rate ``0/0``. Neither
   verdict is honest there -- accepting takes any declaration on zero evidence,
   rejecting is recorded as a forgery detection that never happened -- so it
   raises, and the test asserts the exception rather than a decision.
3. **The two thresholds do their job.** Bob is scored against ``s_a``, Charlie
   against ``s_v``, always read from the record's own party. A single crafted
   rate in the gap makes Bob reject while Charlie accepts, and the
   transferability direction (accepted by Bob implies accepted by Charlie) is
   asserted over a grid of rates rather than at one point.
4. **Verification cannot touch its evidence.** The record and the signature
   compare equal to deep copies of themselves across the call, and every stored
   view is still identical.
5. **Cross-run pairings are refused.** Wrong message bit, wrong length, wrong
   parameter set, a record keyed under the other party -- each fails loudly,
   because each produces the same near-chance mismatch rate that looks like a
   noisy channel.

Crafted versus physical records
-------------------------------
Most assertions here use :func:`_crafted_record`, which builds a log with an
exactly known matched set and an exactly known number of mismatches. That makes
the threshold tests deterministic to the last bit instead of statistical --
these are tests of a counting rule, and the physics of the counting rule's input
is already pinned in ``tests/test_protocol_distribute.py``. The end-to-end tests
at the top and the Werner-channel test at the bottom keep a genuine
teleportation in the loop so the two halves cannot drift apart.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import math

import numpy as np
import pytest

from qiskit.quantum_info import DensityMatrix

from sih141.core.paulis import PauliBasis
from sih141.core.states import BellState, bell_state
from sih141.protocol import (
    DEFAULT_S_A,
    DEFAULT_S_V,
    VERIFIERS,
    KeyElement,
    Party,
    PrivateKey,
    ProtocolParams,
    RecipientRecord,
    Signature,
    VerificationResult,
    distribute_public_key,
    distribute_to_recipient,
    generate_key_pair,
    generate_private_key,
    matched_positions,
    mismatch_positions,
    sign,
    symmetrise_records,
    verify,
    verify_all,
)

SEED = 20260141
"""Base seed for key generation."""

_DIST_OFFSET = 900_000
"""Offset keeping the distribution stream disjoint from the key stream."""

SIGMAS = 4.0
"""Tolerance width for the one statistical assertion in the file."""


# ==========================================================================
# Helpers
# ==========================================================================


def _params(length: int = 24, **changes: object) -> ProtocolParams:
    """Build a small valid parameter set."""
    return ProtocolParams(key_length=length, **changes)  # type: ignore[arg-type]


def _key(
    params: ProtocolParams, message_bit: int = 0, seed: int = SEED
) -> PrivateKey:
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
    """Run one real distribution on a freshly seeded generator."""
    return distribute_to_recipient(
        key,
        params,
        party=party,
        resource_factory=resource_factory,  # type: ignore[arg-type]
        rng=np.random.default_rng(seed),
    )


def _other_basis(basis: PauliBasis, params: ProtocolParams) -> PauliBasis:
    """Return some basis from the alphabet that is not ``basis``."""
    for candidate in params.bases:
        if candidate is not basis:
            return candidate
    raise AssertionError("a valid alphabet always holds at least two bases")


def _crafted_record(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    party: Party | str = Party.BOB,
    matched: tuple[int, ...] | None = None,
    corrupted: tuple[int, ...] = (),
    unmatched_disagree: bool = True,
) -> RecipientRecord:
    """Build a log with an exactly known matched set and mismatch count.

    Parameters
    ----------
    key : PrivateKey
        The key whose declaration the log will be scored against.
    params : ProtocolParams
        Supplies the alphabet used to pick a deliberately *wrong* basis.
    party : Party or str, optional
        Whose log this is; it selects the threshold at verification.
    matched : tuple of int or None, optional
        Positions where the recipient is made to have chosen Alice's basis.
        Defaults to every third position.
    corrupted : tuple of int, optional
        Matched positions whose outcome is flipped, i.e. the intended
        mismatches. Must be a subset of ``matched``.
    unmatched_disagree : bool, optional
        When ``True`` (the default) *every* unmatched position is given the
        opposite of the declared eigenvalue. A correct verifier must not notice.

    Returns
    -------
    RecipientRecord
    """
    if matched is None:
        matched = tuple(range(0, len(key), 3))
    matched_set = set(matched)
    corrupted_set = set(corrupted)
    assert corrupted_set <= matched_set, "corrupted positions must be matched"

    bases: list[PauliBasis] = []
    eigenvalues: list[int] = []
    for index, element in enumerate(key.elements):
        if index in matched_set:
            bases.append(element.basis)
            eigenvalues.append(
                -element.eigenvalue
                if index in corrupted_set
                else element.eigenvalue
            )
        else:
            bases.append(_other_basis(element.basis, params))
            eigenvalues.append(
                -element.eigenvalue
                if unmatched_disagree
                else element.eigenvalue
            )
    return RecipientRecord.from_measurements(
        party, key.message_bit, bases, eigenvalues
    )


def _buggy_rate(key: PrivateKey, record: RecipientRecord) -> float:
    """The rate an implementation gets if it forgets to discard the unmatched.

    Disagreements over *all* ``L`` positions rather than over ``|M_R|``. Present
    so the tests can assert what the bug would have produced on the very same
    data.
    """
    disagreements = sum(
        1
        for index in range(len(record))
        if record.eigenvalues[index] != key.eigenvalues[index]
    )
    return disagreements / len(record)


def _werner(p: float) -> DensityMatrix:
    """Return the Werner state ``(1 - p) |Phi+><Phi+| + p I/4``.

    Teleporting a pure payload over it is a depolarising channel of strength
    ``p``, so a matched position disagrees with probability exactly ``p / 2``.
    """
    phi = DensityMatrix(bell_state(BellState.PHI_PLUS)).data
    return DensityMatrix((1.0 - p) * phi + p * np.eye(4) / 4.0)


def _tolerance(probability: float, count: int, sigmas: float = SIGMAS) -> float:
    """Return ``sigmas`` times the binomial standard error of a proportion."""
    assert count > 0, "cannot form a standard error from an empty sample"
    return sigmas * math.sqrt(probability * (1.0 - probability) / count)


# ==========================================================================
# Phase B -- signing
# ==========================================================================


def test_the_signature_is_the_private_key_itself() -> None:
    """No hash, no trapdoor: signing declares the key that was distributed.

    The security was bought in Phase A, so the declaration carries the key
    object itself rather than a derived value. Identity is asserted because it
    is the point: there is nothing in between.
    """
    params = _params(8)
    key = _key(params)
    signature = sign(0, key, params)
    assert signature.declared_key is key
    assert signature.bases == key.bases
    assert signature.eigenvalues == key.eigenvalues
    assert len(signature) == len(key) == params.key_length


def test_sign_selects_the_key_for_the_bit_from_the_committed_pair() -> None:
    """``keys[b]`` is the key for bit ``b``; sign() does the indexing."""
    params = _params(12)
    keys = generate_key_pair(params, rng=np.random.default_rng(SEED))
    assert sign(0, keys, params).declared_key is keys[0]
    assert sign(1, keys, params).declared_key is keys[1]


def test_signing_a_bit_with_the_other_bits_key_is_refused() -> None:
    """The two distribution runs are independent; crossing them measures noise."""
    params = _params(8)
    key_for_zero = _key(params, message_bit=0)
    with pytest.raises(ValueError, match="cannot sign message bit 1"):
        sign(1, key_for_zero, params)


def test_signature_refuses_a_key_tagged_with_the_other_bit() -> None:
    """The invariant lives on the type, not only in the factory function."""
    params = _params(8)
    key_for_zero = _key(params, message_bit=0)
    with pytest.raises(ValueError, match="cannot sign message bit 1"):
        Signature(message_bit=1, declared_key=key_for_zero)


def test_sign_refuses_a_boolean_message_bit() -> None:
    """``True`` reads as ``1`` but usually means "yes"; refuse it explicitly."""
    params = _params(4)
    keys = generate_key_pair(params, rng=np.random.default_rng(SEED))
    with pytest.raises(ValueError, match="got the boolean"):
        sign(True, keys, params)  # type: ignore[arg-type]


def test_sign_refuses_a_key_pair_of_the_wrong_length() -> None:
    """A run commits to exactly two keys, before Alice knows which she signs."""
    params = _params(4)
    key = _key(params)
    with pytest.raises(ValueError, match="exactly the two keys"):
        sign(0, (key,), params)


def test_sign_refuses_a_misordered_key_pair() -> None:
    """``(k_1, k_0)`` would silently sign the wrong bit."""
    params = _params(4)
    keys = generate_key_pair(params, rng=np.random.default_rng(SEED))
    with pytest.raises(ValueError, match=r"ordered \(key_for_bit_0"):
        sign(0, (keys[1], keys[0]), params)


def test_sign_refuses_a_non_key() -> None:
    """The message points at the right constructor."""
    with pytest.raises(TypeError, match="must be a PrivateKey"):
        sign(0, "not a key")  # type: ignore[arg-type]


def test_sign_refuses_a_key_from_another_parameter_set() -> None:
    """A length mismatch means the key was drawn for a different run."""
    key = _key(_params(8))
    with pytest.raises(ValueError, match="params.key_length"):
        sign(0, key, _params(16))


def test_sign_without_params_still_works() -> None:
    """``params`` is an optional cross-check, not a requirement of Phase B."""
    params = _params(6)
    key = _key(params)
    assert sign(0, key).declared_key is key


def test_signature_is_frozen() -> None:
    """A declaration that could be edited after the fact is not a declaration."""
    params = _params(4)
    signature = sign(0, _key(params), params)
    with pytest.raises(dataclasses.FrozenInstanceError):
        signature.message_bit = 1  # type: ignore[misc]


def test_signature_survives_a_json_round_trip() -> None:
    """Phase B is entirely classical, so it serialises with no encoder."""
    params = _params(10)
    signature = sign(1, _key(params, message_bit=1), params)
    restored = Signature.from_dict(json.loads(json.dumps(signature.to_dict())))
    assert restored == signature


def test_signature_carries_no_free_text_field_the_rule_does_not_cover() -> None:
    """A label the verification rule does not cover would be a real hole.

    The original form of this test asserted that ``Signature`` had exactly two
    fields, which was the right rule stated as the wrong invariant: what makes a
    human-readable label dangerous is not its existence but that nothing binds
    it, so an adversary could rewrite it and every verifier would still accept,
    having checked only the bit.

    ``context`` is a free-text label and it is admissible for exactly one
    reason: it is hashed into ``session_id``, the verifier recomputes that from
    the declaration in front of him and compares it against the identifier his
    own log was stamped with at distribution time, and a rewritten context
    therefore matches no record. So the invariant this test now pins is the
    real one -- every field is either scored or covered -- and it still stops a
    well-meaning dashboard patch from adding an uncovered one.
    """
    fields = {field.name for field in dataclasses.fields(Signature)}
    assert fields == {
        "message_bit",
        "declared_key",
        "session_opening",
        "context",
    }

    # Rewriting the label changes the round the declaration names, so a verifier
    # holding a stamped log refuses it rather than accepting the rewrite.
    params = _params(10)
    key = _key(params, message_bit=1)
    honest = sign(1, key, params, session_opening="a1", context="pay 10")
    rewritten = sign(1, key, params, session_opening="a1", context="pay 10000")
    assert honest.session_id != rewritten.session_id

    # And there is no place to write an identifier of one's choosing: session_id
    # is derived, not stored, so it cannot be set to whatever the record says.
    assert "session_id" not in fields
    with pytest.raises(dataclasses.FrozenInstanceError):
        honest.session_id = rewritten.session_id  # type: ignore[misc]


# ==========================================================================
# THE CORRECTNESS POINT: only matched positions are scored
# ==========================================================================


def test_unmatched_positions_are_discarded_even_when_all_of_them_disagree() -> None:
    """The single most important test in the file.

    The record is built so that *every* unmatched position contradicts the
    declared eigenvalue, and every matched position agrees with it. An
    unmatched position is a measurement of a conjugate observable: the outcome
    is a fair coin regardless of whether the signature is honest, and it carries
    exactly zero bits about the key. So the honest rate here is ``0.0`` and the
    signature is accepted.

    An implementation that counted the unmatched positions would report
    ``(L - |M_R|) / L = 2/3`` and reject. The assertion on ``_buggy_rate`` below
    states that number explicitly, so this test fails loudly and diagnostically
    under the bug rather than merely failing.
    """
    params = _params(96)
    key = _key(params)
    record = _crafted_record(key, params, unmatched_disagree=True)
    signature = sign(0, key, params)

    result = verify(signature, record, params)

    assert result.mismatches == 0
    assert result.rate == 0.0
    assert result.accepted
    assert result.matched_count == 32
    assert result.unmatched_count == 64

    # What the classic bug would have produced from the very same log.
    assert _buggy_rate(key, record) == pytest.approx(2.0 / 3.0)
    assert _buggy_rate(key, record) > DEFAULT_S_V > DEFAULT_S_A


def test_unmatched_positions_are_discarded_at_both_verifiers() -> None:
    """The rule is a property of the counting, not of whose log it is."""
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    for party in VERIFIERS:
        record = _crafted_record(key, params, party=party)
        result = verify(signature, record, params)
        assert result.party is party
        assert result.rate == 0.0
        assert result.accepted


def test_matched_positions_are_exactly_the_positions_of_basis_agreement() -> None:
    """``M_R = { i : chosen_basis_i == declared_basis_i }``, and nothing else."""
    params = _params(60)
    key = _key(params)
    record = _distribute(key, params)
    signature = sign(0, key, params)

    expected = tuple(
        index
        for index in range(len(key))
        if record.bases[index] == key.bases[index]
    )
    assert matched_positions(signature, record) == expected
    assert verify(signature, record, params).matched_count == len(expected)


def test_mismatch_positions_are_always_a_subset_of_matched_positions() -> None:
    """An unmatched position can never be a mismatch: it is not evidence."""
    params = _params(96)
    key = _key(params)
    corrupted = (0, 9, 18)
    record = _crafted_record(key, params, corrupted=corrupted)
    signature = sign(0, key, params)

    matched = set(matched_positions(signature, record))
    mismatched = mismatch_positions(signature, record)
    assert set(mismatched) <= matched
    assert mismatched == corrupted


def test_the_reported_counts_reconstruct_the_reported_rate() -> None:
    """``rate == mismatches / matched_count`` on a run with real mismatches."""
    params = _params(96)
    key = _key(params)
    record = _crafted_record(key, params, corrupted=(0, 3))
    result = verify(sign(0, key, params), record, params)

    assert result.matched_count == 32
    assert result.mismatches == 2
    assert result.rate == 2 / 32
    assert result.agreements == 30


# ==========================================================================
# The empty matched set
# ==========================================================================


def test_empty_matched_set_raises_rather_than_deciding() -> None:
    """``0/0`` is a plumbing failure, not a signature failure, so it is loud.

    Accepting would take any declaration whatsoever on zero evidence; rejecting
    would be counted as a forgery detection in a Phase 5 table when no evidence
    of forgery exists. Neither is honest, so neither is returned.
    """
    params = _params(8, bases=(PauliBasis.X, PauliBasis.Z))
    key = PrivateKey(
        0, tuple(KeyElement(PauliBasis.X, 1) for _ in range(params.key_length))
    )
    record = RecipientRecord.from_measurements(
        Party.BOB, 0, [PauliBasis.Z] * params.key_length, [1] * params.key_length
    )
    signature = sign(0, key, params)

    assert matched_positions(signature, record) == ()
    with pytest.raises(ValueError, match="matched set is empty"):
        verify(signature, record, params)


def test_empty_matched_set_message_says_it_is_not_a_signature_failure() -> None:
    """The message has to prevent the reader from logging it as a rejection."""
    params = _params(6, bases=(PauliBasis.X, PauliBasis.Y))
    key = PrivateKey(
        0, tuple(KeyElement(PauliBasis.Y, -1) for _ in range(params.key_length))
    )
    record = RecipientRecord.from_measurements(
        Party.CHARLIE,
        0,
        [PauliBasis.X] * params.key_length,
        [1] * params.key_length,
    )
    with pytest.raises(ValueError) as excinfo:
        verify(sign(0, key, params), record, params)
    message = str(excinfo.value)
    assert "not a signature failure" in message
    assert "zero evidence" in message


def test_a_result_with_no_matched_positions_cannot_be_constructed() -> None:
    """The type refuses the state too, so no other path can smuggle it in."""
    with pytest.raises(ValueError, match="matched_count must be at least 1"):
        VerificationResult("Bob", True, 0, 0, 0.0, DEFAULT_S_A, 12, 0)


# ==========================================================================
# The two thresholds, and the gap between them
# ==========================================================================


def test_each_verifier_is_scored_against_its_own_threshold() -> None:
    """Bob gets ``s_a``, Charlie gets ``s_v``, read from the record's party."""
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    thresholds = {
        party: verify(
            signature, _crafted_record(key, params, party=party), params
        ).threshold
        for party in VERIFIERS
    }
    assert thresholds[Party.BOB] == params.s_a
    assert thresholds[Party.CHARLIE] == params.s_v
    assert thresholds[Party.BOB] < thresholds[Party.CHARLIE]


def test_a_rate_inside_the_gap_splits_the_two_verifiers() -> None:
    """The gap, demonstrated: 1 mismatch in 32 is 0.03125, between s_a and s_v.

    Bob's tighter cut rejects it and Charlie's looser cut accepts it. That
    asymmetry is exactly what ``s_a < s_v`` buys, and it is what makes a
    signature Bob accepts safe to forward. The rate is written as a fraction of
    the *matched* set (32 of the 96 positions), not of the key.
    """
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    corrupted = (0,)

    bob = verify(
        signature,
        _crafted_record(key, params, party=Party.BOB, corrupted=corrupted),
        params,
    )
    charlie = verify(
        signature,
        _crafted_record(key, params, party=Party.CHARLIE, corrupted=corrupted),
        params,
    )

    assert bob.rate == charlie.rate == 0.03125
    assert DEFAULT_S_A < 0.03125 < DEFAULT_S_V
    assert not bob.accepted
    assert charlie.accepted


def test_whatever_bob_accepts_charlie_accepts_too() -> None:
    """Transferability, as a property of the decision rule over every rate.

    ``s_a < s_v`` means Bob's acceptance region is contained in Charlie's, so on
    identical evidence there is no rate at which Bob accepts and Charlie does
    not. This is the deterministic half of the transferability claim; the
    probabilistic half -- that the two rates are close because they are i.i.d.
    -- belongs to :mod:`sih141.protocol.analysis`.
    """
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    matched = tuple(range(0, len(key), 3))

    for mismatch_count in range(len(matched) + 1):
        corrupted = matched[:mismatch_count]
        verdicts = {
            party: verify(
                signature,
                _crafted_record(
                    key, params, party=party, corrupted=corrupted
                ),
                params,
            )
            for party in VERIFIERS
        }
        bob, charlie = verdicts[Party.BOB], verdicts[Party.CHARLIE]
        assert bob.rate == charlie.rate
        assert not bob.accepted or charlie.accepted


def test_acceptance_is_inclusive_at_the_threshold() -> None:
    """The rule is ``r <= s``, so landing exactly on the cut is accepted.

    One mismatch in 64 matched positions is exactly ``s_a = 1/64``. One more is
    over it. The thresholds are noise budgets measured from an exact zero, so
    the boundary has to be pinned rather than left to a comparison operator's
    mood.
    """
    params = _params(192)
    key = _key(params)
    signature = sign(0, key, params)

    on_the_cut = verify(
        signature, _crafted_record(key, params, corrupted=(0,)), params
    )
    over_the_cut = verify(
        signature, _crafted_record(key, params, corrupted=(0, 3)), params
    )

    assert on_the_cut.rate == DEFAULT_S_A == on_the_cut.threshold
    assert on_the_cut.accepted
    assert on_the_cut.margin == 0.0
    assert over_the_cut.rate > over_the_cut.threshold
    assert not over_the_cut.accepted
    assert over_the_cut.margin < 0.0


def test_the_verdict_always_agrees_with_the_reported_numbers() -> None:
    """A dashboard must never show a rate under the cut next to a rejection."""
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    matched = tuple(range(0, len(key), 3))
    for mismatch_count in (0, 1, 2, 8, len(matched)):
        for party in VERIFIERS:
            result = verify(
                signature,
                _crafted_record(
                    key,
                    params,
                    party=party,
                    corrupted=matched[:mismatch_count],
                ),
                params,
            )
            assert result.accepted == (result.rate <= result.threshold)


def test_a_threshold_cannot_be_passed_in_at_the_call_site() -> None:
    """Which cut applies is a property of whose log it is, never a free knob."""
    params = _params(24)
    key = _key(params)
    record = _distribute(key, params)
    with pytest.raises(TypeError):
        verify(  # type: ignore[call-arg]
            sign(0, key, params), record, params, threshold=0.4
        )


# ==========================================================================
# Verification cannot touch its evidence
# ==========================================================================


def test_verify_does_not_mutate_the_record_it_is_given() -> None:
    """A verifier that could edit its own evidence would not be one.

    The record is frozen and holds only tuples, so the guarantee is structural;
    it is asserted anyway because it is a guarantee a future refactor could lose
    without any other test noticing.
    """
    params = _params(96)
    key = _key(params)
    record = _crafted_record(key, params, corrupted=(0, 3, 6))
    before = copy.deepcopy(record)
    entries_before = record.entries

    verify(sign(0, key, params), record, params)

    assert record == before
    assert record.entries is entries_before
    assert record.bases == before.bases
    assert record.eigenvalues == before.eigenvalues
    assert record.party is before.party
    assert record.message_bit == before.message_bit


def test_verify_does_not_mutate_the_signature_it_is_given() -> None:
    """The declaration is evidence too, and Phase 3 replays it."""
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    before = copy.deepcopy(signature)

    verify(signature, _crafted_record(key, params), params)

    assert signature == before
    assert signature.declared_key is key
    assert key.elements == before.declared_key.elements


def test_the_record_is_immutable_from_the_outside() -> None:
    """Neither the log nor an entry can be reassigned after construction."""
    params = _params(12)
    record = _distribute(_key(params), params)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.entries = ()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        record[0].eigenvalue = -record[0].eigenvalue  # type: ignore[misc]


def test_verify_is_a_pure_function_of_its_arguments() -> None:
    """No randomness (D3), no state: the same inputs give the same decision."""
    params = _params(96)
    key = _key(params)
    signature = sign(0, key, params)
    record = _crafted_record(key, params, corrupted=(0, 3))
    assert verify(signature, record, params) == verify(
        signature, record, params
    )


# ==========================================================================
# VerificationResult -- the Phase 6 dashboard's row
# ==========================================================================


def test_result_carries_everything_the_dashboard_needs() -> None:
    """The six documented fields exist, plus the two that make them readable."""
    params = _params(96)
    key = _key(params)
    result = verify(
        sign(0, key, params), _crafted_record(key, params, corrupted=(0,)), params
    )
    names = {field.name for field in dataclasses.fields(result)}
    assert {
        "accepted",
        "matched_count",
        "mismatches",
        "rate",
        "threshold",
        "party",
    } <= names
    assert result.unmatched_count == result.key_length - result.matched_count
    assert result.agreements == result.matched_count - result.mismatches
    assert result.margin == result.threshold - result.rate
    assert result.message_bit == 0


def test_result_survives_a_json_round_trip() -> None:
    """Purely classical, purely scalar: no bespoke encoder anywhere."""
    params = _params(96)
    key = _key(params)
    result = verify(
        sign(0, key, params),
        _crafted_record(key, params, party=Party.CHARLIE, corrupted=(0, 3)),
        params,
    )
    blob = json.dumps(result.to_dict())
    assert VerificationResult.from_dict(json.loads(blob)) == result
    assert json.loads(blob)["party"] == "Charlie"


def test_result_is_frozen() -> None:
    """A verdict that could be edited after the fact proves nothing."""
    params = _params(96)
    key = _key(params)
    result = verify(sign(0, key, params), _crafted_record(key, params), params)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.accepted = False  # type: ignore[misc]


def test_result_summary_reads_as_a_sentence() -> None:
    """The one-liner the CLI and the dashboard print."""
    params = _params(96)
    key = _key(params)
    result = verify(
        sign(0, key, params), _crafted_record(key, params, corrupted=(0, 3)), params
    )
    summary = result.summary()
    assert summary.startswith("Bob REJECTED bit 0")
    assert "2/32" in summary
    assert "64 discarded" in summary
    # s_a = 1/32 = 0.03125: a threshold must never be shown rounded down.
    assert f"{DEFAULT_S_A:.5f}" in summary
    assert str(DEFAULT_S_A).startswith(f"{DEFAULT_S_A:.5f}")


def test_result_refuses_a_verdict_that_contradicts_its_numbers() -> None:
    """The invariant is enforced by the type, not merely produced by verify()."""
    with pytest.raises(ValueError, match="contradicts rate"):
        VerificationResult("Bob", False, 32, 0, 0.0, DEFAULT_S_A, 96, 0)


def test_result_refuses_a_rate_that_contradicts_its_counts() -> None:
    """Displayed number and displayed counts have to be one measurement."""
    with pytest.raises(ValueError, match="rate must be mismatches"):
        VerificationResult("Bob", True, 32, 1, 0.0, DEFAULT_S_A, 96, 0)


def test_result_refuses_more_mismatches_than_matched_positions() -> None:
    """That state is only reachable by counting the unmatched positions."""
    with pytest.raises(ValueError, match="cannot exceed matched_count"):
        VerificationResult("Bob", False, 32, 64, 1.0, DEFAULT_S_A, 96, 0)


def test_result_refuses_alice() -> None:
    """She signs; she holds no record and has no threshold."""
    with pytest.raises(ValueError, match="Alice reaches no verdict"):
        VerificationResult("Alice", True, 32, 0, 0.0, DEFAULT_S_A, 96, 0)


def test_result_retains_no_quantum_state() -> None:
    """A verdict is scalars and an enum member -- nothing survives from Phase A."""
    params = _params(96)
    key = _key(params)
    result = verify(sign(0, key, params), _crafted_record(key, params), params)
    for field in dataclasses.fields(result):
        value = getattr(result, field.name)
        assert isinstance(value, (bool, int, float, str))


# ==========================================================================
# Cross-run pairings are refused
# ==========================================================================


def test_a_record_from_the_other_message_bit_is_refused() -> None:
    """The two runs use independent keys; crossing them measures pure chance."""
    params = _params(24)
    keys = generate_key_pair(params, rng=np.random.default_rng(SEED))
    record_for_one = _distribute(keys[1], params)
    with pytest.raises(ValueError, match="declares message bit 0"):
        verify(sign(0, keys, params), record_for_one, params)


def test_a_record_of_a_different_length_is_refused() -> None:
    """Verification is positional, so a length mismatch shifts every comparison."""
    short = _params(8)
    long = _params(16)
    key_short = _key(short)
    record_long = _distribute(_key(long), long)
    with pytest.raises(ValueError, match="key positions but"):
        verify(sign(0, key_short, short), record_long, short)


def test_a_record_from_another_parameter_set_is_refused() -> None:
    """``params`` fixes the key length and the alphabet the bounds assume."""
    params = _params(16)
    key = _key(params)
    record = _distribute(key, params)
    with pytest.raises(ValueError, match="params.key_length"):
        verify(sign(0, key, params), record, _params(32))


def test_a_non_signature_is_refused() -> None:
    """A bare private key is not a declaration of which bit it signs."""
    params = _params(8)
    key = _key(params)
    record = _distribute(key, params)
    with pytest.raises(TypeError, match="signature must be a Signature"):
        verify(key, record, params)  # type: ignore[arg-type]


def test_a_non_record_is_refused() -> None:
    """The message points at the function that produces one."""
    params = _params(8)
    key = _key(params)
    with pytest.raises(TypeError, match="record must be a RecipientRecord"):
        verify(sign(0, key, params), [(0, "X", 1)], params)  # type: ignore[arg-type]


def test_non_params_is_refused() -> None:
    """A dictionary of parameters is not a validated parameter set."""
    params = _params(8)
    key = _key(params)
    record = _distribute(key, params)
    with pytest.raises(TypeError, match="params must be a ProtocolParams"):
        verify(sign(0, key, params), record, {"key_length": 8})  # type: ignore[arg-type]


# ==========================================================================
# verify_all -- both verifiers, which is the point of Charlie
# ==========================================================================


def test_verify_all_consumes_what_distribute_public_key_produces() -> None:
    """The two functions are duals and must fit together with nothing in between."""
    params = _params(48)
    key = _key(params)
    records = symmetrise_records(
        distribute_public_key(key, params, rng=np.random.default_rng(SEED)),
        rng=np.random.default_rng(SEED + 1),
    )
    results = verify_all(sign(0, key, params), records, params)

    assert set(results) == set(VERIFIERS)
    for party, result in results.items():
        assert result.party is party
        assert result.accepted
        assert result.rate == 0.0
        assert result.threshold == params.threshold_for(party)


def test_verify_all_preserves_the_order_it_is_given() -> None:
    """Phase 5 tables and Phase 6 rows are written in the caller's order."""
    params = _params(24)
    key = _key(params)
    raw = distribute_public_key(
        key,
        params,
        parties=(Party.CHARLIE, Party.BOB),
        rng=np.random.default_rng(SEED),
    )
    exchanged = symmetrise_records(raw, rng=np.random.default_rng(SEED + 2))
    # symmetrise_records normalises the mapping to VERIFIERS order, so rebuild
    # the caller's order explicitly: it is the order under test.
    records = {party: exchanged[party] for party in raw}
    assert list(verify_all(sign(0, key, params), records, params)) == [
        Party.CHARLIE,
        Party.BOB,
    ]


def test_verify_all_refuses_a_record_filed_under_the_wrong_party() -> None:
    """The key selects the threshold, so a swap scores evidence at the wrong cut."""
    params = _params(24)
    key = _key(params)
    bob_record = _distribute(key, params, party=Party.BOB)
    with pytest.raises(ValueError, match="belongs to 'Bob'"):
        verify_all(sign(0, key, params), {Party.CHARLIE: bob_record}, params)


def test_verify_all_refuses_an_empty_mapping() -> None:
    """Verifying against nobody reaches no verdict."""
    params = _params(8)
    key = _key(params)
    with pytest.raises(ValueError, match="at least one recipient"):
        verify_all(sign(0, key, params), {}, params)


def test_verify_all_refuses_a_non_mapping() -> None:
    """A list of records loses the party keys the thresholds are chosen by."""
    params = _params(8)
    key = _key(params)
    record = _distribute(key, params)
    with pytest.raises(TypeError, match="must be a mapping"):
        verify_all(sign(0, key, params), [record], params)  # type: ignore[arg-type]


# ==========================================================================
# End to end, with a real teleportation in the loop
# ==========================================================================


def test_an_honest_noiseless_run_verifies_at_exactly_zero() -> None:
    """Distribute, sign, verify: rate ``0.0`` exactly, accepted at both cuts.

    Not "nearly zero": teleportation over a clean pair is exact, so on a matched
    position the recipient re-measured the very observable the state was an
    eigenstate of. Every threshold in the scheme is a noise budget measured from
    this zero.
    """
    params = _params(60)
    keys = generate_key_pair(params, rng=np.random.default_rng(SEED))
    for message_bit in (0, 1):
        records = symmetrise_records(
            distribute_public_key(
                keys[message_bit],
                params,
                rng=np.random.default_rng(SEED + _DIST_OFFSET + message_bit),
            ),
            rng=np.random.default_rng(SEED + message_bit),
        )
        results = verify_all(sign(message_bit, keys, params), records, params)
        for result in results.values():
            assert result.mismatches == 0
            assert result.rate == 0.0
            assert result.accepted
            assert result.message_bit == message_bit


def test_a_forged_signature_is_rejected_by_both_verifiers() -> None:
    """A key Alice never distributed disagrees on half the matched positions.

    The forger here is maximally lucky in one respect -- he guesses every basis
    correctly, so the matched set is unchanged -- and still cannot survive,
    because the eigenvalues he invents are independent of the ones the
    recipients measured.
    """
    params = _params(300)
    key = _key(params)
    records = symmetrise_records(
        distribute_public_key(key, params, rng=np.random.default_rng(SEED)),
        rng=np.random.default_rng(SEED + 3),
    )

    forged_key = PrivateKey(
        0,
        tuple(
            KeyElement(element.basis, -element.eigenvalue)
            for element in key.elements
        ),
    )
    results = verify_all(sign(0, forged_key, params), records, params)

    for result in results.values():
        assert result.rate == 1.0
        assert not result.accepted


def test_a_noisy_channel_raises_the_rate_to_half_the_werner_parameter() -> None:
    """The verifier measures the channel, quantitatively.

    A Werner-``p`` entanglement resource makes teleportation a depolarising
    channel of strength ``p``, so a matched position disagrees with probability
    ``p / 2``. At ``p = 1`` the resource carries no entanglement, the rate is a
    fair coin, and both verifiers reject -- which is what a channel attack looks
    like from Phase C's side.
    """
    params = _params(300)
    key = _key(params)
    signature = sign(0, key, params)

    clean = verify(signature, _distribute(key, params), params)
    attacked = verify(
        signature,
        _distribute(key, params, resource_factory=lambda: _werner(1.0)),
        params,
    )

    assert clean.rate == 0.0
    assert clean.accepted
    assert attacked.rate == pytest.approx(
        0.5, abs=_tolerance(0.5, attacked.matched_count)
    )
    assert not attacked.accepted


def test_a_mild_noise_level_still_verifies_at_both_thresholds() -> None:
    """``s_a`` is a noise budget: ``p = 2 * s_a`` is the documented headroom.

    A Werner resource of ``p = 0.01`` gives an expected rate of ``0.005``, well
    inside Bob's ``1/32``. The point is that the thresholds are not decorative
    -- an honest run over a slightly imperfect channel still transfers.
    """
    params = _params(300)
    key = _key(params)
    record = _distribute(key, params, resource_factory=lambda: _werner(0.01))
    result = verify(sign(0, key, params), record, params)

    assert 0.0 <= result.rate < DEFAULT_S_A
    assert result.accepted


def test_the_end_to_end_run_agrees_with_the_hand_counted_rate() -> None:
    """The module's arithmetic is checked against an independent count.

    Written out longhand from the record and the key, with no help from
    :mod:`sih141.protocol.verify`, so that a bug in the matched-set logic cannot
    hide behind the same bug in the test.
    """
    params = _params(240)
    key = _key(params)
    record = _distribute(key, params, resource_factory=lambda: _werner(0.5))
    result = verify(sign(0, key, params), record, params)

    matched = [
        index
        for index in range(len(key))
        if record.bases[index] == key.bases[index]
    ]
    mismatches = sum(
        1
        for index in matched
        if record.eigenvalues[index] != key.eigenvalues[index]
    )
    assert result.matched_count == len(matched)
    assert result.mismatches == mismatches
    assert result.rate == mismatches / len(matched)


# ==========================================================================
# The empty matched set: what can and cannot reach it
# ==========================================================================


def test_a_basis_avoiding_signer_cannot_empty_the_matched_set() -> None:
    """The seam-level denial of service, closed by the symmetrisation exchange.

    An adversary who knew, per position, the basis a verifier had logged could
    declare a different one everywhere and turn ``verify`` into an uncaught
    ``ValueError`` in the middle of ``run()``. He does not know it: the
    ``Signer`` seam is handed the *raw*, pre-exchange logs while each verifier
    is scored on his post-exchange record -- his own entry where he retained it
    and the other verifier's where the pair was swapped. Avoiding every basis in
    Bob's raw log therefore still matches with probability ``(1/2)(1/|B|) =
    1/6`` per position, so the run completes with a real evidence base.

    Asserted as a completed run plus a matched count near ``L/6``, which is the
    mechanism rather than just the outcome.
    """
    from sih141.protocol.session import QDSSession

    params = _params(300)

    def basis_avoiding(
        message_bit: int, keys: object, protocol_params: ProtocolParams, *, records
    ) -> Signature:
        record = records[message_bit][Party.BOB]
        return Signature(
            message_bit,
            PrivateKey(
                message_bit,
                tuple(
                    KeyElement(
                        next(
                            candidate
                            for candidate in protocol_params.bases
                            if candidate != basis
                        ),
                        1,
                    )
                    for basis in record.bases
                ),
            ),
        )

    transcript = QDSSession(
        params, signer=basis_avoiding, rng=np.random.default_rng(SEED)
    ).run(0)

    assert transcript.is_complete
    matched = transcript.bob.matched_count
    # Binomial(300, 1/6): mean 50, sd 6.5, so a five-sigma band is +/- 32.
    assert 18 <= matched <= 82
    # The declaration is nonsense, so it is rejected -- as a *verdict*, which is
    # the whole point of not letting it become an exception.
    assert not transcript.bob.accepted


def test_a_record_that_disagrees_everywhere_still_raises() -> None:
    """The branch is still reachable, and still refuses to invent a verdict.

    Constructed directly rather than through a seam, because that is now the
    only way to get here: a short key, or a record wired to the wrong key.
    """
    params = _params(9)
    key = _key(params)
    record = _crafted_record(key, params, matched=())

    with pytest.raises(ValueError) as excinfo:
        verify(sign(0, key, params), record, params)
    message = str(excinfo.value)
    assert "matched set is empty" in message
    assert "not a signature failure" in message
