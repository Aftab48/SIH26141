"""The matched-count abort rule, and the no-verdict outcome it produces.

Companion to ``tests/test_protocol_verify.py``, kept separate because it pins a
*new* protocol control rather than the counting rule those tests cover. Three
things are asserted here and nowhere else:

1. A declaration that starves the matched set can no longer crash a run.
   ``sih141.protocol.verify``'s module docstring used to claim the empty-matched
   -set branch was "not reachable through the shipped seams". It is: a
   ``Signer`` is handed *both* recipients' raw logs, and a declaration avoiding
   both drives ``|M_B| = |M_C| = 0`` with probability ``1``. Measured 20/20 at
   ``L = 600``, and every one of those runs used to leave an uncaught
   ``ValueError`` inside ``QDSSession.run``.
2. The floor is derived, not chosen. Its value is recomputed here from the
   Chernoff lower tail, and checked against an *exact* binomial tail so that the
   negligible-honest-abort claim is measured rather than asserted.
3. A refusal to score is neither an acceptance nor a rejection, at every layer:
   a different type, a different transcript field, a different summary line, and
   a JSON round trip that keeps them apart.

The security point of (2) is easy to miss and is pinned by
``test_a_starved_matched_set_that_would_have_been_accepted_now_aborts``: a
starved matched set does not merely weaken a verdict, it can *manufacture* one.
Twenty matched positions that all agree give ``r = 0.0``, which sits under both
cuts, so the pre-rule verifier would have accepted -- on evidence for which
every ``exp(-Theta(|M|))`` bound the scheme quotes is worthless.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from sih141.protocol.keys import KeyElement, PrivateKey, generate_private_key
from sih141.protocol.params import (
    DEFAULT_PARAMS,
    DEMO_PARAMS,
    Party,
    ProtocolParams,
)
from sih141.protocol.records import RecipientRecord
from sih141.protocol.session import QDSSession, SessionTranscript
from sih141.protocol.signature import Signature, sign
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    AbortReason,
    MatchedSetTooSmall,
    VerificationAbort,
    VerificationResult,
    matched_positions,
    minimum_matched_count,
    mismatch_positions,
    verify,
    verify_or_abort,
)

SEED = 20260830


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _both_log_avoiding(
    message_bit: int,
    keys: tuple[PrivateKey, PrivateKey],
    params: ProtocolParams,
    *,
    records: object,
) -> Signature:
    """Declare, per position, a basis neither recipient logged.

    The strongest form of the seam-reachable denial of service: with ``|B| = 3``
    and two logged bases per position there is always at least one basis left
    over, and after the symmetrisation exchange every entry either verifier
    holds is one of those two logs. So both matched sets are empty with
    probability ``1``, for any key length and any seed.

    Parameters
    ----------
    message_bit : int
        The bit being signed.
    keys : tuple of PrivateKey
        Alice's committed pair. Ignored: this signer declares nothing she drew.
    params : ProtocolParams
        Supplies the alphabet to pick the unused basis from.
    records : mapping
        The recipients' raw, pre-exchange logs, keyed by bit then party. Both of
        them, which is what makes this reachable at all.

    Returns
    -------
    Signature
        A declaration matching nothing either recipient measured.
    """
    del keys
    bob = records[message_bit][Party.BOB].bases  # type: ignore[index]
    charlie = records[message_bit][Party.CHARLIE].bases  # type: ignore[index]
    return Signature(
        message_bit,
        PrivateKey(
            message_bit,
            tuple(
                KeyElement(
                    next(
                        candidate
                        for candidate in params.bases
                        if candidate != logged_by_bob
                        and candidate != logged_by_charlie
                    ),
                    1,
                )
                for logged_by_bob, logged_by_charlie in zip(bob, charlie)
            ),
        ),
    )


def _record_matching_exactly(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    matched: int,
    party: Party = Party.BOB,
) -> RecipientRecord:
    """Build a log matching ``key`` at exactly ``matched`` positions, agreeing.

    Every matched position reproduces the key's eigenvalue, so the mismatch rate
    over the matched set is exactly ``0.0`` -- the most *favourable* evidence a
    signature can have, which is what makes it the right probe for a rule about
    the evidence base's size rather than its content.

    Parameters
    ----------
    key : PrivateKey
        The declared key.
    params : ProtocolParams
        Supplies the alphabet used to pick a deliberately different basis.
    matched : int
        How many leading positions should match.
    party : Party, optional
        Whose log this is. Defaults to Bob.

    Returns
    -------
    RecipientRecord
        A record of ``len(key)`` entries, symmetrised flag left at its default.
    """
    bases = []
    eigenvalues = []
    for index, element in enumerate(key.elements):
        if index < matched:
            bases.append(element.basis)
            eigenvalues.append(element.eigenvalue)
        else:
            bases.append(
                next(
                    candidate
                    for candidate in params.bases
                    if candidate != element.basis
                )
            )
            eigenvalues.append(element.eigenvalue)
    return RecipientRecord.from_measurements(
        party, key.message_bit, bases, eigenvalues
    )


def _exact_log_binomial_tail(
    trials: int, bases_count: int, below: int
) -> float:
    """Return ``ln P[Binomial(trials, 1/bases_count) < below]``, exactly summed.

    Done in integer arithmetic and logged only at the end. With ``p = 1/|B|``
    every term is the rational ``C(L, k) (|B| - 1)**(L - k) / |B|**L``, so the
    whole tail shares one denominator and the numerator is an exact integer sum.
    Floating point cannot be used directly here: the individual terms underflow
    to zero long before the tail does, which would silently turn this check into
    ``0.0 <= budget`` and assert nothing at all.

    Parameters
    ----------
    trials : int
        ``L``.
    bases_count : int
        ``|B|``.
    below : int
        The floor; the sum runs over ``0 <= k < below``.

    Returns
    -------
    float
        The natural logarithm of the lower-tail probability.
    """
    numerator = sum(
        math.comb(trials, k) * (bases_count - 1) ** (trials - k)
        for k in range(below)
    )
    return math.log(numerator) - trials * math.log(bases_count)


# ==========================================================================
# 1. The declaration that used to crash a run
# ==========================================================================


def test_a_declaration_avoiding_both_raw_logs_never_escapes_run() -> None:
    """20/20 with no exception, where 20/20 used to be an uncaught ValueError.

    The audit's exact case: ``L = 600``, a ``Signer`` reading both raw logs and
    declaring an unused basis at every position. Each run must complete, record
    a no-verdict outcome for *both* verifiers, and be reportable.
    """
    params = ProtocolParams(key_length=600)
    transcripts = []
    for seed in range(20):
        session = QDSSession(
            params,
            signer=_both_log_avoiding,
            rng=np.random.default_rng(seed),
        )
        # The assertion is the absence of an exception; pytest reports one as a
        # failure, so no try/except is needed and none should be added -- a
        # swallowed exception here would hide exactly the regression this pins.
        transcripts.append(session.run(0))

    assert len(transcripts) == 20
    for transcript in transcripts:
        assert transcript.aborted
        assert transcript.results == ()
        assert set(transcript.aborts_by_party) == {Party.BOB, Party.CHARLIE}
        for abort in transcript.aborts:
            assert abort.matched_count == 0
            assert abort.reason is AbortReason.EMPTY_MATCHED_SET
            assert abort.key_length == 600


def test_an_aborted_run_is_neither_accepted_nor_rejected() -> None:
    """No composite event is true of a run with no decision in it.

    A plumbing failure counted as a rejection would appear in a Phase 5 table as
    a forgery detection that never happened, so every derived property that
    could be misread has to be ``False``, and asking for the verdict has to
    raise rather than return one.
    """
    transcript = QDSSession(
        ProtocolParams(key_length=600),
        signer=_both_log_avoiding,
        rng=np.random.default_rng(SEED),
    ).run(1)

    assert transcript.aborted is True
    assert transcript.is_complete is False
    assert transcript.transferable is False
    assert transcript.repudiated is False
    assert transcript.bob is None
    assert transcript.charlie is None
    for party in (Party.BOB, Party.CHARLIE):
        with pytest.raises(ValueError, match="reached no verdict"):
            transcript.verdict_for(party)
        assert isinstance(
            transcript.aborts_by_party[party], VerificationAbort
        )
        assert not isinstance(
            transcript.aborts_by_party[party], VerificationResult
        )


def test_an_aborted_run_says_so_in_its_summary() -> None:
    """The last line a human reads must not be mistakable for a rejection."""
    transcript = QDSSession(
        ProtocolParams(key_length=600),
        signer=_both_log_avoiding,
        rng=np.random.default_rng(SEED + 1),
    ).run(0)
    lines = transcript.summary().splitlines()

    assert lines[-1].startswith("NO VERDICT:")
    assert "not a rejection" in lines[-1]
    assert not any(line.startswith("REJECTED") for line in lines)
    assert sum(line.startswith("Bob NO VERDICT") for line in lines) == 1
    assert sum(line.startswith("Charlie NO VERDICT") for line in lines) == 1


def test_an_aborted_run_round_trips_through_json() -> None:
    """Phase 4 to 6 read transcripts off the wire, aborts included."""
    transcript = QDSSession(
        ProtocolParams(key_length=600),
        signer=_both_log_avoiding,
        rng=np.random.default_rng(SEED + 2),
    ).run(0)

    blob = json.loads(transcript.to_json())
    assert [entry["party"] for entry in blob["aborts"]] == ["Bob", "Charlie"]
    assert blob["results"] == []
    assert all(entry["reason"] == "empty-matched-set" for entry in blob["aborts"])
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


def test_a_transcript_written_before_the_rule_still_restores() -> None:
    """``aborts`` is optional on the way in: stored runs predate the field."""
    honest = QDSSession(
        ProtocolParams(key_length=24), rng=np.random.default_rng(SEED)
    ).run(0)
    blob = honest.to_dict()
    assert blob["aborts"] == []
    del blob["aborts"]

    restored = SessionTranscript.from_dict(blob)
    assert restored == honest
    assert restored.aborts == ()
    assert restored.aborted is False


def test_the_session_records_the_refusal_before_it_propagates() -> None:
    """``verify`` still raises; the run is no longer lost when it does.

    Calling the phase directly is the low-level API and stays exceptional -- the
    caller asked for a verdict and there is none -- but the outcome is on the
    session by the time the exception is seen, which is what lets ``run`` and any
    Phase 3 harness report it.
    """
    params = ProtocolParams(key_length=600)
    session = QDSSession(
        params, signer=_both_log_avoiding, rng=np.random.default_rng(SEED + 3)
    )
    session.distribute()
    session.sign(0)

    with pytest.raises(MatchedSetTooSmall) as excinfo:
        session.verify(Party.BOB)

    assert isinstance(excinfo.value, ValueError)
    assert session.results == {}
    assert session.aborts[Party.BOB] is excinfo.value.abort
    assert "not a signature failure" in str(excinfo.value)

    # And Bob having no verdict does not block the transfer: Charlie's outcome
    # on the same declaration is evidence Phase 3 needs, not noise.
    with pytest.raises(MatchedSetTooSmall):
        session.transfer()
    assert set(session.aborts) == {Party.BOB, Party.CHARLIE}


def test_verify_or_abort_returns_the_refusal_instead_of_raising() -> None:
    """The value-returning form, for code that must record every run."""
    params = ProtocolParams(key_length=600)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    record = _record_matching_exactly(key, params, matched=0)

    outcome = verify_or_abort(sign(0, key, params), record, params)

    assert isinstance(outcome, VerificationAbort)
    assert outcome.matched_count == 0
    assert outcome.reason is AbortReason.EMPTY_MATCHED_SET
    assert not hasattr(outcome, "accepted")


def test_verify_or_abort_still_raises_on_a_wiring_error() -> None:
    """A mis-paired record is a bug in the caller, not an outcome.

    Converting it to a no-verdict would turn a mis-wired experiment into a table
    full of silent refusals, which is the failure this rule exists to prevent,
    inverted.
    """
    params = ProtocolParams(key_length=24)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    wrong_bit = _record_matching_exactly(key, params, matched=24)
    mismatched = RecipientRecord.from_measurements(
        Party.BOB, 1, wrong_bit.bases, wrong_bit.eigenvalues
    )

    with pytest.raises(ValueError, match="declares message bit 0"):
        verify_or_abort(sign(0, key, params), mismatched, params)


# ==========================================================================
# 2. The floor, and where it comes from
# ==========================================================================


def test_the_floor_matches_an_independent_chernoff_derivation() -> None:
    """Recomputed here from ``mu`` and the budget, not read off the module."""
    log_budget = -math.log(HONEST_ABORT_BUDGET)
    for length in (300, 600, 900, 4096, 115200):
        params = ProtocolParams(key_length=length)
        mean = params.expected_matched
        deviation = math.sqrt(2.0 * log_budget / mean)
        assert deviation < 1.0, "the tail bound must be usable at this L"
        assert minimum_matched_count(params) == math.ceil(
            (1.0 - deviation) * mean
        )


def test_the_floor_is_one_where_the_tail_bound_says_nothing() -> None:
    """Below ``L = 2 |B| ln(1/eps)`` there is no power to spend, and it shows.

    The rule then degenerates to the standing "a rate needs a denominator"
    requirement, which is the honest behaviour: a short demonstration key gets
    no statistical control because none is available, not because the control
    was switched off.
    """
    crossover = 2.0 * len(DEMO_PARAMS.bases) * -math.log(HONEST_ABORT_BUDGET)
    assert 266.0 < crossover < 267.0

    for length in (1, 9, 24, 192, 266):
        assert minimum_matched_count(ProtocolParams(key_length=length)) == 1
    assert minimum_matched_count(DEMO_PARAMS) == 1
    assert minimum_matched_count(ProtocolParams(key_length=300)) > 1


def test_the_honest_abort_probability_is_negligible_by_exact_tail() -> None:
    """The claim is measured against the real binomial, not its own bound.

    ``P[|M_R| < m_min]`` is summed exactly, so a floor set too aggressively --
    which would abort honest runs and manufacture no-verdicts -- fails here even
    though the Chernoff algebra it came from would still be self-consistent.
    """
    log_budget = math.log(HONEST_ABORT_BUDGET)
    for length in (300, 600, 900, 2400):
        params = ProtocolParams(key_length=length)
        floor = minimum_matched_count(params)
        log_tail = _exact_log_binomial_tail(
            params.key_length, len(params.bases), floor
        )
        assert log_tail <= log_budget, (
            f"L={length}: honest abort probability e**{log_tail:.1f} exceeds "
            f"the budget e**{log_budget:.1f}"
        )
    # The Chernoff step is a bound, not an identity, so the real tail is far
    # under budget -- which is the direction that matters: the rule errs
    # towards scoring, never towards manufacturing a no-verdict.
    at_600 = _exact_log_binomial_tail(
        600, 3, minimum_matched_count(ProtocolParams(key_length=600))
    )
    assert at_600 < log_budget - math.log(1e10)


def test_the_floor_sits_below_the_honest_mean_but_far_above_an_attack() -> None:
    """It has to be loose enough to be invisible and tight enough to bite.

    The repudiation attack pins the *joint* matched count at about 13 against an
    honest ``2L/|B| = 76800``. The floor is checked per verifier, so a scored run
    carries at least twice it.
    """
    floor = minimum_matched_count(DEFAULT_PARAMS)
    mean = DEFAULT_PARAMS.expected_matched

    assert floor == 36555
    assert mean == 38400.0
    assert 0.95 < floor / mean < 1.0
    # 13 joint matched positions cannot survive: the per-verifier floor alone is
    # three orders of magnitude above the whole of the attack's evidence base.
    assert 2 * floor > 1000 * 13


def test_the_floor_is_a_closed_form_in_the_parameters_only() -> None:
    """Deterministic, data-free and monotone in ``L`` (D3, D4).

    Nothing is learned, fitted or thresholded from run data: two calls on equal
    parameter sets agree, and the floor moves only when ``L`` or the alphabet
    does.
    """
    params = ProtocolParams(key_length=4096)
    assert minimum_matched_count(params) == minimum_matched_count(
        ProtocolParams(key_length=4096)
    )
    lengths = (300, 600, 1200, 2400, 4800)
    floors = [
        minimum_matched_count(ProtocolParams(key_length=length))
        for length in lengths
    ]
    assert floors == sorted(floors)
    assert floors[0] < floors[-1]
    # A smaller alphabet matches more often, so the same L supports a higher
    # floor -- the rule reads |B|, it does not assume three bases.
    two_basis = ProtocolParams(key_length=600, bases=("X", "Z"))
    assert minimum_matched_count(two_basis) > minimum_matched_count(
        ProtocolParams(key_length=600)
    )


def test_params_must_be_a_parameter_set() -> None:
    """The floor can only be read off a parameter set, never guessed."""
    with pytest.raises(TypeError, match="must be a ProtocolParams"):
        minimum_matched_count({"key_length": 600})  # type: ignore[arg-type]


# ==========================================================================
# 3. What the rule buys: a starved matched set can manufacture a verdict
# ==========================================================================


def test_a_starved_matched_set_that_would_have_been_accepted_now_aborts() -> None:
    """The security case for the rule, stated as the counterfactual.

    Twenty matched positions that all agree give ``r = 0/20 = 0.0``, under both
    cuts. Before the rule this was an *acceptance* -- reported with the same
    ``accepted=True`` as a run on ``L/|B| = 200`` positions, and carrying the
    same published confidence, while every ``exp(-Theta(|M|))`` bound behind
    that confidence is worthless at ``|M| = 20``.
    """
    params = ProtocolParams(key_length=600)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED + 4))
    signature = sign(0, key, params)
    record = _record_matching_exactly(key, params, matched=20)

    # The evidence really is flawless, and really is tiny.
    assert len(matched_positions(signature, record)) == 20
    assert mismatch_positions(signature, record) == ()
    assert 0.0 <= params.s_a  # a rate of 0.0 would clear even Bob's cut

    with pytest.raises(MatchedSetTooSmall) as excinfo:
        verify(signature, record, params)

    abort = excinfo.value.abort
    assert abort.reason is AbortReason.BELOW_FLOOR
    assert abort.matched_count == 20
    assert abort.minimum_matched == 67
    assert abort.shortfall == 47
    message = str(excinfo.value)
    assert "not a signature failure" in message
    assert "matched-count floor" in message


def test_a_matched_set_on_the_floor_is_scored_not_aborted() -> None:
    """The rule is ``|M| < m_min``, so the floor itself is evidence enough.

    Pinned because an off-by-one here silently discards a band of legitimate
    runs, and it would look exactly like a slightly unlucky channel.
    """
    params = ProtocolParams(key_length=600)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED + 5))
    signature = sign(0, key, params)
    floor = minimum_matched_count(params)

    result = verify(
        signature, _record_matching_exactly(key, params, matched=floor), params
    )
    assert isinstance(result, VerificationResult)
    assert result.matched_count == floor
    assert result.accepted

    with pytest.raises(MatchedSetTooSmall):
        verify(
            signature,
            _record_matching_exactly(key, params, matched=floor - 1),
            params,
        )


def test_an_honest_run_is_untouched_by_the_rule() -> None:
    """Above the crossover the control has to be invisible on honest evidence."""
    params = ProtocolParams(key_length=300)
    transcript = QDSSession(params, rng=np.random.default_rng(SEED + 6)).run(0)

    assert transcript.aborted is False
    assert transcript.aborts == ()
    assert transcript.is_complete
    assert transcript.transferable
    floor = minimum_matched_count(params)
    for verdict in transcript.results:
        assert verdict.matched_count >= floor
        # Not merely above the floor: nowhere near it, which is the point.
        assert verdict.matched_count > 4 * floor


# ==========================================================================
# 4. The recorded outcome as a type
# ==========================================================================


def test_an_abort_that_met_the_floor_cannot_be_constructed() -> None:
    """A run that met the floor reached a verdict; it is not a refusal."""
    with pytest.raises(ValueError, match="at or above"):
        VerificationAbort("Bob", AbortReason.BELOW_FLOOR, 67, 67, 200.0, 600, 0)


def test_an_aborts_reason_cannot_contradict_its_count() -> None:
    """The label and the numbers have to be the same observation."""
    with pytest.raises(ValueError, match="contradicts matched_count"):
        VerificationAbort("Bob", AbortReason.BELOW_FLOOR, 0, 67, 200.0, 600, 0)
    with pytest.raises(ValueError, match="contradicts matched_count"):
        VerificationAbort(
            "Charlie", AbortReason.EMPTY_MATCHED_SET, 13, 67, 200.0, 600, 1
        )


def test_alice_cannot_abort() -> None:
    """She signs, holds no record and reaches no verdict to refuse."""
    with pytest.raises(ValueError, match="Alice reaches no verdict"):
        VerificationAbort(
            "Alice", AbortReason.EMPTY_MATCHED_SET, 0, 67, 200.0, 600, 0
        )


def test_an_abort_round_trips_through_its_own_dict() -> None:
    """Serialisation is the Phase 4-6 hand-off, so it is pinned on the type."""
    abort = VerificationAbort(
        Party.CHARLIE, AbortReason.BELOW_FLOOR, 13, 67, 200.0, 600, 1
    )
    restored = VerificationAbort.from_dict(
        json.loads(json.dumps(abort.to_dict()))
    )
    assert restored == abort
    assert restored.summary() == abort.summary()


def test_a_party_cannot_hold_both_a_verdict_and_a_refusal() -> None:
    """Phase C leaves one outcome per verifier; a transcript enforces it."""
    params = ProtocolParams(key_length=600)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED + 7))
    signature = sign(0, key, params)
    floor = minimum_matched_count(params)
    verdict = verify(
        signature, _record_matching_exactly(key, params, matched=floor), params
    )
    abort = VerificationAbort(
        Party.BOB, AbortReason.BELOW_FLOOR, 13, floor, 200.0, 600, 0
    )

    with pytest.raises(ValueError, match="both results and aborts"):
        SessionTranscript(
            params=params,
            message_bit=0,
            signature=signature,
            records=(),
            results=(verdict,),
            aborts=(abort,),
        )


def test_a_stored_refusal_cannot_invent_its_own_floor() -> None:
    """The persistence boundary re-derives the floor rather than believing it.

    Same argument as ``_check_result_against`` makes for thresholds: a refusal
    is internally consistent whatever floor it quotes, so a transcript that
    accepted the field verbatim would let a scored run be re-labelled starved.
    """
    params = ProtocolParams(key_length=600)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED + 8))
    honest_abort = VerificationAbort(
        Party.BOB, AbortReason.BELOW_FLOOR, 13, 67, 200.0, 600, 0
    )
    blob = honest_abort.to_dict()
    blob["minimum_matched"] = 599

    with pytest.raises(ValueError, match="matched-count floor"):
        SessionTranscript(
            params=params,
            message_bit=0,
            signature=sign(0, key, params),
            records=(),
            results=(),
            aborts=(VerificationAbort.from_dict(blob),),
        )
