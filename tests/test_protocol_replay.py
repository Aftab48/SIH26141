"""The replay defence: one round, one verdict, and which round is this.

Replay was the one attack in the problem statement with no defence at all. Two
things were open, and both were measured before anything was built:

* a captured signature re-presented after its run was finished verified again at
  rate ``0.0`` and was **accepted**, 3 times out of 3 at each verifier;
* a signature paired with **another run's** records was refused by nothing. The
  transcript constructed without complaint and reported ``transferable=True``,
  and a fresh scoring of the mismatched pair failed only on the rate -- mean
  ``0.507`` over 40 seed pairs, which is the ``(1 - 1/|B|)/2`` chance noise of
  scoring against an unrelated key and says nothing whatever about *which run*.

Every "before" in this file is executed rather than quoted. The old behaviour is
exactly what the new code does when the state the defence reads is absent -- an
unstamped record, a declaration naming no round, no ledger -- so each pair of
tests below runs the attack twice against the same build: once with the binding
stripped, which reproduces the measured "before", and once with it in place.

What is pinned here
-------------------
1.  The two attacks, before and after, at both verifiers and through
    ``QDSSession``.
2.  What the session identifier is derived from, and the property that is easy
    to get wrong: it does **not** depend on the declared key, so a forgery is
    still rejected on its mismatch rate rather than refused as the wrong round.
    Folding the key in would have emptied Phase 3's forgery table into the
    no-verdict column.
3.  The ledger: per verifier and not global, spent only on a verdict, inert on
    a log that names no round, and priced -- including the one denial-of-service
    route that does exist and who can reach it.
4.  That an honest single verification is completely unaffected, over 40 seeded
    runs rather than one.
5.  Message freshness: two authorisations of one instruction under different
    nonces are two rounds, and each verifier decides each round once.
6.  That every refusal lands in the abort machinery, so no Phase 4 or Phase 5
    statistic can average a no-verdict into a rejection.

See Also
--------
sih141.protocol.verify : ``.. _replay:`` -- the rule and its reasoning.
sih141.protocol.signature : ``.. _session-binding:`` -- the derivation.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import numpy as np
import pytest

from sih141.protocol import (
    DEMO_PARAMS,
    VERIFIERS,
    AbortReason,
    ConsumedRecords,
    MatchedSetTooSmall,
    Party,
    PrivateKey,
    ProtocolParams,
    QDSSession,
    RecipientRecord,
    SessionTranscript,
    Signature,
    VerificationAbort,
    VerificationResult,
    fresh_context,
    fresh_opening,
    session_identifier,
    sign,
    verify,
    verify_or_abort,
)
from sih141.protocol.verify import (
    _OWN_COUNT_REASONS,
    _PAIR_REASONS,
    _ROUND_REASONS,
)

SEED = 20260141
"""Base seed. Every run in this module derives its generator from it."""

RUNS = 40
"""Independent seeded runs the "honest verification is unaffected" test uses."""

PRESENTATIONS = 3
"""How many times the audit re-presented the captured signature. It found 3/3
accepted at each verifier; the point of the defence is that this becomes 0/3."""


# ==========================================================================
# Helpers
# ==========================================================================


def _params(length: int = 24, **changes: Any) -> ProtocolParams:
    """Build a small valid parameter set."""
    return ProtocolParams(key_length=length, **changes)


def _session(
    params: ProtocolParams | None = None, seed: int = SEED, **kwargs: Any
) -> QDSSession:
    """Build a session on a freshly seeded generator."""
    return QDSSession(
        params if params is not None else _params(),
        rng=np.random.default_rng(seed),
        **kwargs,
    )


def _unbind_record(record: RecipientRecord) -> RecipientRecord:
    """Return ``record`` as it would have been before the binding existed."""
    return record.with_session_id(None)


def _unbind_signature(signature: Signature) -> Signature:
    """Return ``signature`` as it would have been before the binding existed."""
    return Signature(
        message_bit=signature.message_bit, declared_key=signature.declared_key
    )


def _flip_all(key: PrivateKey) -> PrivateKey:
    """Return ``key`` with every eigenvalue negated -- a maximally wrong key."""
    return PrivateKey(
        key.message_bit,
        tuple(
            dataclasses.replace(element, eigenvalue=-element.eigenvalue)
            for element in key
        ),
    )


# ==========================================================================
# 1. The two attacks, before and after
# ==========================================================================


def test_before_a_captured_signature_is_accepted_every_time_it_is_presented() -> None:
    """The measured "before", reproduced by stripping the binding.

    This is the audit's finding executed rather than quoted, at the parameter
    set it was measured on: with no round on either side and no ledger,
    verification is a pure function of frozen inputs, so it cannot tell the
    first presentation from the fourth. Every presentation is accepted at rate
    ``0.0``, because the declaration really is the key that was distributed --
    which is exactly what makes a replay hard to see.
    """
    session = _session(DEMO_PARAMS)
    transcript = session.run(0)
    captured = _unbind_signature(transcript.signature)

    accepted = [
        verify(
            captured,
            _unbind_record(transcript.records_for(0)[party]),
            session.params,
        )
        for _ in range(PRESENTATIONS)
        for party in VERIFIERS
    ]

    assert [result.accepted for result in accepted] == [True] * (
        PRESENTATIONS * len(VERIFIERS)
    )
    assert {result.rate for result in accepted} == {0.0}


def test_after_a_captured_signature_is_refused_every_time_it_is_re_presented() -> None:
    """3/3 accepted becomes 0/3, at both verifiers.

    The round is spent by the run itself -- ``run`` reaches one verdict per
    verifier -- so every later presentation of the very same declaration to the
    very same verifier is refused. Refused, not rejected: the verifier has
    learned nothing about the signature, and the outcome carries no ``accepted``
    field at all.
    """
    session = _session(DEMO_PARAMS)
    transcript = session.run(0)
    captured = transcript.signature

    outcomes = [
        verify_or_abort(
            captured,
            transcript.records_for(0)[party],
            session.params,
            ledger=session.ledger_for(party),
        )
        for _ in range(PRESENTATIONS)
        for party in VERIFIERS
    ]

    assert len(outcomes) == PRESENTATIONS * len(VERIFIERS)
    assert all(isinstance(outcome, VerificationAbort) for outcome in outcomes)
    assert {outcome.reason for outcome in outcomes} == {
        AbortReason.RECORD_ALREADY_VERIFIED
    }
    # Nothing here is an acceptance and nothing here is a rejection.
    assert not any(hasattr(outcome, "accepted") for outcome in outcomes)
    assert all(outcome.accepted_is_undefined for outcome in outcomes)


def test_the_session_reaches_one_verdict_and_then_refuses_to_reach_more() -> None:
    """The same 3/3 -> 0/3, driven through ``QDSSession`` rather than by hand."""
    session = _session()
    session.run(0)
    verdict = session.results[Party.BOB]

    reasons = []
    for _ in range(PRESENTATIONS):
        with pytest.raises(MatchedSetTooSmall) as excinfo:
            session.verify(Party.BOB)
        reasons.append(excinfo.value.abort.reason)

    assert reasons == [AbortReason.RECORD_ALREADY_VERIFIED] * PRESENTATIONS
    # The verdict that spent the round is untouched: a replay must not be able
    # to delete the decision it is trying to duplicate.
    assert session.results[Party.BOB] == verdict
    assert Party.BOB not in session.aborts


def test_before_one_run_signature_against_another_run_records_fails_only_by_luck() -> (
    None
):
    """The measured "before" for cross-round pairing.

    Nothing refuses the pair. The rate lands near ``(1 - 1/|B|)/2`` -- chance
    noise from scoring against an unrelated key -- and that is the *only* reason
    the signature is not accepted. Over 40 seed pairs the audit measured a mean
    of ``0.507``; here the point is the weaker and more important one, that the
    verdict is a verdict rather than a refusal.
    """
    params = _params()
    a = _session(params, seed=SEED).run(0)
    b = _session(params, seed=SEED + 1).run(0)

    rates = []
    for party in VERIFIERS:
        outcome = verify_or_abort(
            _unbind_signature(a.signature),
            _unbind_record(b.records_for(0)[party]),
            params,
        )
        assert isinstance(outcome, VerificationResult), (
            "before the binding, a cross-round pair reached a verdict: nothing "
            "in the arithmetic knows the two halves came from different runs"
        )
        assert not outcome.accepted
        rates.append(outcome.rate)

    # Well above both thresholds, and nowhere near a rule: this is noise.
    assert all(rate > params.s_v for rate in rates)


def test_after_one_run_signature_against_another_run_records_aborts() -> None:
    """The cross-round pair is refused by rule, at both verifiers.

    Not "rejected with high probability" -- refused. The declaration names round
    A and the log names round B, and no count taken across the two means
    anything, so none is taken.
    """
    params = _params()
    a = _session(params, seed=SEED).run(0)
    b = _session(params, seed=SEED + 1).run(0)

    for party in VERIFIERS:
        outcome = verify_or_abort(
            a.signature, b.records_for(0)[party], params
        )
        assert isinstance(outcome, VerificationAbort)
        assert outcome.reason is AbortReason.SESSION_MISMATCH
        assert outcome.party is party
        assert not outcome.is_pooled
        assert outcome.shortfall == 0


def test_a_transcript_assembled_from_two_rounds_claims_neither_property() -> None:
    """``transferable=True`` on a frankenstein transcript was the false claim.

    The transcript still *constructs* -- it is a record, and refusing to
    represent an incoherent run would lose the evidence that one happened -- but
    the two derived claims that are statements about a single transaction now
    read the pairing before answering.
    """
    params = _params()
    a = _session(params, seed=SEED).run(0)
    b = _session(params, seed=SEED + 1).run(0)

    frankenstein = SessionTranscript(
        params=params,
        message_bit=b.message_bit,
        signature=a.signature,
        records=b.records,
        results=b.results,
        aborts=b.aborts,
    )

    assert b.transferable and b.session_coherent
    assert not frankenstein.session_coherent
    assert not frankenstein.transferable
    assert not frankenstein.repudiated
    # The verdicts themselves are still readable: what is refused is the
    # composite claim, not the record of what each verifier decided.
    assert frankenstein.bob is not None and frankenstein.bob.accepted


def test_a_transcript_written_before_the_binding_still_reads_as_coherent() -> None:
    """Restoring an older run must not invent provenance it never had."""
    params = _params()
    transcript = _session(params).run(0)
    older = transcript.to_dict()
    for record in older["records"]:
        record.pop("session_id")
    older["signature"].pop("session_opening")
    older["signature"].pop("context")

    restored = SessionTranscript.from_dict(json.loads(json.dumps(older)))

    assert all(record.session_id is None for record in restored.records)
    assert restored.signature.session_id is None
    assert restored.session_coherent
    assert restored.transferable


# ==========================================================================
# 2. What the identifier is derived from, and what it deliberately omits
# ==========================================================================


def test_the_identifier_is_derived_and_has_nowhere_to_be_written() -> None:
    """Relabelling is a preimage problem because there is no field to set.

    A ``session_id`` *field* would have been the obvious design and it would
    have been forgeable by assignment: an adversary holding one round's
    declaration would write the other round's identifier into it and the
    comparison would pass. Deriving it from an opening the signer reveals means
    the only way to make a declaration name a round is to hold that round's
    opening.
    """
    fields = {field.name for field in dataclasses.fields(Signature)}
    assert "session_id" not in fields
    assert {"session_opening", "context"} <= fields

    key = PrivateKey.from_dict(
        {"message_bit": 0, "elements": [{"basis": "X", "eigenvalue": 1}]}
    )
    declaration = Signature(0, key, session_opening="round-a")
    with pytest.raises(dataclasses.FrozenInstanceError):
        declaration.session_id = "round-b"  # type: ignore[misc]
    # Nor is it stored on the way through JSON, where a field would have been
    # the easiest thing in the world to edit.
    assert "session_id" not in declaration.to_dict()


def test_the_identifier_does_not_depend_on_the_declared_key() -> None:
    """The property that keeps forgery detection alive, and it is not obvious.

    Hashing the declared key into the identifier is the tempting design. It is
    wrong: the verifier can only recompute from the key he was *declared*, so
    every forgery would produce a mismatching identifier and be reported as a
    refusal to score. The whole of Phase 3's forgery table would empty into the
    no-verdict column, and the scheme's headline detection would read as a
    plumbing error.

    So a forged declaration in the right round is scored, and rejected, on its
    mismatch rate -- which is what this asserts, end to end.
    """
    session = _session()
    session.distribute()
    honest = session.sign(0)
    record = session.records[0][Party.BOB]

    forged = Signature(
        0,
        _flip_all(session.keys[0]),
        session_opening=session.opening_for(0),
        context=None,
    )
    assert forged.session_id == honest.session_id

    outcome = verify_or_abort(forged, record, session.params)
    assert isinstance(outcome, VerificationResult), (
        "a forgery must reach a verdict, not a refusal: the identifier names "
        "the round and the mismatch rate judges the key"
    )
    assert not outcome.accepted
    assert outcome.rate == 1.0


def test_a_forging_signer_seam_still_produces_a_rejection_not_a_refusal() -> None:
    """The same property through the seam, where an attack actually attaches.

    The session binds every declaration to its own round, including one a
    ``Signer`` seam invented, so a seam cannot convert a detectable forgery into
    an abort by declining to name the round.
    """

    def forging_signer(
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: Any,
    ) -> Signature:
        return sign(message_bit, _flip_all(keys[message_bit]), params)

    session = _session(signer=forging_signer)
    transcript = session.run(0)

    assert not transcript.aborted
    assert transcript.is_complete
    assert transcript.bob is not None and not transcript.bob.accepted
    assert transcript.charlie is not None and not transcript.charlie.accepted


def test_distinct_rounds_get_distinct_identifiers() -> None:
    """Freshness of the opening, over many seeds and both message bits."""
    seen: set[str] = set()
    for offset in range(RUNS):
        session = _session(seed=SEED + offset)
        session.distribute()
        seen.update(session.session_ids.values())
    assert len(seen) == 2 * RUNS


def test_the_openings_are_the_commitment_an_auditor_opens() -> None:
    """A fabricated identifier cannot be opened, and this is the check.

    The identifier the signer announces is a commitment to an opening she keeps.
    Handing over the opening reproduces it; nothing else does, short of a
    preimage search. That is what a dispute turns on, and it covers the *unsigned*
    round too -- the one whose key never becomes public.
    """
    session = _session(context="pay 10#nonce-1")
    session.distribute()

    for bit, announced in session.session_ids.items():
        opened = session_identifier(
            bit,
            session.params.key_length,
            opening=session.opening_for(bit),
            context="pay 10#nonce-1",
        )
        assert opened == announced

    # A different opening does not open it, and neither does a different
    # context: both are covered.
    assert (
        session_identifier(
            0,
            session.params.key_length,
            opening=session.opening_for(1),
            context="pay 10#nonce-1",
        )
        != session.session_ids[0]
    )
    assert (
        session_identifier(
            0,
            session.params.key_length,
            opening=session.opening_for(0),
            context="pay 10000#nonce-1",
        )
        != session.session_ids[0]
    )


def test_the_record_is_the_anchor_not_the_signature() -> None:
    """A declaration naming *no* round is refused by a verifier holding one.

    The comparison is driven from the side an adversary cannot reach. Stripping
    the opening from the declaration is the obvious way to try to switch the
    check off -- it is the omission route that had to be closed for the
    declaration digest -- and it does not work here, because the verifier's own
    record still names the round and still demands to be told which one this is.
    """
    session = _session()
    session.distribute()
    declaration = session.sign(0)
    record = session.records[0][Party.BOB]

    stripped = _unbind_signature(declaration)
    assert stripped.session_id is None

    outcome = verify_or_abort(stripped, record, session.params)
    assert isinstance(outcome, VerificationAbort)
    assert outcome.reason is AbortReason.SESSION_MISMATCH


def test_an_unstamped_record_scores_exactly_as_it_did_before() -> None:
    """The other half of the asymmetry, and what keeps older evidence readable.

    A verifier whose log names no round has nothing to compare, so no check is
    applied and the verdict is bit-for-bit the one the same pair reached before
    the binding existed. Blinding himself costs him his own protection and
    nobody else's.
    """
    session = _session()
    session.distribute()
    declaration = session.sign(0)
    record = session.records[0][Party.BOB]

    bound = verify(declaration, record, session.params)
    unstamped = verify(declaration, _unbind_record(record), session.params)
    both_unbound = verify(
        _unbind_signature(declaration),
        _unbind_record(record),
        session.params,
    )

    assert bound == unstamped == both_unbound


def test_the_symmetriser_seam_cannot_strip_the_recipients_binding() -> None:
    """Phase A' is the recipients' own step, so it cannot unname their round.

    A symmetriser that rebuilt records without carrying the identifier through
    would leave both verifiers scoring unbound evidence, which is the replay
    route reopened by the party the replay defence protects. The session
    re-stamps after the exchange for exactly this reason.
    """

    def forgetful_symmetriser(
        records: Any, *, rng: np.random.Generator | None = None
    ) -> dict[Party, RecipientRecord]:
        return {
            party: record.with_session_id(None)
            for party, record in records.items()
        }

    session = _session(symmetriser=forgetful_symmetriser)
    session.distribute()

    for bit in (0, 1):
        for party in VERIFIERS:
            assert (
                session.records[bit][party].session_id
                == session.session_ids[bit]
            )


# ==========================================================================
# 3. The ledger: per verifier, spent only on a verdict, and priced
# ==========================================================================


def test_a_ledger_refuses_the_other_verifiers_evidence() -> None:
    """Per-verifier state, enforced rather than documented.

    Bob's ledger physically cannot hold Charlie's rounds, so there is no object
    anywhere from which one verifier's history can reach the other's decision.
    """
    session = _session()
    session.distribute()
    bob_ledger = session.ledger_for(Party.BOB)

    with pytest.raises(ValueError) as excinfo:
        bob_ledger.spend(session.records[0][Party.CHARLIE])
    message = str(excinfo.value)
    assert "belongs to Bob" in message and "Charlie's record" in message

    with pytest.raises(ValueError):
        bob_ledger.is_spent(session.records[0][Party.CHARLIE])
    with pytest.raises(ValueError):
        ConsumedRecords(Party.ALICE)


def test_the_two_verifiers_ledgers_are_separate_objects() -> None:
    """Spending Bob's round leaves Charlie able to reach his own verdict."""
    session = _session()
    session.distribute()
    session.sign(0)

    assert session.verify(Party.BOB).accepted
    assert len(session.ledger_for(Party.BOB)) == 1
    assert len(session.ledger_for(Party.CHARLIE)) == 0
    assert session.transfer().accepted
    assert len(session.ledger_for(Party.CHARLIE)) == 1
    assert (
        session.ledger_for(Party.BOB) is not session.ledger_for(Party.CHARLIE)
    )


def test_a_refusal_spends_nothing() -> None:
    """Only a verdict closes a round, and that is what makes it unpoisonable.

    If a refusal spent the round, anything that could make a verifier abort --
    a starved matched set, a counterpart count of unrecorded provenance, a
    mismatched round -- would be a way of destroying an honest signature's one
    chance to be scored.
    """
    session = _session()
    session.distribute()
    declaration = session.sign(0)
    record = session.records[0][Party.BOB]
    ledger = session.ledger_for(Party.BOB)

    # Refusal 1: a declaration from another round.
    other = _session(seed=SEED + 1)
    other.distribute()
    other.sign(0)
    wrong_round = Signature(
        0, session.keys[0], session_opening=other.opening_for(0)
    )
    assert isinstance(
        verify_or_abort(wrong_round, record, session.params, ledger=ledger),
        VerificationAbort,
    )
    assert len(ledger) == 0

    # Refusal 2: an evidence floor.
    avoided = PrivateKey(
        0,
        tuple(
            dataclasses.replace(
                element,
                basis=next(
                    b
                    for b in session.params.bases
                    if b != record[index].basis
                ),
            )
            for index, element in enumerate(session.keys[0])
        ),
    )
    starved = Signature(
        0, avoided, session_opening=session.opening_for(0)
    )
    refusal = verify_or_abort(
        starved, record, session.params, ledger=ledger
    )
    assert isinstance(refusal, VerificationAbort)
    assert refusal.reason is AbortReason.EMPTY_MATCHED_SET
    assert len(ledger) == 0

    # And the honest declaration is still scoreable afterwards.
    assert verify(declaration, record, session.params, ledger=ledger).accepted
    assert len(ledger) == 1


def test_a_rejection_spends_the_round_and_this_is_the_denial_of_service_price() -> (
    None
):
    """The one denial-of-service route that exists, executed and priced.

    A *verdict* closes a round, and a rejection is a verdict. So a party who can
    put a declaration in front of a verifier before the honest one arrives can
    burn the round: the verifier rejects the bad declaration, spends, and the
    honest declaration is then refused.

    The price is that nobody can reach this who did not already hold a cheaper
    denial. Phase B runs over an **authenticated** channel, so the only party
    who can put a declaration in front of Bob is the signer -- and a signer who
    wants to deny service can simply not sign. The only party who can put one in
    front of Charlie is whoever holds the Bob-to-Charlie hop, which is Bob, and
    Bob withholding the forward is the same denial for less work.

    Spending only on acceptance would remove even this, at the cost of letting a
    verifier be asked the same rejected question without limit; "one round, one
    verdict" is the rule, and a rejection is a verdict.
    """
    session = _session()
    session.distribute()
    honest = session.sign(0)
    record = session.records[0][Party.BOB]
    ledger = session.ledger_for(Party.BOB)

    rushed = Signature(
        0, _flip_all(session.keys[0]), session_opening=session.opening_for(0)
    )
    rejection = verify(rushed, record, session.params, ledger=ledger)
    assert not rejection.accepted
    assert len(ledger) == 1

    denied = verify_or_abort(honest, record, session.params, ledger=ledger)
    assert isinstance(denied, VerificationAbort)
    assert denied.reason is AbortReason.RECORD_ALREADY_VERIFIED


def test_the_ledger_cannot_be_poisoned_from_outside() -> None:
    """There is no way in but a verdict this verifier reached himself.

    The ledger holds no public mutator that an adversary reaches: entries are
    added by ``verify`` on the way out of a decision, and every other path is a
    refusal that leaves it empty. ``spent_rounds`` hands out a frozen snapshot,
    so a caller cannot reach in and add a round the verifier never scored.
    """
    session = _session()
    session.distribute()
    session.sign(0)
    ledger = session.ledger_for(Party.BOB)

    snapshot = ledger.spent_rounds()
    assert isinstance(snapshot, frozenset)
    with pytest.raises(AttributeError):
        snapshot.add(("forged", 0))  # type: ignore[attr-defined]
    assert not hasattr(ledger, "__dict__"), (
        "the ledger uses __slots__, so an attacker cannot bolt a second set of "
        "spent rounds onto it and have verify() read that instead"
    )

    session.verify(Party.BOB)
    assert len(ledger.spent_rounds()) == 1
    assert len(snapshot) == 0


def test_ledger_growth_is_one_entry_per_round() -> None:
    """Exhaustion, priced: linear in rounds decided and prunable by round.

    Two hundred rounds of one verifier's history is two hundred
    ``(32-character identifier, message bit)`` pairs -- of order ``10**2`` bytes
    each, so ``10**7`` rounds is about a gigabyte. The key is the round, which
    is what makes a retention policy expressible at all.
    """
    ledger = ConsumedRecords(Party.BOB)
    entries = [
        RecipientRecord.from_measurements(
            "Bob", 0, ["X"], [1], session_id=f"round-{index:04d}"
        )
        for index in range(200)
    ]
    for record in entries:
        ledger.spend(record)
        ledger.spend(record)  # idempotent

    assert len(ledger) == 200
    assert all(len(key) == 2 for key in ledger.spent_rounds())
    assert all(ledger.is_spent(record) for record in entries)


def test_a_record_that_names_no_round_is_not_tracked() -> None:
    """Content is deliberately not the ledger key.

    Two structurally identical logs from two different runs are two rounds, so
    keying on content would confuse a coincidence with a replay -- and would
    refuse the second of every pair of identical hand-built records in the test
    suite. An unstamped log therefore spends nothing and is never spent.
    """
    ledger = ConsumedRecords(Party.BOB)
    unbound = RecipientRecord.from_measurements("Bob", 0, ["X", "Z"], [1, -1])
    twin = RecipientRecord.from_measurements("Bob", 0, ["X", "Z"], [1, -1])
    assert unbound == twin

    ledger.spend(unbound)
    assert len(ledger) == 0
    assert not ledger.is_spent(unbound)
    assert not ledger.is_spent(twin)


def test_the_same_round_of_the_other_message_bit_is_a_different_entry() -> None:
    """The key is ``(identifier, message bit)``, and both halves are needed."""
    ledger = ConsumedRecords(Party.CHARLIE)
    for bit in (0, 1):
        ledger.spend(
            RecipientRecord.from_measurements(
                "Charlie", bit, ["X"], [1], session_id="shared"
            )
        )
    assert len(ledger) == 2


def test_verify_rejects_a_ledger_of_the_wrong_type_or_the_wrong_party() -> None:
    """Wiring errors raise; they are bugs in the caller, not outcomes."""
    session = _session()
    session.distribute()
    declaration = session.sign(0)
    record = session.records[0][Party.BOB]

    with pytest.raises(TypeError) as type_error:
        verify(declaration, record, session.params, ledger=set())  # type: ignore[arg-type]
    assert "ConsumedRecords" in str(type_error.value)

    with pytest.raises(ValueError):
        verify(
            declaration,
            record,
            session.params,
            ledger=ConsumedRecords(Party.CHARLIE),
        )


def test_verify_all_takes_one_ledger_per_verifier() -> None:
    """A mapping, not a shared object: the two histories must stay apart."""
    from sih141.protocol.verify import verify_all

    session = _session()
    session.distribute()
    declaration = session.sign(0)
    ledgers = {party: ConsumedRecords(party) for party in VERIFIERS}

    first = verify_all(
        declaration, session.records[0], session.params, ledgers=ledgers
    )
    assert all(result.accepted for result in first.values())
    assert all(len(ledger) == 1 for ledger in ledgers.values())

    with pytest.raises(MatchedSetTooSmall) as excinfo:
        verify_all(
            declaration, session.records[0], session.params, ledgers=ledgers
        )
    assert excinfo.value.abort.reason is AbortReason.RECORD_ALREADY_VERIFIED

    with pytest.raises(TypeError):
        verify_all(
            declaration,
            session.records[0],
            session.params,
            ledgers=ConsumedRecords(Party.BOB),  # type: ignore[arg-type]
        )


# ==========================================================================
# 4. An honest single verification is completely unaffected
# ==========================================================================


@pytest.mark.parametrize("message_bit", [0, 1])
def test_honest_runs_are_unaffected_over_many_seeds(message_bit: int) -> None:
    """No new aborts, and the identical verdict, over 40 seeded runs each.

    One run proves nothing here: the claim is that the defence never fires on
    honest traffic, and the only way to say that is to run a lot of honest
    traffic. For each seed the run is executed twice -- once as the protocol
    now runs it, and once with the binding stripped from both halves, which is
    the code path that existed before -- and the two verdicts must be equal
    objects, not merely both acceptances.
    """
    params = _params()
    for offset in range(RUNS):
        session = _session(params, seed=SEED + offset)
        transcript = session.run(message_bit)

        assert not transcript.aborted, (
            f"seed {SEED + offset} aborted on an honest run: the replay "
            f"defence must never fire on honest traffic"
        )
        assert transcript.is_complete
        assert transcript.transferable
        assert transcript.session_coherent

        for party in VERIFIERS:
            bound = transcript.verdict_for(party)
            unbound = verify(
                _unbind_signature(transcript.signature),
                _unbind_record(transcript.records_for(message_bit)[party]),
                params,
            )
            assert bound == unbound
            assert bound.rate == 0.0
            assert bound.accepted


def test_the_binding_stream_does_not_perturb_the_other_two() -> None:
    """Openings come from a third derived stream, so seeded runs are unchanged.

    Drawing them from Alice's stream would have shifted every later variate and
    silently changed every seeded transcript in the project for a value none of
    them depend on. This pins that the records and keys a session produces are
    exactly what the two documented streams produce on their own.
    """
    from sih141.protocol.distribute import distribute_public_key
    from sih141.protocol.keys import generate_key_pair
    from sih141.protocol.session import (
        _ALICE_STREAM_LABEL,
        _RECIPIENT_STREAM_LABEL,
        _STREAM_MATERIAL_BYTES,
        _derive_stream,
    )
    from sih141.protocol.symmetrise import symmetrise_records

    params = _params()
    material = np.random.default_rng(SEED).bytes(_STREAM_MATERIAL_BYTES)
    alice = _derive_stream(material, _ALICE_STREAM_LABEL)
    recipients = _derive_stream(material, _RECIPIENT_STREAM_LABEL)

    keys = generate_key_pair(params, rng=alice)
    expected: dict[int, dict[Party, RecipientRecord]] = {}
    for bit in (0, 1):
        raw = distribute_public_key(
            keys[bit], params, parties=VERIFIERS, rng=alice
        )
        expected[bit] = symmetrise_records(raw, rng=recipients)

    session = _session(params, seed=SEED)
    session.distribute()

    assert session.keys == keys
    for bit in (0, 1):
        for party in VERIFIERS:
            produced = session.records[bit][party]
            assert _unbind_record(produced) == expected[bit][party]


# ==========================================================================
# 5. Message freshness -- the thin, classical layer
# ==========================================================================


def test_two_nonces_over_one_instruction_are_two_rounds() -> None:
    """A genuinely valid signed instruction cannot be executed twice.

    The freshness nonce goes into the context, the context is hashed into the
    round identifier, and each verifier decides each round exactly once. So a
    second execution of "pay 10" needs a second round -- a second distribution,
    a second key -- and cannot be a re-presentation of the first authorisation.
    """
    params = _params()
    first = _session(
        params, seed=SEED, context=fresh_context("pay 10", "nonce-1")
    )
    second = _session(
        params, seed=SEED, context=fresh_context("pay 10", "nonce-2")
    )
    first.distribute()
    second.distribute()

    # Same seed, same keys, same evidence -- and still different rounds, purely
    # because the authorisations are different.
    assert first.keys == second.keys
    assert first.session_ids[0] != second.session_ids[0]

    first.sign(0)
    replayed = verify_or_abort(
        first.signature, second.records[0][Party.BOB], params
    )
    assert isinstance(replayed, VerificationAbort)
    assert replayed.reason is AbortReason.SESSION_MISMATCH


def test_the_context_is_covered_by_the_rule_that_scores() -> None:
    """A rewritten instruction names a round no record carries.

    This is the whole justification for ``Signature`` carrying a free-text field
    at all, given that the module refuses uncovered labels on principle.
    """
    params = _params()
    session = _session(params, context=fresh_context("pay 10", "nonce-1"))
    session.distribute()
    declaration = session.sign(0)
    record = session.records[0][Party.BOB]

    rewritten = Signature(
        0,
        declaration.declared_key,
        session_opening=declaration.session_opening,
        context=fresh_context("pay 10000", "nonce-1"),
    )
    outcome = verify_or_abort(rewritten, record, params)
    assert isinstance(outcome, VerificationAbort)
    assert outcome.reason is AbortReason.SESSION_MISMATCH


def test_fresh_context_cannot_be_reparsed_into_another_pair() -> None:
    """Length prefixing, so a delimiter inside the instruction is harmless."""
    assert fresh_context("pay", "10#x") != fresh_context("pay#10", "x")
    assert fresh_context("", "n") != fresh_context("n", "n")
    with pytest.raises(ValueError):
        fresh_context("pay 10", "")
    with pytest.raises(TypeError):
        fresh_context("pay 10", 7)  # type: ignore[arg-type]


def test_fresh_opening_is_injected_randomness_only() -> None:
    """D3: the one drawing function here takes a generator and never a default."""
    assert fresh_opening(rng=np.random.default_rng(1)) == fresh_opening(
        rng=np.random.default_rng(1)
    )
    assert fresh_opening(rng=np.random.default_rng(1)) != fresh_opening(
        rng=np.random.default_rng(2)
    )
    assert len(fresh_opening(rng=np.random.default_rng(3))) == 32


def test_an_empty_opening_or_identifier_is_refused_rather_than_accepted() -> None:
    """"Commits to nothing" and "names no round" must not be the same value."""
    key = PrivateKey.from_dict(
        {"message_bit": 0, "elements": [{"basis": "X", "eigenvalue": 1}]}
    )
    with pytest.raises(ValueError):
        Signature(0, key, session_opening="")
    with pytest.raises(ValueError):
        RecipientRecord.from_measurements("Bob", 0, ["X"], [1], session_id="")
    with pytest.raises(ValueError):
        session_identifier(0, 1, opening="")
    # None and "" are different declarations of context, not the same one.
    assert session_identifier(0, 1, opening="a") != session_identifier(
        0, 1, opening="a", context=""
    )


# ==========================================================================
# 6. The refusals live in the abort machinery, apart from the verdicts
# ==========================================================================


def test_every_abort_reason_belongs_to_exactly_one_group() -> None:
    """A new member must be classified, not silently inherit a group.

    ``is_pooled`` and ``shortfall`` both switch on these sets, and a Phase 4 or
    Phase 5 table that reads them would misreport a member nobody placed.
    """
    groups = (_ROUND_REASONS, _OWN_COUNT_REASONS, _PAIR_REASONS)
    for reason in AbortReason:
        assert sum(reason in group for group in groups) == 1, (
            f"{reason.value!r} is in {sum(reason in g for g in groups)} "
            f"reason groups; every member must be in exactly one"
        )
    assert len(AbortReason) == sum(len(group) for group in groups)


@pytest.mark.parametrize(
    "reason",
    [AbortReason.SESSION_MISMATCH, AbortReason.RECORD_ALREADY_VERIFIED],
)
def test_a_round_refusal_names_no_floor_and_survives_json(
    reason: AbortReason,
) -> None:
    """It reports that no counting rule was reached, not that one was missed."""
    abort = VerificationAbort(
        party=Party.BOB,
        reason=reason,
        matched_count=8,
        minimum_matched=1,
        expected_matched=8.0,
        key_length=24,
        message_bit=0,
    )
    assert abort.shortfall == 0
    assert not abort.is_pooled
    assert abort.accepted_is_undefined
    assert reason.value in abort.summary()
    assert "Not a rejection." in abort.summary()

    restored = VerificationAbort.from_dict(
        json.loads(json.dumps(abort.to_dict()))
    )
    assert restored == abort


def test_a_round_refusal_is_recorded_apart_from_the_verdicts() -> None:
    """Nothing downstream can average a refusal into a rejection.

    The two live in different fields of the transcript and are different types
    with no ``accepted`` between them, which is what makes the separation
    structural rather than a convention a Phase 5 table has to remember.
    """
    session = _session()
    session.distribute()
    session.sign(0)
    other = _session(seed=SEED + 1)
    other.distribute()
    other.sign(0)

    wrong_round = Signature(
        0, session.keys[0], session_opening=other.opening_for(0)
    )
    outcome = verify_or_abort(
        wrong_round, session.records[0][Party.BOB], session.params
    )

    assert isinstance(outcome, VerificationAbort)
    assert not isinstance(outcome, VerificationResult)
    assert not hasattr(outcome, "accepted")
    assert not hasattr(outcome, "rate")
    assert not hasattr(outcome, "threshold")


def test_the_refusal_message_says_what_to_investigate() -> None:
    """A reader's first instinct -- logging it as a rejection -- is the one
    thing that must not happen, so both messages say so in words."""
    session = _session()
    session.distribute()
    declaration = session.sign(0)
    record = session.records[0][Party.BOB]
    ledger = session.ledger_for(Party.BOB)

    with pytest.raises(MatchedSetTooSmall) as mismatch:
        verify(_unbind_signature(declaration), record, session.params)
    assert "not a signature failure" in str(mismatch.value)
    assert "distribution round" in str(mismatch.value)

    verify(declaration, record, session.params, ledger=ledger)
    with pytest.raises(MatchedSetTooSmall) as spent:
        verify(declaration, record, session.params, ledger=ledger)
    assert "already reached a verdict" in str(spent.value)
    assert "ConsumedRecords" in str(spent.value)
