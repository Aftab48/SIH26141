"""Tests for :mod:`sih141.attacks.replay`.

Three things are pinned here, in descending order of how much they would cost to
get wrong.

**D6.** :class:`~sih141.attacks.replay.ReplayingForwarder` is put through
:func:`~sih141.attacks.isolation.assert_attack_isolated`, in both directions,
and the measurement functions are shown to refuse the two generators being the
same object. An adversary correlated with the session it attacks publishes rates
that are fiction while looking entirely legitimate, and every Phase 5 figure
would inherit the lie.

**The before/after.** Every attack is measured with the defence enabled and with
it disabled, and the tests assert the *gap* rather than only the defended
number. A defended zero on its own is consistent with an attack that never
worked, and an attack that never worked measures nothing.

**The finding.** The ledger denial of service
(:func:`~sih141.attacks.replay.measure_ledger_denial_of_service`) is asserted in
the direction that hurts: with the ledger, the honest declaration is denied; and
the mechanism -- that the hop can read the live opening off the declaration it
was asked to carry -- is pinned separately, so that a future change which
happens to close it fails this file loudly rather than quietly making a
documented hole disappear.

Notes
-----
Key lengths are 12 to 24 throughout. Below ``L = 140`` both matched-count floors
degenerate and carry no security claim; nothing asserted here is a security
claim, because every defended outcome tested is a *rule* -- an equality on a
round identifier, or a lookup in a set -- and rules do not have sample sizes.
The one statistical assertion is the undefended cross-session rate, and it is
checked against :func:`~sih141.protocol.analysis.forgery_probability` with a
band wide enough that a passing test means the law is right rather than that the
seed was kind.
"""

from __future__ import annotations

import numpy as np
import pytest

from sih141.attacks.isolation import (
    AttackIsolationError,
    assert_attack_isolated,
    check_attack_isolation,
)
from sih141.attacks.replay import (
    COUNTS_AS_RECEIVED,
    COUNTS_AS_SIGNED,
    COUNTS_NONE,
    AttackOutcome,
    ReplayCapture,
    ReplayingForwarder,
    measure_cross_session_pairing,
    measure_identifier_preimage,
    measure_ledger_denial_of_service,
    measure_ledger_poisoning,
    measure_shared_identifier,
    measure_shared_identifier_self_denial,
    measure_straight_replay,
    replay_capture,
    replay_probe,
    wilson_interval,
)
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.session import QDSSession
from sih141.protocol.signature import Signature, session_identifier
from sih141.protocol.verify import (
    AbortReason,
    ConsumedRecords,
    MatchedSetTooSmall,
    VerificationAbort,
    VerificationResult,
    verify_or_abort,
)

SMALL = ProtocolParams(key_length=24)
TINY = ProtocolParams(key_length=12)


def world(seed: int) -> np.random.Generator:
    """Return a generator standing in for the world's randomness."""
    return np.random.default_rng(seed)


def adversary(seed: int) -> np.random.Generator:
    """Return a generator standing in for an adversary's own randomness (D6)."""
    return np.random.default_rng(1_000_000 + seed)


# --------------------------------------------------------------------------- #
# D6: the adversary owns its randomness
# --------------------------------------------------------------------------- #


def test_replaying_forwarder_is_isolated() -> None:
    """The adversary's choices move with its own rng and not with the session."""
    report = assert_attack_isolated(ReplayingForwarder, replay_probe())
    assert report.isolated
    assert not report.reads_the_session
    assert report.uses_its_own_generator


def test_isolation_check_sees_more_than_one_decision() -> None:
    """Check (b) is not passing on a single lucky bit.

    An adversary whose randomness reaches its output through one fair coin
    would pass check (b) by chance one run in sixteen. This one draws a coin, a
    choice and a 128-bit opening, so the probe sees several distinct decisions
    rather than the bare two that would leave the check resting on luck.

    Not *all five*: the default ``replay_probability`` is ``0.5``, and every
    seed that declines to replay returns the live declaration unchanged, so
    those runs collapse onto one another. That collapse is the adversary
    behaving correctly, and asserting five here would be asserting that it
    always attacks.
    """
    report = check_attack_isolation(ReplayingForwarder, replay_probe())
    assert report.distinct_decisions >= 3


def test_builder_is_not_offered_the_session_seed() -> None:
    """The constructor cannot receive the session seed at all.

    The stronger of the two positions the isolation module distinguishes: a
    builder that does not declare ``session_seed`` has made the guarantee
    structural rather than demonstrated.
    """
    report = check_attack_isolation(ReplayingForwarder, replay_probe())
    assert report.session_seed_offered is False


def test_forwarder_refuses_a_missing_generator() -> None:
    """D6's constructor requirement is enforced, not documented."""
    with pytest.raises(TypeError, match="numpy.random.Generator"):
        ReplayingForwarder(rng=12345)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "call",
    [
        lambda gen: measure_ledger_denial_of_service(
            params=TINY, trials=1, rng=gen, attack_rng=gen, defended=True
        ),
        lambda gen: measure_ledger_poisoning(
            params=TINY, trials=1, rng=gen, attack_rng=gen
        ),
        lambda gen: measure_shared_identifier(
            params=TINY, trials=1, rng=gen, attack_rng=gen
        ),
        lambda gen: measure_shared_identifier_self_denial(
            params=TINY, trials=1, rng=gen, attack_rng=gen
        ),
    ],
)
def test_measurements_refuse_one_generator_for_both_roles(call) -> None:
    """Sharing a generator between the world and the adversary is refused.

    Not a style rule. An adversary drawing from the generator that also builds
    the sessions is correlated with the run he is attacking, which is the exact
    defect :mod:`sih141.attacks.isolation` exists to prevent, and it is far
    easier to hit here -- by passing the same object twice -- than through the
    session seam.
    """
    shared = world(7)
    with pytest.raises(ValueError, match="different generators"):
        call(shared)


def test_forwarder_ignores_the_view_it_is_offered() -> None:
    """A replay consults no evidence, so the seam is called with two arguments.

    The session decides once, at construction, whether a forwarder wants a
    :class:`~sih141.protocol.records.RecipientView`, and only a *required*
    parameter counts as wanting one. This adversary defaults it, so a session
    wired with it never builds Bob's view -- which is what keeps the replay
    inside the threat model of a party who holds only the public transcript.
    """
    session = QDSSession(
        TINY,
        forwarder=ReplayingForwarder(rng=adversary(1), replay_probability=0.0),
        rng=world(2),
    )
    session.distribute()
    session.sign(0)
    session.verify(Party.BOB)
    session.transfer()
    assert session.transcript().forwarded_signature is None


# --------------------------------------------------------------------------- #
# The seam-level adversary
# --------------------------------------------------------------------------- #


def test_capture_is_frozen_and_shared() -> None:
    """One capture serves the whole suite and cannot be contaminated."""
    first = replay_capture()
    assert first is replay_capture()
    assert isinstance(first, ReplayCapture)
    assert first.signature.session_id is not None
    for party in (Party.BOB, Party.CHARLIE):
        assert first.records[party].session_id == first.signature.session_id


def test_forwarder_declines_a_capture_of_the_wrong_bit() -> None:
    """A capture the session would refuse outright is not presented.

    Spending the attempt on a declaration the session rejects for its *bit*
    rather than for its key would report the adversary as harmless when he was
    merely clumsy.
    """
    other_bit = replay_capture(message_bit=1).signature
    attack = ReplayingForwarder(
        rng=adversary(3), captures=[other_bit], replay_probability=1.0
    )
    live = replay_capture(message_bit=0).signature
    assert attack(live, replay_capture().params) is live
    assert attack.replays == 0


def test_forwarder_replays_when_it_says_it_will() -> None:
    """``replay_probability=1`` substitutes on every call."""
    capture = replay_capture()
    attack = ReplayingForwarder(
        rng=adversary(4),
        captures=[capture.signature],
        replay_probability=1.0,
        relabel=False,
    )
    live = Signature(
        message_bit=0,
        declared_key=capture.signature.declared_key,
        session_opening="not-the-captured-opening",
    )
    assert attack(live, capture.params) is capture.signature
    assert attack.replays == 1


def test_session_relabels_a_stale_declaration_as_fresh() -> None:
    """The seam cannot express a cross-round replay, and that is deliberate.

    ``QDSSession`` rebinds whatever the forwarder returns to the live round, so
    a stale declaration pushed through the hop reaches Charlie carrying the
    *live* identifier: the replay binding cannot see it at all. That is what
    stops every forgery detection collapsing into a no-verdict, and it is why
    the cross-round measurements assemble their pairs directly instead of going
    through this seam. Pinned so that a change to the rebinding cannot silently
    turn the module's cross-session numbers into something else.

    What Charlie *does* refuse on is Phase C': the session runs the count
    exchange before the hop, so his count names the declaration Alice signed
    and not the one in front of him. That refusal -- not the replay defence --
    is the thing standing between an altering hop and Charlie's ledger, which
    is the whole subject of
    :func:`~sih141.attacks.replay.measure_ledger_denial_of_service`.
    """
    capture = replay_capture()
    session = QDSSession(
        capture.params,
        forwarder=ReplayingForwarder(
            rng=adversary(5),
            captures=[capture.signature],
            replay_probability=1.0,
            relabel=True,
        ),
        rng=world(6),
    )
    session.distribute()
    live = session.sign(0)
    session.verify(Party.BOB)
    with pytest.raises(MatchedSetTooSmall):
        session.transfer()
    forwarded = session.transcript().forwarded_signature
    assert forwarded is not None
    assert forwarded.declared_key == capture.signature.declared_key
    # Relabelled by the session, not by the adversary, and to the live round.
    assert forwarded.session_id == live.session_id
    abort = session.aborts[Party.CHARLIE]
    assert abort.reason is AbortReason.COUNTS_FROM_TWO_DECLARATIONS
    # Nothing was spent, because nothing was decided.
    assert len(session.ledger_for(Party.CHARLIE)) == 0


# --------------------------------------------------------------------------- #
# (a) straight re-verification
# --------------------------------------------------------------------------- #


def test_straight_replay_before_and_after() -> None:
    """Undefended it works every time; defended it never does."""
    before = measure_straight_replay(
        params=SMALL, trials=12, rng=world(11), defended=False
    )
    after = measure_straight_replay(
        params=SMALL, trials=12, rng=world(11), defended=True
    )
    assert before.successes == before.trials
    assert before.refusals == 0
    assert after.successes == 0
    assert after.refusals == after.trials


def test_straight_replay_refusal_is_not_a_rejection() -> None:
    """The second presentation reaches no verdict, rather than a negative one.

    The distinction the whole verification module is built around: a refusal
    decides nothing and must never be counted as a detected forgery.
    """
    session = QDSSession(SMALL, rng=world(12))
    session.distribute()
    signature = session.sign(0)
    record = session.records[0][Party.BOB]
    ledger = ConsumedRecords(Party.BOB)
    first = verify_or_abort(signature, record, SMALL, ledger=ledger)
    again = verify_or_abort(signature, record, SMALL, ledger=ledger)
    assert isinstance(first, VerificationResult) and first.accepted
    assert isinstance(again, VerificationAbort)
    assert again.reason is AbortReason.RECORD_ALREADY_VERIFIED


# --------------------------------------------------------------------------- #
# (b) cross-session pairing
# --------------------------------------------------------------------------- #


def test_cross_session_pairing_before_and_after() -> None:
    """Defended, every pairing is refused before a position is counted."""
    after = measure_cross_session_pairing(
        params=SMALL, trials=10, rng=world(13), defended=True
    )
    before = measure_cross_session_pairing(
        params=SMALL, trials=10, rng=world(13), defended=False
    )
    assert after.successes == 0
    assert after.refusals == after.trials
    # Undefended, the pair is not refused at all -- it is scored, and that is
    # the whole point: nothing in the arithmetic says "wrong run".
    assert before.refusals == 0


def test_cross_session_refusal_names_the_round() -> None:
    """The refusal is SESSION_MISMATCH, and the record is what drives it."""
    stale = QDSSession(SMALL, rng=world(14))
    stale.distribute()
    stale_signature = stale.sign(0)
    live = QDSSession(SMALL, rng=world(15))
    live.distribute()
    live.sign(0)
    record = live.records[0][Party.BOB]

    refusal = verify_or_abort(stale_signature, record, SMALL)
    assert isinstance(refusal, VerificationAbort)
    assert refusal.reason is AbortReason.SESSION_MISMATCH

    # A verifier who never stamped his log has nothing to compare, and is left
    # exactly as he was: the binding is the record's protection, not Alice's.
    unstamped = verify_or_abort(
        stale_signature, record.with_session_id(None), SMALL
    )
    assert isinstance(unstamped, VerificationResult)


@pytest.mark.parametrize("params", [TINY, SMALL])
def test_undefended_cross_session_rate_matches_the_forger_law(params) -> None:
    """The undefended acceptance rate is the outside forger's, as predicted.

    Run A's key is independent of run B's states, so a matched position agrees
    with probability ``1/2`` -- exactly the model
    :func:`~sih141.protocol.analysis.forgery_probability` computes. Checked at
    two key lengths, because agreeing at one could be a coincidence and
    agreeing at two is the law.

    The band is deliberately generous: a tight band on a few hundred trials
    would be a test of the seed rather than of the mathematics.
    """
    from sih141.protocol.analysis import forgery_probability

    trials = 150
    outcome = measure_cross_session_pairing(
        params=params, trials=trials, rng=world(16), defended=False
    )
    predicted = forgery_probability(params, party=Party.BOB)
    low, high = wilson_interval(outcome.successes, trials)
    assert low <= predicted <= high, (
        f"measured {outcome.successes}/{trials} at L={params.key_length}, "
        f"Wilson [{low:.5f}, {high:.5f}], predicted {predicted:.5f}"
    )


# --------------------------------------------------------------------------- #
# (c) the ledger
# --------------------------------------------------------------------------- #


def test_ledger_denial_of_service_is_real() -> None:
    """The finding, asserted in the direction that hurts.

    With the ledger the honest declaration is denied on every trial; without it
    the same adversary achieves nothing that lasts. This is a defence that can
    be turned into a denial of service, and the assertion is written so that a
    future change closing the hole breaks this test loudly rather than quietly
    deleting a documented result.
    """
    defended = measure_ledger_denial_of_service(
        params=SMALL,
        trials=12,
        rng=world(17),
        attack_rng=adversary(17),
        defended=True,
    )
    undefended = measure_ledger_denial_of_service(
        params=SMALL,
        trials=12,
        rng=world(17),
        attack_rng=adversary(17),
        defended=False,
    )
    assert defended.successes == defended.trials
    assert defended.refusals == defended.trials
    assert undefended.successes == 0


@pytest.mark.parametrize(
    ("counts", "expected_successes"),
    [(COUNTS_NONE, 8), (COUNTS_AS_RECEIVED, 8), (COUNTS_AS_SIGNED, 0)],
)
def test_denial_of_service_turns_on_which_declaration_was_counted(
    counts, expected_successes
) -> None:
    """The attack lives or dies on Phase C', not on the replay defence.

    Counting against what each party received -- the deployment reading, and the
    one an adversary holding the hop can arrange, since he computes one of the
    two counts himself -- burns the round every time. Counting against the
    declaration Alice signed, which is what the shipped session happens to do
    because it runs Phase C' before the hop, refuses the forgery on provenance
    and spends nothing.

    Parametrised rather than written three times so that a change which makes
    one ordering behave like another cannot pass by being fixed up in one place.
    """
    outcome = measure_ledger_denial_of_service(
        params=SMALL,
        trials=8,
        rng=world(30),
        attack_rng=adversary(30),
        defended=True,
        counts=counts,
    )
    assert outcome.successes == expected_successes


def test_denial_of_service_refuses_an_unnamed_ordering() -> None:
    """``counts`` decides the whole result, so it is never guessed at."""
    with pytest.raises(ValueError, match="counts must be one of"):
        measure_ledger_denial_of_service(
            params=TINY,
            trials=1,
            rng=world(31),
            attack_rng=adversary(31),
            defended=True,
            counts="whatever",
        )


def test_denial_of_service_mechanism_is_the_revealed_opening() -> None:
    """The hop mints its forgery from the opening Phase B publishes.

    Not a side effect of the harness: the opening travels *on* the declaration,
    the identifier deliberately does not cover the declared key, and the
    Bob-to-Charlie link is the one the threat model leaves unauthenticated. Each
    of those three is asserted, because the attack dies if any one changes.
    """
    session = QDSSession(SMALL, rng=world(18))
    session.distribute()
    signature = session.sign(0)
    assert signature.session_opening is not None

    forged = Signature(
        message_bit=0,
        declared_key=PrivateKey(
            0,
            tuple(
                KeyElement(element.basis, -element.eigenvalue)
                for element in signature.declared_key
            ),
        ),
        session_opening=signature.session_opening,
        context=signature.context,
    )
    # Same round, different key: the binding cannot tell them apart, and that
    # is by design (a key-covering identifier would turn every forgery into a
    # no-verdict).
    assert forged.session_id == signature.session_id

    record = session.records[0][Party.CHARLIE]
    ledger = ConsumedRecords(Party.CHARLIE)
    rejected = verify_or_abort(forged, record, SMALL, ledger=ledger)
    assert isinstance(rejected, VerificationResult)
    assert not rejected.accepted
    assert len(ledger) == 1

    denied = verify_or_abort(signature, record, SMALL, ledger=ledger)
    assert isinstance(denied, VerificationAbort)
    assert denied.reason is AbortReason.RECORD_ALREADY_VERIFIED


def test_ledger_cannot_be_poisoned_from_outside() -> None:
    """No refusal spends a round, and no ledger accepts the other party's log."""
    outcome = measure_ledger_poisoning(
        params=SMALL, trials=8, rng=world(19), attack_rng=adversary(19)
    )
    assert outcome.successes == 0
    assert outcome.refusals == outcome.trials


def test_ledger_growth_is_bounded_by_verdicts_not_by_presentations() -> None:
    """The exhaustion answer: unbounded presentations, bounded storage."""
    session = QDSSession(SMALL, rng=world(20))
    session.distribute()
    signature = session.sign(0)
    record = session.records[0][Party.BOB]
    ledger = ConsumedRecords(Party.BOB)
    noise = adversary(20)
    for _ in range(50):
        elsewhere = Signature(
            message_bit=0,
            declared_key=signature.declared_key,
            session_opening=noise.bytes(16).hex(),
        )
        assert isinstance(
            verify_or_abort(elsewhere, record, SMALL, ledger=ledger),
            VerificationAbort,
        )
    assert len(ledger) == 0
    verify_or_abort(signature, record, SMALL, ledger=ledger)
    assert len(ledger) == 1


def test_one_verifier_cannot_write_the_others_ledger() -> None:
    """Bob's evidence is refused by Charlie's ledger, with a reason."""
    session = QDSSession(TINY, rng=world(21))
    session.distribute()
    session.sign(0)
    with pytest.raises(ValueError, match="must not see"):
        ConsumedRecords(Party.CHARLIE).spend(session.records[0][Party.BOB])


# --------------------------------------------------------------------------- #
# (d) the session identifier
# --------------------------------------------------------------------------- #


def test_shared_identifier_buys_the_signer_nothing() -> None:
    """Two rounds under one identifier do not let a declaration migrate."""
    outcome = measure_shared_identifier(
        params=SMALL, trials=20, rng=world(22), attack_rng=adversary(22)
    )
    assert outcome.successes == 0
    # It passes the binding -- that is the point of the experiment -- and is
    # then simply scored, so nothing is refused.
    assert outcome.refusals == 0


def test_shared_identifier_denies_the_signer_her_second_round() -> None:
    """A reused opening makes two rounds one round to every verifier."""
    outcome = measure_shared_identifier_self_denial(
        params=SMALL, trials=8, rng=world(23), attack_rng=adversary(23)
    )
    assert outcome.successes == outcome.trials
    assert outcome.refusals == outcome.trials


def test_identifier_cannot_be_written_only_hashed_to() -> None:
    """There is no field to assign; relabelling is a preimage problem."""
    capture = replay_capture()
    assert not hasattr(capture.signature, "session_id_setter")
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__  # sanity: frozen dataclass, assignment is refused
        capture.signature.session_opening = "x"  # type: ignore[misc]


def test_bounded_preimage_search_finds_nothing() -> None:
    """A short search reports zero, and reports it as a bound rather than a fact."""
    capture = replay_capture()
    target = capture.signature.session_id
    assert target is not None
    outcome = measure_identifier_preimage(
        target=target,
        params=capture.params,
        attempts=5000,
        rng=adversary(24),
    )
    assert outcome.successes == 0
    low, high = outcome.interval
    assert low == 0.0
    assert 0.0 < high < 0.01


def test_identifier_encoding_resists_delimiter_shifting() -> None:
    """No ``(opening, context)`` pair can be rewritten into another one.

    The obvious structural attack on a concatenated digest, and the reason
    :func:`~sih141.protocol.signature.session_identifier` length-prefixes every
    variable-length field. Openings and contexts here are chosen to contain the
    delimiter, digits that could be mistaken for a length, and the
    ``None``/empty distinction.
    """
    candidates = [
        ("a", None),
        ("a", ""),
        ("a", "|"),
        ("a|", ""),
        ("a|b", None),
        ("a", "b"),
        ("a|1", "b"),
        ("a", "1|b"),
        ("1", "16:a"),
        ("16:a", "1"),
    ]
    identifiers = {
        session_identifier(0, 24, opening=opening, context=context)
        for opening, context in candidates
    }
    assert len(identifiers) == len(candidates)

    # And the round's own coordinates are covered too, so an opening reused
    # across bits or key lengths still names a different round.
    assert session_identifier(0, 24, opening="a") != session_identifier(
        1, 24, opening="a"
    )
    assert session_identifier(0, 24, opening="a") != session_identifier(
        0, 25, opening="a"
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def test_wilson_interval_is_honest_at_zero() -> None:
    """Zero successes gets a real upper bound, not a claim of certainty."""
    low, high = wilson_interval(0, 500)
    assert low == 0.0
    assert 0.0 < high < 0.01
    assert high > 3.0 / 500  # of the right order, not an accidental epsilon


@pytest.mark.parametrize(
    ("successes", "trials"),
    [(0, 1), (1, 1), (3, 10), (500, 1000), (999, 1000)],
)
def test_wilson_interval_brackets_the_point_estimate(successes, trials) -> None:
    """The interval contains the rate it describes."""
    low, high = wilson_interval(successes, trials)
    assert low <= successes / trials <= high


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"successes": 0, "trials": 0}, ValueError),
        ({"successes": 3, "trials": 2}, ValueError),
        ({"successes": -1, "trials": 2}, ValueError),
        ({"successes": True, "trials": 2}, TypeError),
        ({"successes": 1.0, "trials": 2}, TypeError),
    ],
)
def test_wilson_interval_refuses_nonsense(kwargs, error) -> None:
    """Counts are integers in range; a rate with no denominator is refused."""
    with pytest.raises(error):
        wilson_interval(**kwargs)


def test_outcome_reports_its_denominator_and_its_arm() -> None:
    """A rate without its trial count and its arm cannot be argued with."""
    outcome = AttackOutcome(
        label="example",
        defended=False,
        trials=100,
        successes=7,
        refusals=0,
        key_length=24,
        note="context",
    )
    text = outcome.summary()
    assert "7/100" in text
    assert "undefended" in text
    assert "L=24" in text
    assert "context" in text


@pytest.mark.parametrize(
    "kwargs",
    [
        {"trials": 0, "successes": 0},
        {"trials": 5, "successes": 6},
        {"trials": 5, "successes": 0, "refusals": 6},
        {"trials": 5, "successes": 0, "label": ""},
    ],
)
def test_outcome_refuses_an_impossible_table(kwargs) -> None:
    """Every field is validated; an unvalidated outcome is a wrong table."""
    fields = {
        "label": "example",
        "defended": True,
        "refusals": 0,
        "key_length": 24,
    }
    fields.update(kwargs)
    with pytest.raises(ValueError):
        AttackOutcome(**fields)


def test_outcome_refuses_a_truthy_arm() -> None:
    """``defended`` selects an arm and must not be inferred from truthiness."""
    with pytest.raises(TypeError, match="defended must be a bool"):
        AttackOutcome(
            label="example",
            defended=1,  # type: ignore[arg-type]
            trials=5,
            successes=0,
            refusals=0,
            key_length=24,
        )


def test_probe_refuses_a_capture_of_the_wrong_type() -> None:
    """A probe built on the wrong object fails loudly rather than vacuously."""
    with pytest.raises(TypeError, match="ReplayCapture"):
        replay_probe("not a capture")  # type: ignore[arg-type]


def test_isolation_catches_a_forwarder_that_peeks() -> None:
    """The check would catch this adversary if it were written the wrong way.

    A negative control. Without it, the passing isolation test above is
    consistent with a check that passes everything, and a suite that cannot
    fail is not evidence.
    """

    class PeekingForwarder:
        """A forwarder that draws its opening from the session's seed."""

        def __init__(
            self, *, rng: np.random.Generator, session_seed: int
        ) -> None:
            self._opening = np.random.default_rng(session_seed).bytes(16).hex()
            self._noise = int(rng.integers(1000))

        def __call__(self, signature, params, *, view=None):
            """Relabel with an opening only the session could have told it."""
            del params, view
            return Signature(
                message_bit=signature.message_bit,
                declared_key=signature.declared_key,
                session_opening=self._opening,
            )

    with pytest.raises(AttackIsolationError, match="reads the session"):
        assert_attack_isolated(PeekingForwarder, replay_probe())
