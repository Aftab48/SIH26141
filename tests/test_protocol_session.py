"""Tests for :mod:`sih141.protocol.session` -- the whole run, orchestrated.

The six modules underneath this one are already pinned by their own suites, so
nothing here re-tests the matched/unmatched split or the Born rule. What is
tested here is everything that only exists once the phases are composed:

1. **The end-to-end claims.** An honest noiseless run must end with *both*
   verifiers accepting at rate exactly ``0.0`` -- not "small", exactly zero,
   because teleportation over a clean pair is exact and a matched position
   re-measures the very observable the state was an eigenstate of. Over many
   seeded runs, Bob accepting must imply Charlie accepting; that is
   transferability, and it is checked twice -- once on clean runs, where it is
   true trivially, and once through a Werner channel tuned so that Bob genuinely
   rejects some runs, where it is not.
2. **Reproducibility.** One seed reproduces the entire transcript, object for
   object and byte for byte through :meth:`SessionTranscript.to_json`. Phase 5
   sweeps and Phase 3's clean-versus-attacked comparisons are worthless
   otherwise.
3. **JSON, end to end.** Phase 6 serves transcripts over HTTP, so a transcript
   must survive :func:`json.dumps` unchanged and come back equal -- every leaf
   an ``int``, ``float``, ``bool`` or ``str``, with no quantum state anywhere.
4. **The Phase 3 seams.** The whole attack suite hangs off ``resource_factory``,
   ``payload_map``, ``distributor``, ``signer`` and ``forwarder``, so each is
   exercised here from the session's own API: a degraded channel must drive both
   verifiers to reject (which also re-proves the teleportation is genuinely in
   the data path when driven from this module), a forging signer must be
   rejected, and a mis-wired seam must fail loudly rather than quietly produce a
   clean-looking run.

   Two of them are about *what a seam is shown*, and those tests are the ones to
   read first. The ``signer`` seam no longer receives the recipients' logs
   unless the session is built to hand them over, because no single adversary in
   the threat model holds both; and the ``forwarder`` seam -- where a forging
   recipient actually stands -- receives one ``RecipientView``, which is a type
   that cannot hold the counterpart's evidence.
5. **The channel monitor.** A checked run publishes what happened on the sampled
   positions and nothing about the others. That single property is asserted from
   three directions: what the monitor is called on, what the transcript carries,
   and what a hand-edited transcript claiming a key position does when it is
   read back.
6. **What the seams can infer about the check set.** Calling every seam at every
   position was not enough on its own: the protocol then *read* what came back a
   different number of times on the two branches, so an adversary returning an
   instrumented object recovered the whole check set from its own read tally at
   precision ``1.0``. Every seam's answer is now adopted at the boundary, and
   the tests here drive all three seams at once, assert the tally is flat, and
   run an end-to-end spare-the-watched exploit that used to take a channel
   attack from detected to invisible. Both carry a control against the way this
   family of test fails silently: the tally test scores a synthetic pre-fix
   tally and requires the check set back, and the exploit test pins the
   *unspared* arm's published QBER and key damage, so an adversary that has
   quietly stopped attacking cannot pass by leaving nothing to detect.
7. **Phase order and single use.** Every out-of-order call is refused with a
   message naming the call that would fix it, and a session distributes once and
   signs once.

Costs and sizes
---------------
A session teleports ``2 message bits * 2 recipients * L`` qubits, so ``L`` is
kept small here and stated per test. The two tests that run a *noisy* channel
are the exception and use ``L = 600``, because they are the only ones whose
claim is statistical and they were mis-sized before: at ``L = 96`` a verifier
holds about ``32`` matched positions, so Bob's budget ``floor(m * s_a)`` is
**zero** mismatches and Charlie's is one. "``s_a`` is a budget" is not a true
statement at that size, and "Bob accepting implies Charlie accepting" held with
probability about ``0.6`` over the twenty runs -- it passed on the seeds that
were there rather than on the mathematics, and any change to the generator
stream re-rolled it. At ``L = 600`` the budgets are three and twelve mismatches:
a Werner parameter of ``2 * s_a`` puts the matched-position error rate exactly on
Bob's threshold, so he still rejects a third of runs, while Charlie would need
thirteen mismatches where three are expected and the implication fails with
probability of order ``1e-5`` per run. Every seed is fixed.
"""

from __future__ import annotations

import dataclasses
import json
from collections import Counter
from collections.abc import Mapping
from typing import Any

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix, Kraus, Statevector

from sih141.core.states import BellState, bell_state
from sih141.protocol import (
    DEMO_PARAMS,
    MESSAGE_BITS,
    VERIFIERS,
    AbortReason,
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
    KeyElement,
    distribute_public_key,
    honest_forwarder,
    honest_signer,
    ideal_resource,
    no_count_exchange,
    no_symmetrisation,
    sign,
    symmetrise_records,
    verify_or_abort,
)
from sih141.protocol.checkrounds import (
    CheckRole,
    draw_check_plan,
    estimate_chsh,
    estimate_qber,
)
from sih141.protocol.distribute import (
    RecipientDistribution,
    ResourceContext,
    distribute_public_key_with_checks,
    identity_payload,
)
from sih141.protocol.keys import key_from_record
from sih141.protocol.params import CHECKED_PARAMS, DEMO_CHECKED_PARAMS
from sih141.protocol.records import RecipientView
from sih141.protocol.session import (
    _ALICE_STREAM_LABEL,
    _RECIPIENT_STREAM_LABEL,
    _STREAM_MATERIAL_BYTES,
    NO_RECIPIENT_LOGS,
    ChannelSample,
    WithheldRecords,
    _derive_stream,
    _forwarder_wants_view,
)

SEED = 20260141
"""Base seed. Every run in this module derives its generator from it."""

RUNS = 20
"""Number of independent seeded runs the transferability tests average over."""


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


def _werner(p: float) -> DensityMatrix:
    """Return the Werner state ``(1 - p) |Phi+><Phi+| + p I/4``.

    Teleporting a pure payload over it applies a depolarising channel of
    strength ``p``, so a matched position disagrees with the declared eigenvalue
    with probability exactly ``p / 2``. Same helper as
    ``tests/test_protocol_distribute.py``, deliberately: the two suites must be
    talking about the same channel.
    """
    phi = DensityMatrix(bell_state(BellState.PHI_PLUS)).data
    return DensityMatrix((1.0 - p) * phi + p * np.eye(4) / 4.0)


def _flip_all(key: PrivateKey) -> PrivateKey:
    """Return ``key`` with every eigenvalue negated -- a maximally wrong key."""
    return PrivateKey.from_dict(
        {
            "message_bit": key.message_bit,
            "elements": [
                {"basis": element.basis, "eigenvalue": -element.eigenvalue}
                for element in key.elements
            ],
        }
    )


def _reading_signer() -> Any:
    """Return a signer that reaches for a recipient's log, as attacks do."""

    def signer(
        message_bit: int, keys: Any, params: Any, *, records: Any
    ) -> Signature:
        record = records[message_bit][Party.BOB]
        return Signature(message_bit, key_from_record(record))

    return signer


def _checked(length: int = 120, fraction: float = 0.25) -> ProtocolParams:
    """Build a parameter set that reserves check rounds.

    ``L = 120`` with a quarter checked leaves ``90`` signing positions, which is
    small enough to run in a test and large enough that the two floors, the two
    thresholds and the CHSH estimate are all computed from a number that is
    genuinely not ``L``. That is the property every check-round test here is
    really about: the shortening has to reach every derived quantity, and a
    parameter set where the two coincide could not tell.
    """
    return ProtocolParams(key_length=length, check_fraction=fraction)


@pytest.fixture(scope="module")
def honest_run() -> SessionTranscript:
    """One clean, seeded, completed run. Shared, because it costs 96 hops."""
    return _session(_params(24)).run(0)


@pytest.fixture(scope="module")
def checked_run() -> SessionTranscript:
    """One clean, seeded, completed run *with* check rounds. 480 hops."""
    return _session(_checked(), seed=SEED + 101).run(0)


# ==========================================================================
# The honest noiseless run
# ==========================================================================


def test_honest_run_is_accepted_by_both_verifiers(
    honest_run: SessionTranscript,
) -> None:
    """Bob accepts and Charlie accepts. The base case of the whole project."""
    assert honest_run.bob is not None
    assert honest_run.charlie is not None
    assert honest_run.bob.accepted
    assert honest_run.charlie.accepted


def test_honest_run_has_a_mismatch_rate_of_exactly_zero(
    honest_run: SessionTranscript,
) -> None:
    """Exactly ``0.0``, not merely small.

    Teleportation over a clean pair is exact, so on a matched position the
    recipient re-measured the observable the state was an eigenstate of and
    cannot disagree. Anything above zero on a noiseless run is a bug, not noise.
    """
    assert honest_run.bob.rate == 0.0
    assert honest_run.charlie.rate == 0.0
    assert honest_run.bob.mismatches == 0
    assert honest_run.charlie.mismatches == 0


def test_honest_run_is_transferable_and_not_repudiated(
    honest_run: SessionTranscript,
) -> None:
    """The two named composite events take the values an honest run demands."""
    assert honest_run.transferable is True
    assert honest_run.repudiated is False
    assert honest_run.is_complete is True


def test_each_verifier_is_scored_against_its_own_threshold(
    honest_run: SessionTranscript,
) -> None:
    """Bob is cut at ``s_a``, Charlie at ``s_v``, and the gap is real."""
    assert honest_run.bob.threshold == honest_run.params.s_a
    assert honest_run.charlie.threshold == honest_run.params.s_v
    assert honest_run.bob.threshold < honest_run.charlie.threshold


def test_verdicts_are_reached_in_protocol_order(
    honest_run: SessionTranscript,
) -> None:
    """Bob first, Charlie after the transfer -- the order is part of the record."""
    assert [result.party for result in honest_run.results] == list(VERIFIERS)


def test_both_verifiers_scored_the_same_number_of_positions(
    honest_run: SessionTranscript,
) -> None:
    """Both logs are ``L`` long; only the matched subsets differ."""
    assert honest_run.bob.key_length == honest_run.params.key_length
    assert honest_run.charlie.key_length == honest_run.params.key_length
    assert honest_run.bob.matched_count + honest_run.bob.unmatched_count == (
        honest_run.params.key_length
    )


def test_the_two_verifiers_measured_independently(
    honest_run: SessionTranscript,
) -> None:
    """Bob and Charlie hold different logs: two preparations, two fresh pairs.

    If the session distributed once and handed the same record to both, every
    transferability result in the project would be a tautology.
    """
    records = honest_run.records_for(honest_run.message_bit)
    assert records[Party.BOB] != records[Party.CHARLIE]
    assert records[Party.BOB].bases != records[Party.CHARLIE].bases


# ==========================================================================
# Transferability
# ==========================================================================


def test_bob_accepting_implies_charlie_accepting_on_clean_runs() -> None:
    """Over many seeded honest runs, Bob's acceptance is always forwardable.

    Trivially true when the channel is clean -- both rates are zero -- and it is
    still worth asserting, because the cheapest way to break transferability is
    to hand Charlie the wrong threshold or the wrong record, and either would
    show up here.
    """
    transferable = 0
    for run in range(RUNS):
        transcript = _session(_params(24), seed=SEED + run).run(run % 2)
        assert transcript.bob.accepted
        if transcript.bob.accepted:
            assert transcript.charlie.accepted, (
                f"run {run}: Bob accepted but Charlie did not -- "
                f"{transcript.summary()}"
            )
        transferable += transcript.transferable
    assert transferable == RUNS


def test_bob_accepting_implies_charlie_accepting_through_a_noisy_channel() -> None:
    """The same implication where it is not trivial.

    The Werner parameter is ``2 * s_a``, so the matched-position error rate sits
    exactly on Bob's threshold and he rejects a substantial minority of runs.
    Charlie's cut is four times higher, so he keeps accepting -- which is
    precisely what ``s_a < s_v`` was chosen to buy. The assertion is the
    implication; the extra check that Bob rejected at least once is what stops
    the test passing vacuously.

    ``L = 600`` and not the ``96`` used elsewhere in this file, because the
    implication is a statistical claim and ``96`` is too small for it to be
    true: a verifier holds about ``32`` matched positions there, Bob's budget is
    ``floor(32 / 64) = 0`` mismatches and Charlie rejects on two, so the two
    events overlap and "Bob accepted, Charlie did not" arrives on an *honest*
    signer about once in forty runs -- which made this twenty-run test fail
    about two times in five, whatever the code did. At ``600`` the budgets are
    three and twelve mismatches against an expected three, which is the
    separation ``s_a < s_v`` is supposed to provide. See the module docstring on
    sizes; the cost is about a second a run.
    """
    params = _params(600)
    noise = 2.0 * params.s_a

    bob_rejections = 0
    for run in range(RUNS):
        transcript = _session(
            params,
            seed=SEED + 5_000 + run,
            resource_factory=lambda: _werner(noise),
        ).run(run % 2)
        if transcript.bob.accepted:
            assert transcript.charlie.accepted, (
                f"run {run}: transferability failed -- {transcript.summary()}"
            )
            assert transcript.transferable
        else:
            bob_rejections += 1
        assert not transcript.repudiated, (
            f"run {run}: repudiation event on an honest signer -- "
            f"{transcript.summary()}"
        )

    assert 0 < bob_rejections < RUNS, (
        f"the noisy sample must contain both verdicts at Bob for the "
        f"implication to have content, got {bob_rejections}/{RUNS} rejections"
    )


# ==========================================================================
# Reproducibility
# ==========================================================================


def test_the_same_seed_reproduces_the_transcript_exactly() -> None:
    """One seed, one transcript. Compared as objects, not as summaries."""
    params = _params(24)
    first = _session(params, seed=SEED).run(1)
    second = _session(params, seed=SEED).run(1)

    assert first == second
    assert first.signature == second.signature
    assert first.records == second.records
    assert first.results == second.results


def test_the_same_seed_reproduces_the_transcript_byte_for_byte() -> None:
    """The serialised form is identical too, which is what a Phase 5 log diffs."""
    params = _params(24)
    first = _session(params, seed=SEED).run(0)
    second = _session(params, seed=SEED).run(0)
    assert first.to_json(sort_keys=True) == second.to_json(sort_keys=True)


def test_different_seeds_give_different_runs() -> None:
    """Distinct seeds must not collapse to one stream."""
    params = _params(24)
    first = _session(params, seed=SEED).run(0)
    second = _session(params, seed=SEED + 1).run(0)
    assert first != second
    assert first.signature != second.signature


def test_the_callers_generator_is_drawn_from_once_and_then_dropped() -> None:
    """One draw at construction -- the material -- and never again.

    The generator the caller passes in is the one object no seam may ever hold:
    PCG64's transition is invertible, so a seam given it could rewind past this
    draw and re-derive both session streams. So the session takes its material,
    derives Alice's stream and the recipients' from it, and lets the caller's
    generator go. It is still *advanced* by the draw, which is what keeps two
    sessions built from one generator two different runs.
    """
    params = _params(16)
    caller = np.random.default_rng(SEED)
    QDSSession(params, rng=caller).run(0)

    shadow = np.random.default_rng(SEED)
    shadow.bytes(_STREAM_MATERIAL_BYTES)
    assert caller.bit_generator.state == shadow.bit_generator.state

    shared = np.random.default_rng(SEED)
    first = QDSSession(params, rng=shared).run(0)
    second = QDSSession(params, rng=shared).run(0)
    assert first != second


def test_the_alice_stream_is_threaded_through_alices_phases() -> None:
    """Key generation and both distributions share one derived stream (D3).

    Shadowed draw for draw from the Alice-side stream: two variates per key
    element for each of the two keys, then, per message bit, three per key
    position per recipient -- basis choice, Alice's Bell measurement inside
    ``teleport``, and the recipient's projective measurement. **And nothing
    else.** If the symmetrisation coins were still coming out of this stream the
    shadow would part company with it by exactly two ``L``-long draws, which is
    the whole finding this test exists for (:ref:`two-streams`).
    """
    params = _params(16)
    length = params.key_length
    alphabet = len(params.bases)
    captured: list[np.random.Generator] = []

    def watching(
        key: PrivateKey, protocol_params: ProtocolParams, **kwargs: Any
    ) -> Any:
        captured.append(kwargs["rng"])
        return distribute_public_key(key, protocol_params, **kwargs)

    QDSSession(
        params, rng=np.random.default_rng(SEED), distributor=watching
    ).run(0)
    assert len(captured) == len(MESSAGE_BITS)
    assert captured[0] is captured[1]  # one stream, not one per bit

    material = np.random.default_rng(SEED).bytes(_STREAM_MATERIAL_BYTES)
    shadow = _derive_stream(material, _ALICE_STREAM_LABEL)
    for _ in MESSAGE_BITS:  # generate_key_pair: two keys, two draws per element
        for _ in range(length):
            shadow.integers(alphabet)
            shadow.integers(2)
    for _ in MESSAGE_BITS:  # distribute_public_key, per bit
        for _ in VERIFIERS:
            for _ in range(length):
                shadow.integers(alphabet)  # the recipient's basis choice
                shadow.random()  # Alice's Bell measurement, inside teleport()
                shadow.random()  # the recipient's projective measurement

    assert captured[0].bit_generator.state == shadow.bit_generator.state


def test_the_recipient_stream_supplies_exactly_the_symmetrisation_coins() -> None:
    """Phase A' draws from the recipients' own stream, and draws only coins.

    One ``L``-long array per message bit, out of a generator derived under a
    different label from the same material. Two independent sessions of the
    protocol's randomness, from one seed, is what makes the fix free: the run
    stays reproducible and the coins stay unreachable.
    """
    params = _params(16)
    captured: list[np.random.Generator] = []

    def watching(records: Any, *, rng: Any = None) -> Any:
        captured.append(rng)
        return symmetrise_records(records, rng=rng)

    QDSSession(
        params, rng=np.random.default_rng(SEED), symmetriser=watching
    ).run(0)
    assert len(captured) == len(MESSAGE_BITS)
    assert captured[0] is captured[1]

    material = np.random.default_rng(SEED).bytes(_STREAM_MATERIAL_BYTES)
    shadow = _derive_stream(material, _RECIPIENT_STREAM_LABEL)
    for _ in MESSAGE_BITS:
        shadow.integers(0, 2, size=params.key_length)

    assert captured[0].bit_generator.state == shadow.bit_generator.state


def test_an_unseeded_session_still_runs() -> None:
    """``rng=None`` means entropy-seeded, not broken (D3)."""
    transcript = QDSSession(_params(24)).run(0)
    assert transcript.transferable


def test_integer_seeds_are_refused() -> None:
    """A bare seed would restart the stream; ``resolve_rng`` says so (D3)."""
    with pytest.raises(TypeError):
        QDSSession(_params(24), rng=SEED)  # type: ignore[arg-type]


# ==========================================================================
# The transcript: JSON, end to end
# ==========================================================================


def test_transcript_survives_a_json_round_trip(
    honest_run: SessionTranscript,
) -> None:
    """Serialise, parse, rebuild, compare equal. Phase 6 depends on this."""
    restored = SessionTranscript.from_json(honest_run.to_json())
    assert restored == honest_run


def test_transcript_to_dict_holds_only_json_primitives(
    honest_run: SessionTranscript,
) -> None:
    """Every leaf is a primitive -- no state, no generator, no dataclass.

    Checked on the object rather than argued in a docstring, because "the
    session retains no quantum memory" is a property of what it hands back.
    """

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for name, child in node.items():
                assert isinstance(name, str), f"{path}: non-string key {name!r}"
                walk(child, f"{path}.{name}")
        elif isinstance(node, list):
            for position, child in enumerate(node):
                walk(child, f"{path}[{position}]")
        else:
            # ``None`` is JSON null, and is what the two optional fields --
            # forwarded_signature and run_id -- hold on an honest run.
            assert node is None or isinstance(node, (bool, int, float, str)), (
                f"{path} holds {type(node).__name__}, which is not JSON data"
            )
            assert not isinstance(node, (Statevector, DensityMatrix))

    walk(honest_run.to_dict(), "transcript")


def test_transcript_json_is_parseable_and_keeps_its_verdicts(
    honest_run: SessionTranscript,
) -> None:
    """The parsed blob is what a dashboard would read straight off the wire."""
    blob = json.loads(honest_run.to_json())
    assert blob["message_bit"] == honest_run.message_bit
    assert blob["params"]["bases"] == ["X", "Y", "Z"]
    assert [entry["party"] for entry in blob["results"]] == ["Bob", "Charlie"]
    assert all(entry["accepted"] for entry in blob["results"])
    assert len(blob["records"]) == len(MESSAGE_BITS) * len(VERIFIERS)


def test_transcript_round_trip_preserves_the_derived_properties(
    honest_run: SessionTranscript,
) -> None:
    """Derived values are recomputed, never stored, so they cannot drift."""
    restored = SessionTranscript.from_dict(honest_run.to_dict())
    assert restored.transferable == honest_run.transferable
    assert restored.repudiated == honest_run.repudiated
    assert restored.summary() == honest_run.summary()


def test_transcript_json_round_trip_survives_a_rejected_run() -> None:
    """A failed run serialises as faithfully as a successful one."""
    transcript = _session(
        _params(48), resource_factory=lambda: _werner(1.0)
    ).run(0)
    assert not transcript.bob.accepted
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


# ==========================================================================
# The transcript: contents and derived views
# ==========================================================================


def test_transcript_holds_every_log_from_both_message_bits(
    honest_run: SessionTranscript,
) -> None:
    """Four logs: Alice committed to both keys before she knew the message."""
    assert len(honest_run.records) == len(MESSAGE_BITS) * len(VERIFIERS)
    assert sorted({record.message_bit for record in honest_run.records}) == [0, 1]
    for bit in MESSAGE_BITS:
        assert sorted(honest_run.records_for(bit)) == sorted(VERIFIERS)


def test_transcript_records_are_ordered_by_bit_then_by_party(
    honest_run: SessionTranscript,
) -> None:
    """A stable order, so two transcripts of the same run compare equal."""
    assert [
        (record.message_bit, record.party) for record in honest_run.records
    ] == [(bit, party) for bit in MESSAGE_BITS for party in VERIFIERS]


def test_transcript_verdict_lookup_by_party(
    honest_run: SessionTranscript,
) -> None:
    """``verdict_for`` accepts a member or its label."""
    assert honest_run.verdict_for(Party.BOB) is honest_run.bob
    assert honest_run.verdict_for("Charlie") is honest_run.charlie


def test_transcript_distinguishes_never_asked_from_rejected() -> None:
    """A missing verdict raises rather than reading as a rejection.

    Returning ``False`` for "Charlie has not looked at it yet" would let an
    abandoned run be counted as a detection.
    """
    session = _session(_params(24))
    session.distribute()
    session.sign(0)
    session.verify(Party.BOB)
    transcript = session.transcript()

    assert transcript.is_complete is False
    assert transcript.transferable is False
    assert transcript.repudiated is False
    with pytest.raises(ValueError, match="reached no verdict"):
        transcript.verdict_for(Party.CHARLIE)


def test_transcript_summary_names_the_outcome(
    honest_run: SessionTranscript,
) -> None:
    """Context, the pooled evidence, one line per verdict, then the event.

    The Phase C' line comes *before* the verdicts because that is the order the
    protocol runs in: the recipients compare matched counts, and only then does
    either of them decide. The evidence line quotes the *per-run* repudiation
    bound at the observed ``M = m_B + m_C``. It is there because the number a
    reader would otherwise reach for -- the ``M``-averaged one -- is only valid
    while the declaration is independent of the recipients' logged bases, which
    the ``Signer`` seam does not guarantee. See ``analysis`` section 4b.
    """
    lines = honest_run.summary().splitlines()
    assert len(lines) == 6
    assert "message bit 0" in lines[0]
    assert lines[1].startswith("POOLED EVIDENCE bit 0: m_B = ")
    assert "Every floor met." in lines[1]
    assert lines[2].startswith("Bob ACCEPTED")
    assert lines[3].startswith("Charlie ACCEPTED")
    assert lines[4].startswith("EVIDENCE: M = m_B + m_C = ")
    assert "assumes nothing about the signer" in lines[4]
    assert lines[5] == "TRANSFERABLE: Bob accepted and Charlie accepted."


def test_transcript_summary_reports_a_rejection() -> None:
    """A run Bob refuses says so in the last line."""
    transcript = _session(
        _params(48), resource_factory=lambda: _werner(1.0)
    ).run(1)
    assert transcript.summary().splitlines()[-1].startswith("REJECTED")


def test_transcript_is_frozen(honest_run: SessionTranscript) -> None:
    """Evidence must not be editable after the fact (D5)."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        honest_run.message_bit = 1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        honest_run.results = ()  # type: ignore[misc]


def test_transcript_rejects_a_signature_for_the_other_bit(
    honest_run: SessionTranscript,
) -> None:
    """The bit selects which distribution was scored; a mismatch is incoherent."""
    other = sign(1, PrivateKey.from_dict({
        "message_bit": 1,
        "elements": honest_run.signature.declared_key.to_dict()["elements"],
    }))
    with pytest.raises(ValueError, match="wrong records"):
        SessionTranscript(
            params=honest_run.params,
            message_bit=0,
            signature=other,
            records=honest_run.records,
            results=honest_run.results,
        )


def test_transcript_rejects_two_verdicts_from_one_verifier(
    honest_run: SessionTranscript,
) -> None:
    """One verifier reaches one decision per signature."""
    with pytest.raises(ValueError, match="two verdicts"):
        SessionTranscript(
            params=honest_run.params,
            message_bit=honest_run.message_bit,
            signature=honest_run.signature,
            records=honest_run.records,
            results=(honest_run.bob, honest_run.bob),
        )


def test_transcript_rejects_a_non_record(honest_run: SessionTranscript) -> None:
    """Only :class:`RecipientRecord` may stand as evidence."""
    with pytest.raises(TypeError, match="RecipientRecord"):
        SessionTranscript(
            params=honest_run.params,
            message_bit=honest_run.message_bit,
            signature=honest_run.signature,
            records=("not a record",),  # type: ignore[arg-type]
            results=honest_run.results,
        )


def test_transcript_rejects_a_non_result(honest_run: SessionTranscript) -> None:
    """Only :class:`VerificationResult` may stand as a verdict."""
    with pytest.raises(TypeError, match="VerificationResult"):
        SessionTranscript(
            params=honest_run.params,
            message_bit=honest_run.message_bit,
            signature=honest_run.signature,
            records=honest_run.records,
            results=("accepted",),  # type: ignore[arg-type]
        )


def test_transcript_repudiation_property_is_the_named_event(
    honest_run: SessionTranscript,
) -> None:
    """``repudiated`` is exactly "Bob accepted, Charlie did not"."""
    charlie = VerificationResult(
        party=Party.CHARLIE,
        accepted=False,
        matched_count=honest_run.charlie.matched_count,
        mismatches=honest_run.charlie.matched_count,
        rate=1.0,
        threshold=honest_run.params.s_v,
        key_length=honest_run.params.key_length,
        message_bit=honest_run.message_bit,
    )
    forced = SessionTranscript(
        params=honest_run.params,
        message_bit=honest_run.message_bit,
        signature=honest_run.signature,
        records=honest_run.records,
        results=(honest_run.bob, charlie),
    )
    assert forced.repudiated is True
    assert forced.transferable is False
    assert forced.summary().splitlines()[-1].startswith("REPUDIATION")


# ==========================================================================
# Seam 1: resource_factory -- the quantum channel
# ==========================================================================


def test_default_resource_is_the_ideal_pair() -> None:
    """An explicit ideal factory reproduces the default exactly."""
    params = _params(24)
    default = _session(params, seed=SEED).run(0)
    explicit = _session(
        params, seed=SEED, resource_factory=ideal_resource
    ).run(0)
    assert explicit == default


def test_resource_factory_is_consulted_once_per_qubit_of_the_whole_run() -> None:
    """``2 message bits * 2 recipients * L`` hops, one fresh pair each."""
    params = _params(16)
    calls = 0

    def counting() -> Statevector:
        nonlocal calls
        calls += 1
        return ideal_resource()

    _session(params, resource_factory=counting).run(0)
    assert calls == len(MESSAGE_BITS) * len(VERIFIERS) * params.key_length


def test_a_broken_channel_is_rejected_by_both_verifiers() -> None:
    """A maximally mixed resource carries nothing, and both verifiers say so.

    This is also the session-level proof that the teleportation is genuinely in
    the data path: an implementation that re-prepared the eigenstates at the
    recipient would accept here, because the resource would never be touched.
    """
    transcript = _session(_params(96), resource_factory=lambda: _werner(1.0)).run(0)
    assert not transcript.bob.accepted
    assert not transcript.charlie.accepted
    assert transcript.bob.rate > transcript.params.s_v
    assert transcript.charlie.rate > transcript.params.s_v
    assert transcript.transferable is False


def test_a_mild_channel_still_verifies() -> None:
    """Below Bob's noise budget an honest run survives; ``s_a`` is a budget.

    A budget is only a budget where it buys more than nothing: at ``L = 96``
    Bob's is ``floor(32 / 64) = 0`` mismatches, so *any* error rejects and the
    property under test does not exist at that size. At ``L = 600`` he can
    absorb three, and a Werner parameter of ``s_a / 4`` -- a matched-position
    error rate a quarter of the budget -- puts the expected count under one. The
    three seeds are checked rather than one because the claim is statistical:
    each run survives with probability about ``1 - 1e-3``.
    """
    params = _params(600)
    for offset in range(11, 14):
        transcript = _session(
            params,
            seed=SEED + offset,
            resource_factory=lambda: _werner(params.s_a / 4.0),
        ).run(0)
        assert transcript.transferable, transcript.summary()
        assert transcript.bob.rate <= params.s_a


def test_the_channel_seam_does_not_disturb_the_chosen_bases() -> None:
    """A clean run and an attacked run are comparable position by position.

    The generator is advanced identically whatever the resource, so the
    recipients' basis choices -- and Alice's keys -- are the same in both, and
    only the outcomes move. Phase 3 needs exactly that to attribute a change to
    its attack.
    """
    params = _params(48)
    clean = _session(params, seed=SEED).run(0)
    attacked = _session(
        params, seed=SEED, resource_factory=lambda: _werner(0.6)
    ).run(0)

    assert attacked.signature == clean.signature
    for noisy, quiet in zip(attacked.records, clean.records, strict=True):
        assert noisy.party is quiet.party
        assert noisy.message_bit == quiet.message_bit
        assert noisy.bases == quiet.bases
    assert attacked.records != clean.records


def test_a_non_callable_resource_factory_is_refused_at_construction() -> None:
    """Fail before a key is teleported, not halfway through one."""
    with pytest.raises(TypeError, match="resource_factory"):
        QDSSession(
            _params(24),
            resource_factory=ideal_resource(),  # type: ignore[arg-type]
        )


# ==========================================================================
# Seam 2: distributor -- Phase A as a whole
# ==========================================================================


def test_the_distributor_seam_is_the_one_that_runs_phase_a() -> None:
    """The default is :func:`distribute_public_key`, and a wrapper sees the call."""
    params = _params(16)
    seen: list[int] = []

    def watching(key: PrivateKey, *args: Any, **kwargs: Any) -> Any:
        seen.append(key.message_bit)
        return distribute_public_key(key, *args, **kwargs)

    transcript = _session(params, distributor=watching).run(1)
    assert seen == list(MESSAGE_BITS)
    assert transcript.transferable


def test_the_distributor_receives_both_verifiers_and_the_channel_seam() -> None:
    """The session passes the parties and the resource factory straight through."""
    params = _params(16)
    factory = ideal_resource
    captured: list[dict[str, Any]] = []

    def watching(
        key: PrivateKey, protocol_params: ProtocolParams, **kwargs: Any
    ) -> Any:
        captured.append(kwargs)
        return distribute_public_key(key, protocol_params, **kwargs)

    _session(params, distributor=watching, resource_factory=factory).run(0)
    assert len(captured) == len(MESSAGE_BITS)
    for kwargs in captured:
        assert tuple(kwargs["parties"]) == VERIFIERS
        assert kwargs["resource_factory"] is factory
        assert isinstance(kwargs["rng"], np.random.Generator)


def test_a_distributor_that_forgets_charlie_is_refused() -> None:
    """Both verifiers are required; a session without Charlie proves nothing."""

    def bob_only(key: PrivateKey, params: ProtocolParams, **kwargs: Any) -> Any:
        records = distribute_public_key(key, params, **kwargs)
        return {Party.BOB: records[Party.BOB]}

    with pytest.raises(ValueError, match="Charlie"):
        _session(_params(16), distributor=bob_only).distribute()


def test_a_distributor_that_swaps_the_parties_is_refused() -> None:
    """A swapped key would score one verifier's evidence against the other cut."""

    def swapped(key: PrivateKey, params: ProtocolParams, **kwargs: Any) -> Any:
        records = distribute_public_key(key, params, **kwargs)
        return {
            Party.BOB: records[Party.CHARLIE],
            Party.CHARLIE: records[Party.BOB],
        }

    with pytest.raises(ValueError, match="tagged"):
        _session(_params(16), distributor=swapped).distribute()


def test_a_distributor_that_returns_the_wrong_message_bit_is_refused() -> None:
    """Crossing the bits would verify against states never sent for them."""

    def always_zero(key: PrivateKey, params: ProtocolParams, **kwargs: Any) -> Any:
        first = PrivateKey.from_dict(
            {"message_bit": 0, "elements": key.to_dict()["elements"]}
        )
        return distribute_public_key(first, params, **kwargs)

    with pytest.raises(ValueError, match="message bit"):
        _session(_params(16), distributor=always_zero).distribute()


def test_a_distributor_returning_a_non_mapping_is_refused() -> None:
    """The shape is checked before the session builds anything on it."""
    with pytest.raises(TypeError, match="mapping"):
        _session(
            _params(16), distributor=lambda *a, **k: [1, 2]
        ).distribute()


def test_a_distributor_returning_a_non_record_is_refused() -> None:
    """A record is required, not merely something party-shaped."""

    def rubbish(key: PrivateKey, params: ProtocolParams, **kwargs: Any) -> Any:
        return {Party.BOB: "log", Party.CHARLIE: "log"}

    with pytest.raises(TypeError, match="RecipientRecord"):
        _session(_params(16), distributor=rubbish).distribute()


def test_a_distributor_returning_a_short_record_is_refused() -> None:
    """One qubit is distributed per key element, so the lengths must agree."""

    def truncated(key: PrivateKey, params: ProtocolParams, **kwargs: Any) -> Any:
        records = distribute_public_key(key, params, **kwargs)
        return {
            party: RecipientRecord(
                party=record.party,
                message_bit=record.message_bit,
                entries=record.entries[:-1],
            )
            for party, record in records.items()
        }

    with pytest.raises(ValueError, match="key_length"):
        _session(_params(16), distributor=truncated).distribute()


def test_a_non_callable_distributor_is_refused_at_construction() -> None:
    """Caught in the constructor, with the message pointing at the seams."""
    with pytest.raises(TypeError, match="distributor"):
        QDSSession(_params(16), distributor="honest")  # type: ignore[arg-type]


# ==========================================================================
# Seam 3: signer -- Phase B
# ==========================================================================


def test_the_default_signer_declares_the_distributed_key() -> None:
    """The honest signer is :func:`honest_signer`, and it declares ``k_b``."""
    session = _session(_params(24))
    session.distribute()
    signature = session.sign(1)
    assert signature.declared_key is session.keys[1]


def test_the_honest_signer_ignores_the_recipients_records() -> None:
    """Alice does not hold Bob's or Charlie's measurement log, and does not use it."""
    params = _params(24)
    session = _session(params)
    session.distribute()
    with_records = honest_signer(
        0, session.keys, params, records=session.records
    )
    without = honest_signer(0, session.keys, params, records={})
    assert with_records == without
    assert with_records.declared_key is session.keys[0]


def test_the_signer_seam_receives_exactly_what_a_repudiating_alice_holds() -> None:
    """The message bit, both keys, the parameters -- and **no** recipient log.

    The default changed here, and this is the test that says so. A repudiating
    Alice holds her own key pair and nothing of Bob's or Charlie's evidence; the
    seam used to be handed both raw logs, which is strictly more than any single
    adversary in the threat model holds and was the root of the whole
    repudiation attack family the Phase 2 audit found. What arrives now is the
    singleton ``NO_RECIPIENT_LOGS``, asserted by *identity* rather than by
    emptiness, because "the session passed this exact object" cannot be
    satisfied by accident.
    """
    params = _params(16)
    captured: dict[str, Any] = {}

    def watching(
        message_bit: int, keys: Any, protocol_params: Any, *, records: Any
    ) -> Signature:
        captured.update(
            message_bit=message_bit,
            keys=keys,
            params=protocol_params,
            records=records,
        )
        return sign(message_bit, keys, protocol_params)

    session = _session(params, signer=watching)
    session.distribute()
    session.sign(1)

    assert captured["message_bit"] == 1
    assert [key.message_bit for key in captured["keys"]] == list(MESSAGE_BITS)
    assert captured["params"] is params
    assert captured["records"] is NO_RECIPIENT_LOGS
    assert len(captured["records"]) == 0
    assert list(captured["records"]) == []
    # And an empty mapping that a defensive signer probes still behaves.
    assert captured["records"].get(1, {}) == {}


def test_a_signer_reaching_for_a_withheld_log_is_told_why_it_is_missing() -> None:
    """``KeyError: 0`` would send a Phase 3 author hunting a harness bug.

    The whole reason the default is a type rather than a bare ``{}``. "The seam
    was deliberately starved" and "the attack is mis-wired" are indistinguishable
    from a bare KeyError, and only one of them is worth debugging.
    """
    session = _session(_params(16), signer=_reading_signer())
    session.distribute()
    with pytest.raises(KeyError, match="signer_sees_recipient_logs=True"):
        session.sign(0)


def test_the_over_powered_signer_is_opt_in_and_the_transcript_says_so() -> None:
    """The old behaviour is still reachable, and never mistakable for the new.

    Phase 3 must be able to run the two-log signer -- it is the attack the
    pooled matched-count floor was built against, and an insecure arm nobody can
    run is an insecure arm nobody can compare against. What it must not be able
    to do is produce a transcript that looks like a secure-arm one, so the flag
    is carried, survives JSON, and is named out loud in the summary.
    """
    captured: dict[str, Any] = {}

    def watching(
        message_bit: int, keys: Any, protocol_params: Any, *, records: Any
    ) -> Signature:
        captured["records"] = records
        return sign(message_bit, keys, protocol_params)

    session = _session(
        _params(24), signer=watching, signer_sees_recipient_logs=True
    )
    transcript = session.run(0)

    assert sorted(captured["records"]) == list(MESSAGE_BITS)
    assert sorted(captured["records"][1]) == sorted(VERIFIERS)
    assert transcript.signer_saw_recipient_logs is True
    assert "OVER-POWERED SIGNER" in transcript.summary()
    assert (
        SessionTranscript.from_json(transcript.to_json()).signer_saw_recipient_logs
        is True
    )
    # The honest arm carries the flag as False, so the two are never confused.
    assert _session(_params(24)).run(0).signer_saw_recipient_logs is False


def test_the_signer_opt_in_changes_nothing_but_what_the_seam_is_shown() -> None:
    """An honest run made with the flag is the honest run, byte for byte.

    The flag must be a *capability*, not a mode: if turning it on moved the
    generator or the records, an insecure-arm measurement and its control would
    differ in two things and neither could be attributed.
    """
    withheld = _session(_params(24), seed=SEED + 21).run(1)
    shown = _session(
        _params(24), seed=SEED + 21, signer_sees_recipient_logs=True
    ).run(1)
    assert shown.records == withheld.records
    assert shown.signature == withheld.signature
    assert dataclasses.replace(
        shown, signer_saw_recipient_logs=False
    ) == withheld


def test_a_non_bool_signer_opt_in_is_refused() -> None:
    """It is a deliberate yes or no, not a value to be inferred."""
    with pytest.raises(TypeError, match="signer_sees_recipient_logs"):
        QDSSession(
            _params(16),
            signer_sees_recipient_logs="yes",  # type: ignore[arg-type]
        )


def test_a_forged_declaration_is_rejected_by_both_verifiers() -> None:
    """Flip every eigenvalue and both verifiers see a rate of exactly 1.0.

    The strongest possible statement the seam can make: nothing downstream of it
    can be talked into accepting, because the matched/unmatched split and the two
    thresholds are computed from the record and the declaration alone.
    """

    def forger(
        message_bit: int, keys: Any, params: Any, *, records: Any
    ) -> Signature:
        return Signature(
            message_bit=message_bit,
            declared_key=_flip_all(keys[message_bit]),
        )

    transcript = _session(_params(48), signer=forger).run(0)
    assert transcript.bob.rate == 1.0
    assert transcript.charlie.rate == 1.0
    assert not transcript.bob.accepted
    assert not transcript.charlie.accepted
    assert transcript.transferable is False
    assert transcript.repudiated is False


def test_a_forger_who_declares_a_wholly_unrelated_key_is_rejected() -> None:
    """A key Alice never distributed lands at chance, which is well above ``s_v``."""

    def outsider(
        message_bit: int, keys: Any, params: Any, *, records: Any
    ) -> Signature:
        stranger = PrivateKey.from_dict(
            {
                "message_bit": message_bit,
                "elements": [
                    {"basis": "Z", "eigenvalue": 1} for _ in range(len(keys[0]))
                ],
            }
        )
        return Signature(message_bit=message_bit, declared_key=stranger)

    transcript = _session(_params(96), seed=SEED + 3, signer=outsider).run(1)
    assert not transcript.bob.accepted
    assert not transcript.charlie.accepted


def test_a_signer_returning_the_other_bit_is_refused() -> None:
    """The bit selects which distribution is scored; the two must agree."""

    def wrong_bit(
        message_bit: int, keys: Any, params: Any, *, records: Any
    ) -> Signature:
        return sign(1 - message_bit, keys, params)

    session = _session(_params(16), signer=wrong_bit)
    session.distribute()
    with pytest.raises(ValueError, match="signer seam was asked"):
        session.sign(0)


def test_a_signer_returning_a_non_signature_is_refused() -> None:
    """Even a forgery is a :class:`Signature`; anything else is a wiring bug."""
    session = _session(_params(16), signer=lambda *a, **k: "signed")
    session.distribute()
    with pytest.raises(TypeError, match="must return a Signature"):
        session.sign(0)


def test_a_signer_returning_a_foreign_length_key_is_refused() -> None:
    """A declaration of the wrong length cannot be scored against the records."""

    def short(
        message_bit: int, keys: Any, params: Any, *, records: Any
    ) -> Signature:
        trimmed = PrivateKey.from_dict(
            {
                "message_bit": message_bit,
                "elements": keys[message_bit].to_dict()["elements"][:-1],
            }
        )
        return Signature(message_bit=message_bit, declared_key=trimmed)

    session = _session(_params(16), signer=short)
    session.distribute()
    with pytest.raises(ValueError, match="key_length"):
        session.sign(0)


def test_a_non_callable_signer_is_refused_at_construction() -> None:
    """Caught before a single qubit is teleported."""
    with pytest.raises(TypeError, match="signer"):
        QDSSession(_params(16), signer=object())  # type: ignore[arg-type]


# ==========================================================================
# Phase order, single use, and refusals
# ==========================================================================


def test_signing_before_distributing_is_refused() -> None:
    """There is nothing to sign against before Phase A."""
    with pytest.raises(ValueError, match="session.distribute"):
        _session().sign(0)


def test_verifying_before_signing_is_refused() -> None:
    """No declaration, no verdict."""
    session = _session()
    session.distribute()
    with pytest.raises(ValueError, match="session.sign"):
        session.verify(Party.BOB)


def test_transferring_before_bob_verifies_is_refused() -> None:
    """Bob cannot forward what he has not looked at."""
    session = _session()
    session.distribute()
    session.sign(0)
    with pytest.raises(ValueError, match="verify"):
        session.transfer()


def test_a_transcript_before_signing_is_refused() -> None:
    """A run with nothing to verify is not a run."""
    session = _session()
    session.distribute()
    with pytest.raises(ValueError, match="session.sign"):
        session.transcript()


def test_distributing_twice_is_refused() -> None:
    """A session is single-use: the public key states are consumed on receipt."""
    session = _session()
    session.distribute()
    with pytest.raises(ValueError, match="already distributed"):
        session.distribute()


def test_signing_twice_is_refused() -> None:
    """One distribution supports one signature; the other bit needs a new run."""
    session = _session()
    session.distribute()
    session.sign(0)
    with pytest.raises(ValueError, match="already signed"):
        session.sign(1)


def test_running_a_used_session_again_is_refused() -> None:
    """``run`` is subject to the same single-use rule as its parts."""
    session = _session()
    session.run(0)
    with pytest.raises(ValueError, match="already distributed"):
        session.run(1)


def test_alice_cannot_verify() -> None:
    """The signer holds no record and has no threshold."""
    session = _session()
    session.distribute()
    session.sign(0)
    with pytest.raises(ValueError, match="Alice cannot verify"):
        session.verify(Party.ALICE)


def test_an_unknown_party_is_refused() -> None:
    """A typo must not silently pick a verifier."""
    session = _session()
    session.distribute()
    session.sign(0)
    with pytest.raises(ValueError):
        session.verify("Mallory")


def test_an_invalid_message_bit_is_refused() -> None:
    """Only ``0`` and ``1`` exist; there is no key for anything else."""
    session = _session()
    session.distribute()
    with pytest.raises(ValueError):
        session.sign(2)


def test_non_params_is_refused() -> None:
    """The parameter set carries both thresholds; a stand-in has neither."""
    with pytest.raises(TypeError, match="ProtocolParams"):
        QDSSession({"key_length": 24})  # type: ignore[arg-type]


def test_accessors_refuse_before_their_phase_has_run() -> None:
    """Every premature read names the call that would satisfy it."""
    session = _session()
    with pytest.raises(ValueError, match="session.distribute"):
        session.keys
    with pytest.raises(ValueError, match="session.distribute"):
        session.records
    with pytest.raises(ValueError, match="session.sign"):
        session.signature


# ==========================================================================
# Session state and hygiene
# ==========================================================================


def test_session_state_flags_track_the_phases() -> None:
    """``is_distributed``, ``is_signed`` and ``is_complete``, in order."""
    session = _session()
    assert (session.is_distributed, session.is_signed, session.is_complete) == (
        False,
        False,
        False,
    )
    session.distribute()
    assert session.is_distributed and not session.is_signed
    session.sign(0)
    assert session.is_signed and not session.is_complete
    session.verify(Party.BOB)
    assert not session.is_complete
    session.transfer()
    assert session.is_complete


def test_verifying_twice_refuses_instead_of_reaching_a_second_verdict() -> None:
    """One distribution round yields one verdict per verifier.

    This test used to assert the opposite -- that verification was pure and a
    second call recomputed the same decision -- and that purity was precisely
    the replay hole: a captured declaration re-presented after the run collected
    a fresh acceptance every time it was offered, 3/3 at ``DEMO_PARAMS``. The
    verifier now keeps a ``ConsumedRecords`` of the rounds he has decided, so
    the second ask is refused as the replay it is.

    The verdict is not lost and not changed: it is still in ``results``, still
    the only outcome recorded for that party, and the refusal is *not* filed as
    an abort, because the run did reach a verdict.
    """
    session = _session()
    session.run(0)
    first = session.results[Party.BOB]

    with pytest.raises(MatchedSetTooSmall) as excinfo:
        session.verify(Party.BOB)

    assert excinfo.value.abort.reason is AbortReason.RECORD_ALREADY_VERIFIED
    assert excinfo.value.abort.party is Party.BOB
    assert not excinfo.value.abort.is_pooled
    assert excinfo.value.abort.shortfall == 0
    assert session.results[Party.BOB] == first
    assert len(session.transcript().results) == len(VERIFIERS)


def test_a_verifier_who_refused_can_still_be_asked_again() -> None:
    """A refusal spends nothing, so the ledger cannot be burnt by an abort.

    Charlie aborts on the unforwarded declaration and is then asked again on the
    forwarded one -- which is exactly what ``transfer`` does after an abort, and
    what would be impossible if the ledger were written on every call rather
    than only on a verdict.
    """
    session = _session()
    params = session.params
    session.distribute()
    session.sign(0)
    record = session.records[0][Party.CHARLIE]
    ledger = session.ledger_for(Party.CHARLIE)

    # A declaration in the same round whose bases avoid the log entirely, so
    # Charlie has nothing to score and refuses.
    avoided = tuple(
        KeyElement(
            next(b for b in params.bases if b != entry.basis),
            1,
        )
        for entry in record
    )
    starved = Signature(
        0,
        PrivateKey(0, avoided),
        session_opening=session.opening_for(0),
    )
    refusal = verify_or_abort(starved, record, params, ledger=ledger)
    assert isinstance(refusal, VerificationAbort)
    assert refusal.reason is AbortReason.EMPTY_MATCHED_SET
    assert len(ledger) == 0

    session.verify(Party.BOB)
    assert session.transfer().accepted
    assert len(ledger) == 1


def test_the_records_accessor_hands_out_a_copy() -> None:
    """A caller cannot reach in and edit the evidence a verdict rested on."""
    session = _session()
    session.distribute()
    borrowed = session.records
    borrowed[0].pop(Party.CHARLIE)
    assert Party.CHARLIE in session.records[0]


def test_the_session_retains_no_quantum_state() -> None:
    """After Phase A the session's memory is tables of integers, nothing more.

    The design rationale of the whole scheme -- recipients measure on receipt and
    keep a classical log -- so it is asserted on the object, not argued.
    """
    session = _session()
    session.run(0)
    for name, value in vars(session).items():
        assert not isinstance(value, (Statevector, DensityMatrix)), name
    blob = json.dumps(session.transcript().to_dict())
    assert "Statevector" not in blob and "DensityMatrix" not in blob


def test_the_default_parameter_set_is_the_demo_one() -> None:
    """Cheap by default, and documented as carrying no security claim."""
    assert QDSSession(rng=np.random.default_rng(SEED)).params is DEMO_PARAMS


def test_repr_names_the_phase_reached() -> None:
    """Debugging aid: the repr says where in the protocol the session is."""
    session = _session()
    assert "new" in repr(session)
    session.distribute()
    assert "distributed" in repr(session)
    session.sign(1)
    assert "signed bit 1" in repr(session)
    session.verify(Party.BOB)
    assert "verified by B" in repr(session)


def test_run_is_the_four_phases_in_order() -> None:
    """``run`` and the hand-rolled sequence produce the same transcript."""
    params = _params(24)
    by_hand = _session(params, seed=SEED)
    by_hand.distribute()
    by_hand.sign(1)
    by_hand.verify(Party.BOB)
    by_hand.transfer()

    assert by_hand.transcript() == _session(params, seed=SEED).run(1)


# ==========================================================================
# The seams added after the Phase 2 audit: symmetriser, forwarder, run_id
# ==========================================================================


def test_the_session_symmetrises_by_default_and_flags_the_records() -> None:
    """Phase A' runs without being asked, and the transcript says it did.

    The step is the recipients', not Alice's, so it lives in the session rather
    than behind the ``distributor`` seam: an adversary standing in Alice's place
    cannot skip it, because he does not run it. The records the verifiers are
    scored on carry the flag; the raw ones do not.
    """
    session = _session(_params(24))
    session.distribute()

    for bit in MESSAGE_BITS:
        for party in VERIFIERS:
            assert session.records[bit][party].symmetrised
            assert not session.raw_records[bit][party].symmetrised
    assert session.sign(0) is not None
    session.verify(Party.BOB)
    session.transfer()
    assert session.transcript().symmetrised


def test_a_malicious_distributor_cannot_skip_the_exchange() -> None:
    """Records returned by the distributor seam are symmetrised anyway."""

    def raw_distributor(key: Any, params: Any, **kwargs: Any) -> Any:
        # A distributor that hands back unsymmetrised logs -- which is all any
        # distributor can do, since the exchange happens afterwards.
        return distribute_public_key(key, params, **kwargs)

    session = _session(_params(24), distributor=raw_distributor)
    session.distribute()
    assert all(
        session.records[bit][party].symmetrised
        for bit in MESSAGE_BITS
        for party in VERIFIERS
    )


def test_the_symmetriser_seam_can_be_replaced_and_the_transcript_says_so() -> None:
    """``no_symmetrisation`` runs the insecure variant, loudly.

    Two independent signals, because a Phase 3 result computed from the insecure
    arm must never be mistaken for one from the secure arm: the transcript's
    ``symmetrised`` property is ``False``, and ``summary()`` names it.
    """
    transcript = _session(_params(24), symmetriser=no_symmetrisation).run(0)
    assert not transcript.symmetrised
    assert "UNSYMMETRISED" in transcript.summary()
    # ... and it consumes no randomness, so the two arms are otherwise identical.
    secure = _session(_params(24)).run(0)
    assert secure.signature == transcript.signature


def test_the_over_powered_signer_is_shown_the_raw_records() -> None:
    """When the opt-in is set, the logs shown are the pre-exchange ones.

    Which half of the evidence matters, and the choice is the same in both
    directions. It is what a two-log attack needs -- after the exchange, half of
    Charlie's evidence *is* Bob's raw record -- and it is what a repudiating
    Alice must never have, since the exchange is private to the recipients and
    its outcome is the only randomness the non-repudiation bound uses. So even
    the over-powered variant stops at the raw logs, and this pins that.
    """
    captured: dict[str, Any] = {}

    def watching(
        message_bit: int, keys: Any, protocol_params: Any, *, records: Any
    ) -> Any:
        captured["records"] = records
        return honest_signer(
            message_bit, keys, protocol_params, records=records
        )

    session = _session(
        _params(48), signer=watching, signer_sees_recipient_logs=True
    )
    session.distribute()
    session.sign(0)

    for bit in MESSAGE_BITS:
        for party in VERIFIERS:
            assert captured["records"][bit][party] is session.raw_records[bit][party]
            assert not captured["records"][bit][party].symmetrised
    # And never the post-exchange ones the verifiers are actually scored on.
    assert all(
        record.symmetrised for record in session.records[0].values()
    )


def test_the_forwarder_seam_alters_only_what_charlie_scores() -> None:
    """An attack on the Bob-to-Charlie hop, and a transcript that records it.

    Before this seam existed the attack could only be mounted by calling
    module-level ``verify`` directly, and the resulting transcript was lossy: it
    held the declaration Bob saw and silently attributed Charlie's verdict to
    it. Now both declarations are carried and ``signature_for`` reads the right
    one, so a Phase 4 statistic cannot read an attacked run as a clean one.
    """

    def tamper(signature: Signature, protocol_params: Any) -> Signature:
        elements = list(signature.declared_key.elements)
        elements[0] = KeyElement(elements[0].basis, -elements[0].eigenvalue)
        return Signature(
            signature.message_bit,
            PrivateKey(signature.message_bit, tuple(elements)),
        )

    transcript = _session(_params(120), forwarder=tamper).run(0)

    assert transcript.forwarding_altered_signature
    assert transcript.forwarded_signature is not None
    assert transcript.signature_for(Party.BOB) is transcript.signature
    assert transcript.signature_for(Party.CHARLIE) is transcript.forwarded_signature
    assert transcript.signature != transcript.forwarded_signature
    assert "FORWARDING ALTERED" in transcript.summary()
    # Bob scored the honest declaration and still accepts at rate 0.
    assert transcript.bob.rate == 0.0
    # And the tampered declaration survives a JSON round trip.
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


def test_the_honest_forwarder_leaves_no_trace_in_the_transcript() -> None:
    """An unaltered hop must not make honest transcripts differ from each other."""
    plain = _session(_params(24)).run(0)
    explicit = _session(_params(24), forwarder=honest_forwarder).run(0)
    assert plain == explicit
    assert plain.forwarded_signature is None
    assert not plain.forwarding_altered_signature
    assert plain.signature_for(Party.CHARLIE) is plain.signature


def test_a_forwarder_returning_the_wrong_type_is_refused() -> None:
    """Charlie scores a declaration; an attack alters it, it does not remove it."""
    session = _session(_params(16), forwarder=lambda *a, **k: "forwarded")
    session.distribute()
    session.sign(0)
    session.verify(Party.BOB)
    with pytest.raises(TypeError, match="must return a Signature"):
        session.transfer()


def test_run_id_is_carried_verbatim_and_distinguishes_identical_runs() -> None:
    """The ledger key Phase 3's replay experiment needs.

    Two runs made with the same seed are byte-identical by design, so a content
    hash cannot tell a replay from a legitimate repeat. ``run_id`` is
    caller-supplied rather than generated, because a random one would break the
    reproducibility Phase 5 rests on and a seed-derived one would repeat exactly
    when a replay does.
    """
    first = QDSSession(
        _params(24), run_id="alpha", rng=np.random.default_rng(SEED)
    ).run(0)
    second = QDSSession(
        _params(24), run_id="beta", rng=np.random.default_rng(SEED)
    ).run(0)

    assert first.run_id == "alpha"
    assert first != second
    assert first.signature == second.signature  # same seed, same everything else
    assert SessionTranscript.from_json(first.to_json()).run_id == "alpha"
    # Absent by default: nothing is invented.
    assert _session(_params(24)).run(0).run_id is None


def test_a_non_string_run_id_is_refused() -> None:
    """It is a ledger key carried verbatim, not a number to be formatted."""
    with pytest.raises(TypeError, match="run_id must be a string"):
        QDSSession(_params(16), run_id=7)  # type: ignore[arg-type]


def test_transcript_refuses_a_verdict_carrying_the_other_party_s_threshold() -> None:
    """The persistence boundary, guarded.

    ``VerificationResult`` enforces only ``accepted == (rate <= threshold)``, so
    a verdict holding the wrong party's cut is internally consistent and used to
    reconstruct without complaint -- reporting ``transferable=True`` for a run
    the verifier rejected. The transcript now re-derives the threshold from
    ``params`` and the party.
    """
    honest = _session(_params(24)).run(0)
    blob = json.loads(honest.to_json())
    blob["results"][0]["threshold"] = honest.params.s_v
    with pytest.raises(ValueError, match="carries threshold"):
        SessionTranscript.from_json(json.dumps(blob))

    blob = json.loads(honest.to_json())
    blob["results"][0]["key_length"] = honest.params.key_length + 3
    with pytest.raises(ValueError, match="reports key_length"):
        SessionTranscript.from_json(json.dumps(blob))


# ==========================================================================
# The two streams: an Alice-side seam must not be able to read the coins
# ==========================================================================
#
# The symmetrisation coins are the only randomness the non-repudiation bound
# uses, and the bound assumes they are private to Bob and Charlie. The session
# used to hand the ``distributor`` seam the very generator it then drew them
# from, so a distributor that cloned ``rng.bit_generator.state`` held every coin
# before they were tossed, and a signer sharing the clone declared, per
# position, the eigenvalue the coin was about to hand Bob. At DEFAULT_PARAMS
# that was a recorded repudiation, 5 runs out of 5, with m_B = m_C = 37095 and
# M = 74190 -- every floor met -- on a transcript printing
# P(repudiation | this run) <= 1.414e-09.
#
# Nothing there was wrong with the mathematics; it was the harness handing an
# Alice-side seam an object it should never have seen, and every attack number
# this repository publishes comes out of this harness. The tests below pin the
# boundary rather than the convention: each one fails against the pre-fix
# session and passes against this one.


def _aimed_records(
    params: ProtocolParams, message_bit: int, positions: int
) -> dict[Party, RecipientRecord]:
    """Return a raw pair aimed at ``positions`` and distinct at every index.

    Over the first ``positions`` indices both recipients log the first basis
    with opposite eigenvalues, so a declaration in that basis is matched by both
    of them and the coin decides which eigenvalue each ends up holding. Over the
    rest they log two *different* other bases, so those positions are matched by
    neither and the matched count is exactly ``positions`` at each verifier. No
    two entries at the same index are ever equal, which is what makes the coin
    that moved them recoverable afterwards with no coincidences to resolve.
    """
    names = [basis.value for basis in params.bases]
    tail = params.key_length - positions
    return {
        Party.BOB: RecipientRecord.from_measurements(
            "Bob",
            message_bit,
            [names[0]] * positions + [names[1]] * tail,
            [1] * params.key_length,
        ),
        Party.CHARLIE: RecipientRecord.from_measurements(
            "Charlie",
            message_bit,
            [names[0]] * positions + [names[2]] * tail,
            [-1] * positions + [1] * tail,
        ),
    }


def _coins_applied(
    raw: dict[Party, RecipientRecord], exchanged: dict[Party, RecipientRecord]
) -> np.ndarray:
    """Recover the coins Phase A' actually tossed, from before and after.

    A position was swapped exactly when the entry Bob ends up holding is the one
    Charlie logged, which is unambiguous for a pair built by
    :func:`_aimed_records`.
    """
    return np.array(
        [
            exchanged[Party.BOB].entries[index]
            == raw[Party.CHARLIE].entries[index]
            for index in range(len(raw[Party.BOB]))
        ],
        dtype=bool,
    )


class _CoinReadingAlice:
    """The attack: a ``distributor``/``signer`` pair that tries to read the coins.

    The distributor clones the state of the generator it is handed and draws
    ``L`` coins from the clone exactly as
    :func:`~sih141.protocol.symmetrise.symmetrise_records` would; the signer
    declares, at every aimed position, the eigenvalue those coins say Bob is
    about to hold, and the honest eigenvalue everywhere else. Against a session
    that draws the coins from the generator it hands this seam, that is a
    repudiation with every floor met -- which is why ``predicted`` is kept where
    a test can compare it against the truth, and overwrite it with the truth.
    """

    def __init__(self, positions: int) -> None:
        self.positions = positions
        self.predicted: dict[int, np.ndarray] = {}
        self.raw: dict[int, dict[Party, RecipientRecord]] = {}
        self.handed: list[np.random.Generator] = []
        self.states: dict[int, dict[str, Any]] = {}

    def distributor(
        self,
        key: PrivateKey,
        params: ProtocolParams,
        *,
        parties: Any = VERIFIERS,
        resource_factory: Any = None,
        rng: np.random.Generator | None = None,
    ) -> dict[Party, RecipientRecord]:
        """Return aimed logs, having first stolen the generator's state."""
        del parties, resource_factory
        assert rng is not None
        clone = np.random.Generator(type(rng.bit_generator)())
        clone.bit_generator.state = rng.bit_generator.state
        bit = key.message_bit
        self.handed.append(rng)
        self.states[bit] = dict(rng.bit_generator.state)
        self.predicted[bit] = clone.integers(
            0, 2, size=params.key_length
        ).astype(bool)
        self.raw[bit] = _aimed_records(params, bit, self.positions)
        return self.raw[bit]

    def signer(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: Any,
    ) -> Signature:
        """Declare the eigenvalue the stolen coins say Bob will hold."""
        del keys, records
        names = [basis.value for basis in params.bases]
        coins = self.predicted[message_bit]
        elements = tuple(
            KeyElement(names[0], -1 if coins[index] else 1)
            if index < self.positions
            else KeyElement(names[0], 1)
            for index in range(params.key_length)
        )
        return sign(message_bit, PrivateKey(message_bit, elements), params)


def test_a_distributor_that_snapshots_the_generator_cannot_predict_the_coins() -> None:
    """The regression test for the leak. Fails against the pre-fix session.

    The distributor is handed a generator because it stands where the channel
    is. It clones the state of that generator, draws ``L`` coins from the clone
    the way Phase A' does, and the test compares them against the coins Phase A'
    really tossed -- recovered from the records themselves, before and after.
    Pre-fix they agreed at every one of the ``L`` positions, because they *were*
    the same draw from the same object. They must now agree only where two
    independent fair coins happen to.
    """
    params = _params(96)
    alice = _CoinReadingAlice(positions=48)
    records = QDSSession(
        params, rng=np.random.default_rng(SEED), distributor=alice.distributor
    ).distribute()

    for bit in MESSAGE_BITS:
        actual = _coins_applied(alice.raw[bit], records[bit])
        predicted = alice.predicted[bit]
        assert len(predicted) == params.key_length
        assert not np.array_equal(predicted, actual)
        agreement = float(np.mean(predicted == actual))
        assert 0.25 < agreement < 0.75, agreement


def test_a_coin_reading_alice_cannot_repudiate() -> None:
    """The consequence, end to end: no floor and no verdict pair is disturbed.

    The attack clears every matched-count floor by construction -- ``m_B = m_C =
    positions``, and the pooled total twice that -- so nothing but the privacy
    of the coins stands between it and a repudiation. Pre-fix it repudiated on
    every seed; it must now fail the way a guess does, at Bob, whose rate lands
    near ``1/2`` instead of at ``0``.
    """
    params = _params(120)
    positions = 40

    for offset in range(4):
        alice = _CoinReadingAlice(positions=positions)
        transcript = QDSSession(
            params,
            rng=np.random.default_rng(SEED + offset),
            distributor=alice.distributor,
            signer=alice.signer,
        ).run(0)

        assert transcript.pooled is not None
        assert transcript.pooled.meets_every_floor  # no floor is doing the work
        assert transcript.bob is not None and transcript.charlie is not None
        assert transcript.bob.matched_count == positions
        assert transcript.charlie.matched_count == positions
        assert not transcript.repudiated
        assert not transcript.bob.accepted
        assert transcript.bob.rate > params.s_a


def test_the_same_attack_repudiates_when_it_is_handed_the_real_coins() -> None:
    """The control: the attack is sound, and only the coins were missing.

    The identical declaration, built from the coins the session actually tossed
    -- which this test reconstructs from the records, and which no seam can
    obtain -- repudiates outright: Bob accepts at rate ``0``, Charlie rejects at
    rate ``1``, every floor met. That is what makes the test above a statement
    about the leak rather than about a badly aimed attack.
    """
    params = _params(120)
    positions = 40
    alice = _CoinReadingAlice(positions=positions)
    session = QDSSession(
        params,
        rng=np.random.default_rng(SEED),
        distributor=alice.distributor,
        signer=alice.signer,
    )
    records = session.distribute()
    for bit in MESSAGE_BITS:
        alice.predicted[bit] = _coins_applied(alice.raw[bit], records[bit])

    session.sign(0)
    session.exchange_counts()
    session.verify(Party.BOB)
    session.transfer()
    transcript = session.transcript()

    assert transcript.pooled is not None and transcript.pooled.meets_every_floor
    assert transcript.bob is not None and transcript.charlie is not None
    assert transcript.repudiated
    assert transcript.bob.rate == 0.0
    assert transcript.charlie.rate == 1.0


def test_a_distributor_that_rebuilds_the_seed_sequence_cannot_predict_the_coins() -> None:
    """Why the split is a digest and not a spawn.

    ``numpy``'s spawning leaves the parent's entropy in every child's
    ``seed_seq`` in clear, so a seam handed a spawned child could rebuild the
    sequence and spawn the sibling it was not given -- the same leak with one
    more step in it. The stream a seam is handed here is seeded with a SHA-256
    digest of the material instead, so the sequence it can read is a preimage
    problem away from anything the recipients hold.
    """
    params = _params(64)
    alice = _CoinReadingAlice(positions=32)
    records = QDSSession(
        params, rng=np.random.default_rng(SEED), distributor=alice.distributor
    ).distribute()
    actual = _coins_applied(alice.raw[0], records[0])

    sequence = alice.handed[0].bit_generator.seed_seq
    rebuilt = np.random.SeedSequence(
        entropy=sequence.entropy, spawn_key=sequence.spawn_key
    )
    candidates = [np.random.default_rng(rebuilt)]
    candidates += [np.random.default_rng(child) for child in rebuilt.spawn(4)]
    candidates += [
        _derive_stream(
            np.random.default_rng(rebuilt).bytes(_STREAM_MATERIAL_BYTES),
            _RECIPIENT_STREAM_LABEL,
        )
    ]
    for candidate in candidates:
        guess = candidate.integers(0, 2, size=params.key_length).astype(bool)
        assert not np.array_equal(guess, actual)


def test_a_distributor_that_rewinds_the_generator_cannot_predict_the_coins() -> None:
    """Why the caller's own generator is dropped rather than shared.

    PCG64's transition is invertible -- ``advance(-n)`` walks a stream backwards
    exactly -- so a seam handed the caller's generator could rewind the four
    words the session's material was drawn from and derive both streams for
    itself. It is handed a *derived* stream instead, whose earlier states are
    its own: neither reading coins off a rewound state nor re-deriving a
    recipient stream from one predicts anything.
    """
    params = _params(48)
    alice = _CoinReadingAlice(positions=24)
    records = QDSSession(
        params, rng=np.random.default_rng(SEED), distributor=alice.distributor
    ).distribute()
    actual = _coins_applied(alice.raw[0], records[0])
    entry = alice.states[0]

    def _rewound(depth: int) -> np.random.Generator:
        """Return the handed stream, wound back ``depth`` raw words."""
        clone = np.random.Generator(type(alice.handed[0].bit_generator)())
        clone.bit_generator.state = entry
        clone.bit_generator.advance(-depth)
        return clone

    for depth in range(0, 264, 4):
        direct = _rewound(depth).integers(0, 2, size=params.key_length)
        assert not np.array_equal(direct.astype(bool), actual)
        derived = _derive_stream(
            _rewound(depth).bytes(_STREAM_MATERIAL_BYTES),
            _RECIPIENT_STREAM_LABEL,
        )
        guess = derived.integers(0, 2, size=params.key_length).astype(bool)
        assert not np.array_equal(guess, actual)


def test_the_seams_and_the_coins_hold_different_generators() -> None:
    """Identity, not merely different numbers.

    The object the ``distributor`` is handed is not the object the
    ``symmetriser`` is handed, and the two are seeded from different digests of
    one material -- so neither seam's ``bit_generator.state`` nor its
    ``seed_seq`` is a fact about the other's stream.
    """
    params = _params(16)
    to_alice: list[np.random.Generator] = []
    to_recipients: list[np.random.Generator] = []

    def watching_distributor(
        key: PrivateKey, protocol_params: ProtocolParams, **kwargs: Any
    ) -> Any:
        to_alice.append(kwargs["rng"])
        return distribute_public_key(key, protocol_params, **kwargs)

    def watching_symmetriser(records: Any, *, rng: Any = None) -> Any:
        to_recipients.append(rng)
        return symmetrise_records(records, rng=rng)

    QDSSession(
        params,
        rng=np.random.default_rng(SEED),
        distributor=watching_distributor,
        symmetriser=watching_symmetriser,
    ).run(0)

    alice_stream, recipient_stream = to_alice[0], to_recipients[0]
    assert alice_stream is not recipient_stream
    assert (
        alice_stream.bit_generator.state
        != recipient_stream.bit_generator.state
    )
    assert (
        alice_stream.bit_generator.seed_seq.entropy
        != recipient_stream.bit_generator.seed_seq.entropy
    )


def test_no_public_accessor_hands_out_a_generator() -> None:
    """The recipients' stream is not on the session's public surface.

    A guard against the leak coming back through the front door: an accessor
    that returned the session's randomness would put the coins one attribute
    lookup away from anything holding the session.
    """
    session = _session(_params(16))
    session.distribute()

    exposed = []
    for name in dir(session):
        if name.startswith("_"):
            continue
        try:
            value = getattr(session, name)
        except ValueError:
            continue  # an accessor whose phase has not run; not a generator
        if isinstance(value, np.random.Generator):
            exposed.append(name)
    assert not exposed, f"generators reachable from the session: {exposed}"


def test_the_stream_derivation_is_pinned() -> None:
    """The two labels and the digest are part of every seeded run's identity.

    Changing a label, the hash or the material width re-seeds both streams and
    silently changes every seeded transcript in the project. That is allowed --
    but not by accident, and not without this line moving with it.
    """
    assert _STREAM_MATERIAL_BYTES == 32
    material = bytes(range(_STREAM_MATERIAL_BYTES))
    alice = _derive_stream(material, _ALICE_STREAM_LABEL)
    recipients = _derive_stream(material, _RECIPIENT_STREAM_LABEL)
    assert alice.bit_generator.seed_seq.entropy == int(
        "1abc2ba0a8ae1f5bbaab036e3c601bba32a405664632a8dc758f2c5070c9d666", 16
    )
    assert recipients.bit_generator.seed_seq.entropy == int(
        "9591cb2e13d60046355cb65eb48a5c2e9628c3e4e9db4697da8591d805b88f3c", 16
    )


# ==========================================================================
# Seam: payload_map -- the state Alice actually sends
# ==========================================================================
#
# The channel seam owns the pair; this one owns the qubit. Before it existed,
# an attack on what Alice prepares had to be mounted from ``distributor``, i.e.
# by reimplementing the distribution loop -- basis draw, teleportation,
# measurement, variate budget, check-round branch -- inside the attack, where
# it would drift the first time distribute.py changed and where its bugs would
# never be exercised by an honest run.


def _orthogonal(state: Statevector) -> Statevector:
    """Return the state orthogonal to a one-qubit pure state.

    ``|psi> = (a, b)`` maps to ``(-conj(b), conj(a))``, whose overlap with the
    original is ``-b a + a b = 0`` for every ``a, b``. Substituting it is the
    maximally wrong preparation: on a matched position the recipient measures
    the observable Alice declared and gets the *opposite* eigenvalue with
    certainty, so the mismatch rate is exactly ``1.0`` rather than merely high.
    """
    a, b = state.data
    return Statevector(np.array([-np.conj(b), np.conj(a)]))


def test_the_payload_seam_is_the_state_alice_actually_sends() -> None:
    """Send every eigenstate's orthogonal partner: both rates are exactly 1.0.

    Exactly, not approximately, which is what makes this a test of the data path
    rather than of a statistic: teleportation over a clean pair is exact, so a
    matched position reproduces whatever was *sent*. If the seam were being
    ignored -- or applied to a copy, or applied after the hop -- the rate would
    be 0.0.
    """
    transcript = _session(
        _params(48), payload_map=lambda state, context: _orthogonal(state)
    ).run(0)
    assert transcript.bob.rate == 1.0
    assert transcript.charlie.rate == 1.0
    assert not transcript.bob.accepted
    assert not transcript.charlie.accepted


def test_the_payload_seam_can_target_one_recipients_link() -> None:
    """The context names the hop, so a one-sided preparation attack is one line.

    And the run says something the seam's author would not guess: aiming the
    attack at *Charlie's* link raises **Bob's** rate too, because Phase A' then
    re-assigns half of the corrupted entries to Bob. A one-sided attack on the
    channel is not a one-sided attack on the evidence, which is worth knowing
    before a Phase 4 detector is built on the assumption that it is.

    The unsymmetrised arm is where the aim is visible, and it is exact: Bob's
    rate is ``0.0`` and Charlie's is ``1.0``, on the same seed.
    """

    def only_charlie(state: Statevector, context: ResourceContext) -> Any:
        if context.party is Party.CHARLIE:
            return _orthogonal(state)
        return identity_payload(state, context)

    aimed = _session(
        _params(48), payload_map=only_charlie, symmetriser=no_symmetrisation
    ).run(0)
    assert aimed.bob.rate == 0.0
    assert aimed.bob.accepted
    assert aimed.charlie.rate == 1.0
    assert not aimed.charlie.accepted
    # Bob accepted a declaration Charlie rejected, on one key that both of them
    # scored: a repudiation event by the transcript's definition, on a run whose
    # recipients did not symmetrise and which therefore carries no claim at all.
    assert aimed.repudiated
    assert not aimed.symmetrised

    # With the exchange in place the same attack reaches both verifiers.
    spread = _session(_params(600), seed=SEED + 34, payload_map=only_charlie).run(0)
    assert spread.bob.rate > spread.params.s_v
    assert spread.charlie.rate > spread.params.s_v
    assert not spread.transferable


def test_a_mixed_payload_passes_through_the_seam() -> None:
    """``teleport`` takes a DensityMatrix, so a noisy preparation is expressible.

    A maximally mixed payload carries nothing at all, so every matched position
    is a fair coin and both verifiers reject. The claim under test is not the
    rate -- it is that a mixed state survives the seam instead of raising, which
    is what makes "Alice's source is imperfect" a one-line attack rather than a
    reimplementation of the loop.
    """
    noise = DensityMatrix(np.eye(2) / 2.0)
    transcript = _session(
        _params(600), seed=SEED + 31, payload_map=lambda state, context: noise
    ).run(0)
    assert transcript.bob.rate > transcript.params.s_v
    assert transcript.charlie.rate > transcript.params.s_v
    assert not transcript.transferable


def test_the_default_payload_line_sends_the_eigenstate_unaltered() -> None:
    """An explicit identity map reproduces the default run exactly."""
    default = _session(_params(24), seed=SEED + 32).run(0)
    explicit = _session(
        _params(24), seed=SEED + 32, payload_map=identity_payload
    ).run(0)
    assert explicit == default


def test_the_payload_seam_sees_every_position_and_locates_no_check_round() -> None:
    """The seam is offered every position, so its call sequence says nothing.

    It used to be offered key rounds only, which made the *gaps* in its call
    sequence the check set exactly -- recovered whole, in one pass, by a seam
    that did nothing but append to a list. What it returns on a check round is
    still discarded, so a payload attack still cannot move the QBER or the CHSH
    estimate; what it moves is the verification rate, as before. The difference
    is that it can no longer tell which rounds those are.
    """
    seen: list[tuple[Party, int, int]] = []

    def watching(state: Statevector, context: ResourceContext) -> Any:
        seen.append((context.party, context.message_bit, context.position))
        return state

    params = _checked()
    session = _session(params, seed=SEED + 33, payload_map=watching)
    session.run(0)

    for bit in MESSAGE_BITS:
        plan = session.check_plans[bit]
        assert set(plan.positions), "there must be something to hide"
        for party in VERIFIERS:
            touched = {
                position
                for seen_party, seen_bit, position in seen
                if seen_party is party and seen_bit == bit
            }
            assert touched == set(range(params.key_length))
            assert touched > set(plan.positions)
    assert len(seen) == len(MESSAGE_BITS) * len(VERIFIERS) * params.key_length


def test_a_non_callable_payload_map_is_refused_at_construction() -> None:
    """Fail before a key is teleported, as every other seam does."""
    with pytest.raises(TypeError, match="payload_map"):
        QDSSession(_params(24), payload_map=Statevector([1, 0]))  # type: ignore[arg-type]


def test_a_payload_map_returning_none_is_refused_by_name() -> None:
    """``None`` reaching ``teleport`` would be a confusing coercion failure."""
    session = _session(_params(16), payload_map=lambda state, context: None)
    with pytest.raises(ValueError, match="payload_map returned None"):
        session.distribute()


# ==========================================================================
# The forwarder, widened: the faithful recipient-forgery route
# ==========================================================================
#
# session.py used to send a Phase 3 author to mount a forging Bob on the SIGNER
# seam. That models the wrong adversary: the signer's declaration goes to both
# verifiers, so Bob is handed his own forgery and rejects it, both matched
# counts inflate to 2L/3, and a successful forgery is recorded as a
# non-transferable, non-repudiated run. The two tests below are the correction
# and the evidence for it, run on the same seed so the contrast is not a
# sampling artefact.


def _forging_bob(
    signature: Signature, params: Any, *, view: RecipientView
) -> Signature:
    """Declare Bob's own raw log to Charlie. The compliant recipient forgery.

    Takes a **required** keyword-only ``view``, which is how a forwarder asks
    the session for the forger's own holdings; everything it needs is in there,
    and nothing of Charlie's can be.
    """
    return Signature(signature.message_bit, key_from_record(view.raw_record))


def test_the_forwarder_is_handed_the_forgers_own_view_and_nothing_else() -> None:
    """Bob's two logs and Bob's matched count -- with no route to Charlie's.

    The dance this replaces: construct the forger, pass it to the session, then
    back-patch the session onto it and reach into ``raw_records``, which hands
    the attack *both* recipients' logs and leaves staying inside the threat
    model a discipline the author has to remember.
    """
    captured: dict[str, Any] = {}

    def watching(
        signature: Signature, params: Any, *, view: RecipientView
    ) -> Signature:
        captured["view"] = view
        return signature

    session = _session(_params(48), seed=SEED + 41, forwarder=watching)
    transcript = session.run(0)

    view = captured["view"]
    assert isinstance(view, RecipientView)
    assert view.party is Party.BOB
    assert view.message_bit == transcript.message_bit
    assert view.raw_record is session.raw_records[0][Party.BOB]
    assert view.record is session.records[0][Party.BOB]
    assert not view.raw_record.symmetrised
    assert view.symmetrised
    # What Bob actually knows when he forwards: his own verdict's count.
    assert view.matched_count == transcript.bob.matched_count
    # And nothing anywhere in it is Charlie's.
    charlie_logs = {
        id(session.raw_records[0][Party.CHARLIE]),
        id(session.records[0][Party.CHARLIE]),
    }
    assert id(view.raw_record) not in charlie_logs
    assert id(view.record) not in charlie_logs


def test_the_honest_forwarder_does_not_ask_for_a_view() -> None:
    """A defaulted ``view`` declines it, exactly as a defaulted context does.

    ``honest_forwarder`` carries ``view=None`` so that the default has the full
    seam shape, and the session must read that as "does not want one" -- both so
    that no view is built on an honest run, and so that every forwarder written
    before the parameter existed keeps being called with two arguments.
    """
    assert not _forwarder_wants_view(honest_forwarder)
    assert not _forwarder_wants_view(lambda signature, params: signature)
    assert not _forwarder_wants_view(lambda *args, **kwargs: None)
    assert _forwarder_wants_view(_forging_bob)

    def optional(signature: Signature, params: Any, *, view: Any = None) -> Any:
        return signature

    assert not _forwarder_wants_view(optional)
    # A callable that fits neither shape fails at construction, not mid-run.
    with pytest.raises(TypeError, match="forwarder must be callable"):
        QDSSession(_params(16), forwarder=lambda signature: signature)


def test_the_pooled_rule_refuses_to_score_a_substituted_declaration() -> None:
    """Under the shipped rule the forwarder route ends in a no-verdict at Charlie.

    Phase C' happens before either verdict, so the counts Charlie holds were
    computed against the declaration Alice sent; when the hop then delivers a
    different one, ``m_C(forwarded) + m_B(original)`` is nobody's pooled count
    and there is nothing for the pooled floor to be applied to. Charlie refuses
    (:attr:`AbortReason.COUNTS_FROM_TWO_DECLARATIONS`, and see
    ``sih141.protocol.verify``'s ``one-declaration`` section).

    Read it for what it is. The forgery does not succeed -- Charlie accepts
    nothing -- but he has not detected one either: he learned that two numbers
    disagree about their provenance, which this harness guarantees whenever the
    hop substitutes, because the forwarder seam has no way to supply a matching
    count. A forging Bob who could also report his own count against his own
    declaration would not trip this, so the refusal must not be read as evidence
    that recipient forgery is caught.
    """
    transcript = _session(_params(600), seed=SEED + 43, forwarder=_forging_bob).run(0)

    assert transcript.bob is not None and transcript.bob.accepted
    assert transcript.charlie is None
    assert transcript.aborted
    assert (
        transcript.aborts_by_party[Party.CHARLIE].reason
        is AbortReason.COUNTS_FROM_TWO_DECLARATIONS
    )
    assert not transcript.transferable
    assert not transcript.repudiated
    assert "NO VERDICT" in transcript.summary()


def test_the_recipient_forgery_route_is_the_forwarding_hop() -> None:
    """The faithful route: Bob's own evidence stays honest and Charlie is attacked.

    Everything the signer route got wrong is right here. Bob scores Alice's real
    declaration, so his rate is exactly zero and his matched count is the honest
    ``L/3``; Charlie scores the forgery and lands near the ``1/12`` forger floor,
    which is above his ``1/16`` cut. And the run is **not** recorded as a
    repudiation, because Alice declared one key and Bob substituted another.

    Run pre-pooled, with ``no_count_exchange``, which is the same arm Phase 3
    already uses for the split-coin route. Under the shipped pooled rule Charlie
    reaches no verdict at all against a substituted declaration and there is no
    rate to measure -- the test above pins that, and says why it is a denial of
    transfer rather than a detection.
    """
    params = _params(600)
    transcript = _session(
        params,
        seed=SEED + 42,
        forwarder=_forging_bob,
        count_exchange=no_count_exchange,
    ).run(0)

    assert transcript.bob.rate == 0.0
    assert transcript.bob.accepted
    assert transcript.bob.matched_count == pytest.approx(
        params.expected_matched, rel=0.25
    )
    assert transcript.charlie.rate == pytest.approx(params.forger_floor, abs=0.03)
    assert transcript.charlie.rate > params.s_v
    assert not transcript.charlie.accepted

    assert transcript.forwarding_altered_signature
    assert not transcript.transferable
    assert not transcript.repudiated, (
        "a forgery Bob himself forwarded is not Alice repudiating"
    )
    assert transcript.pooled_matched_count is None
    assert "NOT TRANSFERRED" in transcript.summary()
    assert "REPUDIATION" not in transcript.summary()
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


def test_the_signer_route_records_a_successful_forgery_as_a_rejection() -> None:
    """Why the documented route was changed, measured on the same seed.

    Mounted on the signer seam the same forgery reaches *both* verifiers, so Bob
    scores his own forgery against his own log: his rate leaves zero and lands
    at the forger floor with everyone else's, and both matched counts inflate
    from ``L/3`` to ``2L/3`` because the declaration was built from a
    recipient's log instead of drawn independently of it. A Phase 5 table built
    on this route would read a working forgery as a run in which nothing
    happened.
    """
    params = _params(600)
    faithful = _session(
        params,
        seed=SEED + 42,
        forwarder=_forging_bob,
        count_exchange=no_count_exchange,
    ).run(0)
    wrong = _session(
        params,
        seed=SEED + 42,
        signer=_reading_signer(),
        signer_sees_recipient_logs=True,
        count_exchange=no_count_exchange,
    ).run(0)

    assert not wrong.bob.accepted
    assert wrong.bob.rate == pytest.approx(params.forger_floor, abs=0.03)
    assert wrong.bob.matched_count > 1.8 * faithful.bob.matched_count

    # And the sharpest way to put it: Charlie's half of the experiment is the
    # *same* on both routes -- same record, same forged declaration, same
    # verdict object -- so the signer route buys nothing at Charlie and costs
    # Bob his own honest verdict. That is the whole of the correction.
    assert wrong.charlie == faithful.charlie
    assert faithful.bob.accepted and not wrong.bob.accepted
    assert not wrong.transferable
    assert not wrong.repudiated
    # The flag is what keeps the two arms apart in a results table.
    assert wrong.signer_saw_recipient_logs
    assert not faithful.signer_saw_recipient_logs


# ==========================================================================
# Check rounds and the channel-monitor seam
# ==========================================================================
#
# What Phase 4 reads. A checked run diverts a sampled subset of positions to
# measuring the channel; the outcomes are published as CheckLogs and the pairs
# themselves are summarised as ChannelSamples. The single security property of
# the whole feature is that only *check* positions appear -- a per-position
# statement about a key position would make the sample not a sample -- and it is
# asserted here from three directions: what the monitor is called on, what the
# transcript carries, and what a transcript claiming otherwise does when it is
# read back.


def test_a_checked_run_is_scored_under_the_sifted_parameters(
    checked_run: SessionTranscript,
) -> None:
    """The key that was signed is the one that survived, and so are the floors."""
    params = checked_run.params
    assert (params.key_length, params.check_count, params.signing_length) == (
        120,
        30,
        90,
    )
    # The transcript keeps the unsifted set -- it still records that a check
    # fraction was reserved -- and every verdict in it was reached at L = 90.
    for record in checked_run.records:
        assert len(record) == 90
    for result in checked_run.results:
        assert result.key_length == 90
    assert len(checked_run.signature.declared_key) == 90
    assert checked_run.bob.rate == 0.0
    assert checked_run.charlie.rate == 0.0
    assert checked_run.transferable
    assert SessionTranscript.from_json(checked_run.to_json()) == checked_run


def test_alice_draws_a_full_key_and_declares_the_sifted_one() -> None:
    """She does not know the check set when she draws, and cannot declare it.

    Both halves matter. A full-length draw is what keeps the retained key
    unbiased -- the subset is chosen by the recipients' stream, independently of
    the key's contents -- and a sifted declaration is all a verifier can score,
    because the check positions' pairs were spent on measurement and their
    elements were never prepared.
    """
    params = _checked()
    session = _session(params, seed=SEED + 50)
    session.distribute()

    for bit in MESSAGE_BITS:
        assert len(session.keys[bit]) == params.key_length
        assert len(session.signing_keys[bit]) == params.signing_length
        retained = session.check_plans[bit].signing_positions
        assert [element for element in session.signing_keys[bit].elements] == [
            session.keys[bit].elements[position] for position in retained
        ]
    assert session.sign(0).declared_key is session.signing_keys[0]
    # On a run with no check rounds the two are the same object, so every
    # existing claim of the form "the declared key is the drawn key" holds.
    plain = _session(_params(16))
    plain.distribute()
    assert plain.signing_keys is plain.keys


def test_the_shipped_checked_parameter_set_runs_end_to_end() -> None:
    """``DEMO_CHECKED_PARAMS`` is a configuration, not a fixture of this file.

    Every other check-round test here builds its own parameter set, which proves
    the machinery and not the shipping default. This one runs the set a
    deployment would actually be handed, so that the session and
    :mod:`sih141.protocol.params` cannot come to disagree about what
    ``check_fraction`` means -- and so that the security-grade set's *shape* is
    exercised rather than only its arithmetic.
    """
    transcript = QDSSession(
        DEMO_CHECKED_PARAMS, rng=np.random.default_rng(SEED + 60)
    ).run(0)

    assert transcript.transferable
    assert transcript.bob.key_length == DEMO_CHECKED_PARAMS.signing_length
    assert len(transcript.channel) == (
        len(MESSAGE_BITS) * DEMO_CHECKED_PARAMS.check_count
    )
    assert SessionTranscript.from_json(transcript.to_json()) == transcript
    # The security-grade set is far too large to run here; what is checked is
    # that its signing length still clears the length DEFAULT_PARAMS ships,
    # which is the whole reason it is 131664 and not 115200.
    assert CHECKED_PARAMS.signing_length >= DEMO_PARAMS.with_changes(
        key_length=115200
    ).key_length


def test_the_check_plan_is_drawn_from_the_recipients_stream() -> None:
    """Never Alice's: the estimated party must not choose the sample.

    The same boundary the symmetrisation coins sit behind, and the same test
    shape: rebuild the recipients' stream from the seed material and draw the
    plans out of it. If the plan were coming from the Alice-side stream this
    would not reproduce, and a distributor seam could steer which positions were
    watched.
    """
    params = _checked()
    session = _session(params, seed=SEED + 51)
    session.distribute()

    material = np.random.default_rng(SEED + 51).bytes(_STREAM_MATERIAL_BYTES)
    shadow = _derive_stream(material, _RECIPIENT_STREAM_LABEL)
    for bit in MESSAGE_BITS:
        assert session.check_plans[bit] == draw_check_plan(params, rng=shadow)
        # ...then that bit's symmetrisation coins, out of the same stream and
        # in that order: the plan is drawn before the distribution it plans.
        # One coin per position of the *sifted* record, not per position of the
        # run -- the recipients exchange the log they will be scored on, and the
        # check positions are not in it.
        shadow.integers(0, 2, size=params.signing_length)


def test_the_channel_samples_are_exactly_the_check_positions(
    checked_run: SessionTranscript,
) -> None:
    """One sample per check round per link, and never a key position.

    The property the whole seam exists to have. Asserted against the published
    log, which is what a Phase 4 detector will join the samples to.
    """
    assert checked_run.channel_monitored
    # check_count positions are reserved per bit and dealt between the two
    # links, so the samples total check_count per bit and not twice that.
    assert len(checked_run.channel) == (
        len(MESSAGE_BITS) * checked_run.params.check_count
    )
    for bit in MESSAGE_BITS:
        watched: set[int] = set()
        for party in VERIFIERS:
            log = checked_run.check_log_for(party, bit)
            samples = checked_run.channel_for(party, bit)
            assert tuple(sample.position for sample in samples) == log.positions
            # Dealt round-robin, so each link takes half the reserved set to
            # within one round, and the two halves are disjoint.
            assert abs(
                2 * log.round_count - checked_run.params.check_count
            ) <= 1
            assert watched.isdisjoint(log.positions)
            watched |= set(log.positions)
            qber = {entry.position for entry in log.qber}
            for sample in samples:
                assert (sample.role is CheckRole.QBER) == (
                    sample.position in qber
                )
        assert len(watched) == checked_run.params.check_count


def test_an_ideal_channel_summarises_as_an_ideal_pair(
    checked_run: SessionTranscript,
) -> None:
    """Fidelity, purity and concurrence all ``1`` on the honest resource."""
    assert all(sample.is_ideal for sample in checked_run.channel)
    assert all(sample.extra == {} for sample in checked_run.channel)
    # Each half of a maximally entangled pair is maximally mixed on its own.
    assert all(sample.wings_agree for sample in checked_run.channel)
    assert all(
        sample.alice_purity == pytest.approx(0.5)
        for sample in checked_run.channel
    )
    for bit in MESSAGE_BITS:
        for party in VERIFIERS:
            log = checked_run.check_log_for(party, bit)
            # The QBER arm is exact on a clean channel -- both wings measure
            # the same observable on |Phi+> -- so zero errors is a statement
            # about this run and not about a sample size.
            assert estimate_qber(log.qber).errors == 0
            assert estimate_qber(log.qber).estimate == 0.0
            # Both arms are plumbed through and land where the plan put them.
            assert log.qber and log.chsh
            assert abs(estimate_chsh(log.chsh).statistic) <= 4.0
    # Whether the CHSH interval clears the classical bound is a question about
    # the sample size, and 15 rounds per link cannot answer it; that claim
    # belongs to tests/test_protocol_checkrounds.py, which runs hundreds.


def test_a_degraded_channel_shows_up_in_the_samples_and_in_the_estimate() -> None:
    """The seam and the statistics have to be looking at the same channel.

    A Werner pair is less pure, less entangled and further from ``|Phi+>``; the
    QBER arm sees errors on the same rounds. Asserting both from one run is what
    stops the two halves of the feature drifting apart -- a sample recorded from
    a pair that was not the one measured would be a diagnostic about nothing.
    """
    transcript = _session(
        _checked(), seed=SEED + 52, resource_factory=lambda: _werner(0.4)
    ).run(0)

    for sample in transcript.channel:
        assert sample.fidelity < 0.8
        assert sample.purity < 1.0
        assert sample.concurrence < 1.0
        assert not sample.is_ideal
    assert estimate_qber(transcript.check_log_for(Party.BOB, 0).qber).estimate > 0.0
    assert not transcript.transferable


def _damped(gamma: float, qubit: int) -> DensityMatrix:
    """Return ``|Phi+>`` with amplitude damping applied to one leg only.

    An eavesdropper acts on the half that travels, not on the half Alice keeps,
    so a faithful model of one has to be able to say *which* qubit it touched.
    """
    kraus = Kraus(
        [
            np.array([[1.0, 0.0], [0.0, np.sqrt(1.0 - gamma)]]),
            np.array([[0.0, np.sqrt(gamma)], [0.0, 0.0]]),
        ]
    )
    return DensityMatrix(bell_state(BellState.PHI_PLUS)).evolve(
        kraus, qargs=[qubit]
    )


def test_the_two_wings_say_which_end_of_the_pair_was_disturbed() -> None:
    """D2, pinned by an asymmetric resource, and the reason for two numbers.

    Damping *one* leg leaves the global summaries unable to say which: fidelity,
    purity and concurrence are all invariant under swapping the two qubits, so
    an attack on the leg in flight and an equally strong fault in Alice's own
    apparatus produce identical triples. The marginals separate them, and
    reading the pair the wrong way round would attribute an attack to the wrong
    party with nothing failing -- which is exactly why the qubit indices come
    from :mod:`sih141.protocol.checkrounds` rather than from a literal.

    A Werner pair is the control: it mixes both halves equally, so the wings
    agree and the disturbance is real but not one-sided.
    """
    plan = draw_check_plan(_checked(40, 0.25), rng=np.random.default_rng(0))
    scheduled = plan.qber_rounds[0]
    context = ResourceContext(
        party=Party.BOB, message_bit=0, position=scheduled.position
    )

    travelling = ChannelSample.of(_damped(0.5, 1), context, scheduled)
    assert travelling.recipient_purity > travelling.alice_purity
    assert travelling.alice_purity == pytest.approx(0.5)
    assert not travelling.wings_agree

    at_alice = ChannelSample.of(_damped(0.5, 0), context, scheduled)
    assert at_alice.alice_purity > at_alice.recipient_purity
    assert not at_alice.wings_agree
    # The global summaries cannot tell the two apart. That is the point.
    assert at_alice.fidelity == pytest.approx(travelling.fidelity)
    assert at_alice.purity == pytest.approx(travelling.purity)
    assert at_alice.concurrence == pytest.approx(travelling.concurrence)

    symmetric = ChannelSample.of(_werner(0.5), context, scheduled)
    assert symmetric.wings_agree
    assert symmetric.alice_purity == pytest.approx(0.5)
    assert not symmetric.is_ideal


def test_a_one_sided_channel_attack_lands_on_one_link_only() -> None:
    """Charlie's samples degrade and Bob's do not, which is why they stay apart.

    Pooling the two links' check rounds into one rate would report the average
    of two channels and detect neither; this is the run that would hide in the
    average.
    """

    def only_charlie(context: ResourceContext) -> Any:
        if context.party is Party.CHARLIE:
            return _werner(0.6)
        return ideal_resource()

    transcript = _session(
        _checked(), seed=SEED + 53, resource_factory=only_charlie
    ).run(0)

    assert all(sample.is_ideal for sample in transcript.channel_for(Party.BOB, 0))
    assert all(
        not sample.is_ideal for sample in transcript.channel_for(Party.CHARLIE, 0)
    )
    assert estimate_qber(transcript.check_log_for(Party.BOB, 0).qber).errors == 0
    assert estimate_qber(transcript.check_log_for(Party.CHARLIE, 0).qber).errors > 0


def test_the_channel_seam_is_still_called_on_every_position() -> None:
    """The tap must not be visible from the factory it wraps.

    An adversary who could tell a watched round from an unwatched one would
    behave on the watched ones, and every number the check rounds produce would
    be a fiction. The session's tap therefore calls the factory identically at
    all ``L`` positions -- not at the ``signing_length`` of them that carry key
    -- and only records afterwards.
    """
    params = _checked()
    contexts: list[ResourceContext] = []

    def counting(context: ResourceContext) -> Any:
        contexts.append(context)
        return ideal_resource()

    session = _session(params, seed=SEED + 54, resource_factory=counting)
    session.run(0)

    assert len(contexts) == len(MESSAGE_BITS) * len(VERIFIERS) * params.key_length
    for bit in MESSAGE_BITS:
        for party in VERIFIERS:
            positions = [
                context.position
                for context in contexts
                if context.party is party and context.message_bit == bit
            ]
            assert positions == list(range(params.key_length))
    # A zero-argument factory keeps working through the tap, unchanged.
    plain = _session(params, seed=SEED + 54, resource_factory=ideal_resource)
    assert plain.run(0) == session.transcript()


def test_the_channel_monitor_is_called_on_every_position() -> None:
    """Called on every position; recorded only where the plan says.

    Being called used to be the entire signal -- the seam was invoked at check
    positions and nowhere else, so whoever held it read the check set straight
    off its own call sequence. It is now invoked everywhere, which is what
    closes that; what must not change is that nothing is *recorded* at a key
    position, because a per-position statement about the rounds the key is made
    of would stop the sampled estimate being a sample of anything.

    Also that it is handed the resource that was delivered, not a copy of the
    ideal.
    """
    params = _checked()
    seen: list[tuple[Party, int, int]] = []

    def monitor(resource: Any, context: ResourceContext) -> dict[str, Any]:
        seen.append((context.party, context.message_bit, context.position))
        return {"trace": float(np.real(np.trace(DensityMatrix(resource).data)))}

    session = _session(params, seed=SEED + 55, channel_monitor=monitor)
    transcript = session.run(1)

    for bit in MESSAGE_BITS:
        plan = session.check_plans[bit]
        for party in VERIFIERS:
            positions = sorted(
                position
                for seen_party, seen_bit, position in seen
                if seen_party is party and seen_bit == bit
            )
            assert positions == list(range(params.key_length))
            # ... and published only at this link's own reserved positions.
            published = transcript.channel_for(party, bit)
            assert tuple(
                sample.position for sample in published
            ) == plan.positions_for(party)
            assert not {sample.position for sample in published} & set(
                plan.signing_positions
            )
    assert all(
        sample.extra["trace"] == pytest.approx(1.0)
        for sample in transcript.channel
    )
    assert json.loads(transcript.to_json())["channel"][0]["extra"][
        "trace"
    ] == pytest.approx(1.0)


def test_a_monitor_that_edits_the_pair_changes_nothing() -> None:
    """An observer must not be able to become a channel attack by writing to it.

    A qiskit state hands out its array, so a monitor given the object itself
    could edit the pair between the factory that produced it and the
    measurement that consumes it -- a channel attack under an observer's name,
    and one the transcript would not record as a channel attack at all, because
    the ``resource_factory`` it would be attributed to did nothing. The seam is
    therefore handed a copy, and this is the assertion that says so: the same
    seed with and without a vandalising monitor produces the same records and
    the same ideal samples.
    """

    def vandal(resource: Any, context: ResourceContext) -> dict[str, Any]:
        resource.data[0, 0] = 0.0
        return {"seen": float(np.real(resource.data[3, 3]))}

    params = _checked(40, 0.25)
    clean = _session(params, seed=SEED + 61).run(0)
    watched = _session(params, seed=SEED + 61, channel_monitor=vandal).run(0)

    assert watched.records == clean.records
    assert all(sample.is_ideal for sample in watched.channel)
    # The monitor really ran, and really saw the pair it was given.
    assert watched.channel[0].extra["seen"] == pytest.approx(0.5)


def test_the_channel_monitor_is_never_called_without_check_rounds() -> None:
    """No plan, no legitimate round to call it on, so it is not called at all."""
    calls = 0

    def monitor(resource: Any, context: ResourceContext) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {}

    transcript = _session(_params(24), channel_monitor=monitor).run(0)
    assert calls == 0
    assert transcript.channel == ()
    assert transcript.check_logs == ()
    assert not transcript.channel_monitored
    # And an unchecked run is unchanged by the monitor being there at all.
    assert transcript == _session(_params(24)).run(0)


# ==========================================================================
# The check set, and the read counts that used to publish it
# ==========================================================================
#
# Equalising how often each seam is CALLED closed one family of leaks and
# promoted the next: what the protocol then DID with what a seam returned still
# differed between the branches. A resource was read once on a key round and
# twice on a check round, a mapped payload once and not at all, and the
# monitor's mapping was iterated only where a sample was built. All three
# tallies recovered the whole check set -- precision 1.0, recall 1.0, no
# statistics -- for an adversary who returned an instrumented object and
# counted. The three seams are held by one declared adversary, so they are
# driven together here, the way tests/test_protocol_checkrounds.py's
# test_the_factory_cannot_tell_a_check_round_from_a_key_round drives their call
# sequences together.
#
# One route in this family is deliberately NOT closed and is not tested here:
# the wall-clock gap between the branches. It is out of the simulator's scope,
# argued in docs/PHASE3.md section 12, and it leaves the named assumption
# (NO-TIMING) on every check-round statistic this project publishes.


class _CountingStatevector(Statevector):
    """A pure state that tallies every read of its amplitudes.

    The instrument the whole section is built on, and the reason it is a
    subclass rather than a wrapper: it has to pass every ``isinstance`` check
    and every coercion the protocol makes, so that what is measured is the
    protocol's own read pattern and not a rejection path.
    """

    def __init__(
        self, data: Any, tally: Counter[Any], hop: Any
    ) -> None:
        super().__init__(data)
        object.__setattr__(self, "_tally", tally)
        object.__setattr__(self, "_hop", hop)

    @property
    def data(self) -> Any:  # noqa: D102 -- overrides a qiskit property
        self._tally[self._hop] += 1
        return self._data


class _CountingDensityMatrix(DensityMatrix):
    """The same instrument for a mixed state. Same reason it is a subclass."""

    def __init__(
        self, data: Any, tally: Counter[Any], hop: Any
    ) -> None:
        super().__init__(data)
        object.__setattr__(self, "_tally", tally)
        object.__setattr__(self, "_hop", hop)

    @property
    def data(self) -> Any:  # noqa: D102 -- overrides a qiskit property
        self._tally[self._hop] += 1
        return self._data


class _CountingMapping(Mapping):
    """A monitor result that tallies every iteration of itself."""

    def __init__(
        self, payload: dict[str, Any], tally: Counter[Any], hop: Any
    ) -> None:
        self._payload = payload
        self._tally = tally
        self._hop = hop

    def __getitem__(self, key: str) -> Any:
        return self._payload[key]

    def __iter__(self) -> Any:
        self._tally[self._hop] += 1
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


def _nominate(counts: dict[int, int], length: int) -> set[int]:
    """Return the positions an adversary reading ``counts`` would call watched.

    The check set is the minority (``check_fraction < 1/2``), so a read tally
    that separates the branches at all separates them into a small class and a
    large one, and the small class is the check set. When every position lands
    in one class there is nothing to separate and the best available strategy
    is to nominate everything -- which scores exactly the base rate, and is
    what "no better than chance" means as a number.

    Parameters
    ----------
    counts : dict
        Position to read count, for one link of one message bit.
    length : int
        ``L``, so that the degenerate answer is the whole range.

    Returns
    -------
    set of int
        The nominated positions.
    """
    classes: dict[int, set[int]] = {}
    for position, count in counts.items():
        classes.setdefault(count, set()).add(position)
    if len(classes) == 1:
        return set(range(length))
    return min(classes.values(), key=len)


def _score_against_plans(
    tally: Counter[Any], session: QDSSession, params: ProtocolParams
) -> tuple[float, float, set[int]]:
    """Score a read tally against the plans the session actually drew.

    Parameters
    ----------
    tally : collections.Counter
        Keyed by ``(party, message_bit, position)``.
    session : QDSSession
        The run that produced it, read for its plans **after** the fact. This
        is the labelled harness of §8: the adversary never sees it.
    params : ProtocolParams
        For ``L``.

    Returns
    -------
    tuple
        Precision, recall, and the set of distinct read counts observed.
    """
    hits = nominated = watched = 0
    classes: set[int] = set()
    for bit, plan in session.check_plans.items():
        for party in VERIFIERS:
            counts = {
                position: tally[(party, bit, position)]
                for position in range(params.key_length)
            }
            classes.update(counts.values())
            truth = set(plan.positions_for(party))
            guess = _nominate(counts, params.key_length)
            hits += len(guess & truth)
            nominated += len(guess)
            watched += len(truth)
    return (
        hits / nominated if nominated else 0.0,
        hits / watched if watched else 0.0,
        classes,
    )


def test_no_seam_learns_the_check_set_by_counting_its_own_reads() -> None:
    """Every seam's answer is read the same number of times on both branches.

    The load-bearing test of the read-count family, and the companion to
    ``test_the_factory_cannot_tell_a_check_round_from_a_key_round``, which says
    the same thing about *calls*. All three channel-side seams return
    instrumented objects at once, because one adversary holds all three and the
    check set is recovered if **any** of the three tallies separates the
    branches.

    Two assertions, and the second is the one that means something. The
    structural one: each seam's tally has exactly one distinct value, so there
    is no minority class to nominate. The operational one: an adversary scoring
    that tally lands on the per-link base rate ``check_fraction / 2``, which is
    what an adversary who nominates blindly gets and therefore what "learned
    nothing" is worth as a number.

    The positive control at the end is not decoration. A probe that has stopped
    measuring anything -- a subclass whose property no longer overrides, a
    tally keyed on something that never varies -- would satisfy both assertions
    above trivially, and that is exactly the failure the Phase 3 audit found in
    the D6 isolation check. So the same scorer is run over a tally with the
    *pre-fix* shape, built from the plans this very run drew, and it must
    recover the whole set.
    """
    params = _checked(64, 0.25)
    resource_reads: Counter[Any] = Counter()
    payload_reads: Counter[Any] = Counter()
    monitor_reads: Counter[Any] = Counter()

    def hop(context: ResourceContext) -> tuple[Party, int, int]:
        return (context.party, context.message_bit, context.position)

    def factory(context: ResourceContext) -> Statevector:
        return _CountingStatevector(
            bell_state(BellState.PHI_PLUS).data, resource_reads, hop(context)
        )

    def payload(state: Any, context: ResourceContext) -> Statevector:
        return _CountingStatevector(
            Statevector(state).data, payload_reads, hop(context)
        )

    def monitor(resource: Any, context: ResourceContext) -> Mapping[str, Any]:
        return _CountingMapping({"seen": 1}, monitor_reads, hop(context))

    session = _session(
        params,
        seed=SEED + 71,
        resource_factory=factory,
        payload_map=payload,
        channel_monitor=monitor,
    )
    session.distribute()

    hops = 2 * len(VERIFIERS) * params.key_length
    for name, tally in (
        ("resource_factory", resource_reads),
        ("payload_map", payload_reads),
        ("channel_monitor", monitor_reads),
    ):
        precision, recall, classes = _score_against_plans(
            tally, session, params
        )
        # Every position was actually instrumented, so a flat tally is a
        # measurement and not an empty one.
        assert len(tally) == hops, f"{name} was not offered every position"
        assert classes == {1}, (
            f"{name}'s answer is read {sorted(classes)} times depending on the "
            f"position, and the read count is therefore a channel: an "
            f"adversary returning an instrumented object reads the check set "
            f"off its own tally. See sih141.protocol.distribute's "
            f"check-round-lockstep note."
        )
        # The base rate is per LINK, so it is half the check fraction: the plan
        # reserves ``check_count`` positions for the run and deals them between
        # the two links, and a link measures only its own
        # (:ref:`sih141.protocol.checkrounds <check-round-links>`).
        base_rate = params.check_fraction / len(VERIFIERS)
        assert precision == pytest.approx(base_rate), (
            f"{name}'s tally moved the posterior off the {base_rate} base "
            f"rate to {precision}"
        )
        assert recall == pytest.approx(1.0)

    # Positive control: the scorer above, on a tally shaped the way the code
    # used to produce -- one read at a key position, two at a check one.
    pre_fix: Counter[Any] = Counter()
    for bit, plan in session.check_plans.items():
        for party in VERIFIERS:
            watched = set(plan.positions_for(party))
            for position in range(params.key_length):
                pre_fix[(party, bit, position)] = (
                    2 if position in watched else 1
                )
    precision, recall, classes = _score_against_plans(
        pre_fix, session, params
    )
    assert (precision, recall) == (1.0, 1.0) and classes == {1, 2}


def test_a_spare_the_watched_adversary_no_longer_finds_the_watched_rounds() -> None:
    """The consequence, end to end: the published QBER tracks the key damage.

    The inference above is only worth closing because of what it bought. This
    adversary holds ``resource_factory`` and ``payload_map`` -- both are the
    declared channel-side seams -- and attacks every position with a Werner
    pair of strength ``1/2``. Its payload map, called for the same hop a
    moment later, asks whether the pair it just handed over has been read yet;
    before the fix the only reader at that instant was the ``ChannelSample``
    the tap builds, so a read meant *check round*, and the map wrote the clean
    amplitudes back into the pair, in place, before the round measured it.

    Measured against the code as it stood at commit ``adee91b``, at these exact
    parameters and this exact seed:

    ========================  ===================  ===================
    quantity                  before               after
    ========================  ===================  ===================
    published QBER, unspared  ``19/48``            ``19/48``
    published QBER, sparing   ``0/48``             ``19/48``
    key damage, either arm    ``11/52``/``18/62``  ``11/52``/``18/62``
    positions nominated       ``96``               ``768``
    precision, recall         ``1.0``, ``1.0``     ``0.125``, ``1.0``
    ========================  ===================  ===================

    So the exploit used to take the attack from *detected and attributed* to
    *neither*, with bit-identical key damage; it now takes it nowhere. The
    ``0.125`` it scores afterwards is the per-link base rate,
    ``check_fraction / 2`` -- the adversary nominates every position, because
    it can no longer tell them apart, and nominating everything scores the
    prior.

    The counts are pinned rather than estimated. ``19/48`` is one seeded run of
    a 48-round sample whose expectation is ``p / 2 = 0.25``, so the level
    carries a wide interval and is not the claim; the claim is the
    **difference** between the two arms of the comparison, which is what the
    assertions state. Sparing must not change the published QBER, and it must
    not change the key damage either -- the second is what says the adversary
    really did attack, rather than quietly doing nothing.
    """
    params = _checked(192, 0.25)
    ideal = DensityMatrix(bell_state(BellState.PHI_PLUS)).data

    class SpareTheWatched:
        """Attack every position; undo it on the ones that turn out watched."""

        def __init__(self, *, spare: bool) -> None:
            self.spare = spare
            self.reads: Counter[Any] = Counter()
            self.live: dict[Any, Any] = {}
            self.nominated: set[Any] = set()

        def resource(self, context: ResourceContext) -> DensityMatrix:
            hop = (context.party, context.message_bit, context.position)
            pair = _CountingDensityMatrix(_werner(0.5), self.reads, hop)
            self.live[hop] = pair
            return pair

        def payload(self, state: Any, context: ResourceContext) -> Any:
            if self.spare:
                hop = (context.party, context.message_bit, context.position)
                if self.reads[hop] > 0:
                    self.live[hop]._data[:, :] = ideal
                    self.nominated.add(hop)
            return state

    def run(*, spare: bool) -> tuple[SpareTheWatched, QDSSession, Any]:
        attack = SpareTheWatched(spare=spare)
        session = _session(
            params,
            seed=SEED + 72,
            resource_factory=attack.resource,
            payload_map=attack.payload,
        )
        return attack, session, session.run(0)

    def published_qber(transcript: Any) -> tuple[int, int]:
        rounds = [
            observation
            for log in transcript.check_logs
            for observation in log.qber
        ]
        return sum(int(item.is_error) for item in rounds), len(rounds)

    def damage(transcript: Any) -> tuple[tuple[str, int, int], ...]:
        return tuple(
            (result.party.value, result.mismatches, result.matched_count)
            for result in transcript.results
        )

    plain_attack, _, plain = run(spare=False)
    sparing_attack, sparing_session, sparing = run(spare=True)

    # The attack is real and visible on both arms of the comparison.
    assert published_qber(plain) == (19, 48)
    assert damage(plain) == (("Bob", 11, 52), ("Charlie", 18, 62))

    # And trying to hide from the check rounds achieves exactly nothing.
    assert published_qber(sparing) == published_qber(plain)
    assert damage(sparing) == damage(plain)
    assert set(plain_attack.reads.values()) == {1}
    assert set(sparing_attack.reads.values()) == {1}

    # It nominated every position, which is the shape of learning nothing.
    hops = 2 * len(VERIFIERS) * params.key_length
    assert len(sparing_attack.nominated) == hops
    watched = {
        (party, bit, position)
        for bit, plan in sparing_session.check_plans.items()
        for party in VERIFIERS
        for position in plan.positions_for(party)
    }
    assert len(watched & sparing_attack.nominated) / hops == pytest.approx(
        params.check_fraction / len(VERIFIERS)
    )


def test_monitor_output_is_coerced_to_json_leaves() -> None:
    """NumPy comes out of any real computation; the transcript must survive it."""

    def monitor(resource: Any, context: ResourceContext) -> dict[str, Any]:
        eigenvalues = np.linalg.eigvalsh(DensityMatrix(resource).data)
        return {
            "eigenvalues": eigenvalues,
            "rank": np.int64(int(np.sum(eigenvalues > 1e-9))),
            "pure": np.bool_(True),
            "nested": {"depth": [np.float64(0.5), None, "text"]},
        }

    transcript = _session(
        _checked(40, 0.25), seed=SEED + 56, channel_monitor=monitor
    ).run(0)
    extra = transcript.channel[0].extra
    assert isinstance(extra["eigenvalues"], list)
    assert all(isinstance(value, float) for value in extra["eigenvalues"])
    assert extra["rank"] == 1 and isinstance(extra["rank"], int)
    assert extra["pure"] is True
    assert extra["nested"] == {"depth": [0.5, None, "text"]}
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


def test_a_monitor_returning_something_unserialisable_is_refused() -> None:
    """Loudly, at the round that produced it -- not at ``json.dumps`` time."""
    session = _session(
        _checked(40, 0.25),
        seed=SEED + 57,
        channel_monitor=lambda resource, context: {"state": resource},
    )
    with pytest.raises(TypeError, match="no JSON representation"):
        session.distribute()

    session = _session(
        _checked(40, 0.25),
        seed=SEED + 57,
        channel_monitor=lambda resource, context: {"nan": float("nan")},
    )
    with pytest.raises(ValueError, match="non-finite"):
        session.distribute()

    session = _session(
        _checked(40, 0.25),
        seed=SEED + 57,
        channel_monitor=lambda resource, context: [1.0],
    )
    with pytest.raises(TypeError, match="must return a mapping"):
        session.distribute()

    # The likely one: a detector publishing an amplitude straight out of a
    # density matrix. There is no JSON convention for a complex number and
    # inventing one here would make every reader guess, so it is named instead.
    session = _session(
        _checked(40, 0.25),
        seed=SEED + 57,
        channel_monitor=lambda resource, context: {
            "amplitude": DensityMatrix(resource).data[0, 0]
        },
    )
    with pytest.raises(TypeError, match="complex number"):
        session.distribute()


def test_a_non_callable_channel_monitor_is_refused_at_construction() -> None:
    """As every other seam is."""
    with pytest.raises(TypeError, match="channel_monitor"):
        QDSSession(_checked(), channel_monitor={"fidelity": 1.0})  # type: ignore[arg-type]


def test_the_transcript_refuses_a_channel_sample_at_a_key_position(
    checked_run: SessionTranscript,
) -> None:
    """The load-bearing refusal: only sampled positions may be published.

    A per-position statement about a *key* position is a statement about the
    rounds the signature is made of, and the estimate stops being a sample of
    anything. The live path cannot produce one; a file can say whatever it was
    written to say, so the persistence boundary checks it.
    """
    blob = json.loads(checked_run.to_json())
    signing = set(range(checked_run.params.key_length)) - set(
        checked_run.check_log_for(Party.BOB, 0).positions
    )
    blob["channel"][0]["position"] = min(signing)
    with pytest.raises(ValueError, match="not a check round of this run"):
        SessionTranscript.from_json(json.dumps(blob))

    blob = json.loads(checked_run.to_json())
    blob["channel"][0]["position"] = checked_run.params.key_length + 1
    with pytest.raises(ValueError, match="positions"):
        SessionTranscript.from_json(json.dumps(blob))

    blob = json.loads(checked_run.to_json())
    first = checked_run.channel[0]
    other = CheckRole.CHSH if first.role is CheckRole.QBER else CheckRole.QBER
    blob["channel"][0]["role"] = other.value
    with pytest.raises(ValueError, match="arm"):
        SessionTranscript.from_json(json.dumps(blob))


def test_the_transcript_refuses_two_check_logs_for_one_link(
    checked_run: SessionTranscript,
) -> None:
    """A duplicate would double the sample behind every interval computed."""
    with pytest.raises(ValueError, match="two logs"):
        dataclasses.replace(
            checked_run,
            check_logs=checked_run.check_logs + (checked_run.check_logs[0],),
        )


def test_check_round_accessors_refuse_alice(
    checked_run: SessionTranscript,
) -> None:
    """A check round measures one link and she is the far end of both."""
    with pytest.raises(ValueError, match="Alice holds no check log"):
        checked_run.check_log_for(Party.ALICE, 0)
    with pytest.raises(ValueError, match="Alice holds no channel samples"):
        checked_run.channel_for(Party.ALICE, 0)
    assert checked_run.check_log_for(Party.BOB, 1) is not None
    assert _session(_params(16)).run(0).check_log_for(Party.BOB, 0) is None


def test_the_transcript_still_holds_no_quantum_state_on_a_checked_run(
    checked_run: SessionTranscript,
) -> None:
    """Every leaf a JSON primitive, check-round diagnostics included."""
    blob = checked_run.to_dict()

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                assert isinstance(key, str), path
                walk(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        else:
            assert isinstance(value, (int, float, bool, str, type(None))), (
                f"{path} is {type(value).__name__}"
            )

    walk(blob, "transcript")
    assert json.loads(json.dumps(blob))["channel"][0]["fidelity"] == 1.0


def test_the_summary_names_a_checked_run_as_one(
    checked_run: SessionTranscript,
) -> None:
    """The reader is told the key was shortened before being shown its rates."""
    line = next(
        text
        for text in checked_run.summary().splitlines()
        if text.startswith("CHECK ROUNDS:")
    )
    assert "30 of 120" in line
    assert "L=90" in line
    assert "CHECK ROUNDS" not in _session(_params(24)).run(0).summary()


def test_a_distributor_returning_unsifted_records_is_still_refused() -> None:
    """Silently accepting one would score 120 positions against 90's floors.

    The exact failure the sifted parameter set exists to prevent, and the reason
    the record check happens against ``scored_params`` rather than ``params``.
    """

    def unsifted(key: PrivateKey, protocol_params: Any, **kwargs: Any) -> Any:
        kwargs.pop("check_plan", None)
        return distribute_public_key_with_checks(
            key, protocol_params.with_check_fraction(0.0), **kwargs
        )

    session = _session(_checked(), seed=SEED + 58, distributor=unsifted)
    with pytest.raises(ValueError, match="entries"):
        session.distribute()


def test_a_distributor_that_swaps_the_two_links_check_logs_is_refused() -> None:
    """A check log is a statement about one link, and about which one.

    Filing Charlie's under Bob would attribute Charlie's channel to Bob, which
    is precisely the attribution a one-sided attack turns on -- and it would do
    it silently, because both logs are well formed and the records are
    untouched. The seam's output is checked for shape, so it fails loudly here.
    """

    def swapping(key: PrivateKey, protocol_params: Any, **kwargs: Any) -> Any:
        outcomes = distribute_public_key_with_checks(
            key, protocol_params, **kwargs
        )
        bob, charlie = outcomes[Party.BOB], outcomes[Party.CHARLIE]
        return {
            Party.BOB: RecipientDistribution(bob.record, charlie.log, bob.plan),
            Party.CHARLIE: charlie,
        }

    session = _session(_checked(40, 0.25), seed=SEED + 59, distributor=swapping)
    with pytest.raises(ValueError, match="filed a check log for"):
        session.distribute()


def test_the_distributor_may_still_return_bare_records(
    checked_run: SessionTranscript,
) -> None:
    """The historical shape keeps working, and simply publishes no statistics."""

    def bare(key: PrivateKey, protocol_params: Any, **kwargs: Any) -> Any:
        return {
            party: outcome.record
            for party, outcome in distribute_public_key_with_checks(
                key, protocol_params, **kwargs
            ).items()
        }

    transcript = _session(_checked(), seed=SEED + 101, distributor=bare).run(0)
    assert transcript.check_logs == ()
    # The records are the ones the default distributor produced, so the only
    # thing lost is what was published about the channel -- and the samples,
    # which come from the tap rather than from the seam, are still there.
    assert transcript.records == checked_run.records
    assert len(transcript.channel) == len(checked_run.channel)


def test_a_channel_sample_is_a_summary_and_not_a_state() -> None:
    """Built from the pair, carrying numbers, and refusing anything else."""
    context = ResourceContext(party=Party.BOB, message_bit=1, position=7)
    scheduled = draw_check_plan(
        _checked(40, 0.25), rng=np.random.default_rng(0)
    ).qber_rounds[0]
    at = ResourceContext(
        party=Party.BOB, message_bit=1, position=scheduled.position
    )

    sample = ChannelSample.of(bell_state(BellState.PHI_PLUS), at, scheduled)
    assert sample.is_ideal
    assert ChannelSample.from_dict(sample.to_dict()) == sample

    # A one-qubit "resource" is a mis-wired factory, named as one.
    with pytest.raises(ValueError, match="two-qubit state"):
        ChannelSample.of(Statevector([1, 0]), at, scheduled)
    # A round from another position would file this pair under other outcomes.
    with pytest.raises(ValueError, match="hop being summarised"):
        ChannelSample.of(bell_state(BellState.PHI_PLUS), context, scheduled)
    # Alice is at the far end of both links and tags nothing.
    with pytest.raises(ValueError, match="describes one link"):
        dataclasses.replace(sample, party=Party.ALICE)
    # And the fields are numbers, including when they arrive from a file.
    with pytest.raises(TypeError, match="fidelity must be a real number"):
        dataclasses.replace(sample, fidelity="high")
    with pytest.raises(ValueError, match=r"finite number in \[0.0, 1.0\]"):
        dataclasses.replace(sample, recipient_purity=1.5)


def test_the_withheld_records_mapping_is_an_empty_mapping() -> None:
    """It has to behave as ``{}`` for every signer that probes it defensively."""
    withheld = WithheldRecords()
    assert len(withheld) == 0
    assert list(withheld) == []
    assert dict(withheld) == {}
    assert withheld.get(0) is None
    assert repr(NO_RECIPIENT_LOGS) == "WithheldRecords()"
    # And the one thing it adds: the reason, on the way out.
    with pytest.raises(KeyError, match="no adversary in the threat model"):
        withheld[0]
    with pytest.raises(KeyError, match="forwarder seam"):
        withheld[1]
