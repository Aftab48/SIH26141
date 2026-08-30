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
   ``distributor`` and ``signer``, so each is exercised here from the session's
   own API: a degraded channel must drive both verifiers to reject (which also
   re-proves the teleportation is genuinely in the data path when driven from
   this module), a forging signer must be rejected, and a mis-wired seam must
   fail loudly rather than quietly produce a clean-looking run.
5. **Phase order and single use.** Every out-of-order call is refused with a
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
from typing import Any

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix, Statevector

from sih141.core.states import BellState, bell_state
from sih141.protocol import (
    DEMO_PARAMS,
    MESSAGE_BITS,
    VERIFIERS,
    Party,
    PrivateKey,
    ProtocolParams,
    QDSSession,
    RecipientRecord,
    SessionTranscript,
    Signature,
    VerificationResult,
    KeyElement,
    distribute_public_key,
    honest_forwarder,
    honest_signer,
    ideal_resource,
    no_symmetrisation,
    sign,
    symmetrise_records,
)
from sih141.protocol.session import (
    _ALICE_STREAM_LABEL,
    _RECIPIENT_STREAM_LABEL,
    _STREAM_MATERIAL_BYTES,
    _derive_stream,
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


@pytest.fixture(scope="module")
def honest_run() -> SessionTranscript:
    """One clean, seeded, completed run. Shared, because it costs 96 hops."""
    return _session(_params(24)).run(0)


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


def test_the_signer_seam_receives_everything_an_adversary_could_hold() -> None:
    """Message bit, both keys, the parameters and both recipients' logs."""
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
    assert sorted(captured["records"]) == list(MESSAGE_BITS)
    assert sorted(captured["records"][1]) == sorted(VERIFIERS)


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


def test_verifying_twice_reaches_the_same_verdict() -> None:
    """Verification is pure: same frozen inputs, same decision, no randomness."""
    session = _session()
    session.run(0)
    assert session.verify(Party.BOB) == session.results[Party.BOB]
    assert len(session.transcript().results) == len(VERIFIERS)


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


def test_the_signer_seam_receives_the_raw_records() -> None:
    """What the pen-holder is shown: the pre-exchange logs, and only those.

    A forging Bob needs his own raw record -- after the exchange, half of
    Charlie's evidence *is* that record -- and a repudiating Alice must not
    learn the exchange's outcome. Both follow from handing the seam the raw
    logs, and this pins that the seam gets those and not the post-exchange ones.
    """
    captured: dict[str, Any] = {}

    def watching(
        message_bit: int, keys: Any, protocol_params: Any, *, records: Any
    ) -> Any:
        captured["records"] = records
        return honest_signer(
            message_bit, keys, protocol_params, records=records
        )

    session = _session(_params(48), signer=watching)
    session.distribute()
    session.sign(0)

    for bit in MESSAGE_BITS:
        for party in VERIFIERS:
            assert captured["records"][bit][party] is session.raw_records[bit][party]
            assert not captured["records"][bit][party].symmetrised


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
