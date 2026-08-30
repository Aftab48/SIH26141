"""Cross-module agreement between the abort rule and the repudiation bounds.

Three separate repairs landed on this protocol at once -- the matched-count
abort rule in :mod:`sih141.protocol.verify`, the split of the repudiation bound
into a per-run and an ``M``-averaged form in :mod:`sih141.protocol.analysis`,
and the no-verdict plumbing in :mod:`sih141.protocol.session`. Each is tested in
its own file. What is tested *here* is that they agree, because the failure mode
the audit found was never a wrong formula: it was a correct formula published
under the wrong hypothesis, and that is exactly the kind of defect a per-module
test suite cannot see.

Four things are pinned.

1. **What ``M`` means.** Every expression in the repudiation family counts
   *matched records held by the two verifiers together*, ``M = m_B + m_C``, not
   one verifier's own count. ``minimum_matched_count`` is the one quantity that
   is per-verifier, and the factor of two between them is asserted rather than
   assumed.
2. **Which number a run quotes.** A completed run quotes
   :attr:`~sih141.protocol.session.SessionTranscript.repudiation_guarantee`, the
   per-run bound at the *observed* ``M``. The a-priori figure the package is
   entitled to publish is
   :func:`~sih141.protocol.verify.enforced_repudiation_bound`, which reads the
   floor :func:`~sih141.protocol.verify.verify` actually applies. Neither is
   :func:`~sih141.protocol.analysis.averaged_repudiation_bound`.
3. **The adaptive-declaration repudiation attack is prevented**, not merely
   bounded, wherever the floor exceeds the matched count the attack can pin. It
   pins ``M = 13`` at every ``L``; the floor exceeds ``13`` for every
   ``L >= 340``, ``DEFAULT_PARAMS`` included by a factor of ``2800``.
4. **The residual route is a no-verdict, never a reject verdict.** Section
   4b-iii of :mod:`sih141.protocol.analysis` documents one outcome the
   per-verifier floor does not close: a signer aiming ``M`` at ``2 m_min`` can
   leave Charlie below *his* floor while Bob accepts. The test asserts what the
   documentation claims -- that this produces a recorded abort and never a
   repudiation verdict -- so that if the framing ever changes, the claim in the
   docstrings fails with it.

Notes
-----
Determinism (D3)
    Every session here is seeded through an injected
    :class:`numpy.random.Generator`. Nothing reads global randomness.
No machine learning (D4)
    Closed forms, counting, and simulated runs of the protocol itself.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

import numpy as np
import pytest

from sih141.core.paulis import PauliBasis
from sih141.protocol.analysis import (
    averaged_repudiation_bound,
    matched_shortfall_probability,
    repudiation_bound,
    repudiation_bound_with_abort,
)
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import (
    DEFAULT_PARAMS,
    DEMO_PARAMS,
    Party,
    ProtocolParams,
)
from sih141.protocol.records import RecipientRecord
from sih141.protocol.session import QDSSession, SessionTranscript
from sih141.protocol.signature import Signature
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    enforced_repudiation_bound,
    minimum_matched_count,
)

#: Key length used for every simulated run here. Chosen, not guessed: the floor
#: must exceed the ``M = 13`` the starving signer pins (it is ``17`` at this
#: length and ``1`` below ``L = 267``), and the runs must stay cheap. See
#: ``test_the_chosen_key_length_actually_exercises_the_floor``.
ATTACK_KEY_LENGTH: int = 360

#: Seeds per scenario. Small on purpose: every assertion below is "this never
#: happens", so the sample size sets how strong the evidence is, not whether the
#: test is meaningful. The full-scale measurements are in ``docs/PHASE2.md``.
TRIALS: int = 16

BASES: tuple[PauliBasis, ...] = (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)


# --------------------------------------------------------------------------- #
# The adversarial signers. Both read *both* raw logs, which is what the Signer
# seam hands over and strictly more than any single adversary in the model has.
# --------------------------------------------------------------------------- #


def _declare_avoiding_both_logs(
    bob: RecipientRecord,
    charlie: RecipientRecord,
    keep: set[int],
    message_bit: int,
) -> Signature:
    """Build a declaration matched only on ``keep``.

    Off ``keep`` it names a basis absent from both raw logs, which with three
    bases always exists, so the position is matched at neither verifier whatever
    the symmetrisation coin does. On ``keep`` it names Bob's raw entry verbatim.

    Parameters
    ----------
    bob, charlie : RecipientRecord
        The two raw, pre-exchange logs.
    keep : set of int
        Positions to leave matched.
    message_bit : int
        The bit being signed.

    Returns
    -------
    Signature
        The declaration.
    """
    elements: list[KeyElement] = []
    for index in range(bob.length):
        if index in keep:
            elements.append(
                KeyElement(
                    basis=bob.entries[index].basis,
                    eigenvalue=bob.entries[index].eigenvalue,
                )
            )
            continue
        avoid = {bob.entries[index].basis, charlie.entries[index].basis}
        elements.append(
            KeyElement(
                basis=next(b for b in BASES if b not in avoid), eigenvalue=+1
            )
        )
    return Signature(
        message_bit=message_bit,
        declared_key=PrivateKey(
            message_bit=message_bit, elements=tuple(elements)
        ),
    )


def starving_signer(
    message_bit: int,
    keys: tuple[PrivateKey, PrivateKey],
    params: ProtocolParams,
    *,
    records: Mapping[int, Mapping[Party, RecipientRecord]],
) -> Signature:
    """The [CRITICAL] finding's attack: pin ``M = 13`` at every key length.

    Keeps eleven positions where the two logs used *different* bases (one matched
    record each, correct) and one where they used the *same* basis and recorded
    *opposite* outcomes (two matched records, exactly one wrong). Every other
    position is matched at neither verifier. So ``M = 11 + 2 = 13`` with
    probability ``1``, one coin decides who scores the single wrong record, and
    against a verifier with no floor that is a repudiation with probability
    ``1/2`` -- against an ``M``-averaged bound of ``6.9e-10``.

    Parameters
    ----------
    message_bit : int
        The bit being signed.
    keys : tuple of PrivateKey
        Alice's committed pair. Unused: the declaration is built from the logs.
    params : ProtocolParams
        The parameter set.
    records : mapping
        Keyword-only. Both recipients' raw logs, keyed by bit then party.

    Returns
    -------
    Signature
        A declaration pinning ``M = 13``.

    Raises
    ------
    ValueError
        If the logs contain no position where the two verifiers used the same
        basis and disagreed, which at these key lengths has probability
        ``(5/6) ** L``.
    """
    del keys
    bob = records[message_bit][Party.BOB]
    charlie = records[message_bit][Party.CHARLIE]
    conflict = next(
        (
            i
            for i in range(params.key_length)
            if bob.entries[i].basis == charlie.entries[i].basis
            and bob.entries[i].eigenvalue != charlie.entries[i].eigenvalue
        ),
        None,
    )
    if conflict is None:
        raise ValueError(
            f"no same-basis, opposite-outcome position in {params.key_length} "
            f"draws; the attack needs one to place its single wrong record. "
            f"Raise the key length or change the seed."
        )
    split = [
        i
        for i in range(params.key_length)
        if bob.entries[i].basis != charlie.entries[i].basis and i != conflict
    ][:11]
    return _declare_avoiding_both_logs(
        bob, charlie, set(split) | {conflict}, message_bit
    )


def aiming_signer(
    message_bit: int,
    keys: tuple[PrivateKey, PrivateKey],
    params: ProtocolParams,
    *,
    records: Mapping[int, Mapping[Party, RecipientRecord]],
) -> Signature:
    """Aim ``M`` at exactly ``2 * m_min`` with clean records.

    The route section 4b-iii of :mod:`sih141.protocol.analysis` says the
    per-verifier floor leaves open. Keeps ``2 m_min`` positions on which the two
    logs used different bases and declares Bob's entry, so every kept record is
    *correct* and exactly one verifier holds each. The coins then split a total
    of ``2 m_min`` about its mean ``m_min``, and roughly half the time Bob clears
    his floor while Charlie falls below his.

    Parameters
    ----------
    message_bit : int
        The bit being signed.
    keys : tuple of PrivateKey
        Alice's committed pair. Unused.
    params : ProtocolParams
        The parameter set; its floor sets the target.
    records : mapping
        Keyword-only. Both recipients' raw logs, keyed by bit then party.

    Returns
    -------
    Signature
        A declaration whose matched total is ``2 * minimum_matched_count``.

    Raises
    ------
    ValueError
        If the logs offer fewer split positions than the target needs.
    """
    del keys
    bob = records[message_bit][Party.BOB]
    charlie = records[message_bit][Party.CHARLIE]
    target = 2 * minimum_matched_count(params)
    split = [
        i
        for i in range(params.key_length)
        if bob.entries[i].basis != charlie.entries[i].basis
    ]
    if len(split) < target:
        raise ValueError(
            f"only {len(split)} positions have differing logged bases, but the "
            f"attack needs {target} to aim M at 2 * m_min. Raise key_length "
            f"above {params.key_length}."
        )
    return _declare_avoiding_both_logs(
        bob, charlie, set(split[:target]), message_bit
    )


def _attack_params() -> ProtocolParams:
    """Return the parameter set every simulated run here uses."""
    return ProtocolParams(key_length=ATTACK_KEY_LENGTH)


def _classify(transcript: SessionTranscript) -> str:
    """Name the protocol outcome of one run.

    Parameters
    ----------
    transcript : SessionTranscript
        A completed run.

    Returns
    -------
    str
        One of ``"repudiated"``, ``"bob-accepted-charlie-no-verdict"``,
        ``"no-verdict-at-bob"``, ``"transferable"`` or ``"rejected"``. The
        distinction the audit turned on is between the first two: a *reject
        verdict* from Charlie is a repudiation, and a refusal to score is not.
    """
    if transcript.repudiated:
        return "repudiated"
    bob = transcript.bob
    if bob is not None and bob.accepted and Party.CHARLIE in transcript.aborts_by_party:
        return "bob-accepted-charlie-no-verdict"
    if Party.BOB in transcript.aborts_by_party:
        return "no-verdict-at-bob"
    if transcript.transferable:
        return "transferable"
    return "rejected"


# --------------------------------------------------------------------------- #
# 1. What M means, across the three modules.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "params", [DEFAULT_PARAMS, DEMO_PARAMS, ProtocolParams(key_length=600)]
)
def test_m_is_the_pooled_count_in_every_repudiation_expression(
    params: ProtocolParams,
) -> None:
    """``repudiation_bound`` and ``..._with_abort`` are one expression, two names.

    The first takes an observed ``M``, the second a floor on it, and they must
    return the same number at the same argument -- otherwise one of them is
    counting a *per-verifier* quantity and the two modules disagree about what
    the guarantee is stated over.
    """
    for count in (1, 13, 100, params.key_length):
        observed = repudiation_bound(params, matched_records=count)
        floored = repudiation_bound_with_abort(
            params, minimum_matched_records=count
        )
        assert observed == pytest.approx(floored, rel=0.0, abs=0.0), (
            f"at M = {count} the per-run form gives {observed} and the "
            f"abort form {floored}; they must be the same expression, so one "
            f"of them is reading M as a per-verifier count."
        )


@pytest.mark.parametrize(
    "params", [DEFAULT_PARAMS, DEMO_PARAMS, ProtocolParams(key_length=600)]
)
def test_the_floor_is_per_verifier_and_the_published_bound_doubles_it(
    params: ProtocolParams,
) -> None:
    """``minimum_matched_count`` is per verifier; the quoted bound uses ``2 m_min``.

    This is the one place the factor of two lives. ``verify`` sees one record at
    a time, so its floor is on ``m_R``; a *reject verdict* from Charlie means
    both verifiers cleared it, hence ``M >= 2 m_min``, which is what
    ``enforced_repudiation_bound`` evaluates.
    """
    floor = minimum_matched_count(params)
    assert 1 <= floor <= params.key_length
    assert enforced_repudiation_bound(params) == repudiation_bound(
        params, matched_records=2 * floor
    ), (
        "the published a-priori bound must be the per-run bound at twice the "
        "per-verifier floor; a mismatch means verify and analysis disagree on "
        "whether M is pooled."
    )


def test_the_published_a_priori_number_is_the_one_the_defaults_earn() -> None:
    """Pins the three headline figures so a docs edit cannot drift from the code.

    ``6.9e-10`` is the (IND)-dependent average and is *not* published;
    ``4.4e-05`` is what Bob's own floor alone buys; ``1.9e-09`` is what a reject
    verdict from Charlie buys and is the number ``README.md`` and
    ``docs/PHASE2.md`` quote.
    """
    floor = minimum_matched_count(DEFAULT_PARAMS)
    assert floor == 36555
    assert repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=floor
    ) == pytest.approx(4.3614e-05, rel=1e-4)
    assert enforced_repudiation_bound(DEFAULT_PARAMS) == pytest.approx(
        1.9022e-09, rel=1e-4
    )
    assert averaged_repudiation_bound(
        DEFAULT_PARAMS, signer_sees_recipient_bases=False
    ) == pytest.approx(6.9173e-10, rel=1e-4)


def test_the_averaged_number_cannot_be_obtained_without_naming_its_hypothesis(
) -> None:
    """Both barriers on the ``6.9e-10`` still stand after reconciliation."""
    with pytest.raises(TypeError):
        averaged_repudiation_bound(DEFAULT_PARAMS)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="raw"):
        averaged_repudiation_bound(
            DEFAULT_PARAMS, signer_sees_recipient_bases=True
        )
    with pytest.raises(TypeError):
        repudiation_bound(DEFAULT_PARAMS)  # type: ignore[call-arg]


def test_the_package_surface_exports_the_floor_and_the_number_it_buys() -> None:
    """Phase 3 onwards must not have to reach into ``sih141.protocol.verify``.

    ``docs/PHASE2.md`` section 1 states that every public name is re-exported
    from the package; the abort rule's names were the ones that were not.
    """
    import sih141.protocol as protocol

    for name in (
        "HONEST_ABORT_BUDGET",
        "AbortReason",
        "VerificationAbort",
        "MatchedSetTooSmall",
        "minimum_matched_count",
        "enforced_repudiation_bound",
        "verify_or_abort",
    ):
        assert name in protocol.__all__, f"{name} missing from __all__"
        assert getattr(protocol, name, None) is not None, f"{name} unimportable"
    assert len(set(protocol.__all__)) == len(protocol.__all__)


# --------------------------------------------------------------------------- #
# 2. Which number a run quotes.
# --------------------------------------------------------------------------- #


def test_a_completed_run_quotes_the_per_run_bound_at_its_observed_m() -> None:
    """The transcript's guarantee is the conditional bound, not the average."""
    params = _attack_params()
    transcript = QDSSession(params, rng=np.random.default_rng(7)).run(0)

    pooled = transcript.pooled_matched_count
    assert pooled is not None
    assert transcript.bob is not None and transcript.charlie is not None
    assert pooled == transcript.bob.matched_count + transcript.charlie.matched_count
    assert transcript.repudiation_guarantee == repudiation_bound(
        params, matched_records=pooled
    )
    assert transcript.repudiation_guarantee != averaged_repudiation_bound(
        params, signer_sees_recipient_bases=False
    )


def test_a_run_with_no_verdict_quotes_no_guarantee() -> None:
    """A refusal to score contributes no matched count and no bound.

    Counting an abort's missing record as ``m = 0`` would *flatter* the pooled
    total's exponent nowhere and would silently turn a plumbing failure into an
    evidence statement, so the property is ``None`` instead.
    """
    params = _attack_params()
    transcript = QDSSession(
        params, rng=np.random.default_rng(11), signer=starving_signer
    ).run(0)
    assert transcript.aborted
    assert transcript.pooled_matched_count is None
    assert transcript.repudiation_guarantee is None
    assert "EVIDENCE:" not in transcript.summary()


def test_the_summary_puts_the_honest_number_in_front_of_the_reader() -> None:
    """The line exists, names ``M``, and carries the conditional bound."""
    transcript = QDSSession(
        _attack_params(), rng=np.random.default_rng(13)
    ).run(1)
    evidence = [
        line
        for line in transcript.summary().splitlines()
        if line.startswith("EVIDENCE:")
    ]
    assert len(evidence) == 1
    assert f"M = m_B + m_C = {transcript.pooled_matched_count}" in evidence[0]
    assert "assumes nothing about the signer" in evidence[0]


# --------------------------------------------------------------------------- #
# 3. The attack, end to end.
# --------------------------------------------------------------------------- #


def test_the_chosen_key_length_actually_exercises_the_floor() -> None:
    """Non-vacuity: the floor must exceed the ``M = 13`` the attack pins.

    Without this the attack test would pass on a parameter set where the rule is
    inert, which is exactly how a security test becomes decoration.
    """
    floor = minimum_matched_count(_attack_params())
    assert floor > 13, (
        f"floor is {floor} at L = {ATTACK_KEY_LENGTH}, which does not exceed "
        f"the M = 13 the starving signer pins; the attack test would be vacuous"
    )
    assert minimum_matched_count(DEFAULT_PARAMS) > 13


def test_the_adaptive_declaration_attack_is_prevented_by_the_floor() -> None:
    """The [CRITICAL] attack now reaches no verdict at all, on every seed.

    Before the abort rule this signer repudiated at ``0.45``--``0.58`` against a
    published ``6.9e-10``. It pins ``M = 13`` regardless of ``L``, so at any key
    length whose floor exceeds ``13`` both verifiers refuse to score and there is
    no verdict to repudiate. The outcome is recorded, not raised: ``run`` returns
    a transcript.
    """
    params = _attack_params()
    outcomes: Counter[str] = Counter()
    for seed in range(TRIALS):
        transcript = QDSSession(
            params, rng=np.random.default_rng(seed), signer=starving_signer
        ).run(0)
        outcomes[_classify(transcript)] += 1

        assert transcript.aborted, f"seed {seed}: the floor did not fire"
        assert not transcript.repudiated
        assert not transcript.transferable
        assert not transcript.is_complete
        assert set(transcript.aborts_by_party) == {Party.BOB, Party.CHARLIE}
        assert "NO VERDICT" in transcript.summary()
        assert SessionTranscript.from_json(transcript.to_json()) == transcript

    assert outcomes == Counter({"no-verdict-at-bob": TRIALS}), (
        f"expected every run to stop at Bob's floor, got {dict(outcomes)}"
    )


def test_the_attack_is_bounded_where_the_floor_is_inert_and_no_claim_is_made(
) -> None:
    """Below ``L = 267`` the floor degenerates -- and so does the published bound.

    ``DEMO_PARAMS`` has no statistical power to spend, ``minimum_matched_count``
    returns ``1``, and the attack still succeeds about half the time. That is not
    a silent success: the number this parameter set publishes is ``0.9995``, the
    docstring says "no security claim attaches to this set", and the measured
    rate is comfortably below it. The failure is honest at both ends.
    """
    assert minimum_matched_count(DEMO_PARAMS) == 1
    published = enforced_repudiation_bound(DEMO_PARAMS)
    assert published > 0.99

    successes = 0
    for seed in range(TRIALS):
        transcript = QDSSession(
            DEMO_PARAMS, rng=np.random.default_rng(seed), signer=starving_signer
        ).run(0)
        assert transcript.pooled_matched_count == 13
        assert transcript.repudiation_guarantee == pytest.approx(
            repudiation_bound(DEMO_PARAMS, matched_records=13)
        )
        successes += transcript.repudiated

    rate = successes / TRIALS
    assert rate <= published, (
        f"repudiation rate {rate:.2f} exceeds the number this parameter set "
        f"publishes ({published:.4f}); that would be a real violation rather "
        f"than a weak parameter set"
    )
    assert transcript.repudiation_guarantee is not None
    assert transcript.repudiation_guarantee > 0.99


def test_the_residual_route_yields_a_no_verdict_and_never_a_reject_verdict(
) -> None:
    """The limitation section 4b-iii documents, pinned as measured.

    A signer aiming ``M`` at ``2 m_min`` can leave Charlie below his own floor
    while Bob accepts. That outcome is real and is *not* closed by the
    per-verifier rule -- closing it needs a pooled floor and one extra classical
    message. What the test asserts is the framing the bound relies on: the run
    ends in a recorded abort, never in a reject verdict, so
    ``enforced_repudiation_bound`` is not violated and nothing is transferred
    silently.
    """
    params = _attack_params()
    outcomes: Counter[str] = Counter()
    for seed in range(TRIALS):
        transcript = QDSSession(
            params, rng=np.random.default_rng(200 + seed), signer=aiming_signer
        ).run(0)
        outcomes[_classify(transcript)] += 1
        assert not transcript.repudiated, (
            f"seed {seed} produced an actual repudiation verdict against the "
            f"aimed-at-2*m_min route; enforced_repudiation_bound "
            f"({enforced_repudiation_bound(params):.3e}) claims this cannot "
            f"happen except with that probability"
        )
        if transcript.aborted:
            assert "NO VERDICT" in transcript.summary()
            assert "not a rejection" in transcript.summary()

    assert outcomes["repudiated"] == 0
    assert outcomes["bob-accepted-charlie-no-verdict"] > 0, (
        "the documented residual outcome never occurred, so this test is no "
        "longer exercising the route section 4b-iii describes; re-derive the "
        "target before weakening the assertion"
    )


# --------------------------------------------------------------------------- #
# 4. Honest operation is undisturbed.
# --------------------------------------------------------------------------- #


def test_honest_runs_never_trip_the_floor_and_beat_the_published_number(
) -> None:
    """Seeded honest sessions: two verdicts, a transfer, and a stronger bound.

    Two properties in one sweep, because they are two halves of the same
    composition. The floor is a security control, so what would make it a bad
    one is a false positive on an honest run -- none here, with the margin
    asserted rather than eyeballed. And every verdict rests on at least
    ``2 m_min`` records, so each run's *own* bound is at least as strong as the
    a-priori figure the package publishes, which is what makes that figure true.
    """
    params = _attack_params()
    floor = minimum_matched_count(params)
    published = enforced_repudiation_bound(params)
    smallest = params.key_length
    for seed in range(TRIALS):
        transcript = QDSSession(params, rng=np.random.default_rng(seed)).run(
            seed % 2
        )
        assert not transcript.aborted, (
            f"seed {seed} aborted on an honest run at L = {params.key_length}; "
            f"the floor is {floor} and the honest mean is "
            f"{params.expected_matched}"
        )
        assert transcript.transferable
        assert transcript.aborts == ()

        guarantee = transcript.repudiation_guarantee
        assert guarantee is not None
        assert guarantee <= published, (
            f"seed {seed}: the run's own bound {guarantee:.3e} is weaker than "
            f"the published a-priori {published:.3e}, so the floor did not "
            f"deliver what enforced_repudiation_bound presumes"
        )
        for result in transcript.results:
            smallest = min(smallest, result.matched_count)
    assert smallest > floor, (
        f"the smallest matched count observed was {smallest} against a floor "
        f"of {floor}; the rule is running closer to honest operation than its "
        f"derivation allows"
    )


@pytest.mark.parametrize(
    "key_length", [192, 267, 300, 360, 600, 1200, 6912, 115200]
)
def test_the_honest_abort_probability_stays_inside_its_budget(
    key_length: int,
) -> None:
    """The analytic form of the same statement, over the whole range of ``L``.

    Stronger than any number of sampled runs: ``matched_shortfall_probability``
    sums the exact binomial lower tail, so this asserts the design target
    directly at key lengths a simulated run could never reach.
    """
    params = ProtocolParams(key_length=key_length)
    floor = minimum_matched_count(params)
    cost = matched_shortfall_probability(params, minimum_matched=floor)
    assert cost <= HONEST_ABORT_BUDGET, (
        f"L = {key_length}: floor {floor} costs an honest verifier {cost:.3e}, "
        f"above the {HONEST_ABORT_BUDGET:.3e} budget the derivation promises"
    )
    assert 2.0 * cost < enforced_repudiation_bound(params), (
        f"L = {key_length}: the abort rule ({2 * cost:.3e} per run) has become "
        f"the dominant way an honest run fails, against a repudiation bound of "
        f"{enforced_repudiation_bound(params):.3e}"
    )
