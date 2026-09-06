"""Cross-module agreement between the abort rule and the repudiation bounds.

Three separate repairs landed on this protocol at once -- the matched-count
abort rule in :mod:`sih141.protocol.verify`, the split of the repudiation bound
into a per-run and an ``M``-averaged form in :mod:`sih141.protocol.analysis`,
and the no-verdict plumbing in :mod:`sih141.protocol.session`. Each is tested in
its own file. What is tested *here* is that they agree, because the failure mode
the audit found was never a wrong formula: it was a correct formula published
under the wrong hypothesis, and that is exactly the kind of defect a per-module
test suite cannot see.

Five things are pinned.

1. **What ``M`` means.** Every expression in the repudiation family counts
   *matched records held by the two verifiers together*, ``M = m_B + m_C``, not
   one verifier's own count. ``minimum_matched_count`` is per-verifier and
   ``minimum_pooled_matched_count`` is over the pair; the relation between them
   -- ``M_min > 2 m_min``, strictly, at every non-degenerate key length -- is
   asserted rather than assumed, because it is the whole content of the pooled
   rule.
2. **Which number a run quotes.** A completed run quotes
   :attr:`~sih141.protocol.session.SessionTranscript.repudiation_guarantee`, the
   per-run bound at the *observed* ``M``. The a-priori figure the package is
   entitled to publish is
   :func:`~sih141.protocol.verify.enforced_repudiation_bound`, which reads the
   floors :func:`~sih141.protocol.verify.verify` actually applies. Neither is
   :func:`~sih141.protocol.analysis.averaged_repudiation_bound`.
3. **The adaptive-declaration repudiation attack is prevented**, not merely
   bounded, wherever a floor exceeds the matched count the attack can pin. It
   pins ``M = 13`` at every ``L``; the per-verifier floor exceeds ``13`` for
   every ``L >= 340`` and the pooled floor for every ``L >= 155``, so
   ``DEMO_PARAMS`` is now protected where it was not.
4. **The split-coin route is closed, and the closure is not vacuous.** A signer
   aiming ``M`` at ``2 m_min`` used to leave Charlie below *his* floor while Bob
   accepted, at about ``1/2``. Two tests run the same attack with the count
   exchange off and on: the first asserts it still succeeds without the exchange
   -- otherwise the second would pass for the wrong reason -- and the second
   asserts a joint no-verdict on every seed.
5. **The joint consequence, separately.** The pooled floor alone would leave
   Alice a best response at ``M = M_min``, worth ``eps ** (3 - 2 sqrt 2)``
   independent of ``L``. A rigged symmetriser places a run at that point of the
   coin space and pins what each rule does there.

Notes
-----
Determinism (D3)
    Every session here is seeded through an injected
    :class:`numpy.random.Generator`. Nothing reads global randomness.
No machine learning (D4)
    Closed forms, counting, and simulated runs of the protocol itself.
"""

from __future__ import annotations

import math
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
from sih141.protocol.tally import no_count_exchange
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    AbortReason,
    enforced_repudiation_bound,
    guaranteed_pooled_matched_count,
    minimum_matched_count,
    minimum_pooled_matched_count,
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


def aiming_at_the_pooled_floor(
    message_bit: int,
    keys: tuple[PrivateKey, PrivateKey],
    params: ProtocolParams,
    *,
    records: Mapping[int, Mapping[Party, RecipientRecord]],
) -> Signature:
    """Aim ``M`` at exactly ``M_min``: Alice's best response to the pooled floor.

    The smallest total that clears the pooled floor, so the pooled check passes
    and only the *split* is left to attack. Otherwise identical to
    :func:`aiming_signer`: every kept record is on a position where the two logs
    used different bases, and every kept record is correct, so no rate deviates
    anywhere and no exponent has anything to bound.

    Parameters
    ----------
    message_bit : int
        The bit being signed.
    keys : tuple of PrivateKey
        Alice's committed pair. Unused.
    params : ProtocolParams
        The parameter set; its pooled floor sets the target.
    records : mapping
        Keyword-only. Both recipients' raw logs, keyed by bit then party.

    Returns
    -------
    Signature
        A declaration whose matched total is
        ``minimum_pooled_matched_count(params)``.

    Raises
    ------
    ValueError
        If the logs offer fewer split positions than the target needs.
    """
    del keys
    bob = records[message_bit][Party.BOB]
    charlie = records[message_bit][Party.CHARLIE]
    target = minimum_pooled_matched_count(params)
    split = [
        i
        for i in range(params.key_length)
        if bob.entries[i].basis != charlie.entries[i].basis
    ]
    if len(split) < target:
        raise ValueError(
            f"only {len(split)} positions have differing logged bases, but the "
            f"attack needs {target} to aim M at M_min. Raise key_length above "
            f"{params.key_length}."
        )
    return _declare_avoiding_both_logs(
        bob, charlie, set(split[:target]), message_bit
    )


def _never_swap(
    records: Mapping[Party | str, RecipientRecord],
    *,
    rng: np.random.Generator | None = None,
) -> dict[Party, RecipientRecord]:
    """Symmetrise with a coin that never comes up heads: nobody swaps.

    One point of the coin space, of probability ``2 ** -L``, used to place a run
    where a probabilistic demonstration could never reach. The exchange still
    *happened* -- the records are flagged symmetrised -- and what is rigged is
    its outcome. An unconditional bound has to survive every point of that
    space, so pinning the worst one is the honest test of a rule that claims to
    be unconditional.

    Parameters
    ----------
    records : mapping of Party to RecipientRecord
        The raw pair from distribution.
    rng : numpy.random.Generator or None, optional
        Keyword-only, accepted for signature compatibility and unused: no coins
        are tossed, so the session's stream is identical to the honest arm's.

    Returns
    -------
    dict of Party to RecipientRecord
        Each verifier's own raw entries, flagged symmetrised.
    """
    del rng
    return {
        party: RecipientRecord(
            party=party,
            message_bit=records[party].message_bit,  # type: ignore[index]
            entries=records[party].entries,  # type: ignore[index]
            symmetrised=True,
        )
        for party in (Party.BOB, Party.CHARLIE)
    }


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
        ``"both-no-verdict"``, ``"no-verdict-at-bob"``, ``"transferable"`` or
        ``"rejected"``. Three of those are failures of different kinds and the
        distinctions are the whole subject of this file: a *reject verdict* from
        Charlie is a repudiation; Bob accepting what Charlie cannot score is a
        transfer failure that no exponent bounds; and a *joint* no-verdict
        transfers nothing and is a denial of service, which the signer could
        mount by not signing at all.
    """
    if transcript.repudiated:
        return "repudiated"
    bob = transcript.bob
    aborted = transcript.aborts_by_party
    if bob is not None and bob.accepted and Party.CHARLIE in aborted:
        return "bob-accepted-charlie-no-verdict"
    if set(aborted) == {Party.BOB, Party.CHARLIE}:
        return "both-no-verdict"
    if Party.BOB in aborted:
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
def test_the_floor_is_per_verifier_and_the_published_bound_pools_it(
    params: ProtocolParams,
) -> None:
    """Two floors, one published bound, and the bound uses whichever binds.

    ``minimum_matched_count`` is per verifier and
    ``minimum_pooled_matched_count`` is over the pair. A run reaches verdicts
    only when *both* hold, so the guaranteed evidence base is
    ``max(2 m_min, M_min)`` -- which is what ``enforced_repudiation_bound``
    evaluates, and the one place the relation between the two floors lives.
    """
    floor = minimum_matched_count(params)
    pooled_floor = minimum_pooled_matched_count(params)
    assert 1 <= floor <= params.key_length
    assert 1 <= pooled_floor <= 2 * params.key_length
    guaranteed = guaranteed_pooled_matched_count(params)
    assert guaranteed == max(2 * floor, pooled_floor)
    assert enforced_repudiation_bound(params) == repudiation_bound(
        params, matched_records=guaranteed
    ), (
        "the published a-priori bound must be the per-run bound at the pooled "
        "floor the shipped rules guarantee; a mismatch means verify and "
        "analysis disagree on whether M is pooled."
    )


@pytest.mark.parametrize(
    "key_length", [140, 192, 267, 300, 360, 600, 1200, 6912, 115200]
)
def test_the_pooled_floor_strictly_exceeds_twice_the_per_verifier_one(
    key_length: int,
) -> None:
    """``M_min > 2 m_min`` is the whole content of the pooled rule.

    The split-coin signer aims ``M`` at exactly ``2 m_min``: the largest total
    that still leaves both per-verifier floors satisfiable while starving one of
    them. If the pooled floor did not strictly exceed that, the rule would price
    the attack instead of refusing it.

    The inequality holds from ``L = 140`` upwards -- the first key length at
    which the pooled Chernoff form has enough power to reach ``3``. Below it
    both floors are degenerate together and no claim is made
    (``test_the_attack_is_bounded_where_both_floors_are_inert_and_no_claim_is_made``).
    """
    params = ProtocolParams(key_length=key_length)
    floor = minimum_matched_count(params)
    pooled_floor = minimum_pooled_matched_count(params)
    assert pooled_floor > 2 * floor, (
        f"L = {key_length}: M_min = {pooled_floor} does not exceed "
        f"2 m_min = {2 * floor}, so a declaration aimed at 2 m_min would clear "
        f"the pooled floor and the split-coin route would still be open"
    )


@pytest.mark.parametrize("key_length", [300, 360, 600, 1200, 6912, 115200])
def test_the_margin_between_the_floors_matches_its_closed_form(
    key_length: int,
) -> None:
    """``M_min - 2 m_min ~ (2 - sqrt 2) sqrt(2 mu ln(1/eps))``, and it grows.

    Checked against the algebra rather than against a table, so an arithmetic
    change that shrank the margin towards zero fails here rather than in a
    security argument -- and so that "the margin grows like ``sqrt(L)``", which
    is why the closure is not an artefact of a short demonstration key, is a
    measured statement.

    Only over the range where *both* floors are non-degenerate (``L >= 267``);
    below it ``m_min`` is clamped to ``1`` and the two-term expansion does not
    describe the difference.
    """
    params = ProtocolParams(key_length=key_length)
    margin = minimum_pooled_matched_count(params) - 2 * minimum_matched_count(
        params
    )
    predicted = (2.0 - math.sqrt(2.0)) * math.sqrt(
        2.0 * params.expected_matched * -math.log(HONEST_ABORT_BUDGET)
    )
    # Two ceilings, so the margin can sit up to two records either side.
    assert abs(margin - predicted) <= 3.0, (
        f"L = {key_length}: margin {margin} against a predicted "
        f"{predicted:.1f}"
    )
    assert margin > 0


def test_the_published_a_priori_number_is_the_one_the_defaults_earn() -> None:
    """Pins the headline figures so a docs edit cannot drift from the code.

    ``6.9e-10`` is the (IND)-dependent average and is *not* published;
    ``4.4e-05`` is what Bob's own floor alone would buy; ``1.9e-09`` is what the
    per-verifier floor at both verifiers buys, and was the published figure
    while the third outcome it leaves open had to be quoted beside it;
    ``1.4e-09`` is what the pooled floor buys and is the number ``README.md``
    and ``docs/PHASE2.md`` quote, with nothing left to quote beside it.
    """
    floor = minimum_matched_count(DEFAULT_PARAMS)
    pooled_floor = minimum_pooled_matched_count(DEFAULT_PARAMS)
    assert floor == 36555
    assert pooled_floor == 74190
    assert repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=floor
    ) == pytest.approx(4.3614e-05, rel=1e-4, abs=0)
    assert repudiation_bound_with_abort(
        DEFAULT_PARAMS, minimum_matched_records=2 * floor
    ) == pytest.approx(1.9022e-09, rel=1e-4, abs=0)
    assert enforced_repudiation_bound(DEFAULT_PARAMS) == pytest.approx(
        1.4139e-09, rel=1e-4
    , abs=0)
    assert averaged_repudiation_bound(
        DEFAULT_PARAMS, signer_sees_recipient_bases=False
    ) == pytest.approx(6.9173e-10, rel=1e-4, abs=0)


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
        "minimum_pooled_matched_count",
        "guaranteed_pooled_matched_count",
        "enforced_repudiation_bound",
        "verify_or_abort",
        "CountExchange",
        "MatchedCountMessage",
        "PooledMatchedCounts",
        "matched_count_message",
        "exchange_matched_counts",
        "no_count_exchange",
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
        params,
        rng=np.random.default_rng(11),
        signer=starving_signer,
        # Reading BOTH recipients' raw logs is exactly what this attack does
        # and exactly what the threat model does not allow, so the seam offers
        # them only on request. The flag is carried into the transcript, which
        # is what keeps an insecure-arm number from being quoted as a
        # secure-arm one -- see :ref:`two-log-signer`.
        signer_sees_recipient_logs=True,
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
            params,
            rng=np.random.default_rng(seed),
            signer=starving_signer,
            signer_sees_recipient_logs=True,
        ).run(0)
        outcomes[_classify(transcript)] += 1

        assert transcript.aborted, f"seed {seed}: the floor did not fire"
        assert not transcript.repudiated
        assert not transcript.transferable
        assert not transcript.is_complete
        assert set(transcript.aborts_by_party) == {Party.BOB, Party.CHARLIE}
        assert "NO VERDICT" in transcript.summary()
        assert SessionTranscript.from_json(transcript.to_json()) == transcript

    assert outcomes == Counter({"both-no-verdict": TRIALS}), (
        f"expected every run to stop at a floor with neither verifier "
        f"reaching a verdict, got {dict(outcomes)}"
    )


def test_the_attack_is_bounded_where_both_floors_are_inert_and_no_claim_is_made(
) -> None:
    """Below ``L = 134`` *both* floors degenerate -- and so does the published bound.

    The two crossovers differ, and the difference is worth pinning: the
    per-verifier floor is inert below ``L = 267`` and the pooled one only below
    ``L = 134``, because the pooled count has twice the mean. So a parameter set
    in between is protected by the pooled rule alone, which is the case
    ``test_the_pooled_floor_protects_a_key_length_the_local_one_cannot`` covers.

    Here both are inert: ``L = 120`` has no statistical power to spend at either
    scale, and the attack still succeeds about half the time. That is not a
    silent success -- the number this parameter set publishes is ``0.999``, and
    the measured rate is comfortably below it. The failure is honest at both
    ends.
    """
    params = ProtocolParams(key_length=120)
    assert minimum_matched_count(params) == 1
    assert minimum_pooled_matched_count(params) == 1
    published = enforced_repudiation_bound(params)
    assert published > 0.99

    successes = 0
    for seed in range(TRIALS):
        transcript = QDSSession(
            params,
            rng=np.random.default_rng(seed),
            signer=starving_signer,
            signer_sees_recipient_logs=True,
        ).run(0)
        assert transcript.pooled_matched_count == 13
        assert transcript.repudiation_guarantee == pytest.approx(
            repudiation_bound(params, matched_records=13)
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


def test_the_pooled_floor_protects_a_key_length_the_local_one_cannot() -> None:
    """``DEMO_PARAMS`` gains a real control it did not have before.

    ``L = 192`` sits between the two crossovers: ``minimum_matched_count`` is
    still ``1`` there and can refuse nothing, while
    ``minimum_pooled_matched_count`` is ``22`` and refuses the ``M = 13`` the
    starving signer pins. The parameter set still carries no security *claim* --
    ``enforced_repudiation_bound`` is ``0.994`` -- but the attack that used to
    land on it half the time now reaches no verdict at all.
    """
    assert minimum_matched_count(DEMO_PARAMS) == 1
    assert minimum_pooled_matched_count(DEMO_PARAMS) == 22

    for seed in range(TRIALS):
        transcript = QDSSession(
            DEMO_PARAMS,
            rng=np.random.default_rng(seed),
            signer=starving_signer,
            signer_sees_recipient_logs=True,
        ).run(0)
        assert not transcript.repudiated
        assert transcript.aborted
        assert set(transcript.aborts_by_party) == {Party.BOB, Party.CHARLIE}
        for abort in transcript.aborts:
            assert abort.reason is AbortReason.POOLED_BELOW_FLOOR
            assert abort.pooled_count == 13
            assert abort.minimum_pooled == 22


def test_the_split_coin_route_is_open_without_the_count_exchange() -> None:
    """The attack, measured on the pre-pooled variant. **This must keep working.**

    ``no_count_exchange`` is the Phase 3 seam that reproduces the rule this
    package shipped before the pooled floor: each verifier applies his own floor
    and nothing else. A signer aiming ``M`` at ``2 m_min`` then leaves Bob
    accepting a signature Charlie cannot score, about half the time, and the run
    reports a transfer failure that no exponent bounds.

    The test asserts the attack *succeeds* here, which is the only way the next
    test means anything: a closure test whose attack was broken would pass for
    the wrong reason. The expected rate is
    ``(1 - P[Binomial(2 m_min, 1/2) = m_min]) / 2``, which is ``0.43`` at this
    key length and tends to ``1/2`` as ``m_min`` grows -- so the measurement is
    checked against that closed form rather than against ``1/2``.
    """
    params = _attack_params()
    floor = minimum_matched_count(params)
    outcomes: Counter[str] = Counter()
    for seed in range(TRIALS):
        transcript = QDSSession(
            params,
            rng=np.random.default_rng(200 + seed),
            signer=aiming_signer,
            signer_sees_recipient_logs=True,
            count_exchange=no_count_exchange,
        ).run(0)
        outcomes[_classify(transcript)] += 1
        assert not transcript.counts_exchanged
        assert "UNPOOLED" in transcript.summary()

    # P[Bin(2 m_min, 1/2) = m_min], the tie in which both verifiers land
    # exactly on the floor and the attack fails.
    tie = math.comb(2 * floor, floor) / 2.0 ** (2 * floor)
    expected = (1.0 - tie) / 2.0
    measured = outcomes["bob-accepted-charlie-no-verdict"] / TRIALS
    assert 0.40 < expected < 0.44
    assert measured > 0.2, (
        f"the split-coin route succeeded only {measured:.2f} of the time "
        f"against a predicted {expected:.2f}; the attack is no longer being "
        f"mounted, so the closure test below would pass vacuously"
    )
    assert outcomes["repudiated"] == 0, (
        "the route is a no-verdict at Charlie, not a reject verdict; a reject "
        "here would mean a rate deviated, which this attack never does"
    )


def test_the_split_coin_route_is_closed_by_the_pooled_floor() -> None:
    """The same attack against the shipped rule: no verdict, at every seed.

    Two independent things close it, and the abort reasons say which one fired
    for whom:

    * ``M = 2 m_min`` is below ``M_min``, so the *pooled* floor refuses -- this
      is what a verifier who cleared his own floor records; and
    * even at ``M >= M_min``, a verifier below his own floor takes the other
      down with him, so the asymmetric outcome is not in the outcome space at
      all (``test_a_verifier_refuses_when_his_counterpart_is_starved``).

    Whichever fires, ``M`` is the same ``2 m_min`` on every run, both verifiers
    record a no-verdict, nothing is transferred, and the run is reportable
    rather than lost.
    """
    params = _attack_params()
    target = 2 * minimum_matched_count(params)
    outcomes: Counter[str] = Counter()
    reasons: Counter[AbortReason] = Counter()
    for seed in range(TRIALS):
        transcript = QDSSession(
            params,
            rng=np.random.default_rng(200 + seed),
            signer=aiming_signer,
            signer_sees_recipient_logs=True,
        ).run(0)
        outcomes[_classify(transcript)] += 1
        assert transcript.counts_exchanged
        assert not transcript.repudiated
        assert not transcript.transferable
        assert set(transcript.aborts_by_party) == {Party.BOB, Party.CHARLIE}
        assert transcript.pooled is not None
        assert transcript.pooled.pooled == target
        assert not transcript.pooled.meets_pooled_floor
        for abort in transcript.aborts:
            reasons[abort.reason] += 1
            # Whatever the label, the pair's total is what was aimed at, and
            # every abort records it.
            assert abort.pooled_count == target
            assert abort.minimum_pooled == minimum_pooled_matched_count(params)
        assert "NO VERDICT" in transcript.summary()
        assert "not a rejection" in transcript.summary()
        assert SessionTranscript.from_json(transcript.to_json()) == transcript

    assert outcomes == Counter({"both-no-verdict": TRIALS}), (
        f"the split-coin route is meant to end in a joint no-verdict on every "
        f"seed, got {dict(outcomes)}"
    )
    assert set(reasons) <= {
        AbortReason.BELOW_FLOOR,
        AbortReason.POOLED_BELOW_FLOOR,
    }
    assert reasons[AbortReason.POOLED_BELOW_FLOOR] > 0, (
        "no run recorded the pooled floor firing, so this test is exercising "
        "the per-verifier rule alone and would have passed before the change"
    )


def test_a_verifier_refuses_when_his_counterpart_is_starved() -> None:
    """The joint consequence, which is what closes the route at ``M >= M_min``.

    A pooled floor alone does not finish the job. Alice's best response to it is
    to aim at ``M = M_min`` exactly and hope the coins leave Charlie under his
    own floor -- an ``eps ** (3 - 2 sqrt 2) = 4.9e-04`` event at the shipped
    budget, *independent of the key length*, so no amount of ``L`` closes it and
    no feasible number of sampled runs would exhibit it.

    So the run is placed at that point of the coin space deliberately, with a
    symmetriser whose coin never comes up heads. Bob then holds every matched
    record and Charlie holds none. Under the per-verifier rule alone Bob accepts
    and Charlie reaches no verdict -- the residual transfer failure, realised.
    Under the shipped rule Bob refuses too, and says why.
    """
    params = _attack_params()
    for seed in range(TRIALS // 2):
        without = QDSSession(
            params,
            rng=np.random.default_rng(700 + seed),
            signer=aiming_at_the_pooled_floor,
            signer_sees_recipient_logs=True,
            symmetriser=_never_swap,
            count_exchange=no_count_exchange,
        ).run(0)
        assert without.bob is not None and without.bob.accepted
        assert without.bob.rate == 0.0
        assert Party.CHARLIE in without.aborts_by_party
        assert not without.transferable

        withit = QDSSession(
            params,
            rng=np.random.default_rng(700 + seed),
            signer=aiming_at_the_pooled_floor,
            signer_sees_recipient_logs=True,
            symmetriser=_never_swap,
        ).run(0)
        assert withit.bob is None, "Bob must not accept what Charlie cannot score"
        assert set(withit.aborts_by_party) == {Party.BOB, Party.CHARLIE}
        bob_abort = withit.aborts_by_party[Party.BOB]
        assert bob_abort.reason is AbortReason.COUNTERPART_BELOW_FLOOR
        # Bob's own evidence was ample: the refusal is about the split.
        assert bob_abort.matched_count >= bob_abort.minimum_matched
        assert bob_abort.pooled_count is not None
        assert bob_abort.minimum_pooled is not None
        assert bob_abort.pooled_count >= bob_abort.minimum_pooled
        assert (
            withit.aborts_by_party[Party.CHARLIE].reason
            is AbortReason.EMPTY_MATCHED_SET
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
    pooled_floor = minimum_pooled_matched_count(params)
    cost = matched_shortfall_probability(params, minimum_matched=floor)
    pooled_cost = matched_shortfall_probability(
        params, minimum_matched=pooled_floor, pooled=True
    )
    for name, value in (("per-verifier", cost), ("pooled", pooled_cost)):
        assert value <= HONEST_ABORT_BUDGET, (
            f"L = {key_length}: the {name} floor costs an honest run "
            f"{value:.3e}, above the {HONEST_ABORT_BUDGET:.3e} budget the "
            f"derivation promises"
        )
    # Three checks now fire on every run -- each verifier's own floor and the
    # pooled one -- so the union bound is what has to stay negligible.
    whole_run = 2.0 * cost + pooled_cost
    assert whole_run <= 3.0 * HONEST_ABORT_BUDGET
    assert whole_run < enforced_repudiation_bound(params), (
        f"L = {key_length}: the abort rules ({whole_run:.3e} per run) have "
        f"become the dominant way an honest run fails, against a repudiation "
        f"bound of {enforced_repudiation_bound(params):.3e}"
    )
