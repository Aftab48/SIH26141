"""Phase C': the recipients' matched-count exchange, and the pooled floor.

Companion to ``tests/test_protocol_verify_abort.py``, which pins the
per-verifier floor. What is pinned *here* is the second floor and the message
that makes it checkable, and the file is organised around the four claims the
pooled rule rests on. Each of them is a place the rule could be wrong while
still looking right.

1. **The pooled law.** ``M = m_B + m_C ~ Binomial(2L, 1/|B|)``, exactly. The
   trap is the reason: after the symmetrisation exchange ``m_B`` and ``m_C`` are
   *not* independent -- given the records, ``m_C = M - m_B`` exactly -- so the
   convolution argument that would give the same answer is invalid. What makes
   the law exact is conservation: the coins re-assign a fixed multiset of ``2L``
   entries whose bases were drawn i.i.d. uniform, so the total matched count is
   a sum of ``2L`` independent indicators and the coins cannot move it. Both
   halves of that are measured: the invariance through the *shipped*
   ``symmetrise_records`` over many coin seeds, and the law itself against the
   exact binomial.
2. **The floor is derived, not chosen.** Recomputed here from the Chernoff lower
   tail at the same ``eps = 2**-64`` the per-verifier floor uses, and checked
   against an exact binomial tail so that the negligible-honest-abort claim is
   measured rather than asserted.
3. **The message is a message.** One integer each way, computed by each
   recipient from his own log, validated as a pair, and replaceable by a seam
   that skips it. Nothing about the exchange reads a position, and a run made
   without it says so in its transcript.
4. **The two counts are about one declaration.** ``m_B + m_C`` is conserved
   across one fixed pair of records against one fixed declaration and is a
   quantity of nothing across two, so the message names the declaration it
   counted and the exchange refuses a pair that names two. Neither the message
   bit nor the key length can see that difference: they agree across every
   declaration for one distribution. The verifier's half of the rule -- what he
   does when the count he is handed names another declaration -- is pinned in
   ``tests/test_protocol_verify_abort.py`` beside the other abort reasons.

Notes
-----
Determinism (D3)
    Every session here is seeded through an injected
    :class:`numpy.random.Generator`, and one test asserts the exchange consumes
    no randomness at all -- which is what keeps a pooled run and a pre-pooled
    run comparable position by position.
No machine learning (D4)
    Counting, one closed form and exact binomial sums.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from sih141.protocol.distribute import distribute_public_key
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
from sih141.protocol.symmetrise import symmetrise_records
from sih141.protocol.tally import (
    MatchedCountMessage,
    PooledMatchedCounts,
    exchange_matched_counts,
    matched_count_message,
    no_count_exchange,
)
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    matched_positions,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

SEED = 20260830

#: Coin seeds per conservation trial. The claim is "M never moves", so the count
#: sets how strong the evidence is, not whether the test means anything.
COIN_SEEDS: int = 120


def _exact_log_binomial_tail(
    trials: int, bases_count: int, below: int
) -> float:
    """Return ``ln P[Binomial(trials, 1/bases_count) < below]``, exactly summed.

    Integer arithmetic throughout, logged only at the end: with ``p = 1/|B|``
    every term is the rational ``C(n, k) (|B| - 1)**(n - k) / |B|**n``, so the
    tail shares one denominator and the numerator is an exact integer sum.
    Floating point cannot be used here -- the individual terms underflow long
    before the tail does, which would silently turn the assertion into
    ``0.0 <= budget``.

    Parameters
    ----------
    trials : int
        ``n``: ``L`` for one verifier's count, ``2L`` for the pair's.
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


def _honest_pair(
    params: ProtocolParams, seed: int
) -> tuple[Signature, dict[Party, RecipientRecord]]:
    """Return ``(declaration, symmetrised records)`` for one honest run.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    seed : int
        Base seed; key generation, distribution and the coins take ``seed``,
        ``seed + 1`` and ``seed + 2``.

    Returns
    -------
    tuple
        The honest declaration and the two post-exchange logs.
    """
    key = generate_private_key(params, 0, rng=np.random.default_rng(seed))
    raw = distribute_public_key(key, params, rng=np.random.default_rng(seed + 1))
    records = symmetrise_records(raw, rng=np.random.default_rng(seed + 2))
    return sign(0, key, params), records


def _with_flipped_eigenvalue(declaration: Signature) -> Signature:
    """Return the same declaration with position ``0``'s eigenvalue negated.

    The smallest possible alteration: same message bit, same length, same
    declared bases, so every field the exchange compares still agrees and only
    the declaration itself has changed. That is exactly the case a check on the
    message bit and the key length cannot see.

    Parameters
    ----------
    declaration : Signature
        The declaration to alter. Not modified: it is frozen.

    Returns
    -------
    Signature
        The altered declaration, which no honest forwarding hop would produce.
    """
    elements = list(declaration.declared_key.elements)
    elements[0] = KeyElement(elements[0].basis, -elements[0].eigenvalue)
    return Signature(
        declaration.message_bit,
        PrivateKey(declaration.message_bit, tuple(elements)),
    )


# ==========================================================================
# 1. The pooled law: conservation, not independence
# ==========================================================================


def test_the_coins_move_each_count_but_never_their_total() -> None:
    """``M`` is coin-independent; ``m_B`` is not. Measured on the shipped code.

    The whole derivation of the pooled floor rests on this: whatever Alice
    prepared and whatever she declared, the symmetrisation coins only decide who
    scores which of a fixed pair of records, so ``m_B + m_C`` is a constant of
    the run. If it were not, ``M`` would be a quantity the coins could move and
    the floor would be bounding the wrong thing.
    """
    params = ProtocolParams(key_length=120)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    declaration = sign(0, key, params)
    raw = distribute_public_key(
        key, params, rng=np.random.default_rng(SEED + 1)
    )
    before = len(matched_positions(declaration, raw[Party.BOB])) + len(
        matched_positions(declaration, raw[Party.CHARLIE])
    )

    totals: set[int] = set()
    bob_counts: set[int] = set()
    for coin_seed in range(COIN_SEEDS):
        records = symmetrise_records(raw, rng=np.random.default_rng(coin_seed))
        bob = len(matched_positions(declaration, records[Party.BOB]))
        charlie = len(matched_positions(declaration, records[Party.CHARLIE]))
        totals.add(bob + charlie)
        bob_counts.add(bob)

    assert totals == {before}, (
        f"the exchange changed the pooled matched count: saw {sorted(totals)} "
        f"against {before} before the coins. m_B + m_C must be conserved."
    )
    assert len(bob_counts) > 1, (
        "m_B never moved across 120 coin seeds, so this test is not "
        "distinguishing conservation from a constant split"
    )


def test_the_pooled_count_is_binomial_over_two_l_draws() -> None:
    """``M ~ Binomial(2L, 1/|B|)`` against the exact distribution.

    Simulated from the specification -- ``2L`` independent uniform basis draws
    against a declaration fixed first -- rather than through the teleportation
    stack, which is expensive and adds nothing: the matched set depends only on
    the basis draws. The comparison is against the exact binomial CDF, so a law
    that was merely *close* (a convolution of dependent marginals, say) would be
    caught.
    """
    length, trials, alphabet = 90, 20000, 3
    generator = np.random.default_rng(SEED)
    declared = generator.integers(alphabet, size=length)
    counts = np.array(
        [
            int(
                (generator.integers(alphabet, size=length) == declared).sum()
                + (generator.integers(alphabet, size=length) == declared).sum()
            )
            for _ in range(trials)
        ]
    )

    draws = 2 * length
    assert counts.mean() == pytest.approx(draws / alphabet, rel=0.01)
    assert counts.var(ddof=1) == pytest.approx(
        draws * (1 / alphabet) * (1 - 1 / alphabet), rel=0.05
    )

    # Exact CDF of Binomial(2L, 1/3), and the Kolmogorov distance to it.
    pmf = np.array(
        [
            math.comb(draws, k)
            * (alphabet - 1) ** (draws - k)
            / alphabet**draws
            for k in range(draws + 1)
        ]
    )
    cdf = np.cumsum(pmf)
    empirical = np.array([(counts <= k).mean() for k in range(draws + 1)])
    # 1.36/sqrt(n) is the two-sided 95% Kolmogorov critical value.
    assert np.abs(empirical - cdf).max() < 1.36 / math.sqrt(trials)


def test_the_two_marginals_are_not_independent_of_each_other() -> None:
    """The trap the derivation has to avoid, stated as a measurement.

    Conditional on the records and the declaration, ``m_C = M - m_B`` exactly:
    the sample correlation of the two counts over the coins is ``-1``. So the
    pooled law cannot be obtained by convolving the two post-exchange marginals,
    even though that convolution happens to give the right answer. It is right
    for the wrong reason, and the right reason is the conservation above.
    """
    params = ProtocolParams(key_length=120)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED + 3))
    declaration = sign(0, key, params)
    raw = distribute_public_key(
        key, params, rng=np.random.default_rng(SEED + 4)
    )

    bob_counts, charlie_counts = [], []
    for coin_seed in range(COIN_SEEDS):
        records = symmetrise_records(raw, rng=np.random.default_rng(coin_seed))
        bob_counts.append(len(matched_positions(declaration, records[Party.BOB])))
        charlie_counts.append(
            len(matched_positions(declaration, records[Party.CHARLIE]))
        )

    correlation = np.corrcoef(bob_counts, charlie_counts)[0, 1]
    assert correlation == pytest.approx(-1.0, abs=1e-9)


# ==========================================================================
# 2. The floor, and where it comes from
# ==========================================================================


def test_the_pooled_floor_matches_an_independent_chernoff_derivation() -> None:
    """Recomputed from ``mu_M = 2L/|B|`` and the budget, not read off the module."""
    log_budget = -math.log(HONEST_ABORT_BUDGET)
    for length in (300, 600, 900, 4096, 115200):
        params = ProtocolParams(key_length=length)
        mean = 2.0 * params.expected_matched
        deviation = math.sqrt(2.0 * log_budget / mean)
        assert deviation < 1.0, "the tail bound must be usable at this L"
        assert minimum_pooled_matched_count(params) == math.ceil(
            (1.0 - deviation) * mean
        )


def test_the_pooled_floor_is_one_where_the_tail_bound_says_nothing() -> None:
    """Its crossover is half the per-verifier one, because the mean is doubled.

    ``L > |B| ln(1/eps)`` for the pooled count against ``L > 2 |B| ln(1/eps)``
    for one verifier's own, i.e. ``133.1`` against ``266.2``. That gap is not
    cosmetic: between the two crossovers the pooled rule is the *only* control
    with any power, which is why ``DEMO_PARAMS`` gains protection it never had.
    """
    crossover = len(DEMO_PARAMS.bases) * -math.log(HONEST_ABORT_BUDGET)
    assert 133.0 < crossover < 134.0

    for length in (1, 9, 24, 120, 133):
        assert minimum_pooled_matched_count(ProtocolParams(key_length=length)) == 1
    assert minimum_pooled_matched_count(ProtocolParams(key_length=192)) == 22
    assert minimum_matched_count(ProtocolParams(key_length=192)) == 1


def test_the_pooled_honest_abort_probability_is_negligible_by_exact_tail() -> None:
    """The claim is measured against the real binomial, not against its own bound.

    ``P[M < M_min]`` is summed exactly over ``Binomial(2L, 1/|B|)``, so a floor
    set too aggressively -- which would abort honest runs and manufacture
    no-verdicts -- fails here even though the Chernoff algebra it came from
    would still be self-consistent.
    """
    log_budget = math.log(HONEST_ABORT_BUDGET)
    for length in (150, 192, 300, 600, 1200):
        params = ProtocolParams(key_length=length)
        floor = minimum_pooled_matched_count(params)
        log_tail = _exact_log_binomial_tail(
            2 * params.key_length, len(params.bases), floor
        )
        assert log_tail <= log_budget, (
            f"L={length}: honest pooled-abort probability e**{log_tail:.1f} "
            f"exceeds the budget e**{log_budget:.1f}"
        )
    # As with the per-verifier floor, the Chernoff step is a bound rather than
    # an identity, so the real tail is far under budget -- the safe direction.
    at_600 = _exact_log_binomial_tail(
        1200, 3, minimum_pooled_matched_count(ProtocolParams(key_length=600))
    )
    assert at_600 < log_budget - math.log(1e10)


def test_the_pooled_floor_is_a_closed_form_in_the_parameters_only() -> None:
    """Deterministic, data-free and monotone in ``L`` (D3, D4)."""
    params = ProtocolParams(key_length=4096)
    assert minimum_pooled_matched_count(params) == (
        minimum_pooled_matched_count(ProtocolParams(key_length=4096))
    )
    lengths = (300, 600, 1200, 2400, 4800)
    floors = [
        minimum_pooled_matched_count(ProtocolParams(key_length=length))
        for length in lengths
    ]
    assert floors == sorted(floors)
    assert floors[0] < floors[-1]
    # A smaller alphabet matches more often, so the same L supports a higher
    # floor -- the rule reads |B|, it does not assume three bases.
    two_basis = ProtocolParams(key_length=600, bases=("X", "Z"))
    assert minimum_pooled_matched_count(two_basis) > (
        minimum_pooled_matched_count(ProtocolParams(key_length=600))
    )


def test_the_pooled_floor_needs_a_parameter_set() -> None:
    """It can only be read off a parameter set, never guessed."""
    with pytest.raises(TypeError, match="must be a ProtocolParams"):
        minimum_pooled_matched_count({"key_length": 600})  # type: ignore[arg-type]


def test_an_honest_run_clears_the_pooled_floor_by_a_wide_margin() -> None:
    """Above the crossover the control has to be invisible on honest evidence."""
    params = ProtocolParams(key_length=360)
    floor = minimum_pooled_matched_count(params)
    for seed in range(8):
        transcript = QDSSession(
            params, rng=np.random.default_rng(SEED + seed)
        ).run(seed % 2)
        assert not transcript.aborted
        assert transcript.pooled is not None
        assert transcript.pooled.meets_every_floor
        # Not merely above the floor: nowhere near it, which is the point.
        assert transcript.pooled.pooled > 2 * floor


# ==========================================================================
# 3. The message
# ==========================================================================


def test_a_message_counts_exactly_what_the_verdict_will_score() -> None:
    """The announced count and the scored count are one computation.

    If they could differ, a verifier could clear the pooled floor on one number
    and reach a verdict on another, which is the one way the exchange could be
    made meaningless without looking wrong.
    """
    params = ProtocolParams(key_length=300)
    declaration, records = _honest_pair(params, SEED + 5)
    for party, record in records.items():
        message = matched_count_message(declaration, record, params)
        assert message.party is party
        assert message.key_length == params.key_length
        assert message.message_bit == record.message_bit
        assert message.matched_count == len(
            matched_positions(declaration, record)
        )


def test_a_message_carries_a_count_and_no_positions() -> None:
    """The privacy property, asserted on the type rather than argued for.

    A recipient who learned *which* positions the other matched would hold
    evidence the threat model does not give him -- half of it is exactly what
    symmetrisation hid, and a recipient forger's advantage is positional. So the
    message is checked to be five scalars and nothing else.

    The fifth, ``declaration_digest``, is the one that has to be argued rather
    than counted: it is a function of the *declaration*, which both recipients
    already hold, and of nothing else. The test below pins that -- two logs that
    match at different positions produce the same digest -- so the field cannot
    be carrying anything about the sender's log.
    """
    message = MatchedCountMessage("Bob", 0, 204, 600)
    blob = json.loads(json.dumps(message.to_dict()))
    assert set(blob) == {
        "party",
        "message_bit",
        "matched_count",
        "key_length",
        "declaration_digest",
    }
    for value in blob.values():
        assert value is None or isinstance(value, (int, str))
    assert MatchedCountMessage.from_dict(blob) == message


def test_the_digest_names_the_declaration_and_nothing_about_a_log() -> None:
    """One declaration, one digest -- whatever either recipient measured.

    The privacy half of the binding: if the digest depended on the record it
    would be a positional leak dressed as a checksum, and if it did not depend
    on the declaration it could not catch two counts made against two
    declarations. Both halves are measured here on the shipped function.
    """
    params = ProtocolParams(key_length=300)
    declaration, records = _honest_pair(params, SEED + 11)
    messages = {
        party: matched_count_message(declaration, record, params)
        for party, record in records.items()
    }
    bob, charlie = messages[Party.BOB], messages[Party.CHARLIE]
    # Different logs, different counts, one declaration: one digest.
    assert bob.matched_count != charlie.matched_count
    assert bob.declaration_digest == charlie.declaration_digest
    assert isinstance(bob.declaration_digest, str) and bob.declaration_digest

    # A different declaration over the *same* log is a different digest.
    altered = _with_flipped_eigenvalue(declaration)
    assert matched_count_message(
        altered, records[Party.BOB], params
    ).declaration_digest != bob.declaration_digest

    # It survives the wire unchanged, and it is the same 32 characters in every
    # process: a message is compared against one that was serialised, restored,
    # and possibly written by another interpreter, so a salted value -- the
    # builtin hash() is one -- would make the check pass or fail at random.
    restored = MatchedCountMessage.from_dict(
        json.loads(json.dumps(bob.to_dict()))
    )
    assert restored.declaration_digest == bob.declaration_digest
    assert restored == bob
    pinned = Signature(
        0,
        PrivateKey(
            0,
            (
                KeyElement("X", 1),
                KeyElement("Z", -1),
                KeyElement("Y", 1),
            ),
        ),
    )
    assert matched_count_message(
        pinned,
        RecipientRecord.from_measurements("Bob", 0, ["X", "X", "X"], [1, 1, 1]),
        ProtocolParams(key_length=3),
    ).declaration_digest == "10a9a600e3b317cb4ab3617e542e34cd", (
        "the digest of a fixed declaration moved. If the encoding changed on "
        "purpose, re-pin the constant; if it did not, the digest is a function "
        "of something other than the declaration -- a per-process value such as "
        "the builtin hash(), an address, or a clock -- and two messages written "
        "by two processes can no longer be compared at all"
    )


def test_alice_sends_no_matched_count() -> None:
    """She signs, holds no record and is not a party to the exchange."""
    with pytest.raises(ValueError, match="Alice sends no matched-count"):
        MatchedCountMessage("Alice", 0, 1, 600)


def test_a_message_cannot_claim_more_matches_than_positions() -> None:
    """The matched set is a subset of the key positions."""
    with pytest.raises(ValueError, match="cannot exceed"):
        MatchedCountMessage("Bob", 0, 601, 600)


def test_the_exchange_is_symmetric_in_the_two_messages() -> None:
    """Both recipients must reach the same pooled view, or the rule is not joint."""
    params = ProtocolParams(key_length=600)
    bob = MatchedCountMessage("Bob", 0, 210, 600)
    charlie = MatchedCountMessage("Charlie", 0, 190, 600)
    first = exchange_matched_counts(
        {Party.BOB: bob, Party.CHARLIE: charlie}, params
    )
    second = exchange_matched_counts(
        {Party.CHARLIE: charlie, Party.BOB: bob}, params
    )
    assert first == second
    assert first.pooled == 400
    assert first.counterpart_of(Party.BOB) == 190
    assert first.counterpart_of(Party.CHARLIE) == 210
    assert first.count_for(Party.BOB) == 210
    assert first.meets_every_floor


def test_the_exchange_reports_which_floor_failed() -> None:
    """The pooled total and the split are different findings and read differently."""
    params = ProtocolParams(key_length=600)  # m_min = 67, M_min = 212
    thin = exchange_matched_counts(
        {
            Party.BOB: MatchedCountMessage("Bob", 0, 68, 600),
            Party.CHARLIE: MatchedCountMessage("Charlie", 0, 68, 600),
        },
        params,
    )
    assert thin.pooled == 136
    assert not thin.meets_pooled_floor
    assert thin.parties_below_floor == ()
    assert not thin.meets_every_floor
    assert "Pooled floor NOT met" in thin.summary()

    lopsided = exchange_matched_counts(
        {
            Party.BOB: MatchedCountMessage("Bob", 0, 260, 600),
            Party.CHARLIE: MatchedCountMessage("Charlie", 0, 60, 600),
        },
        params,
    )
    assert lopsided.meets_pooled_floor
    assert lopsided.parties_below_floor == (Party.CHARLIE,)
    assert not lopsided.meets_every_floor
    assert "Below the per-verifier floor: Charlie" in lopsided.summary()


def test_a_run_landing_exactly_on_a_floor_meets_it() -> None:
    """``>=``, not ``>``, and ``<``, not ``<=``, at both floors.

    Both floors are derived as "abort iff *below*": ``m_min = ceil((1 - d) mu)``
    and ``M_min`` likewise, and the honest-abort budget is computed for
    ``P[count < floor]``. A run landing exactly on a floor is therefore inside
    the budget and must be scored -- shifting either comparison by one would
    refuse runs the derivation counts as honest, and would do it invisibly,
    since every other case in this file sits well clear of the boundary.
    """
    params = ProtocolParams(key_length=600)
    floor = minimum_matched_count(params)
    pooled_floor = minimum_pooled_matched_count(params)
    assert (floor, pooled_floor) == (67, 212)
    half = pooled_floor - pooled_floor // 2

    def view(bob: int, charlie: int) -> PooledMatchedCounts:
        """Return an exchange with the two counts and this run's floors.

        Parameters
        ----------
        bob, charlie : int
            ``m_B`` and ``m_C``.

        Returns
        -------
        PooledMatchedCounts
        """
        return PooledMatchedCounts(
            bob, charlie, floor, pooled_floor, params.key_length, 0
        )

    on_the_pooled_floor = view(half, pooled_floor - half)
    assert on_the_pooled_floor.pooled == pooled_floor
    assert on_the_pooled_floor.meets_pooled_floor
    assert on_the_pooled_floor.parties_below_floor == ()
    assert on_the_pooled_floor.meets_every_floor
    assert "Every floor met." in on_the_pooled_floor.summary()

    one_short = view(half, pooled_floor - half - 1)
    assert one_short.pooled == pooled_floor - 1
    assert not one_short.meets_pooled_floor
    assert one_short.parties_below_floor == ()
    assert not one_short.meets_every_floor

    on_the_per_verifier_floor = view(floor, pooled_floor)
    assert on_the_per_verifier_floor.parties_below_floor == ()
    assert on_the_per_verifier_floor.meets_every_floor
    one_record_less = view(floor - 1, pooled_floor)
    assert one_record_less.parties_below_floor == (Party.BOB,)
    assert one_record_less.meets_pooled_floor
    assert not one_record_less.meets_every_floor


def test_the_exchange_refuses_a_pair_that_is_not_one_run() -> None:
    """Pooling counts across two runs would pool two unrelated numbers."""
    params = ProtocolParams(key_length=600)
    bob = MatchedCountMessage("Bob", 0, 200, 600)
    with pytest.raises(ValueError, match="different runs"):
        exchange_matched_counts(
            {
                Party.BOB: bob,
                Party.CHARLIE: MatchedCountMessage("Charlie", 1, 200, 600),
            },
            params,
        )
    with pytest.raises(ValueError, match="reports key_length"):
        exchange_matched_counts(
            {
                Party.BOB: MatchedCountMessage("Bob", 0, 100, 300),
                Party.CHARLIE: MatchedCountMessage("Charlie", 0, 100, 300),
            },
            params,
        )


def test_the_exchange_refuses_a_missing_or_mislabelled_verifier() -> None:
    """With one recipient there is nothing to compare, and a swap inverts it."""
    params = ProtocolParams(key_length=600)
    bob = MatchedCountMessage("Bob", 0, 200, 600)
    with pytest.raises(ValueError, match="both verifiers"):
        exchange_matched_counts({Party.BOB: bob}, params)
    with pytest.raises(ValueError, match="keyed by"):
        exchange_matched_counts(
            {
                Party.CHARLIE: bob,
                Party.BOB: MatchedCountMessage("Bob", 0, 200, 600),
            },
            params,
        )
    with pytest.raises(TypeError, match="must be a mapping"):
        exchange_matched_counts([bob], params)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a ProtocolParams"):
        exchange_matched_counts({}, {"key_length": 600})  # type: ignore[arg-type]


def test_a_pooled_view_round_trips_through_json() -> None:
    """It is carried in a transcript, so serialisation is pinned on the type."""
    pooled = PooledMatchedCounts(204, 196, 67, 212, 600, 1)
    restored = PooledMatchedCounts.from_dict(
        json.loads(json.dumps(pooled.to_dict()))
    )
    assert restored == pooled
    assert restored.summary() == pooled.summary()


def test_a_pooled_view_refuses_impossible_counts() -> None:
    """Its own internal consistency, checked before the transcript's is."""
    with pytest.raises(ValueError, match="cannot exceed key_length"):
        PooledMatchedCounts(601, 100, 67, 212, 600, 0)
    with pytest.raises(ValueError, match="cannot exceed"):
        PooledMatchedCounts(100, 100, 67, 1201, 600, 0)
    with pytest.raises(ValueError, match="must be at least 1"):
        PooledMatchedCounts(100, 100, 0, 212, 600, 0)
    with pytest.raises(ValueError, match="Alice holds no matched count"):
        PooledMatchedCounts(204, 196, 67, 212, 600, 0).count_for("Alice")


def test_the_skip_seam_returns_nothing_and_validates_the_same() -> None:
    """A mis-wired experiment must fail the same way in both arms."""
    params = ProtocolParams(key_length=600)
    messages = {
        Party.BOB: MatchedCountMessage("Bob", 0, 200, 600),
        Party.CHARLIE: MatchedCountMessage("Charlie", 0, 200, 600),
    }
    assert no_count_exchange(messages, params) is None
    with pytest.raises(ValueError, match="both verifiers"):
        no_count_exchange({Party.BOB: messages[Party.BOB]}, params)


# ==========================================================================
# 4. The session seam
# ==========================================================================


def test_the_session_exchanges_counts_by_default_and_records_it() -> None:
    """Phase C' runs without being asked, and the transcript carries the result."""
    params = ProtocolParams(key_length=300)
    transcript = QDSSession(
        params, rng=np.random.default_rng(SEED + 6)
    ).run(0)

    assert transcript.counts_exchanged
    pooled = transcript.pooled
    assert pooled is not None
    assert pooled.minimum_matched == minimum_matched_count(params)
    assert pooled.minimum_pooled == minimum_pooled_matched_count(params)
    assert pooled.pooled == transcript.pooled_matched_count
    assert transcript.bob is not None and transcript.charlie is not None
    assert pooled.bob_count == transcript.bob.matched_count
    assert pooled.charlie_count == transcript.charlie.matched_count
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


def test_the_exchange_seam_can_be_replaced_and_the_transcript_says_so() -> None:
    """The pre-pooled variant is reachable, loudly, and only on purpose."""
    params = ProtocolParams(key_length=300)
    transcript = QDSSession(
        params,
        rng=np.random.default_rng(SEED + 7),
        count_exchange=no_count_exchange,
    ).run(0)

    assert not transcript.counts_exchanged
    assert transcript.pooled is None
    assert "UNPOOLED" in transcript.summary()
    # An honest run still verifies: the seam removes a control, not the rate.
    assert transcript.transferable
    assert SessionTranscript.from_json(transcript.to_json()) == transcript


def test_the_exchange_consumes_no_randomness() -> None:
    """A pooled run and a pre-pooled run draw the identical generator sequence.

    Which is what makes the two arms of the split-coin measurement comparable
    position by position rather than two different experiments (D3).
    """
    params = ProtocolParams(key_length=120)
    with_exchange = np.random.default_rng(SEED)
    QDSSession(params, rng=with_exchange).run(0)
    without = np.random.default_rng(SEED)
    QDSSession(params, rng=without, count_exchange=no_count_exchange).run(0)
    assert with_exchange.bit_generator.state == without.bit_generator.state


def test_a_non_callable_exchange_seam_is_refused_at_construction() -> None:
    """Caught before a whole key is teleported, like every other seam."""
    with pytest.raises(TypeError, match="count_exchange must be None"):
        QDSSession(DEMO_PARAMS, count_exchange="off")  # type: ignore[arg-type]


def test_an_exchange_seam_returning_junk_is_refused() -> None:
    """``None`` means "they did not compare"; anything else is a wiring error."""
    session = QDSSession(
        ProtocolParams(key_length=24),
        rng=np.random.default_rng(SEED),
        count_exchange=lambda messages, params: 42,
    )
    session.distribute()
    session.sign(0)
    with pytest.raises(TypeError, match="must return a PooledMatchedCounts"):
        session.exchange_counts()


def test_exchanging_counts_before_signing_is_refused() -> None:
    """There is no declaration to count against before Phase B."""
    session = QDSSession(
        ProtocolParams(key_length=24), rng=np.random.default_rng(SEED)
    )
    session.distribute()
    with pytest.raises(ValueError, match="no declaration"):
        session.exchange_counts()


def test_the_exchange_happens_once_and_verify_triggers_it() -> None:
    """Idempotent, and reachable through the older call sequence.

    A caller who follows ``distribute / sign / verify / transfer`` -- the
    sequence that predates Phase C' -- still gets the pooled rule, because
    ``verify`` runs the exchange the first time a verdict is asked for.
    """
    calls: list[int] = []
    params = ProtocolParams(key_length=300)

    def counting_exchange(messages, params):
        calls.append(1)
        return exchange_matched_counts(messages, params)

    session = QDSSession(
        params,
        rng=np.random.default_rng(SEED + 8),
        count_exchange=counting_exchange,
    )
    session.distribute()
    session.sign(0)
    assert not session.counts_compared
    session.verify(Party.BOB)
    assert session.counts_compared
    session.transfer()
    assert len(calls) == 1
    assert session.pooled is not None


def test_a_stored_exchange_cannot_invent_its_own_floors() -> None:
    """The persistence boundary re-derives both floors rather than believing them.

    Same argument ``_check_abort_against`` makes for the per-verifier floor: a
    recorded exchange is internally consistent whatever floors it quotes, so a
    transcript that took the field verbatim would let a run that failed the rule
    be re-labelled as one that passed it.
    """
    params = ProtocolParams(key_length=300)
    transcript = QDSSession(
        params, rng=np.random.default_rng(SEED + 9)
    ).run(0)
    blob = transcript.to_dict()
    blob["pooled"]["minimum_pooled"] = 2

    with pytest.raises(ValueError, match="pooled matched-count floor"):
        SessionTranscript.from_dict(blob)

    blob = transcript.to_dict()
    blob["pooled"]["minimum_matched"] = 2
    with pytest.raises(ValueError, match="per-verifier matched-count floor"):
        SessionTranscript.from_dict(blob)


def test_a_transcript_written_before_the_exchange_still_restores() -> None:
    """Forward compatibility: the field is optional and defaults to absent.

    Such a transcript really is one whose recipients did not compare counts, so
    restoring it as ``counts_exchanged = False`` is the truthful reading rather
    than a convenience.
    """
    transcript = QDSSession(
        ProtocolParams(key_length=24), rng=np.random.default_rng(SEED + 10)
    ).run(0)
    blob = transcript.to_dict()
    del blob["pooled"]
    restored = SessionTranscript.from_dict(blob)
    assert not restored.counts_exchanged
    assert restored.pooled is None
    assert restored.is_complete


def test_the_default_parameter_set_earns_its_published_floor() -> None:
    """The two shipped numbers, pinned where a reader will look for them."""
    assert minimum_matched_count(DEFAULT_PARAMS) == 36555
    assert minimum_pooled_matched_count(DEFAULT_PARAMS) == 74190
    assert minimum_pooled_matched_count(DEFAULT_PARAMS) > 2 * 36555


# ==========================================================================
# 5. The declaration the counts were about
# ==========================================================================


def test_the_exchange_refuses_two_counts_against_two_declarations() -> None:
    """Same run, same bit, same length -- and two different declarations.

    The pair a check on ``message_bit`` and ``key_length`` cannot see: those
    two fields agree across *every* declaration for one distribution, and it is
    the declaration that decides which positions are matched at all. Pooling
    here would add matches to two different basis strings and call the result
    ``M``, which is a quantity of neither run.
    """
    params = ProtocolParams(key_length=300)
    declaration, records = _honest_pair(params, SEED + 12)
    altered = _with_flipped_eigenvalue(declaration)

    crossed = {
        Party.BOB: matched_count_message(
            declaration, records[Party.BOB], params
        ),
        Party.CHARLIE: matched_count_message(
            altered, records[Party.CHARLIE], params
        ),
    }
    assert crossed[Party.BOB].message_bit == crossed[Party.CHARLIE].message_bit
    assert crossed[Party.BOB].key_length == crossed[Party.CHARLIE].key_length

    with pytest.raises(ValueError, match="counted different declarations"):
        exchange_matched_counts(crossed, params)
    # The Phase 3 seam validates identically, so both arms fail the same way.
    with pytest.raises(ValueError, match="counted different declarations"):
        no_count_exchange(crossed, params)

    # Both against one declaration: pooled as before.
    together = exchange_matched_counts(
        {
            party: matched_count_message(declaration, record, params)
            for party, record in records.items()
        },
        params,
    )
    assert together.declaration_digest == crossed[Party.BOB].declaration_digest


def test_a_pooled_view_hands_on_the_declaration_its_counts_named() -> None:
    """The binding has to reach the verifier, or it checks nothing.

    :meth:`PooledMatchedCounts.counterpart_of` is the one place a count crosses
    from the exchange into a verdict, so it is where the declaration has to
    travel with it. The value is an integer in every respect a caller can
    observe -- it compares, adds and serialises as the count it is -- and
    carries the declaration besides.
    """
    params = ProtocolParams(key_length=300)
    declaration, records = _honest_pair(params, SEED + 13)
    pooled = exchange_matched_counts(
        {
            party: matched_count_message(declaration, record, params)
            for party, record in records.items()
        },
        params,
    )

    handed = pooled.counterpart_of(Party.BOB)
    assert handed == pooled.charlie_count
    assert isinstance(handed, int)
    assert handed + 1 == pooled.charlie_count + 1
    assert json.loads(json.dumps({"m": handed}))["m"] == pooled.charlie_count
    assert handed.declaration_digest == pooled.declaration_digest
    assert (
        pooled.counterpart_of(Party.CHARLIE).declaration_digest
        == pooled.declaration_digest
    )

    # It survives the transcript boundary, because that is where a stored run is
    # re-read from.
    restored = PooledMatchedCounts.from_dict(
        json.loads(json.dumps(pooled.to_dict()))
    )
    assert restored == pooled
    assert restored.counterpart_of(Party.BOB).declaration_digest == (
        pooled.declaration_digest
    )


def test_an_exchange_recorded_before_the_binding_still_restores() -> None:
    """Forward compatibility, and the honest reading of a missing field.

    A stored exchange that names no declaration is one whose provenance was
    never recorded, not one known to be coherent and not one known to be
    mixed. It restores as ``None``, and a verifier reading it applies the pooled
    floor exactly as the package did before the field existed -- inventing a
    refusal for it would turn an old run into an abort it never had.
    """
    blob = PooledMatchedCounts(204, 196, 67, 212, 600, 1).to_dict()
    assert blob["declaration_digest"] is None
    del blob["declaration_digest"]
    restored = PooledMatchedCounts.from_dict(blob)

    assert restored.declaration_digest is None
    assert restored.counterpart_of(Party.BOB) == 196
    assert restored.counterpart_of(Party.BOB).declaration_digest is None
    assert restored.meets_every_floor
    assert restored.summary().startswith("POOLED EVIDENCE bit 1")


def test_a_declaration_digest_must_be_a_string_or_absent() -> None:
    """Two spellings of "not recorded" would be one comparison nobody can read."""
    with pytest.raises(ValueError, match="non-empty string or None"):
        MatchedCountMessage("Bob", 0, 204, 600, "")
    with pytest.raises(TypeError, match="must be a string or None"):
        MatchedCountMessage("Bob", 0, 204, 600, 17)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty string or None"):
        PooledMatchedCounts(204, 196, 67, 212, 600, 0, "")
    with pytest.raises(TypeError, match="must be a string or None"):
        PooledMatchedCounts(204, 196, 67, 212, 600, 0, 17)  # type: ignore[arg-type]


def test_the_session_records_the_declaration_its_exchange_counted() -> None:
    """A transcript says which declaration the pooled numbers are about."""
    params = ProtocolParams(key_length=300)
    session = QDSSession(params, rng=np.random.default_rng(SEED + 14))
    transcript = session.run(0)

    pooled = transcript.pooled
    assert pooled is not None
    assert pooled.declaration_digest is not None
    assert pooled.declaration_digest == (
        matched_count_message(
            transcript.signature, transcript.records_for(0)[Party.BOB], params
        ).declaration_digest
    )
    assert SessionTranscript.from_json(transcript.to_json()) == transcript
