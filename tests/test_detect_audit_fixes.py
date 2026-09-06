"""The four Phase 4 audit findings that were fixed after the audit closed.

Three auditors ran against ``2e75d91`` and returned *sound*; between them they
confirmed six defects. Two were prose (fixed in the closing commit, pinned by
their own doctests). These are the other four, and each test here fails against
the code as the auditors found it.

The findings are numbered as ``docs/PHASE4.md`` section 12 numbers them:

A1-3
    :func:`~sih141.detect.statistics.floor_shortfall_bound` never consulted its
    ``floor`` argument on the Chernoff branch, so a floor above the one the
    derivation supports was silently certified at ``2**-64``.
A2-1
    A family share that underflowed from a too-small ``eps`` was reported
    against the internal field name, sending a caller after an argument they
    never passed.
A3-1
    The noiseless null was absent from the machine-readable verdict, so a
    pipeline tabulating :attr:`~sih141.detect.detector.Detection.detected`
    recorded honest noisy links as detections.
A3-2
    The share-sum refusal did not say that the subnormal region is a floating
    point limit rather than a detector defect.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from sih141.attacks.channel import DepolarisingChannel
from sih141.detect import detect
from sih141.detect.statistics import HONEST_ABORT_BUDGET, floor_shortfall_bound
from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
from sih141.protocol.session import QDSSession
from sih141.protocol.verify import (
    minimum_matched_count,
    minimum_pooled_matched_count,
)

DEFAULTS = DEFAULT_PARAMS


def _honest(key_length: int, seed: int, noise: float = 0.0):
    """Run an honest session, optionally over a noisy wire."""
    factory = None
    if noise:
        factory = DepolarisingChannel(
            noise, rng=np.random.default_rng(770000), target=None
        ).resource
    session = QDSSession(
        ProtocolParams(key_length=key_length),
        resource_factory=factory,
        rng=np.random.default_rng(seed),
    )
    return session.run(0)


# --------------------------------------------------------------- A3-1 ------ #


def test_the_verdict_carries_the_null_it_was_scored_against() -> None:
    """A3-1: ``channel_error_rate`` reaches the serialised output.

    The auditor's exact complaint was that ``to_dict()`` had nineteen keys and
    this was not one of them, so the only machine-readable trace of the null was
    absent while the prose disclosure sat in three docstrings.
    """
    verdict = detect(_honest(96, 4), eps=1e-9)
    payload = verdict.to_dict()

    assert "channel_error_rate" in payload
    assert "null_is_noiseless" in payload
    assert payload["channel_error_rate"] == 0.0
    assert payload["null_is_noiseless"] is True
    json.dumps(payload)


def test_an_honest_noisy_link_says_its_null_was_noiseless() -> None:
    """A3-1: the dangerous case is now self-describing.

    This is the auditor's single-run reproduction. Both verifiers accept, the
    link error is a third of Bob's own acceptance cut, and the run is still
    reported as a detection with a proven bound -- which is correct under the
    stated null and was, before this fix, indistinguishable in the output from
    a detection over a *clean* link.
    """
    transcript = _honest(384, 30000, noise=0.005)
    verdict = detect(transcript, eps=1e-9)

    assert verdict.detected is True
    assert verdict.false_positive_bound < 1e-9
    # The point of the finding: the verdict now discloses the null itself.
    assert verdict.null_is_noiseless is True
    assert verdict.to_dict()["channel_error_rate"] == 0.0


def test_supplying_the_true_rate_clears_both_the_alarm_and_the_flag() -> None:
    """A3-1: the mechanism was always right; only the default was the trap."""
    transcript = _honest(384, 30000, noise=0.005)

    assert detect(transcript, eps=1e-9).null_is_noiseless is True
    informed = detect(transcript, eps=1e-9, channel_error_rate=0.005)
    assert informed.null_is_noiseless is False
    assert informed.to_dict()["channel_error_rate"] == 0.005
    assert informed.detected is False


def test_null_is_noiseless_is_exactly_a_zero_rate() -> None:
    """A3-1: a statement about the null, not about how the caller got there."""
    transcript = _honest(96, 4)
    for rate in (0.0, 1e-12, 0.001, 0.03125):
        verdict = detect(transcript, eps=1e-9, channel_error_rate=rate)
        assert verdict.null_is_noiseless is (rate == 0.0)
        assert verdict.channel_error_rate == rate


# --------------------------------------------------------------- A1-3 ------ #


def test_both_protocol_floors_keep_their_proven_bound() -> None:
    """A1-3: the fix must not cost the two floors the derivation was built for.

    The containment is tight -- at ``DEFAULT_PARAMS`` the per-verifier floor
    applies at ``36554`` against a limit of about ``36554.2`` -- so a fix that
    got the inequality direction wrong would show up here rather than in the
    negative case below.
    """
    trials = DEFAULTS.key_length
    assert floor_shortfall_bound(
        trials, 1 / 3, minimum_matched_count(DEFAULTS)
    ) == pytest.approx(HONEST_ABORT_BUDGET, rel=0, abs=0)
    assert floor_shortfall_bound(
        2 * trials, 1 / 3, minimum_pooled_matched_count(DEFAULTS)
    ) == pytest.approx(HONEST_ABORT_BUDGET, rel=0, abs=0)


def test_a_floor_the_derivation_does_not_support_is_not_certified() -> None:
    """A1-3: the defect itself.

    Handed a floor at the distribution's own mean -- an event of probability
    about a half -- the Chernoff branch used to return ``2**-64`` because it
    never looked at ``floor``.
    """
    trials = DEFAULTS.key_length
    mean = trials / 3
    assert floor_shortfall_bound(trials, 1 / 3, int(mean)) == 1.0
    assert floor_shortfall_bound(trials, 1 / 3, int(mean) + 1000) == 1.0
    assert floor_shortfall_bound(trials, 1 / 3, trials) == 1.0


def test_the_certified_region_ends_where_the_containment_does() -> None:
    """A1-3: the boundary is the algebra's, not a hand-picked cut.

    Walking the floor up from the protocol's own value, the bound must hold
    exactly while ``floor - 1 <= (1 - d0) * mean`` and be ``1.0`` after. Any
    other crossover point would mean the branch is guarding on something other
    than its own containment.
    """
    trials, probability = DEFAULTS.key_length, 1 / 3
    mean = trials * probability
    spread = math.sqrt(2.0 * 64.0 * math.log(2.0) / mean)
    limit = (1.0 - spread) * mean

    for floor in range(minimum_matched_count(DEFAULTS) - 3,
                       minimum_matched_count(DEFAULTS) + 4):
        proven = floor_shortfall_bound(trials, probability, floor)
        contained = floor - 1 <= limit
        assert (proven == HONEST_ABORT_BUDGET) is contained, floor
        assert (proven == 1.0) is not contained, floor


def test_a_zero_count_floor_is_still_answered_exactly() -> None:
    """A1-3: the other regime is untouched -- it never used the budget."""
    assert floor_shortfall_bound(267, 1 / 3, 1) == pytest.approx(
        (2 / 3) ** 267, rel=1e-12, abs=0
    )
    assert floor_shortfall_bound(24, 1 / 3, 3) == 1.0


# --------------------------------------------------- A2-1 and A3-2 --------- #


def test_an_underflowed_share_blames_eps_and_not_the_share() -> None:
    """A2-1: the message must name the argument the caller actually passed.

    An ROC sweep walking ``eps`` down a decade ladder reaches here, and a
    refusal naming ``rate`` sends its author looking for a parameter that does
    not exist on :func:`detect`.
    """
    transcript = _honest(96, 4)
    with pytest.raises(ValueError) as caught:
        detect(transcript, eps=5e-324)

    message = str(caught.value)
    assert "eps=" in message
    assert not message.startswith("rate must")
    assert "too small to divide into family shares" in message
    # It should also say where the usable floor is, so the sweep can stop there.
    assert "2**-64" in message


def test_the_share_sum_refusal_explains_the_subnormal_region() -> None:
    """A3-2: refusing is right; refusing without saying why is the finding."""
    transcript = _honest(96, 4)
    with pytest.raises(ValueError) as caught:
        detect(transcript, eps=1e-314)

    message = str(caught.value)
    assert "eps=" in message
    assert "subnormal" in message
    assert "safe direction" in message


def test_a_usable_budget_ladder_does_not_refuse_anywhere() -> None:
    """A2-1/A3-2: the fixes must not narrow the range a ROC may sweep.

    Every budget from a loose one down past ``2**-64`` and on to ``1e-300``
    must still produce a verdict, because that is the ladder Phase 5 walks.
    """
    transcript = _honest(96, 4)
    ladder = [0.5, 1e-3, 1e-9, 2.0**-64, 1e-30, 1e-100, 1e-300]
    for eps in ladder:
        verdict = detect(transcript, eps=eps)
        assert verdict.false_positive_bound <= eps
        assert verdict.channel_error_rate == 0.0
