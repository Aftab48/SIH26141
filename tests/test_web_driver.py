"""The Phase 6 run driver: every arm, both streams, and the three traps.

:mod:`sih141.web.api` is tested through FastAPI's ``TestClient`` next door. This
file tests the thing underneath it -- :func:`sih141.web.driver.run_once` -- where
the adversaries are actually mounted and where all three of the hazards the
phase was warned about live:

*The seed has to reach both halves, separately.* A demo that cannot be repeated
on a stage will be doubted, so one integer must fix the run; **D6** says the
adversary must not thereby be handed the session's randomness. Those two
requirements pull in opposite directions and the tests below pin both ends.

*The replay arm has a wiring trap that has already cost this project a wrong
number.* :class:`~sih141.attacks.replay.ReplayingForwarder` mints its default
loot at ``key_length=24`` and silently declines a capture whose shape does not
match the live declaration, so at any other length it forwards honestly and the
arm reports a clean ``0`` while looking exactly as though it ran. There is a
test here that would fail if that regressed, and it is the reason this file
exists more than any other.

*Ground truth must not leak into the verdict.* The detector reads a JSON
transcript and nothing else, and the proof of that here is structural: nothing
the harness knows appears anywhere inside the detection object.

Lengths are small on purpose. ``L = 96`` is about a fifth of a second of session
generation and every property asserted here is about the *wiring*, not about a
rate; the rates are Phase 3's and are measured there over hundreds of trials.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from sih141.attacks.isolation import same_stream
from sih141.protocol.params import ProtocolParams
from sih141.web import driver
from sih141.web.catalogue import ATTACK_KEYS, attack_spec
from sih141.web.driver import (
    MESSAGE_BIT,
    RunRequest,
    RunResult,
    _seed_streams,
    run_once,
)
from sih141.web.limits import (
    KEY_LENGTH_MIN,
    LIVE_KEY_LENGTH_MAX,
    RequestRefused,
)


SHORT = 96


def _body(**overrides) -> dict:
    """Return a request body at a length that answers quickly."""
    body = {"key_length": SHORT, "check_fraction": 0.25, "seed": 4242}
    body.update(overrides)
    return body


def _run(**overrides) -> RunResult:
    """Validate and run one request."""
    return run_once(RunRequest.from_mapping(_body(**overrides)))


def _verifier(result: RunResult, party: str) -> dict:
    """Return one verifier's row out of the run payload."""
    for row in result.run["verifiers"]:
        if row["party"] == party:
            return row
    raise AssertionError(f"{party} is missing from the verifier table")


# --------------------------------------------------------------------------- #
# 1. Every arm runs, and every arm produces a well-formed Detection.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def every_arm() -> dict[str, RunResult]:
    """Run every arm once, at a length that answers quickly."""
    results = {}
    for key in ATTACK_KEYS:
        overrides = {"attack": key}
        if key == "channel-manipulation":
            overrides["noise"] = 0.3
        results[key] = _run(**overrides)
    return results


#: The twenty-one keys ``Detection.to_dict`` promises. Pinned here rather than
#: derived from the object, because the point of the check is that the API's
#: consumer -- a frontend being written in parallel against a fixed contract --
#: gets the shape it was promised.
DETECTION_KEYS = {
    "attributions",
    "bound_is_unconditional",
    "budget",
    "channel_error_rate",
    "detected",
    "eps",
    "evidence_bound",
    "false_positive_bound",
    "grouping_key",
    "key_length",
    "kinds",
    "named",
    "not_scored",
    "null_is_noiseless",
    "outcomes",
    "requirements_enforced",
    "security_claim",
    "signals",
    "slack_factor",
    "summary",
    "withheld",
}


@pytest.mark.parametrize("key", ATTACK_KEYS)
def test_every_arm_runs_and_returns_a_well_formed_detection(every_arm, key):
    """Each arm mounts, completes, and is scored against every threshold."""
    result = every_arm[key]
    assert result.error is None, result.error
    assert set(result.detection) == DETECTION_KEYS
    assert isinstance(result.detection["detected"], bool)
    assert 0.0 < result.detection["false_positive_bound"] <= result.request["eps"]
    assert result.detection["eps"] == result.request["eps"]
    assert result.ground_truth["completed"] is True


@pytest.mark.parametrize("key", ATTACK_KEYS)
def test_every_response_is_json_clean(every_arm, key):
    """The whole body serialises, so nothing downstream has to special-case it.

    A ``Party``, a ``numpy.float64`` or an ``AbortReason`` that reached the
    payload would round-trip through ``json.dumps`` and come back as something
    a frontend has to guess at, or would not round-trip at all.
    """
    text = json.dumps(every_arm[key].to_dict())
    assert json.loads(text) == every_arm[key].to_dict()


@pytest.mark.parametrize("key", ATTACK_KEYS)
def test_timings_are_measured_and_the_session_dominates(every_arm, key):
    """Both halves are timed, and detection really is free beside the session.

    The frontend needs these to decide what to show while waiting, so they are
    measured rather than estimated. The ordering is asserted because it is the
    fact the whole live/pre-generated decision rests on: capping ``key_length``
    caps the run, and no cap on the detector would buy anything.
    """
    timings = every_arm[key].timings
    assert timings["session_ms"] > 0.0
    assert timings["detect_ms"] > 0.0
    assert timings["detect_ms"] < timings["session_ms"]


# --------------------------------------------------------------------------- #
# 2. Ground truth is a separate object and never reaches the verdict.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("key", ATTACK_KEYS)
def test_ground_truth_never_appears_inside_the_detection(every_arm, key):
    """The detector saw a JSON transcript and nothing else.

    Asserted structurally rather than by inspection: the detection body is
    serialised and searched for every string the harness knows and the
    transcript does not -- the arm's key, the seams it seized, the link model.
    A detector that could see any of them would not be reporting a detection
    rate, it would be restating the ground truth.
    """
    result = every_arm[key]
    detection = json.dumps(result.detection)
    assert "ground_truth" not in result.detection
    assert result.ground_truth["attack"] == key
    spec = attack_spec(key)
    for seam in spec.seams:
        assert seam not in detection, (
            f"the seam {seam!r} the adversary seized is harness knowledge and "
            f"must not be reachable from the detection body"
        )
    assert result.ground_truth["link"]["model"] not in ("",)
    if key.startswith("channel-") and key != "channel-manipulation":
        assert result.ground_truth["link"]["model"] not in detection


def test_an_inert_adversary_is_reported_as_identical_to_an_honest_run():
    """Mounted and declined is not a miss, and the payload distinguishes them.

    An adversary the operator selected who then does nothing -- a twirl at
    strength zero, a selective starver on a run it let through -- produces a
    transcript byte-identical to an honest one. The detector correctly finds
    nothing in it, and a screen with no way to say why would be showing a
    miss. ``acted`` and ``identical_to_honest`` are that way.
    """
    honest = _run(attack="honest")
    assert honest.ground_truth["adversary_present"] is False
    assert honest.ground_truth["acted"] is False
    # ... and the honest control is never "identical to honest" in that sense,
    # because there was no adversary to decline.
    assert honest.ground_truth["identical_to_honest"] is False

    inert = _run(attack="channel-manipulation", noise=0.0)
    assert inert.ground_truth["adversary_present"] is True
    assert inert.ground_truth["acted"] is False
    assert inert.ground_truth["identical_to_honest"] is True
    assert inert.ground_truth["targeted_links"] == []
    assert inert.detection["detected"] is False

    engaged = _run(attack="channel-manipulation", noise=0.4)
    assert engaged.ground_truth["acted"] is True
    assert engaged.ground_truth["identical_to_honest"] is False
    assert engaged.ground_truth["targeted_links"] == [["Bob", 0], ["Bob", 1]]

    noisy = _run(attack="honest", noise=0.2)
    assert noisy.ground_truth["acted"] is True


def test_the_link_report_says_which_null_the_detector_was_given():
    """The dashboard's worst failure mode, made visible in the payload.

    An honest run over a noisy link departs from the detector's noiseless null
    and fires -- correctly, with both verifiers still accepting. The screen has
    to be able to say that rather than showing red beside the word "honest", so
    the link's true rate is ground truth and the null it was scored against is
    reported beside it.
    """
    result = _run(attack="honest", noise=0.03125, key_length=192)
    link = result.ground_truth["link"]
    assert link["true_error_rate_by_party"] == {
        "Bob": 0.015625,
        "Charlie": 0.015625,
    }
    assert link["rate_null_given_to_detector"] == 0.0
    assert link["nulls_match_link"] is False
    assert result.detection["null_is_noiseless"] is True
    assert result.detection["detected"] is True
    # ... and both verifiers accepted anyway, which is the whole point.
    assert result.detection["outcomes"] == {
        "Bob": "accepted",
        "Charlie": "accepted",
    }

    stated = _run(
        attack="honest",
        noise=0.03125,
        key_length=192,
        channel_error_rate=0.015625,
        tolerated_depolarising=0.03125,
    )
    assert stated.ground_truth["link"]["nulls_match_link"] is True
    assert stated.detection["null_is_noiseless"] is False
    assert stated.detection["detected"] is False


# --------------------------------------------------------------------------- #
# 3. D3 and D6: one seed, two streams, both reached.
# --------------------------------------------------------------------------- #


def test_the_session_and_the_adversary_never_share_a_stream():
    """D6, checked the way the isolation module checks it.

    Two generators built from one seed are ONE stream however different the two
    Python objects are, and an ``is`` test never saw the difference. That is the
    leak this project has already paid for, arriving by the shortest route, so
    the driver's derivation is checked against the same predicate the attacks
    package uses.
    """
    session, adversaries = _seed_streams(99, 3)
    assert len(adversaries) == 3
    for index, generator in enumerate(adversaries):
        assert not same_stream(session, generator), index
        for other in adversaries[:index]:
            assert not same_stream(other, generator)


def test_the_same_request_gives_the_same_answer():
    """A demo that cannot be repeated on a stage is a demo that will be doubted."""
    for key in ("honest", "outside-forgery", "replay", "count-starvation"):
        first = _run(attack=key)
        second = _run(attack=key)
        assert first.detection == second.detection, key
        assert first.run == second.run, key
        assert first.ground_truth == second.ground_truth, key


def test_the_seed_reaches_the_session_and_the_adversary_both():
    """Change the seed and BOTH halves move -- which is what makes it one seed.

    The starving arm is the sharp instrument here because its two halves are
    separately visible in one response: the declared count comes from the
    adversary's own generator (a jittered draw below the denial headroom) and
    the scored matched count comes from the session's. A seed that reached only
    one of them would move one number and leave the other fixed, and the run
    would be reproducible for the wrong reason.

    ``L = 384`` and not the shorter length used elsewhere in this file, for a
    reason that is itself a fact about the scheme: at ``L = 192`` the matched
    floor has degenerated to ``1``, the denial headroom is ``0``, and the
    starver has no choice to make -- every seed declares zero and the test
    would fail while the driver was correct.
    """
    seen_declared = set()
    seen_matched = set()
    for seed in (1, 2, 3, 4, 5):
        result = _run(attack="count-starvation", key_length=384, seed=seed)
        decisions = result.ground_truth["starvation"]["decisions"]
        assert decisions, "the starver must have been asked for a count"
        seen_declared.add(decisions[0]["declared_count"])
        seen_matched.add(
            _verifier(result, "Charlie")["matched"]
        )
    assert len(seen_declared) > 1, (
        "the adversary's own choices did not move with the request seed, so "
        "the seed is not reaching the adversary"
    )
    assert len(seen_matched) > 1, (
        "the session's records did not move with the request seed, so the "
        "seed is not reaching the session"
    )


# --------------------------------------------------------------------------- #
# 4. The replay arm's wiring trap.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("key_length", [24, 96, 192])
def test_the_replay_arm_actually_replays(key_length):
    """The test this file exists for.

    ``ReplayingForwarder`` mints its default capture at ``key_length=24`` and
    declines one whose length does not match the live declaration, so a harness
    that took the default forwards honestly at every other length -- reporting
    a clean arm that never attacked, while every other sign says it ran. ``24``
    is in the parameter list on purpose: an implementation that regressed to
    the default would pass at ``24`` alone, so a single-length test would have
    hidden it.
    """
    result = _run(attack="replay", key_length=key_length)
    assert result.error is None
    assert result.ground_truth["replay"]["replays"] == 1
    assert result.ground_truth["acted"] is True
    assert result.run["forwarding_altered_signature"] is True
    assert result.detection["detected"] is True


def test_the_replay_capture_is_minted_at_this_runs_signing_length():
    """Check rounds shorten the key, so the loot has to be shortened with it.

    A capture minted at ``L`` rather than at the signing length is the same
    silent decline in a subtler dress, and the two lengths differ on every run
    with check rounds.
    """
    result = _run(attack="replay", key_length=192, check_fraction=0.25)
    assert ProtocolParams(key_length=192, check_fraction=0.25).signing_length == 144
    assert result.ground_truth["replay"]["capture_key_length"] == 144
    assert result.run["sifted_key_length"] == 144
    assert result.ground_truth["replay"]["replays"] == 1


def test_the_replayed_round_is_not_the_live_one():
    """A replay of the live declaration would not be a replay."""
    result = _run(attack="replay", key_length=SHORT)
    stale = result.ground_truth["replay"]["capture_session_id"]
    assert stale not in json.dumps(result.detection)
    assert stale not in json.dumps(result.run)


# --------------------------------------------------------------------------- #
# 5. A no-verdict is a third state, and the driver reports it as one.
# --------------------------------------------------------------------------- #


def test_starvation_denies_a_verdict_and_that_is_not_a_rejection():
    """The single most likely way this dashboard could lie, pinned.

    The starver costs Bob his verdict. ``refused-to-score`` is neither
    ``accepted`` nor ``rejected``, the transcript carries the refusal's own
    words, and the starving verifier keeps his own acceptance -- a
    transferability inversion, and a denial of service rather than a forgery.
    """
    result = _run(attack="count-starvation", key_length=192)
    outcomes = result.detection["outcomes"]
    assert outcomes["Bob"] == "refused-to-score"
    assert outcomes["Charlie"] == "accepted"
    bob = _verifier(result, "Bob")
    assert bob["scored"] is False
    assert bob["accepted"] is None
    # NOT 0.0. He did not observe perfect agreement; he observed nothing, and a
    # zero here would be drawn as a flawless verifier.
    assert bob["rate"] is None
    assert bob["matched"] is None
    assert result.run["aborts"]["by_party"]["Bob"]
    assert result.run["is_complete"] is False
    assert result.run["transferable"] is False


def test_the_forwarding_attacks_deny_under_the_shipped_ordering():
    """Under 'before-forwarding' a substituted declaration is refused, not scored.

    Two arms, one outcome, and it is a denial of transfer rather than a catch:
    Charlie counted against the declaration Alice signed and is holding a
    different one, so he refuses on provenance and never scores. The
    ``after-forwarding`` ordering is a different experiment and the two are
    never pooled.
    """
    for key in ("recipient-forgery", "replay"):
        result = _run(attack=key, key_length=192)
        assert result.detection["outcomes"]["Charlie"] == "refused-to-score", key
        assert _verifier(result, "Charlie")["scored"] is False, key
        assert _verifier(result, "Charlie")["rate"] is None, key


def test_the_two_orderings_are_labelled_and_never_merged():
    """``grouping_key`` carries the ordering, so a table cannot pool over it."""
    before = _run(attack="recipient-forgery", count_exchange_timing="before-forwarding")
    after = _run(attack="recipient-forgery", count_exchange_timing="after-forwarding")
    assert before.detection["grouping_key"][0] == "before-forwarding"
    assert after.detection["grouping_key"][0] == "after-forwarding"
    assert before.run["count_exchange_timing"] != after.run["count_exchange_timing"]
    assert before.detection["outcomes"] != after.detection["outcomes"]


def test_full_impersonation_is_indistinguishable_from_honest():
    """Assumption (AUTH), as a run rather than as a sentence.

    Mallory holding both of Alice's seams produces a transcript that looks
    exactly like an honest one, because at the level of the transcript it IS
    one. Nothing fires, both verifiers accept, and the roster says why -- which
    is a stronger statement than a missed detection, not a weaker one.
    """
    result = _run(attack="impersonation-full", key_length=192)
    assert result.detection["detected"] is False
    assert result.detection["named"] == ["honest"]
    assert result.ground_truth["detectable"] == "undetectable-by-construction"
    assert "(AUTH)" in result.ground_truth["assumption"]
    assert result.ground_truth["acted"] is True


def test_an_unmonitored_link_is_reported_as_not_evaluated():
    """``check_fraction = 0`` withholds the whole channel family, and says so."""
    result = _run(attack="channel-intercept-resend", check_fraction=0.0)
    withheld = " ".join(result.detection["withheld"])
    assert "channel" in withheld
    assert "unmonitored link is not a clean one" in withheld
    assert result.run["channel_monitored"] is False


# --------------------------------------------------------------------------- #
# 6. A demo-scale run says what it does not establish.
# --------------------------------------------------------------------------- #


def test_a_demo_scale_run_carries_its_own_repudiation_bound():
    """A green transferability tick at L=192 would be lying, so the number is there.

    Both floors are inert at demo lengths and the per-run repudiation bound is
    order one. The run's own panel carries that figure and the run's own words
    say it, so the screen never has to infer it and can never omit it.
    """
    result = _run(attack="honest", key_length=192, check_fraction=0.0)
    assert result.run["transferable"] is True
    guarantee = result.run["repudiation_guarantee"]
    assert guarantee is not None and guarantee > 0.9, guarantee
    assert "P(repudiation | this run)" in result.run["transcript_summary"]
    assert result.run["enforced_repudiation_bound"] > 0.9
    assert result.run["floors"]["degenerate"] is False
    assert result.run["security_claim"] is True


# --------------------------------------------------------------------------- #
# 7. The bounds refuse what they should, and never clamp.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field", "body"),
    [
        ("attack", {"attack": "no-such-arm"}),
        ("key_length", {"key_length": LIVE_KEY_LENGTH_MAX + 1}),
        ("key_length", {"key_length": KEY_LENGTH_MIN - 1}),
        ("key_length", {"key_length": 10**9}),
        ("key_length", {"key_length": True}),
        ("check_fraction", {"check_fraction": 0.99}),
        ("check_fraction", {"check_fraction": -0.1}),
        ("check_fraction", {"check_fraction": 0.0001}),
        ("noise", {"noise": 0.9}),
        ("noise", {"noise": float("nan")}),
        ("noise", {"attack": "channel-kept-share", "noise": 0.1}),
        ("eps", {"eps": 0.0}),
        ("eps", {"eps": 0.5}),
        ("eps", {"eps": float("inf")}),
        ("channel_error_rate", {"channel_error_rate": -1.0}),
        ("channel_error_rate", {"channel_error_rate": 0.8}),
        ("tolerated_depolarising", {"tolerated_depolarising": 0.9}),
        ("count_exchange_timing", {"count_exchange_timing": "whenever"}),
        ("seed", {"seed": -1}),
        ("seed", {"seed": 2**64}),
    ],
)
def test_the_bounds_refuse_what_they_should(field, body):
    """Each out-of-range field is refused, and the refusal names its own field."""
    with pytest.raises(RequestRefused) as caught:
        RunRequest.from_mapping(_body(**body))
    assert caught.value.field == field
    assert str(caught.value)


def test_a_run_at_the_live_cap_succeeds():
    """The published ceiling is a length that actually runs.

    A cap nobody tested is a cap that is either too high to honour or lower
    than it claims. This is the slowest test in the file -- about three seconds
    of session generation -- and it is the one that makes ``live_key_length_max``
    a promise rather than a number.
    """
    result = _run(attack="honest", key_length=LIVE_KEY_LENGTH_MAX)
    assert result.error is None
    assert result.run["nominal_key_length"] == LIVE_KEY_LENGTH_MAX
    assert result.detection["detected"] is False


def test_a_refused_length_is_never_quietly_clamped():
    """The refusal names the cap, and no run happens at all."""
    with pytest.raises(RequestRefused) as caught:
        RunRequest.from_mapping(_body(key_length=LIVE_KEY_LENGTH_MAX + 1))
    assert caught.value.cap == LIVE_KEY_LENGTH_MAX
    assert str(LIVE_KEY_LENGTH_MAX) in str(caught.value)
    assert "refused rather than quietly run" in str(caught.value)


def test_defaults_fill_in_the_fields_a_request_omits():
    """A body carrying only ``attack`` still describes a complete run."""
    request = RunRequest.from_mapping({"attack": "honest"})
    assert request.to_dict() == {
        "attack": "honest",
        "key_length": 192,
        "check_fraction": 0.25,
        "noise": 0.0,
        "eps": 1e-9,
        "channel_error_rate": 0.0,
        "tolerated_depolarising": 0.0,
        "count_exchange_timing": "before-forwarding",
        "seed": 20260141,
        "message_bit": MESSAGE_BIT,
    }


# --------------------------------------------------------------------------- #
# 8. An adversary that raises is a run-level failure, not a 500 and not a
#    clean run.
# --------------------------------------------------------------------------- #


class _Exploding:
    """A seam that fails the way a mis-wired adversary fails."""

    def __call__(self, *args, **kwargs):
        """Raise, as an adversary with a bug would.

        Raises
        ------
        RuntimeError
        """
        raise RuntimeError("the adversary could not mount")


@pytest.fixture()
def exploding_arm(monkeypatch) -> None:
    """Replace the mounting so the signer seam raises mid-run."""

    def _fake(request):
        mounting = driver._Mounting(
            kwargs={
                "rng": np.random.default_rng(0),
                "signer": _Exploding(),
            }
        )
        mounting.link = driver._link_report("ideal", 0.0, None, 0.0, 0.0, 0.0)
        return mounting

    monkeypatch.setattr(driver, "_mount", _fake)


def test_an_adversary_that_raises_surfaces_as_a_run_level_error(exploding_arm):
    """It must not be a crash, and it must not be mistaken for a clean run.

    Both failure modes are worse than the failure. A traceback out of the
    endpoint gives the screen nothing to render; an exception swallowed into an
    honest run gives it something *false* to render, under the label of the arm
    the operator chose.
    """
    result = _run(attack="outside-forgery")
    assert result.detection is None
    assert result.run is None
    assert result.error is not None
    assert result.error["kind"] == "run-failed"
    assert result.error["exception"] == "RuntimeError"
    assert "could not mount" in result.error["message"]
    assert result.error["attack"] == "outside-forgery"
    # The arm is still named, so a reader can see the attack was mounted and
    # did not complete rather than seeing an empty panel.
    assert result.ground_truth["attack"] == "outside-forgery"
    assert result.ground_truth["seams_held"] == ["signer"]
    assert result.ground_truth["completed"] is False
    assert result.ground_truth["acted"] is False
    assert json.dumps(result.to_dict())
