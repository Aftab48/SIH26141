"""The five endpoints and the static host, driven through FastAPI's TestClient.

No browser is needed on this side, which is the point: the frontend is being
built in parallel against the same fixed contract, and this file pins the
server's half of it without touching a single file the other half owns.

Three groups of checks, and the second and third are the ones that matter at a
venue rather than in a review:

*The contract.* Every endpoint's shape, every field's bound, and the separation
of ``ground_truth`` from ``detection`` -- which is not a naming convention, it
is the guarantee that a detection rate is a detection rate and not a restatement
of what the harness already knew.

*Nothing is fetched from a network.* Venue wifi fails. FastAPI's ``/docs``
loads Swagger UI from a CDN and renders blank without a route out, so it is off;
every served payload is searched for a remote origin; and every endpoint is
exercised with outbound sockets forcibly broken, so a handler that quietly
fetched something would fail here rather than on a stage.

*A request cannot hang or exhaust the server.* Every parameter is bounded and
refused by name, unknown fields are rejected rather than ignored, and
concurrency is capped by a non-blocking gate that answers ``503`` instead of
queueing behind seconds of quantum simulation.
"""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sih141 import __version__
from sih141.eval.security import FLOOR_CROSSOVER, security_claim_at
from sih141.protocol.params import ProtocolParams
from sih141.web import driver
from sih141.web.api import STATIC_DIR, create_app
from sih141.web.catalogue import ATTACK_KEYS, DETECTABLE_VALUES
from sih141.web.limits import (
    KEY_LENGTH_MIN,
    LIVE_KEY_LENGTH_MAX,
    MAX_CONCURRENT_RUNS,
    MAX_ERROR_BODY_DEPTH,
    MAX_REQUEST_BYTES,
    json_safe,
    safe_text,
)


CONTRACT_KEYS = {"detection", "run", "ground_truth", "timings"}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """One application, driven in-process."""
    return TestClient(create_app())


def _run_body(**overrides) -> dict:
    """A short request body."""
    body = {"attack": "honest", "key_length": 96, "seed": 5}
    body.update(overrides)
    return body


# --------------------------------------------------------------------------- #
# 1. The contract, endpoint by endpoint.
# --------------------------------------------------------------------------- #


def test_health(client):
    """``/api/health`` reports the build, so a stale process is visible."""
    body = client.get("/api/health").json()
    assert body == {"ok": True, "version": __version__}


def test_attacks_lists_every_arm_with_the_five_contract_fields(client):
    """One entry per adversary plus the honest control."""
    payload = client.get("/api/attacks").json()
    assert [entry["key"] for entry in payload] == list(ATTACK_KEYS)
    for entry in payload:
        for field in ("key", "label", "summary", "detectable"):
            assert isinstance(entry[field], str) and entry[field], (
                entry["key"],
                field,
            )
        # Present on every entry, and a string exactly where the arm's
        # exclusion rests on an assumption rather than on a threshold.
        assert "assumption" in entry
        assert entry["model_note"].strip()


def test_the_auth_case_is_carried_explicitly_and_never_as_a_blank(client):
    """Point 4 of the phase brief, as a test rather than a promise.

    A boolean ``detectable`` would render full impersonation as ``false``, and
    ``false`` beside ten other rows reads as "we tried and failed". What is
    true is stronger: no transcript statistic separates her from Alice, and the
    assumption that excludes her is named.
    """
    payload = {entry["key"]: entry for entry in client.get("/api/attacks").json()}
    full = payload["impersonation-full"]
    assert full["detectable"] == "undetectable-by-construction"
    assert "(AUTH)" in full["assumption"]
    assert "there cannot be one" in full["summary"]
    for entry in payload.values():
        assert entry["detectable"] in set(DETECTABLE_VALUES), entry["key"]
    # The honest control is "not-an-attack", not "undetected": there is nothing
    # to detect, which is a different sentence from a detector that missed.
    assert payload["honest"]["detectable"] == "not-an-attack"
    # Exactly one arm is excluded by an assumption rather than by a threshold,
    # and it is the only one required to name one.
    named = [
        key
        for key, entry in payload.items()
        if entry["detectable"] == "undetectable-by-construction"
    ]
    assert named == ["impersonation-full"]


def test_defaults_publishes_the_caps_and_the_headline_bounds(client):
    """The contract's four keys, plus the caps the UI is required to show."""
    payload = client.get("/api/defaults").json()
    assert payload["eps_default"] == 1e-9
    assert payload["live_key_length_max"] == LIVE_KEY_LENGTH_MAX
    assert payload["live_key_length_min"] == KEY_LENGTH_MIN
    assert payload["max_concurrent_runs"] == MAX_CONCURRENT_RUNS
    assert payload["check_fraction_max"] == 0.5
    assert payload["noise_max"] == 0.5
    assert payload["channel_error_rate_max"] == 0.5
    assert payload["eps_min"] == 1e-19 and payload["eps_max"] == 0.1
    assert payload["count_exchange_timings"] == [
        "before-forwarding",
        "after-forwarding",
    ]
    # `params` is where the CONTROLS start -- the demo length, the same
    # thresholds -- not the headline set.
    assert payload["params"]["key_length"] == 192
    assert payload["params"]["s_a"] == 0.015625

    limits = payload["limits"]
    assert limits["fields"]["key_length"]["maximum"] == LIVE_KEY_LENGTH_MAX
    assert limits["fields"]["key_length"]["minimum"] == KEY_LENGTH_MIN
    assert limits["max_concurrent_runs"] == MAX_CONCURRENT_RUNS
    assert [row["key_length"] for row in limits["cost_table"]] == [
        96,
        192,
        384,
        768,
        1024,
    ]
    assert "not a bound" in limits["cost_table_note"]

    bounds = payload["bounds"]
    assert bounds["kind"] == "proven"
    # The headline set's numbers, at the top of `bounds` and again inside it.
    assert (bounds["matched_minimum"], bounds["pooled_minimum"]) == (
        36555,
        74190,
    )
    assert f"{bounds['enforced_repudiation_bound']:.4e}" == "1.4139e-09"
    headline = bounds["headline"]
    assert headline["key_length"] == 115200
    assert (headline["minimum_matched"], headline["minimum_pooled"]) == (
        36555,
        74190,
    )
    assert f"{headline['enforced_repudiation_bound']:.4e}" == "1.4139e-09"
    assert headline["floors_are_live"] is True
    # Published and never run: four minutes and ~37 MB of transcript a session.
    assert headline["runnable"] is False
    assert "NOT RUNNABLE HERE" in headline["note"]
    assert bounds["chsh_classical_bound"] == 2.0
    assert f"{bounds['chsh_tsirelson_bound']:.4f}" == "2.8284"
    assert bounds["degenerate_below_key_length"] == FLOOR_CROSSOVER
    # Measured is labelled measured, and carries its sample size.
    assert payload["noise_null_calibration"]["kind"] == "measured"
    assert payload["noise_null_calibration"]["runs_per_level"] == 30
    assert [
        level["detected"]
        for level in payload["noise_null_calibration"]["levels"]
    ] == [0, 14, 23, 28, 30, 30]
    # D9: the panel names the parameters it was measured at and the command
    # that regenerates it. Before the whole-project audit it carried neither.
    assert payload["noise_null_calibration"]["key_length"] == 384
    assert payload["noise_null_calibration"]["check_fraction"] == 0.25
    assert "tools/sweep.py" in payload["noise_null_calibration"]["regenerate"]


def test_the_demo_set_is_published_with_its_own_uselessness_attached(client):
    """A demo-scale run cannot demonstrate non-repudiation, and the payload says so.

    The floors are inert and the enforced bound is ``0.994``. Publishing the
    number beside the note is what stops a screen turning ``transferable:
    true`` into a security claim it does not have.
    """
    demo = client.get("/api/defaults").json()["bounds"]["demo"]
    assert demo["key_length"] == 192
    # The floors ARE live at 192 -- the pooled one bites from 137 up -- and the
    # payload says so, because /api/run says so for the same length. What makes
    # the demo set unquotable is the enforced repudiation bound below, which is
    # order one, and never a floor claim the rest of the project disagrees with.
    assert demo["floors_are_live"] is True
    assert f"{demo['enforced_repudiation_bound']:.4f}" == "0.9940"
    assert "cannot demonstrate non-repudiation" in demo["note"]


def _run_at(client, sifted: int) -> dict:
    """Return the ``run`` block for a run of exactly ``sifted`` positions."""
    body = client.post(
        "/api/run",
        json={
            "attack": "honest",
            "key_length": sifted,
            "check_fraction": 0.0,
            "seed": 11,
        },
    ).json()
    assert body["error"] is None, body["error"]
    assert body["run"]["sifted_key_length"] == sifted
    return body["run"]


def test_the_published_floor_boundary_is_the_one_a_run_actually_crosses(client):
    """``degenerate_below_key_length`` against runs on either side of it.

    The constant used to be a literal ``140`` -- the ``2 -> 3`` step in the
    pooled floor, one transition past the one that matters -- pinned by a test
    that repeated the literal. So the screen said "floors collapse below 140"
    while a run at 137, 138 or 139 came back carrying a security claim, in the
    adjacent row.

    Nothing here names a number. The boundary is read from the payload and then
    made to earn it: the run below it must carry no claim.
    """
    bounds = client.get("/api/defaults").json()["bounds"]
    boundary = bounds["degenerate_below_key_length"]
    assert boundary == FLOOR_CROSSOVER, (
        "the dashboard publishes its own copy of the crossover Phase 5 froze"
    )

    at = _run_at(client, boundary)
    below = _run_at(client, boundary - 1)
    assert at["security_claim"] is True
    assert at["floors"]["degenerate"] is False
    assert below["security_claim"] is False, (
        f"a run of {boundary - 1} sifted positions carries a claim, on a "
        f"screen that says the floors collapse below {boundary}"
    )
    assert below["floors"]["degenerate"] is True


def test_the_defaults_floor_verdict_is_the_one_the_run_endpoint_gives(client):
    """``floors_are_live`` is ``security_claim``, not a second spelling of it.

    ``_parameter_set`` scored the floors as ``m_min > 1 and pooled > 2`` while
    Phase 4 froze ``security_claim = m_min > 1 or pooled > 1``. The two
    disagree for every sifted length from the crossover up to the per-verifier
    one, which is where the dashboard's own demo set lives, so ``/api/defaults``
    published the demo set INERT and ``/api/run`` reported the same length LIVE.
    """
    from sih141.web.api import _parameter_set

    demo = client.get("/api/defaults").json()["bounds"]["demo"]
    run = _run_at(client, demo["key_length"])
    assert run["floors"]["pooled_minimum"] == demo["pooled_minimum"]
    assert demo["floors_are_live"] is run["security_claim"], (
        "the same length is INERT in /api/defaults and LIVE in /api/run"
    )
    assert demo["floors_are_live"] is not run["floors"]["degenerate"]

    # And across the whole window the two predicates used to disagree on,
    # without running any of it: the closed form the payload serves is the
    # closed form the transcript is scored by.
    for length in (24, 136, 137, 138, 160, 192, 272, 273, 512):
        published = _parameter_set(ProtocolParams(key_length=length), "")
        assert published["floors_are_live"] is security_claim_at(length), (
            f"floors_are_live disagrees with security_claim at L = {length}"
        )


def test_a_run_returns_the_contract_keys(client):
    """The four keys of the fixed contract, plus ``error``, always present."""
    body = client.post("/api/run", json=_run_body()).json()
    assert CONTRACT_KEYS <= set(body)
    assert body["error"] is None
    assert body["request"]["key_length"] == 96
    assert set(body["timings"]) == {"session_ms", "detect_ms"}
    assert body["detection"]["detected"] is False
    assert body["run"]["sifted_key_length"] == 72
    assert body["run"]["requested_key_length"] == 96


@pytest.mark.parametrize("attack", ATTACK_KEYS)
def test_every_arm_answers_over_http(client, attack):
    """Each arm survives the round trip, serialised and back."""
    body = _run_body(attack=attack, key_length=96, check_fraction=0.25)
    if attack == "channel-manipulation":
        body["noise"] = 0.3
    response = client.post("/api/run", json=body)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["error"] is None, payload["error"]
    assert payload["ground_truth"]["attack"] == attack


def test_ground_truth_is_never_inside_the_detection_object(client):
    """The whole reason it is a separate key.

    Which link Eve touched and which rounds a starver targeted live on the
    adversary's log. The detector reads a JSON transcript and nothing else, so
    the response can show what actually happened beside what the detector could
    tell -- with no chance of one leaking into the other.
    """
    for attack in ("count-starvation", "channel-intercept-resend", "replay"):
        payload = client.post(
            "/api/run", json=_run_body(attack=attack)
        ).json()
        detection = json.dumps(payload["detection"])
        assert "ground_truth" not in payload["detection"]
        assert "seams_held" not in detection
        assert payload["ground_truth"]["seams_held"]
        assert payload["ground_truth"]["acted"] is True
        assert payload["ground_truth"]["identical_to_honest"] is False


def test_the_same_request_gives_the_same_response(client):
    """Repeatable on a stage, which is the only kind of demo worth giving."""
    body = _run_body(attack="outside-forgery", seed=77)
    first = client.post("/api/run", json=body).json()
    second = client.post("/api/run", json=body).json()
    assert first["detection"] == second["detection"]
    assert first["run"] == second["run"]
    assert first["ground_truth"] == second["ground_truth"]


def test_the_two_count_exchange_orderings_are_two_experiments(client):
    """Constraint 6, from the side that can prove pooling would be wrong.

    The screen's half of this is a label and a sentence
    (``tests/test_web_frontend.py``). This is the fact underneath it: with
    every other parameter held fixed and the same seed, the two orderings of
    Phase C' produce different verdicts from the same adversary -- under
    ``before-forwarding`` the forwarded recipient refuses on provenance and
    reaches NO VERDICT, under ``after-forwarding`` he scores it and rejects.
    One is a denial of transfer and the other is a forgery caught. A mean over
    the two is a mean over two different questions, and the response carries
    the ordering inside ``grouping_key`` so that a reader groups rather than
    pools.
    """
    outcomes = {}
    for timing in ("before-forwarding", "after-forwarding"):
        body = _run_body(
            attack="recipient-forgery",
            key_length=192,
            seed=41,
            count_exchange_timing=timing,
        )
        payload = client.post("/api/run", json=body).json()
        assert payload["run"]["count_exchange_timing"] == timing
        assert timing in [str(part) for part in payload["detection"]["grouping_key"]]
        outcomes[timing] = payload["detection"]["outcomes"]
    assert outcomes["before-forwarding"] != outcomes["after-forwarding"], (
        "the two orderings produced the same outcomes, so this test no longer "
        "demonstrates why they must not be pooled"
    )
    assert "refused-to-score" in outcomes["before-forwarding"].values()
    assert "rejected" in outcomes["after-forwarding"].values()


# --------------------------------------------------------------------------- #
# 2. Bounds: refused by name, never clamped, never ignored.
# --------------------------------------------------------------------------- #


def test_a_run_at_the_live_cap_succeeds_over_http(client):
    """The published ceiling is a length the server will actually run."""
    response = client.post(
        "/api/run", json=_run_body(key_length=LIVE_KEY_LENGTH_MAX)
    )
    assert response.status_code == 200
    assert response.json()["run"]["nominal_key_length"] == LIVE_KEY_LENGTH_MAX


def test_above_the_cap_is_refused_with_a_message_that_names_the_cap(client):
    """Refused, with the number, and with no run performed."""
    response = client.post(
        "/api/run", json=_run_body(key_length=LIVE_KEY_LENGTH_MAX + 1)
    )
    assert response.status_code == 400
    body = response.json()
    assert body["field"] == "key_length"
    assert body["cap"] == LIVE_KEY_LENGTH_MAX
    assert str(LIVE_KEY_LENGTH_MAX) in body["message"]
    assert "refused rather than quietly run" in body["message"]


@pytest.mark.parametrize(
    ("field", "overrides"),
    [
        ("attack", {"attack": "nope"}),
        ("key_length", {"key_length": 10**9}),
        ("key_length", {"key_length": 8}),
        ("check_fraction", {"check_fraction": 0.95}),
        ("noise", {"noise": 0.9}),
        ("noise", {"attack": "channel-intercept-resend", "noise": 0.2}),
        ("eps", {"eps": 0.0}),
        ("channel_error_rate", {"channel_error_rate": 0.9}),
        ("count_exchange_timing", {"count_exchange_timing": "later"}),
        ("seed", {"seed": -3}),
    ],
)
def test_every_bounded_field_is_refused_by_name(client, field, overrides):
    """One 400 per field, each naming the field that refused it."""
    response = client.post("/api/run", json=_run_body(**overrides))
    assert response.status_code == 400, response.text
    assert response.json()["field"] == field


def test_an_unknown_field_is_refused_rather_than_ignored(client):
    """The failure that would be invisible on the screen.

    A body carrying ``keyLength`` would otherwise be accepted, run at the
    default ``L``, and come back labelled with the length the operator typed --
    a screen whose numbers are real and whose caption is a lie. Refusing costs
    a clear error; ignoring costs a wrong result nobody can see.
    """
    response = client.post(
        "/api/run", json={"attack": "honest", "keyLength": 1200}
    )
    assert response.status_code == 422
    assert "keyLength" in response.text


def test_a_nonsense_type_is_refused_before_the_protocol_sees_it(client):
    """Type errors stop at the schema, range errors stop at the caps."""
    assert (
        client.post("/api/run", json=_run_body(key_length="lots")).status_code
        == 422
    )
    assert (
        client.post("/api/run", json=_run_body(eps=0.0)).status_code == 400
    )


@pytest.mark.parametrize(
    ("field", "literal"),
    [
        ("noise", "NaN"),
        ("check_fraction", "Infinity"),
        ("channel_error_rate", "-Infinity"),
        ("eps", "NaN"),
        ("tolerated_depolarising", "Infinity"),
    ],
)
def test_a_non_finite_value_is_refused_and_the_refusal_is_renderable(
    client, field, literal
):
    """The refusal must survive being serialised, or the 400 becomes a 500.

    ``NaN`` and ``Infinity`` are valid **Python** and are not JSON, and
    Python's own encoder emits them by default -- so any Python client, this
    project's own tooling included, can put one on the wire. The range checks
    already refuse them by name (a non-finite value compares false against
    every bound, which is exactly why it is checked for). What did not work is
    what happened next: the refusal body carried the offending value, the
    response encoder rejects non-finite floats, and the caller got ``500
    Internal Server Error`` for a request the validator had handled correctly.
    Found by driving the running service rather than by reading it.
    """
    body = dict(_run_body())
    body.pop(field, None)
    raw = json.dumps(body)[:-1] + f', "{field}": {literal}}}'
    response = client.post(
        "/api/run",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400, response.text
    payload = response.json()
    assert payload["field"] == field
    assert "finite" in payload["message"]
    # The value is named, as text, and the whole body is strict JSON.
    assert isinstance(payload["value"], str)
    json.dumps(payload, allow_nan=False)


@pytest.mark.parametrize("field", ["key_length", "seed"])
def test_a_non_finite_integer_field_is_a_422_and_not_a_500(client, field):
    """The same trap one layer up, in the schema rather than in the caps.

    ``key_length`` and ``seed`` are integers, so a ``NaN`` never reaches this
    project's range checks: pydantic rejects it first and FastAPI's own handler
    writes the offending ``input`` into the ``422`` body -- where the response
    encoder, which forbids non-finite floats, then raised. The rejection was
    right and the report of it was a ``500``. This service renders that body
    itself for exactly that reason.
    """
    raw = f'{{"attack": "honest", "{field}": NaN}}'
    response = client.post(
        "/api/run",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422, response.text
    payload = response.json()
    assert payload["detail"][0]["loc"] == ["body", field]
    assert payload["detail"][0]["input"] == "nan"
    json.dumps(payload, allow_nan=False)


def test_no_abuse_of_the_request_surface_produces_a_500(client):
    """Sweep the shapes a hostile or careless client can send.

    Every row must come back as a refusal the screen can render -- ``400`` from
    a cap, ``422`` from the schema, ``405`` from a wrong method -- and never as
    a ``500``, which has no field, no cap and nothing an operator can act on.
    """
    bodies = [
        '{"key_length": 100000}',
        '{"key_length": 1000000000000}',
        '{"key_length": -5}',
        '{"key_length": 1.5}',
        '{"key_length": "lots"}',
        '{"key_length": null}',
        '{"key_length": NaN}',
        '{"check_fraction": Infinity}',
        '{"check_fraction": 1.5}',
        '{"noise": NaN}',
        '{"noise": -1.0}',
        '{"eps": 0.0}',
        '{"eps": -Infinity}',
        '{"channel_error_rate": NaN}',
        '{"tolerated_depolarising": Infinity}',
        '{"count_exchange_timing": "sideways"}',
        '{"count_exchange_timing": 5}',
        '{"attack": "drop-tables"}',
        '{"attack": null}',
        '{"attack": ""}',
        '{"seed": -1}',
        '{"seed": 1208925819614629174706176}',
        '{"seed": NaN}',
        '{"keyLength": 512}',
        "",
        "<<<not json>>>",
        "[1, 2, 3]",
        '"hello"',
        "null",
        "[" * 200 + "]" * 200,
        "[" * 2_000 + "]" * 2_000,
        '{"attack": "' + "a" * 100_000 + '"}',
    ]
    statuses = set()
    for raw in bodies:
        response = client.post(
            "/api/run",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code < 500, f"{raw[:60]} -> {response.text[:200]}"
        assert "Traceback" not in response.text
        json.dumps(response.json(), allow_nan=False)
        statuses.add(response.status_code)
    assert statuses <= {400, 413, 422}
    for method, path in [
        ("get", "/api/run"),
        ("delete", "/api/run"),
        ("post", "/api/health"),
        ("get", "/api/nope"),
        ("get", "/static/../api.py"),
        ("get", "/static/"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code < 500, f"{method} {path}"


@pytest.mark.parametrize("levels", [200, 2_000, 20_000])
def test_a_body_too_deep_to_encode_is_refused_and_not_a_500(client, levels):
    """The refusal must survive being written, however deep the body is.

    The second instance of the bug the non-finite tests above pin, and the
    same shape: pydantic REFUSES this body correctly -- a list is not an
    object -- and then the report of that refusal is what broke. FastAPI
    echoes the offending value back inside ``input``, and every encoder
    between the rejection and the socket walks it one stack frame per level,
    so ``jsonable_encoder`` raised :exc:`RecursionError` from inside the
    handler and a properly refused request came back as ``500``.

    Measured against the live service before the fix: ``[`` 2000 times gave
    ``500 Internal Server Error`` in 170 ms, with a ``RecursionError`` and a
    thousand-frame traceback in the log. The existing sweep already carried a
    200-deep body, which is why it passed: 200 frames fit inside Python's
    limit and 2000 do not, so the depth is the whole of the test.

    ``json_safe`` now bounds the depth *before* anything else walks the value,
    which is why the fix is an ordering as much as a guard.
    """
    response = client.post(
        "/api/run",
        content="[" * levels + "]" * levels,
        headers={"Content-Type": "application/json"},
    )
    # Which of the two refusals arrives depends on how much stack the caller
    # has left: the JSON parser itself gives up on a deep body (``400``) when
    # it is close to the limit, and the model validator refuses a list where
    # an object belongs (``422``) when it is not. Both are correct refusals.
    # The invariant under test is that neither is a 500 and both are readable.
    assert response.status_code in (400, 422), response.text[:300]
    assert "Traceback" not in response.text
    assert "RecursionError" not in response.text
    # The body is JSON a client can actually parse, which is the point.
    json.dumps(response.json(), allow_nan=False)
    if response.status_code == 422 and levels > MAX_ERROR_BODY_DEPTH:
        # The validator echoed the offending input; it must come back bounded
        # rather than at the depth the client chose.
        assert f"nested beyond {MAX_ERROR_BODY_DEPTH} levels" in response.text


# --------------------------------------------------------------------------- #
# 3. A run-level failure is not a 500, and not a clean run.
# --------------------------------------------------------------------------- #


def test_an_adversary_that_raises_is_a_200_with_an_error(client, monkeypatch):
    """The endpoint stays renderable when the arm underneath it does not."""

    def _explode(request):
        raise RuntimeError("the adversary could not mount")

    monkeypatch.setattr(driver, "_mount", _explode)
    response = client.post("/api/run", json=_run_body(attack="replay"))
    assert response.status_code == 200
    body = response.json()
    assert CONTRACT_KEYS <= set(body)
    assert body["detection"] is None and body["run"] is None
    assert body["error"]["kind"] == "run-failed"
    assert body["error"]["attack"] == "replay"
    assert "could not mount" in body["error"]["message"]
    assert body["ground_truth"]["completed"] is False


def test_the_server_refuses_rather_than_queues_when_it_is_at_capacity():
    """Session generation is CPU-bound, so the gate answers instead of waiting.

    Without the cap a handful of tabs on the run button saturates every core
    and the demo stops answering at all. With it, the over-capacity request
    comes back at once, with a ``Retry-After`` and a message that says what
    happened.
    """
    app = create_app()
    entered = threading.Barrier(MAX_CONCURRENT_RUNS + 1, timeout=30)
    release = threading.Event()

    class _Blocking:
        """A run that parks inside the gate until the test lets it go."""

        def __init__(self, request):
            self.request = request

        def to_dict(self):
            entered.wait()
            release.wait(timeout=30)
            return {
                "request": self.request.to_dict(),
                "detection": None,
                "run": None,
                "ground_truth": {},
                "timings": {"session_ms": 0.0, "detect_ms": 0.0},
                "error": None,
            }

    import sih141.web.api as api_module

    original = api_module.run_once
    api_module.run_once = _Blocking
    try:
        with TestClient(app) as blocked_client:
            statuses: list[int] = []

            def _hold() -> None:
                statuses.append(
                    blocked_client.post("/api/run", json=_run_body()).status_code
                )

            holders = [
                threading.Thread(target=_hold, daemon=True)
                for _ in range(MAX_CONCURRENT_RUNS)
            ]
            for thread in holders:
                thread.start()
            entered.wait()  # every holder is now inside the gate
            refused = blocked_client.post("/api/run", json=_run_body())
            assert refused.status_code == 503
            assert refused.headers["Retry-After"] == "3"
            body = refused.json()
            assert body["error"]["kind"] == "at-capacity"
            assert body["error"]["cap"] == MAX_CONCURRENT_RUNS
            assert body["detection"] is None
            release.set()
            for thread in holders:
                thread.join(timeout=30)
            assert statuses == [200] * MAX_CONCURRENT_RUNS
    finally:
        api_module.run_once = original


# --------------------------------------------------------------------------- #
# 4. Nothing is fetched from a network, ever.
# --------------------------------------------------------------------------- #


ENDPOINTS = (
    "/api/health",
    "/api/attacks",
    "/api/defaults",
    "/api/events",
    "/openapi.json",
    "/",
)

#: Substrings that would mean a payload pointed a browser at somewhere else.
REMOTE_MARKERS = ("http://", "https://", "//cdn.", "//fonts.", "//unpkg.")


@pytest.mark.parametrize("path", ENDPOINTS)
def test_no_served_payload_points_at_a_remote_origin(client, path):
    """A demo that dies on an unreachable CDN dies at the worst moment.

    Searched rather than reasoned about, so that a future edit adding a font
    link or an icon URL to a payload fails here instead of at a venue.
    """
    text = client.get(path).text
    for marker in REMOTE_MARKERS:
        assert marker not in text, (
            f"{path} serves a reference to {marker!r}; every asset this "
            f"dashboard needs is vendored and served locally"
        )


def test_the_run_payload_points_at_no_remote_origin(client):
    """The same check for the one endpoint that is a POST."""
    text = client.post(
        "/api/run", json=_run_body(attack="count-starvation")
    ).text
    for marker in REMOTE_MARKERS:
        assert marker not in text, marker


def test_the_cdn_backed_documentation_pages_are_off(client):
    """FastAPI's ``/docs`` is a shell that fetches Swagger UI from jsdelivr.

    With no route to the internet it renders a blank white page, which is a
    worse thing to have on a laptop at a venue than no page at all. The
    schema itself stays available at ``/openapi.json``, generated in-process.
    """
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    assert "/api/run" in schema.json()["paths"]


def test_every_endpoint_answers_with_outbound_sockets_broken(monkeypatch):
    """Verification by blocked egress, not by inspection.

    Any attempt to open a socket to something that is not loopback raises for
    the duration of this test. Every endpoint is then exercised; a handler that
    quietly fetched a resource would fail here.
    """
    real_connect = socket.socket.connect
    real_create = socket.create_connection

    def _guard(address):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in ("127.0.0.1", "::1", "localhost", ""):
            raise AssertionError(
                f"outbound connection attempted to {host!r}; this server must "
                f"fetch nothing from a network"
            )

    def _connect(self, address):
        _guard(address)
        return real_connect(self, address)

    def _create_connection(address, *args, **kwargs):
        _guard(address)
        return real_create(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket, "create_connection", _create_connection)

    with TestClient(create_app()) as offline:
        for path in ENDPOINTS:
            assert offline.get(path).status_code == 200, path
        assert offline.post("/api/run", json=_run_body()).status_code == 200


def _static_assets() -> list[Path]:
    """Return the frontend files that a browser would load, if any exist yet."""
    if not STATIC_DIR.is_dir():
        return []
    return [
        path
        for path in sorted(STATIC_DIR.rglob("*"))
        if path.is_file() and path.suffix.lower() in {".html", ".css", ".js"}
    ]


def test_no_vendored_asset_reaches_out_for_another_one():
    """The trap the phase brief names: a vendored file with a remote import.

    Checking the tags one wrote is not enough -- a stylesheet that was copied
    into the repository can still carry ``@import url(https://...)`` at the top,
    and a font face can still point at ``fonts.gstatic.com``. This looks for
    fetch-shaped references rather than for any mention of a URL, so a link in
    a comment does not fail it.

    Skipped while the frontend half has not landed; it is a shared guard, not
    a claim that the directory is populated.
    """
    assets = _static_assets()
    if not assets:
        pytest.skip("no frontend assets present yet")
    fetches = ('src="http', "src='http", 'href="http', "href='http",
               "@import url(http", "@import 'http", '@import "http',
               "url(http", "//cdn.", "//fonts.", "//unpkg.", "//code.jquery")
    offenders = []
    for path in assets:
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in fetches:
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert not offenders, (
        "these vendored assets fetch from a network at load time, which is the "
        "failure that will happen at the venue and at the worst moment: "
        + "; ".join(offenders)
    )


# --------------------------------------------------------------------------- #
# 5. The static host.
# --------------------------------------------------------------------------- #


def test_the_root_serves_the_frontend_or_says_it_is_missing(client):
    """Either the dashboard, or a page that is unmistakably not the dashboard."""
    response = client.get("/")
    assert response.status_code == 200
    text = response.text
    if not (STATIC_DIR / "index.html").is_file():
        assert "frontend is not installed" in text
        assert "/api/run" in text


def test_the_static_mount_serves_from_disk(tmp_path):
    """Assets are served locally, from the directory the app was given."""
    (tmp_path / "index.html").write_text("<h1>local</h1>", encoding="utf-8")
    (tmp_path / "app.css").write_text("body{color:#111}", encoding="utf-8")
    with TestClient(create_app(tmp_path)) as local:
        assert local.get("/").text == "<h1>local</h1>"
        assert local.get("/static/app.css").text == "body{color:#111}"
        assert local.get("/static/missing.css").status_code == 404


# --------------------------------------------------------------------------- #
# 6. The refusal path itself, which is the thing that keeps breaking.
# --------------------------------------------------------------------------- #
#
# THREE 500s IN ONE PHASE, ALL THE SAME DEFECT. A request was refused
# CORRECTLY and the code reporting the refusal then fell over while quoting the
# input back:
#
#   1. `NaN` in the error body -- JSON cannot encode it, so the 422 raised.
#   2. a body nested 2000 deep -- every encoder between the rejection and the
#      socket walks it one frame per level, so the 422 raised.
#   3. `key_length` with 309 digits -- the refusal MESSAGE multiplied it by 2.2
#      to estimate the run's cost, and `int -> float` overflowed, so the 400
#      raised.
#
# Each was fixed where it was found. The tests below are written against the
# SHAPE instead: they take every field on the request surface and push at it
# with values that are hard to RENDER rather than values that are out of range,
# because rendering is the step that was breaking. Every one of the three
# instances above is inside this sweep.


_UNRENDERABLE = {
    "nan": "NaN",
    "inf": "Infinity",
    "neg-inf": "-Infinity",
    "309-digit int": "9" * 309,
    "4300-digit int": "9" * 4300,
    "long string": '"' + "x" * 20_000 + '"',
    "deep list": "[" * 400 + "]" * 400,
    "deep object": '{"a":' * 400 + "1" + "}" * 400,
    "object": '{"nested": {"deeper": [1, 2, 3]}}',
}

_REQUEST_FIELDS = [
    "attack",
    "key_length",
    "check_fraction",
    "noise",
    "eps",
    "channel_error_rate",
    "tolerated_depolarising",
    "count_exchange_timing",
    "seed",
]


@pytest.mark.parametrize("field", _REQUEST_FIELDS)
@pytest.mark.parametrize("label", sorted(_UNRENDERABLE))
def test_no_field_can_be_made_to_crash_its_own_refusal(client, field, label):
    """Every field, against every value that is hard to RENDER.

    This is the test that would have caught all three of this phase's ``500``
    responses, and it is deliberately not a list of the three: it crosses the
    whole request surface with the whole class of value.

    A row passes when the service answers with something a screen can render --
    ``400`` naming a cap, ``422`` naming a schema violation, ``413`` naming the
    body ceiling -- carrying a body that is valid JSON with no traceback in it.
    """
    raw = "{" + json.dumps(field) + ": " + _UNRENDERABLE[label] + "}"
    response = client.post(
        "/api/run", content=raw, headers={"Content-Type": "application/json"}
    )
    assert response.status_code < 500, (
        f"{field}={label} produced {response.status_code}: "
        f"{response.text[:300]}"
    )
    assert response.status_code in {400, 413, 422}
    assert "Traceback" not in response.text
    # The body has to survive being written, which is the half that kept
    # failing: it must be JSON, and JSON that does not carry a bare NaN.
    json.dumps(response.json(), allow_nan=False)


@pytest.mark.parametrize("digits", [10, 100, 308, 309, 400, 1000, 4300])
def test_a_key_length_no_float_can_hold_is_a_400_and_not_a_500(client, digits):
    """The third instance, pinned at the boundary it crossed.

    ``sys.float_info.max`` has 309 digits. At 308 the refusal message's
    ``length * 2.2 / 1000.0`` produced a float; at 309 it raised
    :exc:`OverflowError` from inside the handler and the caller got
    ``500 Internal Server Error`` for a request the validator had already
    rejected properly. Measured before the fix: 10 digits -> 400, 100 -> 400,
    308 -> 400, 309 -> 500, 400 -> 500, 1000 -> 500.
    """
    response = client.post(
        "/api/run",
        content='{"key_length": ' + "9" * digits + "}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400, response.text[:200]
    body = response.json()
    assert body["field"] == "key_length"
    assert body["cap"] == LIVE_KEY_LENGTH_MAX
    assert str(LIVE_KEY_LENGTH_MAX) in body["message"]
    # And the refusal stays a readable size however many digits arrived.
    assert len(response.content) < 2_000, len(response.content)


def test_a_refusal_is_never_larger_than_the_request_that_caused_it(client):
    """Refusing must not amplify.

    ``RequestRefused`` names the value it refused, and the value is whatever
    the client sent -- so a large ``attack`` field came back TWICE, once inside
    the message and once as ``value``. Measured before the fix: a 1,000,014-byte
    request produced a 2,000,707-byte response, a factor of 2.00, and the
    process held it. At 256 MB the auditor measured resident memory rising to
    2.4 GB and staying there.
    """
    ratios = []
    for size in (1_000, 10_000, 60_000):
        raw = json.dumps({"attack": "x" * size})
        response = client.post(
            "/api/run",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        ratios.append(len(response.content) / len(raw))
        # The offending value appears, bounded, and never in full.
        body = response.json()
        assert len(body["value"]) < 300
        assert "more characters" in body["value"]
        assert "x" * 300 not in body["message"]
    # A refusal is a constant plus a bounded echo, so the ratio has to FALL as
    # the request grows. Before the fix it was flat at 2.00.
    assert ratios[0] > ratios[1] > ratios[2], ratios
    assert ratios[-1] < 0.1, ratios


def test_a_body_over_the_ceiling_is_refused_before_the_app_sees_it(
    client, monkeypatch
):
    """The cap is on the BODY, and it acts before anything parses it.

    ``MAX_CONCURRENT_RUNS`` protects the CPU and nothing else: the gate is
    taken after validation, so a request refused by a cap never reaches it. A
    256 MB body was therefore parsed, refused, echoed and held, and the gate
    had no opinion. This asserts the request never reaches the driver at all.
    """
    reached = []
    monkeypatch.setattr(
        driver, "run_once", lambda request: reached.append(request)
    )
    oversized = b'{"attack": "' + b"x" * (MAX_REQUEST_BYTES + 1_000) + b'"}'
    response = client.post(
        "/api/run",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413, response.text[:200]
    body = response.json()
    assert body["cap"] == MAX_REQUEST_BYTES
    assert body["field"] == "body"
    assert reached == []
    # The refusal is a few hundred bytes against a request of tens of
    # thousands: the response cannot be a function of the body's size.
    assert len(response.content) < 600
    # And the ceiling is published, so the screen can show it.
    limits = client.get("/api/defaults").json()["limits"]
    assert limits["max_request_bytes"] == MAX_REQUEST_BYTES


def test_a_body_just_under_the_ceiling_is_still_read(client):
    """The cap refuses what is over it and nothing else."""
    padding = "y" * (MAX_REQUEST_BYTES - 200)
    body = json.dumps({"attack": padding})
    assert len(body) < MAX_REQUEST_BYTES
    response = client.post(
        "/api/run", content=body, headers={"Content-Type": "application/json"}
    )
    # Refused for being an unknown attack, which means it was READ.
    assert response.status_code == 400
    assert response.json()["field"] == "attack"


def test_an_oversized_body_without_a_content_length_is_also_refused():
    """A client that declares nothing is bounded by what it actually sends.

    The declared-length check is the cheap path. A chunked body -- or one whose
    ``Content-Length`` lies -- has to be bounded by counting, and the middleware
    stops the moment the count passes the ceiling rather than accumulating to
    the end.
    """
    import asyncio

    from sih141.web.api import _BodyLimit

    seen = {"chunks": 0}

    async def receive():
        seen["chunks"] += 1
        return {
            "type": "http.request",
            "body": b"z" * 8192,
            "more_body": True,
        }

    sent = []

    async def send(message):
        sent.append(message)

    async def never(scope, receive_, send_):  # pragma: no cover - must not run
        raise AssertionError("the application was reached")

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/run",
        "headers": [(b"content-type", b"application/json")],
    }
    asyncio.run(_BodyLimit(never)(scope, receive, send))
    assert sent[0]["status"] == 413
    # It stopped counting rather than reading the (endless) body.
    assert seen["chunks"] <= (MAX_REQUEST_BYTES // 8192) + 2, seen


def test_safe_text_is_total_over_the_values_a_client_can_send():
    """The one function every refusal quotes input through, exercised directly.

    Every value below is one a client can put on the wire, and each of them
    breaks a naive ``repr`` or a naive echo. None may raise, and none may
    return something unbounded.
    """
    hostile = [
        float("nan"),
        float("inf"),
        9 * 10 ** 20_000,
        # Just past `sys.get_int_max_str_digits()`, where `repr` itself raises
        # -- built by arithmetic, because `int("9" * 4301)` raises on the way in.
        10 ** 4_301,
        "x" * 1_000_000,
        b"\xff\xfe" * 1000,
        {"deep": [1, 2, 3]},
        None,
        True,
    ]
    for value in hostile:
        text = safe_text(value)
        assert isinstance(text, str)
        assert len(text) < 300, (type(value), len(text))
        json.dumps(text)


def _nested(levels: int) -> list:
    """Return a list nested ``levels`` deep, for the depth guard."""
    root: list = []
    tip = root
    for _ in range(levels):
        inner: list = []
        tip.append(inner)
        tip = inner
    return root


def test_json_safe_bounds_length_as_well_as_depth_and_encodability():
    """The three failure modes of an echoed value, in one guard."""
    assert json_safe(float("nan")) == "nan"
    assert "nested beyond" in json.dumps(
        json_safe(_nested(MAX_ERROR_BODY_DEPTH + 40))
    )
    echoed = json_safe({"attack": "x" * 500_000})["attack"]
    assert len(echoed) < 300
    assert "more characters" in echoed
    # A huge integer has no decimal form Python will render, and the body says
    # so rather than raising while it tries.
    assert json_safe(9 * 10 ** 20_000) == "<integer of about 20001 digits>"
    # Short values are returned untouched: this is a guard, not a transform.
    assert json_safe(1024) == 1024
    assert json_safe("honest") == "honest"


# --------------------------------------------------------------------------- #
# 7. The two nulls, which is what the screen tells an operator to set.
# --------------------------------------------------------------------------- #


def test_stating_one_null_leaves_an_honest_noisy_run_detected(client):
    """The measurement the calibration panel's sentence has to be true of.

    ``detect()`` takes TWO nulls and both default to a perfect link:
    ``channel_error_rate`` for the rate family and ``tolerated_depolarising``
    for the channel family. The dashboard used to tell an operator to set "the
    link's true rate", singular, and the calibration panel asserted "0/30 at
    every level when the link's true rate is passed to detect()".

    Following that instruction on an HONEST run over a noisy link leaves the
    run DETECTED with ``honest`` RULED OUT and an adversary NAMED -- which is
    this project's own worst failure mode, arriving on a screen, by way of the
    screen's own instruction. Twelve seeds at ``L = 192``,
    ``check_fraction = 0.25``, link strength ``0.03125`` (the design noise
    level ``2 s_a``).
    """
    fired = {"neither": 0, "rate only": 0, "both": 0}
    named_with_rate_only: set[str] = set()
    outcomes_by_seed: dict[int, set[tuple]] = {}
    for seed in range(1, 13):
        for label, rate_null, channel_null in (
            ("neither", 0.0, 0.0),
            ("rate only", 0.015625, 0.0),
            ("both", 0.015625, 0.03125),
        ):
            body = client.post(
                "/api/run",
                json={
                    "attack": "honest",
                    "key_length": 192,
                    "check_fraction": 0.25,
                    "noise": 0.03125,
                    "eps": 1e-9,
                    "channel_error_rate": rate_null,
                    "tolerated_depolarising": channel_null,
                    "seed": seed,
                },
            ).json()
            detection = body["detection"]
            fired[label] += 1 if detection["detected"] else 0
            if label == "rate only":
                named_with_rate_only.update(detection["named"])
            outcomes_by_seed.setdefault(seed, set()).add(
                tuple(sorted(detection["outcomes"].items()))
            )

    assert fired == {"neither": 12, "rate only": 12, "both": 0}, fired
    # And the half-corrected run does not merely fire -- it NAMES an adversary
    # and rules the honest hypothesis out.
    assert "channel-manipulation" in named_with_rate_only
    assert "honest" not in named_with_rate_only

    # THE VERIFIERS DO NOT MOVE WITH THE NULLS. Their outcomes belong to the
    # protocol and the nulls belong to the detector, so the pair is identical
    # under all three settings on every seed -- and it is NOT "both accept
    # everywhere", which is what this note used to claim. At the design noise
    # level Bob rejects the honest signature on 5 of the 12, which is a cost of
    # noise on the SIGNATURE and a separate fact from anything that fired.
    assert all(len(seen) == 1 for seen in outcomes_by_seed.values())
    verdicts = [next(iter(seen)) for seen in outcomes_by_seed.values()]
    accepting = [row for row in verdicts if set(dict(row).values()) == {"accepted"}]
    rejecting = [row for row in verdicts if dict(row)["Bob"] == "rejected"]
    assert (len(accepting), len(rejecting)) == (7, 5), (
        len(accepting),
        len(rejecting),
    )


def test_the_run_reports_which_nulls_were_stated(client):
    """A three-state fact, computed in Python, because the screen branches on it.

    ``Detection.null_is_noiseless`` is the RATE family's flag and nothing more.
    A screen with only that flag cannot tell "both nulls default" from "one
    null stated", and those two states need different words -- one is a
    standing caution, the other is the state in which an honest run is reported
    as an attack.
    """
    cases = {
        (0.0, 0.0): ("both_are_default", True),
        (0.015625, 0.0): ("both_are_default", False),
        (0.0, 0.03125): ("both_are_default", False),
        (0.015625, 0.03125): ("both_are_stated", True),
    }
    for (rate_null, channel_null), (key, expected) in cases.items():
        run = client.post(
            "/api/run",
            json=_run_body(
                channel_error_rate=rate_null,
                tolerated_depolarising=channel_null,
            ),
        ).json()["run"]
        nulls = run["nulls"]
        assert nulls[key] is expected, (rate_null, channel_null, nulls)
        assert nulls["rate_null_field"] == "channel_error_rate"
        assert nulls["channel_null_field"] == "tolerated_depolarising"
        assert nulls["channel_error_rate"] == rate_null
        assert nulls["tolerated_depolarising"] == channel_null
        # Exactly one of the three states is true at a time.
        assert not (nulls["both_are_default"] and nulls["both_are_stated"])


def test_the_calibration_sentence_is_true_when_it_is_read_alone(client):
    """A published sentence has to survive being quoted without its neighbours.

    ``with_true_rate_passed`` is the line under the calibration table, and it
    is the line a reader takes away. Saying "the link's true rate" left it
    describing an instruction that does not work, and the correcting sentence
    the API also ships was rendered nowhere.
    """
    calibration = client.get("/api/defaults").json()["noise_null_calibration"]
    headline = calibration["with_true_rate_passed"]
    assert "channel_error_rate" in headline
    assert "tolerated_depolarising" in headline
    assert "BOTH" in headline
    second = calibration["second_null_note"]
    assert second
    assert "12/12" in second and "0/12" in second
    # And it no longer claims something that is false on 5 of those 12 seeds.
    assert "verifiers accept in every" not in second
    assert "Bob rejects" in second
    # The measured table itself is unchanged: it is a Phase 4 result.
    assert calibration["kind"] == "measured"
    assert calibration["runs_per_level"] == 30


def test_the_published_bound_note_names_the_pair_the_factor_belongs_to(client):
    """``2.944`` is ``eps / false_positive_bound`` and nothing else.

    The note read "...never eps and never evidence_bound, which is a post hoc
    statement ... : at L = 384, eps = 1e-9 the two differ by a factor of
    2.944." The nearest antecedent for "the two" is the
    ``false_positive_bound`` / ``evidence_bound`` pair the clause has just
    contrasted, and THAT ratio is about ``7e9``. Measured here, so the sentence
    and the arithmetic cannot drift apart.
    """
    honest = client.post(
        "/api/run",
        json={
            "attack": "honest",
            "key_length": 384,
            "check_fraction": 0.25,
            "eps": 1e-9,
            "seed": 7,
        },
    ).json()["detection"]
    slack = honest["eps"] / honest["false_positive_bound"]
    assert f"{slack:.3f}" == "2.944"
    assert honest["evidence_bound"] is None

    fired = client.post(
        "/api/run",
        json={
            "attack": "count-starvation",
            "key_length": 192,
            "check_fraction": 0.25,
            "eps": 1e-9,
            "seed": 7,
        },
    ).json()["detection"]
    ratio = fired["false_positive_bound"] / fired["evidence_bound"]
    assert ratio > 1e9, ratio

    note = client.get("/api/defaults").json()["bounds"]["note"]
    assert "2.944" in note
    # The factor is bound to the budget-versus-bound pair, by name, in the
    # same clause -- and evidence_bound is described on its own scale.
    budget_clause = note.split("2.944")[0]
    assert "eps" in budget_clause and "false_positive_bound" in budget_clause
    assert "7e9" in note


# --------------------------------------------------------------------------- #
# 8. Cold loads, stale assets, and the one command.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/static/js/app.js",
        "/static/css/app.css",
        "/static/data/recorded/index.json",
    ],
)
def test_the_frontend_is_served_with_revalidation_forced(client, path):
    """No asset may be reused without asking, so a dead service cannot hide.

    With no ``Cache-Control`` at all, whether a file survived the process dying
    was decided by the browser's HEURISTIC freshness -- roughly a tenth of the
    file's age. A cold load against a dead service therefore had no single
    behaviour: on this tree it rendered the whole page from cache with a
    masthead reading ``RECORDED ONLY -- API NOT REACHABLE`` above a rail with
    ZERO recorded runs in it, and on a tree whose files had just been edited it
    did not render at all.

    ``no-cache`` means revalidate-before-reuse, not do-not-store: a live server
    answers ``304`` over loopback in well under a millisecond, and a dead one
    produces the browser's own error page instead of a shell promising a
    fallback it does not have.
    """
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"


@pytest.mark.parametrize("path", ["/api/health", "/api/attacks", "/api/defaults"])
def test_no_api_answer_may_be_served_from_a_cache(client, path):
    """A cached liveness check is a masthead lying about a dead process.

    ``/api/health`` is polled every five seconds so the screen's ``LIVE API``
    claim is *verified* rather than inferred from something else failing. That
    only works if the poll reaches the process: a heuristically cached
    ``{"ok": true}`` would restore the exact defect the poll closes, with the
    masthead asserting a live API over a process that is gone. The other two
    are live facts about the running build for the same reason.
    """
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


def test_the_service_listens_on_both_loopback_families():
    """``localhost`` is two addresses, and a browser may pick either.

    ``127.0.0.1`` and ``0.0.0.0`` are IPv4 wildcards: nothing listens on
    ``::1``. Measured before the fix, with the server started on
    ``--host 0.0.0.0``: ``http://127.0.0.1:PORT/api/health`` answered and
    ``http://[::1]:PORT/api/health`` returned nothing at all. On Windows
    ``--host ::`` is the mirror image, because an IPv6 socket is ``V6ONLY`` by
    default there.
    """
    from sih141.web.__main__ import bind_hosts, open_listeners

    assert bind_hosts("127.0.0.1") == ("127.0.0.1", "::1")
    assert bind_hosts("0.0.0.0") == ("0.0.0.0", "::")
    assert bind_hosts("10.0.0.7") == ("10.0.0.7",)

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    sockets, bound, skipped = open_listeners("127.0.0.1", port)
    try:
        assert f"http://127.0.0.1:{port}" in bound
        # Every socket that was opened really accepts a connection.
        for listener in sockets:
            address = (
                ("::1", port)
                if listener.family is socket.AF_INET6
                else ("127.0.0.1", port)
            )
            with socket.socket(listener.family, socket.SOCK_STREAM) as caller:
                caller.settimeout(5)
                caller.connect(address)
        if not skipped:
            assert f"http://[::1]:{port}" in bound, bound
            assert socket.AF_INET6 in {s.family for s in sockets}
    finally:
        for listener in sockets:
            listener.close()


def test_every_announced_address_is_the_port_that_was_bound():
    """``--port 0`` announced two addresses ending in ``:0``, on two ports.

    The banner was built from the REQUESTED port, so the one flag that makes
    the requested port differ from the bound one falsified the invariant the
    bind-first fix exists for: neither printed address was ever bound, and the
    loopback pair had landed on two different ephemeral ports, which is two
    servers and not one.
    """
    from sih141.web.__main__ import open_listeners

    sockets, bound, skipped = open_listeners("127.0.0.1", 0)
    try:
        ports = {listener.getsockname()[1] for listener in sockets}
        assert 0 not in ports
        assert len(ports) == 1, (
            f"the loopback pair is two servers on {sorted(ports)}, not one"
        )
        announced = [url.rsplit(":", 1)[1] for url in bound]
        assert announced == [
            str(listener.getsockname()[1]) for listener in sockets
        ], f"announced {bound}, bound {sorted(ports)}"
        # And the announced address really answers, which ``:0`` never could.
        for listener in sockets:
            host = "::1" if listener.family is socket.AF_INET6 else "127.0.0.1"
            with socket.socket(listener.family, socket.SOCK_STREAM) as caller:
                caller.settimeout(5)
                caller.connect((host, ports.copy().pop()))
    finally:
        for listener in sockets:
            listener.close()
    assert skipped == [] or len(sockets) == 1


def test_a_busy_port_fails_before_any_address_is_announced(capsys):
    """Bind first, announce second.

    The banner used to be printed before ``uvicorn.run`` attempted the bind, so
    a second instance on a busy port printed ``http://HOST:PORT`` -- an address
    it never bound -- then uvicorn's own startup lines, then the bind error,
    and ENDED on ``Application shutdown complete``, which reads like a clean
    stop. A presenter who left an instance running an hour ago reads the
    address line and demonstrates against the OLD process.
    """
    from sih141.web.__main__ import main, open_listeners

    held, _bound, _skipped = open_listeners("127.0.0.1", 0)
    try:
        port = held[0].getsockname()[1]
        status = main(["--port", str(port)])
    finally:
        for listener in held:
            listener.close()

    assert status == 1
    printed = capsys.readouterr().out
    assert "COULD NOT START" in printed
    assert str(port) in printed
    # The one thing that must NOT be there: an address that was never bound.
    assert "http://" not in printed
    assert "shutdown complete" not in printed


def test_an_unwritable_audit_log_path_fails_and_announces_no_address(
    tmp_path, capsys
):
    """The other way a start can fail, held to the same rule as a busy port.

    ``--audit-log`` names the one file this server can be asked to write, and a
    path inside a directory that does not exist cannot be opened. The operator
    is told that, and is not handed an address belonging to a process which is
    about to exit.
    """
    from sih141.web.__main__ import main

    missing = tmp_path / "no-such-directory" / "events.jsonl"
    status = main(["--port", "0", "--audit-log", str(missing)])

    assert status == 1
    printed = capsys.readouterr().out
    assert "COULD NOT START" in printed
    assert "http://" not in printed
    assert not missing.parent.exists()


def test_a_start_that_could_not_bind_leaves_no_audit_log_file(
    tmp_path, capsys
):
    """A start that failed wrote nothing to the operator's disk.

    :class:`~sih141.audit.AuditLog` opens its file at construction, which
    creates it. Building the log before the bind therefore left an empty JSON
    Lines file behind on every run that then found the port busy: a run whose
    own message read ``Nothing is serving`` and which had already written. So
    the port is tried first.
    """
    from sih141.web.__main__ import main, open_listeners

    path = tmp_path / "run-events.jsonl"
    held, _bound, _skipped = open_listeners("127.0.0.1", 0)
    try:
        port = held[0].getsockname()[1]
        status = main(["--port", str(port), "--audit-log", str(path)])
    finally:
        for listener in held:
            listener.close()

    assert status == 1
    assert "COULD NOT START" in capsys.readouterr().out
    assert not path.exists()
