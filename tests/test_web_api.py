"""The four endpoints and the static host, driven through FastAPI's TestClient.

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
from sih141.web import driver
from sih141.web.api import STATIC_DIR, create_app
from sih141.web.catalogue import ATTACK_KEYS, DETECTABLE_VALUES
from sih141.web.limits import (
    KEY_LENGTH_MIN,
    LIVE_KEY_LENGTH_MAX,
    MAX_CONCURRENT_RUNS,
    MAX_ERROR_BODY_DEPTH,
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
    assert bounds["degenerate_below_key_length"] == 140
    # Measured is labelled measured, and carries its sample size.
    assert payload["noise_null_calibration"]["kind"] == "measured"
    assert payload["noise_null_calibration"]["runs_per_level"] == 30
    assert [
        level["detected"]
        for level in payload["noise_null_calibration"]["levels"]
    ] == [0, 13, 17, 27, 30, 30]


def test_the_demo_set_is_published_with_its_own_uselessness_attached(client):
    """A demo-scale run cannot demonstrate non-repudiation, and the payload says so.

    The floors are inert and the enforced bound is ``0.994``. Publishing the
    number beside ``floors_are_live: false`` is what stops a screen turning
    ``transferable: true`` into a security claim it does not have.
    """
    demo = client.get("/api/defaults").json()["bounds"]["demo"]
    assert demo["key_length"] == 192
    assert demo["floors_are_live"] is False
    assert f"{demo['enforced_repudiation_bound']:.4f}" == "0.9940"
    assert "cannot demonstrate non-repudiation" in demo["note"]


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
    assert statuses <= {400, 422}
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


ENDPOINTS = ("/api/health", "/api/attacks", "/api/defaults", "/openapi.json", "/")

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
