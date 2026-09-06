"""The security event log, and the dashboard that writes to it.

Two halves, in that order. The first drives :mod:`sih141.audit` directly and
holds it to the four properties the module exists for: the ordering is a
counter and never a clock, the vocabulary is closed, the retention is bounded
and says when it bit, and the store is not reachable from outside. The second
drives the running application and holds the wiring to what it must and must
not record.

The tests worth reading twice are the negative ones. A log that records a
little too much is not a smaller defect than one that records too little, and
three of these assert absence: no clock inside the library, no event for a run
that reached no verdict, and neither the seed nor the transcript on any event
-- so the log cannot become the place a dashboard's requests are quietly kept.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sih141.audit
from sih141.audit import DEFAULT_CAPACITY, AuditLog, SecurityEvent
from sih141.detect.thresholds_structural import RunOutcome
from sih141.protocol.verify import AbortReason
from sih141.web import driver
from sih141.web.api import create_app


def _record(log: AuditLog, **overrides) -> SecurityEvent:
    """Append one event, with the fields a caller must always supply."""
    fields = {
        "party": "Bob",
        "verdict": RunOutcome.ACCEPTED,
        "key_length": 192,
        "check_fraction": 0.25,
    }
    fields.update(overrides)
    return log.record(**fields)


# --------------------------------------------------------------------------- #
# 1. The log itself.
# --------------------------------------------------------------------------- #


def test_the_ordering_is_a_counter_and_the_library_never_reads_a_clock():
    """Two identical sequences of calls produce two identical logs.

    This is convention D9 applied to a log. Every published number in this
    repository is reproducible from a recorded seed and a committed command,
    and a record stamped with :func:`time.time` breaks that for no gain: two
    runs of the same command would differ in the one field nothing in the
    protocol produced. So the ordering is :attr:`SecurityEvent.seq`, and a
    caller who wants a clock passes one in.
    """
    first, second = AuditLog(), AuditLog()
    for log in (first, second):
        _record(log, party="Bob", session_id="round-1")
        _record(log, party="Charlie", verdict=RunOutcome.REJECTED)

    assert [event.seq for event in first.events()] == [0, 1]
    assert first.events() == second.events()
    assert all(event.timestamp is None for event in first.events())

    # And asserted on the source as well, because the property is "nothing in
    # here reads a clock" rather than "the two calls above happened to agree".
    source = Path(sih141.audit.__file__).read_text(encoding="utf-8")
    for banned in ("import time", "import datetime", "time.time", "utcnow"):
        assert banned not in source, banned


def test_a_caller_supplied_timestamp_is_carried_and_not_interpreted():
    """The one way a clock enters, and it is the caller's clock."""
    log = AuditLog()
    assert _record(log, timestamp="2026-09-06T00:00:00Z").timestamp == (
        "2026-09-06T00:00:00Z"
    )
    assert _record(log, timestamp=1757116800.0).timestamp == 1757116800.0


def test_a_verdict_outside_the_four_is_refused_rather_than_stored():
    """An open vocabulary is one nothing can be counted from."""
    log = AuditLog()
    with pytest.raises(ValueError):
        _record(log, verdict="maybe")
    with pytest.raises(ValueError):
        _record(log, verdict="no-verdict")
    assert len(log) == 0


def test_the_two_no_verdict_outcomes_stay_two_labels():
    """``refused-to-score`` and ``not-asked`` are different events.

    A three-valued accepted / rejected / no-verdict schema would fold them, and
    the fold is exactly the one
    :class:`~sih141.detect.thresholds_structural.RunOutcome` was written to
    prevent: a party who was asked and returned nothing and a party the run
    never reached did different things, and a log is where that difference has
    to survive.
    """
    log = AuditLog()
    _record(
        log, verdict=RunOutcome.REFUSED, abort_reason=AbortReason.BELOW_FLOOR
    )
    _record(log, verdict=RunOutcome.NOT_ASKED)
    labels = [event.to_dict()["verdict"] for event in log.events()]
    assert labels == ["refused-to-score", "not-asked"]
    assert log.events()[0].to_dict()["abort_reason"] == (
        "matched-count-below-floor"
    )
    assert log.events()[1].to_dict()["abort_reason"] is None


def test_a_party_outside_the_authorised_set_is_recordable():
    """``party`` is a string for exactly this reason.

    :class:`~sih141.protocol.params.Party` admits ``ALICE``, ``BOB`` and
    ``CHARLIE`` only, so a party outside the round's authorised recipient set
    is not representable in it. An unauthorised verification attempt is by
    definition made by such a party, and a log that cannot name him cannot
    record the event it exists for.
    """
    log = AuditLog()
    event = _record(log, party="Mallory", verdict=RunOutcome.REJECTED)
    assert event.party == "Mallory"
    assert json.loads(log.to_jsonl().splitlines()[0])["party"] == "Mallory"


def test_the_cap_drops_the_oldest_and_publishes_how_many_it_dropped():
    """A truncated log that does not say so lies by omission."""
    log = AuditLog(capacity=3)
    for _ in range(10):
        _record(log)
    assert len(log) == 3
    assert log.recorded == 10
    assert log.dropped == 7
    # The sequence keeps counting past a drop, so a gap in it is a dropped
    # event rather than a lost one.
    assert [event.seq for event in log.events()] == [7, 8, 9]
    # `/api/events` builds its whole document from one `snapshot()`, so the
    # three it returns have to be the three read separately above.
    assert log.snapshot() == (log.events(), log.recorded, log.dropped)


def test_a_log_that_never_filled_reports_no_drops():
    """The counter is not a hedge; it is zero when nothing was dropped."""
    log = AuditLog()
    assert log.capacity == DEFAULT_CAPACITY
    for _ in range(5):
        _record(log)
    assert (len(log), log.recorded, log.dropped) == (5, 5, 0)


def test_the_store_is_not_reachable_through_what_is_handed_out():
    """Append-only from the outside: no update, no delete, no live handle."""
    log = AuditLog()
    _record(log)
    snapshot = log.events()
    assert isinstance(snapshot, tuple)
    _record(log)
    # The snapshot did not grow, so it was a copy and not the store.
    assert len(snapshot) == 1 and len(log) == 2
    with pytest.raises(AttributeError):
        snapshot[0].party = "Mallory"  # frozen: an edited record is not one


def test_json_lines_is_one_object_per_line_and_needs_no_encoder():
    """``StrEnum`` members are strings, so :func:`json.dumps` takes them."""
    log = AuditLog()
    _record(log, session_id="round-1", hypotheses=["honest"])
    _record(
        log,
        party="Charlie",
        verdict=RunOutcome.REFUSED,
        abort_reason=AbortReason.POOLED_BELOW_FLOOR,
    )
    lines = log.to_jsonl().splitlines()
    assert len(lines) == 2
    rebuilt = [json.loads(line) for line in lines]
    assert rebuilt[0]["hypotheses"] == ["honest"]
    assert rebuilt[1]["abort_reason"] == "pooled-matched-count-below-floor"
    assert log.to_jsonl().endswith("\n")
    assert AuditLog().to_jsonl() == ""


def test_a_configured_path_receives_every_event_as_it_is_recorded(tmp_path):
    """The file is the other half, appended to and never rewritten."""
    path = tmp_path / "events.jsonl"
    log = AuditLog(path=path)
    _record(log, party="Bob")
    _record(log, party="Charlie")
    assert path.read_text(encoding="utf-8") == log.to_jsonl()

    # A second log on the same file appends to it: the sequence restarts,
    # because it belongs to the log and not to the file, and the earlier lines
    # are still there.
    again = AuditLog(path=path)
    _record(again, party="Bob")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert [json.loads(line)["seq"] for line in lines] == [0, 1, 0]


def test_the_file_survives_the_cap_that_memory_does_not(tmp_path):
    """Retention bounds what is *served*, not what was written."""
    path = tmp_path / "events.jsonl"
    log = AuditLog(capacity=2, path=path)
    for _ in range(6):
        _record(log)
    assert len(log) == 2 and log.dropped == 4
    assert len(path.read_text(encoding="utf-8").splitlines()) == 6


def test_an_unwritable_path_fails_at_construction_and_not_mid_run(tmp_path):
    """Loud when the log is built, not four minutes into a demonstration."""
    with pytest.raises(OSError):
        AuditLog(path=tmp_path / "no-such-directory" / "events.jsonl")


def test_concurrent_records_never_share_a_sequence_number():
    """Two runs may be in flight, and FastAPI runs each on its own thread."""
    log = AuditLog(capacity=400)
    barrier = threading.Barrier(8, timeout=30)

    def _write() -> None:
        barrier.wait()
        for _ in range(50):
            _record(log)

    threads = [threading.Thread(target=_write) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert log.recorded == 400
    assert sorted(event.seq for event in log.events()) == list(range(400))


# --------------------------------------------------------------------------- #
# 2. The dashboard, which is the only thing in the repository that writes one.
# --------------------------------------------------------------------------- #


@pytest.fixture
def client() -> TestClient:
    """A fresh application, so each test reads only its own events."""
    return TestClient(create_app())


def _events(client: TestClient) -> dict:
    """The parsed ``GET /api/events`` body."""
    response = client.get("/api/events")
    assert response.status_code == 200
    return response.json()


def test_a_run_leaves_one_event_per_verifier(client):
    """Two verifiers, two events, grouped under one identifier."""
    body = client.post(
        "/api/run", json={"attack": "honest", "key_length": 96, "seed": 5}
    ).json()
    assert body["error"] is None

    payload = _events(client)
    assert payload["count"] == 2 and payload["dropped"] == 0
    parties = [event["party"] for event in payload["events"]]
    assert parties == ["Bob", "Charlie"]
    assert [event["verdict"] for event in payload["events"]] == (
        [body["detection"]["outcomes"][party] for party in parties]
    )
    identifiers = {event["session_id"] for event in payload["events"]}
    assert len(identifiers) == 1 and None not in identifiers


def test_two_different_runs_are_two_different_identifiers(client):
    """The identifier groups a run's events; it does not label the endpoint."""
    for seed in (5, 6):
        client.post("/api/run", json={"key_length": 96, "seed": seed})
    identifiers = {event["session_id"] for event in _events(client)["events"]}
    assert len(identifiers) == 2


def test_the_recorded_length_is_the_sifted_one(client):
    """Every floor and every null is stated over the sifted length.

    A verdict filed against the length the caller asked for would be filed
    against a threshold that was never applied to it.
    """
    body = client.post(
        "/api/run",
        json={"key_length": 192, "check_fraction": 0.25, "seed": 5},
    ).json()
    lengths = {event["key_length"] for event in _events(client)["events"]}
    assert lengths == {body["run"]["sifted_key_length"]}
    assert body["run"]["requested_key_length"] == 192
    assert lengths != {192}


def test_a_denied_verifier_is_logged_with_the_reason_he_refused(client):
    """The third state reaches the log as itself, and names why.

    ``refused-to-score`` beside ``accepted`` is a transferability inversion,
    and a log that recorded it as a rejection would be reporting a verifier who
    judged the signature bad. He judged nothing.
    """
    client.post(
        "/api/run",
        json={"attack": "count-starvation", "key_length": 192, "seed": 31},
    )
    events = {event["party"]: event for event in _events(client)["events"]}
    assert events["Bob"]["verdict"] == "refused-to-score"
    # Pinned to the member, not to membership of the enum: the reason is the
    # published half of this number (seed 31, L = 192, check fraction 0.25),
    # and `in set(AbortReason)` would stay green on any of the nine.
    assert events["Bob"]["abort_reason"] == AbortReason.COUNTERPART_BELOW_FLOOR
    assert events["Charlie"]["verdict"] == "accepted"
    assert events["Charlie"]["abort_reason"] is None


def test_a_refused_request_leaves_no_event(client):
    """Nothing verified, so there is nothing to record.

    The log is one line per verification outcome, so a count taken from it is a
    count of verdicts. A refusal is a fact about the request surface and it is
    already an answer the caller received.
    """
    refused = client.post("/api/run", json={"key_length": 100000})
    assert refused.status_code == 400
    assert client.post("/api/run", json={"keyLength": 96}).status_code == 422
    assert _events(client)["events"] == []


def test_a_run_that_failed_before_a_verdict_leaves_no_event(
    client, monkeypatch
):
    """A mounted arm that raised produced no outcome to log."""

    def _explode(request):
        raise RuntimeError("the adversary could not mount")

    monkeypatch.setattr(driver, "_mount", _explode)
    body = client.post(
        "/api/run", json={"attack": "replay", "key_length": 96, "seed": 5}
    ).json()
    assert body["error"]["kind"] == "run-failed"
    assert _events(client)["count"] == 0


def test_no_event_carries_the_seed_or_the_transcript_of_the_run(client):
    """The log must not become where a dashboard's requests are kept.

    The service is unauthenticated and every reader of ``/api/events`` sees
    every event, so what is *not* on an event is the whole of the privacy
    argument: no seed, no transcript, no recipient record, and nothing about
    who sent the request. What is left describes a verdict.

    The check fraction is the one request field that does appear, and the
    permitted key set below says so. A verdict read without it is filed
    against a threshold nothing in the answer states, so it is carried
    deliberately; the name of this test claims only what the body checks.
    """
    seed = 987654321
    client.post("/api/run", json={"key_length": 96, "seed": seed})
    payload = _events(client)
    serialised = json.dumps(payload["events"])
    assert str(seed) not in serialised
    for absent in ("entries", "eigenvalue", "declared_key", "transcript"):
        assert absent not in serialised
    assert set(payload["events"][0]) == {
        "seq",
        "session_id",
        "party",
        "verdict",
        "abort_reason",
        "key_length",
        "check_fraction",
        "hypotheses",
        "timestamp",
    }


def test_the_endpoint_publishes_whether_a_file_was_configured_and_never_where(
    tmp_path,
):
    """A deployment fact, not a path off the operator's disk."""
    path = tmp_path / "events.jsonl"
    with TestClient(create_app(audit_log=AuditLog(path=path))) as client:
        client.post("/api/run", json={"key_length": 96, "seed": 5})
        payload = _events(client)
        assert payload["persisted"] is True
        assert str(path) not in json.dumps(payload)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["party"] == "Bob"


def test_the_default_application_keeps_its_log_in_memory(client):
    """Nothing here chooses to write to a disk."""
    payload = _events(client)
    assert payload["persisted"] is False
    assert payload["capacity"] == DEFAULT_CAPACITY


def test_two_applications_do_not_share_a_log():
    """One log per application, so one reader cannot see another's runs."""
    first = TestClient(create_app())
    second = TestClient(create_app())
    first.post("/api/run", json={"key_length": 96, "seed": 5})
    assert _events(first)["count"] == 2
    assert _events(second)["count"] == 0


def test_the_events_answer_may_not_be_served_from_a_cache(client):
    """Live facts about the running process, like every other API answer."""
    assert client.get("/api/events").headers["cache-control"] == "no-store"


def test_the_run_response_is_unchanged_by_the_presence_of_a_log(client):
    """The frontend's read-side contract is untouched by this feature."""
    body = client.post(
        "/api/run", json={"attack": "honest", "key_length": 96, "seed": 2}
    ).json()
    assert sorted(body) == [
        "detection",
        "error",
        "ground_truth",
        "request",
        "run",
        "timings",
    ]
    assert "audit" not in json.dumps(body)
