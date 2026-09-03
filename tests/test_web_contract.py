"""The live API, held to the frontend's published read-side contract.

The dashboard's two halves were built in parallel. The frontend could not wait
for a server, so it was developed against recorded responses and states the
names it renders in ``sih141/web/static/data/api-contract.json`` -- a
machine-readable list of the fields each panel needs. Its own tests hold that
file and the recorded fixtures to each other. **Nothing held it to the live
service**, and that gap is exactly where a demo goes quiet: the page degrades a
panel to "the API did not supply <field>" rather than inventing a number, which
is the right failure and still leaves a screen of grey boxes in front of a
judge.

So this file closes the loop from the other side. Every field the contract calls
``required`` must be present on a real ``TestClient`` response, for a spread of
arms that exercises the shapes most likely to go missing -- a run where a
verifier reached no verdict, a run with no check rounds at all, a run where the
adversary declined to act.

It is deliberately **one-directional**. Extra keys in a response are fine and
expected: the service publishes more than the page renders, and a contract that
forbade that would turn every addition into a coordinated change. What it will
not tolerate is a *missing* field, because that is the one that blanks a panel.

Skipped, with a message, when the contract file is not present -- it belongs to
the other half and this file does not create it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sih141.web.api import STATIC_DIR, create_app


CONTRACT_PATH = STATIC_DIR / "data" / "api-contract.json"


@pytest.fixture(scope="module")
def contract() -> dict[str, Any]:
    """Load the frontend's read-side contract, or skip."""
    if not CONTRACT_PATH.is_file():
        pytest.skip(f"no read-side contract at {CONTRACT_PATH}")
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def client() -> TestClient:
    """One application, driven in-process."""
    return TestClient(create_app())


#: One request per shape the contract has a panel for. The point of the spread
#: is the awkward ones: a denied verifier has no statistics at all, an
#: unmonitored run publishes no links, and an inert adversary produces an
#: honest transcript. Each of those is a place a field can go missing.
SHAPES: dict[str, dict[str, Any]] = {
    "honest": {"attack": "honest", "key_length": 96, "check_fraction": 0.25},
    "honest-unmonitored": {
        "attack": "honest",
        "key_length": 96,
        "check_fraction": 0.0,
    },
    "denied-verdict": {
        "attack": "count-starvation",
        "key_length": 192,
        "check_fraction": 0.25,
    },
    "refused-forward": {
        "attack": "replay",
        "key_length": 96,
        "check_fraction": 0.25,
    },
    "inert-adversary": {
        "attack": "channel-manipulation",
        "key_length": 96,
        "check_fraction": 0.25,
        "noise": 0.0,
    },
    "targeted-link": {
        "attack": "channel-manipulation",
        "key_length": 96,
        "check_fraction": 0.25,
        "noise": 0.4,
    },
}


@pytest.fixture(scope="module")
def responses(client) -> dict[str, dict[str, Any]]:
    """One live response per shape."""
    out = {}
    for name, body in SHAPES.items():
        response = client.post("/api/run", json={**body, "seed": 31})
        assert response.status_code == 200, (name, response.text)
        out[name] = response.json()
    return out


def _missing(payload: Any, names: list[str]) -> list[str]:
    """Return the names ``payload`` does not carry."""
    if payload is None:
        return list(names)
    return [name for name in names if name not in payload]


def test_health_and_attacks_carry_what_the_page_reads(client, contract):
    """The two payloads the page loads before anything else."""
    endpoints = contract["endpoints"]
    health = client.get("/api/health").json()
    assert not _missing(health, endpoints["health"]["required"])

    roster = client.get("/api/attacks").json()
    required = endpoints["attacks"]["item_required"]
    for entry in roster:
        assert not _missing(entry, required), entry.get("key")

    # The page validates this vocabulary. A fourth value would not be a richer
    # answer, it would be an unrenderable one.
    allowed = set(endpoints["attacks"]["detectable_values"])
    unknown = sorted(
        {entry["detectable"] for entry in roster} - allowed
    )
    assert not unknown, (
        f"the roster publishes detectability values the page cannot render: "
        f"{unknown}. The vocabulary is fixed at {sorted(allowed)} -- extending "
        f"it needs both halves, because a value the page does not know is a "
        f"blank cell, and a blank cell beside a column of verdicts reads as "
        f"'we tried and failed'."
    )


def test_defaults_carries_what_the_page_reads(client, contract):
    """Every field the controls, the caps panel and the headline panel need."""
    spec = contract["endpoints"]["defaults"]
    payload = client.get("/api/defaults").json()
    assert not _missing(payload, spec["required"])
    assert not _missing(payload, spec.get("expected", []))
    assert not _missing(payload["params"], spec.get("params_expected", []))
    assert not _missing(payload["bounds"], spec.get("bounds_expected", []))
    for name in ("headline", "demo"):
        assert not _missing(
            payload["bounds"][name], spec.get("parameter_set_expected", [])
        ), name
    # The headline set is published and never run, and the payload says which
    # of the two it is rather than leaving the screen to infer it.
    assert payload["bounds"]["headline"]["runnable"] is False
    assert payload["bounds"]["demo"]["runnable"] is True
    limits = payload["limits"]
    assert not _missing(limits, spec.get("limits_expected", []))
    assert not _missing(
        limits["fields"], spec.get("limit_fields_expected", [])
    )
    for row in limits["cost_table"]:
        assert not _missing(row, spec.get("cost_row_expected", [])), row


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_run_response_carries_the_contract_keys(responses, contract, shape):
    """The four top-level keys, on every shape."""
    body = responses[shape]
    assert not _missing(
        body, contract["endpoints"]["run"]["required"]
    ), shape
    assert body["error"] is None, body["error"]


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_detection_object_is_published_verbatim(responses, contract, shape):
    """All twenty-one keys, plus the shapes of the nested objects.

    ``Detection.to_dict()`` is republished unchanged -- nothing is recombined
    on the way out and nothing is recombined in the browser. Checking the
    nested signal and attribution shapes matters as much as the top level: a
    signal missing its ``claim`` is a fired threshold the screen cannot explain.
    """
    detection = responses[shape]["detection"]
    spec = contract["detection"]
    assert not _missing(detection, spec["required"]), shape
    for signal in detection["signals"]:
        assert not _missing(signal, spec["signal_required"]), signal.get("name")
    for attribution in detection["attributions"]:
        assert not _missing(
            attribution, spec["attribution_required"]
        ), attribution.get("hypothesis")
    if "budget_required" in spec:
        assert not _missing(detection["budget"], spec["budget_required"])


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_run_facts_carry_what_every_panel_needs(responses, contract, shape):
    """The transcript facts, including the rows and links the charts read."""
    facts = responses[shape]["run"]
    spec = contract["run_facts"]
    assert not _missing(facts, spec["required"]), shape
    assert not _missing(facts, spec.get("expected", [])), shape
    assert not _missing(facts["floors"], spec.get("floors_expected", []))
    assert not _missing(facts["pooled"], spec.get("pooled_expected", []))
    for row in facts["verifiers"]:
        assert not _missing(
            row, spec.get("verifier_expected", [])
        ), row.get("party")
    for link in facts["links"]:
        assert not _missing(
            link, spec.get("link_expected", [])
        ), link.get("party")


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_ground_truth_carries_what_the_page_reads(
    responses, contract, shape
):
    """The harness's knowledge, in the names the page renders it under."""
    truth = responses[shape]["ground_truth"]
    spec = contract["ground_truth"]
    assert not _missing(truth, spec["required"]), shape
    assert not _missing(truth, spec.get("expected", [])), shape


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_timings_are_present_and_measured(responses, contract, shape):
    """Both halves timed, so the page can size a wait rather than guess it."""
    timings = responses[shape]["timings"]
    assert not _missing(timings, contract["timings"]["required"])
    assert timings["session_ms"] > 0.0
    assert timings["detect_ms"] > 0.0


# --------------------------------------------------------------------------- #
# The shapes the contract exists to protect, asserted as behaviour rather than
# as field names.
# --------------------------------------------------------------------------- #


def test_a_denied_verifier_has_no_statistics_and_is_still_in_the_table(
    responses,
):
    """The row survives; every number on it is absent rather than zero.

    A party missing from a table reads as a party who was never involved. A
    party present with zeros reads as a party who scored perfectly. Bob was
    denied his evidence and did neither, and the row says so in ``null``\\ s.
    """
    facts = responses["denied-verdict"]["run"]
    rows = {row["party"]: row for row in facts["verifiers"]}
    assert set(rows) == {"Bob", "Charlie"}
    bob = rows["Bob"]
    assert bob["outcome"] == "refused-to-score"
    assert bob["scored"] is False
    assert bob["accepted"] is None
    assert bob["rate"] is None
    assert bob["matched"] is None
    assert facts["aborts"]["by_party"]["Bob"]
    # The starver kept his own verdict: a transferability inversion, not a
    # rejection of the signature.
    assert rows["Charlie"]["outcome"] == "accepted"


def test_an_unmonitored_run_publishes_no_links_at_all(responses):
    """Empty, never zero-filled: an unmonitored link is not a clean one."""
    facts = responses["honest-unmonitored"]["run"]
    assert facts["links"] == []
    assert facts["channel_evaluable"] is False
    assert facts["check_rounds_present"] is False
    withheld = " ".join(responses["honest-unmonitored"]["detection"]["withheld"])
    assert "unmonitored link is not a clean one" in withheld


def test_an_inert_adversary_is_reported_as_identical_to_honest(responses):
    """Mounted and declined is not a miss, and the payload distinguishes them."""
    truth = responses["inert-adversary"]["ground_truth"]
    assert truth["adversary_present"] is True
    assert truth["acted"] is False
    assert truth["identical_to_honest"] is True
    assert truth["targeted_links"] == []
    assert responses["inert-adversary"]["detection"]["detected"] is False


def test_a_targeted_channel_attack_names_the_link_it_touched(responses):
    """Attribution is ground truth here, and the detector never reads it."""
    truth = responses["targeted-link"]["ground_truth"]
    assert truth["acted"] is True
    assert truth["targeted_links"] == [["Bob", 0], ["Bob", 1]]
    assert truth["link"]["targeted_party"] == "Bob"
    assert truth["link"]["true_error_rate_by_party"]["Charlie"] == 0.0
    assert "targeted_links" not in json.dumps(
        responses["targeted-link"]["detection"]
    )


def test_the_link_report_pairs_each_null_with_the_truth_it_is_read_against(
    responses,
):
    """Both nulls are on the wire, and both are compared with the real link.

    detect() defaults to a perfect link twice over -- ``channel_error_rate`` for
    the rate family, ``tolerated_depolarising`` for the channel family. An
    honest run over a noisy link departs from both and fires, correctly, with
    both verifiers accepting. The screen can only say that if it is told what
    the link actually was, and that is ground truth.
    """
    link = responses["targeted-link"]["ground_truth"]["link"]
    for field in (
        "model",
        "strength",
        "targeted_party",
        "true_error_rate_by_party",
        "rate_null_given_to_detector",
        "channel_null_given_to_detector",
        "rate_null_matches_link",
        "channel_null_matches_link",
        "nulls_match_link",
    ):
        assert field in link, field
    assert link["nulls_match_link"] is False
    assert responses["targeted-link"]["detection"]["null_is_noiseless"] is True


def test_the_recorded_fixtures_and_the_live_service_agree_on_shape():
    """A recorded run and a live one must render through the same code path.

    The page serves recorded runs when no service is reachable. If the two
    disagree about field names, the demonstration silently changes behaviour
    depending on which mode it is in -- and the recorded mode is the one that
    gets used when something has already gone wrong.
    """
    recorded_dir = STATIC_DIR / "data" / "recorded"
    if not recorded_dir.is_dir():
        pytest.skip("no recorded fixtures present yet")
    files = sorted(recorded_dir.glob("run_*.json"))
    if not files:
        pytest.skip("no recorded runs present yet")
    gaps: list[str] = []
    with TestClient(create_app()) as live:
        for path in files:
            recorded = json.loads(path.read_text(encoding="utf-8"))
            request = recorded.get("request")
            if not request:
                continue
            # Replayed as the fixture was recorded, arm for arm: the
            # per-adversary blocks of ground_truth differ by arm, so one honest
            # response is not a yardstick for a starving one.
            body = live.post(
                "/api/run",
                json={
                    key: value
                    for key, value in request.items()
                    if key != "message_bit"
                },
            ).json()
            if body.get("error"):
                gaps.append(f"{path.name}: live run failed, {body['error']}")
                continue
            for name in ("run", "ground_truth"):
                missing = sorted(set(recorded[name]) - set(body[name]))
                if missing:
                    gaps.append(f"{path.name}/{name}: {missing}")
    assert not gaps, (
        "the recorded fixtures carry fields the live service does not, so a "
        "panel that renders in recorded mode would blank in live mode: "
        + "; ".join(gaps)
    )
