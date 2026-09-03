"""Record the real ``/api/*`` responses the Phase 6 dashboard renders.

WHY THIS EXISTS
---------------
The dashboard's two halves -- the FastAPI service and the static frontend --
were built in parallel. The frontend could not wait for the service, and a
frontend developed by clicking a live server is a frontend nobody can test: the
whole screen becomes a function of whatever a run happened to produce that
afternoon.

So the frontend renders **recorded** responses, and this script produces them by
driving :func:`sih141.web.api.create_app` through
:class:`fastapi.testclient.TestClient`. Nothing here reshapes anything: what is
written to disk is byte-for-byte what the service returns, so the recorded mode
and the live mode render the same objects through the same code and a drift
between them is impossible rather than merely unlikely.

The recordings live under ``sih141/web/static/data/recorded/`` and are served by
the page itself. That makes them three things at once:

* the frontend's test fixtures -- ``tests/test_web_frontend.py`` asserts against
  them, and they are the only way to check that a denial renders as a no-verdict
  or that an unmonitored link reads "not evaluated";
* the walk-through -- thirteen runs in the order the demonstration takes them,
  including the two that exist to show what the screen must NOT claim;
* the fallback -- if the service dies mid-demonstration the page notices, says
  ``RECORDED ONLY`` in the masthead, and keeps working.

USAGE
-----
Regenerate everything (about ten seconds)::

    python tools/phase6_fixtures.py

Regenerate one::

    python tools/phase6_fixtures.py --only honest_noisy_wrong_null
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # pragma: no cover - convenience for direct runs
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "sih141" / "web" / "static" / "data" / "recorded"

#: The demonstration, in order: the baseline, then the baseline's own failure
#: mode, then the five adversaries, then the runs that exist to show what this
#: screen must not claim. Each entry is the ``POST /api/run`` body plus the
#: words the button carries -- a recorded run nobody can state the point of is
#: a recorded run nobody will click.
SCENARIOS: dict[str, dict[str, Any]] = {
    "honest": {
        "label": "Honest baseline",
        "why": (
            "L = 192, clean link, noiseless null. Nothing fires. This is the "
            "run the false-positive bound is a statement about."
        ),
        "body": {
            "attack": "honest",
            "key_length": 192,
            "check_fraction": 0.25,
            "seed": 7,
        },
    },
    "honest_noisy_wrong_null": {
        "label": "Honest, noisy link, noiseless null",
        "why": (
            "The same honest run over a link at the design noise level "
            "2 s_a = 0.03125, scored against detect()'s DEFAULT null. It "
            "DETECTS, correctly, and that is not evidence of an adversary."
        ),
        "body": {
            "attack": "honest",
            "key_length": 192,
            "check_fraction": 0.25,
            "noise": 0.03125,
            "seed": 13,
        },
    },
    "honest_noisy_right_null": {
        "label": "Honest, noisy link, true null",
        "why": (
            "The same run with the link's true rate handed to detect() for "
            "both families. The operator sets the null; it is never inferred."
        ),
        "body": {
            "attack": "honest",
            "key_length": 192,
            "check_fraction": 0.25,
            "noise": 0.03125,
            "channel_error_rate": 0.015625,
            "tolerated_depolarising": 0.03125,
            "seed": 13,
        },
    },
    "honest_unmonitored": {
        "label": "Honest, unmonitored link",
        "why": (
            "check_fraction = 0. The whole channel family is unevaluable, and "
            "an unmonitored link is NOT a clean one."
        ),
        "body": {
            "attack": "honest",
            "key_length": 192,
            "check_fraction": 0.0,
            "seed": 11,
        },
    },
    "outside_forgery": {
        "label": "Outside forgery",
        "why": "Eve declares a key drawn independently of every record.",
        "body": {
            "attack": "outside-forgery",
            "key_length": 192,
            "check_fraction": 0.25,
            "seed": 21,
        },
    },
    "impersonation_partial": {
        "label": "Impersonation, one seam",
        "why": "Mallory signs with her own key while Alice distributes.",
        "body": {
            "attack": "impersonation-partial",
            "key_length": 192,
            "check_fraction": 0.25,
            "seed": 51,
        },
    },
    "impersonation_full": {
        "label": "Impersonation, both seams",
        "why": (
            "Undetectable by construction under (AUTH). Nothing fires, and "
            "that is a proof rather than a miss."
        ),
        "body": {
            "attack": "impersonation-full",
            "key_length": 192,
            "check_fraction": 0.25,
            "seed": 61,
        },
    },
    "recipient_forgery": {
        "label": "Recipient forgery",
        "why": (
            "Bob forwards his own log to Charlie. The upper count tail is the "
            "one signal that separates this from channel noise."
        ),
        "body": {
            "attack": "recipient-forgery",
            "key_length": 192,
            "check_fraction": 0.25,
            "seed": 41,
        },
    },
    "count_starvation": {
        "label": "Count starvation",
        "why": (
            "L = 384. A recipient starves the wire integer and the other "
            "party reaches NO VERDICT -- which is not a rejection."
        ),
        "body": {
            "attack": "count-starvation",
            "key_length": 384,
            "check_fraction": 0.25,
            "seed": 500001,
        },
    },
    "replay": {
        "label": "Replay",
        "why": (
            "A decided round presented again; the session binding and the "
            "consumed-records ledger refuse it and the refusal is recorded."
        ),
        "body": {
            "attack": "replay",
            "key_length": 192,
            "check_fraction": 0.25,
            "seed": 81,
        },
    },
    "channel_manipulation": {
        "label": "Channel manipulation, one link",
        "why": (
            "A Pauli twirl on one recipient's link only. Watch QBER and CHSH "
            "move there and stay put on the other."
        ),
        "body": {
            "attack": "channel-manipulation",
            "key_length": 192,
            "check_fraction": 0.25,
            "noise": 0.5,
            "seed": 71,
        },
    },
    "channel_untargeted": {
        "label": "Channel adversary that did not act",
        "why": (
            "Eve is mounted on the resource seam at strength 0 and passes "
            "every pair through. The transcript is an honest transcript and "
            "is shown as one."
        ),
        "body": {
            "attack": "channel-manipulation",
            "key_length": 192,
            "check_fraction": 0.25,
            "noise": 0.0,
            "seed": 7,
        },
    },
    "degenerate_key_length": {
        "label": "Degenerate key length",
        "why": (
            "L = 48. Both floors collapse, the run carries no security claim "
            "at all, and every number still computes cheerfully."
        ),
        "body": {
            "attack": "honest",
            "key_length": 48,
            "check_fraction": 0.25,
            "seed": 97,
        },
    },
}


def main(argv: list[str] | None = None) -> int:
    """Record the API's responses.

    Parameters
    ----------
    argv : list of str, optional

    Returns
    -------
    int
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", default=None, help="one scenario key")
    namespace = parser.parse_args(argv)

    from fastapi.testclient import TestClient

    from sih141.web.api import create_app

    client = TestClient(create_app())
    FIXTURES.mkdir(parents=True, exist_ok=True)

    wanted = [namespace.only] if namespace.only else list(SCENARIOS)
    for scenario in wanted:
        if scenario not in SCENARIOS:
            raise SystemExit(
                f"unknown scenario {scenario!r}; have "
                f"{', '.join(SCENARIOS)}"
            )
        body = SCENARIOS[scenario]["body"]
        response = client.post("/api/run", json=body)
        if response.status_code != 200:
            raise SystemExit(
                f"{scenario}: the API refused the request "
                f"({response.status_code}): {response.text[:400]}"
            )
        payload = response.json()
        path = FIXTURES / f"run_{scenario}.json"
        path.write_text(
            json.dumps(payload, indent=1) + "\n", encoding="utf-8"
        )
        detection = payload["detection"]
        truth = payload["ground_truth"]
        print(
            f"{scenario:26s} detected={str(detection['detected']):5s} "
            f"signals={len(detection['signals']):2d} "
            f"withheld={len(detection['withheld']):2d} "
            f"no-verdict={len(detection['not_scored']):d} "
            f"acted={str(truth.get('acted')):5s} -> {path.name}"
        )

    if not namespace.only:
        for name, route in (
            ("health.json", "/api/health"),
            ("attacks.json", "/api/attacks"),
            ("defaults.json", "/api/defaults"),
        ):
            (FIXTURES / name).write_text(
                json.dumps(client.get(route).json(), indent=1) + "\n",
                encoding="utf-8",
            )
        index = [
            {
                "scenario": scenario,
                "file": f"run_{scenario}.json",
                "attack": SCENARIOS[scenario]["body"]["attack"],
                "label": SCENARIOS[scenario]["label"],
                "why": SCENARIOS[scenario]["why"],
                "request": SCENARIOS[scenario]["body"],
            }
            for scenario in SCENARIOS
        ]
        (FIXTURES / "index.json").write_text(
            json.dumps(index, indent=1) + "\n", encoding="utf-8"
        )
        print("wrote health.json, attacks.json, defaults.json, index.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
