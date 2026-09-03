"""Phase 6: the dashboard's backend -- one process, one command, no network.

A FastAPI application that serves the JSON API **and** the static frontend, over
the interface Phase 4 fixed and nothing else. Run it with:

.. code-block:: text

    pip install -r requirements.txt
    python -m sih141.web

.. _the-frontend-computes-nothing:

Convention D8, and why this package is shaped the way it is
------------------------------------------------------------
**The frontend computes nothing.** Every number that reaches the screen comes
from this package, which got it from :func:`sih141.detect.detect` or from the
transcript. JavaScript may format, lay out, colour and plot; it may not derive,
average, sum, threshold, round-for-meaning or infer. No rate is computed in the
browser, no bound is combined in the browser, no verdict is decided in the
browser.

The reason is not style. Every guarantee this project makes lives in Python that
the test suite and ``--doctest-modules`` cover. A number computed in JavaScript
is outside the suite, outside **D5**, and outside every proven bound -- and it
would sit on the screen next to numbers that *are* covered, with nothing to tell
a reader which is which. So the rule for this package is the mirror image: **if
the screen needs a quantity, it is added here, with a test.** That is why
``/api/run``'s ``run`` object carries every per-verifier count, per-link QBER,
floor and repudiation guarantee the screen could want, all read straight off the
:class:`~sih141.detect.statistics.TranscriptStatistics` the detector itself read
-- so the panel and the verdict cannot disagree, and the browser has nothing
left to work out.

The four things this backend must not let the screen say
---------------------------------------------------------
These came out of the Phase 3 and Phase 4 audits at real cost, and they matter
more on a screen than in a table because a judge reads a screen quickly and in
public. Each one is served by a specific field:

*A no-verdict is not a rejection.* An abort is a third state.
:attr:`~sih141.detect.detector.Detection.outcomes` distinguishes ``accepted``,
``rejected``, ``refused-to-score`` and ``not-asked``; every row of
``run["verifiers"]`` carries that outcome, and a verifier who reached no verdict
carries ``rate: null`` rather than ``0.0`` -- he did not observe perfect
agreement, he observed nothing. Three arms here -- count starvation and the two
forwarding attacks under the shipped ordering -- produce a *denial*, not a
catch.

*Proven and measured are different kinds of number.* Everything under
``/api/defaults``'s ``bounds`` is labelled ``"kind": "proven"`` and is a closed
form; ``timing`` and ``noise_null_calibration`` are labelled ``"measured"`` and
carry their sample sizes. **There is no false-negative bound and there cannot be
one from a transcript**, so nothing here implies one. What a run publishes is
``false_positive_bound``, never ``eps`` and never ``evidence_bound`` -- the last
of those is a post hoc statement about the signals that fired and is a different
claim, differing from the first by a factor of 2.944 at ``L = 384``.

*The null is noiseless by default, and there are two of them.*
:attr:`~sih141.detect.detector.Detection.null_is_noiseless` is on every
response, and ``ground_truth["link"]`` says what the link actually was, which
the detector never sees. See :ref:`sih141.web.driver <the-second-null>`.

*Full impersonation is undetectable by construction.* It is an arm of the
roster whose ``detectable`` field reads ``undetectable-by-construction``, never
a blank, a dash or a zero -- a zero reads as "we tried and failed", and this is
"we proved you cannot, and here is the assumption". See
:ref:`sih141.web.catalogue <auth-is-not-a-blank>`.

The modules
-----------
:mod:`sih141.web.limits`
    Every cap on the request surface, and the rule that a parameter is refused
    rather than clamped.
:mod:`sih141.web.catalogue`
    The arms, with what each may claim, keyed by the detector's own hypothesis
    names.
:mod:`sih141.web.driver`
    The only place a session is built or the detector is called. Two
    independent streams from one seed (**D3**, **D6**), the replay arm's wiring
    trap, and ground truth kept in its own object.
:mod:`sih141.web.payload`
    The ``run`` and ``ground_truth`` objects, in the shape the frontend's
    read-side contract fixes. One producer, shared by the live endpoint and the
    recorded fixtures, so the two cannot drift.
:mod:`sih141.web.api`
    The endpoints, and the two decisions that keep the demo alive without a
    network.

Examples
--------
>>> from sih141.web import create_app
>>> from fastapi.testclient import TestClient
>>> client = TestClient(create_app())
>>> client.get("/api/health").json()
{'ok': True, 'version': '0.1.0'}
"""

from sih141.web.api import STATIC_DIR, RunBody, create_app, defaults_payload
from sih141.web.catalogue import (
    ATTACK_KEYS,
    ATTACKS,
    AttackSpec,
    attack_spec,
    roster_payload,
)
from sih141.web.driver import MESSAGE_BIT, RunRequest, RunResult, run_once
from sih141.web.limits import (
    CHECK_FRACTION_MAX,
    EPS_DEFAULT,
    EPS_MAX,
    EPS_MIN,
    KEY_LENGTH_MIN,
    LIVE_KEY_LENGTH_MAX,
    MAX_CONCURRENT_RUNS,
    RequestRefused,
    limits_payload,
)
from sih141.web.payload import ground_truth_for, run_facts

__all__ = [
    "ATTACKS",
    "ATTACK_KEYS",
    "CHECK_FRACTION_MAX",
    "EPS_DEFAULT",
    "EPS_MAX",
    "EPS_MIN",
    "KEY_LENGTH_MIN",
    "LIVE_KEY_LENGTH_MAX",
    "MAX_CONCURRENT_RUNS",
    "MESSAGE_BIT",
    "STATIC_DIR",
    "AttackSpec",
    "RequestRefused",
    "RunBody",
    "RunRequest",
    "RunResult",
    "attack_spec",
    "create_app",
    "defaults_payload",
    "ground_truth_for",
    "limits_payload",
    "roster_payload",
    "run_facts",
    "run_once",
]
