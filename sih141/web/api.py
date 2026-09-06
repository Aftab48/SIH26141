"""The JSON API and the static host: one process, one command, no network.

Five endpoints and a file server, over :mod:`sih141.web.driver`. Nothing here
computes a protocol quantity; it validates, it serialises, and it refuses.

.. _the-server-now-keeps-something:

The one thing the server keeps, and what bounds it
--------------------------------------------------
Every API answer is sent ``Cache-Control: no-store`` and, until the security
event log, the process kept nothing at all between requests. A log is a
deliberate reversal of that, so it is bounded in three directions at once.

**In size.** :class:`~sih141.audit.AuditLog` retains
:data:`~sih141.audit.DEFAULT_CAPACITY` events and drops the oldest past that,
reporting how many it dropped. Two events per run, so a demonstration cannot
grow the process without limit and a reader cannot mistake a truncated log for
a whole one. The cap is on what the process holds and what ``/api/events``
serves; a file, where one is configured, receives every event and is not
trimmed by anything here.

**In lifetime.** The log lives in memory and dies with the process unless a
caller hands :func:`create_app` one built with a ``path``. Nothing here chooses
to write to a disk.

**In content.** An event carries the party, the four-valued outcome, the abort
reason, the sifted length, the check fraction and the hypotheses the detector
named. It carries no client address, no header and no cookie, and of the
request only the check fraction, which the verdict cannot be read without: not
the seed, not the transcript, not one entry of a recipient record. So the log
holds nothing that identifies who asked for a run and nothing that would let
one reader reconstruct another's. ``session_id`` is a digest of the resolved
request and of nothing else, present so that the two verifiers of one run
group together; nothing of the request it digests is recorded beside it except
the check fraction named above, which is one of nine fields and reveals none
of the other eight.

What is *not* logged is as deliberate: a body refused for its size or its
range, and a run that failed before a verdict, produce no event. The log is one
line per verification outcome, so a count taken from it is a count of verdicts.

.. _nothing-is-fetched:

Nothing is fetched from a network, ever
----------------------------------------
Venue wifi fails, and a demo that dies on an unreachable CDN dies at the worst
possible moment in front of the people it was built for. Two things in this
module exist for that reason alone.

**Swagger UI is turned off.** FastAPI's ``/docs`` and ``/redoc`` are not local
pages: they are three-line HTML shells that pull ``swagger-ui-bundle.js`` and
its stylesheet from ``cdn.jsdelivr.net`` at render time. On a laptop with no
route out they render a blank white page. ``docs_url`` and ``redoc_url`` are
therefore ``None``. ``/openapi.json`` stays -- it is generated in-process and
fetches nothing -- so the schema is still readable, just not through a page that
phones out to draw it.

**The frontend is served from disk.** Everything under
:data:`STATIC_DIR` is mounted and served locally. Whether the *assets in it*
are themselves free of remote ``@import`` rules or webfont URLs is the other
half's responsibility and its own verification; what this module guarantees is
that the server never reaches out, and :func:`create_app` is the only place a
route could have been added that did.

.. _bounded-by-construction:

Bounded by construction
-----------------------
Every field is range-checked before the protocol sees it
(:mod:`sih141.web.limits`), unknown fields are **refused** rather than ignored
-- a body carrying ``keyLength`` would otherwise run silently at the default
``L`` while the screen labelled the result with the number the operator typed,
which is the exact "quietly cap the parameter" failure this dashboard is
forbidden -- and concurrency is capped by a non-blocking semaphore, so the
``MAX_CONCURRENT_RUNS + 1``-th simultaneous run is refused at once with a
``Retry-After`` instead of queueing behind two seconds of quantum simulation.

The bound that has to come **first**, though, is the body's own size, and it is
enforced by :class:`_BodyLimit` before any route is reached. The concurrency
gate protects the CPU and protects nothing else: it is taken *after* validation,
so a request refused by a cap never reaches it. A 256 MB ``attack`` field was
therefore parsed, refused correctly, echoed back twice inside its own refusal --
measured at 2x on the wire and about 9x in resident memory, which was never
released -- and none of that ever met the gate. A body over
:data:`~sih141.web.limits.MAX_REQUEST_BYTES` is now answered ``413`` having been
read only up to that bound, so nothing downstream sees it at all.

What is NOT offered, and why it is published anyway
---------------------------------------------------
:data:`~sih141.protocol.params.DEFAULT_PARAMS` (``L = 115200``) is about four
minutes of session generation and roughly 37 MB of transcript per run. It
cannot come from a button, and a 37 MB pre-generated transcript is not a thing
to commit to a repository that is itself the artefact. So the headline
parameters are published as what they actually are -- **closed forms**: the two
floors, the enforced repudiation bound, and the family-wise budget split, all
computed by the same functions a run would use, none of them requiring a run.
``/api/defaults`` says so in its own words, so no reader can mistake a derived
bound for a measured one.

Examples
--------
>>> from fastapi.testclient import TestClient
>>> from sih141.web.api import create_app
>>> client = TestClient(create_app())
>>> client.get("/api/health").json()["ok"]
True
>>> defaults = client.get("/api/defaults").json()
>>> defaults["live_key_length_max"]
1024
>>> f'{defaults["bounds"]["headline"]["enforced_repudiation_bound"]:.4e}'
'1.4139e-09'

A run above the ceiling is refused, and the refusal names the ceiling:

>>> refused = client.post("/api/run", json={"key_length": 100000})
>>> refused.status_code, refused.json()["cap"]
(400, 1024)

A run that reached verdicts leaves one event per verifier behind. The refusal
above left none, because nothing verified
(:ref:`the-server-now-keeps-something`):

>>> client.post("/api/run", json={"key_length": 96, "seed": 4}).status_code
200
>>> events = client.get("/api/events").json()
>>> [(event["party"], event["verdict"]) for event in events["events"]]
[('Bob', 'accepted'), ('Charlie', 'accepted')]
>>> events["dropped"], events["persisted"]
(0, False)
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from sih141 import __version__
from sih141.audit import AuditLog
from sih141.detect import family_budget
from sih141.eval.security import FLOOR_CROSSOVER, security_claim_at
from sih141.protocol.params import (
    DEFAULT_PARAMS,
    DEMO_PARAMS,
    ProtocolParams,
)
from sih141.protocol.verify import (
    enforced_repudiation_bound,
    minimum_matched_count,
    minimum_pooled_matched_count,
)
from sih141.web.catalogue import roster_payload
from sih141.web.driver import MESSAGE_BIT, RunRequest, run_once
from sih141.web.limits import (
    CHANNEL_ERROR_RATE_MAX,
    CHECK_FRACTION_MAX,
    COST_TABLE,
    COST_TABLE_NOTE,
    COUNT_EXCHANGE_TIMINGS,
    EPS_DEFAULT,
    EPS_MAX,
    EPS_MIN,
    KEY_LENGTH_MIN,
    LIVE_KEY_LENGTH_MAX,
    MAX_CONCURRENT_RUNS,
    MAX_REQUEST_BYTES,
    NOISE_MAX,
    RequestRefused,
    json_safe,
    limits_payload,
)

DEGENERATE_BELOW_KEY_LENGTH: Final[int] = FLOOR_CROSSOVER
"""int: The sifted length below which a run carries no security claim.

The dashboard's name for :data:`sih141.eval.security.FLOOR_CROSSOVER`, aliased
rather than restated: a second literal in a second package is what let this
screen publish ``140`` while every other phase said ``137``.

``137`` is where :func:`~sih141.protocol.verify.minimum_pooled_matched_count`
first exceeds ``1`` and
:attr:`~sih141.detect.statistics.TranscriptStatistics.security_claim` turns on.
It is NOT where *both* floors bite -- the per-verifier floor stays at ``1``
until ``273``
(:data:`~sih141.eval.security.PER_VERIFIER_CROSSOVER`) -- and it is not the
``2 -> 3`` step in the pooled floor at ``140`` either, which is one transition
past the one an operator cares about.

>>> from sih141.web.api import DEGENERATE_BELOW_KEY_LENGTH as boundary
>>> from sih141.eval.security import security_claim_at
>>> boundary
137
>>> security_claim_at(boundary - 1), security_claim_at(boundary)
(False, True)
"""


__all__ = ["STATIC_DIR", "RunBody", "create_app", "defaults_payload"]

#: Notes: :class:`_BodyLimit` and :func:`_refuse_oversized` are private and are
#: exercised through :func:`create_app`, which installs the first as the
#: outermost middleware. :func:`_run_digest` and :func:`_record_verdicts` are
#: private for the same reason and are exercised through ``POST /api/run``,
#: which is the only thing in the repository that writes to a log.


#: Where the frontend lives. Served from disk; nothing is fetched
#: (:ref:`nothing-is-fetched`).
STATIC_DIR: Final[Path] = Path(__file__).resolve().parent / "static"

_NO_FRONTEND: Final[str] = """<!doctype html>
<title>SIH26141 &mdash; API is up, frontend is not installed</title>
<style>
 body{font:15px/1.6 system-ui,sans-serif;margin:3rem auto;max-width:44rem;
      padding:0 1.5rem;color:#1a1a1a;background:#fafaf8}
 code{background:#eeeeea;padding:.1em .35em;border-radius:3px}
 li{margin:.35em 0}
</style>
<h1>SIH26141 detection API</h1>
<p>The server is running and every endpoint below answers. What is missing is
the dashboard itself: no <code>index.html</code> was found in
<code>sih141/web/static/</code>.</p>
<ul>
 <li><code>GET /api/health</code></li>
 <li><code>GET /api/attacks</code></li>
 <li><code>GET /api/defaults</code></li>
 <li><code>POST /api/run</code></li>
 <li><code>GET /api/events</code></li>
 <li><code>GET /openapi.json</code> &mdash; generated in-process, fetches nothing</li>
</ul>
<p>This page is served from memory and loads no scripts, fonts or stylesheets
from anywhere. Neither does anything else here.</p>
"""


def _refuse_oversized(declared: int | None) -> JSONResponse:
    """Return the ``413`` body for a request too large to read.

    Parameters
    ----------
    declared : int or None
        The ``Content-Length`` the client declared, where it declared one.

    Returns
    -------
    fastapi.responses.JSONResponse

    Examples
    --------
    >>> from sih141.web.api import _refuse_oversized
    >>> _refuse_oversized(70000).status_code
    413
    """
    return JSONResponse(
        status_code=413,
        content={
            "field": "body",
            "message": (
                f"The request body is larger than the {MAX_REQUEST_BYTES}-byte "
                f"ceiling and was refused without being read. The largest "
                f"legitimate body here is nine scalars and about 300 bytes. "
                f"Nothing parsed it, nothing echoed it, and no run was "
                f"started."
            ),
            "value": (
                f"{declared} bytes declared"
                if declared is not None
                else "more than the ceiling, sent without a Content-Length"
            ),
            "cap": MAX_REQUEST_BYTES,
        },
    )


class _BodyLimit:
    """Refuse an oversized request body **before the application sees it**.

    Pure ASGI rather than a :class:`starlette.middleware.base.BaseHTTPMiddleware`
    subclass, because this has to act on the raw receive channel: the point is
    that the bytes are never accumulated, and a middleware that is handed a
    ``Request`` has already lost that argument.

    Two paths, because a client picks which one it is on. A declared
    ``Content-Length`` over the ceiling is refused with nothing read at all. A
    body sent without one -- chunked, or simply lying -- is read in the chunks
    the server delivers and abandoned the moment the total passes the ceiling,
    so at most ``limit`` bytes plus one chunk is ever held.

    Everything under the ceiling is replayed to the application unchanged, so
    this is a bound and never a transformation.

    Parameters
    ----------
    app : callable
        The ASGI application to wrap.
    limit : int, optional
        Ceiling in bytes, :data:`~sih141.web.limits.MAX_REQUEST_BYTES` by
        default.

    Examples
    --------
    >>> from fastapi.testclient import TestClient
    >>> from sih141.web.api import create_app
    >>> client = TestClient(create_app())

    A normal run is untouched:

    >>> client.post("/api/run", json={"key_length": 96, "seed": 4}).status_code
    200

    An oversized body is refused, and the refusal is smaller than the request
    that caused it -- which is the whole point, since the previous behaviour
    echoed the offending field back twice:

    >>> huge = client.post(
    ...     "/api/run",
    ...     content=b'{"attack": "' + b"x" * 200000 + b'"}',
    ...     headers={"Content-Type": "application/json"},
    ... )
    >>> huge.status_code, huge.json()["cap"]
    (413, 65536)
    >>> len(huge.content) < 600
    True
    """

    def __init__(self, app: Any, limit: int = MAX_REQUEST_BYTES) -> None:
        self.app = app
        self.limit = int(limit)

    @staticmethod
    def _declared(scope: dict[str, Any]) -> int | None:
        """Return the request's ``Content-Length``, or ``None``."""
        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """Read at most ``limit`` bytes, then hand the request on or refuse it."""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        declared = self._declared(scope)
        if declared is not None and declared > self.limit:
            await _refuse_oversized(declared)(scope, receive, send)
            return

        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                # A disconnect mid-body. Nothing to answer and nothing to run.
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                await _refuse_oversized(declared)(scope, receive, send)
                return
            more = bool(message.get("more_body", False))

        replayed = [bytes(body)]

        async def replay() -> dict[str, Any]:
            """Hand the buffered body to the application, once."""
            if replayed:
                return {
                    "type": "http.request",
                    "body": replayed.pop(),
                    "more_body": False,
                }
            return await receive()

        await self.app(scope, replay, send)


class _NoStaleStatic(StaticFiles):
    """Serve the frontend with ``Cache-Control: no-cache``.

    ``no-cache`` does not mean "do not store". It means **revalidate before
    reuse**, so the browser keeps the bytes and asks with an ``If-None-Match``;
    on a live server that is a ``304`` in under a millisecond over loopback, and
    on a dead one it is a failure the page cannot paper over.

    That second half is the point, and it comes out of a measurement. Without a
    ``Cache-Control`` header at all, whether an asset survives the process dying
    is decided by Chrome's *heuristic* freshness -- roughly a tenth of the
    file's age -- so a cold load against a dead service had no single behaviour.
    Three were observed on this tree: the whole page rendered from cache with a
    masthead reading ``RECORDED ONLY -- API NOT REACHABLE`` above a rail holding
    ZERO recorded runs; the page rendered with some scripts missing; and, on a
    tree whose files had just been edited, nothing rendered at all. A demo whose
    failure mode is a coin flip cannot be documented, and the first of those
    three is a masthead making a promise it cannot keep.

    With this header there is one behaviour: a cold load against a dead service
    does not load, and the browser says so in its own words. The mode that IS
    supported -- the page already open when the service dies -- is unaffected,
    because everything it needs is already in memory by then.

    Examples
    --------
    >>> from fastapi.testclient import TestClient
    >>> from sih141.web.api import create_app
    >>> client = TestClient(create_app())
    >>> client.get("/static/js/app.js").headers["cache-control"]
    'no-cache'
    >>> client.get("/").headers["cache-control"]
    'no-cache'
    """

    def file_response(self, *args: Any, **kwargs: Any) -> Response:
        """Return the file with revalidation forced.

        Returns
        -------
        starlette.responses.Response
        """
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


class RunBody(BaseModel):
    """The ``POST /api/run`` body.

    Types only. Every *range* is checked by
    :meth:`~sih141.web.driver.RunRequest.from_mapping`, in one place, so that a
    refusal names the cap it hit rather than emitting a schema error.

    Unknown fields are forbidden. That is deliberate and it is a safety
    property, not pedantry: a body carrying ``keyLength`` instead of
    ``key_length`` would otherwise be *accepted*, run at the default ``L``, and
    come back labelled with a length nobody ran
    (:ref:`bounded-by-construction`).

    Attributes
    ----------
    attack : str
    key_length : int
    check_fraction : float
    noise : float
    eps : float
    channel_error_rate : float
    tolerated_depolarising : float
        The ninth, optional field. See
        :ref:`sih141.web.driver <the-second-null>`.
    count_exchange_timing : str
    seed : int
    """

    model_config = ConfigDict(extra="forbid")

    attack: str = "honest"
    key_length: int = DEMO_PARAMS.key_length
    check_fraction: float = 0.25
    noise: float = 0.0
    eps: float = EPS_DEFAULT
    channel_error_rate: float = 0.0
    tolerated_depolarising: float = 0.0
    count_exchange_timing: str = "before-forwarding"
    seed: int = 20260141


def _parameter_set(params: ProtocolParams, note: str) -> dict[str, Any]:
    """Return the derived quantities for one parameter set.

    Every number is a closed form evaluated at ``params``: derived, computed
    without running anything, and not a measurement.

    Parameters
    ----------
    params : ProtocolParams
    note : str
        What the set is for, and -- where it applies -- what it does **not**
        establish.

    Returns
    -------
    dict

    Examples
    --------
    >>> from sih141.protocol.params import DEMO_PARAMS
    >>> from sih141.web.api import _parameter_set
    >>> demo = _parameter_set(DEMO_PARAMS, "the interactive set")
    >>> demo["minimum_matched"], demo["minimum_pooled"]
    (1, 22)
    >>> demo["floors_are_live"]
    True

    ``floors_are_live`` is
    :attr:`~sih141.detect.statistics.TranscriptStatistics.security_claim`
    evaluated on the length alone, so it agrees with what ``/api/run`` reports
    for a run of that length rather than contradicting it:

    >>> from sih141.eval.security import security_claim_at
    >>> demo["floors_are_live"] == security_claim_at(192)
    True
    """
    floor = minimum_matched_count(params)
    pooled = minimum_pooled_matched_count(params)
    return {
        "key_length": int(params.key_length),
        "signing_length": int(params.signing_length),
        "expected_matched": float(params.expected_matched),
        "minimum_matched": int(floor),
        "minimum_pooled": int(pooled),
        # The same two numbers under the names the frontend's read-side
        # contract uses. Aliased rather than renamed: both spellings are in
        # circulation between the halves, and a missing field blanks a panel
        # while a duplicated one costs nothing.
        "matched_minimum": int(floor),
        "pooled_minimum": int(pooled),
        "enforced_repudiation_bound": float(
            enforced_repudiation_bound(params)
        ),
        # THE SAME PREDICATE a transcript is scored by, from the same
        # function, and not a second spelling of it: this said
        # `floor > 1 and pooled > 2` while Phase 4 froze
        # `security_claim = floor > 1 or pooled > 1`, so every sifted length
        # in [137, 272] -- the demo set at 192 included -- was published INERT
        # here and LIVE by /api/run on the same screen.
        "floors_are_live": security_claim_at(params.signing_length),
        "family_budget": family_budget(params, eps=EPS_DEFAULT).to_dict(),
        "note": note,
    }


def defaults_payload() -> dict[str, Any]:
    """Return the body ``GET /api/defaults`` serves.

    Returns
    -------
    dict
        ``params`` (the form's starting point), ``bounds`` (what is proven, at
        both the headline set and the demo one), ``eps_default``,
        ``live_key_length_max``, ``limits`` (every published cap and the
        measured cost table) and ``attacks``.

    Notes
    -----
    Everything under ``bounds`` is a **closed form**: derived, computed without
    running anything, and labelled ``"kind": "proven"`` for exactly that
    reason -- proven and measured are different kinds of number and the screen
    has to be able to tell them apart. ``limits["cost_table"]`` and
    ``noise_null_calibration`` are the measured ones and say so, with their
    sample sizes. **There is no false-negative bound here and there cannot be
    one from a transcript**, so nothing in this payload implies one.

    The headline set is published and never run. One session at ``L = 115200``
    is about four minutes and roughly 37 MB of transcript; a pre-generated
    transcript that size is not a thing to commit to a repository that is
    itself the artefact. So it is served as the parameters and closed forms it
    is, with ``"runnable": false`` saying so in the payload rather than in a
    comment.

    Examples
    --------
    >>> from sih141.web.api import defaults_payload
    >>> payload = defaults_payload()
    >>> payload["params"]["key_length"], payload["eps_default"]
    (192, 1e-09)
    >>> payload["live_key_length_max"], payload["live_key_length_min"]
    (1024, 24)
    >>> headline = payload["bounds"]["headline"]
    >>> headline["key_length"], headline["minimum_matched"], headline["minimum_pooled"]
    (115200, 36555, 74190)
    >>> bounds = payload["bounds"]
    >>> bounds["matched_minimum"], bounds["pooled_minimum"]
    (36555, 74190)
    >>> f'{headline["enforced_repudiation_bound"]:.4e}', headline["runnable"]
    ('1.4139e-09', False)

    The demo set is published beside it, with the fact that makes it unquotable
    as a security result attached to the same object:

    >>> demo = payload["bounds"]["demo"]
    >>> demo["key_length"], demo["floors_are_live"]
    (192, True)
    >>> f'{demo["enforced_repudiation_bound"]:.4f}'
    '0.9940'
    >>> "cannot demonstrate non-repudiation" in demo["note"]
    True
    """
    headline = DEFAULT_PARAMS
    demo = DEMO_PARAMS
    headline_set = _parameter_set(
        headline,
        "The documented security-grade set. NOT RUNNABLE HERE: one session is "
        "about four minutes and roughly 37 MB of transcript, so it is "
        "published as the closed forms it is and never as a run. Anything on "
        "the screen labelled with this set is DERIVED; nothing on the screen "
        "was measured at this length.",
    )
    headline_set["runnable"] = False
    demo_set = _parameter_set(
        demo,
        "The dashboard's starting length. Identical thresholds to the "
        "security-grade set -- the decision rule being demonstrated is THE "
        "SAME decision rule -- with only L cut, so a run answers a click. "
        "Watch the repudiation bound: at this length it is order one, which is "
        "no bound worth the name. A demo-scale run demonstrates the MECHANISM "
        "and cannot demonstrate non-repudiation; a green transferability tick "
        "here would be saying otherwise.",
    )
    demo_set["runnable"] = True
    return {
        # -- the form's starting point ---------------------------------------- #
        "params": {
            "key_length": int(demo.key_length),
            "s_a": float(demo.s_a),
            "s_v": float(demo.s_v),
            "bases": [str(basis) for basis in demo.bases],
            "check_fraction": 0.25,
            "signing_length": int(demo.signing_length),
            "match_probability": float(demo.match_probability),
            "message_bit": MESSAGE_BIT,
            "count_exchange_timing": COUNT_EXCHANGE_TIMINGS[0],
            "attack": "honest",
            "noise": 0.0,
            "eps": EPS_DEFAULT,
            "channel_error_rate": 0.0,
            "tolerated_depolarising": 0.0,
            "seed": 20260141,
            "note": (
                "Where the controls start. Identical thresholds to the "
                "security-grade set; only L is cut, so a run answers a click."
            ),
        },
        "eps_default": EPS_DEFAULT,
        "live_key_length_max": LIVE_KEY_LENGTH_MAX,
        "live_key_length_min": KEY_LENGTH_MIN,
        # -- what is PROVEN, at both sets -------------------------------------- #
        "bounds": {
            "kind": "proven",
            # The headline set's own numbers, at the top level, because
            # "the bounds" without qualification has always meant the
            # security-grade set's -- and again inside `headline`, beside the
            # demo set's, because a screen that shows both has to be able to
            # say which is which.
            "enforced_repudiation_bound": headline_set[
                "enforced_repudiation_bound"
            ],
            "matched_minimum": headline_set["matched_minimum"],
            "pooled_minimum": headline_set["pooled_minimum"],
            "family_budget": headline_set["family_budget"],
            "headline": headline_set,
            "demo": demo_set,
            "chsh_classical_bound": 2.0,
            "chsh_tsirelson_bound": 2.0 * math.sqrt(2.0),
            "degenerate_below_key_length": DEGENERATE_BELOW_KEY_LENGTH,
            "note": (
                "Closed forms evaluated at a parameter set: derived, not "
                "measured, and computed without running anything. Nothing here "
                "is a detection rate, and none of it is a false-negative bound "
                "-- there is no such bound in this project and none can be had "
                "from a transcript. What a run publishes afterwards is "
                "Detection.false_positive_bound. It is NOT eps: at L = 384, "
                "eps = 1e-9, false_positive_bound is 3.3964e-10 and the budget "
                "is 2.944 times larger, so quoting the budget overstates the "
                "error rate by that factor. It is also NOT evidence_bound, "
                "which is a post hoc statement about the signals that actually "
                "fired -- a different claim on a different scale entirely, "
                "smaller than false_positive_bound by about 7e9 on a run where "
                "anything fires, and null on a run where nothing does."
            ),
        },
        # -- every cap the request surface enforces ---------------------------- #
        "limits": limits_payload(),
        "check_fraction_max": CHECK_FRACTION_MAX,
        "noise_max": NOISE_MAX,
        "channel_error_rate_max": CHANNEL_ERROR_RATE_MAX,
        "tolerated_depolarising_max": NOISE_MAX,
        "eps_min": EPS_MIN,
        "eps_max": EPS_MAX,
        "count_exchange_timings": list(COUNT_EXCHANGE_TIMINGS),
        "max_concurrent_runs": MAX_CONCURRENT_RUNS,
        # -- MEASURED, and labelled as such ------------------------------------ #
        "noise_null_calibration": {
            "kind": "measured",
            "what": (
                "honest runs over a depolarising wire, scored against the "
                "default noiseless null (channel_error_rate = 0.0). The "
                "denominator is EVERY run at that level, not only the runs "
                "both verifiers accepted: an honest run over a noisy link "
                "can still be rejected on its rate, and at the design "
                "level 16 of the 60 verifier verdicts are rejections. "
                "Filtering to accepting runs would change what the rate "
                "means without changing the number printed beside it."
            ),
            "runs_per_level": 30,
            "key_length": 384,
            "check_fraction": 0.25,
            "source": (
                "Phase 5 experiment 'noise', 6 cells x 30 trials at "
                "L = 384, check_fraction 0.25. Every trial's seed is a "
                "pure function of (experiment, cell, index); see "
                "docs/tables/noise.md for the provenance commit."
            ),
            "regenerate": (
                "python tools/sweep.py run noise && "
                "python tools/sweep.py reduce noise"
            ),
            "levels": [
                {"noise": 0.0, "detected": 0},
                {"noise": 0.0025, "detected": 14},
                {"noise": 0.005, "detected": 23},
                {"noise": 0.01, "detected": 28},
                {"noise": 0.015, "detected": 30},
                {"noise": 0.03125, "detected": 30},
            ],
            # This sentence has to be true READ ALONE, because it is the one
            # line of the calibration a reader takes away and it sits under a
            # table of runs that fired. Saying "the link's true rate", singular,
            # described an instruction that does not work: detect() has TWO
            # nulls, and correcting only this family's leaves an honest noisy
            # run detected with an adversary named. See `second_null_note`.
            "with_true_rate_passed": (
                "0/30 at every level when BOTH of detect()'s nulls are stated: "
                "the link's true matched-position error rate as "
                "channel_error_rate, AND the link's Werner strength as "
                "tolerated_depolarising. This table is the RATE family's. "
                "Correcting this null alone does not clear an honest noisy run."
            ),
            "second_null_note": (
                "That calibration is the RATE family. The CHANNEL family has "
                "its own null, tolerated_depolarising, also defaulting to a "
                "perfect resource, and stating only the first leaves an honest "
                "noisy run firing: measured over twelve seeds at L = 192, "
                "check_fraction = 0.25, link strength 0.03125 -- 12/12 "
                "detected with both nulls at zero, 12/12 with only "
                "channel_error_rate corrected, 0/12 with both stated. THE "
                "VERIFIERS DO NOT MOVE WITH THE NULLS AT ALL: their outcomes "
                "are the protocol's and the nulls are the detector's, and over "
                "those twelve seeds the pair of outcomes is identical under "
                "all three settings -- both accept on 7 seeds and Bob rejects "
                "the honest signature on 5, which is what a link at the design "
                "noise level does to a signature and is a separate fact from "
                "anything the detector said."
            ),
        },
        "attacks": roster_payload(),
    }


def _run_digest(request: dict[str, Any]) -> str:
    """Return the identifier the log groups one run's events under.

    A digest of the **resolved request** and of nothing else. It is not a
    protocol session identifier: the dashboard keeps no ledger and sets no
    ``run_id`` on its sessions, so there is no round name to carry, and this is
    the only sense in which two of its events belong together. It identifies
    the run, never the requester -- no address, no header and no cookie reaches
    it, and of the request it digests only the check fraction is written to the
    log beside it, so an event cannot be replayed from one.

    Parameters
    ----------
    request : dict
        :meth:`~sih141.web.driver.RunRequest.to_dict`.

    Returns
    -------
    str
        Sixteen hexadecimal characters.

    Examples
    --------
    >>> from sih141.web.api import _run_digest
    >>> first = _run_digest({"attack": "honest", "seed": 1})
    >>> len(first), first == _run_digest({"seed": 1, "attack": "honest"})
    (16, True)

    A different run is a different identifier, which is what makes it a
    grouping key rather than a label:

    >>> first == _run_digest({"attack": "honest", "seed": 2})
    False
    """
    canonical = json.dumps(request, sort_keys=True, default=str)
    return hashlib.blake2s(
        canonical.encode("utf-8"), digest_size=8
    ).hexdigest()


def _record_verdicts(log: AuditLog, payload: dict[str, Any]) -> None:
    """Append one security event per verification outcome.

    Called on the way out of ``POST /api/run`` and nowhere else. A run that
    reached no verdict at all -- a refused request, an adversary that raised --
    writes nothing, so a count taken from the log is a count of verdicts
    (:ref:`the-server-now-keeps-something`).

    Parameters
    ----------
    log : sih141.audit.AuditLog
    payload : dict
        The response body, already built. Read only for the fields the event
        names; the payload is not modified and the response does not change
        shape because a log is present.

    Notes
    -----
    ``key_length`` on the event is
    :attr:`~sih141.detect.detector.Detection.key_length`, the **sifted** length
    every null and every floor was stated over, and not the length the caller
    asked for. A verdict read against the requested length would be read
    against a threshold that was never applied to it.
    """
    detection = payload.get("detection")
    if detection is None:
        return
    request = payload["request"]
    by_party = (payload.get("run") or {}).get("aborts", {}).get("by_party", {})
    session_id = _run_digest(request)
    named = tuple(detection.get("named", ()))
    for party, outcome in sorted(detection.get("outcomes", {}).items()):
        log.record(
            party=party,
            verdict=outcome,
            session_id=session_id,
            # The SIFTED length, off the detection, beside the check fraction
            # the caller asked for. Neither is defaulted: a wrong number in an
            # audit record is worse than a missing one, and both of these
            # fields are present on every response that carries a detection.
            key_length=detection["key_length"],
            check_fraction=request["check_fraction"],
            abort_reason=by_party.get(party),
            hypotheses=named,
        )


def create_app(
    static_dir: Path | None = None, audit_log: AuditLog | None = None
) -> FastAPI:
    """Build the application: the JSON API plus the static frontend.

    Parameters
    ----------
    static_dir : pathlib.Path or None, optional
        Where the frontend lives. Defaults to :data:`STATIC_DIR`.
    audit_log : sih141.audit.AuditLog or None, optional
        Where verification outcomes are recorded. ``None`` -- the default --
        gives this application its own log, in memory, at
        :data:`~sih141.audit.DEFAULT_CAPACITY` events. Pass one built with a
        ``path`` to have the events appended to a file as well; that is the
        only way anything here writes to a disk
        (:ref:`the-server-now-keeps-something`).

        The default is a log rather than no log because an endpoint that serves
        one has to have one to serve. This function is the only place that
        builds one unasked: no module under :mod:`sih141.protocol`,
        :mod:`sih141.detect`, :mod:`sih141.eval` or :mod:`sih141.attacks`
        imports :mod:`sih141.audit` at all.

    Returns
    -------
    fastapi.FastAPI

    Notes
    -----
    ``docs_url`` and ``redoc_url`` are ``None`` on purpose
    (:ref:`nothing-is-fetched`): FastAPI's documentation pages load Swagger UI
    from a CDN and render blank without a route to the internet.

    Examples
    --------
    >>> from fastapi.testclient import TestClient
    >>> from sih141.web.api import create_app
    >>> app = create_app()
    >>> app.docs_url is None and app.redoc_url is None
    True
    >>> client = TestClient(app)
    >>> [entry["key"] for entry in client.get("/api/attacks").json()][:2]
    ['honest', 'outside-forgery']

    A run comes back with the contract's keys, and ground truth is not one of
    the detection's:

    >>> body = client.post(
    ...     "/api/run", json={"attack": "honest", "key_length": 96, "seed": 2}
    ... ).json()
    >>> sorted(body)
    ['detection', 'error', 'ground_truth', 'request', 'run', 'timings']
    >>> "ground_truth" in body["detection"], body["error"] is None
    (False, True)
    """
    root = STATIC_DIR if static_dir is None else Path(static_dir)
    app = FastAPI(
        title="SIH26141 - quantum-inspired detection for QDS",
        version=__version__,
        docs_url=None,
        redoc_url=None,
    )
    # Outermost, so that an oversized body is refused before a route, a
    # validator or an error handler can be handed it.
    app.add_middleware(_BodyLimit)
    # Non-blocking, so an over-capacity request is refused immediately rather
    # than parked behind seconds of simulation with nothing on the screen.
    gate = threading.BoundedSemaphore(MAX_CONCURRENT_RUNS)
    # Per application, so two `create_app()` calls are two logs and a test
    # cannot read events another test wrote.
    log = AuditLog() if audit_log is None else audit_log

    @app.exception_handler(RequestRefused)
    async def _refused(
        request: Request, refusal: RequestRefused
    ) -> JSONResponse:
        """Render a bounds refusal as a body that names the cap."""
        del request
        return JSONResponse(status_code=400, content=refusal.to_dict())

    @app.exception_handler(RequestValidationError)
    async def _invalid(
        request: Request, invalid: RequestValidationError
    ) -> JSONResponse:
        """Render a schema error, including one JSON itself cannot quote.

        FastAPI's own handler echoes the offending ``input`` back inside the
        ``422`` body and then encodes that body with ``allow_nan=False``. A
        request carrying the bare token ``NaN`` -- valid Python, not JSON, and
        what every Python client emits for a float NaN by default -- therefore
        turned a correct schema rejection into ``500 Internal Server Error``.
        Every leaf goes through :func:`~sih141.web.limits.json_safe`, so the
        value is named as text and the refusal survives being serialised.

        ``json_safe`` runs FIRST and ``jsonable_encoder`` second, which is the
        whole of the fix for the second version of this bug. A body of ``[``
        two thousand times is refused correctly by pydantic and echoed back
        inside ``input``; ``jsonable_encoder`` then walks it one stack frame
        per level and raised :exc:`RecursionError` from inside this handler,
        so a properly refused request came back as ``500``. ``json_safe``
        bounds the depth before anything else walks the value, so the encoder
        only ever sees a structure it can survive.
        """
        del request
        return JSONResponse(
            status_code=422,
            content={"detail": jsonable_encoder(json_safe(invalid.errors()))},
        )

    @app.get("/api/health")
    def health(response: Response) -> dict[str, Any]:
        """Report that the process is up, and which build it is.

        Parameters
        ----------
        response : fastapi.Response
            Used to forbid caching. This endpoint is the frontend's liveness
            check -- it is polled so the masthead's ``LIVE API`` claim is
            *verified* rather than inferred from something failing -- and a
            cached ``{"ok": true}`` would be a masthead asserting a live API
            over a dead process, which is the defect the poll exists to close.

        Returns
        -------
        dict
            ``ok`` and ``version``.
        """
        response.headers["Cache-Control"] = "no-store"
        return {"ok": True, "version": __version__}

    @app.get("/api/attacks")
    def attacks(response: Response) -> list[dict[str, Any]]:
        """List every arm, with its detectability stated rather than implied.

        Parameters
        ----------
        response : fastapi.Response
            Used to forbid caching, like every other API answer here: these
            are live facts about the running build, and a cached one is a
            screen labelled with a process that is not there.

        Returns
        -------
        list of dict
            One entry per adversary plus the honest control. ``detectable``
            carries the (AUTH) case as its own value, never as a ``false``
            beside eight ``true``\\ s -- see
            :ref:`sih141.web.catalogue <auth-is-not-a-blank>`.
        """
        response.headers["Cache-Control"] = "no-store"
        return roster_payload()

    @app.get("/api/defaults")
    def defaults(response: Response) -> dict[str, Any]:
        """Serve the form's starting point, the published caps and the bounds.

        Parameters
        ----------
        response : fastapi.Response
            Used to forbid caching.

        Returns
        -------
        dict
        """
        response.headers["Cache-Control"] = "no-store"
        return defaults_payload()

    @app.post("/api/run")
    def run(body: RunBody, response: Response) -> dict[str, Any]:
        """Run one arm and score it.

        Parameters
        ----------
        body : RunBody
            The request. Ranges are checked by
            :meth:`~sih141.web.driver.RunRequest.from_mapping` and a violation
            comes back as ``400`` with the cap named.
        response : fastapi.Response
            Used to set ``Retry-After`` when the server is at capacity.

        Returns
        -------
        dict
            ``request``, ``detection``, ``run``, ``ground_truth``, ``timings``
            and ``error``. On a run-level failure the status stays ``200``, all
            the keys are still present, ``detection`` and ``run`` are ``null``
            and ``error`` says what happened -- so the screen renders a failure
            rather than a 500 page, and can never mistake one for a clean run.

        Raises
        ------
        RequestRefused
            Handled above into a ``400`` naming the cap.
        """
        response.headers["Cache-Control"] = "no-store"
        request = RunRequest.from_mapping(body.model_dump())
        if not gate.acquire(blocking=False):
            response.status_code = 503
            response.headers["Retry-After"] = "3"
            return {
                "request": request.to_dict(),
                "detection": None,
                "run": None,
                "ground_truth": {},
                "timings": {"session_ms": 0.0, "detect_ms": 0.0},
                "error": {
                    "kind": "at-capacity",
                    "message": (
                        f"{MAX_CONCURRENT_RUNS} runs are already generating "
                        f"sessions and this one is refused rather than queued. "
                        f"Session generation is CPU-bound; queueing would "
                        f"leave the screen waiting with nothing to show. Try "
                        f"again in a moment."
                    ),
                    "cap": MAX_CONCURRENT_RUNS,
                },
            }
        try:
            payload = run_once(request).to_dict()
        finally:
            gate.release()
        _record_verdicts(log, payload)
        return payload

    @app.get("/api/events")
    def events(response: Response) -> dict[str, Any]:
        """Serve the security event log, oldest event first.

        Read-only. There is no endpoint that clears it and none that writes to
        it: ``POST /api/run`` is the only producer.

        Parameters
        ----------
        response : fastapi.Response
            Used to forbid caching, like every other API answer here.

        Returns
        -------
        dict
            ``events`` (one object per verification outcome), ``count``
            (retained), ``recorded`` (over the process's whole life),
            ``dropped``, ``capacity``, ``persisted`` and ``note``.

            ``events``, ``count``, ``recorded`` and ``dropped`` come from one
            call to :meth:`~sih141.audit.AuditLog.snapshot`, so a run landing
            mid-request cannot produce a document whose list and counters
            disagree.

            ``dropped`` is published rather than inferred. Past ``capacity``
            the oldest event goes, and a reader who cannot tell a truncated log
            from a whole one has a log that lies by omission.

            ``persisted`` is a boolean and never the path. Whether the
            operator configured a file is a fact about the deployment; where
            that file is on their disk is not one this endpoint hands out.
        """
        response.headers["Cache-Control"] = "no-store"
        retained, recorded, dropped = log.snapshot()
        return {
            "events": [event.to_dict() for event in retained],
            "count": len(retained),
            "recorded": recorded,
            "dropped": dropped,
            "capacity": log.capacity,
            "persisted": log.path is not None,
            "note": (
                "One event per verification outcome. A request refused for "
                "its size or its range, and a run that failed before a "
                "verdict, appear nowhere here, so a count of these events is "
                "a count of verdicts. The party is SELF-DECLARED: a verifier "
                "using a recipient record obtained outside the protocol "
                "produces an event no field of which differs from the one its "
                "owner would have produced, and nothing in this log detects "
                "that."
            ),
        }

    if root.is_dir():
        app.mount(
            "/static", _NoStaleStatic(directory=str(root)), name="static"
        )

    @app.get("/", response_class=HTMLResponse)
    def index() -> Response:
        """Serve the frontend, or say plainly that it is not installed.

        Returns
        -------
        fastapi.Response
            ``static/index.html`` when it exists. Otherwise a page served from
            memory that names the endpoints -- never a blank, and never
            something that could be mistaken for the dashboard.
        """
        page = root / "index.html"
        if page.is_file():
            return FileResponse(
                page, headers={"Cache-Control": "no-cache"}
            )
        return HTMLResponse(
            content=_NO_FRONTEND,
            status_code=200,
            headers={"Cache-Control": "no-cache"},
        )

    return app
