"""Every bound the dashboard's request surface enforces, in one place.

A demo server is a program a stranger can send arbitrary numbers to, and this
one turns numbers into *quantum simulation*: ``key_length`` is a linear
multiplier on wall-clock time and on the transcript's size in memory. A request
carrying ``key_length=10**9`` is not a large run, it is an outage, and one
carrying ``check_fraction=0.999`` is a run with nothing left to sign. So the
caps live here rather than being scattered across the endpoints, they are
**published** through :func:`limits_payload` so the screen can show them, and
every refusal names the cap it hit -- a message reading "invalid request" would
leave an operator on a stage guessing.

.. _no-silent-capping:

The rule that matters more than the caps
----------------------------------------
**A parameter is never silently clamped.** ``key_length=5000`` is refused with
:data:`LIVE_KEY_LENGTH_MAX` in the message; it is not quietly run at 1024 and
reported as though 1024 were what was asked for. A dashboard that clamps has
produced a screen whose numbers are real and whose *label* is a lie, and the
label is what a judge reads.

Where the live ceiling comes from
---------------------------------
Session generation is the entire cost of a run -- detection is free, at single
milliseconds even where a session takes seconds -- and it is linear in
``key_length`` at roughly ``2.2 ms`` per position on the machine
:data:`COST_TABLE` was measured on. :data:`LIVE_KEY_LENGTH_MAX` is ``1024``,
measured at ``2.5 s``, which is the largest run that still answers a click.
:data:`KEY_LENGTH_MIN` is ``24``: shorter than that a verifier scores a handful
of positions and every rate on the screen is one draw wide. Both floors are
degenerate below about ``L = 140`` and the run then carries no security claim at
all, which is a thing worth *showing* rather than forbidding -- so the minimum
sits below that line and the run's own panel says what it does not establish.

Both numbers are the ones the frontend half published first, in
``tools/phase6_fixtures.py``; matching them keeps the live dashboard and the
recorded one from disagreeing about what a click may ask for.

The security-grade set (:data:`~sih141.protocol.params.DEFAULT_PARAMS`,
``L = 115200``) is **four minutes and about 37 MB of transcript** per run. It is
not offered live and no pre-generated transcript is shipped for it -- see
:mod:`sih141.web.api` for what is published in its place, which is the closed
forms, not a run.

Examples
--------
The caps are data, and a refusal names the one it hit:

>>> from sih141.web.limits import LIVE_KEY_LENGTH_MAX, RequestRefused, check_key_length
>>> LIVE_KEY_LENGTH_MAX
1024
>>> try:
...     check_key_length(5000)
... except RequestRefused as refusal:
...     print(refusal.field, refusal.cap, str(LIVE_KEY_LENGTH_MAX) in str(refusal))
key_length 1024 True
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Final


__all__ = [
    "CHANNEL_ERROR_RATE_MAX",
    "CHECK_FRACTION_MAX",
    "COST_TABLE",
    "COST_TABLE_NOTE",
    "COUNT_EXCHANGE_TIMINGS",
    "EPS_DEFAULT",
    "EPS_MAX",
    "EPS_MIN",
    "KEY_LENGTH_MIN",
    "LIVE_KEY_LENGTH_MAX",
    "MAX_CONCURRENT_RUNS",
    "NOISE_MAX",
    "SEED_MAX",
    "RequestRefused",
    "check_check_fraction",
    "check_eps",
    "check_key_length",
    "check_probability",
    "check_seed",
    "check_timing",
    "json_safe",
    "limits_payload",
]


#: The shortest run the dashboard will execute. Below this a verifier's matched
#: set is a handful of positions and every rate on the screen is one draw wide;
#: refusing is more honest than rendering it. Deliberately *below* the 140 at
#: which both matched-count floors degenerate: a degenerate run is worth a
#: panel, and the run's own words say what it does not establish.
KEY_LENGTH_MIN: Final[int] = 24

#: The longest run the dashboard will execute live. See the module docstring
#: for the two reasons it sits here. Anything above it is **refused**, never
#: clamped (:ref:`no-silent-capping`).
LIVE_KEY_LENGTH_MAX: Final[int] = 1024

#: The largest share of a run that may be spent measuring the channel instead of
#: carrying key. At ``0.5`` half the positions are check rounds and the signed
#: key is half of ``L``; above that the run is mostly instrumentation.
CHECK_FRACTION_MAX: Final[float] = 0.5

#: The strongest link noise the dashboard will mount, as a depolarising
#: strength. Half of a completely depolarised link, which is already far past
#: anything the scheme tolerates: the design noise level is ``2 s_a = 0.03125``.
NOISE_MAX: Final[float] = 0.5

#: The largest accepted seed. Bounded only so a request cannot carry an integer
#: with a million digits; any value in range reproduces its run exactly.
SEED_MAX: Final[int] = 2**32 - 1

#: How many sessions may be generating at once. Session generation is CPU-bound
#: and blocking, so this is the real protection: without it a handful of tabs
#: hammering the run button saturates every core and the demo stops answering.
MAX_CONCURRENT_RUNS: Final[int] = 2

#: The false-positive budget the dashboard offers by default.
EPS_DEFAULT: Final[float] = 1e-9

#: The tightest budget the dashboard will accept. :func:`~sih141.detect.detect`
#: itself allows anything inside ``(0, 1)``, but a budget far below this leaves
#: every threshold vacuous -- unable to fire at any observation, which is a
#: false-positive probability of exactly zero AND no power at all. Refusing is
#: better than serving a screen on which nothing can ever light up.
EPS_MIN: Final[float] = 1e-19

#: The loosest. Above this the "budget" is not a security parameter any more.
EPS_MAX: Final[float] = 0.1

#: The largest null the rate family may be read against. Beyond this the null
#: describes a link nobody would sign over.
CHANNEL_ERROR_RATE_MAX: Final[float] = 0.5

#: Measured session-generation cost, for the key lengths the screen offers as
#: presets. Published so the frontend can say "about 2.7 seconds" *before* the
#: click without doing any arithmetic of its own (**D8**): it looks the row up,
#: it does not multiply.
#:
#: These are wall-clock measurements on one machine and are labelled as such by
#: :data:`COST_TABLE_NOTE`. They are not a bound and nothing depends on them.
COST_TABLE: Final[tuple[dict[str, Any], ...]] = (
    {"key_length": 96, "session_ms": 203, "detect_ms": 4, "transcript_kb": 32},
    {"key_length": 192, "session_ms": 407, "detect_ms": 6, "transcript_kb": 63},
    {"key_length": 384, "session_ms": 815, "detect_ms": 14, "transcript_kb": 125},
    {"key_length": 768, "session_ms": 1638, "detect_ms": 18, "transcript_kb": 249},
    {"key_length": 1024, "session_ms": 2509, "detect_ms": 33, "transcript_kb": 332},
)

#: What :data:`COST_TABLE` is and is not. Carried in the payload so the screen
#: renders this sentence rather than inventing one.
COST_TABLE_NOTE: Final[str] = (
    "Wall-clock session generation measured on one machine (i7-14700HX, "
    "check_fraction=0.25, no profiler). An estimate for sizing a progress "
    "indicator, not a bound and not a security number. Detection is free at "
    "every length; the session is the whole cost."
)

#: The two orderings of Phase C', which are two different experiments and never
#: a thing to average over.
COUNT_EXCHANGE_TIMINGS: Final[tuple[str, str]] = (
    "before-forwarding",
    "after-forwarding",
)


def json_safe(item: Any) -> Any:
    """Return ``item`` when JSON can carry it, and text where it cannot.

    An error body's whole job is to name the value that was refused -- and the
    one value that most needs naming is the one JSON cannot encode. Python's
    own parser reads the bare tokens ``NaN`` and ``Infinity``, which are valid
    Python and are **not** JSON, so a body carrying either reaches the range
    checks and is correctly refused by :func:`_as_float`. Before this guard the
    *refusal* then raised while being serialised, and the caller got a ``500``
    for a request the validator had already rejected properly -- an error path
    that only fails on the inputs that reach it, which is the kind that is
    found by driving the service rather than by reading it.

    Containers are walked, so one non-finite leaf costs its own leaf and not
    the whole body. Everything JSON already accepts is returned untouched, so
    this is a guard and never a transformation.

    Parameters
    ----------
    item : object
        A candidate for a JSON response body.

    Returns
    -------
    object
        ``item`` unchanged where ``json.dumps(..., allow_nan=False)`` accepts
        it; otherwise the same shape with each unencodable leaf as its
        ``repr``.

    Examples
    --------
    >>> from sih141.web.limits import json_safe
    >>> json_safe(1024), json_safe("honest"), json_safe(None)
    (1024, 'honest', None)
    >>> json_safe(float("nan")), json_safe(float("inf")), json_safe(float("-inf"))
    ('nan', 'inf', '-inf')
    >>> json_safe({"nested": [1, 2]})
    {'nested': [1, 2]}
    >>> json_safe({"loc": ["body", "seed"], "input": float("nan")})
    {'loc': ['body', 'seed'], 'input': 'nan'}
    >>> json_safe(object())[:7]
    '<object'
    """
    try:
        json.dumps(item, allow_nan=False)
    except (TypeError, ValueError):
        pass
    else:
        return item
    if isinstance(item, dict):
        return {str(key): json_safe(value) for key, value in item.items()}
    if isinstance(item, (list, tuple)):
        return [json_safe(value) for value in item]
    return repr(item)


class RequestRefused(Exception):
    """One request parameter was out of bounds, with the bound that refused it.

    Carries the offending field, the value, and the cap, so the endpoint can
    render a body a human can act on instead of a bare 400.

    Parameters
    ----------
    field : str
        The request field.
    message : str
        What is wrong, in a sentence that names the cap.
    value : object, optional
        What arrived.
    cap : object, optional
        The bound that refused it.

    Attributes
    ----------
    field : str
    value : object or None
    cap : object or None

    Examples
    --------
    >>> from sih141.web.limits import RequestRefused
    >>> refusal = RequestRefused("key_length", "too long, max 1024", 5000, 1024)
    >>> refusal.to_dict()["cap"]
    1024
    """

    def __init__(
        self,
        field: str,
        message: str,
        value: Any = None,
        cap: Any = None,
    ) -> None:
        super().__init__(message)
        self.field: str = field
        self.value: Any = value
        self.cap: Any = cap

    def to_dict(self) -> dict[str, Any]:
        """Return the refusal as a JSON-serialisable body.

        Returns
        -------
        dict
            ``field``, ``message``, ``value`` and ``cap``. Both ``value`` and
            ``cap`` pass through :func:`json_safe`, so the one value a
            refusal most needs to name -- the one JSON cannot carry -- is
            named as text rather than crashing the refusal.

        Examples
        --------
        >>> import json
        >>> from sih141.web.limits import RequestRefused
        >>> body = RequestRefused("noise", "must be finite", float("nan")).to_dict()
        >>> body["value"]
        'nan'
        >>> json.loads(json.dumps(body, allow_nan=False))["field"]
        'noise'
        """
        return {
            "field": self.field,
            "message": str(self),
            "value": json_safe(self.value),
            "cap": json_safe(self.cap),
        }


def _as_int(value: Any, field: str) -> int:
    """Return ``value`` as an :class:`int`, refusing bools and non-integers.

    Parameters
    ----------
    value : object
    field : str

    Returns
    -------
    int

    Raises
    ------
    RequestRefused
        If ``value`` is a bool or is not an integer.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequestRefused(
            field,
            f"{field} must be an integer, got {type(value).__name__}.",
            value,
        )
    return int(value)


def _as_float(value: Any, field: str) -> float:
    """Return ``value`` as a finite :class:`float`.

    Parameters
    ----------
    value : object
    field : str

    Returns
    -------
    float

    Raises
    ------
    RequestRefused
        If ``value`` is a bool, is not a real number, or is not finite. NaN is
        refused explicitly: it compares false against every bound, so an
        unchecked NaN slips past a range test and lands inside the protocol.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RequestRefused(
            field,
            f"{field} must be a real number, got {type(value).__name__}.",
            value,
        )
    number = float(value)
    if not math.isfinite(number):
        raise RequestRefused(
            field,
            f"{field} must be finite, got {number!r}. A non-finite value "
            f"compares false against every bound and would pass a range check "
            f"unexamined.",
            value,
        )
    return number


def check_key_length(value: Any) -> int:
    """Return ``value`` if it is a runnable live key length, else refuse.

    Parameters
    ----------
    value : object
        The requested ``L``.

    Returns
    -------
    int

    Raises
    ------
    RequestRefused
        If it is not an integer, or lies outside
        ``[KEY_LENGTH_MIN, LIVE_KEY_LENGTH_MAX]``. The message names the cap and
        says what the cap is for; it never clamps
        (:ref:`no-silent-capping`).

    Examples
    --------
    >>> from sih141.web.limits import RequestRefused, check_key_length
    >>> check_key_length(1024)
    1024
    >>> try:
    ...     check_key_length(1025)
    ... except RequestRefused as refusal:
    ...     print(refusal.cap, "refused rather than quietly run" in str(refusal))
    1024 True
    >>> try:
    ...     check_key_length(4)
    ... except RequestRefused as refusal:
    ...     print(refusal.cap)
    24
    """
    length = _as_int(value, "key_length")
    if length < KEY_LENGTH_MIN:
        raise RequestRefused(
            "key_length",
            f"key_length={length} is below the minimum of {KEY_LENGTH_MIN}. "
            f"Only about a third of positions are matched, so a shorter run "
            f"gives a verifier a handful of records and every rate on the "
            f"screen would be one draw wide.",
            length,
            KEY_LENGTH_MIN,
        )
    if length > LIVE_KEY_LENGTH_MAX:
        raise RequestRefused(
            "key_length",
            f"key_length={length} is above the live ceiling of "
            f"{LIVE_KEY_LENGTH_MAX}. Session generation costs about 2.2 ms per "
            f"position, so this run would take roughly "
            f"{length * 2.2 / 1000.0:.0f} s and hold a transcript of about "
            f"{length * 0.32:.0f} KB. The request is refused rather than "
            f"quietly run at {LIVE_KEY_LENGTH_MAX}: a screen reporting a "
            f"clamped run under the label of the one that was asked for is the "
            f"single easiest way for this dashboard to lie. The "
            f"security-grade set L=115200 is four minutes a run and is not "
            f"offered live; its bounds are closed forms and are published "
            f"under /api/defaults.",
            length,
            LIVE_KEY_LENGTH_MAX,
        )
    return length


def check_check_fraction(value: Any, key_length: int) -> float:
    """Return ``value`` if it designates a runnable check-round plan.

    Parameters
    ----------
    value : object
        The requested share of positions spent on channel estimation.
    key_length : int
        The run's ``L``, needed because ``floor(f * L)`` must be at least one
        check round -- a positive fraction that rounds to no rounds is a run
        that claims to be measuring the channel and is not.

    Returns
    -------
    float

    Raises
    ------
    RequestRefused
        If it is not a real number in ``[0, CHECK_FRACTION_MAX]``, or if it is
        positive and rounds to zero check rounds at this length.

    Examples
    --------
    >>> from sih141.web.limits import RequestRefused, check_check_fraction
    >>> check_check_fraction(0.25, 192)
    0.25
    >>> try:
    ...     check_check_fraction(0.001, 192)
    ... except RequestRefused as refusal:
    ...     print("0 check rounds" in str(refusal))
    True
    >>> try:
    ...     check_check_fraction(0.9, 192)
    ... except RequestRefused as refusal:
    ...     print(refusal.cap)
    0.5
    """
    fraction = _as_float(value, "check_fraction")
    if fraction < 0.0 or fraction > CHECK_FRACTION_MAX:
        raise RequestRefused(
            "check_fraction",
            f"check_fraction={fraction!r} must lie in "
            f"[0.0, {CHECK_FRACTION_MAX}]. Check rounds are excluded from the "
            f"key, so above that ceiling most of the run is instrumentation "
            f"and the signature is scored on what is left.",
            fraction,
            CHECK_FRACTION_MAX,
        )
    if fraction > 0.0 and math.floor(fraction * key_length) < 1:
        raise RequestRefused(
            "check_fraction",
            f"check_fraction={fraction!r} designates "
            f"floor({fraction!r} * {key_length}) = 0 check rounds, so nothing "
            f"would be estimated while the run claims estimation is happening. "
            f"Raise it to at least {1.0 / key_length!r}, lengthen the key, or "
            f"send 0.0 to say plainly that this run publishes no channel "
            f"statistics -- in which case the whole channel family is reported "
            f"as not evaluated, which is not the same as passed.",
            fraction,
            CHECK_FRACTION_MAX,
        )
    return fraction


def check_probability(value: Any, field: str, cap: float = 1.0) -> float:
    """Return ``value`` if it is a probability in ``[0, cap]``.

    Parameters
    ----------
    value : object
    field : str
        The request field, for the message.
    cap : float, optional
        The upper bound, ``1.0`` by default.

    Returns
    -------
    float

    Raises
    ------
    RequestRefused

    Examples
    --------
    >>> from sih141.web.limits import RequestRefused, check_probability
    >>> check_probability(0.03125, "noise")
    0.03125
    >>> try:
    ...     check_probability(2.0, "channel_error_rate")
    ... except RequestRefused as refusal:
    ...     print(refusal.field, refusal.cap)
    channel_error_rate 1.0
    >>> try:
    ...     check_probability(float("nan"), "noise")
    ... except RequestRefused as refusal:
    ...     print("must be finite" in str(refusal))
    True
    """
    number = _as_float(value, field)
    if number < 0.0 or number > cap:
        raise RequestRefused(
            field,
            f"{field}={number!r} must lie in [0.0, {cap}]. It is a "
            f"probability.",
            number,
            cap,
        )
    return number


def check_eps(value: Any) -> float:
    """Return ``value`` if it is a usable false-positive budget.

    Mirrors what :func:`sih141.detect.detect` itself accepts -- the open
    interval ``(0, 1)`` -- so a budget is refused here, with a message, rather
    than inside the detector.

    Parameters
    ----------
    value : object

    Returns
    -------
    float

    Raises
    ------
    RequestRefused

    Examples
    --------
    >>> from sih141.web.limits import RequestRefused, check_eps
    >>> check_eps(1e-9)
    1e-09
    >>> try:
    ...     check_eps(0.0)
    ... except RequestRefused as refusal:
    ...     print(refusal.cap)
    (1e-19, 0.1)
    >>> try:
    ...     check_eps(0.5)
    ... except RequestRefused as refusal:
    ...     print("stopped being a security parameter" in str(refusal))
    True
    """
    number = _as_float(value, "eps")
    if not EPS_MIN <= number <= EPS_MAX:
        raise RequestRefused(
            "eps",
            f"eps={number!r} must lie in [{EPS_MIN}, {EPS_MAX}]. It is the "
            f"false-positive budget for the whole detector. detect() itself "
            f"accepts anything strictly inside (0, 1); the dashboard is "
            f"narrower on purpose. A budget of 0 asks for a detector that "
            f"never fires on an honest run and therefore never fires; far "
            f"below {EPS_MIN} every threshold goes vacuous, which is a "
            f"false-positive probability of exactly zero AND no power at all, "
            f"and a screen on which nothing can light up is worse than a "
            f"refusal. Above {EPS_MAX} the budget has stopped being a security "
            f"parameter.",
            number,
            (EPS_MIN, EPS_MAX),
        )
    return number


def check_seed(value: Any) -> int:
    """Return ``value`` if it is a usable seed.

    Parameters
    ----------
    value : object

    Returns
    -------
    int

    Raises
    ------
    RequestRefused

    Examples
    --------
    >>> from sih141.web.limits import check_seed
    >>> check_seed(20260141)
    20260141
    """
    seed = _as_int(value, "seed")
    if seed < 0 or seed > SEED_MAX:
        raise RequestRefused(
            "seed",
            f"seed={seed} must lie in [0, {SEED_MAX}]. The seed reproduces a "
            f"run exactly -- both the session's stream and the adversary's, "
            f"derived separately (D3, D6) -- and is bounded only so a request "
            f"cannot carry an integer with a million digits.",
            seed,
            SEED_MAX,
        )
    return seed


def check_timing(value: Any) -> str:
    """Return ``value`` if it names one of the two Phase C' orderings.

    Parameters
    ----------
    value : object

    Returns
    -------
    str

    Raises
    ------
    RequestRefused

    Examples
    --------
    >>> from sih141.web.limits import check_timing
    >>> check_timing("after-forwarding")
    'after-forwarding'
    """
    if not isinstance(value, str) or value not in COUNT_EXCHANGE_TIMINGS:
        raise RequestRefused(
            "count_exchange_timing",
            f"count_exchange_timing must be one of "
            f"{list(COUNT_EXCHANGE_TIMINGS)}, got {value!r}. It decides which "
            f"declaration each recipient counted against, which is a different "
            f"experiment and not a tuning knob -- one ordering turns a "
            f"substituted declaration into a refusal and the other into a "
            f"scored forgery. Runs under the two are never pooled.",
            value,
            list(COUNT_EXCHANGE_TIMINGS),
        )
    return value


@dataclass(frozen=True)
class _LimitRow:
    """One published cap, as the screen shows it."""

    field: str
    minimum: Any
    maximum: Any
    note: str


def limits_payload() -> dict[str, Any]:
    """Return every cap as JSON, for ``/api/defaults`` to publish.

    The screen is required to show the caps, so they are served rather than
    duplicated in the frontend where they would drift.

    Returns
    -------
    dict
        ``fields`` (one row per bounded request field), ``max_concurrent_runs``,
        ``cost_table`` and ``cost_table_note``.

    Examples
    --------
    >>> from sih141.web.limits import limits_payload
    >>> payload = limits_payload()
    >>> payload["fields"]["key_length"]["maximum"]
    1024
    >>> payload["max_concurrent_runs"]
    2
    >>> [row["key_length"] for row in payload["cost_table"]]
    [96, 192, 384, 768, 1024]
    """
    rows = (
        _LimitRow(
            "key_length",
            KEY_LENGTH_MIN,
            LIVE_KEY_LENGTH_MAX,
            "L, positions per recipient per message bit. The whole cost of a "
            "run and the only parameter that can make one slow. Above the "
            "ceiling the request is refused, never clamped.",
        ),
        _LimitRow(
            "check_fraction",
            0.0,
            CHECK_FRACTION_MAX,
            "Share of positions spent measuring the channel instead of "
            "carrying key. At 0.0 the run publishes no channel statistics at "
            "all and the whole channel family is reported as not evaluated -- "
            "which is not the same as passed.",
        ),
        _LimitRow(
            "noise",
            0.0,
            NOISE_MAX,
            "Depolarising strength of the physical link, mounted on the "
            "resource line. Applies to the honest arm too, which is the point: "
            "an honest run over a noisy link departs from the detector's "
            "noiseless null.",
        ),
        _LimitRow(
            "eps",
            EPS_MIN,
            EPS_MAX,
            "False-positive budget for the whole detector. What is published "
            "afterwards is the bound the thresholds PROVE -- normally well "
            "inside the budget -- never this number, and never the post hoc "
            "evidence bound either.",
        ),
        _LimitRow(
            "channel_error_rate",
            0.0,
            CHANNEL_ERROR_RATE_MAX,
            "The null the rate family is read against, p_e. Defaults to 0.0, a "
            "claim about a noiseless link. It is set by the operator and never "
            "inferred from the run: a transcript without check rounds carries "
            "no estimate of it, and guessing would be inventing a null.",
        ),
        _LimitRow(
            "tolerated_depolarising",
            0.0,
            NOISE_MAX,
            "The null the CHANNEL family is read against, p0, as a Werner "
            "strength. Also defaults to 0.0, which claims an ideal resource. A "
            "separate number from channel_error_rate on purpose: they are two "
            "parameterisations of the same physics and converting one into the "
            "other silently would state a null the operator did not ask for. "
            "Optional: a request that omits it behaves exactly as the fixed "
            "contract's eight fields say.",
        ),
        _LimitRow(
            "seed",
            0,
            SEED_MAX,
            "Reproduces the run exactly. The session's stream and the "
            "adversary's are derived from it separately and are independent "
            "(D3, D6).",
        ),
        _LimitRow(
            "count_exchange_timing",
            None,
            None,
            "One of "
            + ", ".join(repr(name) for name in COUNT_EXCHANGE_TIMINGS)
            + ". A label on the result and a control, never a thing to pool "
            "over.",
        ),
    )
    return {
        "fields": {
            row.field: {
                "minimum": row.minimum,
                "maximum": row.maximum,
                "note": row.note,
            }
            for row in rows
        },
        "max_concurrent_runs": MAX_CONCURRENT_RUNS,
        "cost_table": [dict(row) for row in COST_TABLE],
        "cost_table_note": COST_TABLE_NOTE,
    }
