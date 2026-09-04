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

.. _refusals-cannot-raise:

A refusal may not raise, and that is a rule about SHAPE
-------------------------------------------------------
Three separate ``500`` responses in this phase were the same defect wearing
three costumes: a request was refused **correctly**, and the code reporting the
refusal fell over while quoting the input back. First a bare ``NaN`` in the
error body, which JSON cannot encode; then a body nested two thousand deep,
which every encoder between the rejection and the socket walks one stack frame
per level; then ``key_length`` with 309 digits, whose refusal message multiplied
it by ``2.2`` and got :exc:`OverflowError`.

So the rule is not "fix the multiplication". It is:

**Nothing that renders a refusal may compute on caller input, and every
caller-supplied value reaches a message or a body through
:func:`safe_text` or :func:`json_safe` -- both of which are total.**

Concretely: no arithmetic on a caller's number in any message here (a message
that wants a cost quotes :data:`COST_TABLE`, which is measured and pinned);
every interpolation of a caller value goes through :func:`safe_text`, which
catches whatever ``repr`` throws and truncates what it returns; and every value
in a response body goes through :func:`json_safe`, which bounds depth, replaces
what JSON cannot carry, and truncates what is too long to echo.
:data:`MAX_REQUEST_BYTES` closes the last door by refusing the body before any
of it is parsed. ``tests/test_web_api.py`` drives a battery of hostile bodies at
the running app and asserts that no request of any shape produces a ``5xx``.

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
    "MAX_ECHOED_CHARS",
    "MAX_ERROR_BODY_DEPTH",
    "MAX_REQUEST_BYTES",
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
    "safe_text",
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

#: How deep :func:`json_safe` will walk a value before replacing the rest with
#: a marker. An error body echoes the input that was refused, and that input is
#: whatever the client sent: ``[`` two thousand times is a body pydantic
#: rejects correctly and then cannot report, because every encoder between the
#: rejection and the socket recurses once per level. Bounded far below Python's
#: own recursion limit, and far above any body this API actually accepts --
#: the deepest legitimate request is a flat object of scalars.
MAX_ERROR_BODY_DEPTH: Final[int] = 32

#: How much caller-supplied text a refusal will quote back, per value. A
#: refusal names the value it refused, and the value is whatever the client
#: chose to send: an ``attack`` field holding 256 MB of ``x`` was echoed TWICE
#: -- once inside the message and once as ``value`` -- for a measured 2x on the
#: wire and about 9x in resident memory that was never released. A refusal has
#: to be *readable*, not complete, so anything longer is truncated with a count
#: of what was dropped (:ref:`refusals-cannot-raise`).
MAX_ECHOED_CHARS: Final[int] = 200

#: The largest request body the service will read, in bytes. The largest
#: legitimate one is nine scalars and about 300 bytes, so this is generous by
#: two orders of magnitude and still refuses the shapes that hurt: a body over
#: this size is answered ``413`` **before the application sees it**, so nothing
#: parses it, echoes it, or holds it. Without it the only thing standing
#: between a socket and the process's memory was the JSON parser, and
#: ``MAX_CONCURRENT_RUNS`` offered nothing at all -- that gate is taken after
#: validation, and a body this size never reaches it.
MAX_REQUEST_BYTES: Final[int] = 64 * 1024

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


def safe_text(value: Any, limit: int = MAX_ECHOED_CHARS) -> str:
    """Return a bounded, printable form of ``value``. Never raises.

    The one function every refusal message quotes caller input through
    (:ref:`refusals-cannot-raise`). It is total by construction, which is the
    whole point: a message is built *while* a request is being refused, so an
    exception raised here turns a correct ``400`` into a ``500`` and the caller
    learns nothing about what was wrong.

    Two things can go wrong when a value is rendered, and both are things a
    client chooses. ``repr`` can **raise** -- an integer with more digits than
    :func:`sys.set_int_max_str_digits` allows is the one this API meets, and an
    object with a hostile ``__repr__`` is the general case -- and ``repr`` can
    return something **enormous**, which is then echoed back down the wire and
    held in memory while it is.

    Parameters
    ----------
    value : object
        Whatever arrived.
    limit : int, optional
        Longest text returned before truncation, :data:`MAX_ECHOED_CHARS` by
        default.

    Returns
    -------
    str
        ``value`` as text, at most ``limit`` characters plus a note counting
        the characters dropped.

    Examples
    --------
    >>> from sih141.web.limits import safe_text
    >>> safe_text(1024), safe_text("honest"), safe_text(None)
    ('1024', 'honest', 'None')

    An integer far too large to render as decimal is described rather than
    printed, and nothing raises:

    >>> len(safe_text(9 * 10 ** 20000)) <= 240
    True
    >>> "20001 digits" in safe_text(9 * 10 ** 20000)
    True

    A value too long to quote is truncated, with the count of what was dropped
    -- this is the whole of the wire amplification defect:

    >>> quoted = safe_text("x" * 1000000)
    >>> len(quoted) < 260, "999800 more characters" in quoted
    (True, True)

    An object whose ``repr`` raises is named by its type, and still no
    exception escapes:

    >>> class Hostile:
    ...     def __repr__(self):
    ...         raise RuntimeError("no")
    >>> safe_text(Hostile())
    '<Hostile whose repr() raised>'
    """
    try:
        text = value if isinstance(value, str) else repr(value)
    except ValueError:
        # The one case with a better answer than "it raised": Python refuses to
        # render an integer beyond `sys.get_int_max_str_digits()` digits, and
        # the digit count is exactly what a reader wants to know.
        try:
            digits = int(math.floor(math.log10(abs(value)))) + 1
            text = f"<integer of about {digits} digits>"
        except Exception:  # noqa: BLE001 - the guard's guard
            text = f"<{type(value).__name__} whose repr() raised>"
    except Exception:  # noqa: BLE001 - deliberately total
        text = f"<{type(value).__name__} whose repr() raised>"
    if len(text) > limit:
        return f"{text[:limit]}... [{len(text) - limit} more characters]"
    return text


def json_safe(item: Any, depth: int = 0) -> Any:
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

    DEPTH is the second way the same error path fails, and it fails for the
    same reason: the body echoes the input that was refused, and the input is
    whatever the client chose to send. A body of ``[`` two thousand times is
    rejected correctly by pydantic -- and then every encoder between that
    rejection and the socket walks it one stack frame per level, so the
    :exc:`RecursionError` lands while the refusal is being written and the
    caller gets a ``500`` for a request that was already properly refused.
    Anything nested deeper than :data:`MAX_ERROR_BODY_DEPTH` is replaced by a
    marker naming that depth, which is a truthful report of a body nobody
    should have sent and cannot itself recurse.

    LENGTH is the third, and it does not crash -- it *amplifies*. The echoed
    value is as large as the client made it, and it appears in the body beside
    a message that also names it, so a large field came back roughly twice its
    own size and was held in memory the whole time it did. Every leaf therefore
    goes through :func:`safe_text`, which truncates with a count of what was
    dropped. A refusal has to be readable, not complete.

    Parameters
    ----------
    item : object
        A candidate for a JSON response body.
    depth : int, optional
        Current nesting level, for the recursive walk. Callers pass nothing.

    Returns
    -------
    object
        ``item`` unchanged where ``json.dumps(..., allow_nan=False)`` accepts
        it and it is short enough to echo; otherwise the same shape with each
        unencodable leaf as text, anything nested deeper than
        :data:`MAX_ERROR_BODY_DEPTH` replaced by a marker, and anything longer
        than :data:`MAX_ECHOED_CHARS` truncated.

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

    A body far deeper than anything this API accepts is reported rather than
    walked, and the result is still JSON:

    >>> import json
    >>> deep = []
    >>> nest = deep
    >>> for _ in range(2000):
    ...     inner = []
    ...     nest.append(inner)
    ...     nest = inner
    >>> nest.append(float("nan"))
    >>> quoted = json.dumps(json_safe(deep), allow_nan=False)
    >>> "nested beyond 32 levels" in quoted
    True

    A value too long to echo is truncated rather than returned, so a refusal
    can never be larger than the thing it refuses:

    >>> echoed = json_safe({"attack": "x" * 1000000})["attack"]
    >>> len(echoed) < 260, "999800 more characters" in echoed
    (True, True)

    An integer no decimal representation exists for is described. It is a
    ``400`` either way; before this it was a ``500``:

    >>> json_safe(9 * 10 ** 20000)
    '<integer of about 20001 digits>'
    """
    if depth >= MAX_ERROR_BODY_DEPTH:
        return f"<nested beyond {MAX_ERROR_BODY_DEPTH} levels>"
    # Containers are ALWAYS walked, never probed whole. Probing first and
    # returning the value untouched when `json.dumps` accepts it is the
    # obvious shape and it is wrong here: a 200-deep list encodes perfectly
    # well, so the probe succeeds, the value is handed back at full depth,
    # and whatever walks it next is the thing that runs out of stack. The
    # depth bound only means anything if it is applied on the way down.
    if isinstance(item, dict):
        return {
            str(key): json_safe(value, depth + 1)
            for key, value in item.items()
        }
    if isinstance(item, (list, tuple)):
        return [json_safe(value, depth + 1) for value in item]
    try:
        json.dumps(item, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return safe_text(item)
    # `json.dumps` accepting it says nothing about its SIZE, and the size is
    # the client's to choose. Only two encodable leaves can be arbitrarily
    # long: a string, and an integer short enough that `dumps` rendered it.
    if isinstance(item, str) and len(item) > MAX_ECHOED_CHARS:
        return safe_text(item)
    if isinstance(item, int) and not isinstance(item, bool):
        quoted = safe_text(item)
        if not quoted.lstrip("-").isdigit():
            return quoted
    return item


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


def _quoted(value: Any) -> str:
    """Return ``value`` as bounded text for a refusal message.

    A one-line alias for :func:`safe_text` at its default bound, so that every
    interpolation of caller input in this module reads the same and none of
    them is an f-string doing its own thing (:ref:`refusals-cannot-raise`).

    Parameters
    ----------
    value : object

    Returns
    -------
    str

    Examples
    --------
    >>> from sih141.web.limits import _quoted
    >>> _quoted(1025)
    '1025'
    """
    return safe_text(value)


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

    A length with more digits than a float can hold is refused like any other,
    and the refusal survives being written. It did not before: the message
    estimated the run's cost by multiplying, and the multiplication raised
    :exc:`OverflowError` at 309 digits or more, so a request the validator had
    already rejected correctly came back as ``500``
    (:ref:`refusals-cannot-raise`).

    >>> import json
    >>> try:
    ...     check_key_length(int("9" * 400))
    ... except RequestRefused as refusal:
    ...     body = refusal.to_dict()
    >>> body["field"], body["cap"]
    ('key_length', 1024)
    >>> json.loads(json.dumps(body, allow_nan=False))["value"]
    '999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999... [200 more characters]'
    >>> try:
    ...     check_key_length(9 * 10 ** 20000)
    ... except RequestRefused as refusal:
    ...     print(refusal.to_dict()["value"])
    <integer of about 20001 digits>
    """
    length = _as_int(value, "key_length")
    if length < KEY_LENGTH_MIN:
        raise RequestRefused(
            "key_length",
            f"key_length={_quoted(length)} is below the minimum of "
            f"{KEY_LENGTH_MIN}. Only about a third of positions are matched, "
            f"so a shorter run gives a verifier a handful of records and every "
            f"rate on the screen would be one draw wide.",
            length,
            KEY_LENGTH_MIN,
        )
    if length > LIVE_KEY_LENGTH_MAX:
        # The cost quoted here is the MEASURED row at the ceiling, not an
        # estimate computed from `length`. That is not a stylistic preference:
        # `length * 2.2 / 1000.0` raised OverflowError for any request with 309
        # or more digits, so a correctly refused request came back as a 500
        # while its own refusal was being written (:ref:`refusals-cannot-raise`).
        ceiling_ms = COST_TABLE[-1]["session_ms"]
        raise RequestRefused(
            "key_length",
            f"key_length={_quoted(length)} is above the live ceiling of "
            f"{LIVE_KEY_LENGTH_MAX}. Session generation is the whole cost of a "
            f"run and it is linear in the key length: the ceiling itself "
            f"measures {ceiling_ms} ms per session, and this asks for more "
            f"positions than that. The request is refused rather than quietly "
            f"run at {LIVE_KEY_LENGTH_MAX}: a screen reporting a clamped run "
            f"under the label of the one that was asked for is the single "
            f"easiest way for this dashboard to lie. The security-grade set "
            f"L=115200 is four minutes a run and is not offered live; its "
            f"bounds are closed forms and are published under /api/defaults.",
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
            f"seed={_quoted(seed)} must lie in [0, {SEED_MAX}]. The seed "
            f"reproduces a "
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

    The value is quoted back through :func:`safe_text`, so a caller who sends a
    megabyte here is told what was wrong without the refusal carrying the
    megabyte twice (:ref:`refusals-cannot-raise`):

    >>> from sih141.web.limits import RequestRefused
    >>> try:
    ...     check_timing("z" * 1000000)
    ... except RequestRefused as refusal:
    ...     print(len(str(refusal)) < 600, len(refusal.to_dict()["value"]) < 260)
    True True
    """
    if not isinstance(value, str) or value not in COUNT_EXCHANGE_TIMINGS:
        raise RequestRefused(
            "count_exchange_timing",
            f"count_exchange_timing must be one of "
            f"{list(COUNT_EXCHANGE_TIMINGS)}, got {_quoted(value)}. It decides "
            f"which "
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
        ``max_request_bytes``, ``cost_table`` and ``cost_table_note``.

    Examples
    --------
    >>> from sih141.web.limits import limits_payload
    >>> payload = limits_payload()
    >>> payload["fields"]["key_length"]["maximum"]
    1024
    >>> payload["max_concurrent_runs"]
    2
    >>> payload["max_request_bytes"]
    65536
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
        "max_request_bytes": MAX_REQUEST_BYTES,
        "max_request_bytes_note": (
            "The largest request body the service will read. A larger one is "
            "answered 413 before the application sees it, so nothing parses "
            "it, echoes it or holds it. The largest legitimate body is nine "
            "scalars and about 300 bytes."
        ),
        "max_echoed_chars": MAX_ECHOED_CHARS,
        "cost_table": [dict(row) for row in COST_TABLE],
        "cost_table_note": COST_TABLE_NOTE,
    }
