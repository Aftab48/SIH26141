"""What this costs to run, measured, and every projection derived from it.

Phase 5's plan rests on one number -- how long a session takes -- and that
number was nearly got badly wrong. An earlier brief stated 6.7 ms per position
and 42.9 hours for the sweep, which was true of the *measurement* rather than of
the thing measured: ``tracemalloc`` had been left attached, inflating every
timing by very close to three times. It survived scrutiny because it was
self-consistent across three key lengths. Internal agreement is not evidence.

Two rules follow, and this module exists to enforce the second.

**Do not attach a profiler to a run you intend to quote.** :func:`time_session`
attaches nothing.

**Do not extrapolate from a cheap proxy when you can afford the real thing.**
The figure below is an end-to-end run at the production parameters, not a
projection from ``L = 3072``.

.. _measured-rate:

The measurement
---------------
:data:`MEASURED_SESSIONS` holds it, and every derived figure in this module is
computed from that table rather than written down beside it. So the totals
Phase 5 plans against -- twelve and a half hours single-threaded, about fifty
minutes at twenty workers -- are doctests over the measured rate, and moving the
rate moves them or fails the suite. That is what D5 asks for: a number written
as an executable example is a live test, and a number written in prose is not
checked at all. Five wrong prose numbers have already shipped in this project.

Examples
--------
The rate itself, and what it says about a full-scale session:

>>> from sih141.eval.perf import (
...     MEASURED_SESSIONS, REFERENCE_MS_PER_POSITION,
...     projected_session_seconds, projected_sweep_hours,
... )
>>> round(REFERENCE_MS_PER_POSITION, 3)
2.041
>>> round(projected_session_seconds(115200), 1)
235.1
>>> round(projected_session_seconds(115200) / 60, 2)
3.92

Two hundred trials at production parameters, single-threaded:

>>> round(projected_sweep_hours(200, 115200), 1)
13.1

And at twenty workers -- as a **range**, because the speedup is the one figure
in this module that did not reproduce. Two runs of the same command gave 7.04x
and 10.27x; the plan's original 15x estimate is outside both and is what the
range exists to rule out. See :data:`MEASURED_SPEEDUP_KEY_LENGTH`.

>>> [round(projected_sweep_hours(200, 115200, speedup=s), 1)
...  for s in (7.04, 10.27)]
[1.9, 1.3]
>>> round(projected_sweep_hours(200, 115200, speedup=15.0) * 60, 0)
52.0

Scaling held across a 1200x range in ``L``, which is what makes the projection
above a projection rather than a guess -- 2.0 to 2.4 ms per position from
``L = 192`` to ``L = 115200``:

>>> lo = min(row["ms_per_position"] for row in MEASURED_SESSIONS)
>>> hi = max(row["ms_per_position"] for row in MEASURED_SESSIONS)
>>> 1.9 < lo and hi < 2.5
True
>>> max(row["key_length"] for row in MEASURED_SESSIONS) // min(
...     row["key_length"] for row in MEASURED_SESSIONS)
1200

Transcript size depends on the check fraction as much as on ``L``, and a figure
quoted without both is not a figure. An unchecked full-scale run is 0.226 KiB per
position; the same length at a quarter checked is 0.330, because every check
round publishes a channel sample:

>>> from sih141.eval.perf import MEASURED_TRANSCRIPT_KB, MEASURED_DETECT_SECONDS
>>> MEASURED_TRANSCRIPT_KB[(115200, 0.0)]
0.226
>>> MEASURED_TRANSCRIPT_KB[(115200, 0.25)]
0.33
>>> round(MEASURED_TRANSCRIPT_KB[(115200, 0.25)]
...       / MEASURED_TRANSCRIPT_KB[(115200, 0.0)], 2)
1.46

**And it is re-measured here rather than looked up.** Three of these entries
were wrong by up to 21% for a whole release because the only test on them read
the dict back; a transcript's size is deterministic in its seed, so the honest
check is to build one and count the bytes. Two lengths, both check fractions,
about a second:

>>> from sih141.eval.perf import time_session
>>> for length in (96, 192):
...     for fraction in (0.0, 0.25):
...         got = time_session(
...             length, seed=5 + length, check_fraction=fraction
...         )["kb_per_position"]
...         want = MEASURED_TRANSCRIPT_KB[(length, fraction)]
...         print(length, fraction, round(got, 3) == want)
96 0.0 True
96 0.25 True
192 0.0 True
192 0.25 True

The check bites, and the retired value shows how far off a wrong one can sit
while still looking plausible. At ``L = 96`` the published figure was 0.408; a
quarter-checked run is 0.337, and 0.408 is roughly what a check fraction of
0.42 produces -- a different configuration, not a different machine. The seed
moves the answer by about a thousandth, so it cannot absorb a gap this size:

>>> quarter = time_session(96, seed=101, check_fraction=0.25)
>>> heavier = time_session(96, seed=101, check_fraction=0.42)
>>> round(quarter["kb_per_position"], 3), round(heavier["kb_per_position"], 3)
(0.337, 0.407)
>>> spread = [
...     time_session(96, seed=s, check_fraction=0.25)["kb_per_position"]
...     for s in (1, 2, 3, 101)
... ]
>>> round(max(spread) - min(spread), 4) < 0.001
True

Detector latency is not the constant few milliseconds an earlier note implied,
because it is dominated by parsing that transcript:

>>> MEASURED_DETECT_SECONDS[115200]
1.541
>>> MEASURED_DETECT_SECONDS[115200] > 100 * MEASURED_DETECT_SECONDS[192]
True
"""

from __future__ import annotations

import sys
import time
from typing import Any, Final, Mapping, Sequence

__all__ = [
    "MEASURED_DETECT_SECONDS",
    "DEGENERATE_END",
    "MEASURED_MEMORY",
    "MEASURED_SESSIONS",
    "MEASURED_SPEEDUP",
    "MEASURED_SPEEDUP_KEY_LENGTH",
    "MEASURED_SPEEDUP_TRIALS",
    "MEASURED_TRANSCRIPT_KB",
    "REFERENCE_KEY_LENGTH",
    "REFERENCE_MS_PER_POSITION",
    "SECURITY_CLAIM_MIN_KEY_LENGTH",
    "SPEEDUP_NOTE",
    "detector_latency",
    "peak_rss_bytes",
    "measure_memory",
    "measure_small_end",
    "measured_speedup_at",
    "measured_speedup_curve",
    "measure_scaling",
    "projected_session_seconds",
    "projected_sweep_hours",
    "speedup_table",
    "time_session",
]

REFERENCE_KEY_LENGTH: Final[int] = 115200
"""int: ``DEFAULT_PARAMS.key_length``. The rate is quoted at this scale."""

MEASURED_SESSIONS: Final[tuple[dict[str, Any], ...]] = (
    {
        "key_length": 96,
        "check_fraction": 0.25,
        "seconds": 0.211,
        "ms_per_position": 2.198,
        "source": "phase5 harness, single worker, BLAS pinned to 1",
    },
    {
        "key_length": 192,
        "check_fraction": 0.25,
        "seconds": 0.420,
        "ms_per_position": 2.188,
        "source": "phase5 harness, single worker, BLAS pinned to 1",
    },
    {
        "key_length": 768,
        "check_fraction": 0.25,
        "seconds": 1.650,
        "ms_per_position": 2.148,
        "source": "phase4 brief, confirmed",
    },
    {
        "key_length": 115200,
        "check_fraction": 0.0,
        "seconds": 235.092,
        "ms_per_position": 2.041,
        "source": "phase5 end-to-end, seed 20260905, no profiler attached",
    },
)
"""tuple of dict: Sessions actually timed, end to end, on the target machine.

The last row is the one everything is planned against: one honest session at
``DEFAULT_PARAMS``, timed with nothing attached. It confirms the 230.2 s already
recorded in ``docs/QDS.md`` to within 2.1%, and buries the 6.7 ms/position
figure for good. See :ref:`measured-rate`.
"""

MEASURED_TRANSCRIPT_KB: Final[Mapping[tuple[int, float], float]] = {
    (96, 0.25): 0.337,
    (192, 0.25): 0.330,
    (768, 0.25): 0.325,
    (3072, 0.25): 0.326,
    (12288, 0.25): 0.327,
    (115200, 0.25): 0.330,
    (96, 0.0): 0.230,
    (192, 0.0): 0.224,
    (768, 0.0): 0.220,
    (3072, 0.0): 0.221,
    (12288, 0.0): 0.223,
    (115200, 0.0): 0.226,
}
"""Mapping: Transcript JSON size in KiB per position, by ``(L, check_fraction)``.

A kibibyte -- ``len(json) / 1024`` -- because that is what
:func:`time_session` divides by, so a megabyte derived from a row here is a
mebibyte and the two must not be mixed in one sentence.

Keyed by ``(L, check_fraction)``, because **the check fraction is half the
answer** and quoting the figure without it is how a correct number becomes a
wrong one. Check rounds publish a channel sample per round -- fidelity, purity,
concurrence, both wing purities -- so a quarter-checked run carries about 46%
more transcript per position than an unchecked one at the same length.

**The curve is not monotone, and an earlier draft of this docstring said it
was.** At ``check_fraction = 0.25`` the size falls from 0.337 at ``L = 96`` to a
minimum of 0.325 around ``L = 768`` and then rises again to 0.330 at full scale;
at ``check_fraction = 0`` it dips to 0.220 at ``L = 768`` and returns to 0.226.
Two effects run against each other -- a fixed header amortising away, and
per-position integers growing a digit as the indices they name get larger -- so
"falls towards 0.33 as the header is amortised" describes only the first half of
the range.

This mapping has now been wrong twice, in opposite directions, which is why the
module docstring re-measures it instead of only looking it up.

The first time, a draft recorded 0.226 as *the* full-scale figure and wrote that
the Phase 5 brief's 0.33 was an error. The brief was right: it had measured a
checked run. Both numbers were correct measurements of two different
configurations and the mistake was reporting one without its second coordinate.

The second time -- caught by the Phase 5 integration audit, by running the
command printed beside the published table -- the three small entries read
0.408, 0.371 and 0.339 against a true 0.337, 0.330 and 0.325. They were 21%, 12%
and 4% high, they had never come from ``perf --session-scaling`` at
``check_fraction = 0.25`` (0.408 is what ``L = 96`` gives at a check fraction of
about 0.42), and they survived because the doctest beside them looked the
constant up rather than measuring anything. A doctest that reads a dict literal
proves the literal is still there. The two full-scale entries were exact.
"""

MEASURED_DETECT_SECONDS: Final[Mapping[int, float]] = {
    96: 0.0029,
    192: 0.0041,
    768: 0.0113,
    115200: 1.541,
}
"""Mapping: :func:`~sih141.detect.detector.detect` latency in seconds, by ``L``.

Measured on the transcript's **JSON text**, which is the door the detector
actually uses, so the figure includes the parse. The three small entries are
quarter-checked runs and the full-scale one is unchecked, which does not affect
the point: latency is not a constant few milliseconds. At full scale it is
1.54 s, dominated by reading 25.4 MiB of JSON, against 2.9 ms on a 96-position
transcript. It scales with ``L`` like everything else, and it is still under one
percent of the session that produced the transcript.
"""

REFERENCE_MS_PER_POSITION: Final[float] = 2.041
"""float: Milliseconds per position at :data:`REFERENCE_KEY_LENGTH`.

The one number the run plan rests on. Taken from the last row of
:data:`MEASURED_SESSIONS`, and everything else in this module is arithmetic
over it.
"""


def projected_session_seconds(
    key_length: int, *, ms_per_position: float = REFERENCE_MS_PER_POSITION
) -> float:
    """Return how long one session at ``key_length`` should take.

    Parameters
    ----------
    key_length : int
        ``L``.
    ms_per_position : float, optional
        Keyword-only. Defaults to the measured rate.

    Returns
    -------
    float
        Seconds.

    Raises
    ------
    ValueError
        If ``key_length`` is not positive.

    Notes
    -----
    Linear in ``L``, which is a claim :data:`MEASURED_SESSIONS` supports over a
    1200-fold range rather than an assumption. It is a projection all the same:
    at the production parameters the *measurement* is in that table and should
    be quoted instead.

    Examples
    --------
    >>> from sih141.eval.perf import projected_session_seconds
    >>> round(projected_session_seconds(192), 3)
    0.392
    >>> round(projected_session_seconds(1024), 2)
    2.09
    """
    if isinstance(key_length, bool) or not isinstance(key_length, int):
        raise TypeError(f"key_length must be an int, got {type(key_length).__name__}")
    if key_length <= 0:
        raise ValueError(f"key_length must be positive, got {key_length}")
    return key_length * float(ms_per_position) / 1000.0


def projected_sweep_hours(
    trials: int,
    key_length: int,
    *,
    speedup: float = 1.0,
    ms_per_position: float = REFERENCE_MS_PER_POSITION,
) -> float:
    """Return how long a sweep of ``trials`` sessions should take, in hours.

    Parameters
    ----------
    trials : int
        Total sessions, across every cell.
    key_length : int
        ``L``.
    speedup : float, optional
        Keyword-only. Achieved parallel speedup -- the *measured* factor, not
        the worker count. On this laptop twenty workers give roughly fifteen,
        because it is a laptop part and it throttles.
    ms_per_position : float, optional
        Keyword-only. Defaults to the measured rate.

    Returns
    -------
    float
        Hours.

    Raises
    ------
    ValueError
        If ``trials`` is not positive or ``speedup`` is not positive.

    Examples
    --------
    >>> from sih141.eval.perf import projected_sweep_hours
    >>> round(projected_sweep_hours(200, 115200), 1)
    13.1
    >>> round(projected_sweep_hours(200, 115200, speedup=20.0) * 60, 1)
    39.2

    The default speedup is one, so passing none gives the single-threaded cost
    rather than an optimistic one:

    >>> projected_sweep_hours(10, 1024) == projected_sweep_hours(
    ...     10, 1024, speedup=1.0)
    True
    """
    if isinstance(trials, bool) or not isinstance(trials, int):
        raise TypeError(f"trials must be an int, got {type(trials).__name__}")
    if trials <= 0:
        raise ValueError(f"trials must be positive, got {trials}")
    if float(speedup) <= 0.0:
        raise ValueError(f"speedup must be positive, got {speedup!r}")
    serial = trials * projected_session_seconds(
        key_length, ms_per_position=ms_per_position
    )
    return serial / float(speedup) / 3600.0


def time_session(
    key_length: int,
    *,
    seed: int,
    check_fraction: float = 0.25,
    message_bit: int = 0,
) -> dict[str, Any]:
    """Time one honest session, its serialisation and its detection.

    No profiler is attached, deliberately; see the module docstring.

    Parameters
    ----------
    key_length : int
        ``L``.
    seed : int
        Keyword-only. The session seed, through
        :func:`~sih141.core.rng.seed_to_generator`.
    check_fraction : float, optional
        Keyword-only. Fraction of positions spent on check rounds.
    message_bit : int, optional
        Keyword-only.

    Returns
    -------
    dict
        ``key_length``, ``seconds``, ``ms_per_position``,
        ``positions_per_second``, ``json_bytes``, ``kb_per_position``,
        ``detect_seconds``, and the run's own ``transferable`` and ``aborted``
        so a timing that silently produced a degenerate run is visible.

    Examples
    --------
    >>> from sih141.eval.perf import time_session
    >>> timing = time_session(96, seed=7)
    >>> timing["key_length"], timing["transferable"]
    (96, True)
    >>> timing["ms_per_position"] > 0 and timing["kb_per_position"] > 0
    True
    """
    from sih141.core.rng import seed_to_generator
    from sih141.detect.detector import detect
    from sih141.protocol.params import ProtocolParams
    from sih141.protocol.session import QDSSession

    params = ProtocolParams(key_length=key_length, check_fraction=check_fraction)
    started = time.perf_counter()
    transcript = QDSSession(params, rng=seed_to_generator(seed)).run(message_bit)
    session_seconds = time.perf_counter() - started

    started = time.perf_counter()
    text = transcript.to_json()
    serialise_seconds = time.perf_counter() - started

    started = time.perf_counter()
    detect(text, eps=1e-9)
    detect_seconds = time.perf_counter() - started

    return {
        "key_length": key_length,
        "check_fraction": check_fraction,
        "seed": seed,
        "seconds": session_seconds,
        "ms_per_position": 1000.0 * session_seconds / key_length,
        "positions_per_second": key_length / session_seconds,
        "json_bytes": len(text),
        "kb_per_position": len(text) / 1024.0 / key_length,
        "serialise_seconds": serialise_seconds,
        "detect_seconds": detect_seconds,
        "transferable": bool(transcript.transferable),
        "aborted": bool(transcript.aborted),
    }


def detector_latency(key_length: int, *, seed: int, repeats: int = 3) -> dict[str, Any]:
    """Time the detector alone, separately from generating the transcript.

    Parameters
    ----------
    key_length : int
        ``L``.
    seed : int
        Keyword-only. Session seed.
    repeats : int, optional
        Keyword-only. How many times to score the same JSON text. The minimum
        is reported alongside the mean, because the minimum is the one a
        background process cannot inflate.

    Returns
    -------
    dict
        ``key_length``, ``json_bytes``, ``mean_seconds``, ``min_seconds``,
        ``mb_per_second``.

    Raises
    ------
    ValueError
        If ``repeats`` is not positive.

    Examples
    --------
    >>> from sih141.eval.perf import detector_latency
    >>> latency = detector_latency(96, seed=3, repeats=2)
    >>> latency["min_seconds"] <= latency["mean_seconds"]
    True
    >>> latency["json_bytes"] > 0
    True
    """
    if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 1:
        raise ValueError(f"repeats must be a positive int, got {repeats!r}")
    from sih141.core.rng import seed_to_generator
    from sih141.detect.detector import detect
    from sih141.protocol.params import ProtocolParams
    from sih141.protocol.session import QDSSession

    params = ProtocolParams(key_length=key_length, check_fraction=0.25)
    text = QDSSession(params, rng=seed_to_generator(seed)).run(0).to_json()
    timings: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        detect(text, eps=1e-9)
        timings.append(time.perf_counter() - started)
    mean = sum(timings) / len(timings)
    return {
        "key_length": key_length,
        "json_bytes": len(text),
        "repeats": repeats,
        "mean_seconds": mean,
        "min_seconds": min(timings),
        "mb_per_second": (len(text) / 1_048_576.0) / min(timings),
    }


def measure_scaling(
    key_lengths: Sequence[int], *, seed: int = 5, check_fraction: float = 0.25
) -> list[dict[str, Any]]:
    """Time one session at each key length and return the rows.

    Parameters
    ----------
    key_lengths : Sequence of int
        The lengths to time, in the order given.
    seed : int, optional
        Keyword-only. Base seed; each length gets ``seed + L`` so the runs are
        independent but reproducible.
    check_fraction : float, optional
        Keyword-only.

    Returns
    -------
    list of dict
        One :func:`time_session` result per length.

    Examples
    --------
    >>> from sih141.eval.perf import measure_scaling
    >>> rows = measure_scaling([48, 96])
    >>> [row["key_length"] for row in rows]
    [48, 96]
    """
    return [
        time_session(length, seed=seed + length, check_fraction=check_fraction)
        for length in key_lengths
    ]


def speedup_table(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Turn ``(workers, seconds)`` measurements into a speedup curve.

    Parameters
    ----------
    rows : Sequence of Mapping
        Each with ``workers`` and ``seconds``. The one-worker row is the
        baseline; without it there is nothing to divide by and that is an
        error rather than a silently-omitted column.

    Returns
    -------
    list of dict
        ``workers``, ``seconds``, ``speedup``, ``efficiency`` -- speedup over
        worker count, which is the number that says whether the extra
        processes are earning their keep.

    Raises
    ------
    ValueError
        If no one-worker row is present.

    Examples
    --------
    >>> from sih141.eval.perf import speedup_table
    >>> table = speedup_table([
    ...     {"workers": 1, "seconds": 100.0},
    ...     {"workers": 4, "seconds": 27.0},
    ...     {"workers": 20, "seconds": 7.0},
    ... ])
    >>> [(r["workers"], round(r["speedup"], 2)) for r in table]
    [(1, 1.0), (4, 3.7), (20, 14.29)]
    >>> round(table[-1]["efficiency"], 3)
    0.714
    """
    baseline = next(
        (float(row["seconds"]) for row in rows if int(row["workers"]) == 1), None
    )
    if baseline is None:
        raise ValueError(
            "a speedup curve needs a one-worker baseline; none of the rows "
            "has workers == 1, and a curve normalised to its own fastest "
            "point reports an efficiency of 1.0 no matter how bad it is."
        )
    table: list[dict[str, Any]] = []
    for row in rows:
        workers = int(row["workers"])
        seconds = float(row["seconds"])
        speedup = baseline / seconds if seconds > 0 else float("inf")
        table.append(
            {
                "workers": workers,
                "seconds": seconds,
                "speedup": speedup,
                "efficiency": speedup / workers,
            }
        )
    return table


def peak_rss_bytes() -> int | None:
    """Return this process's peak resident set size, without a profiler.

    Returns
    -------
    int or None
        Bytes, or ``None`` where the platform offers no cheap answer.

    Notes
    -----
    Deliberately **not** :mod:`tracemalloc`. Leaving a profiler attached is how
    this project's earlier throughput figure came out three times too large, and
    a memory measurement that distorts the timing beside it is worth less than
    no measurement. This reads a counter the operating system maintains anyway:
    ``GetProcessMemoryInfo`` on Windows, :func:`resource.getrusage` elsewhere.
    It costs a syscall and changes nothing about the run.

    Peak rather than current, because the question a sweep asks is "will twenty
    of these fit in 24 GiB", and the answer is about the high-water mark.

    Examples
    --------
    >>> from sih141.eval.perf import peak_rss_bytes
    >>> peak = peak_rss_bytes()
    >>> peak is None or peak > 1_000_000
    True
    """
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class _Counters(ctypes.Structure):
            """The ``PROCESS_MEMORY_COUNTERS`` struct, fields in order."""

            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        # argtypes and restype are not optional here. Without them ctypes
        # defaults every argument to a 32-bit int, so the pseudo-handle -1 that
        # GetCurrentProcess returns arrives as 0xFFFFFFFF rather than as a
        # 64-bit HANDLE, the call fails, and the probe reports zero bytes --
        # which looks exactly like a process that used no memory.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Counters),
            wintypes.DWORD,
        ]
        counters = _Counters()
        counters.cb = ctypes.sizeof(_Counters)
        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        )
        return int(counters.PeakWorkingSetSize) if ok else None
    try:
        import resource
    except ImportError:
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes, macOS bytes.
    return int(usage) * (1024 if sys.platform.startswith("linux") else 1)


def measure_memory(key_lengths: Sequence[int], *, seed: int = 5) -> list[dict[str, Any]]:
    """Time and measure peak memory for one session at each key length.

    Parameters
    ----------
    key_lengths : Sequence of int
        Ascending, because peak RSS is a high-water mark within one process:
        running the largest first would make every later row report that peak.
    seed : int, optional
        Keyword-only. Base seed.

    Returns
    -------
    list of dict
        ``key_length``, ``peak_rss_mb``, ``delta_mb`` (the rise over the
        previous row) and ``json_mb``.

    Raises
    ------
    ValueError
        If ``key_lengths`` is not ascending, since a descending order would
        silently report the first row's peak for all of them.

    Examples
    --------
    >>> from sih141.eval.perf import measure_memory
    >>> rows = measure_memory([48, 96])
    >>> [row["key_length"] for row in rows]
    [48, 96]
    >>> measure_memory([96, 48])
    Traceback (most recent call last):
        ...
    ValueError: key_lengths must be ascending...
    """
    lengths = list(key_lengths)
    if lengths != sorted(lengths):
        raise ValueError(
            f"key_lengths must be ascending, got {lengths}. Peak RSS is a "
            f"high-water mark for the whole process, so a larger run earlier "
            f"would be reported as every later run's peak."
        )
    from sih141.core.rng import seed_to_generator
    from sih141.protocol.params import ProtocolParams
    from sih141.protocol.session import QDSSession

    rows: list[dict[str, Any]] = []
    previous = peak_rss_bytes() or 0
    for length in lengths:
        params = ProtocolParams(key_length=length, check_fraction=0.25)
        transcript = QDSSession(params, rng=seed_to_generator(seed + length)).run(0)
        text = transcript.to_json()
        peak = peak_rss_bytes() or 0
        rows.append(
            {
                "key_length": length,
                "peak_rss_mb": peak / 1_048_576.0,
                "delta_mb": (peak - previous) / 1_048_576.0,
                "json_mb": len(text) / 1_048_576.0,
            }
        )
        previous = peak
        del transcript, text
    return rows


def measure_small_end(
    key_lengths: Sequence[int],
    *,
    trials: int = 5,
    seed: int = 5,
    check_fraction: float = 0.25,
) -> list[dict[str, Any]]:
    """Measure what the protocol does at key lengths too small to claim anything.

    The small end is where three separate things go wrong at once and none of
    them is a bug: the matched-count floors degenerate to 1 so no run carries a
    security claim, honest runs start aborting because a verifier's matched set
    falls under the floor, and whether a detector family is evaluable stops
    being a clean function of ``L``. All three are worth a table, and the table
    had no committed command until this function existed -- its figures came
    from an ad-hoc probe, which under D9 is the same as having no figures.

    Parameters
    ----------
    key_lengths : Sequence of int
        The lengths to probe. A length whose parameter set refuses to exist --
        ``floor(check_fraction * L) == 0`` with a positive check fraction --
        is reported as ``refused`` rather than skipped, because a row missing
        from a table reads as a case that was never tried.
    trials : int, optional
        Keyword-only. Honest sessions per length.
    seed : int, optional
        Keyword-only. Base seed; trial ``i`` at length ``L`` runs under
        ``seed + L + i``, so the whole table is a pure function of its
        arguments.
    check_fraction : float, optional
        Keyword-only.

    Returns
    -------
    list of dict
        Per length: ``key_length``, ``signing_length``, ``m_min``, ``M_min``,
        ``aborts``, ``trials``, ``security_claim``, ``security_claim_varies``
        and ``withheld_min``/``withheld_max`` -- the range of withheld
        detector families over the trials, because near the boundary it is not
        constant -- or ``refused`` with the reason.

    Examples
    --------
    A length whose parameter set cannot exist is a row, not a gap:

    >>> from sih141.eval.perf import measure_small_end
    >>> rows = measure_small_end([3], trials=1)
    >>> rows[0]["key_length"], rows[0]["refused"]
    (3, True)
    >>> "check" in rows[0]["reason"]
    True

    And a real length reports the floors beside the aborts they cause:

    >>> rows = measure_small_end([24], trials=2)
    >>> row = rows[0]
    >>> row["signing_length"], row["m_min"], row["M_min"]
    (18, 1, 1)
    >>> row["security_claim"], row["aborts"] <= row["trials"]
    (False, True)
    >>> row["withheld_min"] <= row["withheld_max"]
    True
    """
    from sih141.core.rng import seed_to_generator
    from sih141.detect.detector import detect
    from sih141.protocol.params import ProtocolParams
    from sih141.protocol.session import QDSSession
    from sih141.protocol.verify import (
        minimum_matched_count,
        minimum_pooled_matched_count,
    )

    rows: list[dict[str, Any]] = []
    for length in key_lengths:
        try:
            params = ProtocolParams(
                key_length=length, check_fraction=check_fraction
            )
        except (ValueError, TypeError) as exc:
            rows.append(
                {
                    "key_length": length,
                    "refused": True,
                    "reason": str(exc).splitlines()[0],
                }
            )
            continue
        aborts = 0
        withheld: list[int] = []
        claims: set[bool] = set()
        for index in range(trials):
            transcript = QDSSession(
                params, rng=seed_to_generator(seed + length + index)
            ).run(0)
            if transcript.aborted:
                aborts += 1
            # Every trial, not just the first. How many families are evaluable
            # is not constant near the boundary -- it depends on how the check
            # rounds happened to split between the QBER and CHSH cells -- so a
            # single run's answer would report one draw as the property.
            detection = detect(transcript.to_json(), eps=1e-9)
            withheld.append(len(detection.withheld))
            claims.add(bool(detection.security_claim))
        rows.append(
            {
                "key_length": length,
                "refused": False,
                "signing_length": params.signing_length,
                "m_min": minimum_matched_count(params),
                "M_min": minimum_pooled_matched_count(params),
                "aborts": aborts,
                "trials": trials,
                "security_claim": claims == {True},
                "security_claim_varies": len(claims) > 1,
                "withheld_min": min(withheld),
                "withheld_max": max(withheld),
            }
        )
    return rows


MEASURED_SPEEDUP: Final[tuple[dict[str, Any], ...]] = (
    {"workers": 1, "wall_seconds": 204.81, "trial_seconds_total": 203.98},
    {"workers": 4, "wall_seconds": 59.86, "trial_seconds_total": 233.17},
    {"workers": 8, "wall_seconds": 40.37, "trial_seconds_total": 305.56},
    {"workers": 14, "wall_seconds": 34.44, "trial_seconds_total": 436.13},
    {"workers": 20, "wall_seconds": 29.10, "trial_seconds_total": 516.26},
)
"""tuple of dict: The achieved parallel speedup, measured on this machine.

120 honest sessions at ``L = 768`` per point, each point into a fresh results
directory so a resumed sweep could not time an empty run. Regenerate with::

    python tools/sweep.py perf --speedup --speedup-cell l768 \
        --trials 120 --workers 1,4,8,14,20

``wall_seconds`` is the sweep end to end, pool startup included.
``trial_seconds_total`` is the sum of the per-trial timings measured *inside*
the workers, and the ratio of the two is how many workers were busy on average.
The two together are what separate "the pool is idling" from "the cores are
slow", and on this machine it is the second: see :data:`SPEEDUP_NOTE`.
"""

SPEEDUP_NOTE: Final[str] = (
    "20 workers give 7.04x wall-clock speedup, not the 15x the plan assumed. "
    "The pool is not idling -- 17.7 of 20 workers are busy on average -- but "
    "each worker runs 2.5x slower than a lone one. The slowdown begins at "
    "eight workers, before any E-core is reached, so it is the all-core turbo "
    "budget and shared cache before it is the E-cores. BLAS oversubscription "
    "was ruled out by asking a worker what its own environment says, and a "
    "cold-versus-hot baseline was ruled out by re-measuring the one-worker "
    "point immediately after the twenty-worker run: 1.702 s/trial against "
    "1.700 s, a 0.1% difference."
)
"""str: What the speedup curve means, in one paragraph, for a table caption."""

MEASURED_SPEEDUP_TRIALS: Final[int] = 120
"""int: Sessions per point in :data:`MEASURED_SPEEDUP`."""

MEASURED_SPEEDUP_KEY_LENGTH: Final[int] = 768
"""int: Key length :data:`MEASURED_SPEEDUP` was measured at.

Stated because the curve should not be quoted at ``L = 115200`` without it. At
768 a trial is 1.7 s and pool startup is a visible share of the parallel
points; at 115200 a trial is 235 s and startup vanishes, but each worker also
holds a far larger transcript, so memory pressure could be worse rather than
better.

**And the speedup ratio should not be quoted as a number at all.** Re-running
the identical command during the Phase 5 integration pass gave 305.47 s at one
worker and 29.75 s at twenty -- a speedup of 10.27x against the 7.04x above.
The twenty-worker wall clock held to 2.2% across the two runs; the SINGLE-WORKER
BASELINE moved by 49%, because a lone core stops boosting as soon as anything
else on the machine is awake. On the re-run, one worker and four workers cost
the same 2.53 s per trial, which is what a collapsed baseline looks like. Quote
the wall clock, which reproduces; quote the ratio only with both measurements
beside it. See ``docs/PHASE5.md`` section 11.2.
"""

MEASURED_MEMORY: Final[tuple[dict[str, Any], ...]] = (
    {"key_length": 96, "peak_rss_mb": 78.5, "transcript_mb": 0.03},
    {"key_length": 768, "peak_rss_mb": 80.4, "transcript_mb": 0.24},
    {"key_length": 3072, "peak_rss_mb": 86.2, "transcript_mb": 0.98},
    {"key_length": 12288, "peak_rss_mb": 107.3, "transcript_mb": 3.92},
    {"key_length": 49152, "peak_rss_mb": 197.0, "transcript_mb": 15.82},
    {"key_length": 115200, "peak_rss_mb": 348.7, "transcript_mb": 37.17},
)
"""tuple of dict: Peak resident set against key length, one worker.

Read from ``GetProcessMemoryInfo`` rather than :mod:`tracemalloc`, so nothing
about the measurement distorts the timings beside it. Regenerate with::

    python tools/sweep.py perf --memory --key-lengths 96,768,3072,12288,49152,115200

Every row is at ``check_fraction = 0.25``, which is the expensive case: the
production set :data:`~sih141.protocol.params.DEFAULT_PARAMS` is unchecked and
its transcript is 25.4 MiB rather than 37.2, so the full-scale peak there is
lower than the last row. Both figures are mebibytes; an earlier draft printed
the first in decimal megabytes as 26.7 and left the second in binary ones,
which is a unit mismatch inside one sentence.

Re-measured during the Phase 5 integration pass, on a machine in a different
state: 79.1, 80.8, 87.3, 107.7, 198.1 and 352.0 MiB. Every row within 1%, and
the transcript sizes identical to the byte because they are deterministic.
Unlike the timings in :data:`MEASURED_SPEEDUP`, this table reproduces.

The floor is a little under 80 MiB -- numpy and qiskit imported, before any
session -- and the rise above it is roughly linear in ``L``. At full scale one
worker peaks at 350 MiB, so twenty are about 7 GiB against this machine's 24.
That fits, but it is not the "under 2 GB" the phase brief records: that figure
is twenty import floors and does not count the transcripts.

Every figure in this docstring is a mebibyte, because ``peak_rss_bytes`` and
``json_bytes`` are both divided by 1048576. Mixing those with decimal megabytes
in one sentence is how the full-scale transcript came to be quoted as 26.7 in
one place and 37.2 in another when both were the same measurement in different
units.
"""

SECURITY_CLAIM_MIN_KEY_LENGTH: Final[int] = 182
"""int: Smallest ``L`` carrying a security claim at ``check_fraction = 0.25``.

Measured by scanning every length, not by bisecting between two of them: at
``L = 181`` -- signing length 136 -- the pooled floor ``M_min`` is 1 and
``Detection.security_claim`` is ``False``; at ``L = 182`` -- signing length 137
-- ``M_min`` reaches 2 and the claim turns on. An earlier draft said 183, from
a bisection that tried 180 and 183 and neither of the two lengths between them;
182 and 183 both carry a claim, so the endpoints agreed and the boundary was
still off by one. :data:`~sih141.eval.security.FLOOR_CROSSOVER` is the same
fact stated in signing lengths, 137, and the two now agree.

The number to hold onto is the **signing** length, 137, not the nominal key
length. A quarter of the positions go to check rounds, so a caller who sets
``key_length = 140`` because "below 140 the floors degenerate" gets a signing
length of 105 and no claim at all. Below this, runs still complete and the
detector still returns a verdict; what it does not return is a claim.
"""

DEGENERATE_END: Final[str] = (
    "Below L=182 at check_fraction=0.25 the pooled floor degenerates to 1 and "
    "no run carries a security claim. Below about L=24 aborts appear on honest "
    "runs -- 1 in 5 at L=6 and L=12 -- because a verifier's matched set falls "
    "under the floor, and those are no-verdicts rather than rejections. At "
    "L=3 the parameter set refuses to be built at all: floor(0.25 * 3) is zero "
    "check rounds, so the run would claim estimation while estimating nothing. "
    "Whether a detector family is evaluable is not a clean function of L "
    "either: below about L=216 the channel family is withheld on some runs and "
    "not others, because it depends on how the check rounds happened to split "
    "between QBER and CHSH cells."
)
"""str: What happens at the small end, measured rather than assumed.

Every figure here comes from ``tools/`` probes over five trials per length; the
boundary at 182 is pinned as :data:`SECURITY_CLAIM_MIN_KEY_LENGTH` and tested
by a scan across it rather than by two endpoints that skip it.
"""


def measured_speedup_curve() -> list[dict[str, Any]]:
    """Return :data:`MEASURED_SPEEDUP` worked into the numbers a table prints.

    Returns
    -------
    list of dict
        ``workers``, ``seconds``, ``speedup``, ``efficiency``, plus
        ``occupancy`` -- in-worker seconds over wall clock, which is how many
        workers were busy on average -- and ``mean_trial_seconds``, which is
        what each of them actually cost.

    Notes
    -----
    Occupancy and speedup answer two different questions and the pair is the
    whole diagnosis. A pool that idles shows low occupancy; a pool whose cores
    slow down shows high occupancy and low speedup. This machine shows the
    second, so adding workers is not the fix and neither is chunk size.

    Examples
    --------
    The curve, and the fact that it is nowhere near linear:

    >>> from sih141.eval.perf import measured_speedup_curve
    >>> curve = measured_speedup_curve()
    >>> [(row["workers"], round(row["speedup"], 2)) for row in curve]
    [(1, 1.0), (4, 3.42), (8, 5.07), (14, 5.95), (20, 7.04)]
    >>> [round(row["efficiency"], 2) for row in curve]
    [1.0, 0.86, 0.63, 0.42, 0.35]

    The pool was not idling -- nearly eighteen of twenty workers were busy --
    so the missing throughput is per-core speed, not scheduling:

    >>> round(curve[-1]["occupancy"], 1)
    17.7
    >>> [round(row["mean_trial_seconds"], 2) for row in curve]
    [1.7, 1.94, 2.55, 3.63, 4.3]

    And the slowdown starts at eight workers, before an E-core is reached:

    >>> round(curve[2]["mean_trial_seconds"] / curve[0]["mean_trial_seconds"], 2)
    1.5
    """
    rows = [
        {"workers": row["workers"], "seconds": row["wall_seconds"]}
        for row in MEASURED_SPEEDUP
    ]
    curve = speedup_table(rows)
    for entry, measured in zip(curve, MEASURED_SPEEDUP):
        entry["occupancy"] = (
            measured["trial_seconds_total"] / measured["wall_seconds"]
        )
        entry["mean_trial_seconds"] = (
            measured["trial_seconds_total"] / MEASURED_SPEEDUP_TRIALS
        )
    return curve


def measured_speedup_at(workers: int) -> float:
    """Return the measured wall-clock speedup at one worker count.

    Parameters
    ----------
    workers : int
        A worker count present in :data:`MEASURED_SPEEDUP`.

    Returns
    -------
    float

    Raises
    ------
    KeyError
        If that worker count was not measured. Interpolating a speedup curve
        that is this far from linear would invent a number.

    Examples
    --------
    The one the run plan uses, and what it does to the plan:

    >>> from sih141.eval.perf import measured_speedup_at, projected_sweep_hours
    >>> round(measured_speedup_at(20), 2)
    7.04
    >>> round(projected_sweep_hours(200, 115200,
    ...                             speedup=measured_speedup_at(20)), 2)
    1.86

    Against the 51 minutes the plan assumed at an estimated 15x:

    >>> round(projected_sweep_hours(200, 115200, speedup=15.0) * 60, 0)
    52.0

    An unmeasured worker count is refused rather than interpolated:

    >>> measured_speedup_at(12)
    Traceback (most recent call last):
        ...
    KeyError: 'no speedup measured at 12 workers; measured: [1, 4, 8, 14, 20]'
    """
    for row in measured_speedup_curve():
        if row["workers"] == workers:
            return float(row["speedup"])
    raise KeyError(
        f"no speedup measured at {workers} workers; measured: "
        f"{[row['workers'] for row in MEASURED_SPEEDUP]}"
    )
