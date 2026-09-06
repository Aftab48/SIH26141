"""The security event log: one line per verification outcome, and nothing else.

The problem statement's deliverable 6 names "logging of security events" as a
key component, and until this module existed the repository had none. There is
no ``import logging`` anywhere under :mod:`sih141` or ``tools/``, and
:mod:`sih141.web.api` persisted nothing at all. This is that log, and every one
of the decisions below is a decision to record *less* than a general-purpose
logger would.

Two modules import this one, both in the web layer: :mod:`sih141.web.api`,
which records a verdict as it is reached, and :mod:`sih141.web.__main__`, which
builds the log the server is handed. Nothing under :mod:`sih141.protocol`,
:mod:`sih141.detect`, :mod:`sih141.eval` or :mod:`sih141.attacks` imports it,
so no protocol quantity and no threshold is computed differently because a log
exists.

The application keeps one whether or not it was asked to.
:func:`~sih141.web.api.create_app` builds an in-memory log when it is passed
none, because ``GET /api/events`` serves a log and an endpoint that serves one
has to have one. So ``create_app()`` now retains up to
:data:`DEFAULT_CAPACITY` events in process memory and serves them on an
unauthenticated endpoint, where before it kept nothing at all between
requests. That is a change in the server's behaviour, and it is stated here
rather than left for a reader to find.

.. _why-not-the-stdlib-logger:

Why this is not :mod:`logging`
------------------------------
Two of :mod:`logging`'s defining properties are wrong here.

**It stamps a wall clock.** Every :class:`logging.LogRecord` carries
``created``, and a project whose published records are reproducible from a
recorded seed (convention D9) cannot have that: two runs of the same committed
command would differ in the one field nothing in the protocol produced. So
**no timestamp is generated in this module**. Events are ordered by
:attr:`SecurityEvent.seq`, a monotonic counter starting at zero on a fresh log.
A caller who wants a clock passes one in through ``timestamp`` and owns what
that does to reproducibility.

**It is reached through a process-global registry.** ``logging.getLogger``
resolves to shared mutable state, so a library call can begin writing to a
handler its caller never installed. Here a log is an object someone holds:
:func:`~sih141.web.api.create_app` builds one per application when it is given
none, so two applications are two logs, and there is no name a third caller
could resolve to reach either.

.. _the-vocabulary-is-the-shipped-one:

The verdict is the shipped four-valued outcome
----------------------------------------------
:attr:`SecurityEvent.verdict` is a
:class:`~sih141.detect.thresholds_structural.RunOutcome` and not a three-valued
accepted / rejected / no-verdict of this module's own. Folding
``refused-to-score`` and ``not-asked`` into a single "no verdict" label loses
the distinction that type was written to keep -- a party who was asked and
returned nothing and a party the run never reached are different events, and a
log is exactly where that difference has to survive. Reusing the type also
means the log and
:attr:`~sih141.detect.detector.Detection.outcomes` cannot drift into two
spellings of one vocabulary.

:attr:`SecurityEvent.party`, by contrast, is a plain :class:`str` and not
:class:`~sih141.protocol.params.Party`. That enum admits ``ALICE``, ``BOB`` and
``CHARLIE`` only, so a party outside the round's authorised recipient set is
not representable in it -- and an unauthorised verification attempt is, by
definition, made by such a party. A log that cannot name the party cannot
record the event it exists for.

.. _what-the-log-cannot-see:

What the log cannot see
-----------------------
An event records a **self-declared** identity. Verification consumes one
:class:`~sih141.protocol.records.RecipientRecord` bound to a distribution
round, and a record obtained by any means outside the protocol still says
``Bob``: a party verifying with a leaked record produces an event no field of
which differs from the event its owner would have produced. This log does not
detect that and cannot. It records what was claimed, which is a smaller thing
than recording who acted, and the difference is not a gap to be closed by
adding fields here.

.. _bounded-retention:

Append-only, and bounded
------------------------
Append-only in the sense that matters: there is no update and no delete, and
:meth:`AuditLog.events` hands back a tuple rather than the live store.

It is also **bounded**, because a log that grows without limit inside a
long-running demo process is an outage with a virtuous name. The store is a
:class:`collections.deque` with ``maxlen``; when it is full the oldest event is
dropped to make room, and :attr:`AuditLog.dropped` counts how many. That
counter is the honest half: a reader who cannot tell a truncated log from a
complete one has a log that lies by omission, and ``dropped > 0`` says which
this is.

The cap bounds what the log **holds**, and only that. A ``path`` receives every
event as it is recorded, including the ones the cap later drops, and nothing
here trims that file: an operator who configures one owns its size.

Serialisation is JSON Lines, one event per line, so a file can be appended to
and read back a line at a time.
:class:`~sih141.detect.thresholds_structural.RunOutcome`,
:class:`~sih141.protocol.verify.AbortReason` and
:class:`~sih141.core.paulis.PauliBasis` are all :class:`enum.StrEnum`, so
members *are* strings and :func:`json.dumps` takes them with no encoder.

Examples
--------
A log, two events, and the ordering that is not a clock:

>>> from sih141.audit import AuditLog
>>> from sih141.detect.thresholds_structural import RunOutcome
>>> from sih141.protocol.verify import AbortReason
>>> log = AuditLog()
>>> event = log.record(
...     party="Bob",
...     verdict=RunOutcome.ACCEPTED,
...     session_id="round-1",
...     key_length=192,
...     check_fraction=0.25,
...     hypotheses=["honest"],
... )
>>> event.seq, event.verdict
(0, <RunOutcome.ACCEPTED: 'accepted'>)
>>> log.record(
...     party="Charlie",
...     verdict=RunOutcome.REFUSED,
...     session_id="round-1",
...     abort_reason=AbortReason.BELOW_FLOOR,
...     key_length=192,
...     check_fraction=0.25,
... ).seq
1

Two runs of the same three lines produce the same two events, because nothing
in them was read off a clock:

>>> other = AuditLog()
>>> _ = other.record(
...     party="Bob",
...     verdict=RunOutcome.ACCEPTED,
...     session_id="round-1",
...     key_length=192,
...     check_fraction=0.25,
...     hypotheses=["honest"],
... )
>>> other.events()[0] == log.events()[0]
True

JSON Lines, and the abort reason arrives as its own label:

>>> import json
>>> lines = log.to_jsonl().splitlines()
>>> len(lines), json.loads(lines[0])["party"]
(2, 'Bob')
>>> json.loads(lines[1])["verdict"], json.loads(lines[1])["abort_reason"]
('refused-to-score', 'matched-count-below-floor')

A party outside the authorised set is representable, which is the whole reason
``party`` is a string (:ref:`the-vocabulary-is-the-shipped-one`):

>>> log.record(
...     party="Mallory",
...     verdict=RunOutcome.REJECTED,
...     key_length=192,
...     check_fraction=0.25,
... ).party
'Mallory'

The cap drops the oldest and says how many it dropped
(:ref:`bounded-retention`):

>>> small = AuditLog(capacity=2)
>>> for index in range(5):
...     _ = small.record(
...         party="Bob",
...         verdict=RunOutcome.ACCEPTED,
...         key_length=96,
...         check_fraction=0.25,
...     )
>>> len(small), small.dropped, [event.seq for event in small.events()]
(2, 3, [3, 4])
"""

from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from sih141.detect.thresholds_structural import RunOutcome

__all__ = ["DEFAULT_CAPACITY", "AuditLog", "SecurityEvent"]


DEFAULT_CAPACITY: Final[int] = 512
"""int: How many events a log retains before the oldest is dropped.

Chosen against the thing that fills the log rather than against a round number:
a run produces one event per verifier, so this is roughly 256 runs, which is
more than a demonstration session generates and small enough that the retained
events are bytes rather than megabytes. Past that the oldest go and
:attr:`AuditLog.dropped` counts them (:ref:`bounded-retention`).
"""


@dataclass(frozen=True)
class SecurityEvent:
    """One verification outcome, as the log records it.

    Frozen, because an audit record that can be edited after the fact is not
    one.

    Attributes
    ----------
    seq : int
        Position in the log that produced it, from zero. **The ordering**, in
        place of a timestamp (:ref:`why-not-the-stdlib-logger`). Monotonic
        across the whole life of a log, so it keeps counting past a drop and a
        gap in the sequence is a dropped event rather than a lost one.
    session_id : str or None
        Which round the event belongs to, as the caller names it. ``None`` when
        the caller keeps no ledger. Two events carrying the same value are two
        parties in one round, which is the only grouping this log supports.
    party : str
        Who reached the verdict, **as declared**. A string rather than
        :class:`~sih141.protocol.params.Party`, so that a party outside the
        authorised recipient set can be named at all; and self-declared, so a
        leaked record still reads ``Bob``
        (:ref:`what-the-log-cannot-see`).
    verdict : RunOutcome
        The shipped four-valued outcome, never a boolean and never a
        three-valued restatement of it
        (:ref:`the-vocabulary-is-the-shipped-one`).
    abort_reason : str or None
        Why no verdict was reached, where none was. An
        :class:`~sih141.protocol.verify.AbortReason` member goes in directly:
        it is a :class:`enum.StrEnum`, so it *is* its label. ``None`` on any
        event that reached a verdict.
    key_length : int
        The parameter the thresholds were derived at. Recorded because a
        verdict read without it says nothing: every floor and every null in the
        scheme is stated over a length.
    check_fraction : float
        The other parameter that moves those thresholds.
    hypotheses : tuple of str
        :attr:`~sih141.detect.detector.Detection.named`, the hypotheses the
        evidence supported. Empty when the detector named none, which is a
        legitimate result and not a missing field.
    timestamp : str or float or None
        Whatever the caller passed, unread and unvalidated. ``None`` by
        default, and nothing in this module ever fills it in
        (:ref:`why-not-the-stdlib-logger`).

    Examples
    --------
    >>> from sih141.audit import SecurityEvent
    >>> from sih141.detect.thresholds_structural import RunOutcome
    >>> event = SecurityEvent(
    ...     seq=0,
    ...     session_id=None,
    ...     party="Bob",
    ...     verdict=RunOutcome.ACCEPTED,
    ...     abort_reason=None,
    ...     key_length=192,
    ...     check_fraction=0.25,
    ...     hypotheses=("honest",),
    ... )
    >>> event.to_dict()["verdict"], event.to_dict()["hypotheses"]
    ('accepted', ['honest'])
    """

    seq: int
    session_id: str | None
    party: str
    verdict: RunOutcome
    abort_reason: str | None
    key_length: int
    check_fraction: float
    hypotheses: tuple[str, ...] = ()
    timestamp: str | float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the event as one JSON object.

        Returns
        -------
        dict
            Passes to :func:`json.dumps` unchanged: ``verdict`` and
            ``abort_reason`` are :class:`enum.StrEnum` members or ``None``, and
            the tuple becomes a list because JSON has no tuple.
        """
        return {
            "seq": self.seq,
            "session_id": self.session_id,
            "party": self.party,
            "verdict": str(self.verdict),
            "abort_reason": (
                None if self.abort_reason is None else str(self.abort_reason)
            ),
            "key_length": self.key_length,
            "check_fraction": self.check_fraction,
            "hypotheses": list(self.hypotheses),
            "timestamp": self.timestamp,
        }


class AuditLog:
    """An append-only, bounded record of verification outcomes.

    Construct it, pass it in, read it back. The one place in :mod:`sih141` that
    builds a log unasked is :func:`~sih141.web.api.create_app`, which needs one
    to serve ``GET /api/events``; nothing else does
    (:ref:`why-not-the-stdlib-logger`).

    Parameters
    ----------
    capacity : int, optional
        How many events to retain, :data:`DEFAULT_CAPACITY` by default. The
        oldest goes when the store is full and :attr:`dropped` counts it
        (:ref:`bounded-retention`).
    path : pathlib.Path or str or None, optional
        Where to append the JSON Lines, or ``None`` -- the default -- to keep
        the log in memory only. The file is opened once at construction, so a
        path that cannot be written fails here rather than in the middle of a
        run.

    Attributes
    ----------
    capacity, path, dropped, recorded

    Examples
    --------
    In memory, which is the default:

    >>> from sih141.audit import AuditLog
    >>> from sih141.detect.thresholds_structural import RunOutcome
    >>> log = AuditLog()
    >>> log.path is None, log.capacity
    (True, 512)
    >>> _ = log.record(
    ...     party="Bob",
    ...     verdict=RunOutcome.REJECTED,
    ...     key_length=96,
    ...     check_fraction=0.25,
    ... )
    >>> len(log), log.recorded, log.dropped
    (1, 1, 0)

    An unknown verdict is refused rather than stored, because a log whose
    vocabulary is open is not one anything can be counted from:

    >>> log.record(
    ...     party="Bob",
    ...     verdict="maybe",
    ...     key_length=96,
    ...     check_fraction=0.25,
    ... )
    Traceback (most recent call last):
        ...
    ValueError: 'maybe' is not a valid RunOutcome
    """

    def __init__(
        self,
        capacity: int = DEFAULT_CAPACITY,
        path: Path | str | None = None,
    ) -> None:
        self._capacity = int(capacity)
        self._path = None if path is None else Path(path)
        self._events: deque[SecurityEvent] = deque(maxlen=self._capacity)
        self._recorded = 0
        # Two runs may be in flight at once (`MAX_CONCURRENT_RUNS`), and
        # FastAPI runs a synchronous endpoint on a worker thread, so `record`
        # really is called from more than one. Assigning the sequence number,
        # appending and writing the line have to be one step, or two events
        # share a `seq`.
        self._lock = threading.Lock()
        if self._path is not None:
            # Fail here on an unwritable path, not four minutes into a demo.
            with self._path.open("a", encoding="utf-8"):
                pass

    @property
    def capacity(self) -> int:
        """int: How many events are retained."""
        return self._capacity

    @property
    def path(self) -> Path | None:
        """pathlib.Path or None: Where events are appended, if anywhere."""
        return self._path

    @property
    def recorded(self) -> int:
        """int: Events recorded over the log's whole life, drops included."""
        return self._recorded

    @property
    def dropped(self) -> int:
        """int: Events the cap discarded.

        ``0`` on any log that never filled. Non-zero means the retained events
        are a suffix and not the whole history, which is a fact a reader has to
        be given rather than left to infer (:ref:`bounded-retention`).

        Read under the lock, because :meth:`record` assigns the sequence number
        and appends the event as two statements: a reader landing between them
        would count one more recorded than retained and report a drop on a log
        that had dropped nothing.
        """
        with self._lock:
            return self._recorded - len(self._events)

    def __len__(self) -> int:
        """int: How many events are retained right now."""
        return len(self._events)

    def record(
        self,
        *,
        party: str,
        verdict: RunOutcome | str,
        key_length: int,
        check_fraction: float,
        session_id: str | None = None,
        abort_reason: str | None = None,
        hypotheses: Iterable[str] = (),
        timestamp: str | float | None = None,
    ) -> SecurityEvent:
        """Append one verification outcome.

        Parameters
        ----------
        party : str
            Keyword-only, and every parameter below it likewise. The verifying
            party as declared.
        verdict : RunOutcome or str
            Coerced through
            :class:`~sih141.detect.thresholds_structural.RunOutcome`, so an
            outcome outside the four raises rather than being stored.
        key_length : int
        check_fraction : float
        session_id : str or None, optional
        abort_reason : str or None, optional
            An :class:`~sih141.protocol.verify.AbortReason` member is accepted
            directly.
        hypotheses : iterable of str, optional
        timestamp : str or float or None, optional
            Passed through untouched; nothing here generates one.

        Returns
        -------
        SecurityEvent
            The event as stored, with its sequence number assigned.

        Raises
        ------
        ValueError
            If ``verdict`` is not one of the four outcomes.
        """
        event_verdict = RunOutcome(verdict)
        with self._lock:
            event = SecurityEvent(
                seq=self._recorded,
                session_id=None if session_id is None else str(session_id),
                party=str(party),
                verdict=event_verdict,
                abort_reason=(
                    None if abort_reason is None else str(abort_reason)
                ),
                key_length=int(key_length),
                check_fraction=float(check_fraction),
                hypotheses=tuple(str(name) for name in hypotheses),
                timestamp=timestamp,
            )
            self._recorded += 1
            self._events.append(event)
            if self._path is not None:
                # ponytail: reopened per event. One line every couple of
                # seconds at demo rates; hold the handle open if the rate ever
                # makes this the cost.
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event.to_dict()) + "\n")
        return event

    def events(self) -> tuple[SecurityEvent, ...]:
        """Return the retained events, oldest first.

        Returns
        -------
        tuple of SecurityEvent
            A snapshot. The caller cannot reach the live store through it, so
            the log stays append-only from the outside.
        """
        with self._lock:
            return tuple(self._events)

    def snapshot(self) -> tuple[tuple[SecurityEvent, ...], int, int]:
        """Return the retained events, the lifetime count and the drops.

        Returns
        -------
        tuple
            ``(events, recorded, dropped)``, all three taken under one lock, so
            they describe the log at a single instant. Reading the three
            properties separately does not: a run landing between two of them
            yields a document whose event list and counters came from different
            logs, and ``GET /api/events`` publishes them as one answer.
        """
        with self._lock:
            events = tuple(self._events)
            return events, self._recorded, self._recorded - len(events)

    def to_jsonl(self) -> str:
        """Return the retained events as JSON Lines.

        Returns
        -------
        str
            One JSON object per line, each line terminated. Empty string on an
            empty log, which is a valid JSON Lines document.
        """
        return "".join(
            json.dumps(event.to_dict()) + "\n" for event in self.events()
        )
