"""What one trial leaves behind, and the wall between truth and evidence.

A full-scale transcript is 25.4 MiB unchecked and 37.2 MiB at
``check_fraction = 0.25`` (0.226 and 0.330 KiB per position at ``L = 115200``,
both measured), so a two-hundred-trial cell in full would be five to seven
gibibytes and a sweep across several cells would be tens. Mebibytes, because the
per-position figure is ``len(json) / 1024``; quoting one in binary units and the
other in decimal is how the pair came to read 26.7 and 37.2 for what is the same
measurement twice. The harness therefore stores a
**reduced record**: the detector's verdict, the handful of transcript fields the
tables need, the seeds, the parameters and the wall clock. Full transcripts are
retained only behind an explicit flag, for a named handful of worked examples.

.. _truth-wall:

Ground truth is not evidence
----------------------------
Phase 3 constraint 4: which link Eve touched, and which runs a selective starver
targeted, live on the **adversary's** log, and a detector may not read them.
:class:`GroundTruth` is the harness's label; :class:`Detection` is what the
detector concluded from the transcript alone. They sit in different fields of
:class:`TrialRecord` and are built at different times -- the detector has
already run and returned before the label is attached.

The property that matters is not "the label is in a different field" but "the
label could not have reached the detector", and there is an observation that
would differ if it had: run the same trial twice with two different labels and
compare the Detection byte for byte. ``tests/test_eval_harness.py`` does exactly
that. A test that merely checked the two fields exist would pass just as
happily if :func:`~sih141.detect.detector.detect` were reading the label.

Two labelling rules that a results table gets wrong if they are not carried on
the record itself:

* ``engaged`` is **measured off the adversary's own log**, not assumed from the
  cell. A channel attack aimed at Bob's link engages on no Charlie hop; a
  selective starver skips most runs. An untargeted run is byte-identical to an
  honest one, correctly, and must be scored as one -- so a cell that mounts an
  attack still produces ``engaged=False`` records, and a reduction that treats
  every record in an attack cell as an attacked run reports a detection rate
  against a denominator that includes runs where nothing happened.
* ``detectable`` is ``False`` for full impersonation, which is undetectable by
  construction under assumption (AUTH). It is a **label**, so the reduction can
  print ``undetectable-by-construction`` in that row rather than a blank, a dash
  or a zero. A hypothesis missing from a table reads as one that was ruled out;
  a zero reads as one we tried and failed to catch.

.. _fingerprint-exclusions:

What the fingerprint leaves out, and why
----------------------------------------
D9's corollary is that a trial's result depends on its seed and on nothing else.
Wall-clock timings depend on the machine, on thermal state and on how many
workers were competing, so they are in the record (Phase 5 needs a performance
section) but out of :meth:`TrialRecord.fingerprint`. The excluded set is exactly
:data:`NON_DETERMINISTIC_FIELDS` and is pinned by a test, so the exclusion
cannot quietly grow to cover a field that genuinely moved.

Examples
--------
>>> import numpy as np
>>> from sih141.detect.detector import detect
>>> from sih141.eval.records import GroundTruth, TrialRecord
>>> from sih141.eval.seeds import trial_seeds
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> seeds = trial_seeds("demo", "small", 0)
>>> params = ProtocolParams(key_length=96)
>>> transcript = QDSSession(params, rng=seeds.session_rng()).run(0)
>>> record = TrialRecord.build(
...     seeds=seeds,
...     params=params,
...     eps=1e-9,
...     transcript=transcript,
...     detection=detect(transcript.to_json(), eps=1e-9),
...     truth=GroundTruth(hypothesis="honest"),
...     wall_clock={"session_seconds": 0.4, "detect_seconds": 0.003},
... )
>>> record.truth.hypothesis, record.truth.engaged
('honest', False)
>>> record.detection["detected"]
False
>>> record.transcript_summary["count_exchange_timing"]
'before-forwarding'

The same trial timed differently is the same result:

>>> slower = TrialRecord.from_dict(
...     {**record.to_dict(),
...      "wall_clock": {"session_seconds": 91.0, "detect_seconds": 9.0}}
... )
>>> slower.fingerprint() == record.fingerprint()
True

...and a different verdict is not:

>>> flagged = TrialRecord.from_dict(
...     {**record.to_dict(),
...      "detection": {**record.detection, "detected": True}}
... )
>>> flagged.fingerprint() == record.fingerprint()
False
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Final, Mapping

from sih141.detect.detector import Detection
from sih141.protocol.params import ProtocolParams
from sih141.protocol.session import SessionTranscript

from .seeds import TrialSeeds, check_name

__all__ = [
    "GroundTruth",
    "link_summary",
    "NON_DETERMINISTIC_FIELDS",
    "RECORD_SCHEMA",
    "TrialRecord",
    "UNDETECTABLE_BY_CONSTRUCTION",
    "transcript_summary",
]

RECORD_SCHEMA: Final[str] = "sih141/eval/record/v1"
"""str: Written into every record so a reduction can refuse a stale one."""

UNDETECTABLE_BY_CONSTRUCTION: Final[str] = "undetectable-by-construction"
"""str: What a results table prints for a hypothesis assumption (AUTH) excludes.

Never a blank, a dash or a zero (Phase 3 constraint 5).
"""

NON_DETERMINISTIC_FIELDS: Final[frozenset[str]] = frozenset({"wall_clock"})
"""frozenset: Top-level record fields excluded from :meth:`TrialRecord.fingerprint`.

Exactly one, and it is timings. See :ref:`fingerprint-exclusions`. A test pins
this set, because an exclusion list is the natural place to hide a field that
did move between one worker and twenty.
"""


def _canonical_json(value: Any) -> str:
    """Serialise deterministically: sorted keys, no whitespace slack.

    Parameters
    ----------
    value : object
        Any JSON-serialisable value.

    Returns
    -------
    str
        Canonical JSON text.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class GroundTruth:
    """The harness's label for a trial. The detector never sees it.

    Parameters
    ----------
    hypothesis : str
        What the cell actually did: ``"honest"``, or a
        :class:`~sih141.detect.detector.Hypothesis` value such as
        ``"outside-forgery"``. Free text rather than an enum because Phase 5
        cells may label finer than the detector's hypothesis roster does.
    engaged : bool, optional
        Whether the adversary **acted on this run**, read off its own log
        rather than assumed from the cell. ``False`` for an honest cell and for
        an attack cell whose adversary skipped this trial.
    engaged_count : int or None, optional
        How many times it acted, where the adversary counts. ``None`` when the
        adversary has no such counter. Zero with ``engaged=True`` is a
        contradiction and is refused: an arm reporting no action must say so.
    targeted_link : str or None, optional
        Which link the adversary aimed at, or ``None`` for both/neither. Purely
        a label; per-link attribution is scored against it.
    detectable : bool, optional
        ``False`` only where an assumption rules detection out -- full
        impersonation under (AUTH). Drives the
        :data:`UNDETECTABLE_BY_CONSTRUCTION` cell in a results table.
    notes : str, optional
        Free text for the row's footnote.

    Raises
    ------
    TypeError
        If a field has the wrong type.
    ValueError
        If ``engaged`` is ``True`` with ``engaged_count == 0``, or
        ``engaged_count`` is negative.

    Examples
    --------
    >>> from sih141.eval.records import GroundTruth
    >>> GroundTruth(hypothesis="honest").engaged
    False
    >>> aimed = GroundTruth(
    ...     hypothesis="channel-manipulation",
    ...     engaged=True,
    ...     engaged_count=57,
    ...     targeted_link="Bob",
    ... )
    >>> aimed.targeted_link, aimed.detectable
    ('Bob', True)

    The contradiction a silently-inert arm would produce is refused rather than
    recorded, because Phase 4's replay arm reported a clean 0/40 while having
    forwarded honestly:

    >>> GroundTruth(hypothesis="replay", engaged=True, engaged_count=0)
    Traceback (most recent call last):
        ...
    ValueError: engaged=True with engaged_count=0...
    """

    hypothesis: str
    engaged: bool = False
    engaged_count: int | None = None
    targeted_link: str | None = None
    detectable: bool = True
    notes: str = ""

    def __post_init__(self) -> None:
        """Validate the label.

        Raises
        ------
        TypeError
            If a field has the wrong type.
        ValueError
            If the label is self-contradictory.
        """
        if not isinstance(self.hypothesis, str) or not self.hypothesis:
            raise TypeError("hypothesis must be a non-empty str")
        for name in ("engaged", "detectable"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        for name in ("targeted_link", "notes"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be a str or None")
        if not isinstance(self.notes, str):
            raise TypeError("notes must be a str")
        count = self.engaged_count
        if count is not None:
            if isinstance(count, bool) or not isinstance(count, int):
                raise TypeError("engaged_count must be an int or None")
            if count < 0:
                raise ValueError(f"engaged_count must be >= 0, got {count}")
            if self.engaged and count == 0:
                raise ValueError(
                    "engaged=True with engaged_count=0 is a contradiction. An "
                    "adversary that reports no action did not act, and a cell "
                    "labelling those runs as attacked publishes a detection "
                    "rate whose denominator counts runs where nothing "
                    "happened. Phase 4's replay arm reported a clean 0/40 "
                    "while having forwarded honestly throughout."
                )

    @property
    def attacked(self) -> bool:
        """bool: ``True`` only if an adversary acted on this run.

        The denominator a detection rate belongs over. An attack cell's
        untargeted trials are honest runs and are excluded by this.
        """
        return self.engaged

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "hypothesis": self.hypothesis,
            "engaged": self.engaged,
            "engaged_count": self.engaged_count,
            "targeted_link": self.targeted_link,
            "detectable": self.detectable,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GroundTruth:
        """Rebuild from :meth:`to_dict` output.

        Parameters
        ----------
        data : Mapping
            As produced by :meth:`to_dict`.

        Returns
        -------
        GroundTruth
        """
        return cls(
            hypothesis=data["hypothesis"],
            engaged=bool(data.get("engaged", False)),
            engaged_count=data.get("engaged_count"),
            targeted_link=data.get("targeted_link"),
            detectable=bool(data.get("detectable", True)),
            notes=data.get("notes", ""),
        )


def link_summary(stats: Any) -> dict[str, dict[str, Any]]:
    """Reduce the per-link check statistics, one entry per link, never pooled.

    Phase 3 constraint 3: **do not pool the two links' check logs.** Per-link
    QBER is the only statistic that both detects a party-targeted channel
    attack and attributes it, and an attack aimed at one link disappears into
    the average of two. So the key here is ``"<party>/<message bit>"`` and
    there is no total.

    Parameters
    ----------
    stats : TranscriptStatistics
        Layer one's extraction of a run.

    Returns
    -------
    dict
        Per link: ``rounds``, ``errors``, ``qber``, and the upper end of the
        QBER interval. Empty for a run with no check rounds -- an unmonitored
        link is not a clean one, and reporting a zero QBER for a link nobody
        measured would say the opposite.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.eval.records import link_summary
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> params = ProtocolParams(key_length=96, check_fraction=0.25)
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(params, rng=np.random.default_rng(11)).run(0)
    ... )
    >>> sorted(link_summary(stats))
    ['Bob/0', 'Bob/1', 'Charlie/0', 'Charlie/1']
    >>> link_summary(stats)["Bob/0"]["errors"]
    0

    With no check rounds there is nothing to report, and nothing is reported:

    >>> unmonitored = TranscriptStatistics.from_transcript(
    ...     QDSSession(ProtocolParams(key_length=96),
    ...                rng=np.random.default_rng(11)).run(0)
    ... )
    >>> link_summary(unmonitored)
    {}
    """
    summary: dict[str, dict[str, Any]] = {}
    for (party, message_bit), link in stats.links.items():
        estimate = link.qber
        summary[f"{party}/{message_bit}"] = {
            "rounds": int(link.errors.trials),
            "errors": int(link.errors.count),
            "qber": None if estimate is None else float(estimate.estimate),
            "qber_upper": (
                None if estimate is None else float(estimate.interval.high)
            ),
        }
    return summary


def transcript_summary(
    transcript: SessionTranscript, *, stats: Any = None
) -> dict[str, Any]:
    """Reduce a transcript to the fields the Phase 5 tables need.

    Everything here except the ``links`` block is a *transcript* fact read
    straight off the run, not a detector conclusion. The two are kept apart so
    that a reduction can cross-check one against the other: the outcome table is
    built from ``verdicts`` here, the detection table from
    :class:`~sih141.detect.detector.Detection`, and a test asserts the two agree
    on every record. A single shared field would make that cross-check vacuous.

    Parameters
    ----------
    transcript : SessionTranscript
        A finished run.
    stats : TranscriptStatistics or None, optional
        Keyword-only. Layer one's extraction of the same run, for the per-link
        block. Passing the one the detector was given avoids a second parse of
        the transcript's JSON, which is 25.4 MiB at ``L = 115200``; ``None``
        builds one, which is correct and slower.

    Returns
    -------
    dict
        JSON-clean. ``verdicts`` maps a party to ``"accepted"``,
        ``"rejected"`` or ``"refused"``; a party never asked is absent, which
        is a third thing again and is why the mapping is not a pair of counts.

    Raises
    ------
    TypeError
        If ``transcript`` is not a
        :class:`~sih141.protocol.session.SessionTranscript`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.eval.records import transcript_summary
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> params = ProtocolParams(key_length=96, check_fraction=0.25)
    >>> summary = transcript_summary(
    ...     QDSSession(params, rng=np.random.default_rng(11)).run(0)
    ... )
    >>> summary["verdicts"]
    {'Bob': 'accepted', 'Charlie': 'accepted'}
    >>> summary["aborted"], summary["is_complete"], summary["transferable"]
    (False, True, True)
    >>> sorted(summary["matched"])
    ['Bob', 'Charlie']
    >>> summary["links"]["Bob/0"]["rounds"] > 0
    True
    """
    if not isinstance(transcript, SessionTranscript):
        raise TypeError(
            f"transcript must be a SessionTranscript, got "
            f"{type(transcript).__name__}"
        )
    verdicts: dict[str, str] = {}
    matched: dict[str, int] = {}
    mismatches: dict[str, int] = {}
    thresholds: dict[str, float] = {}
    for party, result in transcript.results_by_party.items():
        verdicts[str(party)] = "accepted" if result.accepted else "rejected"
        matched[str(party)] = int(result.matched_count)
        mismatches[str(party)] = int(result.mismatches)
        thresholds[str(party)] = float(result.threshold)
    for party in transcript.aborts_by_party:
        verdicts[str(party)] = "refused"

    if stats is None:
        from sih141.detect.statistics import TranscriptStatistics

        stats = TranscriptStatistics.from_transcript(transcript)

    pooled = transcript.pooled_matched_count
    guarantee = transcript.repudiation_guarantee
    return {
        "run_id": transcript.run_id,
        "message_bit": int(transcript.message_bit),
        "count_exchange_timing": str(transcript.count_exchange_timing),
        "verdicts": verdicts,
        "matched": matched,
        "mismatches": mismatches,
        "thresholds": thresholds,
        "pooled_matched_count": None if pooled is None else int(pooled),
        "links": link_summary(stats),
        "aborts": {
            str(party): str(abort.reason)
            for party, abort in transcript.aborts_by_party.items()
        },
        "aborted": bool(transcript.aborted),
        "is_complete": bool(transcript.is_complete),
        "transferable": bool(transcript.transferable),
        "repudiated": bool(transcript.repudiated),
        "symmetrised": bool(transcript.symmetrised),
        "counts_exchanged": bool(transcript.counts_exchanged),
        "channel_monitored": bool(transcript.channel_monitored),
        "session_coherent": bool(transcript.session_coherent),
        "forwarding_altered_signature": bool(
            transcript.forwarding_altered_signature
        ),
        "repudiation_guarantee": None if guarantee is None else float(guarantee),
    }


@dataclass(frozen=True)
class TrialRecord:
    """One trial's reduced result: seed in, verdict out, label alongside.

    Attributes
    ----------
    schema : str
        :data:`RECORD_SCHEMA`.
    experiment, cell : str
        Identity, matching :data:`~sih141.eval.seeds.NAME_PATTERN`.
    index : int
        Trial index within the cell.
    seeds : dict
        As :meth:`~sih141.eval.seeds.TrialSeeds.to_dict`. Enough on its own to
        re-derive the run.
    params : dict
        As :meth:`~sih141.protocol.params.ProtocolParams.to_dict`.
    eps : float
        The detector budget this trial was scored at.
    truth : GroundTruth
        The harness's label. See :ref:`truth-wall`.
    detection : dict
        :meth:`~sih141.detect.detector.Detection.to_dict`, twenty-one keys,
        including ``channel_error_rate``, ``null_is_noiseless``, ``withheld``
        and ``grouping_key``.
    transcript_summary : dict
        As :func:`transcript_summary`.
    wall_clock : dict
        Seconds, by phase. **Excluded from** :meth:`fingerprint`; see
        :ref:`fingerprint-exclusions`.
    transcript_json : str or None
        The whole transcript, retained only when the cell asked for it.

    Examples
    --------
    See the module docstring for a built record; here is the round trip:

    >>> import numpy as np
    >>> from sih141.detect.detector import detect
    >>> from sih141.eval.records import GroundTruth, TrialRecord
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> seeds = trial_seeds("demo", "small", 1)
    >>> params = ProtocolParams(key_length=96)
    >>> transcript = QDSSession(params, rng=seeds.session_rng()).run(1)
    >>> record = TrialRecord.build(
    ...     seeds=seeds, params=params, eps=1e-6, transcript=transcript,
    ...     detection=detect(transcript.to_json(), eps=1e-6),
    ...     truth=GroundTruth(hypothesis="honest"),
    ...     wall_clock={"session_seconds": 0.5},
    ... )
    >>> TrialRecord.from_dict(record.to_dict()) == record
    True
    >>> record.identity
    ('demo', 'small', 1)
    """

    schema: str
    experiment: str
    cell: str
    index: int
    seeds: dict[str, Any]
    params: dict[str, Any]
    eps: float
    truth: GroundTruth
    detection: dict[str, Any]
    transcript_summary: dict[str, Any]
    wall_clock: dict[str, float] = field(default_factory=dict)
    transcript_json: str | None = None

    @classmethod
    def build(
        cls,
        *,
        seeds: TrialSeeds,
        params: ProtocolParams,
        eps: float,
        transcript: SessionTranscript,
        detection: Detection,
        truth: GroundTruth,
        wall_clock: Mapping[str, float] | None = None,
        retain_transcript: bool = False,
        stats: Any = None,
    ) -> TrialRecord:
        """Assemble a record from the pieces a trial produced.

        Parameters
        ----------
        seeds : TrialSeeds
            The trial's identity and both seeds.
        params : ProtocolParams
            The parameter set the run used.
        eps : float
            The budget the detector was called at.
        transcript : SessionTranscript
            The finished run.
        detection : Detection
            What the detector concluded. Must already have been computed --
            this method does not call :func:`~sih141.detect.detector.detect`,
            so there is no path by which ``truth`` could reach it.
        truth : GroundTruth
            The harness's label.
        wall_clock : Mapping or None, optional
            Keyword-only. Seconds by phase.
        retain_transcript : bool, optional
            Keyword-only. Keep the whole transcript. About 25.4 MiB at
            ``L = 115200``, so ``False`` by default and reserved for named
            worked examples.
        stats : TranscriptStatistics or None, optional
            Keyword-only. The extraction the detector was given, reused for
            the per-link block so the transcript is parsed once rather than
            twice.

        Returns
        -------
        TrialRecord

        Raises
        ------
        TypeError
            If an argument has the wrong type.
        """
        if not isinstance(seeds, TrialSeeds):
            raise TypeError(f"seeds must be TrialSeeds, got {type(seeds).__name__}")
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be ProtocolParams, got {type(params).__name__}"
            )
        if not isinstance(detection, Detection):
            raise TypeError(
                f"detection must be a Detection, got {type(detection).__name__}"
            )
        if not isinstance(truth, GroundTruth):
            raise TypeError(f"truth must be GroundTruth, got {type(truth).__name__}")
        return cls(
            schema=RECORD_SCHEMA,
            experiment=check_name(seeds.experiment, what="experiment"),
            cell=check_name(seeds.cell, what="cell"),
            index=seeds.index,
            seeds=seeds.to_dict(),
            params=params.to_dict(),
            eps=float(eps),
            truth=truth,
            detection=detection.to_dict(),
            transcript_summary=transcript_summary(transcript, stats=stats),
            wall_clock={str(k): float(v) for k, v in (wall_clock or {}).items()},
            transcript_json=transcript.to_json() if retain_transcript else None,
        )

    @property
    def identity(self) -> tuple[str, str, int]:
        """tuple: ``(experiment, cell, index)`` -- what the filename is built from."""
        return (self.experiment, self.cell, self.index)

    @property
    def count_exchange_timing(self) -> str:
        """str: The ordering this run used. A table column, never averaged over."""
        return str(self.transcript_summary["count_exchange_timing"])

    @property
    def flagged(self) -> bool:
        """bool: Whether any detector signal fired. Not a rejection."""
        return bool(self.detection["detected"])

    @property
    def null_is_noiseless(self) -> bool:
        """bool: Whether this trial was scored against a noiseless null.

        Phase 4 audit finding A3-1. A mismatch-rate detection under a noiseless
        null on a genuinely noisy link is arithmetically correct and still a
        false claim once the null goes unstated, so this rides on every row.
        """
        return bool(self.detection["null_is_noiseless"])

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            ``transcript_json`` is omitted entirely when it is ``None``, so a
            reduced record carries no dead key.
        """
        payload: dict[str, Any] = {
            "schema": self.schema,
            "experiment": self.experiment,
            "cell": self.cell,
            "index": self.index,
            "seeds": self.seeds,
            "params": self.params,
            "eps": self.eps,
            "truth": self.truth.to_dict(),
            "detection": self.detection,
            "transcript_summary": self.transcript_summary,
            "wall_clock": self.wall_clock,
        }
        if self.transcript_json is not None:
            payload["transcript_json"] = self.transcript_json
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TrialRecord:
        """Rebuild from :meth:`to_dict` output.

        Parameters
        ----------
        data : Mapping
            As produced by :meth:`to_dict`.

        Returns
        -------
        TrialRecord

        Raises
        ------
        ValueError
            If the record was written by a different schema version. A
            reduction across two schemas would silently mix two meanings of
            the same column.
        """
        schema = data.get("schema")
        if schema != RECORD_SCHEMA:
            raise ValueError(
                f"record schema {schema!r} is not {RECORD_SCHEMA!r}. Delete "
                f"the stale results or re-run the sweep; reducing across two "
                f"schemas mixes two meanings of the same column."
            )
        return cls(
            schema=str(schema),
            experiment=str(data["experiment"]),
            cell=str(data["cell"]),
            index=int(data["index"]),
            seeds=dict(data["seeds"]),
            params=dict(data["params"]),
            eps=float(data["eps"]),
            truth=GroundTruth.from_dict(data["truth"]),
            detection=dict(data["detection"]),
            transcript_summary=dict(data["transcript_summary"]),
            wall_clock={
                str(k): float(v) for k, v in dict(data.get("wall_clock", {})).items()
            },
            transcript_json=data.get("transcript_json"),
        )

    def deterministic_payload(self) -> dict[str, Any]:
        """Return the record with the non-deterministic fields removed.

        Returns
        -------
        dict
            :meth:`to_dict` minus :data:`NON_DETERMINISTIC_FIELDS`.
        """
        return {
            key: value
            for key, value in self.to_dict().items()
            if key not in NON_DETERMINISTIC_FIELDS
        }

    def fingerprint(self) -> str:
        """Return a SHA-256 over everything that must not depend on scheduling.

        Returns
        -------
        str
            Sixty-four lowercase hex characters.

        Notes
        -----
        This is the claim D9 rests on, in one value: two runs of the same seed
        set must produce the same fingerprint at one worker and at twenty, in
        any completion order. ``tests/test_eval_harness.py`` runs both and
        compares.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.detect.detector import detect
        >>> from sih141.eval.records import GroundTruth, TrialRecord
        >>> from sih141.eval.seeds import trial_seeds
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> def make(seconds):
        ...     seeds = trial_seeds("demo", "small", 2)
        ...     params = ProtocolParams(key_length=48)
        ...     run = QDSSession(params, rng=seeds.session_rng()).run(0)
        ...     return TrialRecord.build(
        ...         seeds=seeds, params=params, eps=1e-9, transcript=run,
        ...         detection=detect(run.to_json(), eps=1e-9),
        ...         truth=GroundTruth(hypothesis="honest"),
        ...         wall_clock={"session_seconds": seconds},
        ...     )
        >>> make(0.1).fingerprint() == make(99.0).fingerprint()
        True
        >>> len(make(0.1).fingerprint())
        64
        """
        text = _canonical_json(self.deterministic_payload())
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
