"""The ``run`` and ``ground_truth`` objects, in the shape the screen reads.

.. _one-producer:

Why these live here and not in the tool that first wrote them
--------------------------------------------------------------
The dashboard's two halves were built in parallel. The frontend could not wait
for a server, so it was developed against **recorded** responses produced by
``tools/phase6_fixtures.py``, and that script's ``run_facts`` and
``ground_truth_for`` became the read-side contract: the names the page renders,
stated in ``sih141/web/static/data/api-contract.json`` and pinned by the
frontend's own tests. Its module docstring says as much, and asks the service
half to import or copy them rather than write a second set.

So they are here, in the shipped package, and the direction of the dependency is
the one that survives packaging: ``sih141.web`` owns the producers, and the
recording tool should import *these*. Two consequences worth stating.

**A second implementation would drift, and the drift would be invisible.** The
page degrades a panel to "the API did not supply <field>" rather than inventing
a number, which is the right failure -- but a demo full of grey panels is a
demo. One producer, exercised by both the live endpoint and the recorded
fixtures, cannot drift.

**These are covered now.** ``tools/`` is outside ``testpaths``, so nothing in
that script is collected by ``--doctest-modules``; everything in this module is.

.. _no-derived-quantity-here:

This module derives nothing
---------------------------
Every field below is a straight read off
:class:`~sih141.detect.statistics.TranscriptStatistics`,
:class:`~sih141.detect.detector.Detection` or the transcript's own JSON. There
is no arithmetic here beyond ``int()`` and ``float()``, and that is deliberate
in two places in particular:

*The published mismatch rate is read, not recomputed.* The transcript already
carries the number each verifier compared against its threshold. Dividing two
counts again would put a second, untested arithmetic path in front of the same
figure, and the two would disagree the first time one of them was wrong.

*Degeneracy is the package's own answer.*
``floors["degenerate"]`` is ``not stats.security_claim`` -- not a comparison
invented on the way past. A second rule about when a floor stops meaning
anything would be a threshold nobody wrote down (**D7**).

Absent is not zero
------------------
``None`` and ``[]`` appear throughout and they are load-bearing. A verifier who
reached no verdict has no rate; a run with no check rounds has no links; a run
that reached no pair of verdicts has no pooled count. Each of those is rendered
as *absent*, and a zero in its place would read as a measurement that came out
at zero -- a clean channel, a perfect verifier, an empty evidence base -- which
is the opposite of what happened.

Examples
--------
>>> import json
>>> import numpy as np
>>> from sih141.detect import TranscriptStatistics, detect
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> from sih141.web.payload import run_facts
>>> transcript = QDSSession(
...     ProtocolParams(key_length=96, check_fraction=0.25),
...     rng=np.random.default_rng(7),
... ).run(0)
>>> text = transcript.to_json()
>>> stats = TranscriptStatistics.from_json(text)
>>> facts = run_facts(
...     stats, detect(text, eps=1e-9), json.loads(text),
...     requested_key_length=96, check_fraction=0.25,
... )
>>> facts["nominal_key_length"], facts["sifted_key_length"]
(96, 72)
>>> [row["outcome"] for row in facts["verifiers"]]
['accepted', 'accepted']
>>> facts["channel_evaluable"], len(facts["links"])
(True, 4)

An unmonitored run publishes no links at all, and says so rather than drawing a
flat healthy line at zero:

>>> quiet = QDSSession(
...     ProtocolParams(key_length=96), rng=np.random.default_rng(7)
... ).run(0)
>>> text = quiet.to_json()
>>> bare = run_facts(
...     TranscriptStatistics.from_json(text), detect(text, eps=1e-9),
...     json.loads(text), requested_key_length=96, check_fraction=0.0,
... )
>>> bare["links"], bare["channel_evaluable"]
([], False)
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from sih141.detect.statistics import TranscriptStatistics


__all__ = ["ground_truth_for", "run_facts"]


def _interval(interval: Any) -> dict[str, Any] | None:
    """Return one confidence interval as JSON, or ``None``.

    Parameters
    ----------
    interval : Interval or None

    Returns
    -------
    dict or None
    """
    if interval is None:
        return None
    return {
        "low": float(interval.low),
        "high": float(interval.high),
        "confidence": float(interval.confidence),
        "method": str(interval.method),
    }


def _count(statistic: Any) -> dict[str, Any]:
    """Return one :class:`~sih141.detect.statistics.CountStatistic` as JSON.

    The null travels with the count, because a count without the law it is
    read against is not a statistic, it is a number.

    Parameters
    ----------
    statistic : CountStatistic

    Returns
    -------
    dict
    """
    return {
        "name": str(statistic.name),
        "count": int(statistic.count),
        "trials": int(statistic.trials),
        "null_probability": float(statistic.null_probability),
        "null": str(statistic.null),
    }


def _optional_count(statistic: Any) -> int | None:
    """Return one count, or ``None`` where the statistic does not exist.

    Parameters
    ----------
    statistic : CountStatistic or None

    Returns
    -------
    int or None
    """
    return None if statistic is None else int(statistic.count)


def _published_rate(
    results: Mapping[str, Mapping[str, Any]], party: str
) -> float | None:
    """Return the mismatch rate the transcript published for one verifier.

    Read rather than recomputed (:ref:`no-derived-quantity-here`).

    Parameters
    ----------
    results : mapping
        The transcript's own ``results`` entries, keyed by party.
    party : str

    Returns
    -------
    float or None
        ``None`` where the verifier reached no verdict. That is not a rate of
        zero and must not be drawn as one: a verifier who was denied his
        evidence did not observe perfect agreement, he observed nothing.
    """
    entry = results.get(str(party))
    if entry is None or entry.get("rate") is None:
        return None
    return float(entry["rate"])


def _link_facts(link: Any) -> dict[str, Any]:
    """Return one link's published check-round statistics as JSON.

    Parameters
    ----------
    link : LinkStatistics

    Returns
    -------
    dict
        ``qber`` and ``chsh`` are ``None`` where the link published no rounds
        of that kind, never zero: "no Bell test here" and "a Bell test that
        came out at zero" are different facts, and a screen that drew them the
        same way would report an unmeasured link as a broken one -- or, worse,
        a broken one as fine.
    """
    qber = None
    if link.qber is not None:
        qber = {
            "errors": int(link.qber.errors),
            "rounds": int(link.qber.rounds),
            "value": float(link.qber.estimate),
            "interval": _interval(link.qber.interval),
            "bound": _interval(link.qber_bound),
        }
    chsh = None
    if link.chsh is not None:
        chsh = {
            "value": float(link.chsh.statistic),
            "correlators": [float(item) for item in link.chsh.correlators],
            "counts": [int(item) for item in link.chsh.counts],
            "rounds": int(link.chsh.rounds),
            "interval": _interval(link.chsh.interval),
            "bound": _interval(link.chsh_bound),
            "violates_classical_bound": bool(
                link.chsh.violates_classical_bound
            ),
            "consistent_with_ideal": bool(link.chsh.consistent_with_ideal),
        }
    resource = link.resource
    return {
        "party": str(link.party),
        "message_bit": int(link.message_bit),
        "errors": _count(link.errors),
        "qber": qber,
        "chsh": chsh,
        "chsh_unavailable": (
            None
            if link.chsh_unavailable is None
            else str(link.chsh_unavailable)
        ),
        "resource": {
            "samples": int(resource.samples),
            "qber_samples": int(resource.qber_samples),
            "chsh_samples": int(resource.chsh_samples),
            "mean_fidelity": float(resource.mean_fidelity),
            "min_fidelity": float(resource.min_fidelity),
            "mean_purity": float(resource.mean_purity),
            "min_purity": float(resource.min_purity),
            "mean_concurrence": float(resource.mean_concurrence),
            "min_concurrence": float(resource.min_concurrence),
        },
    }


def _verifier_facts(
    stats: TranscriptStatistics,
    outcomes: Mapping[str, Any],
    results: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return one row per verifier, the four-valued outcome included.

    Parameters
    ----------
    stats : TranscriptStatistics
    outcomes : mapping
        :attr:`~sih141.detect.detector.Detection.outcomes`, party to outcome.
        Four-valued, and that is the point: ``accepted``, ``rejected``,
        ``refused-to-score`` and ``not-asked`` are four different things and a
        boolean can hold two of them.
    results : mapping
        The transcript's own ``results`` entries, for the published rate.

    Returns
    -------
    list of dict

    Notes
    -----
    The rows are built over the **union** of the parties in ``stats.verifiers``
    and in ``outcomes``, not over ``stats.verifiers`` alone. A verifier who
    reached no verdict has no
    :class:`~sih141.detect.statistics.VerifierStatistics` at all and would
    simply vanish from a table built from that mapping -- and a party missing
    from a table reads as a party who was never involved, which is precisely
    the confusion between a denial and a rejection that this dashboard must
    not create.
    """
    parties = sorted(
        {str(party) for party in stats.verifiers}
        | {str(party) for party in outcomes}
    )
    rows: list[dict[str, Any]] = []
    for party in parties:
        verifier = stats.verifiers.get(party)
        outcome = outcomes.get(str(party))
        label = None if outcome is None else str(getattr(outcome, "value", outcome))
        if verifier is None:
            rows.append(
                {
                    "party": str(party),
                    "outcome": label,
                    "accepted": None,
                    "matched": None,
                    "matched_trials": None,
                    "matched_null_probability": None,
                    "mismatches": None,
                    "mismatch_trials": None,
                    "rate": None,
                    "threshold": None,
                    "margin": None,
                    "reported_matched": None,
                    "reported_mismatches": None,
                    "consistent": None,
                    "recomputed": False,
                    "scored": False,
                }
            )
            continue
        rows.append(
            {
                "party": str(party),
                "outcome": label,
                "accepted": (
                    None
                    if verifier.accepted is None
                    else bool(verifier.accepted)
                ),
                "matched": int(verifier.matched.count),
                "matched_trials": int(verifier.matched.trials),
                "matched_null_probability": float(
                    verifier.matched.null_probability
                ),
                "mismatches": int(verifier.mismatch.count),
                "mismatch_trials": int(verifier.mismatch.trials),
                "rate": _published_rate(results, party),
                "threshold": (
                    None
                    if verifier.threshold is None
                    else float(verifier.threshold)
                ),
                "margin": (
                    None if verifier.margin is None else float(verifier.margin)
                ),
                "reported_matched": (
                    None
                    if verifier.reported_matched is None
                    else int(verifier.reported_matched)
                ),
                "reported_mismatches": (
                    None
                    if verifier.reported_mismatches is None
                    else int(verifier.reported_mismatches)
                ),
                "consistent": bool(verifier.consistent),
                "recomputed": bool(verifier.recomputed),
                "scored": True,
            }
        )
    return rows


def run_facts(
    stats: TranscriptStatistics,
    detection: Any,
    transcript_json: Mapping[str, Any],
    *,
    requested_key_length: int,
    check_fraction: float,
) -> dict[str, Any]:
    """Return the ``run`` half of a ``POST /api/run`` response.

    Everything the screen needs about the run itself, as distinct from the
    verdict on it: :meth:`~sih141.detect.detector.Detection.to_dict` carries
    the verdict and the bound and nothing about the run that produced them --
    no per-link QBER, no matched count, no floor, no repudiation guarantee.

    Parameters
    ----------
    stats : TranscriptStatistics
        Built from the transcript's JSON, exactly as
        :func:`~sih141.detect.detect` builds it. The same object the detector
        read, so the panel and the verdict cannot disagree.
    detection : Detection or dict
        Read **only** for the four-valued outcomes. Either the object or its
        ``to_dict()``.
    transcript_json : mapping
        ``json.loads(transcript.to_json())``. Read for the published mismatch
        rates only; every other field comes off ``stats``.
    requested_key_length : int
        Keyword-only. What the caller asked for, *before* sifting. Carried
        beside the sifted length so a screen can say which is which: every null
        in the detector is stated over the sifted one, and a panel that showed
        ``L`` where the null says ``signing_length`` would be claiming evidence
        the run does not have.
    check_fraction : float
        Keyword-only. What the caller asked for.

    Returns
    -------
    dict

    Examples
    --------
    See the module docstring, which builds one of these end to end.
    """
    outcomes = (
        detection["outcomes"]
        if isinstance(detection, Mapping)
        else detection.outcomes
    )
    pooled = stats.pooled
    links = [
        _link_facts(stats.links[key]) for key in sorted(stats.links.keys())
    ]
    results = {
        str(entry["party"]): entry
        for entry in transcript_json.get("results", [])
    }
    return {
        "requested_key_length": int(requested_key_length),
        "nominal_key_length": int(stats.nominal_key_length),
        "sifted_key_length": int(stats.params.key_length),
        "check_fraction": float(check_fraction),
        "message_bit": int(stats.message_bit),
        "s_a": float(stats.params.s_a),
        "s_v": float(stats.params.s_v),
        # -- what the run did and did not do -------------------------------- #
        "check_rounds_present": bool(stats.has_check_rounds),
        "channel_monitored": bool(stats.channel_monitored),
        "channel_evaluable": bool(stats.has_check_rounds and bool(links)),
        "counts_exchanged": bool(stats.counts_exchanged),
        "count_exchange_timing": str(stats.count_exchange_timing),
        "symmetrised": bool(stats.symmetrised),
        "session_coherent": bool(stats.session_coherent),
        "is_complete": bool(stats.is_complete),
        "aborted": bool(stats.aborted),
        "forwarding_altered_signature": bool(
            stats.forwarding_altered_signature
        ),
        "signer_saw_recipient_logs": bool(stats.signer_saw_recipient_logs),
        # -- the transferability question ----------------------------------- #
        "security_claim": bool(stats.security_claim),
        "transferable": bool(stats.transferable),
        "repudiated": bool(stats.repudiated),
        "repudiation_guarantee": (
            None
            if stats.repudiation_guarantee is None
            else float(stats.repudiation_guarantee)
        ),
        "enforced_repudiation_bound": (
            None
            if stats.enforced_repudiation_bound is None
            else float(stats.enforced_repudiation_bound)
        ),
        # -- the floors ------------------------------------------------------ #
        "floors": {
            "matched_minimum": int(pooled.minimum_matched),
            "pooled_minimum": int(pooled.minimum_pooled),
            "matched_floor_bound": float(pooled.matched_floor_bound),
            "meets_pooled_floor": bool(pooled.meets_pooled_floor),
            "meets_every_floor": bool(pooled.meets_every_floor),
            "degenerate": not bool(stats.security_claim),
        },
        "verifiers": _verifier_facts(stats, outcomes, results),
        "pooled": {
            "count": (
                None if pooled.pooled is None else int(pooled.pooled.count)
            ),
            "trials": (
                None if pooled.pooled is None else int(pooled.pooled.trials)
            ),
            "null_probability": (
                None
                if pooled.pooled is None
                else float(pooled.pooled.null_probability)
            ),
            "declared_bob": _optional_count(pooled.declared_bob),
            "declared_charlie": _optional_count(pooled.declared_charlie),
            "declared_pooled": _optional_count(pooled.declared_pooled),
            "declaration_digest_present": bool(
                pooled.declaration_digest_present
            ),
        },
        # EMPTY on an unmonitored run, never zero-filled: an unmonitored link
        # is not a clean one.
        "links": links,
        "replay": {
            "total_refusals": int(stats.replay.total_refusals),
            "refusals_by_party": {
                str(party): int(count)
                for party, count in stats.replay.refusals_by_party.items()
            },
            "spent_rounds": int(stats.replay.spent_rounds),
            "distinct_sessions": int(stats.replay.distinct_sessions),
        },
        "aborts": {
            "total": int(stats.aborts.total),
            "structural": int(stats.aborts.structural),
            "evidence": int(stats.aborts.evidence),
            "by_reason": {
                str(reason): int(count)
                for reason, count in stats.aborts.by_reason.items()
            },
            # party -> the REASON, not a count: one verifier aborts at most
            # once per run and the reason is what the screen has to name.
            "by_party": {
                str(party): str(reason)
                for party, reason in stats.aborts.by_party.items()
            },
            "shortfalls": {
                str(party): int(amount)
                for party, amount in stats.aborts.shortfalls.items()
            },
            "honest_bound": float(stats.aborts.honest_bound),
        },
        # The transcript's own words, carried so that a run's panel can say
        # what the run does and does not establish -- including the per-run
        # repudiation bound, which at demo lengths is order one.
        "summary": str(stats.summary()),
    }


def ground_truth_for(
    key: str,
    label: str,
    detectable: str,
    assumption: str | None,
    *,
    acted: bool,
    targeted_links: Sequence[Sequence[Any]] | None = None,
    seams_held: Sequence[str] = (),
    notes: str = "",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the ``ground_truth`` half of a ``POST /api/run`` response.

    **The harness's own knowledge, in its own object.** Which link Eve touched
    and which runs a selective starver targeted live on the adversary's log;
    :func:`~sih141.detect.detect` reads a JSON transcript and nothing else, and
    the only way to be sure of that is to keep these facts out of the object
    the detector produced. Keeping them here lets the screen show "what
    actually happened" beside "what the detector could tell" with no chance of
    one leaking into the other.

    Parameters
    ----------
    key : str
        The attack key from ``GET /api/attacks``. These deliberately match the
        detector's own :class:`~sih141.detect.detector.Hypothesis` names where
        one exists, so a reader can compare ``ground_truth["attack"]`` with
        ``detection["named"]`` directly.
    label : str
        The arm's human name.
    detectable : str
        The arm's detectability verdict, carried here as well as on the roster
        so a rendered result is self-describing.
    assumption : str or None
        The assumption that excludes the adversary where detection cannot.
    acted : bool
        Keyword-only. Whether the adversary actually did anything on this run.
        An adversary that was mounted and declined -- an untargeted channel
        attack, a twirl at strength zero, a selective starver on a run it let
        through -- leaves a transcript **identical to an honest one**, and the
        screen says that in those words rather than showing a miss.
    targeted_links : sequence, optional
        Keyword-only. ``[party, message_bit]`` pairs the adversary acted on.
    seams_held : sequence of str, optional
        Keyword-only. Which :class:`~sih141.protocol.session.QDSSession` seams
        the adversary was mounted on.
    notes : str, optional
        Keyword-only. What happened, in words the screen can render.
    extra : mapping, optional
        Keyword-only. Per-arm additions -- the replay count, the starver's
        declarations, the link's true error rate. Merged in at the top level.

    Returns
    -------
    dict

    Examples
    --------
    >>> from sih141.web.payload import ground_truth_for
    >>> truth = ground_truth_for(
    ...     "channel-manipulation", "Channel manipulation", "detectable", None,
    ...     acted=False, seams_held=("resource_factory",),
    ... )
    >>> truth["adversary_present"], truth["acted"]
    (True, False)
    >>> truth["identical_to_honest"]
    True

    The honest control is never "identical to honest" in that sense, because
    there was no adversary to decline:

    >>> ground_truth_for(
    ...     "honest", "Honest run", "not-an-attack", None, acted=False
    ... )["identical_to_honest"]
    False
    """
    truth = {
        "attack": str(key),
        "label": str(label),
        "adversary_present": key != "honest",
        "acted": bool(acted),
        "identical_to_honest": key != "honest" and not acted,
        "targeted_links": [list(pair) for pair in (targeted_links or [])],
        "seams_held": list(seams_held),
        "detectable": str(detectable),
        "assumption": assumption,
        "notes": str(notes),
    }
    if extra:
        truth.update(extra)
    return truth
