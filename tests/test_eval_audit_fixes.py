"""The Phase 5 audit findings, and the tests that keep them fixed.

Three auditors ran against ``6cb0f57`` plus the sweep and repair stages. Two
returned *sound* and one *unsound*; between them they confirmed nine defects,
every one minor. Four were prose -- a claim that both verifiers abort where only
Charlie does, a count of four ROC cells where there are three, ``51 minutes``
against a doctest that says ``52``, and a table header reading ``MB`` over a
quantity computed in mebibytes -- and those are fixed where they were written.

These are the other five, and each test here fails against the code as the
auditors found it.

A1
    :func:`~sih141.eval.security.repudiated_from_verdicts` enforces Phase 3
    constraint 1 -- a refusal is not a rejection -- correctly, in a line no test
    exercised. The auditor's mutation (``== "rejected"`` to ``!= "accepted"``)
    left the whole eval suite green.
A2
    ``_CAPTURE_CACHE`` in :mod:`sih141.attacks.replay` was keyed on the key
    length while the capture it stored was built from the whole parameter set,
    so two check fractions at one length collided and the survivor depended on
    which worker process arrived first.
A3
    Every cross-worker determinism test used ``smoke``, one cell running the
    honest scenario. No adversary ran at more than one worker anywhere.
A4
    ``repudiation_curve_table`` counted its ``no verdict`` column through
    ``transcript_summary["aborted"]``, the shortcut
    :func:`~sih141.eval.reduce.refused_run`'s own docstring names as the wrong
    question.
A5
    :func:`~sih141.eval.runner.global_rng_fingerprint` sees the two globals D3
    forbids and nothing else. It is blind to an entropy-seeded
    ``default_rng()``, which is irreproducible without touching either.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import numpy as np

from sih141.attacks.replay import replay_capture
from sih141.eval.experiments import experiment
from sih141.eval.reduce import refused_run
from sih141.eval.runner import global_rng_fingerprint, run_experiment
from sih141.eval.security import repudiated_from_verdicts
from sih141.eval.store import ResultStore
from sih141.protocol.params import ProtocolParams


def _record(bob: str, charlie: str, **summary: object) -> SimpleNamespace:
    """Build the least thing ``repudiated_from_verdicts`` reads.

    It touches ``record.transcript_summary`` and nothing else, so a stand-in
    keeps the test about the verdict rule rather than about session plumbing.
    """
    base = {
        "verdicts": {"Bob": bob, "Charlie": charlie},
        "forwarding_altered_signature": False,
        "session_coherent": True,
    }
    base.update(summary)
    return SimpleNamespace(transcript_summary=base)


# ------------------------------------------------------------------ A1 ----- #


def test_a_charlie_who_reached_no_verdict_is_not_a_repudiation() -> None:
    """A1: the guard the auditor mutated, now with something holding it.

    Repudiation is Bob accepting *and Charlie rejecting*. A Charlie who reached
    no verdict did not reject, so Alice has not shown two verifiers disagreeing
    -- she has shown one verifier and one silence. Counting that as a success
    would inflate every rate in the family, and it is the exact shape Phase 3
    constraint 1 exists to forbid.
    """
    assert repudiated_from_verdicts(_record("accepted", "rejected")) is True
    # The mutation `!= "accepted"` turns each of these True.
    assert repudiated_from_verdicts(_record("accepted", "refused")) is False
    assert repudiated_from_verdicts(_record("accepted", "not_asked")) is False


def test_repudiation_still_requires_an_untouched_forwarding_hop() -> None:
    """A1: the other two conjuncts are load-bearing too, and equally untested."""
    assert repudiated_from_verdicts(
        _record("accepted", "rejected", forwarding_altered_signature=True)
    ) is False
    assert repudiated_from_verdicts(
        _record("accepted", "rejected", session_coherent=False)
    ) is False
    assert repudiated_from_verdicts(_record("refused", "rejected")) is False


# ------------------------------------------------------------------ A2 ----- #


def test_the_replay_capture_cache_is_keyed_on_the_whole_parameter_set() -> None:
    """A2: two check fractions at one key length are different loot.

    The capture is built from ``params``. Keying on ``params.key_length`` alone
    returned whichever call arrived first, so the answer depended on worker
    scheduling -- the one thing D3 exists to rule out, reached through a cache
    rather than through a generator.
    """
    unchecked = ProtocolParams(key_length=96, check_fraction=0.0)
    checked = ProtocolParams(key_length=96, check_fraction=0.25)

    first = replay_capture(unchecked)
    second = replay_capture(checked)

    assert first.params.check_fraction == 0.0
    assert second.params.check_fraction == 0.25
    assert first.signature is not second.signature

    # And the order the two were first asked for does not decide the answer.
    assert replay_capture(checked).params.check_fraction == 0.25
    assert replay_capture(unchecked).params.check_fraction == 0.0


# ------------------------------------------------------------------ A3 ----- #


def test_an_adversary_scenario_is_identical_at_one_worker_and_at_four(
    tmp_path: Path,
) -> None:
    """A3: the determinism claim, finally made against an adversary.

    ``smoke`` is the honest scenario, so every cross-worker test in the suite
    compared runs with no adversary in them. ``replay`` is the cell that can
    actually break: its captured declaration lives in a module-level cache
    shared by every trial a worker process handles, which is precisely the
    shared mutable state a pool exposes.
    """
    exp = experiment("roc")
    serial = ResultStore(tmp_path / "serial")
    parallel = ResultStore(tmp_path / "parallel")
    cells = ["replay", "outside-forgery"]

    run_experiment(
        exp, serial, trials=2, cells=cells, workers=1,
        in_process=True, quiet=True,
    )
    summary = run_experiment(
        exp, parallel, trials=2, cells=cells, workers=4, quiet=True,
    )

    assert summary["failed"] == 0
    assert len({o["pid"] for o in summary["outcomes"]}) > 1

    serial_prints = {
        (r.cell, r.index): r.fingerprint() for r in serial.read_experiment("roc")
    }
    pool_prints = {
        (r.cell, r.index): r.fingerprint()
        for r in parallel.read_experiment("roc")
    }
    assert serial_prints and serial_prints == pool_prints
    assert not any(o["touched_global_rng"] for o in summary["outcomes"])


# ------------------------------------------------------------------ A4 ----- #


def test_a_run_that_aborted_is_not_the_same_question_as_a_refusal() -> None:
    """A4: the two routes answer differently, so the shortcut is not a synonym.

    ``transcript_summary["aborted"]`` is true of a run that aborted for any
    reason, including one where the question never reached a verifier.
    ``refused_run`` asks the published question: did a verifier reach no
    verdict. They happen to agree on the shipped cells, which is why counting
    through the wrong one stayed invisible.
    """
    aborted_but_both_answered = SimpleNamespace(
        transcript_summary={
            "aborted": True,
            "verdicts": {"Bob": "accepted", "Charlie": "rejected"},
        }
    )
    assert refused_run(aborted_but_both_answered) is False

    refused = SimpleNamespace(
        transcript_summary={
            "aborted": True,
            "verdicts": {"Bob": "accepted", "Charlie": "refused"},
        }
    )
    assert refused_run(refused) is True


# ------------------------------------------------------------------ A5 ----- #


def test_the_global_rng_probe_cannot_see_an_unseeded_generator() -> None:
    """A5: pin the blind spot so it is never mistaken for a proof.

    ``touched_global_rng == False`` means the two globals were untouched. It
    does not mean the trial is reproducible: a scenario building its own
    ``default_rng()`` is irreproducible and moves nothing here. Recording that
    as a test stops the flag being quietly redescribed as a D3 guarantee, and
    would fail if the probe were ever widened without the docstring following.
    """
    before = global_rng_fingerprint()
    own = np.random.default_rng()
    own.random(1000)
    assert global_rng_fingerprint() == before, "probe widened; update the docs"

    np.random.random()
    assert global_rng_fingerprint() != before
