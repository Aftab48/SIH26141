"""Tests for the Phase 5 evaluation harness.

Every test here is written against one question: **what observation would differ
if the property were false?** Phase 6 shipped four defects behind four passing
tests, and the shape was identical in all four -- the test asserted that a string
was present in a file. That is the right check for "has someone deleted this"
and no check at all for "does this do anything".

So the determinism suite runs the sweep twice, in two process topologies, and
compares the results byte for byte; it does not check that a seed function
exists. The ground-truth wall is tested by feeding the detector two runs that
differ only in their label and asserting its verdict does not move; not by
checking the label lives in a different field. And every table is recomputed by
a second route -- exact arithmetic, or a different field of the record written
by different code -- and the two are asserted equal.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest

from sih141.attacks.isolation import same_stream
from sih141.detect.detector import detect
from sih141.detect.statistics import TranscriptStatistics
from sih141.detect.thresholds_structural import NoVerdictCount, tally_outcomes
from sih141.eval import perf
from sih141.eval.experiments import (
    EXPERIMENTS,
    SCENARIOS,
    Cell,
    Experiment,
    all_cells,
    experiment,
    run_trial,
)
from sih141.eval.manifest import MANIFEST_SCHEMA, RunManifest, seed_derivation
from sih141.eval.records import (
    NON_DETERMINISTIC_FIELDS,
    RECORD_SCHEMA,
    UNDETECTABLE_BY_CONSTRUCTION,
    GroundTruth,
    TrialRecord,
    transcript_summary,
)
from sih141.eval.reduce import (
    CONFIDENCE,
    NOT_EVALUATED,
    Table,
    detection_table,
    group_records,
    outcome_table,
    reduce_experiment,
    tally_from_record,
    timing_table,
)
from sih141.eval.runner import (
    BLAS_ENV_VARS,
    global_rng_fingerprint,
    pin_blas_threads,
    plan_trials,
    probe_pool,
    run_experiment,
)
from sih141.eval.seeds import (
    ADVERSARY_ROLE,
    SEED_DOMAIN,
    SESSION_ROLE,
    TrialSeeds,
    check_name,
    trial_seed,
    trial_seeds,
)
from sih141.eval.store import DEFAULT_RESULTS_ROOT, ResultStore
from sih141.protocol.params import ProtocolParams
from sih141.protocol.session import QDSSession

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# 1. The seed derivation                                                       #
# --------------------------------------------------------------------------- #


def test_seed_is_a_pure_function_of_identity_recomputed_by_hand() -> None:
    """The seed matches an independent implementation of the written rule.

    Not "trial_seed returns an int" -- that would pass on any function. The
    rule in the module docstring is re-implemented here from the prose, and the
    two must agree. If someone changes the derivation without changing the
    documentation, this fails.
    """
    material = b"\x00".join(
        (SEED_DOMAIN, b"honest", b"l192", b"session", b"7")
    )
    expected = int.from_bytes(
        hashlib.blake2b(material, digest_size=8, person=b"sih141-eval").digest(),
        "big",
    )
    assert trial_seed("honest", "l192", 7) == expected


def test_seed_does_not_depend_on_the_process() -> None:
    """A seed computed in a fresh interpreter equals one computed here.

    Python's ``hash`` is randomised per process by PYTHONHASHSEED, so a
    derivation built on it would differ between the parent and a spawned
    worker. This runs a genuinely separate interpreter with a hash seed the
    parent does not have and compares.
    """
    env = dict(os.environ, PYTHONHASHSEED="12345")
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]);"
            "from sih141.eval.seeds import trial_seed;"
            "print(trial_seed('honest', 'l192', 7))",
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=True,
    )
    assert int(done.stdout.strip()) == trial_seed("honest", "l192", 7)


def test_every_identity_component_moves_the_seed() -> None:
    """Changing any one of the four inputs changes the seed."""
    base = trial_seed("honest", "l192", 3)
    assert trial_seed("noise", "l192", 3) != base
    assert trial_seed("honest", "l384", 3) != base
    assert trial_seed("honest", "l192", 4) != base
    assert trial_seed("honest", "l192", 3, role=ADVERSARY_ROLE) != base


def test_separator_prevents_the_concatenation_collision() -> None:
    """``("ab", "c")`` and ``("a", "bc")`` are different trials.

    Without the NUL separator both would hash the same bytes, and two cells
    would silently share a seed stream.
    """
    assert trial_seed("ab", "c", 0) != trial_seed("a", "bc", 0)


def test_session_and_adversary_streams_are_genuinely_distinct() -> None:
    """The two roles give generators that produce different draws (D6).

    Compared through :func:`~sih141.attacks.isolation.same_stream`, which looks
    at realised draws rather than at seeds, so a derivation that happened to
    produce the same generator twice would be caught.
    """
    pair = trial_seeds("honest", "l192", 0)
    assert not same_stream(pair.session_rng(), pair.adversary_rng())
    assert same_stream(pair.session_rng(), pair.session_rng())


def test_seed_names_are_validated() -> None:
    """Illegal names are refused, because they would escape the results root."""
    for bad in ("Upper", "two words", "../escape", "with/slash", "", "a" * 65):
        with pytest.raises((TypeError, ValueError)):
            check_name(bad)
    with pytest.raises(TypeError):
        check_name(7)


def test_seed_index_is_validated() -> None:
    """A negative or non-integer index is refused rather than hashed."""
    with pytest.raises(ValueError):
        trial_seed("honest", "l192", -1)
    with pytest.raises(TypeError):
        trial_seed("honest", "l192", 1.0)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        trial_seed("honest", "l192", True)


def test_seed_derivation_record_matches_the_code() -> None:
    """The manifest's description of the rule is the rule the code uses."""
    derivation = seed_derivation()
    assert derivation["domain"] == SEED_DOMAIN.decode("ascii")
    assert derivation["roles"] == [SESSION_ROLE, ADVERSARY_ROLE]
    assert derivation["digest_size_bytes"] == 8
    assert derivation["hash"] == "blake2b"


# --------------------------------------------------------------------------- #
# 2. Determinism, proven rather than asserted                                  #
# --------------------------------------------------------------------------- #


def _fingerprints(store: ResultStore, name: str) -> dict[tuple[str, int], str]:
    """Return every record's fingerprint, keyed by identity.

    Parameters
    ----------
    store : ResultStore
        Where the results are.
    name : str
        Experiment name.

    Returns
    -------
    dict
    """
    return {
        (record.cell, record.index): record.fingerprint()
        for record in store.read_experiment(name)
    }


def test_one_worker_and_many_workers_give_byte_identical_results(
    tmp_path: Path,
) -> None:
    """The claim D9 rests on: the same seeds give the same results at any width.

    Two whole sweeps into two directories, one in this process and one across a
    pool of four, compared by fingerprint -- a SHA-256 over the canonical JSON
    of everything except the timings. If the runner leaked scheduling into a
    result, these would differ.
    """
    exp = experiment("smoke")
    serial = ResultStore(tmp_path / "serial")
    parallel = ResultStore(tmp_path / "parallel")

    run_experiment(exp, serial, trials=4, workers=1, in_process=True, quiet=True)
    summary = run_experiment(exp, parallel, trials=4, workers=4, quiet=True)

    assert summary["ran"] == 4
    assert summary["failed"] == 0
    assert _fingerprints(serial, "smoke") == _fingerprints(parallel, "smoke")

    # And more than one process really was involved, so the comparison means
    # something. A pool that silently ran everything in one worker would give
    # identical results too, and prove nothing.
    assert len({o["pid"] for o in summary["outcomes"]}) > 1


def test_results_do_not_depend_on_completion_order(tmp_path: Path) -> None:
    """A trial run alone equals the same trial run inside a batch.

    Completion order is the thing a parallel sweep cannot control. Here trial 2
    is produced twice: once as the only trial in its directory, once as the
    third of four. Same fingerprint or the runner is carrying state between
    trials.
    """
    exp = experiment("smoke")
    alone = ResultStore(tmp_path / "alone")
    together = ResultStore(tmp_path / "together")

    # Fill 0, 1 and 3 first so that 2 is not the first trial the batch touches.
    for index in (0, 1, 3):
        together.write(run_trial(exp, "tiny", index))
    run_experiment(exp, together, trials=4, workers=1, in_process=True, quiet=True)
    alone.write(run_trial(exp, "tiny", 2))

    assert (
        alone.read("smoke", "tiny", 2).fingerprint()
        == together.read("smoke", "tiny", 2).fingerprint()
    )


def test_reduced_tables_are_identical_across_worker_counts(tmp_path: Path) -> None:
    """The tables, not just the records, come out the same at 1 and 4 workers.

    The records could match while a reduction sorted by directory order and
    produced two different tables. This compares the rendered markdown.
    """
    exp = experiment("smoke")
    serial = ResultStore(tmp_path / "serial")
    parallel = ResultStore(tmp_path / "parallel")
    run_experiment(exp, serial, trials=4, workers=1, in_process=True, quiet=True)
    run_experiment(exp, parallel, trials=4, workers=4, quiet=True)

    def rendered(store: ResultStore) -> str:
        records = list(store.read_experiment("smoke"))
        return "\n".join(
            table.to_markdown()
            for table in (outcome_table(records), detection_table(records))
        )

    assert rendered(serial) == rendered(parallel)


def test_no_trial_touches_a_global_random_state(tmp_path: Path) -> None:
    """D3, measured: the two global RNG states are unmoved by a whole sweep.

    ``numpy.random`` and stdlib ``random`` are snapshotted around the sweep and
    compared. A single ``np.random.random()`` anywhere under ``run_trial``
    would move one of them. The workers check the same thing inside their own
    processes and report it on every outcome.
    """
    before_np = np.random.get_state()
    before_py = random.getstate()
    before_digest = global_rng_fingerprint()

    summary = run_experiment(
        experiment("smoke"),
        ResultStore(tmp_path),
        trials=3,
        workers=2,
        quiet=True,
    )

    assert global_rng_fingerprint() == before_digest
    assert np.random.get_state()[0] == before_np[0]
    assert np.array_equal(np.random.get_state()[1], before_np[1])
    assert random.getstate() == before_py
    assert summary["global_rng_touched"] == []
    assert all(not o["touched_global_rng"] for o in summary["outcomes"])


def test_the_global_rng_probe_can_actually_fail() -> None:
    """The D3 probe is not decorative: moving the state moves the digest.

    A check that always returns "clean" would pass the test above forever. This
    draws from both globals and asserts the fingerprint notices.
    """
    before = global_rng_fingerprint()
    np.random.random()
    assert global_rng_fingerprint() != before
    middle = global_rng_fingerprint()
    random.random()
    assert global_rng_fingerprint() != middle


def test_every_scenario_is_reproducible_from_its_seeds() -> None:
    """Each registered scenario, run twice on one seed pair, gives one answer.

    Covers the scenarios the registry knows about rather than the two the other
    tests happen to exercise, so a scenario added later without seed discipline
    fails here.
    """
    params = ProtocolParams(key_length=48, check_fraction=0.25)
    seeds = trial_seeds("smoke", "tiny", 0)
    for name in sorted(SCENARIOS):
        options = {"strength": 0.25} if name == "depolarising" else {}
        cell = Cell(
            name="tiny",
            params=params,
            scenario=name,
            scenario_options=options,
            truth_hypothesis="honest",
        )
        first, first_truth = SCENARIOS[name](cell, seeds)
        second, second_truth = SCENARIOS[name](cell, seeds)
        assert first == second, name
        assert first_truth == second_truth, name


# --------------------------------------------------------------------------- #
# 3. The wall between ground truth and evidence                                #
# --------------------------------------------------------------------------- #


def test_the_label_cannot_reach_the_detector() -> None:
    """Two runs differing only in their label get the same Detection.

    The property is not "the label is in a different field" -- it is "the label
    could not have influenced the verdict". So the same transcript is scored
    once, two records are built with contradictory labels, and their
    ``detection`` blocks are compared byte for byte.
    """
    params = ProtocolParams(key_length=96, check_fraction=0.25)
    seeds = trial_seeds("smoke", "tiny", 0)
    transcript = QDSSession(params, rng=seeds.session_rng()).run(0)
    detection = detect(transcript.to_json(), eps=1e-9)

    honest = TrialRecord.build(
        seeds=seeds,
        params=params,
        eps=1e-9,
        transcript=transcript,
        detection=detection,
        truth=GroundTruth(hypothesis="honest"),
    )
    attacked = TrialRecord.build(
        seeds=seeds,
        params=params,
        eps=1e-9,
        transcript=transcript,
        detection=detection,
        truth=GroundTruth(
            hypothesis="channel-manipulation",
            engaged=True,
            engaged_count=99,
            targeted_link="Bob",
        ),
    )
    assert honest.detection == attacked.detection
    assert honest.transcript_summary == attacked.transcript_summary
    assert honest.truth != attacked.truth


def test_detect_takes_no_ground_truth_argument() -> None:
    """There is no parameter through which a label could be passed."""
    import inspect

    parameters = set(inspect.signature(detect).parameters)
    assert parameters == {
        "transcript",
        "eps",
        "channel_error_rate",
        "tolerated_depolarising",
        "method",
        "qber_method",
    }


def test_an_inert_adversary_is_labelled_as_one() -> None:
    """A depolarising cell at strength zero produces honest records.

    Phase 4's replay arm reported a clean 0/40 while having forwarded honestly.
    An arm that reports zero must be checkable for whether it acted at all, and
    the check is the adversary's own engagement count.
    """
    params = ProtocolParams(key_length=96, check_fraction=0.25)
    quiet = Cell(
        name="p000",
        params=params,
        scenario="depolarising",
        scenario_options={"strength": 0.0},
        truth_hypothesis="channel-manipulation",
    )
    loud = Cell(
        name="p050",
        params=params,
        scenario="depolarising",
        scenario_options={"strength": 0.5},
        truth_hypothesis="channel-manipulation",
    )
    seeds = trial_seeds("smoke", "tiny", 0)
    _, quiet_truth = SCENARIOS["depolarising"](quiet, seeds)
    _, loud_truth = SCENARIOS["depolarising"](loud, seeds)

    assert quiet_truth.engaged is False
    assert quiet_truth.engaged_count == 0
    assert quiet_truth.attacked is False
    assert loud_truth.engaged is True
    assert loud_truth.engaged_count > 0


def test_engaged_without_engagement_is_refused() -> None:
    """A label claiming an attack acted, while counting zero actions, raises."""
    with pytest.raises(ValueError, match="contradiction"):
        GroundTruth(hypothesis="replay", engaged=True, engaged_count=0)


def test_a_missing_strength_is_an_error_not_a_default() -> None:
    """A depolarising cell with no strength refuses rather than running inert."""
    cell = Cell(
        name="oops",
        params=ProtocolParams(key_length=48),
        scenario="depolarising",
        scenario_options={},
    )
    with pytest.raises(KeyError, match="strength"):
        SCENARIOS["depolarising"](cell, trial_seeds("smoke", "tiny", 0))


# --------------------------------------------------------------------------- #
# 4. Records                                                                   #
# --------------------------------------------------------------------------- #


def test_fingerprint_ignores_timings_and_nothing_else() -> None:
    """The exclusion list is exactly the timings, and it is pinned.

    An exclusion list is the natural hiding place for a field that genuinely
    moved between one worker and twenty, so this asserts the set and then
    proves each remaining field is inside the fingerprint by mutating it.
    """
    assert NON_DETERMINISTIC_FIELDS == frozenset({"wall_clock"})

    record = run_trial(experiment("smoke"), "tiny", 0)
    base = record.fingerprint()
    payload = record.to_dict()

    slower = TrialRecord.from_dict(
        {**payload, "wall_clock": {"session_seconds": 1e6}}
    )
    assert slower.fingerprint() == base

    for field in ("experiment", "cell", "index", "eps"):
        mutated = dict(payload)
        mutated[field] = (
            payload[field] + 1
            if isinstance(payload[field], (int, float))
            else "changed"
        )
        if field in ("experiment", "cell"):
            mutated[field] = "changed"
        assert TrialRecord.from_dict(mutated).fingerprint() != base, field

    for field in ("seeds", "params", "detection", "transcript_summary"):
        mutated = dict(payload)
        mutated[field] = {**payload[field], "harness_probe": 1}
        assert TrialRecord.from_dict(mutated).fingerprint() != base, field

    # `truth` has a fixed schema, so an unknown key there is dropped on the way
    # back in rather than fingerprinted. Every field it does carry is covered.
    for field, value in (
        ("hypothesis", "outside-forgery"),
        ("engaged", True),
        ("engaged_count", 5),
        ("targeted_link", "Bob"),
        ("detectable", False),
        ("notes", "changed"),
    ):
        mutated = dict(payload)
        mutated["truth"] = {**payload["truth"], field: value}
        if field == "engaged":
            mutated["truth"]["engaged_count"] = 1
        assert TrialRecord.from_dict(mutated).fingerprint() != base, field


def test_record_round_trips_through_json() -> None:
    """A record written and read back is the record that was written."""
    record = run_trial(experiment("smoke"), "tiny", 1)
    text = json.dumps(record.to_dict(), sort_keys=True)
    assert TrialRecord.from_dict(json.loads(text)) == record


def test_a_stale_schema_is_refused() -> None:
    """Reducing across two record schemas is refused, not silently mixed."""
    record = run_trial(experiment("smoke"), "tiny", 0)
    stale = {**record.to_dict(), "schema": "sih141/eval/record/v0"}
    with pytest.raises(ValueError, match="schema"):
        TrialRecord.from_dict(stale)
    assert record.schema == RECORD_SCHEMA


def test_transcript_summary_keeps_the_two_links_apart() -> None:
    """Per-link statistics are per link, with no pooled total (constraint 3)."""
    params = ProtocolParams(key_length=96, check_fraction=0.25)
    summary = transcript_summary(
        QDSSession(params, rng=np.random.default_rng(4)).run(0)
    )
    assert set(summary["links"]) == {"Bob/0", "Bob/1", "Charlie/0", "Charlie/1"}
    assert "pooled_qber" not in summary
    assert "qber" not in summary


def test_an_unmonitored_link_reports_nothing_rather_than_zero() -> None:
    """With no check rounds the link block is empty, not a row of zeroes.

    An unmonitored link is not a clean one. A zero QBER for a link nobody
    measured says the opposite of the truth.
    """
    summary = transcript_summary(
        QDSSession(ProtocolParams(key_length=96), rng=np.random.default_rng(4)).run(0)
    )
    assert summary["links"] == {}


def test_transcripts_are_not_retained_by_default() -> None:
    """The 26.7 MB field is absent unless asked for."""
    lean = run_trial(experiment("smoke"), "tiny", 0)
    assert lean.transcript_json is None
    assert "transcript_json" not in lean.to_dict()

    fat = run_trial(experiment("smoke"), "tiny", 0, retain_transcript=True)
    assert fat.transcript_json is not None
    assert len(fat.transcript_json) > 1000
    assert fat.fingerprint() != lean.fingerprint()


# --------------------------------------------------------------------------- #
# 5. The store: resumable, atomic, ordered                                     #
# --------------------------------------------------------------------------- #


def test_a_resumed_sweep_skips_what_is_on_disk(tmp_path: Path) -> None:
    """The second pass runs nothing and reports the trials as skipped."""
    exp = experiment("smoke")
    store = ResultStore(tmp_path)
    first = run_experiment(exp, store, trials=3, workers=1, in_process=True, quiet=True)
    second = run_experiment(
        exp, store, trials=3, workers=1, in_process=True, quiet=True
    )
    assert (first["ran"], first["skipped"]) == (3, 0)
    assert (second["ran"], second["skipped"]) == (0, 3)
    assert plan_trials(exp, store, trials=3) == []


def test_an_interruption_costs_one_trial_not_the_run(tmp_path: Path) -> None:
    """Trials finished before a crash survive it, and the rest are replanned."""
    exp = experiment("smoke")
    store = ResultStore(tmp_path)
    store.write(run_trial(exp, "tiny", 0))
    store.write(run_trial(exp, "tiny", 2))
    remaining = [spec.index for spec in plan_trials(exp, store, trials=4)]
    assert remaining == [1, 3]


def test_a_half_written_file_is_never_visible(tmp_path: Path) -> None:
    """Writes are atomic: the destination never holds a partial record.

    Proved by making the JSON serialisation fail mid-write and checking that
    the destination does not exist afterwards, and that no temporary file is
    left behind either.
    """
    store = ResultStore(tmp_path)
    record = run_trial(experiment("smoke"), "tiny", 0)

    class Unserialisable:
        """A value :func:`json.dump` refuses, to abort the write partway."""

    broken = TrialRecord(
        schema=record.schema,
        experiment=record.experiment,
        cell=record.cell,
        index=record.index,
        seeds=record.seeds,
        params=record.params,
        eps=record.eps,
        truth=record.truth,
        detection={"bad": Unserialisable()},
        transcript_summary=record.transcript_summary,
    )
    with pytest.raises(TypeError):
        store.write(broken)
    assert not store.path_for("smoke", "tiny", 0).exists()
    assert list(store.cell_dir("smoke", "tiny").glob(".trial-*.tmp")) == []


def test_store_reads_in_index_order_not_directory_order(tmp_path: Path) -> None:
    """Records come back sorted by trial index, whatever order they arrived in."""
    exp = experiment("smoke")
    store = ResultStore(tmp_path)
    for index in (3, 0, 2, 1):
        store.write(run_trial(exp, "tiny", index))
    assert [r.index for r in store.read_cell("smoke", "tiny")] == [0, 1, 2, 3]


def test_store_ignores_junk_in_its_own_directory(tmp_path: Path) -> None:
    """A stray file does not stop a sweep reading its results."""
    store = ResultStore(tmp_path)
    store.write(run_trial(experiment("smoke"), "tiny", 0))
    (store.cell_dir("smoke", "tiny") / "trial-notanumber.json").write_text("{}")
    (store.cell_dir("smoke", "tiny") / "notes.txt").write_text("hello")
    assert store.indices("smoke", "tiny") == [0]


def test_an_absent_store_reports_nothing_rather_than_raising(tmp_path: Path) -> None:
    """Reading a directory that does not exist is an empty result, not an error."""
    store = ResultStore(tmp_path / "nothing-here")
    assert store.experiments() == []
    assert store.cells("smoke") == []
    assert store.indices("smoke", "tiny") == []
    assert store.count("smoke") == 0


def test_a_name_cannot_escape_the_results_root(tmp_path: Path) -> None:
    """Path traversal through an experiment or cell name is refused."""
    store = ResultStore(tmp_path)
    for bad in ("..", "../evil", "a/b", "C:"):
        with pytest.raises(ValueError):
            store.cell_dir(bad, "tiny")
        with pytest.raises(ValueError):
            store.cell_dir("smoke", bad)


def test_the_default_results_root_is_outside_the_repository() -> None:
    """Raw per-trial files are never committed, so they default elsewhere."""
    assert REPO_ROOT not in DEFAULT_RESULTS_ROOT.parents
    assert DEFAULT_RESULTS_ROOT != REPO_ROOT


def test_gitignore_covers_an_in_tree_results_directory() -> None:
    """Someone pointing --results at the working copy still commits nothing."""
    ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert "results/" in ignored
    assert "sweep-results/" in ignored


# --------------------------------------------------------------------------- #
# 6. The manifest                                                              #
# --------------------------------------------------------------------------- #


def test_a_manifest_records_what_d9_needs(tmp_path: Path) -> None:
    """Commit, command, seed rule, workers, machine, and both timestamps."""
    manifest = RunManifest.begin(
        experiment="smoke",
        cells=("tiny",),
        trials=2,
        workers=4,
        results_root=str(tmp_path),
        eps=1e-9,
    )
    assert manifest.finished_at is None
    done = manifest.finish(ran=2, skipped=0, failed=0, wall_clock_seconds=1.0)
    payload = done.to_dict()

    assert payload["schema"] == MANIFEST_SCHEMA
    assert payload["command_line"].startswith("python ")
    assert payload["seed_derivation"]["domain"] == SEED_DOMAIN.decode("ascii")
    assert payload["workers"] == 4
    assert payload["machine"]["cpu_count_logical"] >= 1
    assert payload["started_at"].endswith("Z")
    assert payload["finished_at"].endswith("Z")
    assert "dirty" in payload["git"]
    assert RunManifest.from_dict(payload) == done


def test_a_manifest_filename_is_legal_on_windows() -> None:
    """No colon, because Windows forbids one in a filename."""
    manifest = RunManifest.begin(
        experiment="smoke",
        cells=("tiny",),
        trials=1,
        workers=1,
        results_root=".",
        eps=1e-9,
    )
    assert ":" not in manifest.filename()
    assert manifest.filename().startswith("manifest-")


def test_a_manifest_of_the_wrong_schema_is_refused() -> None:
    """A manifest from another version does not load silently."""
    with pytest.raises(ValueError, match="schema"):
        RunManifest.from_dict({"schema": "sih141/eval/manifest/v0"})


# --------------------------------------------------------------------------- #
# 7. BLAS pinning and the pool                                                 #
# --------------------------------------------------------------------------- #


def test_workers_really_see_the_pinned_thread_limit() -> None:
    """The limit reaches a worker's own environment, measured from inside it.

    A comment saying the variables are set proves nothing about whether they
    arrived: the whole failure mode is that setting them after numpy is
    imported is a silent no-op. So this asks a real spawned worker what it
    sees.
    """
    pin_blas_threads(1)
    reports = probe_pool(2)
    assert reports
    for report in reports:
        for name in BLAS_ENV_VARS:
            assert report["blas_env"][name] == "1", name
    assert len({report["pid"] for report in reports}) >= 1
    assert os.getpid() not in {report["pid"] for report in reports}


def test_pin_blas_threads_reports_whether_it_could_have_worked() -> None:
    """The report says whether numpy was already up, rather than implying not."""
    report = pin_blas_threads(2)
    assert report["threads"] == 2
    assert report["values"]["OMP_NUM_THREADS"] == "2"
    assert report["numpy_already_imported"] is True  # numpy is imported above
    pin_blas_threads(1)


def test_pin_blas_threads_refuses_a_nonsense_limit() -> None:
    """Zero or negative threads is an error, not a silent no-op."""
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError if not isinstance(bad, float) else ValueError):
            pin_blas_threads(bad)  # type: ignore[arg-type]


def test_a_failing_trial_is_counted_not_swallowed(tmp_path: Path) -> None:
    """One bad cell costs that cell, and the failure is named.

    Built by registering an experiment whose cell asks the depolarising
    scenario for a strength it does not supply, so every trial raises.
    """
    broken = Experiment(
        name="brokencell",
        cells=(
            Cell(
                name="tiny",
                params=ProtocolParams(key_length=48),
                scenario="depolarising",
                scenario_options={},
            ),
        ),
        trials=2,
    )
    EXPERIMENTS[broken.name] = broken
    try:
        summary = run_experiment(
            broken,
            ResultStore(tmp_path),
            trials=2,
            workers=1,
            in_process=True,
            quiet=True,
        )
    finally:
        del EXPERIMENTS[broken.name]
    assert summary["ran"] == 0
    assert summary["failed"] == 2
    assert all("strength" in line for line in summary["errors"])
    assert ResultStore(tmp_path).count("brokencell") == 0


# --------------------------------------------------------------------------- #
# 8. The tables, each recomputed by a second route                             #
# --------------------------------------------------------------------------- #


def test_outcome_counts_agree_with_the_detectors_own_tally(tmp_path: Path) -> None:
    """The outcome table's route and the detector's route reach one answer.

    ``tally_from_record`` reads ``transcript_summary["verdicts"]``, written
    straight off the transcript's results and aborts. The detector reaches the
    same conclusion through :mod:`sih141.detect.thresholds_structural` and
    stores it as ``detection["outcomes"]``. Two independent code paths; if they
    disagree, one of them is wrong.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=4, workers=1, in_process=True, quiet=True
    )
    for record in store.read_experiment("smoke"):
        assert record.transcript_summary["verdicts"] == record.detection["outcomes"]


def test_outcome_table_recomputed_from_the_raw_transcript(tmp_path: Path) -> None:
    """One cell of the outcome table, recomputed by re-running the trials.

    The table is built from stored records; this rebuilds the same counts by
    running each trial again and calling
    :func:`~sih141.detect.thresholds_structural.tally_outcomes` on the live
    transcript's statistics -- a different code path from
    ``transcript_summary``. The two must produce the same four counts.
    """
    exp = experiment("smoke")
    store = ResultStore(tmp_path)
    run_experiment(exp, store, trials=3, workers=1, in_process=True, quiet=True)
    table = outcome_table(list(store.read_experiment("smoke")))
    row = table.rows[0]
    _, _, runs, parties, accepted, rejected, refused, not_asked = row

    independent = None
    for index in range(3):
        seeds = trial_seeds("smoke", "tiny", index)
        transcript = QDSSession(
            exp.cell("tiny").params, rng=seeds.session_rng()
        ).run(exp.cell("tiny").message_bit)
        tally = tally_outcomes(TranscriptStatistics.from_transcript(transcript))
        independent = tally if independent is None else independent.merge(tally)

    assert independent is not None
    assert (accepted, rejected) == (independent.accepted, independent.rejected)
    assert refused == int(independent.refused)
    assert not_asked == int(independent.not_asked)
    assert runs == independent.runs == 3
    assert parties == accepted + rejected + refused + not_asked == 6
    assert parties == 2 * runs


def test_a_refusal_can_never_be_added_to_a_rejection(tmp_path: Path) -> None:
    """The tally type refuses the arithmetic that would report a false detection."""
    store = ResultStore(tmp_path)
    store.write(run_trial(experiment("smoke"), "tiny", 0))
    tally = tally_from_record(store.read("smoke", "tiny", 0))
    with pytest.raises(TypeError, match="no-verdict"):
        tally.rejected + tally.refused  # noqa: B018 - evaluating it is the assertion


def test_two_count_orderings_are_never_pooled(tmp_path: Path) -> None:
    """A cell with both orderings becomes two rows, and merging them raises."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=2, workers=1, in_process=True, quiet=True
    )
    records = list(store.read_experiment("smoke"))

    # Forge a second ordering on one record so the grouping has something to
    # separate. The point is the grouping, not the forged run.
    other = records[0].to_dict()
    other["transcript_summary"] = {
        **other["transcript_summary"],
        "count_exchange_timing": "after-forwarding",
    }
    mixed = [*records, TrialRecord.from_dict(other)]

    grouped = group_records(mixed)
    assert set(grouped) == {
        ("tiny", "before-forwarding"),
        ("tiny", "after-forwarding"),
    }
    assert len(outcome_table(mixed).rows) == 2

    before = tally_from_record(records[0])
    after = tally_from_record(TrialRecord.from_dict(other))
    with pytest.raises(ValueError, match="two count orderings"):
        before.merge(after)


def test_detection_rate_interval_recomputed_by_exact_arithmetic(
    tmp_path: Path,
) -> None:
    """The Wilson interval in the table matches one computed here by hand.

    The formula is written out from the definition rather than called, so a
    change to the helper that silently narrowed an interval would show up.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=4, workers=1, in_process=True, quiet=True
    )
    records = list(store.read_experiment("smoke"))
    table = detection_table(records)
    cell = table.rows[0][6]  # flagged on clean (measured)

    successes = sum(1 for r in records if r.flagged)
    trials = len(records)
    assert Fraction(successes, trials) == Fraction(0, 1)

    # Wilson, written from the definition: for k = 0 the centre is
    # (z^2/2) / (n + z^2) and the half-width equals the centre, so the interval
    # is [0, z^2 / (n + z^2)].
    z = 2.5758293035489004  # the two-sided 99% normal quantile
    denominator = trials + z * z
    low = 0.0
    high = (z * z) / denominator
    assert cell == (
        f"{successes}/{trials} = {successes / trials:.3f} "
        f"[{low:.3f}, {high:.3f}]"
    )
    assert CONFIDENCE == 0.99


def test_measured_and_proven_never_share_a_column(tmp_path: Path) -> None:
    """The words are on the headers, and the two are different columns."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=2, workers=1, in_process=True, quiet=True
    )
    table = detection_table(list(store.read_experiment("smoke")))
    measured = [c for c in table.columns if "measured" in c]
    proven = [c for c in table.columns if "proven" in c]
    assert len(measured) == 2
    assert len(proven) == 1
    assert set(measured).isdisjoint(proven)
    assert any("MEASUREMENTS" in note for note in table.notes)
    assert any("PROVEN" in note for note in table.notes)
    assert any("no false-negative bound" in note for note in table.notes)


def test_an_undetectable_hypothesis_is_named_not_zeroed(tmp_path: Path) -> None:
    """A cell excluded by assumption prints the phrase, never 0 and never blank."""
    store = ResultStore(tmp_path)
    record = run_trial(experiment("smoke"), "tiny", 0)
    labelled = TrialRecord.from_dict(
        {
            **record.to_dict(),
            "truth": {
                **record.truth.to_dict(),
                "hypothesis": "impersonation",
                "detectable": False,
                "engaged": True,
                "engaged_count": 1,
            },
        }
    )
    store.write(labelled)
    table = detection_table([labelled])
    assert table.rows[0][5] == UNDETECTABLE_BY_CONSTRUCTION
    assert "0" not in str(table.rows[0][5])
    # The assumption is about the attack, not about the runs it left alone, so
    # the clean column stays a measurement. Here there are no clean runs, which
    # says "no trials" rather than borrowing the phrase from the column beside
    # it -- printing the phrase there would withhold a measurement that could
    # have been made.
    assert table.rows[0][6] == "no trials"


def test_a_withheld_family_is_reported_as_unevaluated(tmp_path: Path) -> None:
    """Families the detector could not score read `not evaluated`, never passed."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=2, workers=1, in_process=True, quiet=True
    )
    records = list(store.read_experiment("smoke"))
    assert any(record.detection["withheld"] for record in records)
    table = detection_table(records)
    assert table.rows[0][9].startswith(NOT_EVALUATED)
    assert any("withheld" in note for note in table.notes)
    # No cell anywhere in the table claims a withheld family passed, and the
    # count in the cell is the number of families actually withheld in that
    # group rather than across the whole table.
    for row in table.rows:
        assert not any("pass" in str(cell).lower() for cell in row)
    withheld_here = set()
    for record in records:
        withheld_here.update(record.detection["withheld"])
    assert table.rows[0][9] == f"{NOT_EVALUATED} ({len(withheld_here)})"
    assert any(
        "channel" in note and "chsh" in note for note in table.notes
    )


def test_a_rate_with_no_trials_says_so_rather_than_printing_zero(
    tmp_path: Path,
) -> None:
    """An empty denominator reads `no trials`, not `0.000`.

    A zero reads as a measurement that found nothing; an absent measurement is
    a different claim entirely.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=2, workers=1, in_process=True, quiet=True
    )
    table = detection_table(list(store.read_experiment("smoke")))
    assert table.rows[0][4] == 0  # no attacked runs in an honest cell
    assert table.rows[0][5] == "no trials"


def test_the_null_is_a_column_on_every_detection_row(tmp_path: Path) -> None:
    """`null_is_noiseless` rides on the table, not in a footnote alone."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=2, workers=1, in_process=True, quiet=True
    )
    table = detection_table(list(store.read_experiment("smoke")))
    assert "null_is_noiseless" in table.columns
    assert table.rows[0][8] == "yes"
    for record in store.read_experiment("smoke"):
        assert record.null_is_noiseless is True
        assert record.detection["channel_error_rate"] == 0.0


def test_a_noisy_cell_reports_its_null_honestly(tmp_path: Path) -> None:
    """A cell given the link's true rate is not scored against a noiseless null.

    The observation that would differ if ``null_is_noiseless`` were decorative:
    two cells, one scored at ``channel_error_rate = 0`` and one at the true
    rate, come out with different values in that column.
    """
    params = ProtocolParams(key_length=96, check_fraction=0.25)
    truthful = Experiment(
        name="truthfulnull",
        cells=(
            Cell(
                name="p010",
                params=params,
                scenario="depolarising",
                scenario_options={"strength": 0.01},
                channel_error_rate=0.005,
                truth_hypothesis="channel-noise",
            ),
        ),
        trials=1,
    )
    EXPERIMENTS[truthful.name] = truthful
    try:
        record = run_trial(truthful, "p010", 0)
    finally:
        del EXPERIMENTS[truthful.name]
    assert record.null_is_noiseless is False
    assert detection_table([record]).rows[0][8] == "no"


def test_timing_table_is_arithmetically_right(tmp_path: Path) -> None:
    """Mean session seconds and ms/position recomputed from the raw records."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=3, workers=1, in_process=True, quiet=True
    )
    records = list(store.read_experiment("smoke"))
    table = timing_table(records)
    _, length, trials, total, mean, _, ms = table.rows[0]

    seconds = [r.wall_clock["session_seconds"] for r in records]
    assert trials == len(seconds) == 3
    assert length == 96
    assert float(total) == pytest.approx(sum(seconds), abs=5e-3)
    assert float(mean) == pytest.approx(sum(seconds) / len(seconds), abs=5e-4)
    assert float(ms) == pytest.approx(
        1000.0 * (sum(seconds) / len(seconds)) / 96, abs=5e-3
    )


def test_every_table_carries_the_command_that_regenerates_it(
    tmp_path: Path,
) -> None:
    """D9: the command is printed next to the table, and its absence is loud."""
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=2, workers=1, in_process=True, quiet=True
    )
    command = "python tools/sweep.py reduce smoke"
    for table in reduce_experiment(store, "smoke", command=command):
        assert table.command == command
        assert f"Regenerate: `{command}`" in table.to_markdown()

    naked = Table(slug="x", title="X", columns=("a",), rows=((1,),))
    assert "not reproducible" in naked.to_markdown()


def test_reducing_nothing_raises_rather_than_publishing_an_empty_table(
    tmp_path: Path,
) -> None:
    """No records is an error; an empty table looks like a measurement of zero."""
    with pytest.raises(FileNotFoundError, match="no records"):
        reduce_experiment(ResultStore(tmp_path), "smoke")


# --------------------------------------------------------------------------- #
# 9. The registry                                                              #
# --------------------------------------------------------------------------- #


def test_every_registered_cell_is_runnable() -> None:
    """Each cell's scenario, params and options actually produce a record.

    A registry entry that raises on its first trial would otherwise be found
    six hours into a sweep.
    """
    for name in sorted(EXPERIMENTS):
        exp = EXPERIMENTS[name]
        for cell in exp.cells:
            small = Experiment(
                name=exp.name,
                cells=(
                    Cell(
                        name=cell.name,
                        params=ProtocolParams(
                            key_length=48,
                            check_fraction=cell.params.check_fraction,
                        ),
                        scenario=cell.scenario,
                        scenario_options=cell.scenario_options,
                        message_bit=cell.message_bit,
                        eps=cell.eps,
                        channel_error_rate=cell.channel_error_rate,
                        tolerated_depolarising=cell.tolerated_depolarising,
                        truth_hypothesis=cell.truth_hypothesis,
                        detectable=cell.detectable,
                    ),
                ),
                trials=1,
            )
            record = run_trial(small, cell.name, 0)
            assert record.cell == cell.name
            assert record.truth.hypothesis == cell.truth_hypothesis


def test_duplicate_cell_names_are_refused() -> None:
    """Two cells sharing a name would share a directory and a seed stream."""
    cell = Cell(name="tiny", params=ProtocolParams(key_length=48))
    with pytest.raises(ValueError, match="duplicate cell names"):
        Experiment(name="dupes", cells=(cell, cell))


def test_an_unknown_scenario_is_refused_at_definition() -> None:
    """A typo in a scenario name fails when the cell is built, not at run time."""
    with pytest.raises(ValueError, match="unknown scenario"):
        Cell(
            name="tiny",
            params=ProtocolParams(key_length=48),
            scenario="depolarizing",  # American spelling: not registered
        )


def test_cell_filtering_keeps_table_order() -> None:
    """Selecting cells does not reorder them, so two runs give one table order."""
    names = [c.name for c in all_cells(experiment("honest"), ["l768", "l192"])]
    assert names == ["l192", "l768"]


# --------------------------------------------------------------------------- #
# 10. The performance figures                                                  #
# --------------------------------------------------------------------------- #


def test_the_measured_rate_and_its_projections_agree() -> None:
    """The projected full-scale session equals the measured one.

    The rate constant and the measurement table are two places one number is
    written; if they drift apart the plan is projecting from a rate nothing
    measured.
    """
    measured = next(
        row for row in perf.MEASURED_SESSIONS if row["key_length"] == 115200
    )
    assert measured["ms_per_position"] == perf.REFERENCE_MS_PER_POSITION
    assert perf.projected_session_seconds(115200) == pytest.approx(
        measured["seconds"], rel=1e-3
    )
    assert measured["seconds"] / measured["key_length"] * 1000 == pytest.approx(
        perf.REFERENCE_MS_PER_POSITION, rel=1e-3
    )


def test_scaling_stayed_linear_across_the_measured_range() -> None:
    """Every measured rate lies inside a narrow band, over a 1200-fold range."""
    rates = [row["ms_per_position"] for row in perf.MEASURED_SESSIONS]
    lengths = [row["key_length"] for row in perf.MEASURED_SESSIONS]
    assert max(lengths) / min(lengths) >= 1000
    assert max(rates) / min(rates) < 1.2
    for row in perf.MEASURED_SESSIONS:
        assert row["seconds"] * 1000 / row["key_length"] == pytest.approx(
            row["ms_per_position"], rel=2e-3
        )


def test_the_sweep_projection_is_the_arithmetic_it_claims() -> None:
    """200 trials at full scale, single-threaded, recomputed by hand."""
    by_hand = 200 * 115200 * perf.REFERENCE_MS_PER_POSITION / 1000.0 / 3600.0
    assert perf.projected_sweep_hours(200, 115200) == pytest.approx(by_hand)
    assert perf.projected_sweep_hours(200, 115200, speedup=15.0) == pytest.approx(
        by_hand / 15.0
    )


def test_a_speedup_curve_without_a_baseline_is_refused() -> None:
    """Normalising to the fastest point would report perfect efficiency always."""
    with pytest.raises(ValueError, match="one-worker baseline"):
        perf.speedup_table(
            [{"workers": 4, "seconds": 10.0}, {"workers": 20, "seconds": 3.0}]
        )


def test_speedup_arithmetic_is_recomputed_by_hand() -> None:
    """Speedup is baseline over elapsed, efficiency is speedup over workers."""
    table = perf.speedup_table(
        [
            {"workers": 1, "seconds": 120.0},
            {"workers": 4, "seconds": 32.0},
            {"workers": 20, "seconds": 8.0},
        ]
    )
    assert [row["speedup"] for row in table] == [1.0, 120 / 32, 15.0]
    assert table[-1]["efficiency"] == pytest.approx(15.0 / 20)
    assert math.isclose(table[1]["efficiency"], (120 / 32) / 4)


def test_time_session_reports_a_run_that_actually_happened() -> None:
    """A timing carries the run's own verdict, so a degenerate run is visible."""
    timing = perf.time_session(48, seed=19)
    assert timing["key_length"] == 48
    assert timing["seconds"] > 0
    assert timing["json_bytes"] > 0
    assert timing["transferable"] in (True, False)
    assert timing["ms_per_position"] == pytest.approx(
        1000 * timing["seconds"] / 48
    )


# --------------------------------------------------------------------------- #
# 11. The CLI                                                                  #
# --------------------------------------------------------------------------- #


def _sweep(*args: str) -> subprocess.CompletedProcess[str]:
    """Run ``tools/sweep.py`` in a subprocess.

    Parameters
    ----------
    *args : str
        Arguments after the script path.

    Returns
    -------
    subprocess.CompletedProcess
    """
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "sweep.py"), *args],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=str(REPO_ROOT),
    )


def test_cli_runs_then_reduces_without_rerunning(tmp_path: Path) -> None:
    """The two halves are separable: reduce works on files run wrote earlier.

    Driven through the real command line in a real subprocess, because the
    ``if __name__ == "__main__"`` guard and the spawn behaviour it protects
    only exist there.
    """
    results = str(tmp_path)
    ran = _sweep("run", "smoke", "--trials", "3", "--workers", "2", "--results", results)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert "ran 3" in ran.stderr

    store = ResultStore(tmp_path)
    assert store.count("smoke") == 3
    assert store.manifests("smoke")

    first = _sweep("reduce", "smoke", "--results", results)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "Run outcomes" in first.stdout
    assert "Regenerate:" in first.stdout

    # Reducing twice changes nothing and runs nothing.
    second = _sweep("reduce", "smoke", "--results", results)
    assert second.stdout == first.stdout
    assert store.count("smoke") == 3


def test_cli_dry_run_writes_nothing(tmp_path: Path) -> None:
    """``--dry-run`` lists the work and leaves the directory empty."""
    done = _sweep("run", "smoke", "--dry-run", "--results", str(tmp_path))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "smoke/tiny#0" in done.stdout
    assert ResultStore(tmp_path).count("smoke") == 0


def test_cli_manifest_records_the_command_and_the_workers(tmp_path: Path) -> None:
    """The manifest on disk is what a reviewer would need to re-run the sweep."""
    _sweep("run", "smoke", "--trials", "2", "--workers", "2", "--results", str(tmp_path))
    manifests = ResultStore(tmp_path).manifests("smoke")
    assert manifests
    payload = json.loads(manifests[-1].read_text(encoding="utf-8"))
    assert payload["workers"] == 2
    assert "tools/sweep.py" in payload["command_line"] or "sweep.py" in payload[
        "command_line"
    ]
    assert payload["finished_at"] is not None
    assert payload["trials_ran"] == 2
    assert payload["seed_derivation"]["function"] == "sih141.eval.seeds.trial_seed"
    assert payload["blas"]["values"]["OMP_NUM_THREADS"] == "1"
    assert payload["worker_probe"]
    for report in payload["worker_probe"]:
        assert report["blas_env"]["OMP_NUM_THREADS"] == "1"


def test_cli_reduce_json_matches_the_markdown(tmp_path: Path) -> None:
    """Both formats come from one reduction, so their numbers cannot diverge."""
    results = str(tmp_path)
    _sweep("run", "smoke", "--trials", "2", "--workers", "1", "--results", results)
    as_json = _sweep("reduce", "smoke", "--results", results, "--format", "json")
    assert as_json.returncode == 0, as_json.stdout + as_json.stderr
    payload = json.loads(as_json.stdout)
    slugs = [table["slug"] for table in payload["tables"]]
    assert slugs == ["outcomes", "detection", "timing"]
    outcomes = next(t for t in payload["tables"] if t["slug"] == "outcomes")
    assert outcomes["rows"][0][2] == 2  # runs


def test_the_memory_probe_cannot_silently_report_zero() -> None:
    """The RSS probe returns a real figure, not the zero a failed call gives.

    This is not a hypothetical. The first version of the probe left ctypes to
    default every argument to a 32-bit int, so the pseudo-handle ``-1`` that
    ``GetCurrentProcess`` returns arrived as ``0xFFFFFFFF`` instead of a 64-bit
    ``HANDLE``, the call failed, and every row of the memory table read
    ``0.0 MB``. It looked exactly like a process that used no memory. Any
    interpreter with numpy and qiskit loaded is well past 10 MB, so this fails
    if the call breaks again.
    """
    peak = perf.peak_rss_bytes()
    assert peak is not None
    assert peak > 10 * 1024 * 1024


def test_memory_measurement_refuses_a_descending_sweep() -> None:
    """Peak RSS is a high-water mark, so the order it is measured in matters."""
    with pytest.raises(ValueError, match="ascending"):
        perf.measure_memory([96, 48])


def test_the_speedup_curve_is_recomputed_from_its_raw_measurements() -> None:
    """Speedup, efficiency and occupancy all follow from the two raw columns.

    ``MEASURED_SPEEDUP`` carries only wall clock and the sum of in-worker trial
    seconds. Everything the table prints is derived here, so a hand-edited
    speedup figure that did not follow from its own measurement would fail.
    """
    curve = perf.measured_speedup_curve()
    baseline = perf.MEASURED_SPEEDUP[0]["wall_seconds"]
    for row, raw in zip(curve, perf.MEASURED_SPEEDUP):
        assert row["speedup"] == pytest.approx(baseline / raw["wall_seconds"])
        assert row["efficiency"] == pytest.approx(row["speedup"] / row["workers"])
        assert row["occupancy"] == pytest.approx(
            raw["trial_seconds_total"] / raw["wall_seconds"]
        )
        assert row["mean_trial_seconds"] == pytest.approx(
            raw["trial_seconds_total"] / perf.MEASURED_SPEEDUP_TRIALS
        )


def test_the_pool_was_busy_while_the_speedup_was_poor() -> None:
    """Occupancy near 20 with speedup near 7 is the diagnosis, not a paradox.

    If the two ever agreed, the explanation in ``SPEEDUP_NOTE`` -- the cores
    slow down rather than the pool idling -- would be the wrong one and the
    caption would have to change.
    """
    twenty = perf.measured_speedup_curve()[-1]
    assert twenty["workers"] == 20
    assert twenty["occupancy"] > 17.0
    assert twenty["speedup"] < 8.0
    assert twenty["mean_trial_seconds"] > 2.0 * perf.measured_speedup_curve()[0][
        "mean_trial_seconds"
    ]


def test_the_corrected_sweep_estimate_uses_the_measured_speedup() -> None:
    """200 full-scale trials at 20 workers is 1.9 hours, not 51 minutes."""
    hours = perf.projected_sweep_hours(
        200, 115200, speedup=perf.measured_speedup_at(20)
    )
    assert hours == pytest.approx(1.86, abs=0.01)
    assert hours > perf.projected_sweep_hours(200, 115200, speedup=15.0)


def test_an_unmeasured_worker_count_is_not_interpolated() -> None:
    """The curve is far from linear, so interpolating it would invent a number."""
    with pytest.raises(KeyError, match="no speedup measured"):
        perf.measured_speedup_at(12)


def test_memory_rises_with_key_length_above_a_fixed_floor() -> None:
    """The import floor is about 76 MB and the rise above it tracks L."""
    rows = perf.MEASURED_MEMORY
    assert rows[0]["peak_rss_mb"] > 70
    assert [r["key_length"] for r in rows] == sorted(r["key_length"] for r in rows)
    assert all(
        later["peak_rss_mb"] >= earlier["peak_rss_mb"]
        for earlier, later in zip(rows, rows[1:])
    )
    # The rise above the floor is roughly proportional to L: the last two
    # points are a 4x jump in L and no more than a 6x jump in the excess.
    floor = 76.0
    excess = [row["peak_rss_mb"] - floor for row in rows[-2:]]
    ratio = excess[1] / excess[0]
    assert 2.0 < ratio < 6.0


def test_the_security_claim_boundary_is_where_it_is_recorded(
) -> None:
    """L=180 carries no claim and L=183 does, run rather than asserted.

    The boundary is a property of the floors, so this runs the protocol at both
    lengths and reads ``Detection.security_claim``. A change to ``M_min`` that
    moved the boundary would fail here rather than quietly invalidate the note
    that tells a Phase 5 reader which cells carry a claim.
    """
    from sih141.core.rng import seed_to_generator

    def claims(length: int) -> bool:
        params = ProtocolParams(key_length=length, check_fraction=0.25)
        transcript = QDSSession(params, rng=seed_to_generator(4242 + length)).run(0)
        return bool(detect(transcript.to_json(), eps=1e-9).security_claim)

    assert perf.SECURITY_CLAIM_MIN_KEY_LENGTH == 183
    assert claims(perf.SECURITY_CLAIM_MIN_KEY_LENGTH) is True
    assert claims(perf.SECURITY_CLAIM_MIN_KEY_LENGTH - 3) is False


def test_a_parameter_set_that_would_estimate_nothing_is_refused() -> None:
    """The smallest degenerate case is an error, not a silent no-op.

    ``floor(0.25 * 3) == 0`` check rounds would leave a run claiming channel
    estimation while estimating nothing. The refusal names the three ways out.
    """
    with pytest.raises(ValueError, match="check rounds"):
        ProtocolParams(key_length=3, check_fraction=0.25)


def test_the_clean_column_survives_an_undetectable_hypothesis(
    tmp_path: Path,
) -> None:
    """An undetectable cell still reports the false-positive rate it measured.

    Assumption (AUTH) rules out detecting the *attack*. It says nothing about
    the runs the adversary left alone, and those are honest runs whose
    false-positive rate is as measurable as any other. A table that printed
    ``undetectable-by-construction`` in both columns would be withholding a
    measurement it had actually made.
    """
    store = ResultStore(tmp_path)
    run_experiment(
        experiment("smoke"), store, trials=4, workers=1, in_process=True, quiet=True
    )
    records = []
    for index, record in enumerate(store.read_experiment("smoke")):
        payload = record.to_dict()
        payload["truth"] = {
            **payload["truth"],
            "hypothesis": "impersonation",
            "detectable": False,
            "engaged": index < 2,
            "engaged_count": 1 if index < 2 else 0,
        }
        records.append(TrialRecord.from_dict(payload))

    table = detection_table(records)
    assert table.rows[0][4] == 2  # two engaged
    assert table.rows[0][5] == UNDETECTABLE_BY_CONSTRUCTION
    assert table.rows[0][6].startswith("0/2 = 0.000 [")


def test_table_rows_follow_the_experiments_cell_order(tmp_path: Path) -> None:
    """Rows come out in the order the experiment declares, not alphabetically.

    `scaling` has cells l192, l768, l3072, l12288. Sorted by name that is
    l12288 first, which is deterministic, correct and useless to anyone reading
    a throughput table for a trend.
    """
    exp = experiment("scaling")
    assert exp.cell_names == ("l192", "l768", "l3072", "l12288")
    assert sorted(exp.cell_names) != list(exp.cell_names)

    store = ResultStore(tmp_path)
    for cell in exp.cell_names:
        small = Experiment(
            name="scaling",
            cells=tuple(
                Cell(name=name, params=ProtocolParams(key_length=48, check_fraction=0.25))
                for name in exp.cell_names
            ),
            trials=1,
        )
        store.write(run_trial(small, cell, 0))

    for table in reduce_experiment(store, "scaling", command="x"):
        assert [row[0] for row in table.rows] == list(exp.cell_names), table.slug


def test_an_unregistered_cell_still_appears_in_a_table(tmp_path: Path) -> None:
    """A record whose cell has left the registry is not silently dropped.

    Ordering by the registry must not become filtering by it: a table missing a
    row reads as a configuration that was never run.
    """
    store = ResultStore(tmp_path)
    record = run_trial(experiment("smoke"), "tiny", 0)
    store.write(record)
    stranger = TrialRecord.from_dict({**record.to_dict(), "cell": "retired"})
    store.write(stranger)

    cells = [row[0] for row in outcome_table(list(store.read_experiment("smoke")),
                                             cell_order=("tiny",)).rows]
    assert cells == ["tiny", "retired"]
