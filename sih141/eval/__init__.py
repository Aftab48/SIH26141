"""The Phase 5 evaluation harness: run trials, store them, reduce them to tables.

Phase 5's only product is numbers, and D9 is the rule that makes them worth
having: **every published number is reproducible from a recorded seed and a
committed command**. That is a constraint on the plumbing before it is a
constraint on the tables, and this package is the plumbing.

The two halves are separable on purpose. ``tools/sweep.py run`` executes trials
and writes one file per trial; ``tools/sweep.py reduce`` reads whatever is on
disk and regenerates every table. The long sweep happens once, whenever the
human likes; the tables can be redrawn a hundred times without re-running
anything, and a table that could only be produced by a fourteen-hour run is a
table nobody will check.

The pieces
----------
:mod:`~sih141.eval.seeds`
    Where a trial's randomness comes from: a pure function of ``(experiment,
    cell, role, index)``, so a result depends on its seed and on nothing else --
    not on worker count, not on scheduling, not on which core it landed.
:mod:`~sih141.eval.records`
    The reduced per-trial record, and the wall between the harness's ground
    truth and the evidence the detector was allowed to read.
:mod:`~sih141.eval.store`
    One file per trial, written atomically as it completes, named from the
    trial's identity so a resumed sweep skips what is done.
:mod:`~sih141.eval.manifest`
    The commit, the command, the seed rule, the workers and the machine -- what
    makes D9 checkable rather than aspirational.
:mod:`~sih141.eval.experiments`
    Cells, scenarios and the registry. Adding an adversary is one function.
:mod:`~sih141.eval.runner`
    The process pool, the BLAS thread pinning that keeps it from being slower
    than serial, and the resume logic.
:mod:`~sih141.eval.reduce`
    Records to tables, with the denominators stated, the aborts kept out of the
    rejections, and ``measured`` never sharing a column with ``proven``.
:mod:`~sih141.eval.perf`
    The measured throughput of this machine, and the projections derived from
    it as doctests rather than prose.

What the tables are not allowed to do
-------------------------------------
Phases 3 and 4 were audited at real cost, and the findings are constraints on
the *tables*, not just the code. The three that this package enforces in types
rather than in documentation:

* **A refusal is not a rejection.** Aborts live in their own transcript field
  with their own type, and the reduction counts them separately through
  :class:`~sih141.detect.thresholds_structural.OutcomeTally`, which has no
  field that sums a rejection with a no-verdict.
* **The two count orderings are never pooled.** ``count_exchange_timing`` is a
  grouping key on every row. ``OutcomeTally.merge`` refuses two tallies that
  disagree on it.
* **Measured is not proven.** A detection rate is a measurement with a sample
  size and a confidence interval; a false-positive bound is proven under the
  honest null. :mod:`~sih141.eval.reduce` puts the word on the column and the
  two never share one.

Examples
--------
The registry is open: a Phase 5 family adds its experiments from its own
module, so this asserts that the four the harness itself ships are present
rather than that nothing else is. A literal list here would have to be edited
by every family that registers one, which is a merge conflict standing in for
a check nobody wants.

>>> from sih141.eval import EXPERIMENTS, trial_seeds
>>> set(EXPERIMENTS) >= {'honest', 'noise', 'scaling', 'smoke'}
True
>>> [name for name in ('honest', 'noise', 'scaling', 'smoke')
...  if name not in EXPERIMENTS]
[]
>>> trial_seeds("honest", "l192", 0).session
15537000204045215064
"""

from __future__ import annotations

from . import experiments, manifest, perf, records, reduce, runner, seeds, store
from . import roc
from . import security
from .experiments import (
    DEFAULT_EPS,
    EXPERIMENTS,
    SCENARIOS,
    Cell,
    Experiment,
    Scenario,
    all_cells,
    depolarising_scenario,
    experiment,
    honest_scenario,
    run_trial,
)
from .manifest import (
    HARNESS_VERSION,
    MANIFEST_SCHEMA,
    RunManifest,
    command_line,
    git_state,
    machine_facts,
    seed_derivation,
    utc_now,
)
from .records import (
    NON_DETERMINISTIC_FIELDS,
    RECORD_SCHEMA,
    UNDETECTABLE_BY_CONSTRUCTION,
    GroundTruth,
    TrialRecord,
    transcript_summary,
)
from .perf import (
    MEASURED_SESSIONS,
    REFERENCE_MS_PER_POSITION,
    detector_latency,
    projected_session_seconds,
    projected_sweep_hours,
    time_session,
)
from .reduce import (
    EXTRA_CHARTS,
    EXTRA_REDUCTIONS,
    Table,
    detection_table,
    outcome_table,
    reduce_experiment,
    timing_table,
)
from .roc import (
    EPS_LADDER,
    RocPoint,
    monotonicity_violations,
    reconciliation,
    roc_chart_svg,
    roc_points,
    roc_reduction,
    roc_table,
    score_ladder,
)
from .security import (
    FLOOR_CROSSOVER,
    FLOOR_LADDER,
    PER_VERIFIER_CROSSOVER,
    REPUDIATION_LADDER,
    SECURITY_PROBE_OPTIONS,
    SECURITY_SCENARIOS,
    TiltingPreparation,
    averaged_bound_log10,
    enforced_bound_log10,
    floor_table,
    forgery_reduction,
    forgery_table,
    gap_table,
    optimal_tilt,
    orthogonal_state,
    repudiated_from_verdicts,
    repudiation_curve_table,
    repudiation_reduction,
    security_charts,
    security_claim_at,
)
from .runner import (
    TrialOutcome,
    TrialSpec,
    default_results_root,
    pin_blas_threads,
    plan_trials,
    probe_pool,
    run_experiment,
    worker_probe,
)
from .seeds import (
    ADVERSARY_ROLE,
    NAME_PATTERN,
    SEED_DOMAIN,
    SEED_PERSON,
    SESSION_ROLE,
    TrialSeeds,
    check_name,
    trial_seed,
    trial_seeds,
)
from .store import DEFAULT_RESULTS_ROOT, MANIFEST_GLOB, TRIAL_GLOB, ResultStore

__all__ = [
    "ADVERSARY_ROLE",
    "Cell",
    "DEFAULT_EPS",
    "DEFAULT_RESULTS_ROOT",
    "EPS_LADDER",
    "EXPERIMENTS",
    "EXTRA_CHARTS",
    "EXTRA_REDUCTIONS",
    "Experiment",
    "FLOOR_CROSSOVER",
    "FLOOR_LADDER",
    "GroundTruth",
    "HARNESS_VERSION",
    "MANIFEST_GLOB",
    "MANIFEST_SCHEMA",
    "MEASURED_SESSIONS",
    "NAME_PATTERN",
    "NON_DETERMINISTIC_FIELDS",
    "PER_VERIFIER_CROSSOVER",
    "RECORD_SCHEMA",
    "REFERENCE_MS_PER_POSITION",
    "REPUDIATION_LADDER",
    "ResultStore",
    "RocPoint",
    "RunManifest",
    "SCENARIOS",
    "SECURITY_PROBE_OPTIONS",
    "SECURITY_SCENARIOS",
    "SEED_DOMAIN",
    "SEED_PERSON",
    "SESSION_ROLE",
    "Scenario",
    "TRIAL_GLOB",
    "Table",
    "TiltingPreparation",
    "TrialOutcome",
    "TrialRecord",
    "TrialSeeds",
    "TrialSpec",
    "UNDETECTABLE_BY_CONSTRUCTION",
    "all_cells",
    "averaged_bound_log10",
    "check_name",
    "default_results_root",
    "command_line",
    "depolarising_scenario",
    "detection_table",
    "detector_latency",
    "enforced_bound_log10",
    "experiment",
    "experiments",
    "floor_table",
    "forgery_reduction",
    "forgery_table",
    "gap_table",
    "git_state",
    "honest_scenario",
    "machine_facts",
    "manifest",
    "monotonicity_violations",
    "optimal_tilt",
    "orthogonal_state",
    "outcome_table",
    "perf",
    "pin_blas_threads",
    "plan_trials",
    "probe_pool",
    "projected_session_seconds",
    "projected_sweep_hours",
    "reconciliation",
    "records",
    "reduce",
    "reduce_experiment",
    "repudiated_from_verdicts",
    "repudiation_curve_table",
    "repudiation_reduction",
    "roc",
    "roc_chart_svg",
    "roc_points",
    "roc_reduction",
    "roc_table",
    "run_experiment",
    "run_trial",
    "runner",
    "score_ladder",
    "security",
    "security_charts",
    "security_claim_at",
    "seed_derivation",
    "seeds",
    "store",
    "time_session",
    "timing_table",
    "transcript_summary",
    "trial_seed",
    "trial_seeds",
    "utc_now",
    "worker_probe",
]
