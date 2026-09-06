"""What a sweep runs: cells, the scenarios that fill them, and the registry.

An **experiment** is a named set of **cells**; a cell is one row of one results
table, and it fixes everything except the trial index -- the parameter set, the
message bit, the detector budget, the null the detector is given, and which
scenario produces the run. A **scenario** is the function that actually
executes one trial and hands back the run together with the harness's label.

The split exists so that the runner never needs to know what an experiment is
about. It hands a scenario a cell and a pair of seeds and stores what comes
back, which means a later phase can add an adversary by writing one function and
registering it, with no change to the runner, the store, the manifest or the
reduction.

.. _scenario-contract:

The scenario contract
---------------------
A scenario has the signature::

    def scenario(cell: Cell, seeds: TrialSeeds) -> tuple[SessionTranscript,
                                                         GroundTruth]

and three obligations, each of which is a constraint the results table inherits:

1. **It takes its randomness from** ``seeds`` **and nowhere else.** The session
   gets ``seeds.session_rng()``, the adversary gets ``seeds.adversary_rng()``,
   and neither is ever handed the other's (D3, D6). A scenario that calls
   :func:`numpy.random.default_rng` with no argument, or touches the global
   ``numpy.random``, breaks the reproducibility claim the whole phase rests on;
   ``tests/test_eval_harness.py`` catches it by running every registered
   scenario twice and comparing.
2. **It reports ``engaged`` off the adversary's own log**, not off the cell's
   intent. A channel attack aimed at Bob's link engages on no Charlie hop, and
   an untargeted run is byte-identical to an honest one and must be scored as
   one. Phase 4's replay arm reported a clean 0/40 while having forwarded
   honestly; an arm reporting zero has to be able to prove it acted.
3. **It does not call the detector.** Detection happens in
   :func:`run_trial`, after the scenario has returned, from the transcript
   alone. There is no argument by which the label could reach it.

Examples
--------
The registry is open: a Phase 5 experiment family registers from its own module
at import, so this asserts that the four the harness itself ships are still
there rather than that nothing else is. Pinning the literal list would make
every family that registers one edit this line, which is a merge conflict
standing in for a check nobody wants.

>>> from sih141.eval.experiments import EXPERIMENTS, experiment
>>> set(EXPERIMENTS) >= {'honest', 'noise', 'scaling', 'smoke'}
True
>>> honest = experiment("honest")
>>> [cell.name for cell in honest.cells]
['l192', 'l384', 'l768']
>>> honest.cell("l192").params.key_length
192

Every ``noise`` cell but the first departs from the noiseless null the detector
defaults to, which is exactly the situation Phase 4 audit finding A3-1 is about:

>>> [c.name for c in experiment("noise").cells]
['clean', 'p0025', 'p005', 'p010', 'p015', 'p03125']
>>> {c.channel_error_rate for c in experiment("noise").cells}
{0.0}
>>> [c.scenario_options["strength"] for c in experiment("noise").cells]
[0.0, 0.0025, 0.005, 0.01, 0.015, 0.03125]

One trial, end to end, seeds in and a labelled record out. The detector's
``key_length`` is the *signing* length, 72 of the cell's 96 positions, because
the other 24 went to check rounds:

>>> from sih141.eval.experiments import run_trial
>>> record = run_trial(experiment("smoke"), "tiny", 0)
>>> record.identity
('smoke', 'tiny', 0)
>>> record.truth.hypothesis, record.truth.engaged
('honest', False)
>>> record.detection["key_length"]
72
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Final, Mapping, Sequence

from sih141.attacks.channel import DepolarisingChannel
from sih141.detect.detector import detect
from sih141.detect.statistics import TranscriptStatistics
from sih141.protocol.params import ProtocolParams
from sih141.protocol.session import QDSSession, SessionTranscript

from .records import GroundTruth, TrialRecord
from .seeds import TrialSeeds, check_name, trial_seeds

__all__ = [
    "Cell",
    "DEFAULT_EPS",
    "EXPERIMENTS",
    "Experiment",
    "SCENARIOS",
    "SCENARIO_PROBE_OPTIONS",
    "Scenario",
    "all_cells",
    "claim",
    "experiment",
    "honest_scenario",
    "depolarising_scenario",
    "run_trial",
]

DEFAULT_EPS: Final[float] = 1e-9
"""float: The detector budget a cell inherits when it names none.

Matches the budget Phase 4's own examples are stated at, so a Phase 5 number
and a Phase 4 doctest are comparable without a conversion.
"""


@dataclass(frozen=True)
class Cell:
    """One row of one results table: everything fixed except the trial index.

    Attributes
    ----------
    name : str
        Cell name, matching :data:`~sih141.eval.seeds.NAME_PATTERN`. It is a
        directory component and part of the seed material, so it may not be
        changed once trials exist without re-seeding the cell.
    params : ProtocolParams
        The parameter set every trial in this cell runs at.
    scenario : str
        Key into :data:`SCENARIOS`.
    scenario_options : Mapping
        Passed to the scenario. Recorded nowhere else, so anything that changes
        what the cell measures belongs here rather than in a closure.
    message_bit : int
        Which bit is signed.
    eps : float
        Detector budget.
    channel_error_rate : float
        ``p_e``, the null handed to :func:`~sih141.detect.detector.detect` for
        the rate family. Defaults to ``0.0``, the **noiseless** null. Left at
        zero on a genuinely noisy link the mismatch members fire on honest
        runs, correctly, which is Phase 4 audit finding A3-1; the cell's
        choice rides onto every record as
        :attr:`~sih141.eval.records.TrialRecord.null_is_noiseless` so a table
        can carry it as a column instead of a caveat.
    tolerated_depolarising : float
        ``p0``, the channel family's null, as a Werner strength. Deliberately
        separate from ``channel_error_rate``: the two parameterise the same
        physics and converting silently would state a null the cell did not
        ask for.
    truth_hypothesis : str
        The harness's label for what this cell does.
    detectable : bool
        ``False`` where an assumption rules detection out -- full
        impersonation under (AUTH). The reduction prints
        ``undetectable-by-construction`` for such a row rather than a zero.
    retain_transcript : bool
        Keep the whole transcript on every record. About 25.4 MiB per trial
        at ``L = 115200`` unchecked and 37.2 MiB at ``check_fraction = 0.25``,
        so reserved for named worked examples.
    notes : str
        Footnote for the row.

    Raises
    ------
    TypeError, ValueError
        If a field has the wrong type, or the name is illegal, or the scenario
        is not registered.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="l192", params=ProtocolParams(key_length=192))
    >>> cell.scenario, cell.eps, cell.channel_error_rate
    ('honest', 1e-09, 0.0)
    >>> Cell(name="l192", params=ProtocolParams(key_length=192),
    ...      scenario="not-a-scenario")
    Traceback (most recent call last):
        ...
    ValueError: unknown scenario 'not-a-scenario'...
    """

    name: str
    params: ProtocolParams
    scenario: str = "honest"
    scenario_options: Mapping[str, Any] = field(default_factory=dict)
    message_bit: int = 0
    eps: float = DEFAULT_EPS
    channel_error_rate: float = 0.0
    tolerated_depolarising: float = 0.0
    truth_hypothesis: str = "honest"
    detectable: bool = True
    retain_transcript: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        """Validate the cell.

        Raises
        ------
        TypeError
            If a field has the wrong type.
        ValueError
            If the name is illegal or the scenario is not registered.
        """
        check_name(self.name, what="cell")
        if not isinstance(self.params, ProtocolParams):
            raise TypeError(
                f"params must be ProtocolParams, got {type(self.params).__name__}"
            )
        if self.scenario not in SCENARIOS:
            raise ValueError(
                f"unknown scenario {self.scenario!r}; registered scenarios are "
                f"{sorted(SCENARIOS)}"
            )
        if self.message_bit not in (0, 1):
            raise ValueError(f"message_bit must be 0 or 1, got {self.message_bit!r}")
        if not 0.0 < float(self.eps) < 1.0:
            raise ValueError(f"eps must lie in (0, 1), got {self.eps!r}")
        for name in ("channel_error_rate", "tolerated_depolarising"):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must lie in [0, 1], got {value!r}")

    @property
    def null_is_noiseless(self) -> bool:
        """bool: Whether this cell scores against a noiseless null."""
        return float(self.channel_error_rate) == 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view, for the manifest.

        Returns
        -------
        dict
        """
        return {
            "name": self.name,
            "params": self.params.to_dict(),
            "scenario": self.scenario,
            "scenario_options": dict(self.scenario_options),
            "message_bit": self.message_bit,
            "eps": float(self.eps),
            "channel_error_rate": float(self.channel_error_rate),
            "tolerated_depolarising": float(self.tolerated_depolarising),
            "truth_hypothesis": self.truth_hypothesis,
            "detectable": self.detectable,
            "retain_transcript": self.retain_transcript,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Experiment:
    """A named set of cells, and the unit ``tools/sweep.py run`` takes.

    Attributes
    ----------
    name : str
        Experiment name, matching :data:`~sih141.eval.seeds.NAME_PATTERN`.
    cells : tuple of Cell
        In table order.
    trials : int
        Default trials per cell; overridable on the command line.
    description : str
        One line, printed above the table.

    Raises
    ------
    TypeError, ValueError
        If a field has the wrong type, the name is illegal, or two cells share
        a name -- which would put two different measurements in one directory.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment
    >>> smoke = experiment("smoke")
    >>> smoke.name, [c.name for c in smoke.cells], smoke.trials
    ('smoke', ['tiny'], 4)
    >>> smoke.cell("absent")
    Traceback (most recent call last):
        ...
    KeyError: "experiment 'smoke' has no cell 'absent'; it has ['tiny']"
    """

    name: str
    cells: tuple[Cell, ...]
    trials: int = 30
    description: str = ""

    def __post_init__(self) -> None:
        """Validate the experiment.

        Raises
        ------
        TypeError
            If a field has the wrong type.
        ValueError
            If the name is illegal, the cells are empty, two share a name, or
            ``trials`` is not positive.
        """
        check_name(self.name, what="experiment")
        if not self.cells:
            raise ValueError(f"experiment {self.name!r} has no cells")
        for cell in self.cells:
            if not isinstance(cell, Cell):
                raise TypeError(f"cells must be Cell, got {type(cell).__name__}")
        names = [cell.name for cell in self.cells]
        if len(set(names)) != len(names):
            raise ValueError(
                f"experiment {self.name!r} has duplicate cell names: {names}. "
                f"Two cells sharing a name share a directory and a seed "
                f"stream, so one would overwrite the other's trials."
            )
        if isinstance(self.trials, bool) or not isinstance(self.trials, int):
            raise TypeError("trials must be an int")
        if self.trials <= 0:
            raise ValueError(f"trials must be positive, got {self.trials}")

    @property
    def cell_names(self) -> tuple[str, ...]:
        """tuple of str: The cell names, in table order."""
        return tuple(cell.name for cell in self.cells)

    def cell(self, name: str) -> Cell:
        """Return one cell by name.

        Parameters
        ----------
        name : str
            Cell name.

        Returns
        -------
        Cell

        Raises
        ------
        KeyError
            If no such cell exists, naming the ones that do.
        """
        for cell in self.cells:
            if cell.name == name:
                return cell
        raise KeyError(
            f"experiment {self.name!r} has no cell {name!r}; it has "
            f"{list(self.cell_names)}"
        )


Scenario = Callable[[Cell, TrialSeeds], "tuple[SessionTranscript, GroundTruth]"]
"""Callable: The scenario contract; see :ref:`scenario-contract`."""


def honest_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Run one honest session. No adversary, and the label says so.

    Parameters
    ----------
    cell : Cell
        The cell being run.
    seeds : TrialSeeds
        The trial's seeds. Only :meth:`~sih141.eval.seeds.TrialSeeds.session_rng`
        is drawn on; the adversary seed is left untouched, which is the visible
        difference between this scenario and one that mounts an attack.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, honest_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="tiny", params=ProtocolParams(key_length=48))
    >>> run, truth = honest_scenario(cell, trial_seeds("demo", "tiny", 0))
    >>> truth.hypothesis, truth.engaged, truth.engaged_count
    ('honest', False, 0)
    >>> run.is_complete
    True
    """
    session = QDSSession(cell.params, rng=seeds.session_rng())
    transcript = session.run(cell.message_bit)
    return transcript, GroundTruth(
        hypothesis=cell.truth_hypothesis,
        engaged=False,
        engaged_count=0,
        detectable=cell.detectable,
        notes=cell.notes,
    )


def depolarising_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Run a session over a depolarising wire, and label it from the wire's log.

    The adversary owns its randomness (D6): it is constructed from
    :meth:`~sih141.eval.seeds.TrialSeeds.adversary_rng`, which is a different
    stream from the session's, and it is never shown the session's generator.

    Parameters
    ----------
    cell : Cell
        The cell. ``scenario_options`` takes ``strength`` (the Werner ``p``,
        required) and ``target`` (``"Bob"``, ``"Charlie"`` or ``None`` for
        both).
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` is the attack's own count of the hops it actually
        touched, so a strength-zero cell honestly reports zero and is scored as
        an honest run rather than as a missed detection.

    Raises
    ------
    KeyError
        If ``strength`` is absent from ``scenario_options``. Defaulting it to
        zero would turn a typo into a silently inert arm, which is the exact
        failure Phase 4's replay arm shipped.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, depolarising_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=96, check_fraction=0.25)
    >>> cell = Cell(
    ...     name="p050", params=params, scenario="depolarising",
    ...     scenario_options={"strength": 0.5, "target": "Bob"},
    ...     truth_hypothesis="channel-manipulation",
    ... )
    >>> run, truth = depolarising_scenario(cell, trial_seeds("demo", "p050", 0))
    >>> truth.hypothesis, truth.targeted_link
    ('channel-manipulation', 'Bob')
    >>> truth.engaged, truth.engaged_count > 0
    (True, True)

    A strength of zero touches nothing, and the label refuses to pretend
    otherwise -- this run is honest and a table must score it as one:

    >>> quiet = Cell(
    ...     name="p000", params=params, scenario="depolarising",
    ...     scenario_options={"strength": 0.0},
    ...     truth_hypothesis="channel-manipulation",
    ... )
    >>> _, label = depolarising_scenario(quiet, trial_seeds("demo", "p000", 0))
    >>> label.engaged, label.engaged_count
    (False, 0)
    """
    options = dict(cell.scenario_options)
    if "strength" not in options:
        raise KeyError(
            f"cell {cell.name!r} uses the depolarising scenario but names no "
            f"'strength' in scenario_options. There is no default: a missing "
            f"strength would run an inert arm that looks exactly like a "
            f"detector finding nothing."
        )
    strength = float(options["strength"])
    target = options.get("target")
    attack = DepolarisingChannel(
        strength, rng=seeds.adversary_rng(), target=target
    )
    session = QDSSession(
        cell.params, resource_factory=attack.resource, rng=seeds.session_rng()
    )
    transcript = session.run(cell.message_bit)
    engaged_count = int(attack.engaged_count)
    return transcript, GroundTruth(
        hypothesis=cell.truth_hypothesis,
        engaged=engaged_count > 0,
        engaged_count=engaged_count,
        targeted_link=None if target is None else str(target),
        detectable=cell.detectable,
        notes=cell.notes,
    )


SCENARIOS: Final[dict[str, Scenario]] = {
    "honest": honest_scenario,
    "depolarising": depolarising_scenario,
}
"""dict: Registered scenarios, by name.

Adding an adversary to Phase 5 means writing one function to the contract in
:ref:`scenario-contract` and adding it here. Nothing in the runner, the store,
the manifest or the reduction needs to change.
"""

SCENARIO_PROBE_OPTIONS: Final[dict[str, dict[str, Any]]] = {
    "depolarising": {"strength": 0.25},
}
"""dict: The smallest ``scenario_options`` that make each scenario run at all.

A scenario is entitled to refuse a missing option rather than default it --
``depolarising`` does, and so does every adversary a Phase 5 family has added,
because a defaulted typo is how an inert arm comes to report a clean zero. The
cost is that a scenario cannot then be exercised generically, and
``tests/test_eval_harness.py`` has a contract test that runs *every* registered
scenario twice and compares. This is what that test reads.

**A family that registers a scenario registers its probe options here too**,
from its own module, beside the scenario. A scenario that needs options and
appears in neither place raises in that test rather than being skipped, which
is the intended failure: a scenario nobody can construct is a scenario nobody
has checked.

Examples
--------
>>> from sih141.eval.experiments import SCENARIO_PROBE_OPTIONS
>>> SCENARIO_PROBE_OPTIONS["depolarising"]
{'strength': 0.25}
"""


def claim(registry: dict[str, Any], name: str, value: Any, what: str) -> None:
    """Put ``value`` in ``registry`` under ``name``, refusing to displace another.

    The one guard every Phase 5 family uses for every registry it writes to --
    :data:`SCENARIOS`, :data:`SCENARIO_PROBE_OPTIONS`, :data:`EXPERIMENTS`,
    ``reduce.EXTRA_REDUCTIONS`` and ``reduce.EXTRA_CHARTS``. It takes the
    registry as an argument rather than importing it, so a family can claim a
    key in a module this one does not import.

    Parameters
    ----------
    registry : dict
        A shared Phase 5 registry.
    name : str
        The key this family claims.
    value : object
        What it claims the key for.
    what : str
        Noun for the error message, e.g. ``"scenario"``.

    Raises
    ------
    RuntimeError
        If the key is already held by something that is not ``value``.

    Notes
    -----
    Symmetric on purpose, and it is the second half that is easy to get wrong.
    A guard that refuses to *overwrite* but silently *yields* -- ``setdefault``,
    or ``if key not in registry`` -- leaves the losing family registered
    nowhere and its cells never run, which looks from the outside exactly like
    a family nobody wrote. A guard that silently overwrites gives whichever
    family imported last. Both directions are a collision and both raise.

    Re-claiming a key for the identical object is a no-op, which is what makes
    a family's ``register()`` idempotent under a repeated import.

    Examples
    --------
    Claiming a free key, then re-claiming it for the same object:

    >>> from sih141.eval.experiments import claim
    >>> registry: dict[str, object] = {}
    >>> claim(registry, "mine", len, "scenario")
    >>> claim(registry, "mine", len, "scenario")
    >>> registry
    {'mine': <built-in function len>}

    Both directions of collision raise, and the registry is left alone:

    >>> claim(registry, "mine", sorted, "scenario")
    Traceback (most recent call last):
        ...
    RuntimeError: scenario 'mine' is already registered to something else...
    >>> registry["mine"] is len
    True
    """
    existing = registry.get(name)
    if existing is not None and existing is not value:
        raise RuntimeError(
            f"{what} {name!r} is already registered to something else "
            f"({existing!r}). Two Phase 5 families sharing a registry key "
            f"would give whichever imported last, silently, and the other's "
            f"cells would run under the wrong label or not at all."
        )
    registry[name] = value


def run_trial(
    exp: Experiment,
    cell_name: str,
    index: int,
    *,
    retain_transcript: bool | None = None,
) -> TrialRecord:
    """Execute one trial and return its reduced record.

    The only place the detector is called, and it is called on the transcript's
    JSON with nothing but the cell's budget and nulls. The label is attached
    after :func:`~sih141.detect.detector.detect` has already returned, so there
    is no argument, closure or attribute by which it could have been read; see
    :ref:`truth-wall`.

    Parameters
    ----------
    exp : Experiment
        The experiment.
    cell_name : str
        Which cell.
    index : int
        Zero-based trial index within the cell.
    retain_transcript : bool or None, optional
        Keyword-only. Overrides the cell's own setting; ``None`` uses it.

    Returns
    -------
    TrialRecord

    Raises
    ------
    KeyError
        If the cell does not exist, or a scenario needs an option it was not
        given.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment, run_trial
    >>> record = run_trial(experiment("smoke"), "tiny", 1)
    >>> record.index, record.cell, record.flagged
    (1, 'tiny', False)
    >>> record.seeds["session"] > 0
    True
    >>> set(record.wall_clock) == {"session_seconds", "detect_seconds",
    ...                            "total_seconds"}
    True
    """
    cell = exp.cell(cell_name)
    seeds = trial_seeds(exp.name, cell.name, index)
    scenario = SCENARIOS[cell.scenario]

    started = time.perf_counter()
    transcript, truth = scenario(cell, seeds)
    after_session = time.perf_counter()

    # The whole detector interface Phase 5 is allowed to use. The transcript is
    # serialised first so that what the detector reads is exactly what a
    # reviewer could read from a saved file -- no live object, no back-door.
    text = transcript.to_json()
    stats = TranscriptStatistics.from_json(text)
    detection = detect(
        stats,
        eps=cell.eps,
        channel_error_rate=cell.channel_error_rate,
        tolerated_depolarising=cell.tolerated_depolarising,
    )
    finished = time.perf_counter()

    keep = cell.retain_transcript if retain_transcript is None else retain_transcript
    return TrialRecord.build(
        seeds=seeds,
        params=cell.params,
        eps=cell.eps,
        transcript=transcript,
        detection=detection,
        truth=truth,
        wall_clock={
            "session_seconds": after_session - started,
            "detect_seconds": finished - after_session,
            "total_seconds": finished - started,
        },
        retain_transcript=keep,
        stats=stats,
    )


def _honest_experiment() -> Experiment:
    """Build the honest-baseline experiment.

    Returns
    -------
    Experiment
        Three key lengths with check rounds, all honest, all scored against the
        noiseless null they actually ran on. What it measures is the
        false-positive rate -- and because the link really is noiseless, the
        null is the truth and the measurement is comparable with the proven
        bound on every record.
    """
    return Experiment(
        name="honest",
        description=(
            "Honest runs on a noiseless link at three key lengths: the "
            "false-positive arm, measured against a proven bound."
        ),
        trials=30,
        cells=tuple(
            Cell(
                name=f"l{length}",
                params=ProtocolParams(key_length=length, check_fraction=0.25),
                notes="honest, noiseless link, noiseless null",
            )
            for length in (192, 384, 768)
        ),
    )


def _noise_experiment() -> Experiment:
    """Build the honest-but-noisy experiment.

    Returns
    -------
    Experiment
        Honest parties over a depolarising wire at six strengths, every cell
        scored against the **noiseless** null. That is deliberate and is the
        arm that reproduces Phase 4 audit finding A3-1: an honest run over a
        noisy link departs from a noiseless null and is reported as a
        detection, with a proven bound, correctly. The cells exist so the
        reduction has a table where ``null_is_noiseless`` is load-bearing
        rather than decorative.
    """
    params = ProtocolParams(key_length=384, check_fraction=0.25)
    # The last two carry the dashboard's calibration panel, whose figures had no
    # recorded seed or command until they were measured here. 0.03125 is 2*s_a,
    # the design noise level, and is the row the panel's warning is about.
    levels = (
        ("clean", 0.0),
        ("p0025", 0.0025),
        ("p005", 0.005),
        ("p010", 0.01),
        ("p015", 0.015),
        ("p03125", 0.03125),
    )
    return Experiment(
        name="noise",
        description=(
            "Honest parties over a depolarising wire, scored against the "
            "noiseless null: the arm where null_is_noiseless is the column "
            "that decides whether the row is a false claim."
        ),
        trials=30,
        cells=tuple(
            Cell(
                name=name,
                params=params,
                scenario="depolarising",
                scenario_options={"strength": strength, "target": None},
                truth_hypothesis="honest" if strength == 0.0 else "channel-noise",
                notes=f"depolarising strength {strength}, noiseless null",
            )
            for name, strength in levels
        ),
    )


def _scaling_experiment() -> Experiment:
    """Build the throughput-against-key-length experiment.

    Returns
    -------
    Experiment
        Honest runs at four key lengths spanning a 32-fold range. Its purpose
        is the performance section rather than a security claim: run through
        the same runner and the same store as everything else, so the timing
        table it produces can be checked against the sweep's own manifest. If
        aggregate throughput and the manifest disagree, one of them is wrong.
    """
    return Experiment(
        name="scaling",
        description=(
            "Throughput against key length, measured through the real "
            "runner so it can be checked against the run manifest."
        ),
        trials=20,
        cells=tuple(
            Cell(
                name=f"l{length}",
                params=ProtocolParams(key_length=length, check_fraction=0.25),
                notes="performance measurement; carries no security claim",
            )
            for length in (192, 768, 3072, 12288)
        ),
    )


def _smoke_experiment() -> Experiment:
    """Build the tiny experiment the tests and the CLI's ``--dry-run`` use.

    Returns
    -------
    Experiment
        One cell, ``L = 96``, four trials. Small enough that the whole
        determinism suite runs in seconds and large enough that the protocol
        actually completes.
    """
    return Experiment(
        name="smoke",
        description="A four-trial cell at L=96, for exercising the harness.",
        trials=4,
        cells=(
            Cell(
                name="tiny",
                params=ProtocolParams(key_length=96, check_fraction=0.25),
                notes="harness smoke test; carries no security claim",
            ),
        ),
    )


EXPERIMENTS: Final[dict[str, Experiment]] = {
    exp.name: exp
    for exp in (
        _honest_experiment(),
        _noise_experiment(),
        _scaling_experiment(),
        _smoke_experiment(),
    )
}
"""dict: The registered experiments, by name.

Deliberately short. The harness is the deliverable of this step and these four
are what prove it works end to end -- an honest arm, an arm whose null is
knowingly wrong, a throughput arm for the performance section, and a four-trial
cell for the tests. Later phases add cells and scenarios; nothing about adding
one touches the runner.
"""


def experiment(name: str) -> Experiment:
    """Return a registered experiment by name.

    Parameters
    ----------
    name : str
        Experiment name.

    Returns
    -------
    Experiment

    Raises
    ------
    KeyError
        If no such experiment is registered, naming the ones that are.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment
    >>> experiment("honest").name
    'honest'
    >>> experiment("nope")
    Traceback (most recent call last):
        ...
    KeyError: "no experiment named 'nope'; registered: [...'scaling', 'smoke']"
    """
    try:
        return EXPERIMENTS[name]
    except KeyError:
        raise KeyError(
            f"no experiment named {name!r}; registered: {sorted(EXPERIMENTS)}"
        ) from None


def all_cells(exp: Experiment, only: Sequence[str] | None = None) -> tuple[Cell, ...]:
    """Return the cells to run, filtered by name.

    Parameters
    ----------
    exp : Experiment
        The experiment.
    only : Sequence of str or None, optional
        Cell names to keep, in the experiment's own order. ``None`` keeps all.

    Returns
    -------
    tuple of Cell

    Raises
    ------
    KeyError
        If a requested cell does not exist.

    Examples
    --------
    >>> from sih141.eval.experiments import all_cells, experiment
    >>> [c.name for c in all_cells(experiment("honest"), ["l768", "l192"])]
    ['l192', 'l768']
    """
    if only is None:
        return exp.cells
    wanted = set(only)
    for name in wanted:
        exp.cell(name)
    return tuple(cell for cell in exp.cells if cell.name in wanted)

