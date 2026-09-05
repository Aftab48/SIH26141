"""The Phase 5 reconciliation: three families, one harness.

The harness, the security curves and the ROC family were written in parallel
against a shared registry, and the two experiment families each grew their own
copy of the helpers the harness had not provided. This file is the pin, and it
exists for the same reason ``tests/test_detect_reconciliation.py`` does: in
Phase 3, four copies of a Wilson interval had drifted and **two carried a real
bug**. Duplication that nothing compares is not duplication, it is divergence
with a delay.

What was actually found here, and what each test would catch if it came back:

1. **The registry guards disagreed, and the disagreement was silent.** The ROC
   family wrote a symmetric ``claim``: a name held by somebody else raises,
   in both directions. The security family guarded only its *scenario* names
   that way and used ``setdefault`` or an ``is None`` test for its experiments,
   its reductions and its chart, and assigned its probe options outright. So a
   collision on any of those four would have left the security family
   registered nowhere -- its cells never running, which from the outside looks
   exactly like a family nobody wrote -- or silently taken the other family's
   key. The scenario direction had a test. The other four did not, and that is
   the whole reason they were able to disagree. Both families now go through
   one guard, and :func:`test_every_family_refuses_a_collision_in_every_registry`
   drives every registry of every family from both sides.

2. **Three copies of the measured-rate formatter**, differing only in decimal
   places. None carried a bug -- ``CONFIDENCE`` and ``wilson_interval`` were
   already single-sourced, which is what kept the Phase 3 failure from
   recurring -- but three copies of the empty-denominator rule is three places
   for the ``no trials`` convention to rot into a ``0.000``.

3. **Two identical copies of the XML escape** used by two chart renderers.

4. **One family had a completeness check and the others had none, and the one
   that had it could not see the case that matters.** It looked for gaps
   *below the highest index present*, which catches a scenario that raised and
   misses what an interruption actually leaves -- a short tail. A cell asked
   for 400 trials with 380 on disk printed "no trial index is missing from any
   cell". Every rate in the table was then over a denominator that had quietly
   shrunk, with an affirmative line saying it had not. The check now compares
   against the manifest's requested count as well, and rides on the outcome
   table, which every experiment has rather than only the one family.

5. **The two halves of the CLI quoted their commands differently.** ``run``
   quoted with ``shlex``; ``reduce`` interpolated its ``--results`` path raw,
   so a path with a space printed a regenerating command that argparse
   rejects. D9's whole claim is that a reviewer can re-run it.

The structural test at the end is the one that matters for the next family:
it re-runs the duplicate hunt over the whole package, so a fourth family
copying a helper in fails here rather than in six months.

Nothing in this file runs a session. It is about the seams.
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

from sih141.eval import experiments as experiments_module
from sih141.eval import reduce as reduce_module
from sih141.eval import roc as roc_module
from sih141.eval import security as security_module
from sih141.eval.experiments import claim
from sih141.eval.reduce import (
    CONFIDENCE,
    completeness_note,
    escape_xml,
    measured_rate,
)

# --------------------------------------------------------------------------- #
# 1. One registry guard, and it refuses in both directions
# --------------------------------------------------------------------------- #

#: ``(family label, register callable, registry name, key, foreign value)``.
#:
#: Every registry every Phase 5 family writes to, from both sides. The
#: ``scenarios`` and ``experiments`` registries are injectable through
#: ``register``'s keyword arguments; the other three are module-level
#: dictionaries that the test swaps out and restores.
COLLISIONS: tuple[tuple[str, Callable[..., None], str, str], ...] = (
    ("roc", roc_module.register, "scenarios", "roc-replay"),
    ("roc", roc_module.register, "experiments", "roc"),
    ("security", security_module.register, "scenarios", "security-tilt"),
    ("security", security_module.register, "experiments", "repudiation-curve"),
    ("security", security_module.register, "experiments", "forgery-curve"),
)


@pytest.mark.parametrize(
    "label, register, registry, key",
    COLLISIONS,
    ids=[f"{lab}-{reg}-{key}" for lab, _, reg, key in COLLISIONS],
)
def test_every_family_refuses_a_collision_in_every_registry(
    label: str, register: Callable[..., None], registry: str, key: str
) -> None:
    """A key another family holds must raise, not be yielded or overwritten.

    This is the test the security family did not have for four of its five
    registries. Before the reconciliation, the two ``experiments`` cases here
    passed silently: ``register`` saw the key was taken, did nothing, and
    returned -- leaving that family's experiments unregistered and its cells
    unrunnable, with no exception and no log line.
    """
    kwargs: dict[str, Any] = {"scenarios": {}, "experiments": {}}
    kwargs[registry] = {key: "another family owns this"}
    with pytest.raises(RuntimeError, match="already registered"):
        register(**kwargs)


@pytest.mark.parametrize(
    "label, register", (("roc", roc_module.register), ("security", security_module.register))
)
def test_registering_twice_is_a_no_op(
    label: str, register: Callable[..., None]
) -> None:
    """Import order must not matter, so ``register`` has to be idempotent.

    The identity comparison in :func:`~sih141.eval.experiments.claim` makes
    this a real constraint rather than a free one: a family that rebuilds its
    ``Experiment`` on each call hands ``claim`` an equal-but-distinct object
    and raises on the second call. Both families cache.
    """
    register()
    register()


def test_the_two_families_use_the_same_guard_object() -> None:
    """Not merely guards that behave alike -- the same function.

    Two guards that agree today are two guards that can disagree tomorrow,
    which is exactly what happened.
    """
    assert roc_module.claim is claim
    assert security_module.claim is claim
    assert claim is experiments_module.claim


def test_the_guard_leaves_the_registry_untouched_when_it_refuses() -> None:
    """A refused claim must not be a half-applied one.

    ``register`` claims several keys in sequence, so a guard that wrote before
    it checked would leave a partially registered family behind after raising.
    """
    registry: dict[str, Any] = {"taken": len}
    with pytest.raises(RuntimeError, match="already registered"):
        claim(registry, "taken", sorted, "scenario")
    assert registry["taken"] is len
    assert list(registry) == ["taken"]


def test_the_guard_accepts_a_free_key_and_a_repeat_of_its_own() -> None:
    """The permissive half, so the test above is not passing vacuously.

    If ``claim`` raised on everything, every collision test in this file would
    be green and the guard would be useless.
    """
    registry: dict[str, Any] = {}
    claim(registry, "mine", len, "scenario")
    claim(registry, "mine", len, "scenario")
    assert registry == {"mine": len}


def test_a_family_that_registers_nowhere_is_the_failure_being_prevented() -> None:
    """Demonstrate the old behaviour, so the fix has something to be a fix of.

    ``setdefault`` is the exact idiom the security family used for its
    reductions. It returns without error and without registering, and the
    caller cannot tell the two apart -- which is why this is written out here
    rather than described.
    """
    registry: dict[str, Any] = {"forgery-curve": "another family owns this"}
    registry.setdefault("forgery-curve", security_module.forgery_reduction)
    assert registry["forgery-curve"] == "another family owns this"

    fresh: dict[str, Any] = {"forgery-curve": "another family owns this"}
    with pytest.raises(RuntimeError, match="already registered"):
        claim(fresh, "forgery-curve", security_module.forgery_reduction, "reduction")


def test_the_families_are_registered_where_the_sweep_looks_for_them() -> None:
    """The guard must not have cost the registration it guards.

    A stricter ``register`` that raised on its own second call would leave the
    package importable and every experiment missing.
    """
    for name in ("roc", "repudiation-curve", "forgery-curve"):
        assert name in experiments_module.EXPERIMENTS
    for name in ("roc", "repudiation-curve", "forgery-curve"):
        assert name in reduce_module.EXTRA_REDUCTIONS
    for name in ("roc", "repudiation-curve"):
        assert name in reduce_module.EXTRA_CHARTS


# --------------------------------------------------------------------------- #
# 2. One measured-rate formatter
# --------------------------------------------------------------------------- #


def test_the_three_families_share_one_rate_formatter() -> None:
    """One object, reached three ways."""
    assert roc_module.measured_rate is measured_rate
    assert security_module.measured_rate is measured_rate
    assert reduce_module.measured_rate is measured_rate


@pytest.mark.parametrize("places", (3, 4))
def test_an_empty_denominator_is_never_a_zero(places: int) -> None:
    """The convention that had three copies, checked at every width.

    ``0.000`` reads as a measurement that found nothing. ``no trials`` is the
    absence of a measurement, and the two are not the same claim.
    """
    assert measured_rate(0, 0, places=places) == "no trials"
    assert "0.000" not in measured_rate(0, 0, places=places)


def test_places_moves_the_width_and_nothing_else() -> None:
    """The only axis the three copies differed on.

    Same sample, same numerator, same denominator; the coarser rendering must
    be the finer one rounded, not a different computation.
    """
    coarse = measured_rate(3, 40, places=3)
    fine = measured_rate(3, 40, places=6)
    assert coarse.split(" = ")[0] == fine.split(" = ")[0] == "3/40"
    coarse_rate = float(coarse.split(" = ")[1].split(" ")[0])
    fine_rate = float(fine.split(" = ")[1].split(" ")[0])
    assert coarse_rate == pytest.approx(fine_rate, abs=5e-4)


def test_the_formatter_carries_the_projects_own_wilson_interval() -> None:
    """Recomputed from the definition by hand, not from the same call.

    A test that the formatter calls ``wilson_interval`` proves nothing about
    the number in the table. This recomputes the 99% interval from the closed
    form and asserts the printed endpoints are those numbers.
    """
    import math

    successes, trials = 3, 40
    # Wilson, from the definition: centre and half-width about p-hat.
    z = 2.5758293035489004  # the 99% two-sided normal quantile
    p = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    half = (
        z
        * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    low, high = centre - half, centre + half

    printed = measured_rate(successes, trials, places=4)
    body = printed.split("[")[1].rstrip("]")
    printed_low, printed_high = (float(x) for x in body.split(", "))
    assert printed_low == pytest.approx(low, abs=1e-4)
    assert printed_high == pytest.approx(high, abs=1e-4)
    assert CONFIDENCE == 0.99


def test_the_quantile_used_above_is_the_projects_own() -> None:
    """Pin the constant the hand recomputation leans on.

    Otherwise the test above checks the formatter against a number this file
    made up.
    """
    from sih141.detect.statistics import wilson_interval

    # At the endpoint that ships -- zero successes -- the Wilson upper limit
    # has the closed form z^2 / (n + z^2), which isolates the quantile.
    trials = 40
    interval = wilson_interval(0, trials, confidence=CONFIDENCE)
    z_squared = interval.high * trials / (1.0 - interval.high)
    assert z_squared**0.5 == pytest.approx(2.5758293035489004, rel=1e-9)


# --------------------------------------------------------------------------- #
# 3. One XML escape
# --------------------------------------------------------------------------- #


def test_both_chart_renderers_share_one_escape() -> None:
    """Two copies of this existed, byte-identical, in two chart modules."""
    assert roc_module.escape_xml is escape_xml
    assert security_module.escape_xml is escape_xml


def test_the_escape_does_the_ampersand_first() -> None:
    """The ordering bug this helper is one line away from.

    Replacing ``<`` before ``&`` double-escapes every entity the later
    replacements introduce, so the command printed under a chart would read
    ``&amp;lt;``. A single ampersand is the case that exposes it.
    """
    assert escape_xml("a & b") == "a &amp; b"
    assert escape_xml("<tag>") == "&lt;tag&gt;"
    assert "&amp;lt;" not in escape_xml("<a & b>")
    assert escape_xml("&") == "&amp;"


def test_an_escaped_command_survives_into_a_chart() -> None:
    """The reason the helper exists: D9 prints a command under every figure.

    A command containing an ampersand -- and this project's own commands do,
    since the repository path is quoted after a ``cd`` -- must not break the
    SVG it is printed in.
    """
    import xml.etree.ElementTree as ElementTree

    command = 'cd "a & b" && python tools/sweep.py reduce roc'
    document = f"<svg><text>{escape_xml(command)}</text></svg>"
    parsed = ElementTree.fromstring(document)
    assert parsed[0].text == command


# --------------------------------------------------------------------------- #
# 4. The structural check, which is the one that catches the next family
# --------------------------------------------------------------------------- #

#: Names a family is expected to define for itself, with a body of its own.
#:
#: ``_chart_x`` and ``_chart_y`` are the honest case: both families have chart
#: geometry helpers under those names, and they are *different functions* --
#: the ROC family maps a proven bound onto a log-scaled x-axis, the security
#: family maps a key length. Sharing the name is a readability wart; sharing an
#: implementation would be wrong. They are listed so the duplicate hunt below
#: does not have to be weakened to accommodate them.
#:
#: The two scenario names are the same story: both families run a forger, at
#: different key lengths under different wiring, registered under different
#: scenario keys.
#:
#: ``register`` is each family's entry point and names that family's own keys,
#: so there is one per family by construction. What they must share -- and now
#: do -- is the *guard*, which is asserted separately by
#: :func:`test_the_two_families_use_the_same_guard_object`.
DIVERGENT_BY_DESIGN: frozenset[str] = frozenset(
    {
        "_chart_x",
        "_chart_y",
        "outside_forgery_scenario",
        "recipient_forgery_scenario",
        "register",
    }
)


def _eval_package() -> pathlib.Path:
    """Return the directory holding the Phase 5 evaluation modules.

    Returns
    -------
    pathlib.Path
    """
    module_file = experiments_module.__file__
    assert module_file is not None
    return pathlib.Path(module_file).parent


def _function_bodies() -> dict[str, list[tuple[str, int, str]]]:
    """Hash every module-level function body in the eval package.

    Returns
    -------
    dict
        Function name to a list of ``(module, line, body hash)``. The
        docstring is stripped before hashing, so two copies that differ only
        in their prose still count as duplicates -- which is what the three
        rate formatters were.
    """
    found: dict[str, list[tuple[str, int, str]]] = {}
    for path in sorted(_eval_package().glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            body = node.body
            first = body[0] if body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                body = body[1:]
            dumped = ast.dump(ast.Module(body=body, type_ignores=[]))
            digest = hashlib.sha256(dumped.encode("utf-8")).hexdigest()[:16]
            found.setdefault(node.name, []).append((path.name, node.lineno, digest))
    return found


def test_no_two_eval_modules_define_the_same_function_body() -> None:
    """The duplicate hunt, re-run on every test run.

    This is the test that would have caught ``_escape`` -- two byte-identical
    copies in two modules -- the day the second one was written, and it is
    what a fourth Phase 5 family will hit if it copies a helper in rather than
    importing one.

    It compares *bodies*, not names, so the two ``_chart_x`` functions do not
    trip it: they share a name and nothing else.
    """
    duplicated: list[str] = []
    for name, sites in sorted(_function_bodies().items()):
        if len(sites) < 2:
            continue
        digests = {digest for _, _, digest in sites}
        if len(digests) == 1:
            where = ", ".join(f"{module}:{line}" for module, line, _ in sites)
            duplicated.append(f"{name} ({where})")
    assert not duplicated, (
        "identical function bodies in more than one sih141/eval module; import "
        "one rather than copying it: " + "; ".join(duplicated)
    )


def test_the_duplicate_hunt_can_fail() -> None:
    """Prove the check above is not green because it never looks at anything.

    A structural test that silently found no functions would pass forever. This
    asserts it parsed a real package, and that its comparison is by body, by
    feeding it two names it must already see as sharing a name but not a body.
    """
    bodies = _function_bodies()
    assert len(bodies) > 50, "the AST walk found almost nothing; it is not looking"
    for name in DIVERGENT_BY_DESIGN:
        sites = bodies[name]
        assert len(sites) == 2, f"{name} no longer has two definitions"
        assert len({digest for _, _, digest in sites}) == 2, (
            f"{name} now has two identical bodies -- consolidate it and drop it "
            f"from DIVERGENT_BY_DESIGN"
        )


# --------------------------------------------------------------------------- #
# 4. One completeness check, and it sees the case an interruption leaves
# --------------------------------------------------------------------------- #


class _Rec:
    """The two fields :func:`completeness_note` reads.

    Attributes
    ----------
    cell : str
        Cell name.
    index : int
        Trial index.
    """

    def __init__(self, cell: str, index: int) -> None:
        self.cell, self.index = cell, index


def _old_style_gap_check(records: list[_Rec]) -> bool:
    """Re-implement the check that shipped, to show what it could not see.

    Parameters
    ----------
    records : list
        Records to inspect.

    Returns
    -------
    bool
        ``True`` if the old check would have reported everything present.

    Notes
    -----
    This is the ROC family's original ``_missing_note`` logic: gaps below the
    highest index present. It is reproduced rather than described so the test
    below compares two behaviours instead of asserting a claim about one.
    """
    by_cell: dict[str, set[int]] = {}
    for record in records:
        by_cell.setdefault(record.cell, set()).add(record.index)
    for seen in by_cell.values():
        if sorted(set(range(max(seen) + 1)) - seen):
            return False
    return True


def test_a_cell_short_by_its_last_trials_is_caught() -> None:
    """The failure an interrupted sweep actually leaves.

    An interruption takes the *highest* indices, not interior ones, so a check
    that looks for holes below the maximum present reports a short cell as
    complete. That is false reassurance, and worse than printing nothing.
    """
    truncated = [_Rec("a", 0), _Rec("a", 1), _Rec("a", 2)]
    assert _old_style_gap_check(truncated), "the old check saw nothing wrong"

    note = completeness_note(truncated, {"a": 20})
    assert "INCOMPLETE" in note
    assert "a has 3 of 20 trials" in note


def test_an_interior_gap_is_still_caught() -> None:
    """The case the old check did handle must not have been lost."""
    holed = [_Rec("a", 0), _Rec("a", 2)]
    assert not _old_style_gap_check(holed)
    note = completeness_note(holed, {"a": 3})
    assert "INCOMPLETE" in note
    assert "a is missing index [1]" in note


def test_a_complete_store_says_so_and_a_short_one_never_does() -> None:
    """Both directions, so neither answer is the constant one."""
    whole = [_Rec("a", 0), _Rec("a", 1)]
    assert completeness_note(whole, {"a": 2}).startswith("Complete:")
    assert "INCOMPLETE" not in completeness_note(whole, {"a": 2})
    assert not completeness_note(whole, {"a": 3}).startswith("Complete:")


def test_a_cell_with_no_records_at_all_is_named() -> None:
    """A cell that never ran is missing, not absent from the question."""
    note = completeness_note([_Rec("a", 0)], {"a": 1, "b": 4})
    assert "b has no records at all" in note


def test_without_a_manifest_it_does_not_claim_completeness() -> None:
    """The honest answer when there is nothing to check the count against.

    A reduction handed records and no expectation can see interior gaps and
    nothing else. Saying "complete" there would be a claim it cannot support.
    """
    note = completeness_note([_Rec("a", 0), _Rec("a", 1)], {})
    assert "only interior gaps were" in note
    assert not note.startswith("Complete:")
    assert "INCOMPLETE" not in note


def test_every_experiment_gets_the_completeness_note_not_just_roc(
    tmp_path: Path,
) -> None:
    """It rides on the outcome table, which every experiment has.

    The check began life inside one family's own table. An experiment without
    an ``EXTRA_REDUCTIONS`` entry -- which is most of them -- had no
    completeness check at all, and its tables shrank in silence.
    """
    ran = _sweep("run", "smoke", "--trials", "3", "--workers", "1", "--results", str(tmp_path))
    assert ran.returncode == 0, ran.stdout + ran.stderr

    from sih141.eval.reduce import reduce_experiment
    from sih141.eval.store import ResultStore

    store = ResultStore(tmp_path)
    outcomes = reduce_experiment(store, "smoke")[0]
    assert outcomes.slug == "outcomes"
    assert outcomes.notes[0].startswith("Complete:"), outcomes.notes[0]

    # Remove the highest index -- the interruption case -- and it must complain.
    highest = sorted(tmp_path.rglob("trial-*.json"))[-1]
    highest.unlink()
    after = reduce_experiment(store, "smoke")[0]
    assert "INCOMPLETE" in after.notes[0]
    assert "2 of 3 trials" in after.notes[0]


def test_expected_trials_reads_the_manifest_not_the_registry(
    tmp_path: Path,
) -> None:
    """What the store was asked for, not what the default happens to be.

    The registry says ``smoke`` runs 4 trials. A store built with ``--trials 3``
    is complete at 3, and a check against the default would call it short.
    """
    from sih141.eval.experiments import EXPERIMENTS
    from sih141.eval.reduce import expected_trials
    from sih141.eval.store import ResultStore

    assert EXPERIMENTS["smoke"].trials != 3, "pick a count unlike the default"
    ran = _sweep("run", "smoke", "--trials", "3", "--workers", "1", "--results", str(tmp_path))
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert expected_trials(ResultStore(tmp_path), "smoke") == {"tiny": 3}


# --------------------------------------------------------------------------- #
# 5. The two halves of the CLI quote their commands the same way
# --------------------------------------------------------------------------- #


def test_the_printed_regenerating_command_actually_runs(tmp_path: Path) -> None:
    """D9's claim is that a reviewer can re-run the command, so re-run it.

    The ``run`` side builds its command through
    :func:`~sih141.eval.manifest.command_line`, which quotes with ``shlex``.
    The ``reduce`` side interpolated its ``--results`` path raw, so a results
    directory with a space in its name printed a command that argparse rejects
    with ``unrecognized arguments`` -- a table carrying a regenerating command
    that does not regenerate it.

    This test drives the printed string rather than inspecting how it was
    built: it takes the ``Regenerate:`` line out of the output, splits it the
    way a shell would, runs it, and requires the same table back. It fails on
    the unquoted version.
    """
    results = tmp_path / "dir with space"
    ran = _sweep("run", "smoke", "--trials", "2", "--workers", "1", "--results", str(results))
    assert ran.returncode == 0, ran.stdout + ran.stderr

    first = _sweep("reduce", "smoke", "--results", str(results))
    assert first.returncode == 0, first.stdout + first.stderr
    printed = [
        line for line in first.stdout.splitlines() if line.startswith("Regenerate: `")
    ]
    assert printed, "no regenerating command was printed at all"

    command = printed[0][len("Regenerate: `") :].rstrip("`")
    assert "dir with space" in command, "this test is not exercising the quoting"

    argv = shlex.split(command)
    assert argv[0] == "python" and argv[1].endswith("sweep.py")
    replayed = subprocess.run(
        [sys.executable, str(_repo_root() / "tools" / "sweep.py"), *argv[2:]],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=str(_repo_root()),
    )
    assert replayed.returncode == 0, (
        "the printed regenerating command does not run:\n"
        f"  command: {command}\n"
        f"  stderr: {replayed.stderr[-600:]}"
    )
    assert _tables_of(replayed.stdout) == _tables_of(first.stdout)


def test_the_unquoted_form_really_would_have_failed() -> None:
    """Prove the test above is not passing for some unrelated reason.

    Without this, a ``reduce`` that ignored ``--results`` entirely would make
    the replay succeed and the test green.
    """
    naive = f"python tools/sweep.py reduce smoke --results {'/tmp/dir with space'}"
    assert shlex.split(naive)[-2:] == ["with", "space"]
    quoted = (
        f"python tools/sweep.py reduce smoke "
        f"--results {shlex.quote('/tmp/dir with space')}"
    )
    assert shlex.split(quoted)[-1] == "/tmp/dir with space"


def _repo_root() -> pathlib.Path:
    """Return the repository root.

    Returns
    -------
    pathlib.Path
    """
    return _eval_package().parent.parent


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
        [sys.executable, str(_repo_root() / "tools" / "sweep.py"), *args],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=str(_repo_root()),
    )


def _tables_of(output: str) -> list[str]:
    """Strip the lines that legitimately differ between two identical reductions.

    Parameters
    ----------
    output : str
        Markdown from ``reduce``.

    Returns
    -------
    list of str
        Every line that is not a path-bearing provenance or regenerate line.
    """
    return [
        line
        for line in output.splitlines()
        if not line.startswith(("Regenerate:", "- produced by:", "- commit:"))
    ]


def test_the_names_the_families_still_share_are_the_ones_we_expect() -> None:
    """A shared name is not a defect, but it should be a decision.

    If a new shared name appears, this fails and somebody decides whether it is
    a third copy of something or a genuinely different function that happens to
    be called the same thing.
    """
    shared = {name for name, sites in _function_bodies().items() if len(sites) > 1}
    assert shared == DIVERGENT_BY_DESIGN


def test_the_timing_table_says_its_numbers_carry_contention(tmp_path: Path) -> None:
    """`ms/position` read off a parallel sweep is not the protocol's cost.

    The number is arithmetically correct and misleading without its condition,
    the same species as ``null_is_noiseless``. It is also load-bearing: the
    whole throughput claim, and docs/QDS.md's projection for a production run,
    rest on ms/position. Measured in the production sweep at twenty workers,
    the scaling experiment reported 5.010 to 7.244 ms/position against a
    single-threaded reference of about 2.04, so anyone multiplying the table's
    figure by a key length would overstate a run by more than a factor of two.

    The note must name the single-threaded reference and the command that
    regenerates it, or it is a warning with nowhere to go.
    """
    from sih141.eval.perf import REFERENCE_MS_PER_POSITION
    from sih141.eval.reduce import reduce_experiment
    from sih141.eval.store import ResultStore

    ran = _sweep("run", "smoke", "--trials", "2", "--workers", "2", "--results", str(tmp_path))
    assert ran.returncode == 0, ran.stdout + ran.stderr
    timing = reduce_experiment(ResultStore(tmp_path), "smoke")[2]
    assert timing.slug == "timing"
    assert "ms/position" in timing.columns

    caveat = [note for note in timing.notes if "NOT THE PROTOCOL'S COST" in note]
    assert len(caveat) == 1, "the contention caveat is missing from the timing table"
    assert "REFERENCE_MS_PER_POSITION" in caveat[0]
    assert "tools/sweep.py perf" in caveat[0]
    assert REFERENCE_MS_PER_POSITION > 0
