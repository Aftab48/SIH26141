"""Convention D6, made structural: an adversary owns its randomness.

Every attack in Phase 3 and every number in Phase 5 rests on one rule:

    **An adversary's behaviour is a function of its OWN generator and of what
    the threat model says it can observe -- never of the session's randomness.**

This module is that rule as a *behavioural* check, applied to a candidate
adversary and returning a verdict. It is not a syntactic scan of source text:
a scan is evaded by an indirection and gives false confidence in exchange for
nothing, whereas an adversary whose decisions provably do not move when the
session's seed moves has demonstrated the property itself.

Why a paragraph in a docstring was not enough
---------------------------------------------
:class:`~sih141.protocol.session.QDSSession` splits the generator it is given
into two labelled streams (:ref:`sih141.protocol.session <two-streams>`), so no
Alice-side seam is ever handed the symmetrisation coins. That closes the leak
*through the seam*. It does nothing about the leak through the **harness**, and
the harness leak is the one an attack author walks into by accident, because it
is what writing a reproducible experiment looks like:

.. code-block:: python

    seed = 20260141
    attack = MyForger(seed)                                   # <-- the defect
    session = QDSSession(params, signer=attack, rng=np.random.default_rng(seed))

An adversary holding that integer does not need to break SHA-256, guess a
stream label or reach into a private attribute. It rebuilds the entire run:

>>> import numpy as np
>>> from sih141.protocol.params import Party, ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> params = ProtocolParams(key_length=60)
>>> seed = 20260141
>>> honest = QDSSession(params, rng=np.random.default_rng(seed))
>>> _ = honest.distribute()
>>> rebuilt = QDSSession(params, rng=np.random.default_rng(seed))
>>> _ = rebuilt.distribute()
>>> rebuilt.records == honest.records
True

Which means every symmetrisation coin -- the private, recipient-side coins the
whole non-repudiation bound is an exponential in -- is predicted exactly, on
both message bits, using nothing but the public API:

>>> def coins(session):
...     # Position i is True where Bob ended up holding Charlie's raw entry.
...     return [
...         session.records[bit][Party.BOB].entries[index]
...         == session.raw_records[bit][Party.CHARLIE].entries[index]
...         for bit in (0, 1)
...         for index in range(params.key_length)
...     ]
>>> predicted, actual = coins(rebuilt), coins(honest)
>>> sum(a == b for a, b in zip(predicted, actual)), len(actual)
(120, 120)

Nothing there is a defect in the mathematics; the Hoeffding argument assumes
the coins are private and a real Alice cannot read two other people's coin
tosses. It is a defect in the *experiment*. An attack written that way regains
full coin prediction silently, and publishes repudiation rates that are pure
fiction while looking entirely legitimate -- same seams, same transcript, same
printed bound.

The check, and why it has two halves
------------------------------------
:func:`check_attack_isolation` builds the candidate many times and probes it:

(a) **Attack generator fixed, session seed varied.** Every choice the adversary
    makes on its own account must be *unchanged*. If its decisions move, it is
    reading the session, and that is the defect.

(b) **Session seed fixed, attack generator varied.** Its decisions *must* move.
    If they do not, the adversary is not actually using the generator it was
    handed -- and then (a) passed vacuously, because a constant is trivially
    independent of everything. This half is not a nicety: without it the whole
    check is worth nothing, and a suite of adversaries could pass it while
    ignoring their generators entirely.

An adversary that fails (a) is reading the session. One that fails (b) is
either deterministic-by-construction -- in which case (a) proves nothing about
it and it needs a different argument -- or its probe is not looking at the part
of it that is random.

What a probe must do, and the one way to get it wrong
-----------------------------------------------------
A :class:`DecisionProbe` runs the candidate and returns its decisions. Check (a)
compares those decisions across session seeds, so the probe must hold
**everything the adversary legitimately observes fixed** and vary the session
seed alone. That is the whole discipline, and the trap is a natural-looking
probe that violates it: a probe which runs a fresh :class:`QDSSession` per seed
hands a recipient-forger a *different measurement log* each time, so his
declaration moves for an entirely honest reason and a perfectly isolated
adversary is reported as a cheat.

:func:`signer_probe` is the ready-made probe for the :class:`Signer` seam and
does it correctly: one honest run is performed once, under its own unrelated
seed, and frozen (:func:`signer_scenario`); every probe call replays that same
scenario. The session seed is then something the adversary can only know if it
went and took it -- which is exactly the question being asked.

For a seam that legitimately *receives* a generator -- ``distributor``,
``resource_factory``, ``symmetriser`` -- write a probe that passes
``np.random.default_rng(session_seed)`` as that seam's ``rng`` and holds its
other arguments fixed. Check (a) then catches an adversary that draws its own
decisions from Alice's stream instead of from its own generator, which
:ref:`sih141.protocol.session <phase3-seams>` already asks implementations not
to do and which nothing until now checked.

.. _deterministic-mode:

When check (b) cannot apply, and what to do instead
---------------------------------------------------
Check (b) -- *vary the adversary's own generator and its decisions must move* --
is what stops check (a) passing vacuously, because a constant is independent of
every input. It also cannot be satisfied by the adversary whose rate this
project most wants to publish.

The optimal recipient forger is a **deterministic function of his view**.
Declaring his own raw log strictly dominates every randomised alternative at
every position: on a position the symmetrisation swapped away he matches with
certainty, on a retained one his measured basis gives ``P(match | scored) =
2/3`` against ``1/2`` for any other declaration, and flipping the eigenvalue is
strictly worse. He has nothing to draw. The same trap catches the obvious
depolarising channel -- returning the Werner state
``(1-p)|Phi+><Phi+| + p I/4`` consumes no randomness at all -- and a count
starver whose declaration is a fixed function of the counterpart's count.

Three responses, in order of preference.

1. **Realise the adversary as a sampled process** where the physics allows it.
   A Pauli twirl drawn per round from the adversary's own generator has exactly
   the depolarising ensemble and *is* a function of its own stream, so check (b)
   applies unchanged. This is the right answer whenever it exists, and note that
   the two realisations are not observationally equivalent to a channel monitor:
   the sampled twirl leaves purity and concurrence pinned at ``1.0`` with
   fidelity flipping between ``1`` and ``0``, where the averaged state would
   report a constant fidelity of ``1 - 3p/4`` on every round.

2. **Check a randomised sibling that shares the call path.** Give the adversary
   a knob that mixes in its own coin -- ``guess_probability`` on the recipient
   forger, ``jitter`` on the count starver -- and run the ordinary two-sided
   check on ``functools.partial(TheAdversary, guess_probability=0.25)``. The
   knob is strictly suboptimal, so no published rate may be measured with it,
   but it exercises the identical ``__call__`` and therefore demonstrates that
   *that code* draws from the generator it was handed.

3. **Waive check (b) in writing**, with ``deterministic="..."``. Check (a) still
   runs and still raises; what the waiver buys is that
   :attr:`IsolationReport.isolated` no longer requires (b), and the reason is
   carried in the report and printed by :meth:`IsolationReport.summary` so that
   nobody reads the verdict without it. The waiver is only sound **alongside**
   response 2: on its own it says "this candidate made the same choice five
   times", which is equally consistent with a candidate that quietly derived
   that choice from the session. Phase 3 uses both together for
   :class:`~sih141.attacks.forgery.RecipientForger`.

What the waiver must never be used for is a candidate that *has* randomness and
is failing (b) because the probe is not looking at it. That is a broken probe,
and the fix is to return the part of the decision the generator reaches.

.. _probe-traps:

Two ways to write a probe that blames the adversary for your bug
-----------------------------------------------------------------
Both were found the hard way in Phase 3, by different agents, and both report a
perfectly isolated attack as a cheat.

**A distributor probe must return the adversary's own decision, never the seam's
output.** The obvious probe for the ``distributor`` seam returns the records it
produced -- but the records are a function of the session's Alice-side stream
*by construction*, honestly and for every implementation, so check (a) fails and
the report points at the adversary. Return the thing the adversary chose: the
key an impersonating distributor substituted, the axis a channel attack drew.
:func:`sih141.attacks.impersonation.distributor_probe` is the worked example.

**A payload_map probe must run with ``check_fraction = 0``.** ``payload_map`` is
called on key rounds only, and *which* positions are key rounds is drawn from
the session's own generator, so the set of contexts the seam is legitimately
offered moves with the session seed even for a flawless adversary. A probe
returning a log that includes positions therefore fails check (a), which
:func:`check_attack_isolation` then reports as ``reads_the_session=True``. The
``resource_factory`` seam has no such problem: check-round lockstep calls it at
every position identically.

The rule both cases are instances of: everything the adversary *legitimately
observes* -- including the set of occasions on which it is consulted -- must be
identical across probe calls, or check (a) is not a statement about the
adversary at all.

Adding the sixth adversary
--------------------------
The candidate is supplied as an :class:`AttackBuilder`, and the ordinary
builder is the adversary's own class, because D6 already requires its
constructor to take ``rng``. So a suite grows by one line:

.. code-block:: python

    @pytest.mark.parametrize(
        "attack", [ForgingBob, RepudiatingAlice, ..., TheSixthOne]
    )
    def test_every_adversary_owns_its_randomness(attack):
        assert_attack_isolated(attack, probe=signer_probe())

A builder that also accepts ``session_seed`` is offered it, so a candidate can
demonstrate it does not use the seed rather than merely being unable to reach
it; one that does not accept it has made the guarantee structural already, and
:attr:`IsolationReport.session_seed_offered` records which of the two happened.
A builder that refuses ``rng`` is refused here, with D6 quoted at it.

Notes
-----
Determinism (D3)
    Generators are built from explicit seeds inside this module and threaded;
    nothing reaches for global randomness. The seeds are the check's *inputs*,
    which is why they are named constants and parameters rather than literals.
No machine learning (D4)
    Equality of decision traces and two set-cardinality tests.

See Also
--------
sih141.protocol.records.RecipientView : The other half of the same boundary --
    what an adversary may *see*, where this module governs what it may *draw*.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Protocol

import numpy as np

from sih141.protocol.keys import PrivateKey
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.records import (
    RecipientRecord,
    RecipientView,
    recipient_views,
)
from sih141.protocol.session import (
    NO_RECIPIENT_LOGS,
    QDSSession,
    forwarder_wants_view,
    honest_signer,
)

__all__ = [
    "DEFAULT_ATTACK_SEEDS",
    "DEFAULT_SESSION_SEEDS",
    "MIN_JUSTIFICATION",
    "SCENARIO_PARAMS",
    "SCENARIO_SEED",
    "AttackBuilder",
    "AttackIsolationError",
    "DecisionProbe",
    "IsolationReport",
    "SignerScenario",
    "assert_attack_isolated",
    "canonical",
    "check_attack_isolation",
    "forwarder_probe",
    "signer_probe",
    "signer_scenario",
]


DEFAULT_SESSION_SEEDS: Final[tuple[int, ...]] = (901, 902, 903, 904, 905)
"""Session seeds check (a) varies over, with the attack's generator held fixed.

Five, and disjoint from :data:`DEFAULT_ATTACK_SEEDS` and :data:`SCENARIO_SEED`
so that a coincidence between two of them cannot be mistaken for isolation.
"""

DEFAULT_ATTACK_SEEDS: Final[tuple[int, ...]] = (101, 102, 103, 104, 105)
"""Attack-generator seeds check (b) varies over, with the session seed fixed.

Check (b) passes as soon as two of the resulting decision traces differ. Five
seeds is ample for an adversary that makes ``L`` choices; an adversary whose
own randomness amounts to a single fair coin would fail here once in sixteen
runs by chance, so such a candidate should be checked with a longer list rather
than trusted to this default.
"""

SCENARIO_SEED: Final[int] = 20260141
"""Seed of the one honest run :func:`signer_scenario` freezes.

Deliberately unrelated to both seed lists above: the scenario is the *fixed*
part of the experiment, and an adversary must not be able to reach it by
guessing a session seed.
"""

SCENARIO_PARAMS: Final[ProtocolParams] = ProtocolParams(key_length=24)
"""Parameters for the frozen scenario -- small, because it is run per probe set.

Neither matched-count floor carries a security claim below ``L = 140``, and
none is wanted here: the scenario exists to give a candidate adversary a
realistic set of records to react to, not to measure a forgery rate.
"""

MIN_JUSTIFICATION: Final[int] = 40
"""Shortest ``deterministic=`` justification :func:`check_attack_isolation` takes.

Forty characters, which is about one clause. The argument switches off half the
check, so it is deliberately not satisfiable by ``"n/a"`` or ``"deterministic"``:
the caller has to write down *why* the adversary has no randomness to vary, and
that sentence is what the next reader audits. See :ref:`deterministic-mode`.
"""

_MAX_CANONICAL_DEPTH: Final[int] = 16
"""Recursion limit for :func:`canonical`, so a cyclic trace fails loudly."""

_OPAQUE_REPR: Final[re.Pattern[str]] = re.compile(
    r"^<.* object at 0x[0-9a-fA-F]+>$"
)
"""Matches the default :func:`repr`, whose address makes every trace differ."""


# --------------------------------------------------------------------------- #
# The two callables a caller supplies
# --------------------------------------------------------------------------- #


class AttackBuilder(Protocol):
    """Callable returning a fresh adversary, built from a generator of its own.

    Ordinarily the adversary's own class: D6 already requires its constructor to
    take a keyword-only ``rng``, so the class *is* a conforming builder and no
    wrapper is needed.

    ``session_seed`` is optional. A builder that declares it (or accepts
    ``**kwargs``) is offered the seed the harness would hand
    :class:`~sih141.protocol.session.QDSSession`, so that check (a) has a
    construction-time channel to test; a builder that does not declare it cannot
    receive the seed at all, which is the stronger position and is recorded in
    :attr:`IsolationReport.session_seed_offered`. Either way the builder **must**
    accept ``rng``.
    """

    def __call__(self, *, rng: np.random.Generator) -> Any:
        """Return a new adversary drawing its randomness from ``rng``."""
        ...


class DecisionProbe(Protocol):
    """Callable that exercises one adversary and returns what it decided.

    The return value is compared for equality across runs after
    :func:`canonical` has normalised it, so it must be *content*-comparable: a
    :class:`~sih141.protocol.signature.Signature`, a tuple of indices, an array
    of flips, a dataclass. An opaque object whose :func:`repr` carries its
    address is refused with an explanation rather than silently failing check
    (a) on every seed.

    The probe receives the session seed and **must not** vary the adversary's
    legitimate observations with it -- see the module docstring on the one way
    to get a probe wrong. :func:`signer_probe` is the worked example.
    """

    def __call__(self, attack: Any, session_seed: int) -> Any:
        """Run ``attack`` and return the decisions it made."""
        ...


class AttackIsolationError(AssertionError):
    """Raised by :func:`assert_attack_isolated` when a candidate fails a check.

    An :exc:`AssertionError` because it reports a failed property of a candidate
    adversary rather than a misuse of the API -- misuse raises
    :exc:`TypeError`/:exc:`ValueError` as everywhere else in the project.
    """


# --------------------------------------------------------------------------- #
# Normalising a decision trace
# --------------------------------------------------------------------------- #


def canonical(value: Any) -> Any:
    """Return a hashable, content-comparable normal form of a decision trace.

    Probes return whatever is natural for the adversary they exercise, and the
    check compares those returns for equality and counts distinct ones. NumPy
    arrays break both (``==`` is elementwise, and they are unhashable), nested
    mappings break ordering, and floats break reflexivity at ``nan``. This
    flattens all of it into tuples of primitives.

    Parameters
    ----------
    value : object
        Any decision trace: primitives, numpy scalars and arrays, sequences,
        mappings, sets, and dataclass instances, nested arbitrarily.

    Returns
    -------
    object
        A hashable value equal to the canonical form of any equal-content input.

    Raises
    ------
    ValueError
        If the structure nests deeper than 16 levels (a cycle, most likely), or
        if it contains an object with the default :func:`repr` -- whose memory
        address would make two identical runs compare unequal and report a false
        isolation failure.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import canonical
    >>> canonical(np.array([1, 0, 1])) == canonical(np.array([1, 0, 1]))
    True
    >>> canonical({"b": (1, 2), "a": 3}) == canonical({"a": 3, "b": [1, 2]})
    True
    >>> canonical(float("nan")) == canonical(float("nan"))
    True
    >>> hash(canonical({"flips": np.array([2, 5])})) is not None
    True
    """
    return _canonical(value, 0)


def _canonical(value: Any, depth: int) -> Any:
    """Recursive worker for :func:`canonical`; ``depth`` guards cycles."""
    if depth > _MAX_CANONICAL_DEPTH:
        raise ValueError(
            f"decision trace nests deeper than {_MAX_CANONICAL_DEPTH} levels, "
            f"which usually means it contains a cycle. A probe should return a "
            f"flat, content-comparable summary of what the adversary decided, "
            f"not a live object graph."
        )
    if value is None or isinstance(value, (bool, int, bytes)):
        return value
    if isinstance(value, str):
        # StrEnum members (Party, PauliBasis) land here and compare by value.
        return str(value)
    if isinstance(value, (float, complex)):
        # repr, so that nan == nan: a trace containing a nan must not report an
        # isolation failure against an identical trace.
        return (type(value).__name__, repr(value))
    if isinstance(value, np.generic):
        return _canonical(value.item(), depth + 1)
    if isinstance(value, np.ndarray):
        return (
            "ndarray",
            tuple(value.shape),
            str(value.dtype),
            _canonical(value.tolist(), depth + 1),
        )
    if isinstance(value, Mapping):
        items = tuple(
            (_canonical(key, depth + 1), _canonical(item, depth + 1))
            for key, item in value.items()
        )
        return ("mapping", tuple(sorted(items, key=repr)))
    if isinstance(value, (set, frozenset)):
        members = tuple(_canonical(item, depth + 1) for item in value)
        return ("set", tuple(sorted(members, key=repr)))
    if isinstance(value, Sequence):
        return ("sequence", tuple(_canonical(item, depth + 1) for item in value))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            "dataclass",
            type(value).__qualname__,
            tuple(
                (field.name, _canonical(getattr(value, field.name), depth + 1))
                for field in dataclasses.fields(value)
            ),
        )
    text = repr(value)
    if _OPAQUE_REPR.match(text):
        raise ValueError(
            f"a probe returned {type(value).__qualname__}, whose repr carries "
            f"its memory address, so two identical runs would compare unequal "
            f"and every candidate would be reported as reading the session. "
            f"Return what the adversary *decided* -- a Signature, a tuple of "
            f"positions, an array of flips -- rather than the adversary itself "
            f"or a live protocol object."
        )
    return ("repr", type(value).__qualname__, text)


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IsolationReport:
    """The outcome of both halves of the check, with the evidence kept.

    Frozen. The decision traces are retained rather than reduced to booleans so
    that a failure can be explained -- "these two session seeds gave different
    declarations" is actionable, "not isolated" is not.

    Parameters
    ----------
    attack : str
        The candidate's name, for messages.
    session_seeds : tuple of int
        The seeds check (a) varied over, in order.
    attack_seeds : tuple of int
        The seeds check (b) varied over, in order.
    session_seed_offered : bool
        Whether the builder accepted a ``session_seed`` argument. ``False``
        means the candidate could not reach the seed through construction at
        all, so check (a) tested only the call-time channel the probe provides.
    decisions_across_session_seeds : tuple
        Canonicalised decisions under ``attack_seeds[0]``, one per session seed.
    decisions_across_attack_seeds : tuple
        Canonicalised decisions under ``session_seeds[0]``, one per attack seed.
    deterministic_justification : str or None, optional
        The caller's stated reason that check (b) is inapplicable to this
        candidate, or ``None`` for the ordinary two-sided check. See
        :ref:`deterministic-mode`.

    Attributes
    ----------
    attack : str
    session_seeds : tuple of int
    attack_seeds : tuple of int
    session_seed_offered : bool
    decisions_across_session_seeds : tuple
    decisions_across_attack_seeds : tuple
    deterministic_justification : str or None

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import check_attack_isolation
    >>> class Coin:
    ...     '''An adversary whose only choice comes from its own generator.'''
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.face = int(rng.integers(1000))
    >>> report = check_attack_isolation(Coin, lambda attack, seed: attack.face)
    >>> report.isolated, report.reads_the_session
    (True, False)
    >>> report.session_seed_offered
    False
    """

    attack: str
    session_seeds: tuple[int, ...]
    attack_seeds: tuple[int, ...]
    session_seed_offered: bool
    decisions_across_session_seeds: tuple[Any, ...]
    decisions_across_attack_seeds: tuple[Any, ...]
    deterministic_justification: str | None = None

    @property
    def reads_the_session(self) -> bool:
        """bool: ``True`` when check (a) failed -- decisions moved with the seed.

        The defect. The adversary's own choices are a function of something
        derived from the session's randomness, so any rate it produces is
        correlated with the coins the security bound assumes are private.
        """
        return len(set(self.decisions_across_session_seeds)) > 1

    @property
    def uses_its_own_generator(self) -> bool:
        """bool: ``True`` when check (b) passed -- decisions moved with ``rng``.

        ``False`` means the candidate ignored the generator it was handed, so
        check (a) told us nothing: a constant is independent of every input.
        """
        return len(set(self.decisions_across_attack_seeds)) > 1

    @property
    def deterministic_accepted(self) -> bool:
        """bool: ``True`` when check (b) was waived by a stated justification.

        Only meaningful alongside :attr:`uses_its_own_generator`: a waiver on a
        candidate that turned out to be random anyway was unnecessary, and the
        report says so rather than hiding it.
        """
        return self.deterministic_justification is not None

    @property
    def isolated(self) -> bool:
        """bool: ``True`` when check (a) passed and check (b) passed or is waived.

        Without a waiver this is "both halves passed", which is the only verdict
        that stands on its own. With one it is "check (a) passed, and the caller
        has written down why check (b) cannot apply" -- weaker, deliberately
        visible in :meth:`summary`, and the only verdict available for the
        optimal recipient forger (:ref:`deterministic-mode`).
        """
        if self.reads_the_session:
            return False
        return self.uses_its_own_generator or self.deterministic_accepted

    @property
    def offending_session_seeds(self) -> tuple[int, ...]:
        """tuple of int: Session seeds whose decisions differ from the first.

        Empty when check (a) passed. These are the seeds to reproduce with when
        hunting the leak.
        """
        if not self.decisions_across_session_seeds:
            return ()
        anchor = self.decisions_across_session_seeds[0]
        return tuple(
            seed
            for seed, decision in zip(
                self.session_seeds,
                self.decisions_across_session_seeds,
                strict=True,
            )
            if decision != anchor
        )

    @property
    def distinct_decisions(self) -> int:
        """int: How many distinct decisions the attack seeds produced.

        ``1`` is the check (b) failure. Larger numbers say how much of the
        candidate's behaviour the probe is actually looking at.
        """
        return len(set(self.decisions_across_attack_seeds))

    def summary(self) -> str:
        """Return a one-block human-readable verdict.

        Returns
        -------
        str
            Four lines: the candidate, each check with its verdict, and the
            overall result.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.isolation import check_attack_isolation
        >>> class Coin:
        ...     def __init__(self, *, rng: np.random.Generator) -> None:
        ...         self.face = int(rng.integers(1000))
        >>> report = check_attack_isolation(
        ...     Coin, lambda attack, seed: attack.face
        ... )
        >>> print(report.summary())
        Coin: ISOLATED
          (a) vary session seed, fix own rng: 1 distinct decision (want 1)
          (b) vary own rng, fix session seed: 5 distinct decisions (want >1)
          session_seed offered to the builder: no
        """
        across_session = len(set(self.decisions_across_session_seeds))
        verdict = "ISOLATED" if self.isolated else "NOT ISOLATED"
        if self.deterministic_accepted:
            verdict = (
                "ISOLATED (check (b) waived)"
                if self.isolated
                else "NOT ISOLATED"
            )
        waiver = (
            ""
            if not self.deterministic_accepted
            else f"\n  (b) waived, deterministic by construction: "
            f"{self.deterministic_justification}"
        )
        return (
            f"{self.attack}: {verdict}\n"
            f"  (a) vary session seed, fix own rng: {across_session} distinct "
            f"{'decision' if across_session == 1 else 'decisions'} (want 1)\n"
            f"  (b) vary own rng, fix session seed: "
            f"{self.distinct_decisions} distinct "
            f"{'decision' if self.distinct_decisions == 1 else 'decisions'} "
            f"(want >1)\n"
            f"  session_seed offered to the builder: "
            f"{'yes' if self.session_seed_offered else 'no'}"
            f"{waiver}"
        )


# --------------------------------------------------------------------------- #
# The check
# --------------------------------------------------------------------------- #


def _as_justification(value: Any) -> str | None:
    """Validate a ``deterministic=`` waiver: ``None`` or a real sentence.

    Parameters
    ----------
    value : object
        ``None`` for the ordinary two-sided check, or the caller's reason.

    Returns
    -------
    str or None
        The stripped justification, or ``None``.

    Raises
    ------
    TypeError
        If ``value`` is neither ``None`` nor a string.
    ValueError
        If the string is shorter than :data:`MIN_JUSTIFICATION` characters.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(
            f"deterministic must be None or a string explaining why check (b) "
            f"cannot apply, got {type(value).__name__}. It is not a flag: "
            f"passing True would switch off half the check without leaving a "
            f"reason in the report."
        )
    reason = value.strip()
    if len(reason) < MIN_JUSTIFICATION:
        raise ValueError(
            f"deterministic must be at least {MIN_JUSTIFICATION} characters of "
            f"actual justification, got {len(reason)}. Say why this adversary "
            f"has no randomness for check (b) to vary -- for instance that "
            f"declaring his own raw log strictly dominates every randomised "
            f"alternative at every position -- because that sentence is the "
            f"argument replacing the check, and it is what the next reader "
            f"audits."
        )
    return reason


def _as_seed_tuple(seeds: Any, name: str) -> tuple[int, ...]:
    """Validate a seed list: at least two distinct non-negative integers."""
    if isinstance(seeds, (str, bytes)) or not isinstance(seeds, Sequence):
        raise TypeError(
            f"{name} must be a sequence of integer seeds, got "
            f"{type(seeds).__name__}"
        )
    values = []
    for position, seed in enumerate(seeds):
        if isinstance(seed, bool) or not isinstance(seed, (int, np.integer)):
            raise TypeError(
                f"{name}[{position}] must be an int, got "
                f"{type(seed).__name__}. These are seeds the check builds "
                f"generators from, not generators."
            )
        if int(seed) < 0:
            raise ValueError(
                f"{name}[{position}] must be non-negative, got {int(seed)}"
            )
        values.append(int(seed))
    if len(set(values)) < 2:
        raise ValueError(
            f"{name} must hold at least two distinct seeds, got {values}. The "
            f"check works by varying one thing at a time; with a single seed "
            f"there is nothing to vary and the verdict would be meaningless."
        )
    return tuple(values)


def _builder_offers_session_seed(build: Any, name: str) -> bool:
    """Say whether ``build`` takes ``session_seed``; raise if it refuses ``rng``.

    Also the point where D6's constructor requirement is enforced: an adversary
    that does not take a generator of its own has already failed the convention,
    and saying so here is far clearer than the :exc:`TypeError` the first build
    call would otherwise raise.
    """
    if not callable(build):
        raise TypeError(
            f"{name} must be a callable returning a fresh adversary -- normally "
            f"the adversary's own class -- got {type(build).__name__}"
        )
    try:
        signature = inspect.signature(build)
    except (TypeError, ValueError):
        # A C-level callable exposes no signature. Assume the minimum.
        return False

    takes_rng = False
    takes_seed = False
    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            # **kwargs accepts everything, including both names. The loop is
            # not cut short here: a candidate that swallows keywords still has
            # to be offered the seed *and* still satisfies D6's rng argument.
            takes_rng = True
            takes_seed = True
        elif parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            if parameter.name == "rng":
                takes_rng = True
            elif parameter.name == "session_seed":
                takes_seed = True
    if not takes_rng:
        raise TypeError(
            f"{name} must accept a keyword argument 'rng'; its signature is "
            f"{signature}. Convention D6: every adversary takes its OWN "
            f"numpy.random.Generator as a constructor argument, so that its "
            f"behaviour cannot depend on the seed the harness gives the "
            f"session. An adversary built from an integer seed, or from no "
            f"randomness at all, cannot be checked -- and an attack that "
            f"reuses the harness seed silently predicts every symmetrisation "
            f"coin (module docstring)."
        )
    return takes_seed


def check_attack_isolation(
    build: AttackBuilder,
    probe: DecisionProbe,
    *,
    session_seeds: Sequence[int] = DEFAULT_SESSION_SEEDS,
    attack_seeds: Sequence[int] = DEFAULT_ATTACK_SEEDS,
    name: str | None = None,
    deterministic: str | None = None,
) -> IsolationReport:
    """Run both halves of the D6 check against one candidate adversary.

    A fresh adversary is built for every probe, from a generator seeded
    explicitly, because an adversary reused across probes carries its generator
    state forward and would look like it was reading the session when it was
    only continuing its own stream.

    Parameters
    ----------
    build : AttackBuilder
        Callable returning a fresh adversary. Normally the adversary's class.
        Must accept a keyword ``rng``; may also accept ``session_seed``, and is
        offered it when it does.
    probe : DecisionProbe
        Callable ``(attack, session_seed) -> decisions``. Must hold everything
        the adversary legitimately observes fixed across calls -- see the module
        docstring, and :func:`signer_probe` for the worked example.
    session_seeds : sequence of int, optional
        Keyword-only. Varied in check (a) with ``attack_seeds[0]`` held fixed.
        At least two distinct non-negative integers.
    attack_seeds : sequence of int, optional
        Keyword-only. Varied in check (b) with ``session_seeds[0]`` held fixed.
    name : str or None, optional
        Keyword-only label for the report; defaults to the builder's
        ``__name__``.
    deterministic : str or None, optional
        Keyword-only. A written justification that check (b) is inapplicable
        because the candidate is deterministic *by construction*. Both halves
        still run and both are still reported; what changes is that
        :attr:`IsolationReport.isolated` no longer requires (b). At least
        :data:`MIN_JUSTIFICATION` characters -- see :ref:`deterministic-mode`
        for when this is legitimate and when it is a bug being papered over.

    Returns
    -------
    IsolationReport
        Both halves' evidence and their verdicts. Nothing is raised for a
        failing candidate; use :func:`assert_attack_isolated` for that.

    Raises
    ------
    TypeError
        If ``build`` is not callable, does not accept ``rng`` (D6), or a seed
        list is not a sequence of ints.
    ValueError
        If a seed list holds fewer than two distinct seeds, or if ``probe``
        returns something :func:`canonical` cannot compare.

    Notes
    -----
    Performs ``len(session_seeds) + len(attack_seeds) - 1`` probe calls: the two
    halves share the corner ``(attack_seeds[0], session_seeds[0])``, which is
    also the anchor both comparisons are made against.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import check_attack_isolation

    An adversary that draws from its own generator and nothing else passes:

    >>> class OwnCoins:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.flips = rng.integers(0, 2, size=8)
    >>> probe = lambda attack, session_seed: attack.flips
    >>> check_attack_isolation(OwnCoins, probe).isolated
    True

    One that mixes in the session seed is caught by check (a), and the report
    names the seeds that moved it:

    >>> class SeedPeeker:
    ...     def __init__(
    ...         self, *, rng: np.random.Generator, session_seed: int
    ...     ) -> None:
    ...         self.flips = rng.integers(0, 2, size=8) ^ np.random.default_rng(
    ...             session_seed
    ...         ).integers(0, 2, size=8)
    >>> report = check_attack_isolation(SeedPeeker, probe)
    >>> report.isolated, report.reads_the_session
    (False, True)
    >>> report.session_seed_offered
    True
    >>> len(report.offending_session_seeds)
    4

    And one that ignores the generator it was handed is caught by check (b),
    which is what stops check (a) from passing vacuously:

    >>> class Deaf:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.flips = np.zeros(8, dtype=int)
    >>> report = check_attack_isolation(Deaf, probe)
    >>> report.reads_the_session, report.uses_its_own_generator
    (False, False)
    >>> report.isolated
    False
    """
    sessions = _as_seed_tuple(session_seeds, "session_seeds")
    attacks = _as_seed_tuple(attack_seeds, "attack_seeds")
    justification = _as_justification(deterministic)
    offered = _builder_offers_session_seed(build, "build")
    if not callable(probe):
        raise TypeError(
            f"probe must be a callable (attack, session_seed) -> decisions, got "
            f"{type(probe).__name__}"
        )
    label = name if name is not None else getattr(build, "__name__", None)
    if label is None:
        label = type(build).__name__

    def observe(attack_seed: int, session_seed: int) -> Any:
        """Build a fresh adversary for one seed pair and read its decisions.

        Fresh, never reused: an adversary carried from one probe to the next
        would have advanced its own generator in between, and an isolated
        candidate would then look like it was reading the session.
        """
        generator = np.random.default_rng(attack_seed)
        if offered:
            keywords = {"rng": generator, "session_seed": session_seed}
            attack = build(**keywords)  # type: ignore[call-arg]
        else:
            attack = build(rng=generator)
        return canonical(probe(attack, session_seed))

    anchor = observe(attacks[0], sessions[0])
    across_session = (anchor,) + tuple(
        observe(attacks[0], seed) for seed in sessions[1:]
    )
    across_attack = (anchor,) + tuple(
        observe(seed, sessions[0]) for seed in attacks[1:]
    )
    return IsolationReport(
        attack=label,
        session_seeds=sessions,
        attack_seeds=attacks,
        session_seed_offered=offered,
        decisions_across_session_seeds=across_session,
        decisions_across_attack_seeds=across_attack,
        deterministic_justification=justification,
    )


def assert_attack_isolated(
    build: AttackBuilder,
    probe: DecisionProbe,
    *,
    session_seeds: Sequence[int] = DEFAULT_SESSION_SEEDS,
    attack_seeds: Sequence[int] = DEFAULT_ATTACK_SEEDS,
    name: str | None = None,
    deterministic: str | None = None,
) -> IsolationReport:
    """Run :func:`check_attack_isolation` and raise unless the candidate passes.

    The one-line form a test suite uses. Returns the report as well, so a test
    that wants to assert something further -- how many distinct decisions the
    probe saw, say -- does not have to run the check twice.

    Parameters
    ----------
    build : AttackBuilder
        As :func:`check_attack_isolation`.
    probe : DecisionProbe
        As :func:`check_attack_isolation`.
    session_seeds : sequence of int, optional
        Keyword-only. As :func:`check_attack_isolation`.
    attack_seeds : sequence of int, optional
        Keyword-only. As :func:`check_attack_isolation`.
    name : str or None, optional
        Keyword-only. As :func:`check_attack_isolation`.
    deterministic : str or None, optional
        Keyword-only. As :func:`check_attack_isolation`. When supplied, a
        candidate that fails check (b) is *not* raised on; a candidate that
        fails check (a) still is, and that is the half the waiver does not
        touch.

    Returns
    -------
    IsolationReport
        The passing report.

    Raises
    ------
    AttackIsolationError
        If either half failed. The message names which, why it matters, and the
        seeds to reproduce with.
    TypeError, ValueError
        As :func:`check_attack_isolation`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import (
    ...     AttackIsolationError, assert_attack_isolated)
    >>> class OwnCoins:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.flips = rng.integers(0, 2, size=8)
    >>> probe = lambda attack, session_seed: attack.flips
    >>> assert_attack_isolated(OwnCoins, probe).isolated
    True

    >>> class Deaf:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.flips = np.zeros(8, dtype=int)
    >>> try:
    ...     assert_attack_isolated(Deaf, probe)
    ... except AttackIsolationError as error:
    ...     print(str(error).splitlines()[0])
    Deaf ignored the generator it was handed.
    """
    report = check_attack_isolation(
        build,
        probe,
        session_seeds=session_seeds,
        attack_seeds=attack_seeds,
        name=name,
        deterministic=deterministic,
    )
    if report.reads_the_session:
        raise AttackIsolationError(
            f"{report.attack} reads the session's randomness.\n"
            f"Its own generator was held fixed at seed "
            f"{report.attack_seeds[0]} and only the session seed changed, yet "
            f"its decisions moved at session "
            f"{'seeds' if len(report.offending_session_seeds) != 1 else 'seed'} "
            f"{list(report.offending_session_seeds)} (anchor: session seed "
            f"{report.session_seeds[0]}).\n"
            f"Convention D6: an adversary's behaviour must be a function of its "
            f"own generator and of what the threat model says it can observe. "
            f"An attack derived from the session seed predicts every "
            f"symmetrisation coin and publishes repudiation rates that are "
            f"fiction. Draw the adversary's choices from the rng it was "
            f"constructed with, and never from the harness seed.\n"
            f"If the decisions moved because the *probe* handed the adversary "
            f"different records per seed, fix the probe instead: it must hold "
            f"everything the adversary legitimately observes fixed.\n"
            f"{report.summary()}"
        )
    if not report.uses_its_own_generator and not report.deterministic_accepted:
        raise AttackIsolationError(
            f"{report.attack} ignored the generator it was handed.\n"
            f"The session seed was held fixed at {report.session_seeds[0]} and "
            f"the attack's own generator was varied over "
            f"{list(report.attack_seeds)}, and every run decided the same "
            f"thing.\n"
            f"This is not a pass with a caveat, it is a failed check: a "
            f"constant is independent of everything, so the first half of the "
            f"check proved nothing about this candidate. Either the adversary "
            f"is not drawing from its rng -- in which case D6 is untested for "
            f"it -- or the probe is not looking at the part of it that is "
            f"random.\n"
            f"If the candidate is deterministic *by construction* -- its "
            f"optimal move is a fixed function of what it observes, so there "
            f"is no randomness to vary and never was -- pass "
            f"deterministic='...' with the argument for why, and read "
            f":ref:`deterministic-mode` first: the waiver is only sound when a "
            f"randomised variant of the same adversary is checked alongside "
            f"it.\n"
            f"{report.summary()}"
        )
    return report


# --------------------------------------------------------------------------- #
# The ready-made scenario and probe for the Signer seam
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SignerScenario:
    """One honest Phase A outcome, frozen, to be replayed into every probe.

    The fixed half of the experiment. Check (a) varies the session seed and
    requires the adversary's decisions not to move, which is only a statement
    about the adversary if everything it legitimately observes is identical
    across the two runs -- so those observations are captured once, here, under
    a seed (:data:`SCENARIO_SEED`) that is not in either varied seed list.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the scenario was produced under.
    message_bit : int
        The bit the probe will ask the candidate to sign.
    keys : tuple of PrivateKey
        Alice's committed ``(k_0, k_1)``. Offered because the
        :class:`~sih141.protocol.session.Signer` seam offers them; a
        recipient-flavoured adversary must ignore them, and
        :func:`check_attack_isolation` cannot tell whether it did -- that is
        what :class:`~sih141.protocol.records.RecipientView` is for.
    raw_records : mapping
        Pre-exchange logs, keyed by message bit then party. Converted to
        read-only views at construction.
    records : mapping
        Post-exchange logs, same shape, likewise read-only.

    Attributes
    ----------
    params : ProtocolParams
    message_bit : int
    keys : tuple of PrivateKey
    raw_records : mapping
    records : mapping

    Examples
    --------
    >>> from sih141.attacks.isolation import signer_scenario
    >>> scenario = signer_scenario()
    >>> scenario.message_bit, len(scenario.keys)
    (0, 2)
    >>> sorted(scenario.records)
    [0, 1]
    >>> scenario.records[0][Party.BOB].symmetrised
    True
    """

    params: ProtocolParams
    message_bit: int
    keys: tuple[PrivateKey, PrivateKey]
    raw_records: Mapping[int, Mapping[Party, RecipientRecord]]
    records: Mapping[int, Mapping[Party, RecipientRecord]]

    def __post_init__(self) -> None:
        """Replace both nested mappings with read-only views of themselves."""
        for name in ("raw_records", "records"):
            nested = getattr(self, name)
            object.__setattr__(
                self,
                name,
                MappingProxyType(
                    {
                        bit: MappingProxyType(dict(by_party))
                        for bit, by_party in nested.items()
                    }
                ),
            )

    @property
    def views(self) -> dict[Party, RecipientView]:
        """dict: One :class:`RecipientView` per verifier, Bob then Charlie.

        The scenario's message bit only. Use it to construct a
        recipient-flavoured adversary that is *structurally* unable to read the
        counterpart's log, rather than one that merely happens not to.
        """
        return recipient_views(
            self.message_bit,
            raw_records=self.raw_records,
            records=self.records,
        )


_SCENARIO_CACHE: dict[tuple[int, int, int], SignerScenario] = {}


def signer_scenario(
    params: ProtocolParams = SCENARIO_PARAMS,
    *,
    message_bit: int = 0,
    seed: int = SCENARIO_SEED,
) -> SignerScenario:
    """Run one honest session and freeze it as the probe's fixed observations.

    Cached on ``(key_length, message_bit, seed)``, so a whole parametrised suite
    of adversaries pays for one distribution rather than one per candidate. The
    result is immutable, and every record in it is a frozen
    :class:`~sih141.protocol.records.RecipientRecord`, so sharing it between
    candidates cannot let one contaminate another.

    Parameters
    ----------
    params : ProtocolParams, optional
        Defaults to :data:`SCENARIO_PARAMS`.
    message_bit : int, optional
        Keyword-only, ``0`` or ``1``. The bit the candidate will be asked to
        sign.
    seed : int, optional
        Keyword-only. The scenario's own seed, deliberately unrelated to the
        seeds the check varies.

    Returns
    -------
    SignerScenario

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`.
    ValueError
        If ``message_bit`` is not ``0``/``1``, or ``seed`` is negative.

    Examples
    --------
    >>> from sih141.attacks.isolation import signer_scenario
    >>> scenario = signer_scenario()
    >>> len(scenario.records[0][Party.BOB]) == scenario.params.key_length
    True
    >>> signer_scenario() is scenario
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    if isinstance(message_bit, bool) or message_bit not in (0, 1):
        raise ValueError(
            f"message_bit must be 0 or 1, got {message_bit!r}. A scenario "
            f"covers the one distribution run the candidate will sign against."
        )
    if isinstance(seed, bool) or not isinstance(seed, (int, np.integer)):
        raise TypeError(f"seed must be an int, got {type(seed).__name__}")
    if int(seed) < 0:
        raise ValueError(f"seed must be non-negative, got {int(seed)}")

    key = (params.key_length, int(message_bit), int(seed))
    cached = _SCENARIO_CACHE.get(key)
    if cached is not None:
        return cached
    session = QDSSession(params, rng=np.random.default_rng(int(seed)))
    session.distribute()
    scenario = SignerScenario(
        params=params,
        message_bit=int(message_bit),
        keys=session.keys,
        raw_records=session.raw_records,
        records=session.records,
    )
    _SCENARIO_CACHE[key] = scenario
    return scenario


def signer_probe(scenario: SignerScenario | None = None) -> DecisionProbe:
    """Return a :class:`DecisionProbe` for the ``Signer`` seam.

    The worked example of a correct probe. It calls the candidate exactly as
    :meth:`sih141.protocol.session.QDSSession.sign` would -- same arguments,
    same keyword-only ``records`` holding the **raw** pre-exchange logs -- and
    returns the :class:`~sih141.protocol.signature.Signature` it declared.

    The ``session_seed`` argument is **deliberately unused**. Every probe call
    replays one frozen scenario, so the candidate's observations are identical
    on every call and the session seed is a quantity it can only know if it went
    and took it. That is the whole question check (a) asks, and it is why this
    probe does not run a fresh session per seed: doing so would hand a
    recipient-forger a different log each time, moving his declaration for an
    entirely honest reason and reporting him as a cheat.

    Parameters
    ----------
    scenario : SignerScenario or None, optional
        The frozen observations. ``None`` uses :func:`signer_scenario`.

    Returns
    -------
    DecisionProbe
        ``(attack, session_seed) -> Signature``.

    Raises
    ------
    TypeError
        If ``scenario`` is neither ``None`` nor a :class:`SignerScenario`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import assert_attack_isolated, signer_probe
    >>> from sih141.protocol.keys import KeyElement, PrivateKey, key_from_record
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.signature import Signature

    A forging Bob who declares his own raw log, with one position redrawn from
    his own generator, is isolated -- and the check says so in one call:

    >>> class ForgingBob:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.rng = rng
    ...     def __call__(self, message_bit, keys, params, *, records):
    ...         own = records[message_bit][Party.BOB]
    ...         elements = list(key_from_record(own, message_bit=message_bit))
    ...         where = int(self.rng.integers(len(elements)))
    ...         flipped = elements[where]
    ...         elements[where] = KeyElement(
    ...             flipped.basis, -flipped.eigenvalue
    ...         )
    ...         return Signature(
    ...             message_bit, PrivateKey(message_bit, elements)
    ...         )
    >>> assert_attack_isolated(ForgingBob, signer_probe()).isolated
    True

    Note what check (b) is reacting to there. The declaration is a
    deterministic reading of a fixed log, so the adversary's own draw has to
    reach the declaration for the check to see it; a candidate whose randomness
    never affects its output fails check (b) -- correctly, since check (a)
    would then have proved nothing about it.
    """
    resolved = signer_scenario() if scenario is None else scenario
    if not isinstance(resolved, SignerScenario):
        raise TypeError(
            f"scenario must be a SignerScenario or None, got "
            f"{type(resolved).__name__}. Build one with signer_scenario()."
        )

    def probe(attack: Any, session_seed: int) -> Any:
        """Declare once against the frozen scenario; return what was said."""
        del session_seed  # An isolated signer cannot see it. That is the point.
        return attack(
            resolved.message_bit,
            resolved.keys,
            resolved.params,
            records=resolved.raw_records,
        )

    return probe


def forwarder_probe(
    scenario: SignerScenario | None = None,
    *,
    party: Party = Party.BOB,
    matched_count: int | None = None,
) -> DecisionProbe:
    """Return a :class:`DecisionProbe` for the ``forwarder`` seam.

    The Bob-to-Charlie hop, which is where the threat model actually puts an
    adversary and which had no ready-made probe: two Phase 3 agents each wrote
    one privately before this existed. It calls the candidate exactly as
    :meth:`sih141.protocol.session.QDSSession.transfer` would -- the declaration
    Bob received, the parameters, and a keyword-only ``view`` carrying **Bob's**
    holdings and nobody else's -- and returns the declaration the seam forwarded.

    A forwarder that does not want the view is called with two arguments, the
    way the session calls one; the choice is read off the candidate's signature
    exactly as :func:`sih141.protocol.session.forwarder_wants_view` reads it,
    so a probe pass and a session run exercise the same code path.

    ``session_seed`` is **deliberately unused**, for the reason spelled out on
    :func:`signer_probe`: one frozen scenario is replayed into every call, so
    the seed is a quantity the candidate can only have by going and taking it.

    Parameters
    ----------
    scenario : SignerScenario or None, optional
        The frozen observations. ``None`` uses :func:`signer_scenario`.
    party : Party, optional
        Keyword-only. Whose view the hop is given; Bob owns this hop, so
        :attr:`~sih141.protocol.params.Party.BOB` is the only value a shipped
        run produces and the default. Charlie is accepted for a probe of a
        second hop; Alice is refused, because she holds no record.
    matched_count : int or None, optional
        Keyword-only. The matched count to put on the view, standing in for the
        verdict the forwarding party has just reached. ``None`` -- the default
        -- models a party who reached no verdict, and is the conservative
        choice: an adversary that branches on the count is then exercised on the
        branch that does not have it.

    Returns
    -------
    DecisionProbe
        ``(attack, session_seed) -> Signature``.

    Raises
    ------
    TypeError
        If ``scenario`` is neither ``None`` nor a :class:`SignerScenario`, or
        ``party`` is not a :class:`~sih141.protocol.params.Party`.
    ValueError
        If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE`.

    See Also
    --------
    signer_probe : The same discipline for the Phase B seam.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import (
    ...     assert_attack_isolated, forwarder_probe)
    >>> from sih141.protocol.keys import KeyElement, PrivateKey
    >>> from sih141.protocol.signature import Signature

    A hop that substitutes a declaration built from its own coins is isolated:

    >>> class CoinFlippingHop:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.rng = rng
    ...     def __call__(self, signature, params, *, view):
    ...         elements = [
    ...             KeyElement(
    ...                 params.bases[int(self.rng.integers(len(params.bases)))],
    ...                 int(self.rng.choice((-1, 1))),
    ...             )
    ...             for _ in range(params.key_length)
    ...         ]
    ...         return Signature(
    ...             signature.message_bit,
    ...             PrivateKey(signature.message_bit, elements),
    ...         )
    >>> assert_attack_isolated(CoinFlippingHop, forwarder_probe()).isolated
    True

    And the view it is handed is one party's, structurally:

    >>> seen = {}
    >>> class Peeking:
    ...     def __init__(self, *, rng: np.random.Generator) -> None:
    ...         self.rng = rng
    ...     def __call__(self, signature, params, *, view):
    ...         seen["party"] = view.party
    ...         return signature
    >>> _ = forwarder_probe()(Peeking(rng=np.random.default_rng(0)), 901)
    >>> seen["party"] is Party.BOB
    True
    """
    resolved = signer_scenario() if scenario is None else scenario
    if not isinstance(resolved, SignerScenario):
        raise TypeError(
            f"scenario must be a SignerScenario or None, got "
            f"{type(resolved).__name__}. Build one with signer_scenario()."
        )
    if not isinstance(party, Party):
        raise TypeError(
            f"party must be a Party, got {type(party).__name__}"
        )
    if party is Party.ALICE:
        raise ValueError(
            "Alice does not forward: the hop this probe models is the one "
            "between the two recipients, and she holds no measurement record "
            "to build a RecipientView from. Pass Party.BOB, who owns it."
        )
    if matched_count is not None and (
        isinstance(matched_count, bool)
        or not isinstance(matched_count, (int, np.integer))
    ):
        raise TypeError(
            f"matched_count must be an int or None, got "
            f"{type(matched_count).__name__}"
        )

    view = RecipientView.for_party(
        party,
        resolved.message_bit,
        raw_records=resolved.raw_records,
        records=resolved.records,
        matched_count=None if matched_count is None else int(matched_count),
    )
    # The declaration the hop receives is frozen alongside the records, and is
    # Alice's honest one: a probe that re-signed per seed would be varying the
    # candidate's observations, which is exactly the mistake :ref:`probe-traps`
    # is about.
    declaration = honest_signer(
        resolved.message_bit,
        resolved.keys,
        resolved.params,
        records=NO_RECIPIENT_LOGS,
    )

    def probe(attack: Any, session_seed: int) -> Any:
        """Forward once against the frozen scenario; return what was passed on."""
        del session_seed  # An isolated hop cannot see it. That is the point.
        if forwarder_wants_view(attack):
            return attack(declaration, resolved.params, view=view)
        return attack(declaration, resolved.params)

    return probe
