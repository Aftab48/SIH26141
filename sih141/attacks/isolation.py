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

.. _check-a-channel:

How check (a) reaches the candidate, and how it once failed to
--------------------------------------------------------------
Check (a) can only catch an adversary reading the session if the session's
randomness is *reachable*. This is not a detail: for most of Phase 3 it was not
reachable at all. Every ready-made probe took ``session_seed`` and wrote ``del
session_seed`` on its first line, no shipped adversary declared a
``session_seed`` constructor argument, and so nothing whatsoever varied between
the five calls check (a) compares. All fourteen rows of
``tests/test_phase3_isolation_suite.py`` passed a check no row could fail --
the vacuous-test failure mode, in the test the phase called its most important.
The negative controls kept working throughout, which is exactly why it went
unnoticed: they read the seed through the *builder*, the one channel that was
live.

:func:`check_attack_isolation` now installs a :class:`SessionEnvironment` around
every build and every probe call, and varies it with the session seed. It opens
the three routes a real experiment leaks through -- the harness's seed constant
(:func:`active_session`), ambient global randomness, and an adversary generator
the harness derived from the session's own seed -- so that a candidate taking
any of them moves and is caught. See :class:`SessionEnvironment` for what each
route stands for.

The routes are open *on purpose*. A check that offers no leak detects no theft,
and the ordinary, isolated adversary is unaffected by their existence: it draws
from the generator it was handed, and that generator is what check (b) varies.
The two halves compose into a proof rather than two assertions -- check (b)
establishes that the probe can see the candidate's own stream, so an adversary
whose stream was derived from the session's *must* be caught by check (a). That
is what ``test_the_session_channel_is_live_on_every_row`` runs, per row, and it
is the evidence "14/14 pass check (a)" previously did not carry.

The one adversary that cannot be covered this way is the one whose decisions do
not move with its own generator either -- the deterministic recipient forger --
and that is precisely why a waiver is only sound beside a randomised sibling
(:ref:`deterministic-mode`).

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
went and took it -- which is exactly the question being asked, and which it can
in fact do, by any of the routes :ref:`check-a-channel` describes.

Freezing the *observations* and varying the *session* are therefore two
different jobs, and both have to happen. The probe does the first; the second is
:func:`check_attack_isolation`'s, through the environment it installs around
every call. A probe that does the second job as well -- running a fresh session
per seed -- blames the adversary for the harness's choices, and a ``del
session_seed`` with nothing doing the second job at all, which is what shipped,
proves nothing about the adversary either way.

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

Three ways to write a probe that does not say what you think it says
--------------------------------------------------------------------
All three were found the hard way in Phase 3, by different agents. Two report a
perfectly isolated attack as a cheat; the third reports nothing at all, which is
worse, because a green row is read as evidence.

**A distributor probe must return the adversary's own decision, never the seam's
output.** The obvious probe for the ``distributor`` seam returns the records it
produced -- but the records are a function of the session's Alice-side stream
*by construction*, honestly and for every implementation, so check (a) fails and
the report points at the adversary. Return the thing the adversary chose: the
key an impersonating distributor substituted, the axis a channel attack drew.
:func:`sih141.attacks.impersonation.distributor_probe` is the worked example.

**A payload_map probe used to need ``check_fraction = 0``, and that was the
protocol's bug rather than the probe's.** ``payload_map`` was invoked on key
rounds only, and *which* positions are key rounds is drawn from the session's
own generator, so the set of contexts the seam was legitimately offered moved
with the session seed even for a flawless adversary: a probe reporting those
positions failed check (a), and :func:`check_attack_isolation` reported it as
``reads_the_session=True`` against an innocent attack. The same fact was a leak
in its own right -- the gaps in the seam's call sequence *were* the check set --
and it is closed at the source: :mod:`sih141.protocol.distribute` now offers the
seam every position and discards what it returns on a check round, exactly as
``resource_factory`` was always called, and :mod:`sih141.protocol.session` does
the same for ``channel_monitor``. A payload probe may now run with check rounds
on, and the rows in ``tests/test_phase3_isolation_suite.py`` do.

**A probe that freezes its session seed silently narrows what its row proves.**
This one does not fail; it passes for less. Check (a) still bites, because the
:class:`SessionEnvironment` is installed by :func:`check_attack_isolation`
around the probe call rather than by the probe (:ref:`check-a-channel`), so an
adversary reading the session is caught whatever the probe does with its
argument -- which is why ``del session_seed`` in a seam-less probe is correct
and not a defect. What a frozen probe loses is the *other* half: with the
session seed varying, a probe that runs a live checked session also requires the
adversary's view to be independent of the **check plan**, and that is a
statement about the protocol's seam lockstep as much as about the adversary. A
probe that pins ``rng=default_rng(0)`` keeps the first guarantee and quietly
drops the second.

The rule the first two are instances of: everything the adversary *legitimately
observes* -- including the set of occasions on which it is consulted -- must be
identical across probe calls, or check (a) is not a statement about the
adversary at all. The rule the third is an instance of: a probe should vary
everything the row claims the adversary is independent of.

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
demonstrate it does not use the seed rather than merely being unable to reach it
by that route; one that does not accept it has closed the construction-time
channel, and :attr:`IsolationReport.session_seed_offered` records which of the
two happened. Closing that channel is not the whole guarantee and was once read
as if it were: the environment around every probe call reaches a candidate that
declares nothing at all (:ref:`check-a-channel`). A builder that refuses ``rng``
is refused here, with D6 quoted at it.

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

import contextlib
import dataclasses
import inspect
import random
import re
from collections.abc import Iterator, Mapping, Sequence
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
    "SESSION_MATERIAL_BYTES",
    "AttackBuilder",
    "AttackIsolationError",
    "DecisionProbe",
    "IsolationReport",
    "SessionEnvironment",
    "SignerScenario",
    "active_session",
    "assert_attack_isolated",
    "canonical",
    "check_attack_isolation",
    "derived_from_seed",
    "forwarder_probe",
    "require_distinct_streams",
    "same_stream",
    "session_environment",
    "signer_probe",
    "signer_scenario",
    "stream_fingerprint",
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

SESSION_MATERIAL_BYTES: Final[int] = 32
"""Bytes :class:`~sih141.protocol.session.QDSSession` draws from its generator.

Mirrors ``sih141.protocol.session._STREAM_MATERIAL_BYTES``. It is repeated here
rather than imported because it is used to *model the leak* rather than to run
the protocol: :meth:`SessionEnvironment.stream_material` reproduces the session's
one draw so that a negative control can rebuild the run exactly as a real
adversary holding the seed would. If the session ever changes its draw width,
this constant should follow it and
``test_the_environment_reproduces_the_session_s_own_material`` will say so.
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
    receive the seed *that way*, which is the stronger position and is recorded
    in :attr:`IsolationReport.session_seed_offered`. It is not the only way --
    the :class:`SessionEnvironment` around the build reaches every candidate
    whether it declares anything or not, which is what keeps check (a) from
    passing vacuously on a builder that simply does not name the argument
    (:ref:`check-a-channel`). Either way the builder **must** accept ``rng``.
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
    to get a probe wrong. :func:`signer_probe` is the worked example. Nor does
    it have to *use* the seed for check (a) to be live: a seam that takes no
    generator is reached by the :class:`SessionEnvironment`
    :func:`check_attack_isolation` installs around the call, so a probe that
    simply passes the seed on to no one is correct, where a probe that varies
    the observations with it is not (:ref:`check-a-channel`).
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
# The session the candidate is being checked against (see :ref:`check-a-channel`)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SessionEnvironment:
    """The session randomness in force for one probe call, deliberately reachable.

    Check (a) varies the session seed and requires the candidate's decisions not
    to move. That is only a statement about the candidate if the seed is
    *reachable*: an adversary with no route to the session's randomness cannot
    fail, and a check no candidate can fail is a check that has proved nothing.
    The Phase 3 audit found exactly that -- every probe wrote ``del
    session_seed``, so the fourteen shipped rows passed check (a) vacuously.

    This class is the fix. :func:`check_attack_isolation` installs one around
    every build-and-probe, and it opens the three routes a real experiment
    actually leaks through, so that an adversary taking any of them moves with
    the seed and is caught:

    1. **The harness's seed constant.** Every attack script in this repository
       is written as ``SEED = 20260141`` at module level and passed to
       :class:`~sih141.protocol.session.QDSSession`; an adversary defined in the
       same module has it in scope whether it declares a parameter or not.
       :func:`active_session` is that constant, and it is public *on purpose* --
       the check offers the leak so that it can detect the taking.
    2. **Ambient global randomness.** :data:`numpy.random`'s legacy global
       stream and :mod:`random`'s are seeded from the session seed for the
       duration of the call, which is what a harness written for reproducibility
       does to them. Convention **D3** forbids an adversary drawing there; one
       that does is now correlated with the run it is attacking, and check (a)
       says so instead of the rule sitting unenforced in a docstring.
    3. **Its own generator, if the harness built it from the session's seed.**
       :meth:`stream_material` reproduces the session's single
       ``rng.bytes(32)`` draw, so a candidate built that way can rebuild every
       stream. This is the route :func:`same_stream` refuses at the measurement
       entry points and the one the per-row controls in
       ``tests/test_phase3_isolation_suite.py`` exercise.

    Parameters
    ----------
    seed : int
        The seed the session under attack was built from -- what a harness
        passes as ``rng=numpy.random.default_rng(seed)``.

    Attributes
    ----------
    seed : int

    See Also
    --------
    active_session : The environment in force, or ``None`` outside a check.
    session_environment : The context manager that installs one.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import SessionEnvironment
    >>> environment = SessionEnvironment(seed=901)

    Its generator is the one the harness would have handed the session, so the
    material it draws is the material the session derived its streams from:

    >>> environment.stream_material() == np.random.default_rng(901).bytes(32)
    True
    >>> len(environment.stream_material())
    32
    """

    seed: int

    def __post_init__(self) -> None:
        """Coerce and range-check the seed, so a bool or a float fails here."""
        if isinstance(self.seed, bool) or not isinstance(
            self.seed, (int, np.integer)
        ):
            raise TypeError(
                f"seed must be an int, got {type(self.seed).__name__}. This is "
                f"the integer a harness passes to numpy.random.default_rng, "
                f"not the generator it returns."
            )
        if int(self.seed) < 0:
            raise ValueError(f"seed must be non-negative, got {int(self.seed)}")
        object.__setattr__(self, "seed", int(self.seed))

    def session_rng(self) -> np.random.Generator:
        """Return a fresh copy of the generator the session was given.

        Fresh on every call rather than stored, so that one caller reading it
        cannot advance it under another and turn a deterministic check into a
        seed-order-dependent one.

        Returns
        -------
        numpy.random.Generator

        Examples
        --------
        >>> from sih141.attacks.isolation import SessionEnvironment
        >>> environment = SessionEnvironment(seed=7)
        >>> environment.session_rng().bytes(4) == (
        ...     environment.session_rng().bytes(4)
        ... )
        True
        """
        return np.random.default_rng(self.seed)

    def stream_material(self) -> bytes:
        """Return the session's seed material: its one draw from that generator.

        :class:`~sih141.protocol.session.QDSSession` takes
        :data:`SESSION_MATERIAL_BYTES` bytes from the caller's generator and
        derives Alice's stream, the recipients' stream and the binding stream
        from it. Anything holding this holds all three.

        Returns
        -------
        bytes
            :data:`SESSION_MATERIAL_BYTES` bytes.

        Examples
        --------
        >>> from sih141.attacks.isolation import SessionEnvironment
        >>> SessionEnvironment(seed=1).stream_material() != (
        ...     SessionEnvironment(seed=2).stream_material()
        ... )
        True
        """
        return self.session_rng().bytes(SESSION_MATERIAL_BYTES)


_ACTIVE_SESSION: SessionEnvironment | None = None
"""The environment installed by :func:`session_environment`, or ``None``."""


def active_session() -> SessionEnvironment | None:
    """Return the :class:`SessionEnvironment` in force, or ``None``.

    The check's stand-in for the module-level seed constant a real experiment
    script keeps in scope. Published deliberately: check (a) can only catch an
    adversary reading the session if there is something to read, and an
    adversary that calls this is doing precisely what D6 forbids.

    Returns
    -------
    SessionEnvironment or None
        ``None`` outside :func:`check_attack_isolation`, so ordinary use of an
        adversary is unaffected by the existence of this hook.

    See Also
    --------
    SessionEnvironment : What the three routes are, and why they are open.

    Examples
    --------
    >>> from sih141.attacks.isolation import active_session, session_environment
    >>> active_session() is None
    True
    >>> with session_environment(901) as environment:
    ...     active_session() is environment, active_session().seed
    (True, 901)
    >>> active_session() is None
    True
    """
    return _ACTIVE_SESSION


@contextlib.contextmanager
def session_environment(seed: int) -> Iterator[SessionEnvironment]:
    """Install one session's randomness for the duration of a probe call.

    Sets :func:`active_session` and seeds both ambient global streams from
    ``seed``, then restores all three -- including the exact global states that
    were in force on entry -- on the way out, so a check leaves no trace on the
    process it ran in.

    Seeding the globals is not a D3 violation and is the opposite of one: this
    module never *draws* from them. It writes them so that a candidate which
    draws from them is drawing from something the session seed controls, and is
    therefore caught by check (a) rather than passing while quietly depending on
    process-wide state.

    Parameters
    ----------
    seed : int
        Non-negative. The session seed check (a) is currently varying.

    Yields
    ------
    SessionEnvironment
        The environment installed, also reachable via :func:`active_session`.

    Raises
    ------
    TypeError
        If ``seed`` is not an integer.
    ValueError
        If ``seed`` is negative.

    Notes
    -----
    Not thread-safe, and deliberately so: the ambient state it installs is
    process-wide, so two checks running concurrently in one process would seed
    each other's globals and the verdicts would depend on interleaving. Nesting
    is safe -- each level restores what it found, so an inner environment hands
    the outer one back intact.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import session_environment

    Inside, the ambient stream is a function of the session seed:

    >>> with session_environment(901):
    ...     first = float(np.random.random())
    >>> with session_environment(901):
    ...     again = float(np.random.random())
    >>> with session_environment(902):
    ...     other = float(np.random.random())
    >>> first == again, first == other
    (True, False)

    And the state the process had is handed back untouched:

    >>> before = np.random.get_state()[1][:4].tolist()
    >>> with session_environment(903):
    ...     _ = np.random.random()
    >>> np.random.get_state()[1][:4].tolist() == before
    True
    """
    global _ACTIVE_SESSION
    environment = SessionEnvironment(seed=seed)
    previous = _ACTIVE_SESSION
    numpy_state = np.random.get_state()
    stdlib_state = random.getstate()
    _ACTIVE_SESSION = environment
    # The legacy global seeder takes a 32-bit value; the check's seeds are far
    # below that, and the mask only matters for a caller passing a wide one.
    np.random.seed(environment.seed % (2**32))
    random.seed(environment.seed)
    try:
        yield environment
    finally:
        _ACTIVE_SESSION = previous
        np.random.set_state(numpy_state)
        random.setstate(stdlib_state)


# --------------------------------------------------------------------------- #
# When are two generators the same stream?
# --------------------------------------------------------------------------- #


def stream_fingerprint(rng: np.random.Generator) -> tuple[Any, ...]:
    """Return a content-comparable identity for a generator's stream.

    Two generators are the same stream when they were derived from the same
    seed material, whether or not they are the same Python object and whether or
    not either has been advanced since. The fingerprint carries both halves of
    that: the seed sequence the bit generator was built from, and the bit
    generator's current state.

    Parameters
    ----------
    rng : numpy.random.Generator
        The generator to fingerprint.

    Returns
    -------
    tuple
        ``(derivation, state)``. ``derivation`` is ``None`` when the bit
        generator exposes no seed sequence, in which case only the state
        distinguishes it.

    Raises
    ------
    TypeError
        If ``rng`` is not a :class:`numpy.random.Generator`.

    See Also
    --------
    same_stream : The comparison built on this.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import stream_fingerprint

    One seed, two objects, one stream -- the defect D6 is about:

    >>> left, right = np.random.default_rng(7), np.random.default_rng(7)
    >>> left is right
    False
    >>> stream_fingerprint(left) == stream_fingerprint(right)
    True
    >>> stream_fingerprint(left) == stream_fingerprint(
    ...     np.random.default_rng(8)
    ... )
    False

    Advancing one changes its state but not its derivation, which is why both
    halves are kept:

    >>> _ = left.random()
    >>> stream_fingerprint(left)[1] == stream_fingerprint(right)[1]
    False
    >>> stream_fingerprint(left)[0] == stream_fingerprint(right)[0]
    True
    """
    if not isinstance(rng, np.random.Generator):
        raise TypeError(
            f"rng must be a numpy.random.Generator, got "
            f"{type(rng).__name__}"
        )
    bit_generator = rng.bit_generator
    sequence = getattr(bit_generator, "seed_seq", None)
    derivation: Any = None
    if sequence is not None:
        entropy = getattr(sequence, "entropy", None)
        if entropy is not None:
            derivation = (
                type(bit_generator).__name__,
                canonical(entropy),
                canonical(tuple(getattr(sequence, "spawn_key", ()))),
            )
    return (derivation, canonical(bit_generator.state))


def same_stream(left: np.random.Generator, right: np.random.Generator) -> bool:
    """Return whether two generators draw from the same stream.

    The comparison the D6 guards need, and the one they were not making. An
    experiment that builds the adversary and the session from **one seed** hands
    the adversary the session's entire randomness -- ``QDSSession`` consumes its
    caller's generator as a single ``rng.bytes(32)`` and derives every stream
    from that material -- yet the two generators are different Python objects,
    so an ``is`` test waves it through. That is the leak
    :mod:`sih141.attacks.isolation` exists to prevent, arriving by the shortest
    possible route.

    ``True`` when the two are the same object, when they stand at the same point
    in the same stream, or when they were derived from the same seed sequence at
    any offset.

    Parameters
    ----------
    left, right : numpy.random.Generator
        The two generators.

    Returns
    -------
    bool

    Raises
    ------
    TypeError
        If either argument is not a :class:`numpy.random.Generator`.

    See Also
    --------
    require_distinct_streams : The same test, raising with the reason attached.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import same_stream

    The object test that was shipped catches only the first of these; the
    second is the one that matters:

    >>> shared = np.random.default_rng(11)
    >>> same_stream(shared, shared)
    True
    >>> same_stream(np.random.default_rng(11), np.random.default_rng(11))
    True
    >>> same_stream(np.random.default_rng(11), np.random.default_rng(12))
    False

    Advancing one does not make it a different stream:

    >>> advanced = np.random.default_rng(11)
    >>> _ = advanced.random(1000)
    >>> same_stream(advanced, np.random.default_rng(11))
    True

    Two children spawned from one parent *are* independent, and are not refused:

    >>> parent = np.random.default_rng(11)
    >>> first, second = parent.spawn(2)
    >>> same_stream(first, second)
    False
    """
    if left is right:
        return True
    left_derivation, left_state = stream_fingerprint(left)
    right_derivation, right_state = stream_fingerprint(right)
    if left_state == right_state:
        return True
    return left_derivation is not None and left_derivation == right_derivation


def derived_from_seed(rng: np.random.Generator, seed: int) -> bool:
    """Return whether ``rng`` is the stream ``default_rng(seed)`` produces.

    The seed-shaped half of :func:`same_stream`, for the entry points that take
    a session *seed* and an adversary *generator* rather than two generators --
    :func:`sih141.attacks.impersonation.run_impersonation` and
    :func:`sih141.attacks.starvation.measure_starvation`.

    Parameters
    ----------
    rng : numpy.random.Generator
        The adversary's generator.
    seed : int
        A session seed the harness will build a generator from.

    Returns
    -------
    bool

    Raises
    ------
    TypeError
        If ``rng`` is not a generator or ``seed`` is not an integer.
    ValueError
        If ``seed`` is negative.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import derived_from_seed
    >>> derived_from_seed(np.random.default_rng(500_000), 500_000)
    True
    >>> derived_from_seed(np.random.default_rng(4242), 500_000)
    False
    """
    return same_stream(rng, SessionEnvironment(seed=seed).session_rng())


def require_distinct_streams(
    left: np.random.Generator,
    right: np.random.Generator,
    *,
    left_name: str,
    right_name: str,
    detail: str = "",
) -> None:
    """Raise unless two generators are independent streams (D6).

    The guard every measurement entry point in this package runs before it
    spends a single trial. What it refuses is the experiment written from one
    seed, which is how the defect actually arrives -- nobody passes the same
    object twice, but everybody writes ``SEED = 20260141`` once and uses it for
    both the session and the adversary.

    Parameters
    ----------
    left, right : numpy.random.Generator
        The two generators, in the order the message should name them.
    left_name, right_name : str
        Keyword-only. Argument names, quoted in the message.
    detail : str, optional
        Keyword-only. One extra sentence about what each generator is for in
        the calling function, appended to the standard explanation.

    Raises
    ------
    TypeError
        If either generator is not a :class:`numpy.random.Generator`, or
        ``detail`` is not a string.
    ValueError
        If the two are the same stream.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.isolation import require_distinct_streams
    >>> require_distinct_streams(
    ...     np.random.default_rng(1),
    ...     np.random.default_rng(2),
    ...     left_name="rng",
    ...     right_name="session_rng",
    ... ) is None
    True
    >>> try:
    ...     require_distinct_streams(
    ...         np.random.default_rng(1),
    ...         np.random.default_rng(1),
    ...         left_name="rng",
    ...         right_name="session_rng",
    ...     )
    ... except ValueError as error:
    ...     print(str(error).splitlines()[0])
    rng and session_rng are the same stream (D6).
    """
    if not isinstance(detail, str):
        raise TypeError(
            f"detail must be a string, got {type(detail).__name__}"
        )
    if not same_stream(left, right):
        return
    context = f"{detail.strip()}\n" if detail.strip() else ""
    raise ValueError(
        f"{left_name} and {right_name} are the same stream (D6).\n"
        f"They need not be the same object to be the same stream, and here "
        f"they are not being compared as objects: two generators built from "
        f"one seed produce identical bytes for ever. QDSSession consumes its "
        f"caller's generator as a single 32-byte draw and derives Alice's "
        f"stream, the recipients' stream and the binding stream from that "
        f"material, so an adversary holding the same stream rebuilds the whole "
        f"run and predicts every private symmetrisation coin. Every rate "
        f"measured that way is fiction while the transcript looks entirely "
        f"normal.\n"
        f"{context}"
        f"Seed the two independently, and not from two arithmetic neighbours "
        f"of one constant either; use two unrelated seeds, or parent.spawn(2), "
        f"whose children this guard accepts."
    )


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
        means the candidate could not reach the seed through *construction*, so
        check (a) tested it through the :class:`SessionEnvironment` alone --
        which is a live channel and not, as this field once implied, no channel
        at all (:ref:`check-a-channel`).
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

        Both the build and the probe run inside a :class:`SessionEnvironment`
        for ``session_seed``, which is what makes check (a) a check at all: a
        candidate with no route to the session's randomness cannot fail, so the
        routes a real experiment leaks through are opened here and varied with
        the seed. See :ref:`check-a-channel`.
        """
        with session_environment(session_seed):
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
            f"Three routes reach the seed and any of them produces this "
            f"symptom: a constructor argument, a draw from ambient global "
            f"randomness (numpy.random.* or random.*, which D3 forbids for "
            f"exactly this reason), and an own generator the harness derived "
            f"from the session's seed. See :ref:`check-a-channel`.\n"
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

    The worked example of a correct probe. It calls the candidate with the
    :class:`~sih141.protocol.session.Signer` seam's four arguments and returns
    the :class:`~sih141.protocol.signature.Signature` it declared.

    It is **not** identical to what a live session hands that seam, and the
    difference is deliberately in the adversary's favour. ``records`` here holds
    the frozen scenario's **raw** pre-exchange logs for both recipients;
    :meth:`~sih141.protocol.session.QDSSession.sign` passes
    :data:`~sih141.protocol.session.NO_RECIPIENT_LOGS` unless the session was
    built with ``signer_sees_recipient_logs=True``, which the shipped default is
    not (:ref:`sih141.protocol.session <two-log-signer>`). So this probe offers
    a candidate strictly more than the protocol does. That is sound for an
    isolation check -- an adversary shown more and still not moving with the
    session seed is isolated *a fortiori*, and no rate is measured here -- but
    it is not an equivalence, and a probe that needed one would have to build
    its session with that flag set.

    The ``session_seed`` argument is not read here, and reading it is not what
    would make this probe vary with the seed. Every probe call replays one
    frozen scenario, because the candidate's *observations* must be identical
    across seeds or check (a) is a statement about the harness rather than about
    the adversary -- running a fresh session per seed would hand a
    recipient-forger a different log each time, moving his declaration for an
    entirely honest reason and reporting him as a cheat. What varies with the
    seed is the :class:`SessionEnvironment` that
    :func:`check_attack_isolation` installs around this call
    (:ref:`check-a-channel`); a candidate that goes and takes the session's
    randomness finds something that moves, and is caught.

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
        """Declare once against the frozen scenario; return what was said.

        The seed is not passed on: the seam takes no such argument, and what
        varies with it is the environment around this call, not the candidate's
        observations. See :ref:`check-a-channel`.
        """
        del session_seed
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

    ``session_seed`` is not passed on, for the reason spelled out on
    :func:`signer_probe`: the seam takes no such argument, one frozen scenario
    is replayed into every call so that the candidate's observations do not move
    with the seed, and what does move with it is the
    :class:`SessionEnvironment` around the call (:ref:`check-a-channel`).

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
        """Forward once against the frozen scenario; return what was passed on.

        The seed reaches the candidate through the environment around this call,
        never through its observations. See :ref:`check-a-channel`.
        """
        del session_seed
        if forwarder_wants_view(attack):
            return attack(declaration, resolved.params, view=view)
        return attack(declaration, resolved.params)

    return probe
