"""Tests for :mod:`sih141.attacks.isolation` -- convention D6, made structural.

D6 says an adversary's behaviour must be a function of its own generator and of
what the threat model says it can observe, never of the session's randomness.
:mod:`sih141.attacks.isolation` turns that from a paragraph into a check. This
file's job is to establish that the check *works*, which needs three things and
not one.

1. **A positive control.** An adversary that genuinely owns its randomness must
   pass. Otherwise the check is a rejection machine and the suite would learn to
   route around it.
2. **Two permanent negative controls**, kept here forever rather than run once
   and deleted, because a test that has never failed is not known to work:

   ``SessionSeedForger``
       Derives from the session seed, the way an experiment written for
       reproducibility naturally would. Must fail check (a). Its prediction is
       separately pinned as *exact* -- 120 of 120 private symmetrisation coins
       across both message bits -- so that the control is faithful to the leak
       it stands for, and not merely something that happens to differ.
   ``DeafForger``
       Ignores the generator it was handed. Must fail check (b). This is the
       control for the guard that stops check (a) passing vacuously: without it
       an adversary could satisfy the whole harness by being constant.

3. **The one way to get a probe wrong**, pinned rather than described: a probe
   that runs a fresh session per seed hands the adversary different evidence
   each time, so a perfectly isolated forger is reported as a cheat. The test
   below asserts both halves of that -- the false failure under the naive probe,
   and the pass under :func:`~sih141.attacks.isolation.signer_probe`.

The adversaries here are *toys*. The real suite is built later and attaches
through the session seams; what these establish is the harness the integrator
will point at it, one line per adversary.
"""

from __future__ import annotations

import dataclasses
import random

import numpy as np
import pytest

from sih141.attacks import (
    DEFAULT_ATTACK_SEEDS,
    DEFAULT_SESSION_SEEDS,
    SCENARIO_PARAMS,
    SCENARIO_SEED,
    AttackIsolationError,
    IsolationReport,
    SignerScenario,
    assert_attack_isolated,
    canonical,
    check_attack_isolation,
    signer_probe,
    signer_scenario,
)
from sih141.attacks.isolation import (
    SESSION_MATERIAL_BYTES,
    SessionEnvironment,
    active_session,
    derived_from_seed,
    require_distinct_streams,
    same_stream,
    session_environment,
    stream_fingerprint,
)
from sih141.protocol import (
    KeyElement,
    Party,
    PrivateKey,
    ProtocolParams,
    QDSSession,
    RecipientView,
    Signature,
    key_from_record,
)

COIN_PREDICTION_LENGTH = 60
"""Key length for the faithfulness pin: 60 positions x two bits = 120 coins."""


# ==========================================================================
# Toy adversaries: one honest, two deliberately broken
# ==========================================================================


def _perturb(
    record_key: PrivateKey, positions: list[int], message_bit: int
) -> Signature:
    """Return ``record_key`` with the eigenvalue flipped at ``positions``."""
    elements = list(record_key)
    for position in positions:
        element = elements[position]
        elements[position] = KeyElement(element.basis, -element.eigenvalue)
    return Signature(message_bit, PrivateKey(message_bit, elements))


class IsolatedForger:
    """The positive control: a forging Bob who owns his randomness.

    Declares his own raw log -- the documented recipient-forgery strategy -- and
    hedges a handful of positions chosen from the generator he was constructed
    with. He reads ``records[message_bit][Party.BOB]`` and nothing else, and
    draws from ``self._rng`` and nothing else, so both halves of the check
    should pass.
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        self._rng = rng

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Declare his own log with a few positions redrawn."""
        del keys  # A forging recipient holds no key. That is the point of him.
        own = records[message_bit][Party.BOB]  # type: ignore[index]
        declared = key_from_record(own, message_bit=message_bit)
        hedged = self._rng.choice(
            len(declared), size=max(1, len(declared) // 8), replace=False
        )
        return _perturb(declared, [int(index) for index in hedged], message_bit)


class ViewForger:
    """The positive control that cannot even reach the counterpart's log.

    Identical in strategy to :class:`IsolatedForger`, but built against a
    :class:`~sih141.protocol.records.RecipientView` handed in at construction
    rather than against the two-recipient mapping the ``Signer`` seam offers.
    It ignores ``records`` entirely, so there is no line in it that *could* read
    Charlie -- which is what the view is for.
    """

    def __init__(self, *, rng: np.random.Generator, view: RecipientView) -> None:
        self._rng = rng
        self._view = view

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Declare the raw log this recipient actually holds."""
        del keys, records  # Neither is his; he has his own view.
        declared = key_from_record(
            self._view.raw_record, message_bit=message_bit
        )
        hedged = self._rng.choice(len(declared), size=2, replace=False)
        return _perturb(declared, [int(index) for index in hedged], message_bit)


def build_view_forger(*, rng: np.random.Generator) -> ViewForger:
    """Build a :class:`ViewForger` over the frozen scenario's Bob view.

    The builder pattern for an adversary that needs observations injected: the
    *harness* narrows both recipients' logs into one view (the only place the
    pair is legitimately in scope) and the adversary receives only its half.
    """
    return ViewForger(rng=rng, view=signer_scenario().views[Party.BOB])


class SessionSeedForger:
    """**DELIBERATELY BROKEN.** The permanent negative control for check (a).

    This is the defect the whole module exists for, written exactly the way an
    author reaching for reproducibility writes it: the experiment has one seed,
    it goes to the session, and it also goes to the attack. Holding it, the
    adversary needs nothing private -- it rebuilds the entire run from the
    public API and reads the post-exchange split straight off the reconstruction,
    which is knowledge the threat model does not give any single party.

    It also draws from its own generator, so that it fails check (a) and passes
    check (b): a control that failed both would not tell the two halves apart.
    """

    def __init__(
        self, *, rng: np.random.Generator, session_seed: int
    ) -> None:
        self._rng = rng
        self._session_seed = session_seed

    def rebuild(self, params: ProtocolParams) -> QDSSession:
        """Reconstruct the whole session from the seed. This is the leak."""
        session = QDSSession(
            params, rng=np.random.default_rng(self._session_seed)
        )
        session.distribute()
        return session

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Declare against what the reconstruction says Charlie will score."""
        del keys, records
        predicted = self.rebuild(params).records[message_bit][Party.CHARLIE]
        declared = key_from_record(predicted, message_bit=message_bit)
        hedged = self._rng.choice(len(declared), size=2, replace=False)
        return _perturb(declared, [int(index) for index in hedged], message_bit)


class AmbientSessionForger:
    """**DELIBERATELY BROKEN.** The control for the route nothing was watching.

    The permanent negative control the Phase 3 audit's first finding needed.
    :class:`SessionSeedForger` reads the seed through its **constructor**, which
    was the one channel the check ever had live; every ready-made probe wrote
    ``del session_seed`` on its first line, so an adversary that took the seed
    at *call* time -- the way an attack defined in the same module as the
    harness's ``SEED`` constant does, without declaring anything -- was invisible
    to check (a), and all fourteen shipped rows passed a check none of them
    could fail.

    This is that adversary. Its constructor is
    :class:`OutsideForger`-shaped and takes ``rng`` alone, so
    :attr:`~sih141.attacks.isolation.IsolationReport.session_seed_offered` is
    ``False`` for it exactly as it is for every shipped attack. It reaches the
    session through :func:`~sih141.attacks.isolation.active_session` while it is
    being called, which is the check's stand-in for that module-level constant.

    It draws from its own generator as well, so it fails check (a) and passes
    check (b) -- a control that failed both would not tell the halves apart.
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        self._rng = rng

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Take the session seed at call time and hedge according to it.

        One position, offset by the stolen seed, rather than an extra position
        beside its own: two flips at one index cancel, and a control whose
        defect can cancel is a control that reports a pass it did not earn.
        """
        del keys
        own = records[message_bit][Party.BOB]  # type: ignore[index]
        declared = key_from_record(own, message_bit=message_bit)
        environment = active_session()
        stolen = 0 if environment is None else environment.seed
        mine = int(self._rng.integers(len(declared)))
        return _perturb(
            declared, [(mine + stolen) % len(declared)], message_bit
        )


class GlobalRandomnessForger:
    """**DELIBERATELY BROKEN.** The control for the ambient-randomness route.

    Draws its hedge from :mod:`numpy.random`'s process-global stream instead of
    from the generator it was handed, which convention **D3** forbids.

    Note what the :class:`~sih141.attacks.isolation.SessionEnvironment` changes
    here, because it is not "caught rather than missed". Without one this
    candidate is *also* flagged -- the global stream simply advances from call to
    call, so its five decisions differ -- but it is flagged for being
    nondeterministic rather than for being correlated, and that verdict depends
    on whatever else in the process happened to touch the global stream. With
    the environment the global stream is a deterministic function of the session
    seed, exactly as it is in a harness that seeds it from the same constant it
    gives the session, so the failure means what the report says it means: this
    adversary's choices move with the session's randomness.
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        del rng  # It has one and does not use it. That is half the defect.

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Hedge from the global stream -- nobody's own randomness."""
        del keys
        own = records[message_bit][Party.BOB]  # type: ignore[index]
        declared = key_from_record(own, message_bit=message_bit)
        where = int(np.random.randint(len(declared)))  # noqa: NPY002
        return _perturb(declared, [where], message_bit)


class SessionStreamForger:
    """**DELIBERATELY BROKEN.** The control for one seed used twice.

    The defect :func:`~sih141.attacks.isolation.same_stream` refuses at the
    measurement entry points, seen from the other side. The harness folds the
    session's own seed into this adversary's generator -- the "let us make each
    trial reproducible" line that a real experiment writes without noticing --
    so its stream is a function of the 32 bytes the session derived all three of
    *its* streams from.

    The class itself is written exactly as an honest adversary would be, and
    that is the point: the defect is in :func:`build_from_the_session_stream`,
    not here. Its decisions do move with the generator it was handed, so it
    passes check (b) and fails check (a) alone -- a control that failed both
    would not tell the two halves apart.
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        self._rng = rng

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Declare his own log with a few positions redrawn from his stream."""
        del keys
        own = records[message_bit][Party.BOB]  # type: ignore[index]
        declared = key_from_record(own, message_bit=message_bit)
        hedged = self._rng.choice(len(declared), size=2, replace=False)
        return _perturb(declared, [int(index) for index in hedged], message_bit)


def build_from_the_session_stream(
    *, rng: np.random.Generator
) -> SessionStreamForger:
    """Build a :class:`SessionStreamForger` with the session's seed mixed in.

    The harness half of the defect, isolated into one function so the adversary
    class can stay honest. This is the line a real experiment writes without
    noticing: one ``SEED``, folded into everything so that "the run reproduces".

    The adversary's own seed is kept as well, so the candidate still passes
    check (b) and check (a) is the only half that fires.
    """
    environment = active_session()
    seed = SCENARIO_SEED if environment is None else environment.seed
    material = int.from_bytes(rng.bytes(8), "big")
    mixed = np.random.SeedSequence([material, seed])
    return SessionStreamForger(rng=np.random.default_rng(mixed))


class DeafForger:
    """**DELIBERATELY BROKEN.** The permanent negative control for check (b).

    Accepts a generator, as D6 requires, and then never draws from it. Its
    declaration is a deterministic reading of a fixed log, so it sails through
    check (a) -- a constant is independent of every input -- and check (b) is
    the only thing standing between it and a clean bill of health it has not
    earned.
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        del rng  # Accepted and dropped: that is the defect being modelled.

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Declare his own log verbatim, with no randomness anywhere."""
        del keys
        own = records[message_bit][Party.BOB]  # type: ignore[index]
        return Signature(
            message_bit, key_from_record(own, message_bit=message_bit)
        )


class DrawsAtCallTime:
    """An isolated adversary that draws when called, not when constructed.

    Present to pin that the check builds a *fresh* adversary for every probe. If
    one instance were reused across the session seeds, its generator would have
    advanced between calls and this candidate would be reported as reading the
    session -- a false failure that would be blamed on the adversary.
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        self._rng = rng

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: object,
    ) -> Signature:
        """Draw the hedge at call time from the generator held since birth."""
        del keys
        own = records[message_bit][Party.BOB]  # type: ignore[index]
        declared = key_from_record(own, message_bit=message_bit)
        hedged = self._rng.choice(len(declared), size=3, replace=False)
        return _perturb(declared, [int(index) for index in hedged], message_bit)


# ==========================================================================
# The positive controls
# ==========================================================================


@pytest.mark.parametrize(
    "build", [IsolatedForger, build_view_forger, DrawsAtCallTime]
)
def test_an_adversary_that_owns_its_randomness_passes(build: object) -> None:
    """The one-line form the integrator will apply to the real suite.

    Adding a sixth adversary is one entry in the list above, which is the
    interface this module was designed for.
    """
    report = assert_attack_isolated(build, signer_probe())  # type: ignore
    assert report.isolated
    assert report.reads_the_session is False
    assert report.uses_its_own_generator is True


def test_a_class_taking_only_rng_is_a_conforming_builder() -> None:
    """D6 already requires the constructor to take rng, so the class *is* one.

    No wrapper, no fixture, no adapter: the thing the convention already asks
    for is exactly what the checker consumes.
    """
    report = check_attack_isolation(IsolatedForger, signer_probe())
    assert report.session_seed_offered is False
    assert report.attack == "IsolatedForger"


def test_the_view_forger_cannot_reach_the_counterpart_at_all() -> None:
    """The two halves of this task composing: a view, and the D6 check on it."""
    forger = build_view_forger(rng=np.random.default_rng(0))
    scenario = signer_scenario()
    declaration = forger(
        scenario.message_bit, scenario.keys, scenario.params, records={}
    )
    assert len(declaration) == scenario.params.key_length
    # It declared Bob's raw log, bar the two hedged positions.
    bob = scenario.views[Party.BOB]
    agreeing = sum(
        1
        for index in range(len(bob.raw_record))
        if declaration.declared_key[index].eigenvalue
        == bob.raw_record[index].eigenvalue
    )
    assert agreeing == len(bob.raw_record) - 2
    # Passing records={} proves it never reads the seam's two-recipient mapping.


# ==========================================================================
# The permanent negative controls
# ==========================================================================


def test_the_seed_peeking_forger_is_caught_by_check_a() -> None:
    """The defect the module exists for, caught rather than described."""
    report = check_attack_isolation(SessionSeedForger, signer_probe())
    assert report.session_seed_offered is True
    assert report.reads_the_session is True
    assert report.uses_its_own_generator is True  # ... so it is (a) that fired
    assert report.isolated is False
    assert set(report.offending_session_seeds) == set(DEFAULT_SESSION_SEEDS[1:])


def test_the_seed_peeking_forger_raises_with_an_actionable_message() -> None:
    """The message has to name the defect, the seeds and the fix."""
    with pytest.raises(AttackIsolationError) as excinfo:
        assert_attack_isolated(SessionSeedForger, signer_probe())
    message = str(excinfo.value)
    assert "SessionSeedForger reads the session's randomness" in message
    assert "D6" in message
    assert "symmetrisation coin" in message
    assert str(DEFAULT_SESSION_SEEDS[0]) in message
    assert "NOT ISOLATED" in message
    # ... and it names the probe as the other possible culprit, because a
    # probe that varies the observations produces this same symptom.
    assert "fix the probe instead" in message


def test_the_negative_control_really_does_predict_the_private_coins() -> None:
    """Faithfulness: the control is the leak, not merely something that differs.

    A control that merely produced different output per seed would still catch
    a defect, but it would not stand for *this* defect. What makes the seed a
    catastrophe is that it reconstructs the recipients' private symmetrisation
    coins -- the ones every non-repudiation bound is an exponential in --
    exactly, on both message bits, from the public API alone.
    """
    params = ProtocolParams(key_length=COIN_PREDICTION_LENGTH)
    seed = 424242
    honest = QDSSession(params, rng=np.random.default_rng(seed))
    honest.distribute()

    forger = SessionSeedForger(
        rng=np.random.default_rng(0), session_seed=seed
    )
    rebuilt = forger.rebuild(params)
    assert rebuilt.records == honest.records
    assert rebuilt.raw_records == honest.raw_records

    def coins(session: QDSSession) -> np.ndarray:
        """True at position i where Bob ended up holding Charlie's raw entry."""
        return np.array(
            [
                session.records[bit][Party.BOB].entries[index]
                is session.raw_records[bit][Party.CHARLIE].entries[index]
                for bit in (0, 1)
                for index in range(params.key_length)
            ]
        )

    predicted, actual = coins(rebuilt), coins(honest)
    assert len(actual) == 2 * COIN_PREDICTION_LENGTH == 120
    assert int((predicted == actual).sum()) == 120
    assert np.array_equal(predicted, actual)


# --------------------------------------------------------------------------- #
# The route nothing was watching, and the proof that it is watched now
# --------------------------------------------------------------------------- #


def test_check_a_is_not_vacuous_it_catches_a_call_time_reader() -> None:
    """The regression test for the Phase 3 audit's first finding.

    Every ready-made probe wrote ``del session_seed``, no shipped adversary
    declared a ``session_seed`` constructor argument, and so nothing whatsoever
    varied between the five calls check (a) compares. Fourteen adversaries
    passed a check none of them could fail.

    :class:`AmbientSessionForger` is that gap made concrete: a constructor
    taking ``rng`` alone -- so ``session_seed_offered`` is ``False``, exactly as
    for every shipped attack -- which nonetheless takes the seed while it is
    being called. Under the shipped check it passed. It must not now.
    """
    report = check_attack_isolation(AmbientSessionForger, signer_probe())
    assert report.session_seed_offered is False, (
        "the point of this control is that it dodges the constructor channel"
    )
    assert report.reads_the_session is True, report.summary()
    assert report.uses_its_own_generator is True  # ... so it is (a) that fired
    assert report.isolated is False
    assert set(report.offending_session_seeds) <= set(DEFAULT_SESSION_SEEDS[1:])
    assert report.offending_session_seeds != ()
    with pytest.raises(AttackIsolationError, match="reads the session"):
        assert_attack_isolated(AmbientSessionForger, signer_probe())


def test_an_adversary_drawing_from_global_randomness_is_caught() -> None:
    """D3's ban on global randomness, enforced by check (a) rather than asked for.

    A harness written for reproducibility seeds the process-global stream from
    the same constant it gives the session. An adversary drawing there is
    therefore correlated with the run it is attacking, and its rate is fiction
    for the same reason a seed-reader's is.

    The environment also makes the verdict *reproducible*: the global stream is
    now a deterministic function of the session seed, so the same candidate
    fails the same way on every run of this suite rather than depending on what
    else in the process last touched that stream.
    """
    report = check_attack_isolation(GlobalRandomnessForger, signer_probe())
    assert report.reads_the_session is True, report.summary()
    assert report.isolated is False
    again = check_attack_isolation(GlobalRandomnessForger, signer_probe())
    assert (
        again.decisions_across_session_seeds
        == report.decisions_across_session_seeds
    )


def test_an_adversary_seeded_from_the_session_is_caught() -> None:
    """One seed used twice, seen from the adversary's side.

    The measurement entry points refuse this at the door
    (:func:`~sih141.attacks.isolation.same_stream`); an attack wired up by hand
    can still arrive at it, and check (a) is the second line of defence.
    """
    report = check_attack_isolation(
        build_from_the_session_stream, signer_probe(), name="SessionStream"
    )
    assert report.reads_the_session is True, report.summary()
    assert report.uses_its_own_generator is True  # (b) still passes: (a) fired
    assert report.isolated is False


def test_the_three_routes_are_the_only_ones_that_move_a_clean_adversary() -> None:
    """The routes are open; an isolated adversary is untouched by them.

    A check that offers a leak has to be shown not to *create* one: the honest
    candidates must still pass with the environment installed, or the suite
    would have traded a vacuous check for a false-failure machine.
    """
    for build in (IsolatedForger, build_view_forger, DrawsAtCallTime):
        report = check_attack_isolation(build, signer_probe())
        assert report.isolated, report.summary()
        assert report.offending_session_seeds == ()


def test_the_environment_reproduces_the_session_s_own_material() -> None:
    """Faithfulness: the leak the environment offers is the real one.

    A control that merely produced different output per seed would catch a
    defect without standing for *this* one. What makes the session seed a
    catastrophe is that it reconstructs both recipients' private symmetrisation
    coins exactly, and it does so because ``QDSSession`` draws its whole seed
    material -- all three streams -- from one ``rng.bytes(32)`` off the
    generator it is given. :meth:`SessionEnvironment.stream_material` is that
    draw, and this pins the two together.
    """
    environment = SessionEnvironment(seed=SCENARIO_SEED)
    assert len(environment.stream_material()) == SESSION_MATERIAL_BYTES
    assert environment.stream_material() == np.random.default_rng(
        SCENARIO_SEED
    ).bytes(SESSION_MATERIAL_BYTES)

    # And a session built from that seed is reproducible from it, coin for coin.
    params = ProtocolParams(key_length=COIN_PREDICTION_LENGTH)
    honest = QDSSession(params, rng=np.random.default_rng(SCENARIO_SEED))
    honest.distribute()
    rebuilt = QDSSession(params, rng=environment.session_rng())
    rebuilt.distribute()
    assert rebuilt.records == honest.records
    assert rebuilt.raw_records == honest.raw_records


def test_the_environment_restores_everything_it_touched() -> None:
    """A check must leave no trace on the process it ran in.

    Global state written and not handed back is how one test starts depending
    on the order the suite happens to run in.
    """
    numpy_before = np.random.get_state()
    stdlib_before = random.getstate()
    assert active_session() is None
    with session_environment(904) as environment:
        assert active_session() is environment
        _ = np.random.random()
        _ = random.random()
    assert active_session() is None
    after = np.random.get_state()
    assert after[0] == numpy_before[0]
    assert np.array_equal(after[1], numpy_before[1])
    assert after[2:] == numpy_before[2:]
    assert random.getstate() == stdlib_before


def test_nested_environments_hand_the_outer_one_back_intact() -> None:
    """The docstring claims nesting is safe, so nesting is pinned.

    It happens for real: a probe that runs a whole session inside the
    environment -- the channel and distributor probes both do -- could one day
    want an environment of its own, and an inner one that clobbered the outer
    stream would silently change what check (a) was comparing.
    """
    before = np.random.get_state()
    with session_environment(901) as outer:
        first = float(np.random.random())
        with session_environment(902) as inner:
            assert active_session() is inner
        assert active_session() is outer
    with session_environment(901):
        again = float(np.random.random())
    assert first == again
    assert np.array_equal(np.random.get_state()[1], before[1])


def test_the_environment_is_restored_even_when_the_probe_raises() -> None:
    """A probe that blows up must not leave the globals seeded behind it."""
    before = np.random.get_state()
    with pytest.raises(RuntimeError, match="probe exploded"):
        with session_environment(905):
            raise RuntimeError("probe exploded")
    assert active_session() is None
    assert np.array_equal(np.random.get_state()[1], before[1])


def test_the_environment_validates_its_seed() -> None:
    """It is the integer a harness hands default_rng, and nothing else."""
    with pytest.raises(TypeError, match="seed must be an int"):
        SessionEnvironment(seed="901")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="seed must be an int"):
        SessionEnvironment(seed=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative"):
        SessionEnvironment(seed=-1)


# --------------------------------------------------------------------------- #
# Stream identity: what the guards were comparing, and what they compare now
# --------------------------------------------------------------------------- #


def test_two_generators_from_one_seed_are_one_stream() -> None:
    """The Phase 3 audit's second finding, stated as the property it needs.

    The shipped guards refused only the same *object*, which is the form of the
    mistake nobody makes. Everybody writes one ``SEED`` constant and two
    ``default_rng(SEED)`` calls, and those are one stream byte for byte -- which
    is the whole leak, since a session's three streams come out of one 32-byte
    draw off the generator it is handed.
    """
    left, right = np.random.default_rng(7), np.random.default_rng(7)
    assert left is not right
    assert same_stream(left, right)
    assert left.bytes(32) == np.random.default_rng(7).bytes(32)
    assert not same_stream(np.random.default_rng(7), np.random.default_rng(8))


def test_an_advanced_generator_is_still_the_same_stream() -> None:
    """Consuming from one of them does not make it independent of the other."""
    advanced = np.random.default_rng(7)
    _ = advanced.random(1000)
    fresh = np.random.default_rng(7)
    # Its position has moved, so the state half of the fingerprint differs ...
    assert stream_fingerprint(advanced)[1] != stream_fingerprint(fresh)[1]
    # ... and its derivation has not, which is what makes it the same stream.
    assert stream_fingerprint(advanced)[0] == stream_fingerprint(fresh)[0]
    assert same_stream(advanced, fresh)


def test_spawned_children_are_independent_and_are_not_refused() -> None:
    """The guard must not refuse the one correct way to split a generator.

    ``parent.spawn(2)`` is what a caller who wants two reproducible, genuinely
    independent streams should reach for, so refusing it would push people back
    towards two ``default_rng`` calls on one seed.
    """
    parent = np.random.default_rng(7)
    first, second = parent.spawn(2)
    assert not same_stream(first, second)
    assert not same_stream(first, np.random.default_rng(7))
    require_distinct_streams(
        first, second, left_name="rng", right_name="attack_rng"
    )


def test_derived_from_seed_is_the_seed_shaped_half_of_the_same_test() -> None:
    """The seed-shaped half, for the entry points that take a seed and an rng.

    :func:`~sih141.attacks.impersonation.run_impersonation` and
    :func:`~sih141.attacks.starvation.measure_starvation` take a session *seed*
    for one role and a *generator* for the other, so the two-generator guard
    does not fit them; before the audit they had no guard at all.
    """
    assert derived_from_seed(np.random.default_rng(500_000), 500_000)
    assert not derived_from_seed(np.random.default_rng(4242), 500_000)
    used = np.random.default_rng(500_000)
    _ = used.integers(0, 2, size=64)
    assert derived_from_seed(used, 500_000)


def test_require_distinct_streams_explains_the_leak_and_names_a_fix() -> None:
    """"Refused" is not actionable; the mechanism and the repair are."""
    with pytest.raises(ValueError) as excinfo:
        require_distinct_streams(
            np.random.default_rng(9),
            np.random.default_rng(9),
            left_name="rng",
            right_name="session_rng",
            detail="rng is the forger's own.",
        )
    message = str(excinfo.value)
    assert "rng and session_rng are the same stream (D6)" in message
    assert "symmetrisation coin" in message
    assert "rng is the forger's own." in message
    assert "spawn(2)" in message


def test_stream_helpers_refuse_a_non_generator() -> None:
    """A seed is not a generator, and the message says so throughout D3."""
    with pytest.raises(TypeError, match="numpy.random.Generator"):
        stream_fingerprint(7)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="numpy.random.Generator"):
        same_stream(np.random.default_rng(1), 1)  # type: ignore[arg-type]


def test_the_deaf_forger_is_caught_by_check_b() -> None:
    """The guard that stops check (a) passing vacuously."""
    report = check_attack_isolation(DeafForger, signer_probe())
    assert report.reads_the_session is False  # (a) is happy: it is constant
    assert report.uses_its_own_generator is False
    assert report.isolated is False
    assert report.distinct_decisions == 1


def test_the_deaf_forger_raises_saying_why_that_is_not_a_pass() -> None:
    """"Deterministic" must not read as "safe": (a) proved nothing about it."""
    with pytest.raises(AttackIsolationError) as excinfo:
        assert_attack_isolated(DeafForger, signer_probe())
    message = str(excinfo.value)
    assert "ignored the generator it was handed" in message
    assert "not a pass with a caveat" in message
    assert "proved nothing about this candidate" in message


# ==========================================================================
# The one way to get a probe wrong
# ==========================================================================


def test_a_probe_that_varies_the_observations_reports_a_false_failure() -> None:
    """Pinned rather than described, because the docs claim it.

    A probe that runs a fresh session per session seed hands a recipient-forger
    a *different measurement log* every time, so his declaration moves for an
    entirely honest reason. The isolated forger is then reported as reading the
    session. The fix is the probe, not the adversary -- which is why the failure
    message says so.
    """

    def naive_probe(attack: object, session_seed: int) -> object:
        """The wrong probe: fresh evidence per seed."""
        session = QDSSession(
            SCENARIO_PARAMS, rng=np.random.default_rng(session_seed)
        )
        session.distribute()
        return attack(  # type: ignore[operator]
            0, session.keys, SCENARIO_PARAMS, records=session.raw_records
        )

    assert check_attack_isolation(IsolatedForger, naive_probe).reads_the_session
    assert check_attack_isolation(IsolatedForger, signer_probe()).isolated


def test_the_frozen_scenario_is_what_makes_the_correct_probe_correct() -> None:
    """Every probe call replays one run; only the session seed differs."""
    probe = signer_probe()
    forger = DeafForger(rng=np.random.default_rng(0))
    first = probe(forger, DEFAULT_SESSION_SEEDS[0])
    second = probe(forger, DEFAULT_SESSION_SEEDS[-1])
    assert first == second


# ==========================================================================
# The scenario
# ==========================================================================


def test_signer_scenario_is_cached_frozen_and_read_only() -> None:
    """One distribution pays for a whole parametrised suite, and cannot drift."""
    scenario = signer_scenario()
    assert signer_scenario() is scenario
    assert isinstance(scenario, SignerScenario)
    with pytest.raises(dataclasses.FrozenInstanceError):
        scenario.message_bit = 1  # type: ignore[misc]
    with pytest.raises(TypeError):
        scenario.records[0][Party.BOB] = None  # type: ignore[index]
    with pytest.raises(TypeError):
        scenario.raw_records[0] = {}  # type: ignore[index]


def test_signer_scenario_is_an_honest_symmetrised_run() -> None:
    """The candidate must be reacting to a realistic Phase A outcome."""
    scenario = signer_scenario()
    assert scenario.params is SCENARIO_PARAMS
    assert sorted(scenario.records) == [0, 1]
    for bit in (0, 1):
        for party in (Party.BOB, Party.CHARLIE):
            assert scenario.records[bit][party].symmetrised is True
            assert scenario.raw_records[bit][party].symmetrised is False
            assert len(scenario.records[bit][party]) == SCENARIO_PARAMS.key_length
    assert [key.message_bit for key in scenario.keys] == [0, 1]


def test_scenario_seed_is_disjoint_from_the_varied_seeds() -> None:
    """A scenario an adversary could reach by guessing a seed proves nothing."""
    assert SCENARIO_SEED not in DEFAULT_SESSION_SEEDS
    assert SCENARIO_SEED not in DEFAULT_ATTACK_SEEDS
    assert not set(DEFAULT_SESSION_SEEDS) & set(DEFAULT_ATTACK_SEEDS)


def test_scenario_views_are_the_recipient_boundary() -> None:
    """The scenario hands out views, not the two-recipient mapping."""
    views = signer_scenario().views
    assert sorted(party.value for party in views) == ["Bob", "Charlie"]
    assert views[Party.BOB].party is Party.BOB
    assert views[Party.BOB].raw_record.party is Party.BOB
    assert views[Party.BOB].symmetrised is True
    assert views[Party.BOB].matched_count is None


def test_signer_scenario_validates_its_arguments() -> None:
    """A mis-built scenario would silently change what every candidate sees."""
    with pytest.raises(TypeError, match="must be a ProtocolParams"):
        signer_scenario(24)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="message_bit must be 0 or 1"):
        signer_scenario(message_bit=2)
    with pytest.raises(ValueError, match="seed must be non-negative"):
        signer_scenario(seed=-1)
    with pytest.raises(TypeError, match="seed must be an int"):
        signer_scenario(seed=1.5)  # type: ignore[arg-type]


def test_signer_probe_rejects_a_non_scenario() -> None:
    """The message names the constructor to use."""
    with pytest.raises(TypeError, match="signer_scenario"):
        signer_probe(object())  # type: ignore[arg-type]


# ==========================================================================
# The checker's own contract
# ==========================================================================


def test_a_builder_that_refuses_rng_is_refused_with_d6_quoted_at_it() -> None:
    """D6 enforced at the interface, not discovered as a TypeError deep inside."""

    class SeededForger:
        """The shape D6 forbids: built from an integer, not a generator."""

        def __init__(self, seed: int) -> None:
            self.seed = seed

    with pytest.raises(TypeError) as excinfo:
        check_attack_isolation(SeededForger, signer_probe())
    message = str(excinfo.value)
    assert "must accept a keyword argument 'rng'" in message
    assert "Convention D6" in message
    assert "symmetrisation coin" in message


def test_the_checker_validates_its_seeds_and_callables() -> None:
    """A single seed makes the verdict meaningless, so it is refused."""
    probe = signer_probe()
    with pytest.raises(ValueError, match="at least two distinct seeds"):
        check_attack_isolation(IsolatedForger, probe, session_seeds=(1, 1))
    with pytest.raises(ValueError, match="at least two distinct seeds"):
        check_attack_isolation(IsolatedForger, probe, attack_seeds=(7,))
    with pytest.raises(TypeError, match="must be an int"):
        check_attack_isolation(IsolatedForger, probe, session_seeds=(1, 2.5))
    with pytest.raises(ValueError, match="must be non-negative"):
        check_attack_isolation(IsolatedForger, probe, session_seeds=(1, -2))
    with pytest.raises(TypeError, match="must be a sequence"):
        check_attack_isolation(
            IsolatedForger, probe, session_seeds=5  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="probe must be a callable"):
        check_attack_isolation(IsolatedForger, "not a probe")  # type: ignore
    with pytest.raises(TypeError, match="must be a callable returning"):
        check_attack_isolation("not a builder", probe)  # type: ignore


def test_the_report_keeps_the_evidence_and_is_frozen() -> None:
    """"Not isolated" is not actionable; the seeds that moved it are."""
    report = check_attack_isolation(IsolatedForger, signer_probe())
    assert isinstance(report, IsolationReport)
    assert report.session_seeds == DEFAULT_SESSION_SEEDS
    assert report.attack_seeds == DEFAULT_ATTACK_SEEDS
    across_session = report.decisions_across_session_seeds
    across_attack = report.decisions_across_attack_seeds
    assert len(across_session) == len(DEFAULT_SESSION_SEEDS)
    assert len(across_attack) == len(DEFAULT_ATTACK_SEEDS)
    assert report.offending_session_seeds == ()
    assert report.distinct_decisions == len(DEFAULT_ATTACK_SEEDS)
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.attack = "other"  # type: ignore[misc]


def test_the_two_halves_share_their_anchor() -> None:
    """One probe call is saved, and both comparisons run against one point."""
    report = check_attack_isolation(IsolatedForger, signer_probe())
    assert (
        report.decisions_across_session_seeds[0]
        == report.decisions_across_attack_seeds[0]
    )


def test_the_summary_names_both_checks_and_the_verdict() -> None:
    """It is what a failure message ends with, so it has to read on its own."""
    lines = check_attack_isolation(IsolatedForger, signer_probe()).summary()
    assert lines.startswith("IsolatedForger: ISOLATED")
    assert "(a) vary session seed, fix own rng: 1 distinct" in lines
    assert "(b) vary own rng, fix session seed: 5 distinct" in lines
    assert "session_seed offered to the builder: no" in lines
    assert max(len(line) for line in lines.splitlines()) <= 79
    failing = check_attack_isolation(DeafForger, signer_probe()).summary()
    assert "DeafForger: NOT ISOLATED" in failing


def test_a_custom_name_and_wider_seed_lists_are_honoured() -> None:
    """A low-entropy candidate needs more seeds; the knob has to work."""
    report = check_attack_isolation(
        IsolatedForger,
        signer_probe(),
        session_seeds=(11, 12, 13),
        attack_seeds=(21, 22, 23, 24, 25, 26, 27),
        name="renamed",
    )
    assert report.attack == "renamed"
    assert report.session_seeds == (11, 12, 13)
    assert report.distinct_decisions == 7
    assert report.isolated


def test_assert_attack_isolated_returns_the_passing_report() -> None:
    """So a test that wants a further assertion need not run the check twice."""
    report = assert_attack_isolated(IsolatedForger, signer_probe())
    assert report.isolated
    assert report.attack == "IsolatedForger"


# ==========================================================================
# canonical
# ==========================================================================


def test_canonical_makes_arrays_comparable_and_hashable() -> None:
    """Arrays break both == and hash, which the check needs."""
    left = canonical(np.array([[1, 0], [0, 1]]))
    right = canonical(np.array([[1, 0], [0, 1]]))
    assert left == right
    assert len({left, right}) == 1
    assert canonical(np.array([1, 0])) != canonical(np.array([0, 1]))
    assert canonical(np.array([1, 0])) != canonical(np.array([1.0, 0.0]))


def test_canonical_ignores_mapping_order_and_sequence_flavour() -> None:
    """Two probes that build the same trace differently must compare equal."""
    assert canonical({"a": 1, "b": [2, 3]}) == canonical({"b": (2, 3), "a": 1})
    assert canonical({1, 2}) == canonical({2, 1})


def test_canonical_makes_nan_reflexive() -> None:
    """A nan in a trace must not report a false isolation failure."""
    assert canonical(float("nan")) == canonical(float("nan"))
    assert canonical([float("nan"), 1.0]) == canonical([float("nan"), 1.0])


def test_canonical_compares_dataclasses_by_content_and_type() -> None:
    """Signatures, keys and records are dataclasses; identity is not enough."""
    record_key = PrivateKey(0, (KeyElement("X", 1),))
    assert canonical(Signature(0, record_key)) == canonical(
        Signature(0, PrivateKey(0, (KeyElement("X", 1),)))
    )
    assert canonical(Signature(0, record_key)) != canonical(record_key)


def test_canonical_handles_numpy_scalars_and_str_enums() -> None:
    """Both turn up in traces: a drawn index, a party, a basis."""
    assert canonical(np.int64(3)) == canonical(3)
    assert canonical(Party.BOB) == canonical("Bob")


def test_canonical_refuses_an_opaque_object_with_an_explanation() -> None:
    """Its address would make every candidate look like it reads the session."""

    class Opaque:
        """No __eq__, no dataclass, default repr."""

    with pytest.raises(ValueError) as excinfo:
        canonical(Opaque())
    message = str(excinfo.value)
    assert "memory address" in message
    assert "reported as reading the session" in message


def test_canonical_refuses_a_cyclic_trace() -> None:
    """A live object graph is not a decision trace."""
    loop: list[object] = []
    loop.append(loop)
    with pytest.raises(ValueError, match="nests deeper than"):
        canonical(loop)


def test_a_probe_returning_an_opaque_object_fails_loudly_not_silently() -> None:
    """The failure has to be the probe's, not a bogus isolation verdict."""
    with pytest.raises(ValueError, match="memory address"):
        check_attack_isolation(
            IsolatedForger, lambda attack, session_seed: attack
        )


def test_a_builder_swallowing_keywords_is_offered_the_seed() -> None:
    """``**kwargs`` accepts everything, so it must be offered everything.

    Otherwise a candidate could dodge the construction-time half of check (a)
    simply by not naming the argument, while still being able to read it.
    """

    class Swallower:
        """Accepts anything and, in this instance, cheats with the seed."""

        def __init__(self, **kwargs: object) -> None:
            rng = kwargs["rng"]
            seed = kwargs["session_seed"]
            self.face = int(rng.integers(1000)) + int(seed)  # type: ignore

    report = check_attack_isolation(
        Swallower, lambda attack, session_seed: attack.face
    )
    assert report.session_seed_offered is True
    assert report.reads_the_session is True
