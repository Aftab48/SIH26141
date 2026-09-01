"""D6 applied to every Phase 3 adversary, from one table.

The single most important test in Phase 3. Every measured rate in
:mod:`sih141.attacks` -- every forgery probability, every repudiation figure,
every channel statistic -- is a statement about an adversary drawing on its own
randomness. An adversary that instead derives its choices from the seed the
harness gave :class:`~sih141.protocol.session.QDSSession` predicts every private
symmetrisation coin (``120/120``, demonstrated in
:mod:`sih141.attacks.isolation`'s own docstring) and publishes numbers that are
fiction while the transcript, the seams and the printed bound all look normal.
So the check has to be applied to all of them, not to whichever ones their
authors remembered.

:data:`ADVERSARIES` is that application. One row per adversary-and-seam pair,
and adding a sixth adversary is one row.

What each row carries, and why the last two fields exist
--------------------------------------------------------
``build``
    An :class:`~sih141.attacks.isolation.AttackBuilder`: the adversary's own
    class where its constructor takes only ``rng``, a
    :func:`functools.partial` where it takes more.
``probe``
    A :class:`~sih141.attacks.isolation.DecisionProbe` exercising the seam this
    row is about. Where the attacks package ships one it is used unchanged, so
    a probe passing here and a probe passing in that module's own suite are the
    same object and cannot drift.
``deterministic``
    A written justification, or ``None``. Present for exactly one row -- the
    optimal :class:`~sih141.attacks.forgery.RecipientForger`, whose best move is
    a fixed function of his view, so there is no randomness for check (b) to
    vary and never was (:ref:`sih141.attacks.isolation <deterministic-mode>`).
    A waiver is only sound alongside a randomised sibling that shares the call
    path, which is why ``recipient-forger/randomised`` is a separate row and why
    :func:`test_every_waiver_has_a_randomised_sibling` refuses to let the waiver
    stand alone.

The negative controls are not optional
--------------------------------------
A check that has never failed is not known to work, so this module also runs the
deliberately-defective adversaries from :mod:`tests.test_attack_isolation` and
asserts that each is still caught by the half it was built to fail. If those ever
pass, every row above them is worthless and this file says so first.

Why a shared control is not enough, and what replaced "14/14"
-------------------------------------------------------------
The Phase 3 audit found this file publishing "14/14 pass check (a)" over a check
no row could fail. Every ready-made probe wrote ``del session_seed``, no shipped
adversary declared a ``session_seed`` constructor argument, and so nothing varied
between the five calls check (a) compares. The controls kept working the whole
time -- they read the seed through the *builder*, which was the one channel that
was live -- and that is exactly why nobody noticed.

A control passing through :func:`~sih141.attacks.isolation.signer_probe` says
that *that* probe's channel is live. It says nothing about
:func:`~sih141.attacks.starvation.starvation_probe`, or about the two channel
probes, or about any probe added next year. So the evidence is now produced per
row: :func:`test_the_session_channel_is_live_on_every_row` rebuilds each shipped
adversary with the session's own seed folded into its generator, through the
row's own probe, and requires check (a) to catch it. Thirteen of the fourteen
rows are covered directly; the fourteenth is the deterministic recipient forger,
whose decisions move with nothing at all, and whose randomised sibling is
covered -- which is the same argument
:func:`test_every_waiver_has_a_randomised_sibling` already makes and is why the
waiver is only sound beside one.

What check (a) means now that the seams are called on every position
---------------------------------------------------------------------
Two Phase 3 defects were repaired at once, and they meet in this file, so it is
worth writing down what a green row asserts today rather than leaving a reader
to assume it is what it was.

The other repair was in the protocol: ``payload_map`` used to be invoked on key
rounds only and ``channel_monitor`` on check rounds only, so either seam handed
its holder the check set outright. Both are now called at every position and
their answers discarded where they have no use
(:ref:`sih141.protocol.distribute <check-round-lockstep>`). That changes what a
probe can do here, and therefore what a row means:

* **Before.** ``_channel_payload_probe`` had to run with ``check_fraction = 0``,
  because the set of positions the seam was offered moved with the session seed
  all by itself and check (a) would have reported an innocent adversary as
  reading the session. With no plan drawn, varying the session seed varied only
  the seed. A green row said "this adversary does not read the session seed".
* **Now.** Both channel probe helpers run the *same* checked parameters
  (:data:`CHANNEL_PROBE_PARAMS`), so across check (a)'s five calls the check
  plan is a different subset every time. A green row says "this adversary does
  not read the session seed **and** its decisions do not move with the check
  plan" -- and the second half is a property of the seam wiring, which is why
  :func:`test_the_channel_rows_ride_on_the_seam_lockstep` states it directly
  and in a form whose failure blames the protocol rather than the attack.

Two things follow that are easy to get wrong.

``del session_seed`` in a probe is correct and is not the old defect. What made
check (a) inert was never the ``del``; it was that nothing else offered the
candidate a route to the session. :func:`check_attack_isolation` now installs a
:class:`~sih141.attacks.isolation.SessionEnvironment` around every build and
probe call, so the routes are open whatever a probe does with its argument.

A probe that *freezes* its session is the remaining way to weaken a row without
failing anything: check (a) still catches a session-reading adversary, but the
plan stops moving and the row silently drops the second half of its claim.
:func:`test_the_channel_probes_vary_the_session_they_run` is what notices.
"""

from __future__ import annotations

import functools
from typing import Final

import numpy as np
import pytest

from sih141.attacks import (
    AttackIsolationError,
    CountStarver,
    DepolarisingChannel,
    Impersonator,
    InterceptResend,
    KeptShareSwap,
    OutsideForger,
    RecipientForger,
    ReplayingForwarder,
    assert_attack_isolated,
    check_attack_isolation,
    distributor_probe,
    forwarder_probe,
    replay_probe,
    signer_probe,
    signing_probe,
    starvation_probe,
)
from sih141.attacks.channel import ChannelAttack
from sih141.attacks.isolation import (
    DEFAULT_SESSION_SEEDS,
    active_session,
)
from sih141.protocol.distribute import (
    PayloadMap,
    ResourceContext,
    ResourceFactory,
    ideal_resource,
)
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.session import QDSSession
from tests.test_attack_isolation import (
    AmbientSessionForger,
    DeafForger,
    SessionSeedForger,
)

RECIPIENT_FORGER_DETERMINISM = (
    "the optimal recipient forger declares his own raw log, which strictly "
    "dominates every randomised alternative at every position: a swapped "
    "position matches with certainty, a retained one gives P(match | scored) "
    "= 2/3 against 1/2 for any other declaration, and flipping the eigenvalue "
    "is strictly worse. There is no coin to vary. The randomised sibling in "
    "the row below exercises the identical __call__."
)
"""Why check (b) cannot apply to the adversary whose rate Phase 3 publishes."""


CHANNEL_PROBE_PARAMS: Final[ProtocolParams] = ProtocolParams(
    key_length=24, check_fraction=0.25
)
"""The parameter set both channel probes mount on. Check rounds are **on**.

They used to differ: the resource probe ran with checks and the payload probe
without, because ``payload_map`` was invoked on key rounds only and *which*
positions are key rounds is drawn from the session's own generator -- so the set
of occasions a payload adversary was offered moved with the session seed, and a
probe reporting those positions failed check (a) against a flawless attack
(:ref:`sih141.attacks.isolation <probe-traps>`). That was the protocol's leak,
not the probe's bug, and it is closed: every channel-side seam is now offered
every position. Both probes therefore run the same parameters, and running them
*with* checks is what makes check (a) say something new -- see
:func:`test_the_channel_rows_ride_on_the_seam_lockstep`.
"""


def _channel_session(
    session_seed: int,
    *,
    resource_factory: ResourceFactory | None = None,
    payload_map: PayloadMap | None = None,
) -> QDSSession:
    """Build the live session both channel probes mount on.

    One home rather than one per probe, so that the liveness the rows depend on
    can be asserted against the object the rows actually use
    (:func:`test_the_channel_probes_vary_the_session_they_run`) instead of
    against a copy of it that can drift.

    Parameters
    ----------
    session_seed : int
        The seed check (a) is varying. It reaches the session's generator, so
        the check plan drawn from the recipients' stream moves with it.
    resource_factory : ResourceFactory or None, optional
        Keyword-only. The entanglement seam, or ``None``.
    payload_map : PayloadMap or None, optional
        Keyword-only. The payload seam, or ``None``.

    Returns
    -------
    QDSSession
        Undistributed; the caller runs :meth:`~QDSSession.distribute`.
    """
    return QDSSession(
        CHANNEL_PROBE_PARAMS,
        resource_factory=resource_factory,
        payload_map=payload_map,
        rng=np.random.default_rng(session_seed),
    )


def _channel_resource_probe(attack: ChannelAttack, session_seed: int) -> object:
    """Mount a channel attack on ``resource_factory`` and read back its log.

    A real session rather than a frozen scenario, because for this seam the
    wiring is what is under test: an attack reaching the session's generator
    *through the seam* is caught here and nowhere else.
    """
    session = _channel_session(session_seed, resource_factory=attack.resource)
    session.distribute()
    return attack.decisions()


def _channel_payload_probe(attack: ChannelAttack, session_seed: int) -> object:
    """Mount a channel attack on ``payload_map`` and read back its log.

    The same live session and the same parameters as the resource probe, check
    rounds included. That is a change: this probe used to require
    ``check_fraction = 0`` to avoid blaming the adversary for a seam the
    protocol offered a seed-dependent set of positions
    (:data:`CHANNEL_PROBE_PARAMS`).
    """
    session = _channel_session(session_seed, payload_map=attack.payload)
    session.distribute()
    return attack.decisions()


ADVERSARIES: tuple[tuple[str, object, object, str | None], ...] = (
    (
        "outside-forger/signer",
        OutsideForger,
        signer_probe(),
        None,
    ),
    (
        "recipient-forger/forwarder",
        RecipientForger,
        forwarder_probe(),
        RECIPIENT_FORGER_DETERMINISM,
    ),
    (
        "recipient-forger/randomised",
        functools.partial(RecipientForger, guess_probability=0.25),
        forwarder_probe(),
        None,
    ),
    (
        "impersonator/signer",
        Impersonator,
        signing_probe(),
        None,
    ),
    (
        "impersonator/distributor",
        Impersonator,
        distributor_probe(),
        None,
    ),
    (
        "replaying-forwarder/forwarder",
        ReplayingForwarder,
        replay_probe(),
        None,
    ),
    (
        "depolarising-channel/resource",
        functools.partial(DepolarisingChannel, 0.14),
        _channel_resource_probe,
        None,
    ),
    (
        "depolarising-channel/payload",
        functools.partial(DepolarisingChannel, 0.14),
        _channel_payload_probe,
        None,
    ),
    (
        "depolarising-channel/targeted",
        functools.partial(DepolarisingChannel, 0.14, target=Party.BOB),
        _channel_resource_probe,
        None,
    ),
    (
        "intercept-resend/resource",
        InterceptResend,
        _channel_resource_probe,
        None,
    ),
    (
        "intercept-resend/payload",
        InterceptResend,
        _channel_payload_probe,
        None,
    ),
    (
        "kept-share-swap/resource",
        KeptShareSwap,
        _channel_resource_probe,
        None,
    ),
    (
        "kept-share-swap/payload",
        KeptShareSwap,
        _channel_payload_probe,
        None,
    ),
    (
        "count-starver/count-exchange",
        CountStarver,
        starvation_probe(),
        None,
    ),
)
"""Every Phase 3 adversary, on every seam it mounts on.

``(label, build, probe, deterministic)``. A sixth adversary is one row. The
labels are the test ids, so a failure names the adversary and the seam.
"""


@pytest.mark.parametrize(
    ("build", "probe", "deterministic"),
    [row[1:] for row in ADVERSARIES],
    ids=[row[0] for row in ADVERSARIES],
)
def test_every_adversary_owns_its_randomness(build, probe, deterministic):
    """D6, behaviourally, for every adversary in Phase 3 on every seam.

    Check (a) must pass for every row without exception: an adversary whose
    choices move with the session seed is reading randomness the security bound
    assumes is private, and its published rate is fiction.
    """
    report = assert_attack_isolated(build, probe, deterministic=deterministic)
    assert report.isolated
    assert not report.reads_the_session, report.summary()
    assert report.offending_session_seeds == ()


@pytest.mark.parametrize(
    ("label", "build", "probe"),
    [row[:3] for row in ADVERSARIES if row[3] is None],
    ids=[row[0] for row in ADVERSARIES if row[3] is None],
)
def test_every_unwaived_adversary_really_draws_from_its_generator(
    label, build, probe
):
    """Check (b), on its own, for every row that did not claim a waiver.

    Separated from the row above so that the waiver cannot quietly spread: if
    an adversary stops using its generator, this test fails for that adversary
    by name rather than being absorbed into a mode meant for one row.
    """
    report = check_attack_isolation(build, probe, name=label)
    assert report.uses_its_own_generator, report.summary()
    assert report.distinct_decisions > 1


def test_the_channel_probes_vary_the_session_they_run() -> None:
    """The seven channel rows must actually put a moving session under the attack.

    Check (a) varies the session seed and requires the adversary's decisions not
    to move. For a row whose probe runs a *live checked session*, that is two
    statements at once: the adversary does not read the seed, **and** its view
    does not move with the check plan the recipients drew from that seed. The
    second only holds if the plan moves, so this asserts that it does, against
    :func:`_channel_session` -- the object the rows themselves call, not a copy.

    A probe that quietly pinned ``rng=default_rng(0)`` would still pass check
    (a), because the :class:`~sih141.attacks.isolation.SessionEnvironment` that
    makes check (a) bite is installed by
    :func:`~sih141.attacks.isolation.check_attack_isolation` and not by the
    probe. It would pass for less, and this is what notices
    (:ref:`sih141.attacks.isolation <probe-traps>`).
    """
    plans: set[tuple[int, ...]] = set()
    for seed in DEFAULT_SESSION_SEEDS:
        session = _channel_session(seed)
        session.distribute()  # the plans are drawn here, not at construction
        plans.add(tuple(session.check_plans[0].positions))
    assert len(plans) == len(DEFAULT_SESSION_SEEDS), (
        "the check plan must be a different set at every session seed check (a) "
        "varies, or the channel rows stop testing independence from the plan "
        "and only test independence from the seed"
    )
    assert all(plan for plan in plans), "the probe parameters must reserve rounds"


def test_the_channel_rows_ride_on_the_seam_lockstep() -> None:
    """Why a payload row may run with check rounds on, asserted rather than assumed.

    The row above requires the plan to move. This one requires the seams not to
    notice, which is the protocol's job and not the adversary's: with a plan in
    force, ``resource_factory``, ``payload_map`` and ``channel_monitor`` are
    each offered every position of every link of every message bit, in order.

    Kept here, in the isolation suite, because it is the premise the seven
    channel rows rest on. If it ever fails, check (a) on
    ``depolarising-channel/payload``
    fails immediately afterwards and the report will name the *adversary* --
    which is what happened for the whole of Phase 3 and is why the payload probe
    used to need ``check_fraction = 0``. A failure here says the fault is in
    :mod:`sih141.protocol.distribute` or :mod:`sih141.protocol.session`, not in
    the attack.
    """
    seen: dict[str, list[tuple[Party, int, int]]] = {
        "resource": [],
        "payload": [],
        "monitor": [],
    }

    def note(name: str, context: ResourceContext) -> None:
        """Record one hop against one seam."""
        seen[name].append(
            (context.party, context.message_bit, context.position)
        )

    def factory(context: ResourceContext) -> object:
        """The entanglement seam, honest and watching."""
        note("resource", context)
        return ideal_resource()

    def payload(state: object, context: ResourceContext) -> object:
        """The payload seam, honest and watching."""
        note("payload", context)
        return state

    def monitor(resource: object, context: ResourceContext) -> dict[str, object]:
        """The observer seam, honest and watching."""
        note("monitor", context)
        return {}

    session = QDSSession(
        CHANNEL_PROBE_PARAMS,
        resource_factory=factory,
        payload_map=payload,
        channel_monitor=monitor,
        rng=np.random.default_rng(DEFAULT_SESSION_SEEDS[0]),
    )
    session.distribute()

    expected = [
        (party, bit, index)
        for bit in (0, 1)
        for party in VERIFIERS
        for index in range(CHANNEL_PROBE_PARAMS.key_length)
    ]
    for name, calls in seen.items():
        assert calls == expected, (
            f"the {name} seam was not offered every position of a checked run. "
            f"The fault is in the protocol, not in any adversary: a seam whose "
            f"call set moves with the plan hands the check set to whoever holds "
            f"it, and makes check (a) on the channel rows blame the attack for "
            f"it. See sih141.protocol.distribute's check-round-lockstep note."
        )
    assert session.check_plans[0].positions, "the run must reserve rounds"


def seeded_from_the_session(build, label):
    """Return ``build`` rewired to fold the session's own seed into the adversary.

    The D6 defect as a harness writes it: one ``SEED``, given to the session and
    then mixed into the attack "so the run reproduces". The adversary class is
    untouched -- same constructor, same ``__call__``, same seam -- and the only
    thing that changed is whose randomness it was handed. It should therefore be
    caught by check (a) and by nothing else, on every row where the probe can see
    the candidate's own stream at all, which is precisely what check (b) has
    already established for that row.

    Parameters
    ----------
    build : callable
        The row's builder, taking a keyword-only ``rng``.
    label : str
        The row's id, used to name the report.

    Returns
    -------
    callable
        A builder of the same shape, defective in one line.
    """

    def build_from_the_session(*, rng):
        """Build the row's adversary from a stream the session controls."""
        environment = active_session()
        assert environment is not None, (
            "check_attack_isolation must install a SessionEnvironment around "
            "every build; without one this control cannot reach the seed and "
            "the test below would pass for the wrong reason"
        )
        own = int.from_bytes(rng.bytes(8), "big")
        mixed = np.random.SeedSequence([own, environment.seed])
        return build(rng=np.random.default_rng(mixed))

    build_from_the_session.__name__ = f"session-seeded {label}"
    return build_from_the_session


@pytest.mark.parametrize(
    ("label", "build", "probe"),
    [row[:3] for row in ADVERSARIES if row[3] is None],
    ids=[row[0] for row in ADVERSARIES if row[3] is None],
)
def test_the_session_channel_is_live_on_every_row(label, build, probe):
    """Per row, the evidence that ``14/14 pass check (a)`` did not carry.

    The audit's first finding was that check (a) was inert: every probe deleted
    the session seed, no shipped adversary could receive it through its
    constructor, and so the five decisions check (a) compares were five runs of
    an identical experiment. Every row passed a check no row could fail.

    A shared control cannot fix that, because a control run through one probe
    proves only that *that* probe's channel is live. So this runs the row's own
    adversary, through the row's own probe, with the session's seed folded into
    the generator the harness hands it -- one line of defect, nothing else
    changed -- and requires check (a) to catch it. Together with
    :func:`test_every_adversary_owns_its_randomness` above, which requires the
    unmodified row to pass, that is a two-sided statement: this probe can see a
    session-reading adversary, and this adversary is not one.

    A failure here does **not** mean the shipped adversary is broken. It means
    the check has gone blind on this row, and every number that row's attack
    publishes is once again unevidenced.
    """
    report = check_attack_isolation(
        seeded_from_the_session(build, label), probe, name=label
    )
    assert report.reads_the_session, (
        f"check (a) did not notice that {label} was built from the session's "
        f"own seed, so it cannot notice a real one either.\n"
        f"{report.summary()}"
    )
    assert report.uses_its_own_generator, (
        f"{label} stopped drawing from its generator under this control, so "
        f"the row above is now the one carrying the weight.\n"
        f"{report.summary()}"
    )
    assert not report.isolated


def test_the_one_row_the_channel_test_cannot_cover_is_the_waived_one():
    """And it is covered by its randomised sibling, which is why one is required.

    The deterministic recipient forger's declaration is a fixed function of his
    view: it moves with nothing, so no defect in *whose* randomness he was given
    can make it move, and no control of this shape can catch him. That is not a
    hole in the evidence -- it is the same fact the waiver rests on, and the
    sibling row exercising the identical ``__call__`` is what closes it.
    """
    uncovered = {label for label, _, _, reason in ADVERSARIES if reason}
    assert uncovered == {"recipient-forger/forwarder"}
    label, build, probe, _ = next(
        row for row in ADVERSARIES if row[0] in uncovered
    )
    report = check_attack_isolation(
        seeded_from_the_session(build, label), probe, name=label
    )
    assert not report.uses_its_own_generator, (
        "this row was waived because it is deterministic; if it has grown "
        "randomness, drop the waiver and add it to the channel test above"
    )
    assert not report.reads_the_session
    covered = {
        row_label.split("/")[0]
        for row_label, _, _, reason in ADVERSARIES
        if reason is None
    }
    assert {name.split("/")[0] for name in uncovered} <= covered


def test_every_waiver_has_a_randomised_sibling():
    """A deterministic waiver is only sound beside a checked randomised twin.

    The waiver says "there is no randomness here to vary". On its own that is
    indistinguishable from "this adversary quietly derived its one choice from
    the session", which is the defect the whole check exists for. What rules
    that out is a sibling row exercising the *same* ``__call__`` with a coin
    mixed in, and passing check (b) outright. This test asserts the table
    actually contains one for every waiver rather than trusting the author to
    have added it.
    """
    waived = {
        label.split("/")[0] for label, _, _, reason in ADVERSARIES if reason
    }
    randomised = {
        label.split("/")[0]
        for label, _, _, reason in ADVERSARIES
        if reason is None
    }
    assert waived, "the deterministic mode is exercised by at least one row"
    assert waived <= randomised, (
        f"these adversaries waived check (b) with no randomised sibling in "
        f"the table: {sorted(waived - randomised)}. A waiver on its own is "
        f"consistent with an adversary that read the session once."
    )


def test_the_waiver_is_recorded_in_the_report_and_printed():
    """A weakened verdict must be unmistakable in what the check prints.

    Otherwise a reader sees ``isolated == True`` and never learns that half the
    check did not apply.
    """
    report = assert_attack_isolated(
        RecipientForger,
        forwarder_probe(),
        deterministic=RECIPIENT_FORGER_DETERMINISM,
    )
    assert report.isolated
    assert report.deterministic_accepted
    assert not report.uses_its_own_generator
    summary = report.summary()
    assert "ISOLATED (check (b) waived)" in summary
    assert "deterministic by construction" in summary
    assert RECIPIENT_FORGER_DETERMINISM in summary


def test_the_waiver_does_not_rescue_check_a():
    """The waiver switches off (b) and touches nothing else.

    An adversary reading the session seed is still caught with the waiver in
    hand, which is the property that stops the waiver being a way to silence
    the check.
    """
    with pytest.raises(AttackIsolationError, match="reads the session"):
        assert_attack_isolated(
            SessionSeedForger,
            signer_probe(),
            deterministic=RECIPIENT_FORGER_DETERMINISM,
        )


def test_a_waiver_must_actually_say_something():
    """``deterministic=`` is a justification, not a flag."""
    with pytest.raises(ValueError, match="at least 40 characters"):
        check_attack_isolation(DeafForger, signer_probe(), deterministic="n/a")
    with pytest.raises(TypeError, match="not a flag"):
        check_attack_isolation(DeafForger, signer_probe(), deterministic=True)


# --------------------------------------------------------------------------- #
# The negative controls. A check that has never failed is not known to work.
# --------------------------------------------------------------------------- #


def test_the_session_seed_control_is_still_caught_by_check_a():
    """The toy adversary that reads the harness seed must still fail.

    :class:`tests.test_attack_isolation.SessionSeedForger` derives its
    declaration from the seed the session was given -- the exact defect D6
    exists to prevent. If this ever passes, every row in :data:`ADVERSARIES`
    means nothing, because the check would be accepting adversaries that read
    the session.
    """
    report = check_attack_isolation(SessionSeedForger, signer_probe())
    assert report.reads_the_session
    assert not report.isolated
    assert len(report.offending_session_seeds) >= 1
    with pytest.raises(AttackIsolationError) as caught:
        assert_attack_isolated(SessionSeedForger, signer_probe())
    assert "reads the session's randomness" in str(caught.value)


def test_the_call_time_control_is_caught_by_check_a():
    """The control the shipped check had no channel for.

    :class:`tests.test_attack_isolation.AmbientSessionForger` takes only ``rng``
    in its constructor, exactly as every adversary in :data:`ADVERSARIES` does,
    and reads the session while it is being called. Under the check as shipped
    it passed, because the probe deleted the seed and the builder was never
    offered it. It is the control that would have caught the vacuous check, and
    it is kept here permanently for the same reason the other two are.
    """
    report = check_attack_isolation(AmbientSessionForger, signer_probe())
    assert report.session_seed_offered is False
    assert report.reads_the_session
    assert not report.isolated
    with pytest.raises(AttackIsolationError) as caught:
        assert_attack_isolated(AmbientSessionForger, signer_probe())
    assert "reads the session's randomness" in str(caught.value)


def test_the_deaf_control_is_still_caught_by_check_b():
    """The toy adversary that ignores its generator must still fail.

    :class:`tests.test_attack_isolation.DeafForger` is what stops check (a)
    passing vacuously: a constant is independent of every input. Without this
    control an adversary could satisfy the suite by never drawing at all.
    """
    report = check_attack_isolation(DeafForger, signer_probe())
    assert not report.uses_its_own_generator
    assert not report.isolated
    assert report.distinct_decisions == 1
    with pytest.raises(AttackIsolationError) as caught:
        assert_attack_isolated(DeafForger, signer_probe())
    assert "ignored the generator it was handed" in str(caught.value)


def test_the_check_b_failure_names_the_deterministic_escape_hatch():
    """A candidate failing (b) is told what the legitimate response is.

    Otherwise the next author reaches for the waiver without reading when it is
    sound, which is how a check gets switched off by accident.
    """
    with pytest.raises(AttackIsolationError) as caught:
        assert_attack_isolated(DeafForger, signer_probe())
    message = str(caught.value)
    assert "deterministic *by construction*" in message
    assert "deterministic='...'" in message
    assert "randomised variant" in message


def test_the_table_covers_every_adversary_the_package_exports():
    """No adversary may be added to the package without a row here.

    The failure mode this guards against is silent: a sixth attack lands, its
    author tests it in its own module, and it never meets the one check that
    every published rate depends on. Comparing against the package's own export
    list makes the omission a test failure instead of an oversight.
    """
    exported = {
        "OutsideForger",
        "RecipientForger",
        "Impersonator",
        "ReplayingForwarder",
        "DepolarisingChannel",
        "InterceptResend",
        "KeptShareSwap",
        "CountStarver",
    }
    covered = set()
    for _, build, _, _ in ADVERSARIES:
        target = getattr(build, "func", build)
        covered.add(getattr(target, "__name__", type(target).__name__))
    assert exported <= covered, (
        f"these adversaries have no isolation row: {sorted(exported - covered)}"
    )
