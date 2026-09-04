"""Phase 3: the replay adversary, measured against the defence it was built for.

The defence exists already. :ref:`sih141.protocol.verify <replay>` builds it in
two halves -- a round identifier both sides carry, and a per-verifier
:class:`~sih141.protocol.verify.ConsumedRecords` ledger -- and this module is
the other side of that transaction: an adversary who tries to break each half,
with every claim carried by a measured rate rather than by an assertion.

Four questions, and the honest answers
--------------------------------------
Each is measured twice, with the defence enabled and with it disabled, because
"the attack fails" means nothing without the number it used to be.

**(a) Straight re-verification.** A captured declaration re-presented to the
verifier who already scored it. The ledger refuses it
(:attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`) and the
defence holds outright. :func:`measure_straight_replay`.

**(b) Cross-session pairing.** Run A's declaration scored against run B's
records. The round binding refuses it before any counting happens
(:attr:`~sih141.protocol.verify.AbortReason.SESSION_MISMATCH`). Undefended, it
is refused by nothing and decided by luck alone, at exactly the rate an outside
forger faces -- which is the point:
:func:`~sih141.protocol.analysis.forgery_probability` is the analytic
prediction and the measurement agrees with it.
:func:`measure_cross_session_pairing`.

**(c) The ledger, turned around.** *This is the finding.* Entries cannot be
added from outside -- a refusal spends nothing, so an unbounded stream of bogus
presentations grows a ledger by zero (:func:`measure_ledger_poisoning`) -- but
an adversary does not need to add an entry he is not entitled to. He needs the
*verifier* to spend one. The declaration reveals its own opening in Phase B, so
anyone on the Bob-to-Charlie hop -- which is exactly where the threat model puts
an adversary -- can mint a declaration that names the live round, hand it to
Charlie, and let Charlie reject it. Charlie has now spent the round, because a
rejection is a verdict. The genuine declaration, arriving afterwards by any
route, is refused rather than accepted, **permanently**: the ledger converts a
one-shot denial into an unrecoverable one.

What stops it is not the replay defence but **Phase C'**, and only under one
ordering. A count names the declaration it counted, so if Bob's count reaches
Charlie naming the declaration *Alice signed* while Charlie is looking at the
forged one, Charlie refuses on provenance and spends nothing. That is what the
shipped :class:`~sih141.protocol.session.QDSSession` does, because it runs
Phase C' before the forwarding hop. It is not what a deployment does: each
recipient counts against the declaration he received, the adversary holding the
hop is also the recipient computing one of the two counts, and he counts against
what he forwards. :func:`measure_ledger_denial_of_service` measures all three
orderings, and the honest summary is that the ledger's denial-of-service
surface is closed by an accident of ordering in one component rather than by
anything in the replay defence itself.

**(d) The identifier.** A signer can give two rounds one identifier by reusing
an opening, and gains nothing by it -- the second round's declaration is scored
against the first round's key and rejected on the rate, and her verifier's
ledger has already spent the identifier, so she has denied herself
(:func:`measure_shared_identifier`). Forging an identifier so a stale
declaration looks fresh is a 128-bit preimage search on an injective encoding;
:func:`measure_identifier_preimage` runs a bounded one and finds nothing, which
is the only honest thing a bounded search can report.

What is being attacked, and from where
--------------------------------------
:class:`ReplayingForwarder` is the seam-level adversary: the party holding the
Bob-to-Charlie hop (:class:`~sih141.protocol.session.Forwarder`), substituting a
declaration he captured earlier for the one he was asked to pass on. He holds
his own generator (**D6**) and never reads the session's, which
:func:`replay_probe` demonstrates rather than asserts.

The measurement functions do **not** go through that seam, and the reason is a
seam property worth knowing about rather than a shortcut: the session rebinds
whatever a forwarder returns to the live round, so a stale declaration pushed
through the seam arrives at Charlie *relabelled as fresh* and is scored as a
forgery. That is deliberate -- it is what stops every forgery detection
collapsing into a no-verdict -- but it means the seam cannot express a
cross-round replay at all. A faithful cross-round experiment assembles the pair
itself and calls :func:`~sih141.protocol.verify.verify_or_abort` directly, which
is what these functions do.

Key length, and what a small one is allowed to say
--------------------------------------------------
The measurements run at ``L = 24`` to ``96``. Below ``L = 140`` both
matched-count floors degenerate (``m_min = 1``) and carry no security claim, so
nothing here should be read as exhibiting security at scale. It does not need to
be: three of the four defended results are **rules, not rates** -- a session
mismatch, a spent round and a refused cross-party record are decided by an
equality test that no key length changes -- so a ``0`` out of ``N`` at ``L = 24``
is the same ``0`` at ``L = 115200``. The one genuinely statistical result is the
*undefended* cross-session acceptance rate, and that one has a closed form
(:func:`~sih141.protocol.analysis.forgery_probability`) which the measurement is
compared against here and which shrinks like ``exp(-L * c)``: ``1.3e-2`` at
``L = 24``, ``6.3e-16`` at ``L = 192``, and past every floating-point floor at
``L = 115200``. The denial-of-service result is likewise a rule, and it gets
*worse* with ``L``, since a longer key makes the forged declaration Charlie
rejects no less scorable.

Notes
-----
Determinism (D3, D6)
    Every function takes its generators explicitly. The *world* generator builds
    sessions; the *attack* generator is the adversary's own, and the two are
    required to be different objects, checked and refused rather than trusted.
    An adversary built from the seed the harness gives
    :class:`~sih141.protocol.session.QDSSession` predicts every symmetrisation
    coin (:mod:`sih141.attacks.isolation`), and the natural way to write a
    reproducible experiment is precisely how one gets there by accident.
No machine learning (D4)
    Counting, one Wilson interval, and a hash.

See Also
--------
sih141.protocol.verify.ConsumedRecords : The ledger half of the defence.
sih141.protocol.signature.session_identifier : The binding half.
sih141.attacks.isolation : The D6 check every adversary here satisfies.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from sih141.attacks.isolation import require_distinct_streams
from sih141.attacks.statistics import wilson_bounds
from sih141.protocol.analysis import forgery_probability
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.records import RecipientRecord, RecipientView
from sih141.protocol.session import QDSSession
from sih141.protocol.signature import Signature, session_identifier
from sih141.protocol.tally import (
    exchange_matched_counts,
    matched_count_message,
)
from sih141.protocol.verify import (
    AbortReason,
    ConsumedRecords,
    VerificationAbort,
    VerificationResult,
    verify_or_abort,
)

__all__ = [
    "CAPTURE_PARAMS",
    "CAPTURE_SEED",
    "COUNTS_AS_RECEIVED",
    "COUNTS_AS_SIGNED",
    "COUNTS_NONE",
    "AttackOutcome",
    "ReplayCapture",
    "ReplayingForwarder",
    "measure_cross_session_pairing",
    "measure_identifier_preimage",
    "measure_ledger_denial_of_service",
    "measure_ledger_poisoning",
    "measure_shared_identifier",
    "measure_shared_identifier_self_denial",
    "measure_straight_replay",
    "replay_capture",
    "replay_probe",
    "wilson_interval",
]


CAPTURE_SEED: Final[int] = 41200626
"""Seed of the one finished run :func:`replay_capture` freezes.

The adversary's *loot*: a declaration and the records of a round that is over.
Deliberately unrelated to every seed a measurement or the D6 check varies, so
that nothing an experiment does can move what the adversary is holding.
"""

CAPTURE_PARAMS: Final[ProtocolParams] = ProtocolParams(key_length=24)
"""Parameters for the frozen capture -- small, because it is built on demand.

No security claim is attached to it: it exists to give
:class:`ReplayingForwarder` something realistic to re-present and to give
:func:`replay_probe` a fixed observation to hold still. Below ``L = 140`` both
matched-count floors degenerate anyway.
"""

_Z_95: Final[float] = 1.959963984540054
"""Standard normal two-sided 95% quantile, for :func:`wilson_interval`."""

_OPENING_HEX_BYTES: Final[int] = 16
"""Width of an invented opening, matching the one the protocol draws."""

COUNTS_NONE: Final[str] = "none"
"""Phase C' did not run: the pre-pooled variant, per-verifier floors only.

What :func:`sih141.protocol.tally.no_count_exchange` selects. Nothing checks
which declaration a count was taken against, because there is no count.
"""

COUNTS_AS_RECEIVED: Final[str] = "as-received"
"""Each recipient counted against the declaration he actually received.

The deployment reading of Phase C', and the one that matters for
:func:`measure_ledger_denial_of_service`: the adversary holds the hop *and*
computes one of the two counts, so he counts against what he forwards and the
provenance check sees one consistent declaration.
"""

COUNTS_AS_SIGNED: Final[str] = "as-signed"
"""Both counts named the declaration Alice signed, whatever Charlie then got.

The shipped :class:`~sih141.protocol.session.QDSSession` ordering, which runs
Phase C' before the forwarding hop. It makes an altered forwarding visible as
:attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`, which
turns out to be the only thing standing between the hop and Charlie's ledger.
"""

_COUNTS_MODES: Final[tuple[str, ...]] = (
    COUNTS_NONE,
    COUNTS_AS_RECEIVED,
    COUNTS_AS_SIGNED,
)
"""Every Phase C' ordering :func:`_as_counts_mode` will accept."""


# --------------------------------------------------------------------------- #
# Reporting one measured rate
# --------------------------------------------------------------------------- #


def _as_nonnegative_int(value: Any, name: str) -> int:
    """Coerce a count, refusing bools and negatives with a named message.

    Parameters
    ----------
    value : object
        The candidate count.
    name : str
        Field name, for the message.

    Returns
    -------
    int

    Raises
    ------
    TypeError
        If ``value`` is a bool or not an integer.
    ValueError
        If ``value`` is negative.
    """
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise TypeError(
            f"{name} must be an int, got {type(value).__name__}; counts of "
            f"trials and successes are integers, not rates."
        )
    count = int(value)
    if count < 0:
        raise ValueError(f"{name} must be non-negative, got {count}")
    return count


def _as_generator(value: Any, name: str) -> np.random.Generator:
    """Require an explicit generator; D3 forbids falling back to a default.

    Parameters
    ----------
    value : object
        The candidate generator.
    name : str
        Argument name, for the message.

    Returns
    -------
    numpy.random.Generator

    Raises
    ------
    TypeError
        If ``value`` is not a :class:`numpy.random.Generator`.
    """
    if not isinstance(value, np.random.Generator):
        raise TypeError(
            f"{name} must be a numpy.random.Generator, got "
            f"{type(value).__name__}. Every generator in this module is passed "
            f"explicitly (D3), and the adversary's own is separate from the "
            f"world's on purpose (D6)."
        )
    return value


def _distinct_generators(
    world: Any, attack: Any
) -> tuple[np.random.Generator, np.random.Generator]:
    """Validate both generators and refuse a shared stream (D6).

    The one mistake this module exists to make impossible. An adversary drawing
    from the randomness that also builds the sessions is an adversary correlated
    with the run he is attacking, and every rate he reports is fiction --
    :mod:`sih141.attacks.isolation` demonstrates the mechanism.

    It used to refuse only the same *object*, which is the form of the mistake
    nobody makes. The form everybody makes is one seed used twice, and two
    generators built from one seed are one stream: identical bytes, for ever.
    :func:`~sih141.attacks.isolation.same_stream` is the comparison that catches
    both.

    Parameters
    ----------
    world : object
        The generator that builds sessions.
    attack : object
        The adversary's own generator.

    Returns
    -------
    tuple of numpy.random.Generator
        ``(world, attack)``, validated.

    Raises
    ------
    TypeError
        If either is not a generator.
    ValueError
        If they are the same stream -- the same object, the same position in one
        stream, or two generators derived from one seed.
    """
    checked_world = _as_generator(world, "rng")
    checked_attack = _as_generator(attack, "attack_rng")
    require_distinct_streams(
        checked_world,
        checked_attack,
        left_name="rng",
        right_name="attack_rng",
        detail=(
            "rng is the world's and builds the sessions; attack_rng is the "
            "adversary's own and nothing he does may be a function of the "
            "first."
        ),
    )
    return checked_world, checked_attack


def wilson_interval(
    successes: int, trials: int, *, z: float = _Z_95
) -> tuple[float, float]:
    """Return a Wilson score interval for a measured success rate.

    Wilson rather than the textbook normal interval, for the reason this suite
    keeps running into: most defended results are ``0`` successes out of ``N``,
    where the normal interval is the degenerate ``[0, 0]`` and would claim
    certainty from a finite experiment. Wilson reports a real upper bound there,
    which is the honest statement and the one a reader can argue with.

    Parameters
    ----------
    successes : int
        Number of successful trials, in ``0 .. trials``.
    trials : int
        Number of trials. Must be positive.
    z : float, optional
        Keyword-only. Normal quantile; the default is two-sided 95%.

    Returns
    -------
    tuple of (float, float)
        Lower and upper bounds, clipped into ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``successes`` or ``trials`` is not an integer, or ``z`` is not a real
        number.
    ValueError
        If ``trials`` is not positive, ``successes`` is out of range, or ``z``
        is negative.

    Examples
    --------
    >>> from sih141.attacks.replay import wilson_interval
    >>> low, high = wilson_interval(0, 200)
    >>> low, round(high, 4)
    (0.0, 0.0188)
    >>> low, high = wilson_interval(200, 200)
    >>> round(low, 4), high
    (0.9812, 1.0)
    >>> low, high = wilson_interval(25, 2000)
    >>> round(low, 5), round(high, 5)
    (0.00848, 0.01839)
    """
    trial_count = _as_nonnegative_int(trials, "trials")
    success_count = _as_nonnegative_int(successes, "successes")
    if trial_count < 1:
        raise ValueError(
            f"trials must be at least 1, got {trial_count}; a rate measured "
            f"over no trials is not a rate."
        )
    if success_count > trial_count:
        raise ValueError(
            f"successes ({success_count}) exceeds trials ({trial_count})"
        )
    if isinstance(z, bool) or not isinstance(z, (int, float, np.floating)):
        raise TypeError(f"z must be a real number, got {type(z).__name__}")
    if float(z) < 0.0:
        raise ValueError(f"z must be non-negative, got {float(z)}")

    # One implementation for the suite, in sih141.attacks.statistics, which is
    # also where the exact-at-the-ends clamping is explained (:ref:`float-dust`).
    return wilson_bounds(success_count, trial_count, z=float(z))


@dataclass(frozen=True)
class AttackOutcome:
    """One measured attack rate, with the conditions that produced it.

    Frozen. Carries the trial count and the success count rather than only the
    ratio, because a rate without its denominator cannot be pooled, cannot be
    given an interval, and cannot be argued with.

    Parameters
    ----------
    label : str
        What was measured, in a few words. Non-empty.
    defended : bool
        Whether the replay defence was enabled for these trials. Every attack
        here is measured both ways; a defended number alone says nothing about
        what the defence bought.
    trials : int
        How many independent attempts were made. Positive.
    successes : int
        How many achieved the adversary's goal. The goal is named in each
        measurement function's docstring and is **not** always "accepted" -- for
        a denial-of-service attack the goal is that an honest declaration was
        refused.
    refusals : int
        How many trials ended in a
        :class:`~sih141.protocol.verify.VerificationAbort` rather than a
        verdict. Reported separately because a refusal is a no-verdict, never a
        rejection, and folding the two together is the single easiest way to
        publish a wrong table.
    key_length : int
        ``L`` the trials ran at.
    note : str, optional
        One line of context: the analytic prediction, the mechanism, or the
        caveat. Empty by default.

    Attributes
    ----------
    label : str
    defended : bool
    trials : int
    successes : int
    refusals : int
    key_length : int
    note : str

    Raises
    ------
    TypeError
        If a count is not an integer, or a flag or the note is not of its type.
    ValueError
        If ``label`` is empty, ``trials`` is not positive, or a count is out of
        range.

    Examples
    --------
    >>> from sih141.attacks.replay import AttackOutcome
    >>> outcome = AttackOutcome(
    ...     label="straight replay", defended=True, trials=200,
    ...     successes=0, refusals=200, key_length=24,
    ... )
    >>> outcome.rate
    0.0
    >>> print(outcome.summary())
    straight replay [defended, L=24]: 0/200 = 0.0000, 95% CI [0.0000, 0.0188]
      200 of 200 trials reached no verdict at all.
    """

    label: str
    defended: bool
    trials: int
    successes: int
    refusals: int
    key_length: int
    note: str = ""

    def __post_init__(self) -> None:
        """Validate every field; an unvalidated outcome is a wrong table."""
        if not isinstance(self.label, str) or not self.label:
            raise ValueError(
                f"label must be a non-empty string, got {self.label!r}"
            )
        if not isinstance(self.defended, bool):
            raise TypeError(
                f"defended must be a bool, got {type(self.defended).__name__}. "
                f"It says which arm of the before/after this number is, and "
                f"there is no third arm."
            )
        if not isinstance(self.note, str):
            raise TypeError(
                f"note must be a string, got {type(self.note).__name__}"
            )
        object.__setattr__(
            self, "trials", _as_nonnegative_int(self.trials, "trials")
        )
        object.__setattr__(
            self, "successes", _as_nonnegative_int(self.successes, "successes")
        )
        object.__setattr__(
            self, "refusals", _as_nonnegative_int(self.refusals, "refusals")
        )
        object.__setattr__(
            self,
            "key_length",
            _as_nonnegative_int(self.key_length, "key_length"),
        )
        if self.trials < 1:
            raise ValueError(
                f"trials must be at least 1, got {self.trials}; an outcome "
                f"over no trials reports nothing."
            )
        if self.successes > self.trials:
            raise ValueError(
                f"successes ({self.successes}) exceeds trials ({self.trials})"
            )
        if self.refusals > self.trials:
            raise ValueError(
                f"refusals ({self.refusals}) exceeds trials ({self.trials})"
            )

    @property
    def rate(self) -> float:
        """float: ``successes / trials``."""
        return self.successes / self.trials

    @property
    def interval(self) -> tuple[float, float]:
        """tuple of (float, float): Wilson 95% interval for :attr:`rate`."""
        return wilson_interval(self.successes, self.trials)

    def summary(self) -> str:
        """Return a human-readable statement of the result.

        Returns
        -------
        str
            The rate with its interval, the refusal count when there were any,
            and the note when there is one.

        Examples
        --------
        >>> from sih141.attacks.replay import AttackOutcome
        >>> print(AttackOutcome(
        ...     label="cross-session pairing", defended=False, trials=1000,
        ...     successes=13, refusals=0, key_length=24,
        ...     note="predicted 0.012520",
        ... ).summary())
        cross-session pairing [undefended, L=24]: 13/1000 = 0.0130, 95% CI [0.0076, 0.0221]
          predicted 0.012520
        """
        low, high = self.interval
        arm = "defended" if self.defended else "undefended"
        lines = [
            f"{self.label} [{arm}, L={self.key_length}]: "
            f"{self.successes}/{self.trials} = {self.rate:.4f}, "
            f"95% CI [{low:.4f}, {high:.4f}]"
        ]
        if self.refusals:
            lines.append(
                f"  {self.refusals} of {self.trials} trials reached no verdict "
                f"at all."
            )
        if self.note:
            lines.append(f"  {self.note}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# The loot: one finished round, frozen
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ReplayCapture:
    """A finished round, as an adversary who watched it would hold it.

    Everything here was public at the moment it was captured: the declaration
    Alice sent in Phase B, including the opening it reveals, and the round
    identifier both verifiers stamped on their logs. The verifiers' *records*
    are held too, and that is deliberate over-provisioning rather than a
    threat-model slip -- the measurement functions need them to build the honest
    side of each experiment, and :class:`ReplayingForwarder`, the only thing
    here that ever sits on a seam, touches nothing but :attr:`signature`.

    Parameters
    ----------
    params : ProtocolParams
        What the captured round ran under.
    signature : Signature
        The declaration, with its opening revealed exactly as Phase B reveals
        it.
    records : dict
        The two verifiers' post-symmetrisation logs, keyed by
        :class:`~sih141.protocol.params.Party`.

    Attributes
    ----------
    params : ProtocolParams
    signature : Signature
    records : dict

    Examples
    --------
    >>> from sih141.attacks.replay import replay_capture
    >>> from sih141.protocol.params import Party
    >>> capture = replay_capture()
    >>> capture.signature.session_id == capture.records[Party.BOB].session_id
    True
    >>> capture.signature.session_opening is not None
    True
    """

    params: ProtocolParams
    signature: Signature
    records: dict[Party, RecipientRecord]


_CAPTURE_CACHE: dict[tuple[int, int, int], ReplayCapture] = {}


def replay_capture(
    params: ProtocolParams = CAPTURE_PARAMS,
    *,
    message_bit: int = 0,
    seed: int = CAPTURE_SEED,
) -> ReplayCapture:
    """Run one honest round to completion and freeze it as an adversary's loot.

    Cached on ``(key_length, message_bit, seed)``, so a whole suite pays for one
    distribution. The result is immutable and every record in it is frozen, so
    sharing it between adversaries cannot let one contaminate another.

    Parameters
    ----------
    params : ProtocolParams, optional
        Defaults to :data:`CAPTURE_PARAMS`.
    message_bit : int, optional
        Keyword-only, ``0`` or ``1``.
    seed : int, optional
        Keyword-only. Defaults to :data:`CAPTURE_SEED`, which is unrelated to
        every seed a measurement or the D6 check varies.

    Returns
    -------
    ReplayCapture

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`,
        or ``seed`` is not an int.
    ValueError
        If ``message_bit`` is not ``0``/``1``, or ``seed`` is negative.

    Examples
    --------
    >>> from sih141.attacks.replay import replay_capture
    >>> capture = replay_capture()
    >>> len(capture.signature) == capture.params.key_length
    True
    >>> replay_capture() is capture
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    if isinstance(message_bit, bool) or message_bit not in (0, 1):
        raise ValueError(
            f"message_bit must be 0 or 1, got {message_bit!r}; a capture "
            f"covers the one round the adversary watched."
        )
    seed_value = _as_nonnegative_int(seed, "seed")

    cache_key = (params.key_length, int(message_bit), seed_value)
    cached = _CAPTURE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    session = QDSSession(params, rng=np.random.default_rng(seed_value))
    session.distribute()
    signature = session.sign(int(message_bit))
    capture = ReplayCapture(
        params=params,
        signature=signature,
        records=dict(session.records[int(message_bit)]),
    )
    _CAPTURE_CACHE[cache_key] = capture
    return capture


# --------------------------------------------------------------------------- #
# The seam-level adversary
# --------------------------------------------------------------------------- #


class ReplayingForwarder:
    """The Bob-to-Charlie hop, re-presenting a declaration captured earlier.

    A :class:`~sih141.protocol.session.Forwarder`: the session hands it the live
    declaration and it returns whatever Charlie will score. This one sometimes
    returns a *stale* declaration instead -- one it captured from a round that
    is over -- and can relabel it with an opening of its own invention, which is
    attack (d) of the module docstring in its most direct form.

    **It owns its randomness (D6).** Whether to replay, which capture to
    re-present, and what opening to invent are all drawn from the generator
    handed to the constructor. Nothing here reads the session, and
    :func:`replay_probe` demonstrates that rather than asserting it. It also
    declines the :class:`~sih141.protocol.records.RecipientView`: a replay needs
    no evidence, only a copy of something that was public, so the ``view``
    parameter is defaulted -- which is how a forwarder says it does not want one
    (:class:`~sih141.protocol.session.Forwarder`).

    **What it will not achieve, and why that is worth encoding.** The session
    rebinds whatever a forwarder returns to the live round, so a stale
    declaration pushed through this seam reaches Charlie carrying the *live*
    identifier and is scored as a forgery rather than refused as a replay. The
    adversary is written faithfully anyway -- an attack that quietly stopped
    short of what the threat model allows would be measuring its own timidity --
    and the consequence is reported in the module docstring instead of being
    hidden.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, and the adversary's **own** (D6). Never the generator the
        harness gives :class:`~sih141.protocol.session.QDSSession`.
    captures : sequence of Signature or None, optional
        Keyword-only. The declarations this adversary is holding. ``None`` takes
        both bits' worth from :func:`replay_capture`.
    replay_probability : float, optional
        Keyword-only, in ``[0, 1]``. How often it substitutes rather than
        forwarding honestly. Defaults to ``0.5``, so a transcript shows both
        behaviours.
    relabel : bool, optional
        Keyword-only. When ``True`` (the default) a substituted declaration is
        rebuilt with an opening drawn from this adversary's generator -- an
        attempt to make a stale round name a fresh one, which succeeds only on a
        preimage (:func:`measure_identifier_preimage`).

    Attributes
    ----------
    replay_probability : float
    relabel : bool
    replays : int
        How many calls substituted a capture. Read by a harness that wants to
        report what the adversary actually did rather than what it was
        configured to do.

    Raises
    ------
    TypeError
        If ``rng`` is not a generator, ``captures`` holds anything but
        :class:`~sih141.protocol.signature.Signature`, or a flag has the wrong
        type.
    ValueError
        If ``captures`` is empty, or ``replay_probability`` is outside
        ``[0, 1]``.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import ReplayingForwarder, replay_capture
    >>> capture = replay_capture()
    >>> attack = ReplayingForwarder(
    ...     rng=np.random.default_rng(11), replay_probability=1.0
    ... )
    >>> forwarded = attack(capture.signature, capture.params)
    >>> attack.replays
    1

    Relabelling produces a fresh-looking identifier that names no real round:

    >>> forwarded.session_id == capture.signature.session_id
    False
    >>> forwarded.declared_key is capture.signature.declared_key
    True

    An adversary told never to replay is the identity, which is what lets the
    honest arm of a before/after comparison run through the same code:

    >>> quiet = ReplayingForwarder(
    ...     rng=np.random.default_rng(11), replay_probability=0.0
    ... )
    >>> quiet(capture.signature, capture.params) is capture.signature
    True
    """

    __slots__ = (
        "_captures",
        "_rng",
        "relabel",
        "replay_probability",
        "replays",
    )

    def __init__(
        self,
        *,
        rng: np.random.Generator,
        captures: Sequence[Signature] | None = None,
        replay_probability: float = 0.5,
        relabel: bool = True,
    ) -> None:
        self._rng: Final[np.random.Generator] = _as_generator(rng, "rng")
        if captures is None:
            resolved: tuple[Signature, ...] = tuple(
                replay_capture(message_bit=bit).signature for bit in (0, 1)
            )
        else:
            if isinstance(captures, (str, bytes)) or not isinstance(
                captures, Sequence
            ):
                raise TypeError(
                    f"captures must be a sequence of Signature, got "
                    f"{type(captures).__name__}"
                )
            for position, item in enumerate(captures):
                if not isinstance(item, Signature):
                    raise TypeError(
                        f"captures[{position}] must be a Signature, got "
                        f"{type(item).__name__}. An adversary replays a "
                        f"declaration, which is the only thing Phase B made "
                        f"public."
                    )
            resolved = tuple(captures)
            if not resolved:
                raise ValueError(
                    "captures must hold at least one Signature; an adversary "
                    "with nothing captured has no replay to mount."
                )
        self._captures: Final[tuple[Signature, ...]] = resolved
        if isinstance(replay_probability, bool) or not isinstance(
            replay_probability, (int, float, np.floating)
        ):
            raise TypeError(
                f"replay_probability must be a real number, got "
                f"{type(replay_probability).__name__}"
            )
        probability = float(replay_probability)
        if not 0.0 <= probability <= 1.0:
            raise ValueError(
                f"replay_probability must lie in [0, 1], got {probability}"
            )
        if not isinstance(relabel, bool):
            raise TypeError(
                f"relabel must be a bool, got {type(relabel).__name__}"
            )
        self.replay_probability: float = probability
        self.relabel: bool = relabel
        self.replays: int = 0

    def __repr__(self) -> str:
        """Return a debugging representation naming the loot and the rate."""
        return (
            f"ReplayingForwarder({len(self._captures)} capture(s), "
            f"p={self.replay_probability}, relabel={self.relabel}, "
            f"{self.replays} replay(s) so far)"
        )

    def __call__(
        self,
        signature: Signature,
        params: ProtocolParams,
        *,
        view: RecipientView | None = None,
    ) -> Signature:
        """Return the declaration Charlie will be given.

        Parameters
        ----------
        signature : Signature
            What the hop was asked to pass on.
        params : ProtocolParams
            The parameter set. Unused: a replay carries its own key and its own
            length, and a capture of the wrong shape is declined by comparing
            against the live declaration, which is stricter.
        view : RecipientView or None, optional
            Keyword-only and **defaulted, which is how this adversary declines
            it**: a replay consults no evidence.

        Returns
        -------
        Signature
            ``signature`` itself when this call forwards honestly, otherwise a
            captured declaration, relabelled when :attr:`relabel` is set.

        Raises
        ------
        TypeError
            If ``signature`` is not a
            :class:`~sih141.protocol.signature.Signature`.
        """
        del params, view  # A replay consults neither; that is what makes it cheap.
        if not isinstance(signature, Signature):
            raise TypeError(
                f"signature must be a Signature, got "
                f"{type(signature).__name__}"
            )
        # Every draw below comes from this adversary's own generator (D6), and
        # all three are made unconditionally so that the stream advances the
        # same way whatever the live declaration happens to be. An adversary
        # whose draw *pattern* depended on what it was handed would carry the
        # session into its own generator state, and its later decisions would
        # move with the session seed for a reason that has nothing to do with
        # what it decided.
        coin = float(self._rng.random())
        choice = int(self._rng.integers(len(self._captures)))
        opening = self._rng.bytes(_OPENING_HEX_BYTES).hex()
        if coin >= self.replay_probability:
            return signature
        # Only a capture of the live declaration's bit and length is worth
        # presenting: the session refuses the others outright, and spending the
        # attempt on a refusal would report the adversary as harmless when he
        # was merely clumsy.
        eligible = [
            stale
            for stale in self._captures
            if stale.message_bit == signature.message_bit
            and len(stale) == len(signature)
        ]
        if not eligible:
            return signature
        stale = eligible[choice % len(eligible)]
        self.replays += 1
        if not self.relabel:
            return stale
        return Signature(
            message_bit=stale.message_bit,
            declared_key=stale.declared_key,
            session_opening=opening,
            context=stale.context,
        )


def replay_probe(capture: ReplayCapture | None = None) -> Any:
    """Return a :class:`~sih141.attacks.isolation.DecisionProbe` for this seam.

    The forwarder analogue of :func:`sih141.attacks.isolation.signer_probe`. One
    frozen capture is replayed into every probe call, so the adversary's
    observations -- the live declaration and the parameters -- are identical
    across session seeds, and the session seed is a quantity it can only know if
    it went and took it. That is exactly the question check (a) asks, and it is
    why this probe does not build a fresh session per seed.

    Parameters
    ----------
    capture : ReplayCapture or None, optional
        The frozen observations. ``None`` uses :func:`replay_capture`.

    Returns
    -------
    DecisionProbe
        ``(attack, session_seed) -> Signature``.

    Raises
    ------
    TypeError
        If ``capture`` is neither ``None`` nor a :class:`ReplayCapture`.

    Examples
    --------
    >>> from sih141.attacks.isolation import assert_attack_isolated
    >>> from sih141.attacks.replay import ReplayingForwarder, replay_probe
    >>> assert_attack_isolated(ReplayingForwarder, replay_probe()).isolated
    True
    """
    resolved = replay_capture() if capture is None else capture
    if not isinstance(resolved, ReplayCapture):
        raise TypeError(
            f"capture must be a ReplayCapture or None, got "
            f"{type(resolved).__name__}. Build one with replay_capture()."
        )

    def probe(attack: Any, session_seed: int) -> Any:
        """Forward once against the frozen capture; return what was passed on."""
        del session_seed  # An isolated hop cannot see it. That is the point.
        return attack(resolved.signature, resolved.params)

    return probe


def _as_params_arg(value: Any) -> ProtocolParams:
    """Require an explicit parameter set; there is no default worth guessing.

    Parameters
    ----------
    value : object
        The candidate parameter set.

    Returns
    -------
    ProtocolParams

    Raises
    ------
    TypeError
        If ``value`` is not a :class:`~sih141.protocol.params.ProtocolParams`.
    """
    if not isinstance(value, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(value).__name__}. "
            f"Every measurement here is a rate at one key length, so the key "
            f"length is named rather than inherited."
        )
    return value


def _as_flag(value: Any, name: str) -> bool:
    """Require a real bool; a truthy value would silently pick an arm.

    Parameters
    ----------
    value : object
        The candidate flag.
    name : str
        Argument name, for the message.

    Returns
    -------
    bool

    Raises
    ------
    TypeError
        If ``value`` is not a :class:`bool`.
    """
    if not isinstance(value, bool):
        raise TypeError(
            f"{name} must be a bool, got {type(value).__name__}. It selects "
            f"which arm of the before/after comparison is being measured, and "
            f"a truthy value would pick one silently."
        )
    return value


# --------------------------------------------------------------------------- #
# Small helpers the measurements share
# --------------------------------------------------------------------------- #


def _as_trials(value: Any) -> int:
    """Coerce a trial count and refuse zero: a rate needs a denominator."""
    count = _as_nonnegative_int(value, "trials")
    if count < 1:
        raise ValueError(
            f"trials must be at least 1, got {count}; an attack measured over "
            f"no trials reports nothing, and reporting nothing as a zero rate "
            f"is how a defence gets credit it never earned."
        )
    return count


def _as_verifier(value: Any) -> Party:
    """Resolve a verifier, refusing Alice, who holds no record to attack."""
    party = value if isinstance(value, Party) else Party(value)
    if party is Party.ALICE:
        raise ValueError(
            "party must be Party.BOB or Party.CHARLIE. Alice signs; she holds "
            "no measurement record and reaches no verdict, so there is nothing "
            "at her end for a replay to be presented to."
        )
    return party


def _random_key(
    params: ProtocolParams, message_bit: int, rng: np.random.Generator
) -> PrivateKey:
    """Draw a key uniformly, from the **adversary's** generator.

    The declaration a hop adversary mints when all he wants is for the verifier
    to reach *a* verdict. Its per-matched-position agreement probability is
    ``1/2``, so it is rejected at overwhelming probability -- which is the point
    of it: a rejection is a verdict, and a verdict spends the round.

    Parameters
    ----------
    params : ProtocolParams
        Supplies ``L`` and the basis alphabet.
    message_bit : int
        The bit the forged declaration will claim.
    rng : numpy.random.Generator
        The adversary's own (D6).

    Returns
    -------
    PrivateKey
    """
    bases = tuple(params.bases)
    basis_choices = rng.integers(len(bases), size=params.key_length)
    signs = rng.integers(2, size=params.key_length)
    return PrivateKey(
        message_bit,
        tuple(
            KeyElement(bases[int(where)], 1 if int(sign) == 0 else -1)
            for where, sign in zip(basis_choices, signs, strict=True)
        ),
    )


def _accepted(outcome: VerificationResult | VerificationAbort) -> bool:
    """Return whether an outcome is a verdict *and* an accepting one."""
    return isinstance(outcome, VerificationResult) and outcome.accepted


def _refused(outcome: VerificationResult | VerificationAbort) -> bool:
    """Return whether an outcome is a refusal to score rather than a verdict."""
    return isinstance(outcome, VerificationAbort)


def _describe(outcome: VerificationResult | VerificationAbort) -> str:
    """Return a short phrase naming what a verifier did, for a message.

    Parameters
    ----------
    outcome : VerificationResult or VerificationAbort
        The verifier's outcome.

    Returns
    -------
    str

    Examples
    --------
    >>> from sih141.attacks.replay import _describe
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.verify import AbortReason, VerificationAbort
    >>> _describe(
    ...     VerificationAbort(
    ...         party=Party.CHARLIE,
    ...         reason=AbortReason.BELOW_FLOOR,
    ...         matched_count=1,
    ...         minimum_matched=3,
    ...         expected_matched=16.0,
    ...         key_length=24,
    ...         message_bit=0,
    ...     )
    ... )
    "no verdict, reason 'matched-count-below-floor'"
    """
    if isinstance(outcome, VerificationAbort):
        return f"no verdict, reason {str(outcome.reason.value)!r}"
    return f"a verdict, accepted={outcome.accepted}"


def _round_already_spent(
    outcome: VerificationResult | VerificationAbort,
) -> bool:
    """Return whether an outcome is the ledger refusing a spent round.

    The mechanism :func:`measure_ledger_denial_of_service` measures, isolated
    from every other way a declaration can fail to be accepted. That function
    used to score itself on ``not _accepted(...)``, which is the adversary's
    *goal* but not his *mechanism*, and the two come apart at a degenerate key
    length: an honest declaration that was never going to be accepted counts as
    a burned round under the first and as nothing at all under the second. A
    published ``0/300`` computed the first way is a statement about the seed
    that happened not to produce such a trial.

    Parameters
    ----------
    outcome : VerificationResult or VerificationAbort
        What the verifier did with the honest declaration.

    Returns
    -------
    bool
        ``True`` only for
        :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`.

    Examples
    --------
    >>> from sih141.attacks.replay import _round_already_spent
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.verify import AbortReason, VerificationAbort
    >>> spent = VerificationAbort(
    ...     party=Party.CHARLIE,
    ...     reason=AbortReason.RECORD_ALREADY_VERIFIED,
    ...     matched_count=0,
    ...     minimum_matched=1,
    ...     expected_matched=16.0,
    ...     key_length=24,
    ...     message_bit=0,
    ... )
    >>> _round_already_spent(spent)
    True

    A refusal for any other reason is not this attack succeeding:

    >>> starved = VerificationAbort(
    ...     party=Party.CHARLIE,
    ...     reason=AbortReason.BELOW_FLOOR,
    ...     matched_count=1,
    ...     minimum_matched=3,
    ...     expected_matched=16.0,
    ...     key_length=24,
    ...     message_bit=0,
    ... )
    >>> _round_already_spent(starved)
    False
    """
    return (
        isinstance(outcome, VerificationAbort)
        and outcome.reason is AbortReason.RECORD_ALREADY_VERIFIED
    )


def _signed_round(
    params: ProtocolParams, message_bit: int, rng: np.random.Generator
) -> tuple[Signature, dict[Party, RecipientRecord]]:
    """Run one honest round and return its declaration and both logs.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    message_bit : int
        Which bit to sign.
    rng : numpy.random.Generator
        The **world's** generator, from which the session draws its own stream
        material. It is advanced by the call, which is what makes consecutive
        rounds independent without any seed arithmetic in this module.

    Returns
    -------
    tuple
        ``(signature, records)`` with ``records`` the post-symmetrisation logs
        of both verifiers.
    """
    session = QDSSession(params, rng=rng)
    session.distribute()
    signature = session.sign(message_bit)
    return signature, dict(session.records[message_bit])


def _present(
    record: RecipientRecord, *, defended: bool
) -> RecipientRecord:
    """Return the log as the verifier holds it in one arm of the comparison.

    Defended, he has stamped the round Alice announced on his log and the
    binding check has something to compare. Undefended, the stamp is absent --
    which is not a hypothetical: it is exactly the state of every log written
    before the binding existed, and :func:`~sih141.protocol.verify.verify`
    still scores such a log rather than refusing it, so this is the *real*
    "before" rather than a synthetic one.
    """
    return record if defended else record.with_session_id(None)


def _ledger(party: Party, *, defended: bool) -> ConsumedRecords | None:
    """Return the verifier's ledger, or ``None`` for the undefended arm."""
    return ConsumedRecords(party) if defended else None


def _as_counts_mode(value: Any) -> str:
    """Resolve which Phase C' ordering a measurement is to run under.

    Parameters
    ----------
    value : object
        One of :data:`COUNTS_NONE`, :data:`COUNTS_AS_RECEIVED`,
        :data:`COUNTS_AS_SIGNED`.

    Returns
    -------
    str

    Raises
    ------
    TypeError
        If ``value`` is not a string.
    ValueError
        If it names no ordering.
    """
    if not isinstance(value, str):
        raise TypeError(
            f"counts must be a string naming a Phase C' ordering, got "
            f"{type(value).__name__}"
        )
    if value not in _COUNTS_MODES:
        raise ValueError(
            f"counts must be one of {list(_COUNTS_MODES)}, got {value!r}. It "
            f"selects which declaration the recipients counted against, and "
            f"that single choice decides whether the denial-of-service "
            f"succeeds -- so it is named rather than defaulted silently."
        )
    return value


def _counterpart_count(
    declaration: Signature,
    records: dict[Party, RecipientRecord],
    params: ProtocolParams,
    *,
    ordering: str,
) -> Any:
    """Return what Charlie receives from Bob over Phase C', or ``None``.

    Built through the real :mod:`sih141.protocol.tally` API rather than as a
    bare integer, because a bare integer is taken at its word while a pooled
    count carries the fingerprint of the declaration it counted -- and that
    fingerprint is the whole subject of
    :func:`measure_ledger_denial_of_service`.

    Parameters
    ----------
    declaration : Signature
        The declaration **both** recipients counted against in this ordering.
    records : dict
        Both verifiers' post-symmetrisation logs.
    params : ProtocolParams
        The parameter set.
    ordering : str
        One of :data:`COUNTS_NONE`, :data:`COUNTS_AS_RECEIVED`,
        :data:`COUNTS_AS_SIGNED`.

    Returns
    -------
    int or None
        Bob's count as Charlie receives it, carrying its provenance, or
        ``None`` when Phase C' did not run.
    """
    if ordering == COUNTS_NONE:
        return None
    pooled = exchange_matched_counts(
        {
            party: matched_count_message(declaration, records[party], params)
            for party in (Party.BOB, Party.CHARLIE)
        },
        params,
    )
    return pooled.counterpart_of(Party.CHARLIE)


# --------------------------------------------------------------------------- #
# (a) Straight re-verification
# --------------------------------------------------------------------------- #


def measure_straight_replay(
    *,
    params: ProtocolParams,
    trials: int,
    rng: np.random.Generator,
    defended: bool,
    party: Party | str = Party.BOB,
) -> AttackOutcome:
    """Measure attack (a): re-present a captured declaration to its own verifier.

    The simplest replay there is, and the one that used to work every time. The
    adversary needs no key material, no forgery and no channel access beyond a
    copy of what Phase B made public: he hands the verifier the same declaration
    a second time. **Success is a second acceptance.**

    Nothing here is drawn by the adversary -- a straight replay is a byte-for-byte
    re-presentation and has no choices to make -- so this measurement takes only
    the world's generator. That is not a D6 exemption: it is what D6 looks like
    when the adversary is deterministic, and :class:`ReplayingForwarder` is where
    the randomised version of the same idea lives.

    Parameters
    ----------
    params : ProtocolParams
        Keyword-only. The parameter set every trial runs at.
    trials : int
        Keyword-only, positive. One fresh round per trial.
    rng : numpy.random.Generator
        Keyword-only. The world's generator; each session draws from it, so
        consecutive rounds are independent without any seed arithmetic here.
    defended : bool
        Keyword-only. ``True`` stamps the round on the verifier's log and gives
        him a :class:`~sih141.protocol.verify.ConsumedRecords`; ``False`` is the
        state of the package before the defence, with an unstamped log and no
        ledger.
    party : Party or str, optional
        Keyword-only. Which verifier is replayed at. Defaults to Bob, who
        receives the declaration directly.

    Returns
    -------
    AttackOutcome
        ``successes`` counts trials whose **second** presentation was accepted.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams` or ``rng`` is not a
        generator.
    ValueError
        If ``trials`` is not positive, ``defended`` is not a bool, or ``party``
        is Alice.

    Notes
    -----
    The first presentation is the honest verification, and it is required to
    have been accepted: a trial where the honest run was itself rejected or
    refused says nothing about replay, so it is counted as a non-success and its
    refusal recorded rather than being quietly dropped.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import measure_straight_replay
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=24)

    Undefended, every replay is accepted again -- the verification rule is a
    pure function and cannot tell the second call from the first:

    >>> before = measure_straight_replay(
    ...     params=params, trials=8, rng=np.random.default_rng(4), defended=False
    ... )
    >>> before.successes, before.trials
    (8, 8)

    Defended, the ledger refuses every one, and refuses it as a no-verdict
    rather than as a rejection:

    >>> after = measure_straight_replay(
    ...     params=params, trials=8, rng=np.random.default_rng(4), defended=True
    ... )
    >>> after.successes, after.refusals
    (0, 8)
    """
    checked = _as_params_arg(params)
    count = _as_trials(trials)
    world = _as_generator(rng, "rng")
    _as_flag(defended, "defended")
    verifier = _as_verifier(party)

    successes = 0
    refusals = 0
    for _ in range(count):
        signature, records = _signed_round(checked, 0, world)
        record = _present(records[verifier], defended=defended)
        ledger = _ledger(verifier, defended=defended)
        first = verify_or_abort(signature, record, checked, ledger=ledger)
        again = verify_or_abort(signature, record, checked, ledger=ledger)
        if _refused(again):
            refusals += 1
        if _accepted(first) and _accepted(again):
            successes += 1
    return AttackOutcome(
        label=f"straight re-verification at {verifier.value}",
        defended=defended,
        trials=count,
        successes=successes,
        refusals=refusals,
        key_length=checked.key_length,
        note=(
            "refused as RECORD_ALREADY_VERIFIED by the consumed-records ledger"
            if defended
            else "the scoring rule is pure and cannot tell a second call from "
            "a first"
        ),
    )


# --------------------------------------------------------------------------- #
# (b) Cross-session pairing
# --------------------------------------------------------------------------- #


def measure_cross_session_pairing(
    *,
    params: ProtocolParams,
    trials: int,
    rng: np.random.Generator,
    defended: bool,
    party: Party | str = Party.BOB,
) -> AttackOutcome:
    """Measure attack (b): run A's declaration against run B's records.

    Two independent rounds per trial. The adversary takes the declaration of the
    finished round A and presents it to a verifier holding the logs of the live
    round B. **Success is acceptance.**

    Defended, the round binding refuses it before anything is counted: the
    verifier's log names round B and the declaration names round A, so the
    outcome is
    :attr:`~sih141.protocol.verify.AbortReason.SESSION_MISMATCH` and no rate is
    even computed. Undefended, nothing refuses it at all and the outcome is
    decided by arithmetic alone -- and the arithmetic is exactly the outside
    forger's, because run A's key is independent of run B's states, so each
    matched position agrees with probability ``1/2``. The analytic prediction is
    therefore :func:`~sih141.protocol.analysis.forgery_probability` for the
    party's own threshold, and it is carried in the returned
    :attr:`AttackOutcome.note` so that the comparison is on the record rather
    than in a commit message.

    Parameters
    ----------
    params : ProtocolParams
        Keyword-only.
    trials : int
        Keyword-only, positive. **Two** rounds are distributed per trial, so
        this is the expensive measurement of the module.
    rng : numpy.random.Generator
        Keyword-only. The world's generator.
    defended : bool
        Keyword-only. Whether the verifier's log carries the round it was made
        in.
    party : Party or str, optional
        Keyword-only. Which verifier is targeted, and therefore which threshold
        applies -- ``s_a = 1/64`` for Bob, ``s_v = 1/16`` for Charlie. Defaults
        to Bob.

    Returns
    -------
    AttackOutcome
        ``successes`` counts accepted pairings; ``refusals`` counts trials that
        reached no verdict, which under the defence is all of them.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams` or ``rng`` is not a
        generator.
    ValueError
        If ``trials`` is not positive, ``defended`` is not a bool, or ``party``
        is Alice.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import measure_cross_session_pairing
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=24)
    >>> after = measure_cross_session_pairing(
    ...     params=params, trials=6, rng=np.random.default_rng(17),
    ...     defended=True,
    ... )
    >>> after.successes, after.refusals
    (0, 6)

    Undefended the pairing is not refused -- it is *scored*, and scoring an
    unrelated key is what the mismatch rate is for:

    >>> before = measure_cross_session_pairing(
    ...     params=params, trials=6, rng=np.random.default_rng(17),
    ...     defended=False,
    ... )
    >>> before.refusals
    0
    """
    checked = _as_params_arg(params)
    count = _as_trials(trials)
    world = _as_generator(rng, "rng")
    _as_flag(defended, "defended")
    verifier = _as_verifier(party)

    successes = 0
    refusals = 0
    for _ in range(count):
        stale_signature, _ = _signed_round(checked, 0, world)
        _, live_records = _signed_round(checked, 0, world)
        record = _present(live_records[verifier], defended=defended)
        outcome = verify_or_abort(
            stale_signature,
            record,
            checked,
            ledger=_ledger(verifier, defended=defended),
        )
        if _refused(outcome):
            refusals += 1
        elif _accepted(outcome):
            successes += 1
    predicted = forgery_probability(checked, party=verifier)
    return AttackOutcome(
        label=f"cross-session pairing at {verifier.value}",
        defended=defended,
        trials=count,
        successes=successes,
        refusals=refusals,
        key_length=checked.key_length,
        note=(
            "refused as SESSION_MISMATCH before any position is counted"
            if defended
            else f"predicted {predicted:.6g} by "
            f"analysis.forgery_probability: an unrelated key agrees at 1/2 "
            f"per matched position, which is the outside forger's law exactly"
        ),
    )


# --------------------------------------------------------------------------- #
# (c) The ledger itself
# --------------------------------------------------------------------------- #


def measure_ledger_denial_of_service(
    *,
    params: ProtocolParams,
    trials: int,
    rng: np.random.Generator,
    attack_rng: np.random.Generator,
    defended: bool,
    counts: str = COUNTS_AS_RECEIVED,
) -> AttackOutcome:
    """Measure attack (c): burn Charlie's round so the genuine signature dies.

    **This is the attack that works, and it works because of the defence rather
    than in spite of it -- but only under one of the three count-exchange
    orderings measured here.** Read the mechanism before the number, and then
    read ``counts``, because the whole result lives in that argument.

    Phase B reveals the round's opening on the declaration itself. Anyone
    downstream of that reveal therefore knows the live round's identifier and
    can mint a declaration that *names* it -- the identifier deliberately does
    not cover the declared key
    (:func:`~sih141.protocol.signature.session_identifier`), precisely so that a
    forgery is scored rather than refused. The Bob-to-Charlie hop is exactly
    where the threat model puts an adversary, and the classical authentication
    assumption covers Alice's channel, not that one. So the adversary hands
    Charlie a declaration carrying the live identifier and a key of his own
    choosing. Charlie scores it, rejects it -- and **spends the round**, because
    a rejection is a verdict.

    The genuine declaration then arrives, by whatever route the application
    provides. Charlie refuses it as
    :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`. He can
    never accept it, in this round, ever. Without the ledger the same adversary
    achieves a *recoverable* denial: Charlie rejects the forgery and then
    accepts the genuine declaration on the next presentation.

    **What stops it, when anything does, is Phase C'.** A count carries the
    fingerprint of the declaration it counted
    (:attr:`~sih141.protocol.tally.MatchedCountMessage.declaration_digest`), and
    :func:`~sih141.protocol.verify.verify` refuses a count taken against another
    declaration. So whether the round is burned turns on *which* declaration the
    two recipients counted against, which is exactly what ``counts`` selects --
    and the answer is uncomfortable: the ordering that saves Charlie is the one
    where Bob counts against a declaration he is not the one who will forward,
    and a dishonest Bob has no reason to cooperate with it.

    **Success is that the honest declaration was refused as
    :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`** --
    the round spent by the forgery -- and not acceptance of anything of the
    adversary's. That inversion is why :class:`AttackOutcome` names the goal in
    each function rather than assuming one.

    It is deliberately the *mechanism* and not the looser "the honest
    declaration was not accepted", which is what this counted until the Phase 3
    audit. The two agree on every healthy trial and come apart on a degenerate
    one: below ``L = 140`` both matched-count floors degenerate, an honest run
    can fail on its own, and the loose reading scores that as the adversary
    burning a round he never touched. A ``0/300`` produced that way is a
    statement about the seed that happened to contain no such trial, not about
    the attack. Trials of that kind are now refused outright, loudly, rather
    than folded into either column -- see the :exc:`ValueError` below.

    What this does *not* say: the ledger is still unpoisonable from outside
    (:func:`measure_ledger_poisoning`), the round identifier is still
    unforgeable (:func:`measure_identifier_preimage`), and neither of those
    claims is weakened. What is weakened is the pricing of the residual
    denial-of-service surface at zero, which holds only if every channel that
    can present a declaration to a verifier is authenticated *and* the pooled
    count exchange is in force with counts taken against the signed
    declaration. The Bob-to-Charlie hop is not authenticated, and the
    recipient who runs it is the recipient who computes one of the two counts.

    Parameters
    ----------
    params : ProtocolParams
        Keyword-only.
    trials : int
        Keyword-only, positive.
    rng : numpy.random.Generator
        Keyword-only. The world's generator, which builds the rounds.
    attack_rng : numpy.random.Generator
        Keyword-only, and a **different stream** (D6): the adversary's own,
        from which the forged key is drawn.
    defended : bool
        Keyword-only. ``True`` gives Charlie the ledger and the stamped log.
    counts : str, optional
        Keyword-only. Which declaration Phase C' counted against.

        :data:`COUNTS_NONE`
            No pooled exchange at all -- the pre-pooled variant the package
            shipped first, and what
            :func:`~sih141.protocol.tally.no_count_exchange` selects. Nothing
            checks provenance, so the forgery is scored and the round burns.
        :data:`COUNTS_AS_RECEIVED`
            The default, and the deployment reading: each recipient counts
            against the declaration **he actually received**, which for both of
            them is the forged one, because the adversary is the hop and
            computes his own count against what he forwards. Provenance agrees,
            the forgery is scored, and the round burns.
        :data:`COUNTS_AS_SIGNED`
            The shipped :class:`~sih141.protocol.session.QDSSession` ordering:
            Phase C' runs before the forward, so both counts name the
            declaration Alice signed. Charlie's count then does not match the
            declaration in front of him, he refuses as
            :attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`,
            nothing is spent, and the genuine declaration is accepted
            afterwards. The attack fails -- on a check that was built for a
            different purpose entirely.

    Returns
    -------
    AttackOutcome
        ``successes`` counts trials where the honest declaration was refused
        because the round had already been spent; ``refusals`` counts every
        no-verdict, so the two are equal exactly when the ledger was the only
        thing refusing.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or either generator is
        not one.
    ValueError
        If ``trials`` is not positive, ``defended`` is not a bool, ``counts``
        names no ordering, the two generators are the same stream (D6), or a
        trial's honest declaration was neither accepted nor denied by the
        ledger -- a trial in which this attack was not measured, and which must
        not be silently scored either way.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import (
    ...     COUNTS_AS_SIGNED, measure_ledger_denial_of_service)
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=24)

    With the ledger and counts taken against what each party received, the
    honest declaration is denied every time:

    >>> after = measure_ledger_denial_of_service(
    ...     params=params, trials=8, rng=np.random.default_rng(31),
    ...     attack_rng=np.random.default_rng(77), defended=True,
    ... )
    >>> after.successes, after.refusals
    (8, 8)

    Without the ledger, the same adversary achieves nothing that lasts:

    >>> before = measure_ledger_denial_of_service(
    ...     params=params, trials=8, rng=np.random.default_rng(31),
    ...     attack_rng=np.random.default_rng(77), defended=False,
    ... )
    >>> before.successes
    0

    And under the session's own ordering the count-provenance check refuses the
    forgery before Charlie can spend the round on it:

    >>> saved = measure_ledger_denial_of_service(
    ...     params=params, trials=8, rng=np.random.default_rng(31),
    ...     attack_rng=np.random.default_rng(77), defended=True,
    ...     counts=COUNTS_AS_SIGNED,
    ... )
    >>> saved.successes
    0
    """
    checked = _as_params_arg(params)
    count = _as_trials(trials)
    world, adversary = _distinct_generators(rng, attack_rng)
    _as_flag(defended, "defended")
    ordering = _as_counts_mode(counts)

    successes = 0
    refusals = 0
    for trial in range(count):
        signature, records = _signed_round(checked, 0, world)
        record = _present(records[Party.CHARLIE], defended=defended)
        ledger = _ledger(Party.CHARLIE, defended=defended)
        # The hop reads the opening off the declaration it was asked to carry,
        # and mints one of its own naming the same round.
        forged = Signature(
            message_bit=signature.message_bit,
            declared_key=_random_key(
                checked, signature.message_bit, adversary
            ),
            session_opening=signature.session_opening,
            context=signature.context,
        )
        counted_against = signature if ordering == COUNTS_AS_SIGNED else forged
        verify_or_abort(
            forged,
            record,
            checked,
            counterpart_matched=_counterpart_count(
                counted_against, records, checked, ordering=ordering
            ),
            ledger=ledger,
        )
        honest = verify_or_abort(
            signature,
            record,
            checked,
            counterpart_matched=_counterpart_count(
                signature, records, checked, ordering=ordering
            ),
            ledger=ledger,
        )
        if _refused(honest):
            refusals += 1
        if _round_already_spent(honest):
            successes += 1
        elif not _accepted(honest):
            # Neither burned nor accepted. The attack was not measured on this
            # trial, and scoring it as a success -- which "not accepted" did --
            # is what made a published 0/N a statement about the seed.
            raise ValueError(
                f"trial {trial} of {count}: the honest declaration was neither "
                f"accepted nor denied by the ledger. It came back as "
                f"{_describe(honest)}, which is not this attack's mechanism: "
                f"success here is the round having been *spent* by the "
                f"forgery, so a trial whose honest declaration would not have "
                f"been accepted anyway measures nothing at all. Counting such "
                f"a trial as a success -- which scoring on 'not accepted' did "
                f"-- turns a published rate into a statement about this seed "
                f"rather than about the attack, and counting it as a failure "
                f"would understate a defence that never got to act.\n"
                f"L = {checked.key_length}: below 140 both matched-count "
                f"floors degenerate and an honest run can fail on its own. "
                f"Raise the key length, or investigate the reason above."
            )
    return AttackOutcome(
        label=(
            f"hop burns Charlie's round before the genuine declaration "
            f"[counts {ordering}]"
        ),
        defended=defended,
        trials=count,
        successes=successes,
        refusals=refusals,
        key_length=checked.key_length,
        note=(
            "the count-provenance check refuses the forgery, so nothing is "
            "spent and the genuine declaration still lands"
            if ordering == COUNTS_AS_SIGNED
            else (
                "the ledger makes the denial permanent: "
                "RECORD_ALREADY_VERIFIED"
                if defended
                else "without the ledger the denial is recoverable on the "
                "next presentation"
            )
        ),
    )


def measure_ledger_poisoning(
    *,
    params: ProtocolParams,
    trials: int,
    rng: np.random.Generator,
    attack_rng: np.random.Generator,
) -> AttackOutcome:
    """Measure attack (c), the other half: add an entry nobody earned.

    Three routes are tried per trial, and **success is that a verifier's ledger
    grew without that verifier reaching a verdict** -- the exhaustion and
    poisoning question, since an adversary who can add entries at will can
    both fill the store and pre-spend rounds that have not happened yet.

    1. *A declaration naming another round.* Refused as
       :attr:`~sih141.protocol.verify.AbortReason.SESSION_MISMATCH`. A refusal
       spends nothing, so an unbounded stream of these grows the ledger by
       zero -- which is also the exhaustion answer: storage is bounded by the
       number of rounds the signer actually ran, and a signer who wants to deny
       service can more simply decline to sign.
    2. *A count from the counterpart below his own floor.* Refused, and again
       spends nothing, so the recipients' own Phase C' step cannot burn a round
       either.
    3. *The other verifier's record, handed to this ledger.* Raises rather than
       answering, so one verifier's history cannot be written from the other's
       evidence. Counted as a success if it were ever to succeed.

    There is no fourth route, and that is the finding worth stating plainly: the
    only way into a ledger is a verdict the verifier was entitled to reach. That
    is exactly why :func:`measure_ledger_denial_of_service` attacks the *verdict*
    instead.

    Parameters
    ----------
    params : ProtocolParams
        Keyword-only.
    trials : int
        Keyword-only, positive. One fresh round per trial; all three routes are
        tried against it.
    rng : numpy.random.Generator
        Keyword-only. The world's generator.
    attack_rng : numpy.random.Generator
        Keyword-only, a different object (D6). Supplies the invented opening of
        route 1.

    Returns
    -------
    AttackOutcome
        ``successes`` counts trials in which any route added an entry;
        ``refusals`` counts trials in which **all three** routes were refused,
        which is the only reading under which a partial trial cannot look like
        a pass.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or either generator is
        not one.
    ValueError
        If ``trials`` is not positive, or the two generators are the same
        object.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import measure_ledger_poisoning
    >>> from sih141.protocol.params import ProtocolParams
    >>> outcome = measure_ledger_poisoning(
    ...     params=ProtocolParams(key_length=24), trials=6,
    ...     rng=np.random.default_rng(5), attack_rng=np.random.default_rng(6),
    ... )
    >>> outcome.successes, outcome.refusals
    (0, 6)
    """
    checked = _as_params_arg(params)
    count = _as_trials(trials)
    world, adversary = _distinct_generators(rng, attack_rng)

    successes = 0
    refusals = 0
    for _ in range(count):
        signature, records = _signed_round(checked, 0, world)
        record = records[Party.CHARLIE]
        ledger = ConsumedRecords(Party.CHARLIE)

        # Route 1: a declaration that names a round nobody ran.
        elsewhere = Signature(
            message_bit=signature.message_bit,
            declared_key=signature.declared_key,
            session_opening=adversary.bytes(_OPENING_HEX_BYTES).hex(),
            context=signature.context,
        )
        wrong_round = verify_or_abort(elsewhere, record, checked, ledger=ledger)

        # Route 2: a counterpart count that cannot carry a verdict.
        starved = verify_or_abort(
            signature, record, checked, counterpart_matched=0, ledger=ledger
        )

        # Route 3: the other verifier's evidence, offered to this ledger.
        blocked = False
        try:
            ledger.spend(records[Party.BOB])
        except ValueError:
            blocked = True

        # One refusal per trial, counted only when *every* route was refused:
        # a trial in which two routes were refused and one was not is not a
        # trial that held, and reporting it as two thirds of a refusal would
        # hide exactly the case this measurement exists to catch.
        if _refused(wrong_round) and _refused(starved) and blocked:
            refusals += 1

        if len(ledger) > 0:
            successes += 1
    return AttackOutcome(
        label="poison a verifier's ledger from outside",
        defended=True,
        trials=count,
        successes=successes,
        refusals=refusals,
        key_length=checked.key_length,
        note=(
            "a refusal spends nothing and a cross-party record is refused, so "
            "the only way into a ledger is a verdict the verifier reached"
        ),
    )


# --------------------------------------------------------------------------- #
# (d) The session identifier
# --------------------------------------------------------------------------- #


def measure_shared_identifier(
    *,
    params: ProtocolParams,
    trials: int,
    rng: np.random.Generator,
    attack_rng: np.random.Generator,
) -> AttackOutcome:
    """Measure attack (d): a signer gives two rounds one identifier.

    The one relabelling a signer can perform without a preimage. She reuses an
    opening, so two distribution rounds announce the same identifier and a
    declaration from either passes the other's binding check. **Success is that
    round A's declaration is accepted against round B's records** -- a
    declaration migrating between rounds, which is the whole thing the binding
    exists to stop.

    It does not migrate. The identifier names the round and never the key
    (:func:`~sih141.protocol.signature.session_identifier`), so passing the
    binding check buys the declaration nothing but the right to be *scored*, and
    round A's key is independent of round B's states. The acceptance rate is
    therefore the outside forger's again --
    :func:`~sih141.protocol.analysis.forgery_probability` -- carried in the
    note. The signer has spent an opening and gained the rate she already had.

    See :func:`measure_shared_identifier_self_denial` for what she *does*
    achieve, which is denying herself the second round.

    Parameters
    ----------
    params : ProtocolParams
        Keyword-only.
    trials : int
        Keyword-only, positive. Two rounds per trial.
    rng : numpy.random.Generator
        Keyword-only. The world's generator.
    attack_rng : numpy.random.Generator
        Keyword-only, a different object (D6). Draws the opening the dishonest
        signer reuses.

    Returns
    -------
    AttackOutcome
        ``successes`` counts accepted migrations. ``defended`` is ``True``: the
        binding is switched on and this attack is an attempt to walk through it,
        not a measurement of its absence.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or either generator is
        not one.
    ValueError
        If ``trials`` is not positive, or the two generators are the same
        object.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import measure_shared_identifier
    >>> from sih141.protocol.params import ProtocolParams
    >>> outcome = measure_shared_identifier(
    ...     params=ProtocolParams(key_length=24), trials=6,
    ...     rng=np.random.default_rng(23), attack_rng=np.random.default_rng(24),
    ... )
    >>> outcome.successes, outcome.refusals
    (0, 0)
    """
    checked = _as_params_arg(params)
    count = _as_trials(trials)
    world, adversary = _distinct_generators(rng, attack_rng)

    successes = 0
    refusals = 0
    for _ in range(count):
        opening = adversary.bytes(_OPENING_HEX_BYTES).hex()
        shared = session_identifier(0, checked.key_length, opening=opening)
        stale_signature, _ = _signed_round(checked, 0, world)
        _, live_records = _signed_round(checked, 0, world)
        relabelled = Signature(
            message_bit=0,
            declared_key=stale_signature.declared_key,
            session_opening=opening,
        )
        record = live_records[Party.BOB].with_session_id(shared)
        outcome = verify_or_abort(
            relabelled, record, checked, ledger=ConsumedRecords(Party.BOB)
        )
        if _refused(outcome):
            refusals += 1
        elif _accepted(outcome):
            successes += 1
    predicted = forgery_probability(checked, party=Party.BOB)
    return AttackOutcome(
        label="declaration migrates between two rounds sharing an identifier",
        defended=True,
        trials=count,
        successes=successes,
        refusals=refusals,
        key_length=checked.key_length,
        note=(
            f"the binding passes by construction and buys nothing: scored at "
            f"the outside forger's law, predicted {predicted:.6g} by "
            f"analysis.forgery_probability"
        ),
    )


def measure_shared_identifier_self_denial(
    *,
    params: ProtocolParams,
    trials: int,
    rng: np.random.Generator,
    attack_rng: np.random.Generator,
) -> AttackOutcome:
    """Measure what reusing an opening actually costs the signer who does it.

    Same setup as :func:`measure_shared_identifier`: two rounds announcing one
    identifier. Here the verifier decides round A honestly, and the *honest*
    declaration of round B is then presented. **Success -- from the point of
    view of an adversary who wants the second round dead -- is that the honest
    round B declaration is refused.**

    It always is. A ledger keys on ``(session_id, message_bit)``, so two rounds
    sharing an identifier are one round to every verifier and the second is
    refused as
    :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`. That
    confirms the claim in :mod:`sih141.protocol.signature` rather than
    contradicting it, and it is worth measuring rather than quoting because it
    is also a *self*-inflicted denial of service and the only party who can
    mount it is the signer, who could have declined to sign instead. The opening
    is secret until Phase B, so no third party can arrange the collision.

    Parameters
    ----------
    params : ProtocolParams
        Keyword-only.
    trials : int
        Keyword-only, positive. Two rounds per trial.
    rng : numpy.random.Generator
        Keyword-only. The world's generator.
    attack_rng : numpy.random.Generator
        Keyword-only, a different object (D6). Draws the reused opening.

    Returns
    -------
    AttackOutcome
        ``successes`` counts trials whose honest second round was denied.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or either generator is
        not one.
    ValueError
        If ``trials`` is not positive, or the two generators are the same
        object.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import measure_shared_identifier_self_denial
    >>> from sih141.protocol.params import ProtocolParams
    >>> outcome = measure_shared_identifier_self_denial(
    ...     params=ProtocolParams(key_length=24), trials=6,
    ...     rng=np.random.default_rng(23), attack_rng=np.random.default_rng(24),
    ... )
    >>> outcome.successes, outcome.refusals
    (6, 6)
    """
    checked = _as_params_arg(params)
    count = _as_trials(trials)
    world, adversary = _distinct_generators(rng, attack_rng)

    successes = 0
    refusals = 0
    for _ in range(count):
        opening = adversary.bytes(_OPENING_HEX_BYTES).hex()
        shared = session_identifier(0, checked.key_length, opening=opening)
        first_signature, first_records = _signed_round(checked, 0, world)
        second_signature, second_records = _signed_round(checked, 0, world)
        ledger = ConsumedRecords(Party.BOB)

        def present(
            signature: Signature,
            records: dict[Party, RecipientRecord],
            *,
            opening: str = opening,
            shared: str = shared,
            ledger: ConsumedRecords = ledger,
        ) -> VerificationResult | VerificationAbort:
            """Score one of the two rounds, both announcing ``shared``."""
            return verify_or_abort(
                Signature(
                    message_bit=0,
                    declared_key=signature.declared_key,
                    session_opening=opening,
                ),
                records[Party.BOB].with_session_id(shared),
                checked,
                ledger=ledger,
            )

        # The first round is decided honestly; the second is the one the reused
        # opening costs her, and it is the second that this outcome is about.
        present(first_signature, first_records)
        outcome = present(second_signature, second_records)
        if _refused(outcome):
            refusals += 1
        if not _accepted(outcome):
            successes += 1
    return AttackOutcome(
        label="second round denied by an identifier its signer reused",
        defended=True,
        trials=count,
        successes=successes,
        refusals=refusals,
        key_length=checked.key_length,
        note=(
            "two rounds sharing an identifier are one round to every verifier; "
            "only the signer can arrange it and it costs her the second round"
        ),
    )


def measure_identifier_preimage(
    *,
    target: str,
    params: ProtocolParams,
    attempts: int,
    rng: np.random.Generator,
    message_bit: int = 0,
) -> AttackOutcome:
    """Measure attack (d): forge an opening so a stale declaration looks fresh.

    The relabelling a hop adversary would need in order to make a captured
    declaration name the *live* round. There is nowhere to write an identifier
    -- :attr:`~sih141.protocol.signature.Signature.session_id` is a property of
    the opening -- so the adversary must find an opening hashing to the target,
    which is a 128-bit preimage on BLAKE2b. **Success is a hit.**

    A bounded search finds nothing, and that is all a bounded search can
    honestly report: ``0`` out of ``N`` bounds the rate above by roughly
    ``3.7 / N`` at 95%, while the analytic value is ``2**-128``. The measurement
    is here to show the search was actually run and the encoding actually
    exercised, not to establish the exponent -- the exponent comes from the
    digest width, and :func:`~sih141.protocol.signature.session_identifier`
    length-prefixes every variable-length field so that no ``(opening,
    context)`` pair can be rewritten into another one by moving a delimiter.

    Parameters
    ----------
    target : str
        The identifier to hit -- normally the live round's, read off a
        verifier's log.
    params : ProtocolParams
        Keyword-only. Supplies the key length bound into every identifier.
    attempts : int
        Keyword-only, positive. How many openings to try.
    rng : numpy.random.Generator
        Keyword-only. The **adversary's own** generator (D6); no session is
        built here, so there is no world generator to keep it away from.
    message_bit : int, optional
        Keyword-only, ``0`` or ``1``. The bit the forged identifier must claim.

    Returns
    -------
    AttackOutcome
        ``successes`` counts openings that hashed to ``target``.

    Raises
    ------
    TypeError
        If ``target`` is not a string, ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or ``rng`` is not a
        generator.
    ValueError
        If ``target`` is empty, ``attempts`` is not positive, or
        ``message_bit`` is not ``0``/``1``.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.replay import (
    ...     measure_identifier_preimage, replay_capture)
    >>> capture = replay_capture()
    >>> outcome = measure_identifier_preimage(
    ...     target=capture.signature.session_id, params=capture.params,
    ...     attempts=2000, rng=np.random.default_rng(99),
    ... )
    >>> outcome.successes
    0
    >>> round(outcome.interval[1], 5)
    0.00192
    """
    if not isinstance(target, str):
        raise TypeError(
            f"target must be a string identifier, got {type(target).__name__}"
        )
    if not target:
        raise ValueError(
            "target must be non-empty: there is no round named by the empty "
            "identifier, so a search for it would report a meaningless zero."
        )
    checked = _as_params_arg(params)
    count = _as_trials(attempts)
    adversary = _as_generator(rng, "rng")
    if isinstance(message_bit, bool) or message_bit not in (0, 1):
        raise ValueError(f"message_bit must be 0 or 1, got {message_bit!r}")

    successes = 0
    for _ in range(count):
        opening = adversary.bytes(_OPENING_HEX_BYTES).hex()
        if (
            session_identifier(
                int(message_bit), checked.key_length, opening=opening
            )
            == target
        ):
            successes += 1
    return AttackOutcome(
        label="preimage on a round identifier",
        defended=True,
        trials=count,
        successes=successes,
        refusals=0,
        key_length=checked.key_length,
        note=(
            "analytic rate 2**-128 = 2.9e-39 per attempt; a bounded search can "
            "only bound it, and this one bounds it at the Wilson upper limit"
        ),
    )
