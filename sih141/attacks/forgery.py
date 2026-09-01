"""Forgery: the outside adversary who knows nothing, and the recipient who does.

Two adversaries, one question -- *can somebody who is not Alice produce a
declaration a verifier accepts?* -- and the whole of the answer is in the gap
between them.

:class:`OutsideForger`
    Eve. She holds no key, no record and no coin. She declares a freshly drawn
    key and hopes. Her per-scored-position mismatch rate is ``1/2``, because a
    declaration independent of the verifier's log agrees with it on a fair coin,
    and her acceptance probability is
    :func:`~sih141.protocol.analysis.forgery_probability`.
:class:`RecipientForger`
    Bob, attacking Charlie. **The binding adversary, and the one a security
    claim is about.** He measured his own copy of the same public key, and after
    Phase A' he *supplied* half of the evidence Charlie will score him against.
    His mismatch rate is ``1/12`` rather than ``1/2``, and his acceptance
    probability is
    :func:`~sih141.protocol.analysis.recipient_forgery_probability`.

Without Phase A' the same recipient sits at ``1/3`` instead of ``1/12`` --
scored on the ordinary ``1/3`` of positions where Charlie's basis happens to
match his declared one, and wrong on a third of those. That single comparison,
measured in :func:`measure_recipient_forgery` with ``symmetrised=False``, is the
clearest statement of what the symmetrisation step buys, and it is the number
this module exists to produce.

.. _forgery-routes:

Which seam each forger is mounted on, and why it is not negotiable
-----------------------------------------------------------------
:class:`RecipientForger` is a **forwarder**, never a signer. The signer's
declaration reaches *both* verifiers, so a Bob mounted there is handed his own
forgery, scores it against his own log and rejects it; the run is recorded as a
rejection and a Phase 5 table built on it understates the attack. The forwarder
seam is the Bob-to-Charlie hop: Bob receives Alice's real declaration, accepts
it, and substitutes what *he* would have Charlie believe. That is the faithful
route, and :ref:`sih141.protocol.session <forger-route>` is the protocol-side
statement of the same thing.

He is handed a :class:`~sih141.protocol.records.RecipientView` -- his own two
logs and his own matched count, and nothing of Charlie's -- so the attack cannot
read its target's evidence even by accident.

:class:`OutsideForger` is a **signer**: Eve stands on the classical channel from
Alice and substitutes the declaration outright. Because that declaration goes to
both verifiers, one run measures her against Bob's cut ``s_a`` *and* Charlie's
``s_v``, which is exactly what :func:`forgery_probability` predicts per party.
Mounting her on the forwarder instead would measure only Charlie and would waste
half of every run; there is no self-verification problem for her, because she is
neither verifier.

.. _pooled-arm:

The forwarding forger and Phase C'
----------------------------------
Under the shipped pooled rule a substituted declaration does not get *rejected*
-- Charlie reaches **no verdict**,
:attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`, because
the counts were exchanged against Alice's declaration while he is scoring Bob's.
That is a denial of transfer and **not a detection**: Charlie has learned that
two numbers disagree about their provenance and nothing whatever about the
signature, and a real forging Bob who announced a count against his own
declaration would not trip it. It is measured here
(``measure_recipient_forgery(..., pooled_counts=True)``) and reported in its own
field, never folded into a rejection count.

The forger's *rate* is therefore measured in the pre-pooled arm,
:func:`~sih141.protocol.tally.no_count_exchange`, where Charlie scores on his own
floor and rejects on the mismatch rate -- which is the quantity ``1/12`` is a
statement about.

.. _forgery-scaling:

Key lengths: why a measurement at ``L = 60`` says something about ``L = 115200``
-------------------------------------------------------------------------------
Both acceptance probabilities fall off exponentially in ``L``
(:func:`~sih141.protocol.analysis.recipient_forgery_bound`), so at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` there is no acceptance to measure:
the predicted rate is ``1e-103``, and a hundred billion runs would see nothing.
Measuring there would confirm only that the harness can count to zero.

What *is* measured at small ``L``, and what carries, is the per-position
behaviour the bound is built from:

``scored fraction``
    ``2/3`` symmetrised, ``1/3`` without the exchange. A per-position property of
    the basis draws; it does not depend on ``L``.
``mismatch rate among scored positions``
    ``1/12`` symmetrised, ``1/3`` without. Likewise per-position.

Those two numbers are the entire input to
:func:`~sih141.protocol.analysis.recipient_forgery_probability`, which is then
evaluated exactly at any ``L``, and the measured acceptance rate at small ``L``
is checked against it to confirm that the harness composes them the way the
analysis says. That is the scaling argument, and it is the only honest one:
a run at ``L = 60`` exhibits *no security* -- both matched-count floors
degenerate below ``L = 140`` -- and must never be presented as if it did. It
exhibits a **rate**, and the rate is what scales.

Notes
-----
Convention D6
    Both adversaries take their own :class:`numpy.random.Generator` and read
    nothing of the session's. :func:`forwarder_probe` and
    :func:`~sih141.attacks.isolation.signer_probe` demonstrate it rather than
    asserting it; ``tests/test_attack_forgery.py`` runs both halves of
    :func:`~sih141.attacks.isolation.check_attack_isolation` over both classes.

    One caveat belongs here rather than in a test comment: the **optimal**
    recipient forger is a deterministic function of his view. Declaring his own
    raw log is strictly better than any randomised alternative at every position
    (see :func:`~sih141.protocol.keys.key_from_record`), so at
    ``guess_probability=0`` he ignores his generator and check (b) of the
    isolation contract -- "vary the attack's own rng and the decisions must
    move" -- cannot pass, by the nature of the adversary rather than by any
    defect in him. :attr:`RecipientForger.guess_probability` exists for that: a
    positive value mixes in independently drawn positions, exercises the same
    call path, and makes the candidate visible to both halves of the check. It
    is strictly suboptimal and is **not** what a rate is measured at.
No machine learning (D4)
    Binomial counting, a Wilson interval, and one exact double-binomial sum
    imported from :mod:`sih141.protocol.analysis`.

See Also
--------
sih141.attacks.isolation : The D6 check both adversaries are held to.
sih141.protocol.analysis.forgery_probability : Eve's exact acceptance rate.
sih141.protocol.analysis.recipient_forgery_probability : Bob's.
sih141.protocol.keys.key_from_record : Reading a log as a declaration.

Examples
--------
Eve, at a length where she is occasionally lucky. Her declaration is drawn from
her own generator and owes nothing to the session's:

>>> import numpy as np
>>> from sih141.attacks.forgery import OutsideForger, measure_outside_forgery
>>> from sih141.protocol.params import Party, ProtocolParams
>>> measurement = measure_outside_forgery(
...     ProtocolParams(key_length=24),
...     trials=24,
...     rng=np.random.default_rng(11),
...     session_rng=np.random.default_rng(12),
... )
>>> measurement[Party.CHARLIE].mismatch_rate_within(0.5, 0.08)
True

Bob, forging on the forwarding hop, in the pre-pooled arm where Charlie scores:

>>> from sih141.attacks.forgery import measure_recipient_forgery
>>> bound = measure_recipient_forgery(
...     ProtocolParams(key_length=48),
...     trials=24,
...     rng=np.random.default_rng(13),
...     session_rng=np.random.default_rng(14),
... )
>>> bound.mismatch_rate_within(1 / 12, 0.03)
True
>>> bound.scored_fraction_within(2 / 3, 0.05)
True

And the same forger with Phase A' removed, which is the demonstration:

>>> stripped = measure_recipient_forgery(
...     ProtocolParams(key_length=48),
...     trials=24,
...     rng=np.random.default_rng(15),
...     session_rng=np.random.default_rng(16),
...     symmetrised=False,
... )
>>> stripped.mismatch_rate_within(1 / 3, 0.06)
True
>>> stripped.scored_fraction_within(1 / 3, 0.05)
True
>>> round(bound.mismatch_rate, 3) < round(stripped.mismatch_rate, 3)
True
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from sih141.attacks.isolation import (
    DecisionProbe,
    SignerScenario,
    signer_scenario,
)
from sih141.attacks.statistics import wilson_bounds
from sih141.core.rng import resolve_rng
from sih141.protocol.analysis import (
    forgery_probability,
    recipient_forgery_probability,
)
from sih141.protocol.keys import (
    KeyElement,
    PrivateKey,
    generate_private_key,
    key_from_record,
)
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.records import RecipientView
from sih141.protocol.session import QDSSession
from sih141.protocol.signature import Signature
from sih141.protocol.symmetrise import no_symmetrisation
from sih141.protocol.tally import no_count_exchange

__all__ = [
    "OUTSIDE_FORGER_MISMATCH_RATE",
    "RECIPIENT_FORGER_MISMATCH_RATE",
    "UNSYMMETRISED_FORGER_MISMATCH_RATE",
    "Z_95",
    "ForgeryMeasurement",
    "OutsideForger",
    "RecipientForger",
    "forwarder_probe",
    "measure_outside_forgery",
    "measure_recipient_forgery",
    "wilson_interval",
]


Z_95: Final[float] = 1.959963984540054
"""float: The normal quantile behind every interval this module reports.

Two-sided 95%. Named rather than written inline because the intervals are
compared against analytic predictions and a reader has to know what "agrees"
was tested at.
"""

OUTSIDE_FORGER_MISMATCH_RATE: Final[float] = 0.5
"""float: Eve's mismatch rate among scored positions -- a fair coin.

Her declaration is independent of the verifier's log, so on a scored position
the two agree exactly when a coin does. Equal to
:data:`~sih141.protocol.analysis.FORGER_MATCHED_MISMATCH_PROBABILITY`, and
restated here because it is what :func:`measure_outside_forgery` checks its
own arithmetic against.
"""

RECIPIENT_FORGER_MISMATCH_RATE: Final[float] = 1.0 / 12.0
"""float: Bob's mismatch rate among scored positions, ``(n-1)/(2n(n+1))``.

``1/12`` for the three-basis alphabet:
:attr:`~sih141.protocol.params.ProtocolParams.forger_floor`. On the half of
positions the exchange swapped, Charlie holds *Bob's own* entry and the
declaration is right by construction; elsewhere Bob is scored on a third of
positions and wrong on a third of those.
"""

UNSYMMETRISED_FORGER_MISMATCH_RATE: Final[float] = 1.0 / 3.0
"""float: The same recipient's mismatch rate with Phase A' removed.

``(1 - 1/n)/2 = 1/3``:
:attr:`~sih141.protocol.params.ProtocolParams.unmatched_noise_rate`. The gap
between this and :data:`RECIPIENT_FORGER_MISMATCH_RATE` is what the
symmetrisation exchange buys, and it is the single clearest figure Phase 5 can
draw.
"""

_GUESS_LABEL: Final[str] = "guess_probability"
"""Name quoted in :class:`RecipientForger`'s validation messages."""


# --------------------------------------------------------------------------- #
# Interval arithmetic
# --------------------------------------------------------------------------- #


def wilson_interval(
    successes: int, trials: int, *, z: float = Z_95
) -> tuple[float, float]:
    """Return the Wilson score interval for a binomial proportion.

    Wilson rather than the normal approximation because every interesting rate
    here is near an endpoint: Eve accepts on a few runs in a thousand, and the
    normal interval at ``0/2000`` is the single point ``0``, which would report
    perfect agreement with any prediction whatsoever and perfect disagreement
    with the truth. Wilson keeps a two-sided interval of positive width at
    ``0`` successes and at ``trials`` successes alike.

    Parameters
    ----------
    successes : int
        Number of successes, ``0 <= successes <= trials``.
    trials : int
        Number of trials. Must be positive: a rate over no trials is not a
        wide interval, it is no measurement.
    z : float, optional
        Keyword-only normal quantile; defaults to :data:`Z_95`. Positive.

    Returns
    -------
    tuple of float
        ``(low, high)``, both clipped into ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``successes`` or ``trials`` is not an integer, or ``z`` is not a
        real number.
    ValueError
        If ``trials`` is not positive, ``successes`` is out of range, or ``z``
        is not positive and finite.

    Examples
    --------
    >>> from sih141.attacks.forgery import wilson_interval
    >>> low, high = wilson_interval(0, 100)
    >>> low, round(high, 4)
    (0.0, 0.037)
    >>> low, high = wilson_interval(50, 100)
    >>> round(low, 4), round(high, 4)
    (0.4038, 0.5962)
    """
    checked_trials = _as_count(trials, "trials")
    checked_successes = _as_count(successes, "successes")
    if checked_trials <= 0:
        raise ValueError(
            f"trials must be positive, got {checked_trials}. An interval over "
            f"zero trials is not a wide measurement, it is the absence of one; "
            f"report the trial count instead of a rate."
        )
    if checked_successes > checked_trials:
        raise ValueError(
            f"successes ({checked_successes}) exceeds trials "
            f"({checked_trials}); a proportion above one is a counting error "
            f"upstream, not a rate."
        )
    if isinstance(z, bool) or not isinstance(z, (int, float, np.floating)):
        raise TypeError(f"z must be a real number, got {type(z).__name__}")
    quantile = float(z)
    if not math.isfinite(quantile) or quantile <= 0.0:
        raise ValueError(
            f"z must be positive and finite, got {quantile}. It is a normal "
            f"quantile; Z_95 is the default."
        )

    # One implementation for the suite, in sih141.attacks.statistics: four
    # modules needed this closed form and four wrote it, two of them carrying
    # the same float-dust bug at zero successes (:ref:`float-dust`).
    return wilson_bounds(checked_successes, checked_trials, z=quantile)


def _as_count(value: Any, name: str) -> int:
    """Coerce a non-negative integer count, refusing bools and floats."""
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise TypeError(
            f"{name} must be an int, got {type(value).__name__}. Counts of "
            f"runs are integers; a float here is usually a rate that has "
            f"already been divided once."
        )
    count = int(value)
    if count < 0:
        raise ValueError(f"{name} must be non-negative, got {count}")
    return count


def _as_generator(value: Any, name: str) -> np.random.Generator:
    """Resolve one generator argument, keeping :func:`resolve_rng`'s rules."""
    if value is not None and not isinstance(value, np.random.Generator):
        raise TypeError(
            f"{name} must be a numpy.random.Generator or None, got "
            f"{type(value).__name__}. Integer seeds are refused throughout the "
            f"project (D3); build a generator with numpy.random.default_rng."
        )
    return resolve_rng(value)


# --------------------------------------------------------------------------- #
# The result of one experiment
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ForgeryMeasurement:
    """What one block of forgery trials produced, with its evidence kept.

    Frozen, and made of ints, floats, bools and one
    :class:`~sih141.protocol.params.Party`, so it drops straight into
    :func:`json.dumps` for a Phase 5 table.

    Counts rather than rates are the fields; every rate is a property derived
    from them, so a caller can re-pool two blocks by adding the counts and
    cannot accidentally average two rates over different denominators.

    Parameters
    ----------
    label : str
        Which experiment this was, for a report row.
    party : Party
        The verifier being attacked.
    key_length : int
        The scored key length, i.e. ``params.signing_length``.
    trials : int
        Runs attempted. Positive.
    accepted : int
        Runs on which the target accepted the forged declaration. The
        numerator of :attr:`rate`.
    no_verdict : int
        Runs on which the target reached no verdict at all -- a matched-count
        floor refused the evidence base, or Phase C' refused the declaration's
        provenance (:ref:`pooled-arm`). Counted separately and **never** as a
        rejection: a refusal to score is a denial of transfer, not a detection.
    scored_positions : int
        Total matched positions summed over the runs that reached a verdict.
        The denominator of :attr:`mismatch_rate`.
    mismatches : int
        Total disagreements within those matched positions.
    predicted : float or None
        The analytic acceptance probability for this experiment, or ``None``
        when no closed form applies.
    predicted_mismatch_rate : float or None
        The analytic per-scored-position mismatch rate.
    symmetrised : bool
        Whether Phase A' ran. ``False`` is the stripped comparison arm.
    bob_accepted : int
        How many runs the *forwarding* recipient's own verification accepted,
        i.e. how many runs were genuine forgeries rather than repudiations.
        ``0`` for an experiment in which no such party exists.

    Attributes
    ----------
    label : str
    party : Party
    key_length : int
    trials : int
    accepted : int
    no_verdict : int
    scored_positions : int
    mismatches : int
    predicted : float or None
    predicted_mismatch_rate : float or None
    symmetrised : bool
    bob_accepted : int

    Raises
    ------
    TypeError
        If any count is not an integer or ``party`` is not a party.
    ValueError
        If ``trials`` is not positive, if the counts are inconsistent
        (``accepted + no_verdict > trials``, or ``mismatches >
        scored_positions``), or if a predicted rate is outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.attacks.forgery import ForgeryMeasurement
    >>> from sih141.protocol.params import Party
    >>> block = ForgeryMeasurement(
    ...     label="outside forger",
    ...     party=Party.CHARLIE,
    ...     key_length=30,
    ...     trials=2000,
    ...     accepted=9,
    ...     no_verdict=0,
    ...     scored_positions=20000,
    ...     mismatches=10000,
    ...     predicted=0.004211,
    ...     predicted_mismatch_rate=0.5,
    ... )
    >>> round(block.rate, 5), block.agrees_with_prediction
    (0.0045, True)
    >>> block.mismatch_rate
    0.5
    """

    label: str
    party: Party
    key_length: int
    trials: int
    accepted: int
    no_verdict: int = 0
    scored_positions: int = 0
    mismatches: int = 0
    predicted: float | None = None
    predicted_mismatch_rate: float | None = None
    symmetrised: bool = True
    bob_accepted: int = 0

    def __post_init__(self) -> None:
        """Coerce the counts and refuse a self-contradictory block."""
        if not isinstance(self.label, str):
            raise TypeError(
                f"label must be a string, got {type(self.label).__name__}"
            )
        if not isinstance(self.party, (Party, str)):
            raise TypeError(
                f"party must be a Party or its label, got "
                f"{type(self.party).__name__}"
            )
        try:
            resolved = Party(self.party)
        except ValueError as error:
            raise ValueError(
                f"party names nobody in the protocol: {self.party!r}. The "
                f"verifiers are "
                f"{[member.value for member in VERIFIERS]}."
            ) from error
        if resolved is Party.ALICE:
            raise ValueError(
                "a forgery measurement is about a verifier's decision, and "
                "Alice reaches none. Pass Party.BOB or Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        for name in (
            "key_length",
            "trials",
            "accepted",
            "no_verdict",
            "scored_positions",
            "mismatches",
            "bob_accepted",
        ):
            object.__setattr__(self, name, _as_count(getattr(self, name), name))
        if self.trials <= 0:
            raise ValueError(
                f"trials must be positive, got {self.trials}. A measurement "
                f"block with no runs in it has no rate to report."
            )
        if self.accepted + self.no_verdict > self.trials:
            raise ValueError(
                f"accepted ({self.accepted}) plus no_verdict "
                f"({self.no_verdict}) exceeds trials ({self.trials}). A run "
                f"ends in exactly one of accepted, rejected or no-verdict; "
                f"counting an aborted run as a rejection as well is the error "
                f"this check exists to catch."
            )
        if self.mismatches > self.scored_positions:
            raise ValueError(
                f"mismatches ({self.mismatches}) exceeds scored_positions "
                f"({self.scored_positions}); mismatches are counted within the "
                f"matched set only."
            )
        for name in ("predicted", "predicted_mismatch_rate"):
            value = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(
                value, (int, float, np.floating)
            ):
                raise TypeError(
                    f"{name} must be a float or None, got "
                    f"{type(value).__name__}"
                )
            number = float(value)
            if not 0.0 <= number <= 1.0:
                raise ValueError(
                    f"{name} must be a probability in [0, 1], got {number}"
                )
            object.__setattr__(self, name, number)
        if not isinstance(self.symmetrised, bool):
            raise TypeError(
                f"symmetrised must be a bool, got "
                f"{type(self.symmetrised).__name__}. It names which protocol "
                f"variant was run, not a rate."
            )

    # -- derived rates ------------------------------------------------------ #

    @property
    def rejected(self) -> int:
        """int: Runs on which the target scored the forgery and refused it."""
        return self.trials - self.accepted - self.no_verdict

    @property
    def rate(self) -> float:
        """float: Acceptance rate, ``accepted / trials``.

        A no-verdict run is in the denominator and not in the numerator: the
        forgery did not succeed on it. Read :attr:`no_verdict` to see how many
        of the failures were refusals to score rather than rejections --
        :ref:`pooled-arm` explains why the two must not be added together.
        """
        return self.accepted / self.trials

    @property
    def interval(self) -> tuple[float, float]:
        """tuple of float: Two-sided 95% Wilson interval for :attr:`rate`."""
        return wilson_interval(self.accepted, self.trials)

    @property
    def agrees_with_prediction(self) -> bool:
        """bool: Whether :attr:`predicted` lies inside :attr:`interval`.

        ``False`` when no prediction was supplied, since an absent prediction
        agrees with nothing; check ``predicted is None`` first.
        """
        if self.predicted is None:
            return False
        low, high = self.interval
        return low <= self.predicted <= high

    @property
    def scored_runs(self) -> int:
        """int: Runs on which the target reached a verdict."""
        return self.trials - self.no_verdict

    @property
    def mismatch_rate(self) -> float:
        """float: Disagreements per scored position, ``e / |M|``.

        The statistic the security bound is an exponential in, and the one that
        carries from a demonstration length to ``L = 115200``
        (:ref:`forgery-scaling`). ``nan`` when nothing was scored.
        """
        if self.scored_positions == 0:
            return float("nan")
        return self.mismatches / self.scored_positions

    @property
    def mismatch_interval(self) -> tuple[float, float]:
        """tuple of float: 95% Wilson interval for :attr:`mismatch_rate`.

        Over scored *positions*, which is the right denominator: the positions
        are independent given the declaration, and pooling them is what makes
        this the tight statistic even when the acceptance rate is not.
        """
        if self.scored_positions == 0:
            return (0.0, 1.0)
        return wilson_interval(self.mismatches, self.scored_positions)

    @property
    def scored_fraction(self) -> float:
        """float: Matched positions per key position, ``|M| / L``.

        ``2/3`` for a symmetrised recipient forger, ``1/3`` for the stripped
        arm and for an outside forger. ``nan`` when no run reached a verdict.
        """
        positions = self.scored_runs * self.key_length
        if positions == 0:
            return float("nan")
        return self.scored_positions / positions

    def mismatch_rate_within(self, target: float, tolerance: float) -> bool:
        """Say whether :attr:`mismatch_rate` is within ``tolerance`` of ``target``.

        A helper for doctests and reports, so that a live numeric claim can be
        written as an executable example (D5) without pinning a digit that a
        different trial count would move.

        Parameters
        ----------
        target : float
            The predicted rate, e.g. :data:`RECIPIENT_FORGER_MISMATCH_RATE`.
        tolerance : float
            Non-negative absolute tolerance.

        Returns
        -------
        bool
            ``False`` when nothing was scored, since ``nan`` is within nothing.

        Raises
        ------
        ValueError
            If ``tolerance`` is negative.

        Examples
        --------
        >>> from sih141.attacks.forgery import ForgeryMeasurement
        >>> from sih141.protocol.params import Party
        >>> block = ForgeryMeasurement(
        ...     "demo", Party.CHARLIE, 48, 10, 0,
        ...     scored_positions=320, mismatches=27,
        ... )
        >>> block.mismatch_rate_within(1 / 12, 0.02)
        True
        """
        return _within(self.mismatch_rate, target, tolerance)

    def scored_fraction_within(self, target: float, tolerance: float) -> bool:
        """Say whether :attr:`scored_fraction` is within ``tolerance``.

        Parameters
        ----------
        target : float
            The predicted fraction, ``2/3`` or ``1/3``.
        tolerance : float
            Non-negative absolute tolerance.

        Returns
        -------
        bool

        Raises
        ------
        ValueError
            If ``tolerance`` is negative.

        Examples
        --------
        >>> from sih141.attacks.forgery import ForgeryMeasurement
        >>> from sih141.protocol.params import Party
        >>> block = ForgeryMeasurement(
        ...     "demo", Party.CHARLIE, 48, 10, 0, scored_positions=320
        ... )
        >>> block.scored_fraction_within(2 / 3, 0.02)
        True
        """
        return _within(self.scored_fraction, target, tolerance)

    def summary(self) -> str:
        """Return a compact human-readable block, one experiment per call.

        Returns
        -------
        str
            Five lines: the label, the acceptance rate with its interval and
            the prediction, the mismatch rate with its interval and prediction,
            the scored fraction, and the no-verdict count.

        Examples
        --------
        >>> from sih141.attacks.forgery import ForgeryMeasurement
        >>> from sih141.protocol.params import Party
        >>> print(ForgeryMeasurement(
        ...     "recipient forger", Party.CHARLIE, 48, 100, 34,
        ...     scored_positions=3200, mismatches=267,
        ...     predicted=0.371, predicted_mismatch_rate=1 / 12,
        ... ).summary())
        recipient forger vs Charlie, L=48, symmetrised, 100 trials
          accepted   0.34000  95% CI [0.25462, 0.43722]  predicted 0.371 (agrees)
          mismatch   0.08344  95% CI [0.07435, 0.09353]  predicted 0.083333 (agrees)
          scored     0.66667 of positions
          no verdict 0 runs, 66 rejections
        """
        low, high = self.interval
        mlow, mhigh = self.mismatch_interval
        accepted_note = (
            "no prediction"
            if self.predicted is None
            else (
                f"predicted {self.predicted:g} "
                f"({'agrees' if self.agrees_with_prediction else 'DISAGREES'})"
            )
        )
        if self.scored_positions == 0:
            mismatch_note = "nothing was scored"
        elif self.predicted_mismatch_rate is None:
            mismatch_note = "no prediction"
        else:
            inside = mlow <= self.predicted_mismatch_rate <= mhigh
            mismatch_note = (
                f"predicted {self.predicted_mismatch_rate:.5g} "
                f"({'agrees' if inside else 'DISAGREES'})"
            )
        return (
            f"{self.label} vs {self.party.value}, L={self.key_length}, "
            f"{'symmetrised' if self.symmetrised else 'NOT symmetrised'}, "
            f"{self.trials} trials\n"
            f"  accepted   {self.rate:.5f}  95% CI [{low:.5f}, {high:.5f}]  "
            f"{accepted_note}\n"
            f"  mismatch   {self.mismatch_rate:.5f}  95% CI "
            f"[{mlow:.5f}, {mhigh:.5f}]  {mismatch_note}\n"
            f"  scored     {self.scored_fraction:.5f} of positions\n"
            f"  no verdict {self.no_verdict} runs, {self.rejected} rejections"
        )


def _within(value: float, target: float, tolerance: float) -> bool:
    """Return ``abs(value - target) <= tolerance``, ``False`` at ``nan``."""
    if isinstance(tolerance, bool) or not isinstance(
        tolerance, (int, float, np.floating)
    ):
        raise TypeError(
            f"tolerance must be a real number, got {type(tolerance).__name__}"
        )
    if float(tolerance) < 0.0:
        raise ValueError(
            f"tolerance must be non-negative, got {float(tolerance)}. A "
            f"negative tolerance makes every comparison fail and reads as a "
            f"passing test that never passes."
        )
    if math.isnan(value):
        return False
    return abs(value - float(target)) <= float(tolerance)


# --------------------------------------------------------------------------- #
# (a) the outside forger
# --------------------------------------------------------------------------- #


class OutsideForger:
    """Eve: draws a fresh key, declares it, and knows nothing (D6).

    A :class:`~sih141.protocol.session.Signer` seam. She stands on the
    classical channel from Alice and substitutes her own declaration, which
    then reaches *both* verifiers -- so one run measures her against ``s_a`` and
    ``s_v`` at once. She is neither verifier, so nothing about that route makes
    her verify her own forgery (:ref:`forgery-routes`).

    Everything the seam offers her -- Alice's committed keys, and the recipient
    logs on a session built with ``signer_sees_recipient_logs=True`` -- is
    ignored, deliberately and checkably: the adversary model behind
    :func:`~sih141.protocol.analysis.forgery_probability` is an Eve who holds
    *no* information about the private key, and a forger who peeked would be
    measuring a different quantity under the same name.

    Parameters
    ----------
    rng : numpy.random.Generator or None
        Keyword-only. Her own generator, and the only randomness she uses (D6).
        ``None`` draws fresh entropy through
        :func:`~sih141.core.rng.resolve_rng`, which is reproducible-by-seed at
        the caller's option and never reachable from the session.

    Attributes
    ----------
    calls : int
        How many declarations she has made. A session calls her once.

    Raises
    ------
    TypeError
        If ``rng`` is neither ``None`` nor a :class:`numpy.random.Generator`.

    See Also
    --------
    RecipientForger : The binding adversary, and the one with real information.
    measure_outside_forgery : Runs her and reports the rate.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.forgery import OutsideForger
    >>> from sih141.attacks.isolation import assert_attack_isolated, signer_probe
    >>> assert_attack_isolated(OutsideForger, signer_probe()).isolated
    True

    She ignores the keys she is shown -- the same generator gives the same
    declaration whatever Alice committed to:

    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import NO_RECIPIENT_LOGS
    >>> params = ProtocolParams(key_length=8)
    >>> alice = generate_key_pair(params, rng=np.random.default_rng(1))
    >>> other = generate_key_pair(params, rng=np.random.default_rng(2))
    >>> first = OutsideForger(rng=np.random.default_rng(5))(
    ...     0, alice, params, records=NO_RECIPIENT_LOGS
    ... )
    >>> second = OutsideForger(rng=np.random.default_rng(5))(
    ...     0, other, params, records=NO_RECIPIENT_LOGS
    ... )
    >>> first == second, first.declared_key == alice[0]
    (True, False)
    """

    def __init__(self, *, rng: np.random.Generator | None = None) -> None:
        self._rng = _as_generator(rng, "rng")
        self.calls = 0

    def __repr__(self) -> str:
        """Return a debugging representation naming the call count."""
        return f"OutsideForger(calls={self.calls})"

    def __call__(
        self,
        message_bit: int,
        keys: Any,
        params: ProtocolParams,
        *,
        records: Any = None,
    ) -> Signature:
        """Declare a uniformly random key for ``message_bit``.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``, as the :class:`~sih141.protocol.session.Signer`
            seam passes it.
        keys : object
            Alice's committed pair. **Ignored**, and not even validated: the
            point of this adversary is that she holds nothing.
        params : ProtocolParams
            The scored parameter set, which supplies the declaration's length
            and basis alphabet. On a checked run this is the sifted set, so the
            declaration is the right length by construction.
        records : object, optional
            Keyword-only. Recipient logs, when the session was built to offer
            them. **Ignored**, for the same reason as ``keys``.

        Returns
        -------
        Signature
            A declaration of a fresh key, drawn from her own generator.

        Raises
        ------
        TypeError
            If ``params`` is not a
            :class:`~sih141.protocol.params.ProtocolParams`.
        ValueError
            If ``message_bit`` is not ``0``/``1``.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.forgery import OutsideForger
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import NO_RECIPIENT_LOGS
        >>> forger = OutsideForger(rng=np.random.default_rng(0))
        >>> declaration = forger(
        ...     1, None, ProtocolParams(key_length=6),
        ...     records=NO_RECIPIENT_LOGS,
        ... )
        >>> declaration.message_bit, len(declaration), forger.calls
        (1, 6, 1)
        """
        del keys, records  # She holds neither. See the class docstring.
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got {type(params).__name__}."
                f" The signer seam is handed the session's scored parameter "
                f"set; it supplies the declaration's length and alphabet."
            )
        self.calls += 1
        return Signature(
            message_bit,
            generate_private_key(params, message_bit, rng=self._rng),
        )


# --------------------------------------------------------------------------- #
# (b) the recipient forger -- the binding adversary
# --------------------------------------------------------------------------- #


class RecipientForger:
    """Bob, forging to Charlie on the forwarding hop (D6).

    A :class:`~sih141.protocol.session.Forwarder` seam that asks for a
    ``view``. Bob receives Alice's genuine declaration, verifies it, accepts,
    and then hands Charlie a declaration built from **his own raw log** -- which
    is worth far more to him than his post-exchange one, because after Phase A'
    roughly half of the raw log is precisely the evidence Charlie now holds
    (:func:`~sih141.protocol.keys.key_from_record`).

    That is the whole attack. It is one line long, it is optimal over all POVMs
    (:mod:`sih141.protocol.analysis`, section 3b), and it lands at exactly
    :data:`RECIPIENT_FORGER_MISMATCH_RATE` -- ``1/12`` -- against
    :data:`UNSYMMETRISED_FORGER_MISMATCH_RATE` -- ``1/3`` -- when the exchange
    is removed.

    **He is mounted on the forwarder and never on the signer.** A signer's
    declaration reaches both verifiers, so a Bob mounted there scores his own
    forgery and the run is recorded as a rejection; :ref:`forgery-routes` and
    :ref:`sih141.protocol.session <forger-route>` both say why.

    Parameters
    ----------
    rng : numpy.random.Generator or None
        Keyword-only. His own generator (D6). Used **only** by
        ``guess_probability``; the optimal forger draws nothing, which is a
        property of the adversary and is discussed in the module docstring
        under D6.
    guess_probability : float, optional
        Keyword-only, default ``0.0``. Probability that a position is declared
        from an independently drawn ``(basis, eigenvalue)`` instead of from his
        log. Strictly suboptimal -- it replaces information with noise, and
        drives the mismatch rate from ``1/12`` towards ``1/2`` -- and it exists
        for one reason: it makes his own randomness visible to check (b) of
        :func:`~sih141.attacks.isolation.check_attack_isolation`, which a
        deterministic candidate cannot pass. **Leave it at zero to measure a
        rate.**

    Attributes
    ----------
    guess_probability : float
    calls : int
        How many declarations he has forwarded.
    guessed_positions : int
        How many positions he has replaced with an independent draw, summed
        over calls. ``0`` for the optimal forger, and the quantity a test uses
        to confirm the knob does what it says.

    Raises
    ------
    TypeError
        If ``rng`` is not a generator or ``None``, or ``guess_probability`` is
        not a real number.
    ValueError
        If ``guess_probability`` is outside ``[0, 1]`` or is not finite.

    See Also
    --------
    measure_recipient_forgery : Runs him, in both the symmetrised and the
        stripped arm.
    sih141.protocol.records.RecipientView : What he is allowed to see.

    Notes
    -----
    He must be run with
    :func:`~sih141.protocol.tally.no_count_exchange` to measure a *rate*: under
    the shipped pooled rule Charlie reaches no verdict at all on a substituted
    declaration, which is a denial of transfer and not a detection
    (:ref:`pooled-arm`).

    Examples
    --------
    >>> import numpy as np
    >>> from functools import partial
    >>> from sih141.attacks.forgery import RecipientForger, forwarder_probe
    >>> from sih141.attacks.isolation import (
    ...     assert_attack_isolated, check_attack_isolation
    ... )

    The randomised variant satisfies both halves of the D6 check:

    >>> randomised = partial(RecipientForger, guess_probability=0.25)
    >>> assert_attack_isolated(
    ...     randomised, forwarder_probe(), name="RecipientForger"
    ... ).isolated
    True

    The optimal one reads nothing of the session either -- it is check (b) it
    cannot meet, because its declaration is a deterministic reading of its own
    view:

    >>> report = check_attack_isolation(RecipientForger, forwarder_probe())
    >>> report.reads_the_session, report.distinct_decisions
    (False, 1)
    """

    def __init__(
        self,
        *,
        rng: np.random.Generator | None = None,
        guess_probability: float = 0.0,
    ) -> None:
        self._rng = _as_generator(rng, "rng")
        if isinstance(guess_probability, bool) or not isinstance(
            guess_probability, (int, float, np.floating)
        ):
            raise TypeError(
                f"{_GUESS_LABEL} must be a real number, got "
                f"{type(guess_probability).__name__}"
            )
        probability = float(guess_probability)
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError(
                f"{_GUESS_LABEL} must be a probability in [0, 1], got "
                f"{probability}. It is the fraction of positions the forger "
                f"throws away and replaces with an independent draw; 0.0 is "
                f"the optimal forger and the only value a measured rate should "
                f"be taken at."
            )
        self.guess_probability = probability
        self.calls = 0
        self.guessed_positions = 0

    def __repr__(self) -> str:
        """Return a debugging representation naming the knob and the traffic."""
        return (
            f"RecipientForger({_GUESS_LABEL}={self.guess_probability!r}, "
            f"calls={self.calls}, guessed={self.guessed_positions})"
        )

    def __call__(
        self,
        signature: Signature,
        params: ProtocolParams,
        *,
        view: RecipientView,
    ) -> Signature:
        """Substitute a declaration built from his own raw log.

        Parameters
        ----------
        signature : Signature
            What Alice sent Bob and Bob has already scored. Only its
            ``message_bit`` is used: the forged declaration must name the run
            Charlie is in, and the session re-binds the round in any case.
        params : ProtocolParams
            The scored parameter set. Used for the basis alphabet when
            ``guess_probability`` is positive, and to check the view's length
            against what Charlie will score.
        view : RecipientView
            Keyword-only, and the only evidence he holds:
            :attr:`~sih141.protocol.records.RecipientView.raw_record` is the log
            he declares. There is no route from here to Charlie's log.

        Returns
        -------
        Signature
            The declaration Charlie will score.

        Raises
        ------
        TypeError
            If ``signature`` is not a
            :class:`~sih141.protocol.signature.Signature`, ``params`` is not a
            :class:`~sih141.protocol.params.ProtocolParams`, or ``view`` is not
            a :class:`~sih141.protocol.records.RecipientView`.
        ValueError
            If the view is for another message bit than the declaration, or if
            it belongs to a party other than
            :attr:`~sih141.protocol.params.Party.BOB` -- Charlie owns no
            forwarding hop, and a view filed there is a wiring error rather
            than an attack.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.forgery import RecipientForger
        >>> from sih141.attacks.isolation import signer_scenario
        >>> from sih141.protocol.params import Party
        >>> from sih141.protocol.signature import Signature
        >>> scenario = signer_scenario()
        >>> view = scenario.views[Party.BOB]
        >>> honest = Signature(scenario.message_bit, scenario.keys[0])
        >>> forger = RecipientForger(rng=np.random.default_rng(3))
        >>> forged = forger(honest, scenario.params, view=view)
        >>> forged.message_bit == honest.message_bit
        True
        >>> forged.declared_key == honest.declared_key
        False

        Every element of the forgery is a line of his own raw log:

        >>> all(
        ...     element.basis == entry.basis
        ...     and element.eigenvalue == entry.eigenvalue
        ...     for element, entry in zip(
        ...         forged.declared_key, view.raw_record.entries
        ...     )
        ... )
        True
        """
        if not isinstance(signature, Signature):
            raise TypeError(
                f"signature must be a Signature, got "
                f"{type(signature).__name__}. The forwarder seam is handed the "
                f"declaration Bob received; a forgery replaces it with another "
                f"declaration, it does not remove it."
            )
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got {type(params).__name__}"
            )
        if not isinstance(view, RecipientView):
            raise TypeError(
                f"view must be a RecipientView, got {type(view).__name__}. "
                f"This adversary is a recipient and holds one recipient's "
                f"evidence; a mapping of both logs would put the target's own "
                f"record in his hands and measure a different adversary."
            )
        if view.party is not Party.BOB:
            raise ValueError(
                f"view belongs to {view.party.value}, but the forwarding hop "
                f"is Bob's: he is the party who receives Alice's declaration "
                f"and passes it on. A Charlie-flavoured forger attacks Bob and "
                f"needs a route of his own, not this seam."
            )
        if view.message_bit != signature.message_bit:
            raise ValueError(
                f"view is for message bit {view.message_bit} but the "
                f"declaration is for bit {signature.message_bit}. The two "
                f"distribution runs share no key and no evidence, so a forgery "
                f"built from the wrong run's log is scored against states that "
                f"were never sent for it."
            )

        elements = list(
            key_from_record(view.raw_record, message_bit=signature.message_bit)
        )
        if self.guess_probability > 0.0:
            elements = self._blend(elements, params)
        self.calls += 1
        return Signature(
            signature.message_bit,
            PrivateKey(signature.message_bit, elements),
        )

    def _blend(
        self, elements: list[KeyElement], params: ProtocolParams
    ) -> list[KeyElement]:
        """Replace a random subset of ``elements`` with independent draws.

        Parameters
        ----------
        elements : list of KeyElement
            The optimal declaration, read off his raw log.
        params : ProtocolParams
            Supplies the basis alphabet the replacements are drawn from.

        Returns
        -------
        list of KeyElement
            A new list; ``elements`` is not modified.

        Notes
        -----
        Draws exactly one uniform array plus two variates per replaced
        position, all from his own generator, so the number of draws depends on
        his own coins and never on the session's.
        """
        bases = params.bases
        coins = self._rng.random(len(elements))
        blended = list(elements)
        for index, coin in enumerate(coins):
            if coin >= self.guess_probability:
                continue
            basis = bases[int(self._rng.integers(len(bases)))]
            eigenvalue = 1 if int(self._rng.integers(2)) == 0 else -1
            blended[index] = KeyElement(basis, eigenvalue)
            self.guessed_positions += 1
        return blended


def forwarder_probe(scenario: SignerScenario | None = None) -> DecisionProbe:
    """Return a :class:`~sih141.attacks.isolation.DecisionProbe` for the hop.

    The forwarder-seam counterpart of
    :func:`~sih141.attacks.isolation.signer_probe`, and correct in the same
    way: one honest run is frozen once
    (:func:`~sih141.attacks.isolation.signer_scenario`) and **replayed** into
    every probe call, so the adversary's legitimate observations -- Bob's view
    -- are identical on every session seed. A probe that ran a fresh session
    per seed would hand the forger a different log each time, move his
    declaration for an entirely honest reason, and report an isolated adversary
    as a cheat.

    The declaration handed in is Alice's genuine one for the scenario's bit,
    which is what a forwarder receives.

    Parameters
    ----------
    scenario : SignerScenario or None, optional
        The frozen observations. ``None`` uses
        :func:`~sih141.attacks.isolation.signer_scenario`, so a whole
        parametrised suite shares one distribution.

    Returns
    -------
    DecisionProbe
        ``(attack, session_seed) -> Signature``. The seed is deliberately
        unused: it is a quantity the forwarder can only know if it went and
        took it, which is exactly what check (a) asks.

    Raises
    ------
    TypeError
        If ``scenario`` is neither ``None`` nor a
        :class:`~sih141.attacks.isolation.SignerScenario`.

    Examples
    --------
    >>> from functools import partial
    >>> from sih141.attacks.forgery import RecipientForger, forwarder_probe
    >>> from sih141.attacks.isolation import assert_attack_isolated
    >>> assert_attack_isolated(
    ...     partial(RecipientForger, guess_probability=0.5),
    ...     forwarder_probe(),
    ...     name="RecipientForger",
    ... ).isolated
    True
    """
    resolved = signer_scenario() if scenario is None else scenario
    if not isinstance(resolved, SignerScenario):
        raise TypeError(
            f"scenario must be a SignerScenario or None, got "
            f"{type(resolved).__name__}. Build one with signer_scenario()."
        )
    view = resolved.views[Party.BOB]
    declaration = Signature(
        resolved.message_bit, resolved.keys[resolved.message_bit]
    )

    def probe(attack: Any, session_seed: int) -> Any:
        """Forward once against the frozen view; return what was declared."""
        del session_seed  # An isolated forwarder cannot see it. That is the point.
        return attack(declaration, resolved.params, view=view)

    return probe


# --------------------------------------------------------------------------- #
# The experiments
# --------------------------------------------------------------------------- #


def _check_streams(
    rng: np.random.Generator | None, session_rng: np.random.Generator | None
) -> tuple[np.random.Generator, np.random.Generator]:
    """Resolve the two generators and refuse a shared one (D6).

    The defect this exists to catch is the one
    :mod:`sih141.attacks.isolation` was written about: an experiment that hands
    the adversary the same generator it hands the session lets the adversary
    rebuild every symmetrisation coin, and publishes rates that are fiction
    while looking entirely legitimate.

    Parameters
    ----------
    rng : numpy.random.Generator or None
        The adversary's.
    session_rng : numpy.random.Generator or None
        The harness's.

    Returns
    -------
    tuple of numpy.random.Generator
        ``(attack generator, session generator)``.

    Raises
    ------
    ValueError
        If the two are the same object.
    TypeError
        If either is neither ``None`` nor a generator.
    """
    if rng is not None and rng is session_rng:
        raise ValueError(
            "rng and session_rng must be different generators (D6). An "
            "adversary drawing from the generator the session was given can "
            "rebuild the run and predict every private symmetrisation coin, "
            "so the rate it reports is fiction while the transcript looks "
            "entirely normal. Pass two independently seeded generators."
        )
    return _as_generator(rng, "rng"), _as_generator(session_rng, "session_rng")


def _as_trials(trials: Any) -> int:
    """Coerce and range-check a trial count."""
    count = _as_count(trials, "trials")
    if count <= 0:
        raise ValueError(
            f"trials must be positive, got {count}. A block of no runs "
            f"produces no rate and no interval; ask for at least one."
        )
    return count


def measure_outside_forgery(
    params: ProtocolParams,
    *,
    trials: int,
    rng: np.random.Generator | None = None,
    session_rng: np.random.Generator | None = None,
) -> dict[Party, ForgeryMeasurement]:
    """Run :class:`OutsideForger` on the signer seam and report both verifiers.

    Each run substitutes Alice's declaration with a freshly drawn key, which
    then reaches both verifiers, so one block of trials measures Eve against
    Bob's ``s_a`` *and* Charlie's ``s_v``. The runs are otherwise entirely
    honest: the exchange happens, Phase C' happens, and both verifiers score
    the same declaration, so a no-verdict outcome here means a matched-count
    floor refused the evidence base and nothing else.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set. Choose it for statistics, not for security: below
        ``L = 140`` both matched-count floors degenerate, and a result there
        exhibits a *rate* and never a security claim
        (:ref:`forgery-scaling`).
    trials : int
        Keyword-only. Number of runs. Positive.
    rng : numpy.random.Generator or None, optional
        Keyword-only. **The adversary's** generator (D6). One forger is built
        per run from it, so the block is reproducible from this seed alone
        given ``session_rng``.
    session_rng : numpy.random.Generator or None, optional
        Keyword-only. The harness's generator, from which each
        :class:`~sih141.protocol.session.QDSSession` draws its own material.
        Must not be the same object as ``rng``.

    Returns
    -------
    dict of Party to ForgeryMeasurement
        One block per verifier, keyed by
        :data:`~sih141.protocol.params.VERIFIERS`, each carrying the exact
        prediction from
        :func:`~sih141.protocol.analysis.forgery_probability` for that party's
        threshold.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, ``trials`` is not an
        integer, or a generator argument is of the wrong type.
    ValueError
        If ``trials`` is not positive, or ``rng`` and ``session_rng`` are the
        same object (D6).

    Notes
    -----
    Costs two full distributions per trial -- the session distributes both
    message bits whatever is signed -- so it is linear in ``trials * L`` and
    about ``3 ms`` per key position on a laptop.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.forgery import measure_outside_forgery
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> blocks = measure_outside_forgery(
    ...     ProtocolParams(key_length=24),
    ...     trials=40,
    ...     rng=np.random.default_rng(21),
    ...     session_rng=np.random.default_rng(22),
    ... )
    >>> sorted(blocks) == list(VERIFIERS)
    True

    Eve is a fair coin on every position she is scored on, which is the whole
    content of her ``1/2``. Forty runs at ``L = 24`` is a few hundred scored
    positions, so the tolerance here is wide on purpose -- a tight one would be
    a claim about this seed rather than about the adversary, and the tight
    version, over enough positions to deserve it, is in
    ``tests/test_attack_forgery.py``:

    >>> blocks[Party.BOB].mismatch_rate_within(0.5, 0.1)
    True
    >>> blocks[Party.CHARLIE].scored_fraction_within(1 / 3, 0.05)
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    count = _as_trials(trials)
    attack_rng, harness_rng = _check_streams(rng, session_rng)

    scored = params.sifted() if params.has_check_rounds else params
    accepted = {party: 0 for party in VERIFIERS}
    no_verdict = {party: 0 for party in VERIFIERS}
    positions = {party: 0 for party in VERIFIERS}
    mismatches = {party: 0 for party in VERIFIERS}

    for _ in range(count):
        session = QDSSession(
            params,
            signer=OutsideForger(rng=attack_rng),
            rng=harness_rng,
        )
        transcript = session.run(0)
        for party in VERIFIERS:
            result = transcript.results_by_party.get(party)
            if result is None:
                no_verdict[party] += 1
                continue
            accepted[party] += int(result.accepted)
            positions[party] += result.matched_count
            mismatches[party] += result.mismatches

    return {
        party: ForgeryMeasurement(
            label="outside forger",
            party=party,
            key_length=scored.key_length,
            trials=count,
            accepted=accepted[party],
            no_verdict=no_verdict[party],
            scored_positions=positions[party],
            mismatches=mismatches[party],
            predicted=forgery_probability(scored, party=party),
            predicted_mismatch_rate=OUTSIDE_FORGER_MISMATCH_RATE,
        )
        for party in VERIFIERS
    }


def measure_recipient_forgery(
    params: ProtocolParams,
    *,
    trials: int,
    rng: np.random.Generator | None = None,
    session_rng: np.random.Generator | None = None,
    symmetrised: bool = True,
    pooled_counts: bool = False,
    guess_probability: float = 0.0,
) -> ForgeryMeasurement:
    """Run :class:`RecipientForger` on the forwarding hop and report Charlie.

    Bob receives Alice's real declaration and verifies it -- :attr:`bob_accepted
    <ForgeryMeasurement.bob_accepted>` counts how often he accepted, which is
    the check that the run really is a forgery experiment and not a repudiation
    one -- and then forwards a declaration built from his own raw log. Charlie
    scores that.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set; see :ref:`forgery-scaling` on choosing it.
    trials : int
        Keyword-only. Number of runs. Positive.
    rng : numpy.random.Generator or None, optional
        Keyword-only. **The adversary's** generator (D6).
    session_rng : numpy.random.Generator or None, optional
        Keyword-only. The harness's. Must not be the same object as ``rng``.
    symmetrised : bool, optional
        Keyword-only, default ``True``. ``False`` wires
        :func:`~sih141.protocol.symmetrise.no_symmetrisation` and runs the
        variant with Phase A' removed, where the same forger sits at ``1/3``
        instead of ``1/12`` -- the comparison this module exists to make.
    pooled_counts : bool, optional
        Keyword-only, default ``False``. ``False`` wires
        :func:`~sih141.protocol.tally.no_count_exchange`, the pre-pooled arm in
        which Charlie scores the forgery on his own floor and a *rate* is
        measurable. ``True`` runs the shipped pooled rule, under which Charlie
        reaches no verdict on every substituted declaration -- a denial of
        transfer and **not** a detection (:ref:`pooled-arm`). Every run then
        lands in :attr:`~ForgeryMeasurement.no_verdict`, which is the honest
        way to report it, and the block carries **no** prediction: the
        acceptance probability describes a Charlie who scores, and this one
        never does.
    guess_probability : float, optional
        Keyword-only, passed to :class:`RecipientForger`. Leave at ``0.0`` to
        measure the optimal forger.

    Returns
    -------
    ForgeryMeasurement
        Charlie's block, carrying the exact prediction from
        :func:`~sih141.protocol.analysis.recipient_forgery_probability` for the
        arm that was run -- ``None`` when ``guess_probability`` is positive,
        because no closed form covers a deliberately degraded forger.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, if ``trials`` is not
        an integer, if a generator is of the wrong type, or if ``symmetrised``
        or ``pooled_counts`` is not a bool.
    ValueError
        If ``trials`` is not positive, or ``rng`` and ``session_rng`` are the
        same object (D6).

    See Also
    --------
    measure_outside_forgery : The weaker adversary, for the gap.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.forgery import measure_recipient_forgery
    >>> from sih141.protocol.params import ProtocolParams
    >>> block = measure_recipient_forgery(
    ...     ProtocolParams(key_length=48),
    ...     trials=20,
    ...     rng=np.random.default_rng(31),
    ...     session_rng=np.random.default_rng(32),
    ... )
    >>> block.bob_accepted == block.trials
    True
    >>> block.mismatch_rate_within(1 / 12, 0.035)
    True

    Under the shipped pooled rule the same forgery is refused rather than
    scored, and the block says so without calling it a detection:

    >>> pooled = measure_recipient_forgery(
    ...     ProtocolParams(key_length=24),
    ...     trials=4,
    ...     rng=np.random.default_rng(33),
    ...     session_rng=np.random.default_rng(34),
    ...     pooled_counts=True,
    ... )
    >>> pooled.no_verdict == pooled.trials, pooled.accepted
    (True, 0)
    >>> pooled.predicted is None
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    for name, flag in (
        ("symmetrised", symmetrised),
        ("pooled_counts", pooled_counts),
    ):
        if not isinstance(flag, bool):
            raise TypeError(
                f"{name} must be a bool, got {type(flag).__name__}. It selects "
                f"which protocol variant is run, not a rate."
            )
    count = _as_trials(trials)
    attack_rng, harness_rng = _check_streams(rng, session_rng)

    scored = params.sifted() if params.has_check_rounds else params
    accepted = 0
    no_verdict = 0
    positions = 0
    mismatches = 0
    bob_accepted = 0

    for _ in range(count):
        session = QDSSession(
            params,
            forwarder=RecipientForger(
                rng=attack_rng, guess_probability=guess_probability
            ),
            symmetriser=None if symmetrised else no_symmetrisation,
            count_exchange=None if pooled_counts else no_count_exchange,
            rng=harness_rng,
        )
        # run() records a starved matched set as an abort rather than raising
        # it, so there is nothing to catch here: a refusal to score arrives as
        # `charlie is None` and is counted in `no_verdict`.
        transcript = session.run(0)
        bob = transcript.bob
        bob_accepted += int(bob is not None and bob.accepted)
        charlie = transcript.charlie
        if charlie is None:
            no_verdict += 1
            continue
        accepted += int(charlie.accepted)
        positions += charlie.matched_count
        mismatches += charlie.mismatches

    # No prediction is attached to a block nothing predicts. A degraded forger
    # has no closed form, and under the pooled rule Charlie never scores at
    # all, so quoting the pre-pooled acceptance probability beside a column of
    # refusals would print DISAGREES at a comparison that was never made.
    predictable = guess_probability <= 0.0 and not pooled_counts
    predicted = (
        recipient_forgery_probability(
            scored, party=Party.CHARLIE, symmetrised=symmetrised
        )
        if predictable
        else None
    )
    predicted_mismatch = (
        (
            RECIPIENT_FORGER_MISMATCH_RATE
            if symmetrised
            else UNSYMMETRISED_FORGER_MISMATCH_RATE
        )
        if predictable
        else None
    )
    return ForgeryMeasurement(
        label="recipient forger",
        party=Party.CHARLIE,
        key_length=scored.key_length,
        trials=count,
        accepted=accepted,
        no_verdict=no_verdict,
        scored_positions=positions,
        mismatches=mismatches,
        predicted=predicted,
        predicted_mismatch_rate=predicted_mismatch,
        symmetrised=symmetrised,
        bob_accepted=bob_accepted,
    )
