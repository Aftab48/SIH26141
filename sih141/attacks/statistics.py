"""One binomial-interval implementation for the whole attack suite.

Phase 3 shipped with **four** private copies of the Wilson score interval --
one each in :mod:`sih141.attacks.forgery`, :mod:`sih141.attacks.impersonation`,
:mod:`sih141.attacks.replay` and :mod:`sih141.attacks.starvation` -- written
independently by five agents who each needed the same closed form on the same
afternoon. Two of them carried the same float-dust bug and two had already been
patched for it separately. That is the shape of a missing module, so here it is:
the arithmetic lives once, and the four public functions keep their own
signatures and delegate.

.. _float-dust:

The dust, since it is the reason this file exists rather than a footnote
------------------------------------------------------------------------
At ``successes == 0`` the Wilson lower bound is *exactly* zero::

    centre = z^2 / (2(n + z^2))
    spread = z * sqrt(0 + z^2/4) / (n + z^2)  =  z^2 / (2(n + z^2))

Those two expressions are equal in exact arithmetic and differ by about
``1e-18`` in IEEE 754, so ``max(0.0, centre - spread)`` returns ``1.7e-18``
rather than ``0.0``. Every defended result in this suite is ``0`` successes out
of ``N`` -- ``0/400`` refused replays, ``0/200`` accepted partial
impersonations, ``0/8000`` errors on a clean link -- so the dust lands on
precisely the numbers a reader most needs to be able to read plainly, and
``low == 0.0`` is ``False`` in a test that ought to pass. Both endpoints are
therefore clamped **by case**, not by ``max``/``min`` alone.

.. _tolerance-from-se:

Tolerances are computed, never guessed
--------------------------------------
:func:`agrees_within` exists because "the measured rate is close to the
prediction" is not a testable claim until *close* is derived from the sampling
distribution of the estimator. A tolerance chosen by eye either passes a broken
attack (too loose) or fails a correct one on an ordinary draw (too tight), and
both failure modes are silent. The tolerance here is
``sigmas * sqrt(p(1-p)/n)`` at the **predicted** ``p`` -- predicted rather than
measured, because the null hypothesis under test is that the analysis is right,
and an estimator's own value has no business setting the width of its own
acceptance band.

Examples
--------
>>> from sih141.attacks.statistics import agrees_within, wilson_bounds
>>> low, high = wilson_bounds(0, 400)
>>> low, round(high, 5)
(0.0, 0.00951)

A measured 8 in 2000 against a predicted 0.0042075 agrees at four sigma:

>>> verdict = agrees_within(8, 2000, 0.0042075)
>>> verdict.agrees, round(verdict.z_score, 3)
(True, -0.143)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

__all__ = [
    "Z_90",
    "Z_95",
    "Z_99",
    "AgreementVerdict",
    "agrees_within",
    "binomial_standard_error",
    "sigma_tolerance",
    "two_sided_z",
    "wilson_bounds",
]


Z_90: Final[float] = 1.6448536269514722
"""Two-sided 90% normal quantile, ``Phi^-1(0.95)``."""

Z_95: Final[float] = 1.959963984540054
"""Two-sided 95% normal quantile, ``Phi^-1(0.975)`` -- the suite's default."""

Z_99: Final[float] = 2.5758293035489004
"""Two-sided 99% normal quantile, ``Phi^-1(0.995)``.

Used by :mod:`sih141.attacks.channel`, whose standalone check-round campaigns
make a dozen comparisons in one run and would otherwise expect a miss every
twenty.
"""

_DEFAULT_SIGMAS: Final[float] = 4.0
"""Default width of :func:`agrees_within`, in standard errors.

Four rather than two, and the reason is the number of comparisons rather than
timidity: :mod:`tests.test_phase3_integration` makes on the order of twenty
prediction-versus-measurement calls per suite run, so a two-sigma band would be
expected to fail roughly once per run on correct code and the suite would teach
its readers to re-run until green. Four sigma is a per-comparison false-alarm
rate of ``6.3e-05``, and it is still tight enough to catch every defect the five
attack modules were capable of producing: the failure modes are a rate that is
wrong by a factor (``1/2`` against ``1/12``, ``2/3`` against ``1/3``), never one
that is wrong by three standard errors.
"""


def two_sided_z(confidence: float) -> float:
    """Return the two-sided normal quantile for a confidence level.

    ``Phi^-1(1 - (1 - confidence)/2)``, by bisection on :func:`math.erf`, so
    that no SciPy dependency is introduced for one quantile.

    Parameters
    ----------
    confidence : float
        Strictly inside ``(0, 1)``.

    Returns
    -------
    float
        The positive quantile.

    Raises
    ------
    TypeError
        If ``confidence`` is not a real number.
    ValueError
        If ``confidence`` is not strictly inside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.attacks.statistics import two_sided_z
    >>> round(two_sided_z(0.95), 6)
    1.959964
    >>> round(two_sided_z(0.99), 6)
    2.575829
    """
    if isinstance(confidence, bool) or not isinstance(
        confidence, (int, float, np.floating)
    ):
        raise TypeError(
            f"confidence must be a real number, got "
            f"{type(confidence).__name__}"
        )
    level = float(confidence)
    if not 0.0 < level < 1.0:
        raise ValueError(
            f"confidence must lie strictly inside (0, 1), got {level}. It is a "
            f"coverage probability, not a percentage: pass 0.95, not 95."
        )
    target = 1.0 - (1.0 - level) / 2.0
    low, high = 0.0, 40.0
    for _ in range(200):
        middle = (low + high) / 2.0
        if 0.5 * (1.0 + math.erf(middle / math.sqrt(2.0))) < target:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def _as_count(value: Any, name: str) -> int:
    """Coerce a non-negative integer count, refusing bools and floats."""
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise TypeError(
            f"{name} must be an int, got {type(value).__name__}. Counts of "
            f"trials are integers; a float here is usually a rate that has "
            f"already been divided once."
        )
    count = int(value)
    if count < 0:
        raise ValueError(f"{name} must be non-negative, got {count}")
    return count


def _as_quantile(value: Any, name: str) -> float:
    """Coerce a positive finite normal quantile."""
    if isinstance(value, bool) or not isinstance(
        value, (int, float, np.floating, np.integer)
    ):
        raise TypeError(f"{name} must be a real number, got "
                        f"{type(value).__name__}")
    quantile = float(value)
    if not math.isfinite(quantile) or quantile <= 0.0:
        raise ValueError(
            f"{name} must be positive and finite, got {quantile}. It is a "
            f"normal quantile; Z_95 is the suite default."
        )
    return quantile


def wilson_bounds(
    successes: int, trials: int, *, z: float = Z_95
) -> tuple[float, float]:
    """Return the Wilson score interval for a binomial proportion.

    The one implementation. :func:`sih141.attacks.forgery.wilson_interval`,
    :func:`sih141.attacks.impersonation.wilson_interval`,
    :func:`sih141.attacks.replay.wilson_interval` and
    :func:`sih141.attacks.starvation.wilson_interval` all delegate here, keeping
    their own argument spellings.

    Wilson rather than the normal approximation because nearly every rate this
    suite measures sits at or beside an endpoint, where the Wald interval
    collapses to the single point it was measured at and claims certainty from a
    finite experiment.

    Parameters
    ----------
    successes : int
        ``0 <= successes <= trials``.
    trials : int
        At least ``1``.
    z : float, optional
        Keyword-only normal quantile; defaults to :data:`Z_95`.

    Returns
    -------
    tuple of float
        ``(low, high)``, exactly ``0.0`` at zero successes and exactly ``1.0``
        at ``successes == trials`` (:ref:`float-dust`), otherwise clipped into
        ``[0, 1]``.

    Raises
    ------
    TypeError
        If a count is not an integer, or ``z`` is not a real number.
    ValueError
        If ``trials < 1``, ``successes`` is outside ``[0, trials]``, or ``z`` is
        not positive and finite.

    Examples
    --------
    >>> from sih141.attacks.statistics import wilson_bounds
    >>> low, high = wilson_bounds(0, 100)
    >>> low, round(high, 4)
    (0.0, 0.037)
    >>> low, high = wilson_bounds(100, 100)
    >>> round(low, 4), high
    (0.963, 1.0)
    >>> low, high = wilson_bounds(50, 100)
    >>> round(low, 4), round(high, 4)
    (0.4038, 0.5962)

    The endpoints are exact, not merely small -- which is the whole point:

    >>> wilson_bounds(0, 8000)[0] == 0.0
    True
    >>> wilson_bounds(400, 400)[1] == 1.0
    True
    """
    total = _as_count(trials, "trials")
    hits = _as_count(successes, "successes")
    if total < 1:
        raise ValueError(
            f"trials must be at least 1, got {total}. A rate measured over no "
            f"trials is not a wide interval, it is the absence of a "
            f"measurement; report the trial count instead."
        )
    if hits > total:
        raise ValueError(
            f"successes ({hits}) exceeds trials ({total}); a proportion above "
            f"one is a counting error upstream, not a rate."
        )
    quantile = _as_quantile(z, "z")

    n = float(total)
    rate = hits / n
    z2 = quantile * quantile
    denominator = 1.0 + z2 / n
    centre = (rate + z2 / (2.0 * n)) / denominator
    spread = (
        quantile
        * math.sqrt(rate * (1.0 - rate) / n + z2 / (4.0 * n * n))
        / denominator
    )
    # Clamped by case rather than by max/min: see :ref:`float-dust`. The two
    # extremes are exact in the closed form and inexact in floating point, and
    # they are exactly the results this suite reports most often.
    low = 0.0 if hits == 0 else max(0.0, centre - spread)
    high = 1.0 if hits == total else min(1.0, centre + spread)
    return (low, high)


def binomial_standard_error(probability: float, trials: int) -> float:
    """Return ``sqrt(p(1-p)/n)``, the standard error of a measured proportion.

    Parameters
    ----------
    probability : float
        The proportion the error is computed *at*. In an agreement test this is
        the analytic prediction, never the measurement -- see
        :ref:`tolerance-from-se`.
    trials : int
        At least ``1``.

    Returns
    -------
    float
        The standard error. Zero when ``probability`` is ``0`` or ``1``, which
        is correct and is why :func:`sigma_tolerance` adds a floor.

    Raises
    ------
    TypeError
        If ``probability`` is not a real number or ``trials`` is not an int.
    ValueError
        If ``probability`` is outside ``[0, 1]`` or ``trials < 1``.

    Examples
    --------
    >>> from sih141.attacks.statistics import binomial_standard_error
    >>> round(binomial_standard_error(0.5, 8000), 6)
    0.00559
    >>> round(binomial_standard_error(1 / 12, 32054), 6)
    0.001544
    """
    if isinstance(probability, bool) or not isinstance(
        probability, (int, float, np.floating)
    ):
        raise TypeError(
            f"probability must be a real number, got "
            f"{type(probability).__name__}"
        )
    p = float(probability)
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"probability must lie in [0, 1], got {p}")
    total = _as_count(trials, "trials")
    if total < 1:
        raise ValueError(f"trials must be at least 1, got {total}")
    return math.sqrt(p * (1.0 - p) / total)


def sigma_tolerance(
    probability: float, trials: int, *, sigmas: float = _DEFAULT_SIGMAS
) -> float:
    """Return the half-width of an agreement band, in units of the rate.

    ``sigmas * binomial_standard_error(probability, trials)``, with a floor of
    ``sigmas / trials`` so that a prediction of exactly ``0`` or exactly ``1``
    still admits a band. Without the floor the standard error vanishes there and
    the test would demand a bit-exact match from a random experiment -- which is
    right for a *rule* (``0/400`` refusals) and wrong for a *rate*, and the
    caller cannot always tell the two apart.

    Parameters
    ----------
    probability : float
        The analytic prediction, in ``[0, 1]``.
    trials : int
        At least ``1``.
    sigmas : float, optional
        Keyword-only band half-width in standard errors; defaults to ``4.0``.
        Positive and finite.

    Returns
    -------
    float
        The tolerance to compare ``abs(measured - predicted)`` against.

    Raises
    ------
    TypeError, ValueError
        As :func:`binomial_standard_error`, plus ``sigmas`` positive and finite.

    Examples
    --------
    >>> from sih141.attacks.statistics import sigma_tolerance
    >>> round(sigma_tolerance(0.5, 800), 5)
    0.07071
    >>> round(sigma_tolerance(1.0, 200), 5)
    0.02

    Halving the sample widens the band by ``sqrt(2)``, which is the property a
    guessed tolerance does not have:

    >>> round(sigma_tolerance(0.25, 2000) / sigma_tolerance(0.25, 4000), 6)
    1.414214
    """
    error = binomial_standard_error(probability, trials)
    span = _as_quantile(sigmas, "sigmas")
    total = int(trials)
    return max(span * error, span / total)


@dataclass(frozen=True)
class AgreementVerdict:
    """Whether one measured rate agrees with one analytic prediction.

    Frozen, and it keeps the inputs rather than reducing to a bool, because
    "disagrees" is only actionable alongside the number of standard errors and
    the band that was applied.

    Parameters
    ----------
    successes : int
        Observed successes.
    trials : int
        Trials.
    predicted : float
        The analytic prediction the measurement is tested against.
    sigmas : float
        The band half-width in standard errors that was applied.

    Attributes
    ----------
    successes : int
    trials : int
    predicted : float
    sigmas : float

    Examples
    --------
    >>> from sih141.attacks.statistics import AgreementVerdict
    >>> verdict = AgreementVerdict(279, 800, 0.345566, 4.0)
    >>> verdict.agrees
    True
    >>> round(verdict.measured, 5), round(verdict.z_score, 3)
    (0.34875, 0.189)
    """

    successes: int
    trials: int
    predicted: float
    sigmas: float

    @property
    def measured(self) -> float:
        """float: ``successes / trials``."""
        return self.successes / self.trials

    @property
    def tolerance(self) -> float:
        """float: The band half-width, from :func:`sigma_tolerance`."""
        return sigma_tolerance(
            self.predicted, self.trials, sigmas=self.sigmas
        )

    @property
    def standard_error(self) -> float:
        """float: ``sqrt(p(1-p)/n)`` at the *predicted* ``p``."""
        return binomial_standard_error(self.predicted, self.trials)

    @property
    def z_score(self) -> float:
        """float: Standard errors between measurement and prediction.

        ``0.0`` when the standard error is zero and the measurement lands on the
        prediction exactly, and ``inf`` when it does not -- a prediction of
        exactly ``0`` that was observed to happen is infinitely surprising under
        its own law, and saying so is more useful than dividing by zero.
        """
        error = self.standard_error
        gap = self.measured - self.predicted
        if error == 0.0:
            return 0.0 if gap == 0.0 else math.copysign(math.inf, gap)
        return gap / error

    @property
    def agrees(self) -> bool:
        """bool: Whether the gap is inside :attr:`tolerance`."""
        return abs(self.measured - self.predicted) <= self.tolerance

    @property
    def interval(self) -> tuple[float, float]:
        """tuple of float: The measurement's own Wilson 95% interval."""
        return wilson_bounds(self.successes, self.trials)

    def summary(self) -> str:
        """Return a one-line verdict naming every number behind it.

        Returns
        -------
        str
            Measured rate with its count, the prediction, the gap in standard
            errors, and the band applied.

        Examples
        --------
        >>> from sih141.attacks.statistics import AgreementVerdict
        >>> print(AgreementVerdict(8, 2000, 0.0042075, 4.0).summary())
        AGREES: 8/2000 = 0.004000 vs predicted 0.004208 (z = -0.14, band 4.0 se = 0.005790)
        """
        verdict = "AGREES" if self.agrees else "DISAGREES"
        return (
            f"{verdict}: {self.successes}/{self.trials} = "
            f"{self.measured:.6f} vs predicted {self.predicted:.6f} "
            f"(z = {self.z_score:.2f}, band {self.sigmas} se = "
            f"{self.tolerance:.6f})"
        )


def agrees_within(
    successes: int,
    trials: int,
    predicted: float,
    *,
    sigmas: float = _DEFAULT_SIGMAS,
) -> AgreementVerdict:
    """Test a measured rate against an analytic prediction at a computed band.

    The function :mod:`tests.test_phase3_integration` uses for every
    prediction-versus-measurement assertion, so that no tolerance in Phase 3 is
    a number somebody liked the look of.

    Parameters
    ----------
    successes : int
        Observed successes, ``0 <= successes <= trials``.
    trials : int
        At least ``1``.
    predicted : float
        The analytic prediction, in ``[0, 1]``.
    sigmas : float, optional
        Keyword-only band half-width in standard errors; defaults to ``4.0``
        for the reason given on ``_DEFAULT_SIGMAS``.

    Returns
    -------
    AgreementVerdict
        The verdict with its evidence kept.

    Raises
    ------
    TypeError, ValueError
        As :func:`wilson_bounds` and :func:`sigma_tolerance`.

    Examples
    --------
    >>> from sih141.attacks.statistics import agrees_within

    The measured outside-forgery rate against its exact prediction:

    >>> print(agrees_within(8, 2000, 0.0042075).summary())
    AGREES: 8/2000 = 0.004000 vs predicted 0.004208 (z = -0.14, band 4.0 se = 0.005790)

    And a rate that is wrong by a factor -- the failure mode this suite can
    actually produce -- is caught with room to spare:

    >>> wrong = agrees_within(2641, 32054, 1 / 3)
    >>> wrong.agrees, round(wrong.z_score, 1)
    (False, -95.3)
    """
    total = _as_count(trials, "trials")
    hits = _as_count(successes, "successes")
    if total < 1:
        raise ValueError(f"trials must be at least 1, got {total}")
    if hits > total:
        raise ValueError(
            f"successes ({hits}) exceeds trials ({total})"
        )
    if isinstance(predicted, bool) or not isinstance(
        predicted, (int, float, np.floating)
    ):
        raise TypeError(
            f"predicted must be a real number, got {type(predicted).__name__}"
        )
    probability = float(predicted)
    if not 0.0 <= probability <= 1.0:
        raise ValueError(
            f"predicted must lie in [0, 1], got {probability}. It is a "
            f"probability from sih141.protocol.analysis, not a count."
        )
    return AgreementVerdict(
        successes=hits,
        trials=total,
        predicted=probability,
        sigmas=_as_quantile(sigmas, "sigmas"),
    )
