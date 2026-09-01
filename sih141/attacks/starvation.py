"""Count starvation: a verifier denies every verdict with one integer.

The fifth attack surface, and the only one in Phase 3 that is not named in the
problem statement. It was found by the Phase 2 audit of
:mod:`sih141.protocol.tally` and nothing had measured it: the counterpart
matched count that crosses the wire in Phase C' is an **unauthenticated
integer**, chosen by a party the threat model already treats as an adversary,
and every check downstream of it -- the pooled floor and the counterpart floor
-- is applied to whatever he said.

.. code-block:: text

    Charlie says  m_C = 0
    Bob computes  |M_B| + 0 < M_min      ->  POOLED_BELOW_FLOOR, no verdict
    Charlie scores his own log honestly  ->  accepts

The run is not rejected. It reaches **no verdict**, which is recorded in
:attr:`~sih141.protocol.session.SessionTranscript.aborts` and is deliberately
not a rejection (:class:`~sih141.protocol.verify.VerificationAbort`). So in the
transcript a denial of service on verification looks exactly like a run whose
evidence was genuinely thin -- which is the finding this module exists to turn
into numbers.

What this adversary is, and is not
----------------------------------
It is **one recipient**, wired in as the ``count_exchange`` seam of
:class:`~sih141.protocol.session.QDSSession`. It reports a count for itself and
passes its counterpart's through untouched -- :meth:`CountStarver.__call__`
refuses to do anything else, because a seam that could edit both counts is a
stronger adversary than any recipient is, and a rate measured for it would be a
rate for nobody. The declaration, the floors and the digest are likewise left
alone: they are checked elsewhere (:func:`_check_pooled_against` in
:mod:`sih141.protocol.session` re-derives both floors, and a doctored digest is
refused as :attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`),
so a starver that reached for them would be measuring a check that already
holds.

It is **not** a forgery and cannot become one. Every acceptance still requires
the accepting verifier's own rate on his own log to clear his own threshold, and
no message from the counterpart touches that. Under-reporting can only ever
*withhold* an acceptance. :mod:`sih141.protocol.tally` says so in prose; this
module says so as an experiment (:func:`measure_starvation` never records an
acceptance the honest arm did not also record).

.. _starvation-headroom:

How cheap the denial is, exactly
--------------------------------
A verifier ``R`` reaching a verdict needs all of

.. code-block:: text

    |M_R| >= m_min           his own, from his own log
    |M_R| + c >= M_min       the pooled floor,       c = what the other said
    c      >= m_min          the counterpart floor

so the counterpart denies him by declaring any ``c`` with ``c < m_min`` or
``c < M_min - |M_R|``. The largest such ``c`` -- the *headroom*,
:func:`denial_headroom` -- is

.. code-block:: text

    h = max(m_min - 1,  M_min - |M_B| - 1)

and any declaration at or below it denies the run with probability ``1``. There
is no probability to measure in the denial itself: it is deterministic, costs
one integer, needs no key material, no quantum resource and no computation.
What is worth measuring is the *price in plausibility*, and that is where the
attack turns out to be expensive.

.. _starvation-z:

Why it cannot look statistically normal
---------------------------------------
An honest count is ``Binomial(L, 1/|B|)``: mean ``mu = L/3``, standard
deviation ``sqrt(2L/9)``. Both floors are the same Chernoff tail at the same
budget ``eps =`` :data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET`, so the
first branch of the headroom sits a *fixed* number of standard deviations below
the mean, independent of ``L``:

.. code-block:: text

    mu - m_min = sqrt(2 mu ln(1/eps))
    sd         = sqrt(2 mu / 3)
    z          = -(mu - m_min) / sd  ->  -sqrt(3 ln(1/eps))  =  -11.5362

:func:`least_implausible_z` computes it, and it converges from below:

>>> from sih141.attacks.starvation import least_implausible_z
>>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
>>> f"{least_implausible_z(ProtocolParams(key_length=600)):.4f}"
'-11.6047'
>>> f"{least_implausible_z(DEFAULT_PARAMS):.4f}"
'-11.5375'
>>> import math
>>> f"{-math.sqrt(3 * 64 * math.log(2)):.4f}"          # the L-independent limit
'-11.5362'

So the *least implausible* declaration that still denies is eleven and a half
standard deviations low at every key length, and the probability an honest
verifier would ever report a count that small is
:func:`~sih141.protocol.analysis.matched_shortfall_probability` of it --
the honest lower tail at that count:

>>> from sih141.protocol.analysis import matched_shortfall_probability
>>> from sih141.protocol.verify import minimum_matched_count
>>> for parameters in (ProtocolParams(key_length=600), DEFAULT_PARAMS):
...     floor = minimum_matched_count(parameters)
...     tail = matched_shortfall_probability(parameters, minimum_matched=floor)
...     print(parameters.key_length, floor, f"{tail:.1e}")
600 67 4.1e-37
115200 36555 2.5e-31

That is the Phase 4 headline:
**a single-run threshold on the declared count catches every successful
starvation, at a false-alarm rate bounded by the honest-abort budget the floors
were already calibrated to.** No history is needed and no ML is needed (D4) --
it is one z-score against a binomial whose parameters are ``L`` and ``|B|``.

The second branch, ``c < M_min - |M_B|``, is the only way to deny while
declaring a count above ``m_min``, and it is not a way out: it requires the
*counterpart's* own count to be below ``M_min - m_min``, which is itself
``(sqrt(2) - 1) sqrt(3 ln(1/eps)) = 4.78`` standard deviations low. The starver
cannot cause that -- it is Bob's own honest draw -- so the branch opens only on
the rare runs :func:`pooled_branch_requirement` prices, and when it does it
still forces a declaration inside a window a few counts wide just above
``m_min``:

>>> from sih141.attacks.starvation import pooled_branch_requirement
>>> threshold, probability = pooled_branch_requirement(DEFAULT_PARAMS)
>>> threshold, f"{probability:.1e}"
(37635, '8.3e-07')

.. _starvation-selectivity:

Selectivity, which is the part that is worse
--------------------------------------------
Denying every signature is a fault; denying *chosen* signatures is censorship,
and it is what a transcript-level detector has the hardest time with. The seam
sees the message bit and the declaration digest before it answers, so the choice
is free: :class:`CountStarver` takes ``target_bits`` and a ``denial_probability``
and starves only where it wants to. Selective denial leaves the untargeted runs
completing normally, so no aggregate over a run's *outcomes* separates a
selective starver from an honest pair on a noisy channel -- the separation has
to come from the declared counts themselves, which is again :ref:`starvation-z`.

.. _starvation-history:

What the transcript retains, and the one thing it does not
----------------------------------------------------------
Per run, :class:`~sih141.protocol.session.SessionTranscript` keeps

* :attr:`~sih141.protocol.session.SessionTranscript.pooled` -- the declared
  ``m_B`` and ``m_C``, so the z-score above is computable directly;
* the aborts, each naming
  :attr:`~sih141.protocol.verify.AbortReason.POOLED_BELOW_FLOOR` or
  :attr:`~sih141.protocol.verify.AbortReason.COUNTERPART_BELOW_FLOOR` and
  carrying ``counterpart_matched``;
* the verdicts, each carrying the scoring verifier's **true**
  :attr:`~sih141.protocol.verify.VerificationResult.matched_count`.

The last of those is the naive starver's undoing and is worth stating on its
own, because it is a within-one-run contradiction rather than a statistic: a
starving Charlie still scores his own log, so a transcript can hold
``pooled.charlie_count = 0`` beside ``results[Charlie].matched_count = 208``
(:func:`declared_versus_scored`). He cannot suppress it from inside this seam --
his own verdict is computed from his own record and the *counterpart's* count,
neither of which he is editing.

What the transcript does **not** retain is history. A
:class:`~sih141.protocol.session.SessionTranscript` is one run; nothing in the
package accumulates "this verifier has now reported a starving count fourteen
times". A Phase 4 detector that wants the pattern rather than the instance has
to keep that ledger itself, keyed by party across transcripts. That is a Phase 4
requirement, not a protocol gap -- the per-run signal is already decisive -- but
it should be stated rather than discovered.

Standing rules
--------------
D3/D6
    :class:`CountStarver` takes its own keyword-only
    :class:`numpy.random.Generator` and never sees the session's. Its
    constructor does not accept ``session_seed`` at all, so the guarantee is
    structural; :func:`starvation_probe` is the
    :class:`~sih141.attacks.isolation.DecisionProbe` that demonstrates it.
D4
    Binomial arithmetic and a z-score. No estimator is fitted to anything.
D5
    The numbers in this docstring are doctests above and in
    :func:`least_implausible_z`; the measured rates live in
    :class:`StarvationMeasurement`, not in prose.

See Also
--------
sih141.protocol.tally : Phase C', the message this attack lies in.
sih141.protocol.verify : The four checks that consume the lie.
sih141.attacks.isolation : The D6 check every adversary here must pass.
"""

from __future__ import annotations

import dataclasses
import enum
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from sih141.attacks.statistics import wilson_bounds
from sih141.attacks.isolation import DecisionProbe
from sih141.protocol.analysis import (
    matched_shortfall_probability,
    matched_statistics,
)
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.session import QDSSession, SessionTranscript
from sih141.protocol.tally import (
    MatchedCountMessage,
    PooledMatchedCounts,
    exchange_matched_counts,
)
from sih141.protocol.verify import (
    MatchedSetTooSmall,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

__all__ = [
    "PROBE_PARAMS",
    "CountStarver",
    "StarvationDecision",
    "StarvationMeasurement",
    "StarvationMode",
    "declaration_z_score",
    "declared_versus_scored",
    "denial_headroom",
    "least_implausible_z",
    "measure_starvation",
    "pooled_branch_requirement",
    "probe_messages",
    "starvation_probe",
    "wilson_interval",
]


PROBE_PARAMS: Final[ProtocolParams] = ProtocolParams(key_length=600)
"""Parameters the D6 probe's frozen messages are stated under.

``L = 600`` because both floors are non-degenerate there (``m_min = 67``,
``M_min = 212``), so the probe exercises the branch of :func:`denial_headroom`
that a demo-scale ``L`` would collapse. No session is run for it: the probe's
inputs are two integers and a digest, which is the whole of what this adversary
observes.
"""

_HONEST_PROBE_COUNTS: Final[tuple[int, int]] = (198, 203)
"""``(m_B, m_C)`` the probe freezes: two ordinary draws near ``mu = 200``."""

_PROBE_DIGEST: Final[str] = "a1b2c3d4"
"""A stand-in declaration fingerprint. Its value is irrelevant and its
*constancy* is not: both frozen messages carry it, so the honest exchange the
adversary delegates to accepts the pair."""


class StarvationMode(enum.StrEnum):
    """How far below the headroom a starving declaration goes.

    A :class:`enum.StrEnum`, so a mode passes through :func:`json.dumps` into a
    Phase 5 table as its own name.

    Attributes
    ----------
    ZERO
        Declare ``0``. The audit's original observation, and the loudest thing
        the adversary can do: at ``L = 600`` it is seventeen standard deviations
        below the honest mean. Kept because it is the variant that was measured
        first and because it is the only one available where ``m_min``
        degenerates to ``1`` -- below ``L = 140`` the headroom is ``0`` and a
        starver has no choice.
    LEAST_IMPLAUSIBLE
        Declare the largest count that still denies -- :func:`denial_headroom`,
        less a small draw from the adversary's own generator so that a run of
        them is not the constant ``m_min - 1``. The best a starver can do at
        hiding, and :ref:`starvation-z` is the statement of how little that is.
    """

    ZERO = "zero"
    LEAST_IMPLAUSIBLE = "least-implausible"


@dataclass(frozen=True)
class StarvationDecision:
    """What the starver did on one Phase C' exchange, and what it could see.

    One per call to :meth:`CountStarver.__call__`, accumulated in
    :attr:`CountStarver.log`. This is the adversary's own bookkeeping and is
    **not** part of the transcript: a Phase 4 detector may not read it. It exists
    so that a Phase 5 table can report what the attack chose alongside what the
    protocol did about it, and so that the detector signals of
    :func:`declaration_z_score` can be checked against ground truth.

    Parameters
    ----------
    party : Party
        The starving verifier.
    message_bit : int
        The bit whose declaration was being counted.
    true_count : int
        What this verifier's honest message said, i.e. ``|M_R|``.
    declared_count : int
        What was put on the wire instead. Never above ``true_count``:
        over-reporting is a different attack and this one refuses it.
    counterpart_count : int
        The other verifier's count, passed through untouched.
    headroom : int
        :func:`denial_headroom` for this run -- the largest declaration that
        would still deny.
    starved : bool
        Whether this call chose to deny. ``False`` on a call the selectivity
        rule passed over, in which case ``declared_count == true_count``.

    Attributes
    ----------
    party : Party
    message_bit : int
    true_count : int
    declared_count : int
    counterpart_count : int
    headroom : int
    starved : bool

    Examples
    --------
    >>> from sih141.attacks.starvation import StarvationDecision
    >>> from sih141.protocol.params import Party
    >>> decision = StarvationDecision(
    ...     party=Party.CHARLIE, message_bit=0, true_count=203,
    ...     declared_count=64, counterpart_count=198, headroom=66,
    ...     starved=True,
    ... )
    >>> decision.denies, decision.understatement
    (True, 139)
    """

    party: Party
    message_bit: int
    true_count: int
    declared_count: int
    counterpart_count: int
    headroom: int
    starved: bool

    @property
    def denies(self) -> bool:
        """bool: ``True`` iff the declared count is at or below the headroom.

        The adversary's own prediction of the outcome, made before the verifier
        applies any rule. :func:`measure_starvation` checks it against what the
        session actually did, so a disagreement is a finding about
        :func:`denial_headroom` rather than a silent miscount.
        """
        return self.declared_count <= self.headroom

    @property
    def understatement(self) -> int:
        """int: ``|M_R|`` minus what was declared. ``0`` on an honest call."""
        return self.true_count - self.declared_count


def denial_headroom(counterpart_matched: int, params: ProtocolParams) -> int:
    """Return the largest own-count declaration that still denies the run.

    The whole cost of the attack, as a number: any ``c`` at or below this denies
    the counterpart a verdict with probability ``1``, and any ``c`` above it
    denies nothing. Derived in :ref:`starvation-headroom` from the three checks
    a verifier applies to the pair.

    Parameters
    ----------
    counterpart_matched : int
        ``|M_B|`` -- what the *other* verifier holds, which is what the pooled
        branch is measured against. The seam is handed it before it answers, so
        the starver is a last mover; see the ``Notes``.
    params : ProtocolParams
        The parameter set the run executes under. Supplies both floors.

    Returns
    -------
    int
        In ``[0, key_length]``. Never negative: ``m_min >= 1`` always, so
        declaring ``0`` always denies.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`
        or ``counterpart_matched`` is not an integer.
    ValueError
        If ``counterpart_matched`` is negative or exceeds ``key_length``.

    See Also
    --------
    least_implausible_z : How far below the honest mean this sits.
    pooled_branch_requirement : When the second branch is the larger one.

    Notes
    -----
    The maximum is over two branches. The first, ``m_min - 1``, is always
    available and does not depend on the counterpart at all. The second,
    ``M_min - |M_B| - 1``, exceeds it only when the counterpart is himself
    starved of evidence, which the adversary cannot arrange -- see
    :func:`pooled_branch_requirement`.

    That the seam knows ``|M_B|`` before answering is an artefact of the
    interface, not of the protocol: Phase C' is described as an exchange, and a
    real one may be simultaneous. Reported as seam friction rather than worked
    around, because the artefact only ever *helps* the adversary and a
    conservative measurement should keep it.

    Consumes no randomness (D3) and fits nothing (D4).

    Examples
    --------
    >>> from sih141.attacks.starvation import denial_headroom
    >>> from sih141.protocol.params import DEMO_PARAMS, ProtocolParams
    >>> params = ProtocolParams(key_length=600)          # m_min 67, M_min 212
    >>> denial_headroom(200, params)                     # the ordinary case
    66
    >>> denial_headroom(140, params)                     # Bob starved himself
    71
    >>> denial_headroom(64, DEMO_PARAMS)                 # L = 192: m_min is 1
    0
    """
    checked = _as_params(params)
    counterpart = _as_count(counterpart_matched, "counterpart_matched")
    if counterpart > checked.key_length:
        raise ValueError(
            f"counterpart_matched ({counterpart}) cannot exceed key_length "
            f"({checked.key_length}); a matched set is a subset of the key "
            f"positions."
        )
    own_branch = minimum_matched_count(checked) - 1
    pooled_branch = minimum_pooled_matched_count(checked) - counterpart - 1
    return max(0, min(checked.key_length, max(own_branch, pooled_branch)))


def declaration_z_score(count: int, params: ProtocolParams) -> float:
    """Return how many honest standard deviations a declared count is off.

    The detector signal of :ref:`starvation-z`, and the one a Phase 4 pass
    should key on: it needs nothing but ``L``, the alphabet size and the integer
    the verifier put on the wire, all three of which are in the transcript.

    Parameters
    ----------
    count : int
        The declared matched count.
    params : ProtocolParams
        The parameter set, supplying ``mu = L/|B|`` and ``sqrt(mu(1 - 1/|B|))``
        through :func:`~sih141.protocol.analysis.matched_statistics`.

    Returns
    -------
    float
        ``(count - mu) / sd``. Negative for an under-report.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`
        or ``count`` is not an integer.
    ValueError
        If ``count`` is negative.

    See Also
    --------
    sih141.protocol.analysis.matched_shortfall_probability : The exact tail, for
        when a z-score is not enough.

    Examples
    --------
    >>> from sih141.attacks.starvation import declaration_z_score
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=600)
    >>> f"{declaration_z_score(200, params):.2f}"        # the honest mean
    '0.00'
    >>> f"{declaration_z_score(66, params):.2f}"         # the best a starver can do
    '-11.60'
    >>> f"{declaration_z_score(0, params):.2f}"          # the audit's variant
    '-17.32'
    """
    checked = _as_params(params)
    value = _as_count(count, "count")
    statistics = matched_statistics(checked)
    return (value - statistics.expected) / math.sqrt(statistics.variance)


def least_implausible_z(params: ProtocolParams) -> float:
    """Return the z-score of the quietest declaration that still denies.

    ``declaration_z_score(m_min - 1, params)``: the branch of
    :func:`denial_headroom` that is always available, expressed in the units a
    detector works in. It converges to ``-sqrt(3 ln(1/eps)) = -11.5362`` from
    below as ``L`` grows, which is the reason count starvation does not become
    cheaper at the key lengths the scheme is deployed at.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    float
        Negative, and bounded away from ``0`` uniformly in ``L``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`.

    See Also
    --------
    denial_headroom : The count itself.

    Notes
    -----
    Below ``L = 140`` the per-verifier floor degenerates to ``m_min = 1``, so
    the quietest denying declaration is ``0`` and this returns
    ``-sqrt(mu / (1 - 1/|B|))`` instead -- a *different* and larger quantity
    that happens to be smaller in magnitude at demo scale. It is reported here
    for completeness and carries no security claim: neither floor does below
    that length.

    Examples
    --------
    >>> from sih141.attacks.starvation import least_implausible_z
    >>> from sih141.protocol.params import (
    ...     DEFAULT_PARAMS, DEMO_PARAMS, ProtocolParams
    ... )
    >>> f"{least_implausible_z(ProtocolParams(key_length=600)):.4f}"
    '-11.6047'
    >>> f"{least_implausible_z(ProtocolParams(key_length=1200)):.4f}"
    '-11.5738'
    >>> f"{least_implausible_z(DEFAULT_PARAMS):.4f}"
    '-11.5375'
    >>> f"{least_implausible_z(DEMO_PARAMS):.4f}"     # m_min degenerate, no claim
    '-9.7980'
    """
    checked = _as_params(params)
    return declaration_z_score(
        max(0, minimum_matched_count(checked) - 1), checked
    )


def pooled_branch_requirement(params: ProtocolParams) -> tuple[int, float]:
    """Return what the counterpart's own count must be for the second branch.

    The pooled branch of :func:`denial_headroom` is the only route to a denying
    declaration at or **above** ``m_min``, so it is the only route that could
    plausibly hide. It opens exactly when the counterpart's honest count falls
    below ``M_min - m_min``, which the starver does not control.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    threshold : int
        ``M_min - m_min``. The pooled branch exceeds the own branch iff the
        counterpart's count is strictly below this.
    probability : float
        How often an honest counterpart lands there, from
        :func:`~sih141.protocol.analysis.matched_shortfall_probability`. This is
        an upper bound on the fraction of runs where a starver may declare a
        count above ``m_min`` and still deny.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`.

    Notes
    -----
    The threshold is ``mu - (sqrt(2) - 1) sqrt(2 mu ln(1/eps))``, i.e.
    ``(sqrt(2) - 1) sqrt(3 ln(1/eps)) = 4.78`` standard deviations low -- again
    independent of ``L``. Even inside that branch the window of usable
    declarations is ``[m_min, M_min - |M_B|)``, which is empty unless the
    counterpart is below the threshold and only a few counts wide when he is
    just below it.

    Examples
    --------
    >>> from sih141.attacks.starvation import pooled_branch_requirement
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> threshold, probability = pooled_branch_requirement(
    ...     ProtocolParams(key_length=600)
    ... )
    >>> threshold, f"{probability:.1e}"
    (145, '4.0e-07')
    >>> threshold, probability = pooled_branch_requirement(DEFAULT_PARAMS)
    >>> threshold, f"{probability:.1e}"
    (37635, '8.3e-07')
    """
    checked = _as_params(params)
    threshold = minimum_pooled_matched_count(checked) - minimum_matched_count(
        checked
    )
    if threshold < 1:
        return threshold, 0.0
    return threshold, matched_shortfall_probability(
        checked, minimum_matched=threshold
    )


class CountStarver:
    """A verifier who under-reports his Phase C' count to deny the verdict.

    Wired in as :class:`~sih141.protocol.session.QDSSession`'s ``count_exchange``
    seam. On each exchange it decides whether to starve, replaces **its own**
    :class:`~sih141.protocol.tally.MatchedCountMessage` with a smaller count, and
    hands the pair to the shipped :func:`~sih141.protocol.tally.exchange_matched_counts`
    -- so every validation the honest exchange performs still runs, and the only
    thing that differs between the honest arm and the attack arm is one integer.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, and the adversary's **own** (D6). Used for the selectivity
        coin and for the jitter on a starving declaration. The constructor does
        not accept the session's seed in any form, so
        :func:`~sih141.attacks.isolation.check_attack_isolation`'s first half is
        structural for this candidate rather than merely observed.
    party : Party or str, optional
        Keyword-only. Which verifier is dishonest. Defaults to
        :attr:`~sih141.protocol.params.Party.CHARLIE`, the transferee, because
        starving him denies Bob -- the party Alice signed to -- while the starver
        still reaches his own verdict. Alice is refused: she is not in Phase C'.
    mode : StarvationMode or str, optional
        Keyword-only. Defaults to
        :attr:`~StarvationMode.LEAST_IMPLAUSIBLE`, the strongest variant.
    denial_probability : float, optional
        Keyword-only, in ``[0, 1]``. The per-exchange coin, drawn from ``rng``.
        ``1.0`` (the default) denies every targeted run; anything less is the
        selective attack of :ref:`starvation-selectivity`.
    target_bits : iterable of int or None, optional
        Keyword-only. Message bits eligible for denial. ``None`` (the default)
        means both. ``(1,)`` is a censor who lets every ``0`` through, which no
        outcome-level statistic distinguishes from an honest pair.
    jitter : int, optional
        Keyword-only, non-negative. In :attr:`~StarvationMode.LEAST_IMPLAUSIBLE`
        the declaration is the headroom less ``rng.integers(0, jitter + 1)``, so
        a sequence of them is not the constant ``m_min - 1``. Defaults to ``8``.
        It only ever lowers the count, so it cannot turn a denial into a verdict.

    Attributes
    ----------
    party : Party
    mode : StarvationMode
    denial_probability : float
    target_bits : frozenset of int
    jitter : int
    log : tuple of StarvationDecision
        One entry per exchange, in call order. The adversary's own notes; see
        :class:`StarvationDecision` on why a detector may not read them.

    Raises
    ------
    TypeError
        If ``rng`` is not a :class:`numpy.random.Generator`, or an argument is of
        the wrong type.
    ValueError
        If ``party`` is Alice, ``denial_probability`` is outside ``[0, 1]``,
        ``jitter`` is negative, or ``target_bits`` names anything but ``0`` and
        ``1``.

    See Also
    --------
    measure_starvation : Runs it against real sessions and counts outcomes.
    starvation_probe : The D6 check's probe for this adversary.

    Notes
    -----
    **What it refuses to do, and why the refusal is part of the experiment.**
    The seam is handed both messages, but a recipient controls only his own. The
    counterpart's count, both floors and the declaration digest are passed
    through untouched; a variant that edited them would be measuring a check
    that :func:`sih141.protocol.session._check_pooled_against` and
    :attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`
    already close, and would not be a recipient.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.starvation import CountStarver
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> params = ProtocolParams(key_length=600)
    >>> starver = CountStarver(rng=np.random.default_rng(2026))
    >>> transcript = QDSSession(
    ...     params, rng=np.random.default_rng(7), count_exchange=starver
    ... ).run(0)

    Bob reaches no verdict, and it is recorded as a refusal rather than a
    rejection:

    >>> transcript.is_complete, transcript.transferable
    (False, False)
    >>> [(abort.party.value, str(abort.reason)) for abort in transcript.aborts]
    [('Bob', 'counterpart-matched-count-below-floor')]

    Charlie meanwhile scores his own log and accepts, which is the contradiction
    a detector can read straight out of one transcript:

    >>> declared, scored = transcript.pooled.charlie_count, [
    ...     result.matched_count
    ...     for result in transcript.results
    ...     if result.party.value == "Charlie"
    ... ][0]
    >>> declared < 67 <= scored
    True
    """

    def __init__(
        self,
        *,
        rng: np.random.Generator,
        party: Party | str = Party.CHARLIE,
        mode: StarvationMode | str = StarvationMode.LEAST_IMPLAUSIBLE,
        denial_probability: float = 1.0,
        target_bits: Iterable[int] | None = None,
        jitter: int = 8,
    ) -> None:
        """Store the adversary's own generator and its policy."""
        if not isinstance(rng, np.random.Generator):
            raise TypeError(
                f"rng must be a numpy.random.Generator, got "
                f"{type(rng).__name__}. Convention D6: an adversary owns its "
                f"randomness and never derives it from the seed the harness "
                f"gave QDSSession."
            )
        self._rng = rng
        self.party = _as_verifier(party)
        self.mode = StarvationMode(mode)
        if isinstance(denial_probability, bool) or not isinstance(
            denial_probability, (int, float, np.floating, np.integer)
        ):
            raise TypeError(
                f"denial_probability must be a real number in [0, 1], got "
                f"{type(denial_probability).__name__}"
            )
        probability = float(denial_probability)
        if not 0.0 <= probability <= 1.0:
            raise ValueError(
                f"denial_probability must lie in [0, 1], got {probability}. It "
                f"is the per-exchange coin the selective attack is defined by."
            )
        self.denial_probability = probability
        if target_bits is None:
            resolved_bits = frozenset({0, 1})
        else:
            resolved_bits = frozenset(
                _as_message_bit(bit) for bit in target_bits
            )
            if not resolved_bits:
                raise ValueError(
                    "target_bits must name at least one message bit, got an "
                    "empty collection. Pass None for both bits, or omit the "
                    "adversary entirely for an honest run."
                )
        self.target_bits = resolved_bits
        span = _as_count(jitter, "jitter")
        self.jitter = span
        self._log: list[StarvationDecision] = []

    @property
    def log(self) -> tuple[StarvationDecision, ...]:
        """tuple of StarvationDecision: every exchange, in call order."""
        return tuple(self._log)

    def __call__(
        self,
        messages: Mapping[Party | str, MatchedCountMessage],
        params: ProtocolParams,
    ) -> PooledMatchedCounts:
        """Run Phase C' with this verifier's count replaced. The seam itself.

        Parameters
        ----------
        messages : mapping of Party to MatchedCountMessage
            Both verifiers' honest messages, as the session computed them. Only
            the entry for :attr:`party` is altered.
        params : ProtocolParams
            The parameter set the run executes under.

        Returns
        -------
        PooledMatchedCounts
            Built by :func:`~sih141.protocol.tally.exchange_matched_counts` from
            the doctored pair, so it carries the honest floors and the honest
            declaration digest.

        Raises
        ------
        TypeError, ValueError
            As :func:`~sih141.protocol.tally.exchange_matched_counts`, which
            validates the pair exactly as it would on an honest run.

        Notes
        -----
        Draws from the adversary's own generator: one coin for the selectivity
        rule and, on a starving call in
        :attr:`~StarvationMode.LEAST_IMPLAUSIBLE`, one jitter. Nothing about the
        session's randomness is reachable from here (D6) -- the seam is handed
        two integers, a bit, a length and a digest.
        """
        checked = _as_params(params)
        counterpart_party = _counterpart_of(self.party)
        own = _message_for(messages, self.party)
        counterpart = _message_for(messages, counterpart_party)
        headroom = denial_headroom(counterpart.matched_count, checked)
        # The coin is drawn on *every* call, targeted or not, so that the
        # adversary's generator advances identically whichever bits it targets
        # and two policies stay comparable position by position.
        coin = float(self._rng.random())
        starving = (
            own.message_bit in self.target_bits
            and coin < self.denial_probability
        )
        declared = own.matched_count
        if starving:
            declared = self._starving_count(own.matched_count, headroom)
        self._log.append(
            StarvationDecision(
                party=self.party,
                message_bit=own.message_bit,
                true_count=own.matched_count,
                declared_count=declared,
                counterpart_count=counterpart.matched_count,
                headroom=headroom,
                starved=starving,
            )
        )
        doctored = dataclasses.replace(own, matched_count=declared)
        return exchange_matched_counts(
            {self.party: doctored, counterpart_party: counterpart}, checked
        )

    def _starving_count(self, true_count: int, headroom: int) -> int:
        """Return the count to declare on a call that has decided to deny.

        Parameters
        ----------
        true_count : int
            ``|M_R|``. The declaration is capped at it, because over-reporting
            is a different attack and this one does not make it by accident.
        headroom : int
            :func:`denial_headroom` for this exchange.

        Returns
        -------
        int
            In ``[0, min(true_count, headroom)]``.
        """
        ceiling = min(true_count, headroom)
        if self.mode is StarvationMode.ZERO or ceiling <= 0:
            return 0
        if self.jitter == 0:
            return ceiling
        return max(0, ceiling - int(self._rng.integers(0, self.jitter + 1)))


def probe_messages(
    params: ProtocolParams = PROBE_PARAMS,
    *,
    message_bit: int = 0,
    counts: tuple[int, int] = _HONEST_PROBE_COUNTS,
) -> dict[Party, MatchedCountMessage]:
    """Return the frozen pair of messages the D6 probe replays.

    Deliberately synthetic. The whole of what a ``count_exchange`` adversary
    observes is two counts, a bit, a key length and a digest, so freezing those
    directly is both sufficient and cleaner than running a session: it removes
    the session from the probe entirely, which is what makes
    :func:`~sih141.attacks.isolation.check_attack_isolation`'s first half a
    statement about the adversary rather than about the records it was handed.

    Parameters
    ----------
    params : ProtocolParams, optional
        Defaults to :data:`PROBE_PARAMS`.
    message_bit : int, optional
        Keyword-only, ``0`` or ``1``.
    counts : tuple of int, optional
        Keyword-only ``(m_B, m_C)``. Defaults to two ordinary draws near ``mu``.

    Returns
    -------
    dict of Party to MatchedCountMessage
        Keyed by :attr:`~sih141.protocol.params.Party.BOB` then
        :attr:`~sih141.protocol.params.Party.CHARLIE`.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`
        or a count is not an integer.
    ValueError
        If ``message_bit`` is not ``0``/``1``, or a count is out of range.

    Examples
    --------
    >>> from sih141.attacks.starvation import probe_messages
    >>> from sih141.protocol.params import Party
    >>> messages = probe_messages()
    >>> messages[Party.BOB].matched_count, messages[Party.CHARLIE].matched_count
    (198, 203)
    >>> messages[Party.BOB].declaration_digest == messages[
    ...     Party.CHARLIE
    ... ].declaration_digest
    True
    """
    checked = _as_params(params)
    bit = _as_message_bit(message_bit)
    bob_count, charlie_count = (
        _as_count(counts[0], "counts[0]"),
        _as_count(counts[1], "counts[1]"),
    )
    return {
        Party.BOB: MatchedCountMessage(
            Party.BOB, bit, bob_count, checked.key_length, _PROBE_DIGEST
        ),
        Party.CHARLIE: MatchedCountMessage(
            Party.CHARLIE, bit, charlie_count, checked.key_length, _PROBE_DIGEST
        ),
    }


def starvation_probe(
    params: ProtocolParams = PROBE_PARAMS, *, repeats: int = 24
) -> DecisionProbe:
    """Return the :class:`~sih141.attacks.isolation.DecisionProbe` for this attack.

    ``(attack, session_seed) -> tuple of int``: the counts the candidate
    declares over ``repeats`` exchanges against one frozen pair of messages.
    ``session_seed`` is **deliberately unused**, for the reason
    :func:`~sih141.attacks.isolation.signer_probe` gives: the adversary's
    observations are identical on every call, so the session seed is a quantity
    it can only know if it went and took it, and that is exactly the question
    the check asks.

    Parameters
    ----------
    params : ProtocolParams, optional
        Defaults to :data:`PROBE_PARAMS`.
    repeats : int, optional
        Keyword-only. How many exchanges to observe per probe call. More than
        one because a single starving declaration under a policy that denies
        every run is deterministic, and the check's second half needs the
        adversary's own generator to be visible in the trace. ``24`` makes an
        accidental collision between two attack seeds negligible.

    Returns
    -------
    DecisionProbe
        Ready for :func:`~sih141.attacks.isolation.assert_attack_isolated`.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`
        or ``repeats`` is not an integer.
    ValueError
        If ``repeats`` is not positive.

    Examples
    --------
    >>> from sih141.attacks.isolation import assert_attack_isolated
    >>> from sih141.attacks.starvation import CountStarver, starvation_probe
    >>> report = assert_attack_isolated(CountStarver, starvation_probe())
    >>> report.isolated, report.session_seed_offered
    (True, False)
    >>> report.distinct_decisions > 1
    True
    """
    checked = _as_params(params)
    count = _as_count(repeats, "repeats")
    if count < 1:
        raise ValueError(
            f"repeats must be at least 1, got {count}; the probe has to see at "
            f"least one decision."
        )
    frozen = probe_messages(checked)

    def probe(attack: Any, session_seed: int) -> tuple[int, ...]:
        """Declare ``repeats`` times against the frozen pair; return the counts."""
        del session_seed  # An isolated recipient cannot see it. That is the point.
        return tuple(
            attack(frozen, checked).count_for(_starver_party(attack))
            for _ in range(count)
        )

    return probe


def wilson_interval(
    successes: int, trials: int, *, z: float = 1.959963984540054
) -> tuple[float, float]:
    """Return a Wilson score interval for a measured rate.

    Used instead of the normal approximation because every rate this module
    measures lands at or very near ``0`` or ``1``, where the normal interval is
    either degenerate or extends outside ``[0, 1]``.

    Parameters
    ----------
    successes : int
        Number of successes, ``0 <= successes <= trials``.
    trials : int
        Number of trials, at least ``1``.
    z : float, optional
        Keyword-only standard normal quantile. Defaults to the 95% two-sided
        one.

    Returns
    -------
    tuple of float
        ``(low, high)``, both in ``[0, 1]``.

    Raises
    ------
    TypeError
        If a count is not an integer or ``z`` is not a real number.
    ValueError
        If ``trials < 1``, ``successes`` is outside ``[0, trials]``, or
        ``z <= 0``.

    Examples
    --------
    >>> from sih141.attacks.starvation import wilson_interval
    >>> low, high = wilson_interval(60, 60)
    >>> f"{low:.4f}", f"{high:.4f}"
    ('0.9398', '1.0000')
    >>> low, high = wilson_interval(0, 60)
    >>> f"{low:.4f}", f"{high:.4f}"
    ('0.0000', '0.0602')
    """
    hits = _as_count(successes, "successes")
    total = _as_count(trials, "trials")
    if total < 1:
        raise ValueError(
            f"trials must be at least 1, got {total}; a rate needs a "
            f"denominator."
        )
    if hits > total:
        raise ValueError(
            f"successes ({hits}) cannot exceed trials ({total})."
        )
    if isinstance(z, bool) or not isinstance(
        z, (int, float, np.floating, np.integer)
    ):
        raise TypeError(f"z must be a real number, got {type(z).__name__}")
    quantile = float(z)
    if quantile <= 0.0:
        raise ValueError(f"z must be positive, got {quantile}")
    # One implementation for the suite, in sih141.attacks.statistics, which is
    # also where the exact-at-the-ends clamping is explained (:ref:`float-dust`).
    return wilson_bounds(hits, total, z=quantile)


@dataclass(frozen=True)
class StarvationMeasurement:
    """The outcome of one arm of the starvation experiment.

    Frozen and made of primitives, so it drops into a Phase 5 table unchanged.
    Every rate carries its numerator, its denominator and an interval, because a
    denial rate quoted without them is exactly the kind of claim D5 exists to
    stop.

    Parameters
    ----------
    label : str
        The arm's name.
    key_length : int
        ``L`` the arm was run at.
    trials : int
        Sessions run.
    denied : int
        Runs where at least one verifier reached **no verdict**. This is the
        attack's success count. Note it is a count of *aborts*, never of
        rejections: the two are different types in the transcript and are not
        added together anywhere.
    complete : int
        Runs where both verifiers reached a verdict.
    transferable : int
        Runs where both verifiers accepted.
    starved_exchanges : int
        Exchanges on which the adversary chose to deny. Equal to ``trials`` for
        a non-selective starver and about ``denial_probability * trials``
        otherwise. ``0`` for the honest control arm.
    accepted_by_starver : int
        Runs where the starving verifier himself accepted. The number that shows
        the denial is one-sided.
    declared_counts : tuple of int
        What the starving verifier put on the wire, per run. Empty for the
        control arm.
    scored_counts : tuple of int
        What the starving verifier's own verdict recorded as his true
        ``|M_R|``, per run in which he reached one. The other half of
        :func:`declared_versus_scored`.
    abort_reasons : tuple of str
        Every abort reason recorded across the arm, in run order.

    Attributes
    ----------
    label : str
    key_length : int
    trials : int
    denied : int
    complete : int
    transferable : int
    starved_exchanges : int
    accepted_by_starver : int
    declared_counts : tuple of int
    scored_counts : tuple of int
    abort_reasons : tuple of str

    Examples
    --------
    >>> from sih141.attacks.starvation import StarvationMeasurement
    >>> arm = StarvationMeasurement(
    ...     label="zero", key_length=192, trials=40, denied=40, complete=0,
    ...     transferable=0, starved_exchanges=40, accepted_by_starver=40,
    ...     declared_counts=(0,) * 40, scored_counts=(64,) * 40,
    ...     abort_reasons=("pooled-matched-count-below-floor",) * 40,
    ... )
    >>> arm.denial_rate
    1.0
    >>> low, high = arm.denial_interval
    >>> f"{low:.4f}"
    '0.9124'
    """

    label: str
    key_length: int
    trials: int
    denied: int
    complete: int
    transferable: int
    starved_exchanges: int
    accepted_by_starver: int
    declared_counts: tuple[int, ...]
    scored_counts: tuple[int, ...]
    abort_reasons: tuple[str, ...]

    @property
    def denial_rate(self) -> float:
        """float: fraction of runs in which some verifier reached no verdict."""
        return self.denied / self.trials

    @property
    def denial_interval(self) -> tuple[float, float]:
        """tuple of float: 95% Wilson interval for :attr:`denial_rate`."""
        return wilson_interval(self.denied, self.trials)

    @property
    def completion_rate(self) -> float:
        """float: fraction of runs in which both verifiers reached a verdict."""
        return self.complete / self.trials

    def summary(self) -> str:
        """Return a one-line account of the arm.

        Returns
        -------
        str

        Examples
        --------
        >>> from sih141.attacks.starvation import StarvationMeasurement
        >>> StarvationMeasurement(
        ...     "zero", 192, 40, 40, 0, 0, 40, 40, (), (), ()
        ... ).summary()
        'zero (L=192): denied 40/40 = 1.000 [0.912, 1.000], complete 0/40, \
transferable 0/40, starving exchanges 40.'
        """
        low, high = self.denial_interval
        return (
            f"{self.label} (L={self.key_length}): denied {self.denied}/"
            f"{self.trials} = {self.denial_rate:.3f} [{low:.3f}, {high:.3f}], "
            f"complete {self.complete}/{self.trials}, transferable "
            f"{self.transferable}/{self.trials}, starving exchanges "
            f"{self.starved_exchanges}."
        )


def declared_versus_scored(
    transcript: SessionTranscript, party: Party | str
) -> tuple[int, int] | None:
    """Return ``(declared, scored)`` for one verifier from a single transcript.

    The within-one-run detector signal of :ref:`starvation-history`, extracted
    from data a Phase 4 pass actually has. A starving verifier's declared count
    comes from
    :attr:`~sih141.protocol.session.SessionTranscript.pooled`; his true count
    comes from his own
    :class:`~sih141.protocol.verify.VerificationResult`, which he still produces
    because his verdict is computed from his own record and the *counterpart's*
    count -- neither of which this attack edits.

    Parameters
    ----------
    transcript : SessionTranscript
        A finished or partial run.
    party : Party or str
        The verifier to look at.

    Returns
    -------
    tuple of int or None
        ``(declared, scored)``, or ``None`` when the pair is not available:
        either the recipients did not exchange counts
        (:attr:`~sih141.protocol.session.SessionTranscript.counts_exchanged`
        ``False``) or this verifier reached no verdict, so no true count was
        published.

    Raises
    ------
    TypeError
        If ``transcript`` is not a
        :class:`~sih141.protocol.session.SessionTranscript`.
    ValueError
        If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE`.

    Notes
    -----
    ``None`` is the interesting return value as well as the boring one: it is
    what a *jointly* starved run gives, and it is why the per-run contradiction
    is a signal about this attack rather than about starvation in general.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.starvation import (
    ...     CountStarver, declared_versus_scored
    ... )
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> transcript = QDSSession(
    ...     ProtocolParams(key_length=600),
    ...     rng=np.random.default_rng(7),
    ...     count_exchange=CountStarver(rng=np.random.default_rng(2026)),
    ... ).run(0)
    >>> declared, scored = declared_versus_scored(transcript, Party.CHARLIE)
    >>> declared < scored
    True
    >>> declared_versus_scored(transcript, Party.BOB) is None   # Bob aborted
    True
    """
    if not isinstance(transcript, SessionTranscript):
        raise TypeError(
            f"transcript must be a SessionTranscript, got "
            f"{type(transcript).__name__}"
        )
    resolved = _as_verifier(party)
    if transcript.pooled is None:
        return None
    for result in transcript.results:
        if result.party is resolved:
            return (
                transcript.pooled.count_for(resolved),
                result.matched_count,
            )
    return None


def measure_starvation(
    params: ProtocolParams,
    trials: int,
    *,
    label: str,
    starver: CountStarver | None = None,
    message_bits: Sequence[int] = (0,),
    session_seed_start: int = 500_000,
) -> StarvationMeasurement:
    """Run one arm of the experiment and count what the sessions did.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set every session in the arm runs under.
    trials : int
        Sessions to run, at least ``1``.
    label : str
        Keyword-only name for the arm.
    starver : CountStarver or None, optional
        Keyword-only. ``None`` runs the honest control arm with the shipped
        :func:`~sih141.protocol.tally.exchange_matched_counts`. The same
        adversary object is reused across the arm's trials **on purpose**: its
        generator carries forward, so its selectivity coins are independent
        across runs rather than restarted.
    message_bits : sequence of int, optional
        Keyword-only. Cycled over the trials, so an arm can mix bits and a
        bit-selective starver can be seen to let one of them through.
    session_seed_start : int, optional
        Keyword-only. Session seeds are ``session_seed_start + i``. **D6**: this
        must have nothing to do with the seed ``starver``'s generator was built
        from, and the two are separate arguments here so that a caller cannot
        pass one number and get both.

    Returns
    -------
    StarvationMeasurement

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`,
        ``starver`` is neither ``None`` nor a :class:`CountStarver`, or a count
        is not an integer.
    ValueError
        If ``trials < 1``, ``message_bits`` is empty or names anything but
        ``0``/``1``, or ``session_seed_start`` is negative.

    See Also
    --------
    StarvationMeasurement : What comes back.

    Notes
    -----
    Each trial is a fresh :class:`~sih141.protocol.session.QDSSession`, so no
    replay ledger is shared between runs and no
    :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED` can
    contaminate the abort tally.
    :exc:`~sih141.protocol.verify.MatchedSetTooSmall` is already caught inside
    :meth:`~sih141.protocol.session.QDSSession.run`, so a denied run returns a
    transcript rather than raising.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.starvation import CountStarver, measure_starvation
    >>> from sih141.protocol.params import DEMO_PARAMS
    >>> arm = measure_starvation(
    ...     DEMO_PARAMS, 3, label="demo",
    ...     starver=CountStarver(rng=np.random.default_rng(11)),
    ... )
    >>> arm.denied, arm.complete, arm.starved_exchanges
    (3, 0, 3)
    >>> set(arm.declared_counts)                # m_min is 1 at L = 192
    {0}
    """
    checked = _as_params(params)
    total = _as_count(trials, "trials")
    if total < 1:
        raise ValueError(f"trials must be at least 1, got {total}")
    if not isinstance(label, str) or not label:
        raise ValueError(
            f"label must be a non-empty string naming the arm, got {label!r}"
        )
    if starver is not None and not isinstance(starver, CountStarver):
        raise TypeError(
            f"starver must be a CountStarver or None, got "
            f"{type(starver).__name__}; None runs the honest control arm."
        )
    bits = tuple(_as_message_bit(bit) for bit in message_bits)
    if not bits:
        raise ValueError(
            "message_bits must name at least one bit; it is cycled over the "
            "trials."
        )
    start = _as_count(session_seed_start, "session_seed_start")

    denied = complete = transferable = accepted_by_starver = 0
    declared: list[int] = []
    scored: list[int] = []
    reasons: list[str] = []
    starved_before = 0 if starver is None else len(starver.log)

    for index in range(total):
        session = QDSSession(
            checked,
            rng=np.random.default_rng(start + index),
            count_exchange=exchange_matched_counts
            if starver is None
            else starver,
        )
        try:
            transcript = session.run(bits[index % len(bits)])
        except MatchedSetTooSmall:  # pragma: no cover - run() catches these
            raise
        if not transcript.is_complete:
            denied += 1
        else:
            complete += 1
        if transcript.transferable:
            transferable += 1
        reasons.extend(str(abort.reason) for abort in transcript.aborts)
        if starver is not None and transcript.pooled is not None:
            declared.append(transcript.pooled.count_for(starver.party))
            pair = declared_versus_scored(transcript, starver.party)
            if pair is not None:
                scored.append(pair[1])
                accepted_by_starver += sum(
                    1
                    for result in transcript.results
                    if result.party is starver.party and result.accepted
                )

    starved = (
        0
        if starver is None
        else sum(
            1 for decision in starver.log[starved_before:] if decision.starved
        )
    )
    return StarvationMeasurement(
        label=label,
        key_length=checked.key_length,
        trials=total,
        denied=denied,
        complete=complete,
        transferable=transferable,
        starved_exchanges=starved,
        accepted_by_starver=accepted_by_starver,
        declared_counts=tuple(declared),
        scored_counts=tuple(scored),
        abort_reasons=tuple(reasons),
    )


# --------------------------------------------------------------------------- #
# Small local coercions. Deliberately not imported from the protocol package:
# the attacks package must not grow a dependency on its private helpers.
# --------------------------------------------------------------------------- #


def _as_params(params: Any) -> ProtocolParams:
    """Return ``params`` unchanged, refusing anything else.

    Parameters
    ----------
    params : ProtocolParams
        The candidate.

    Returns
    -------
    ProtocolParams

    Raises
    ------
    TypeError
        If it is not a :class:`~sih141.protocol.params.ProtocolParams`.
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    return params


def _as_count(value: Any, name: str) -> int:
    """Return ``value`` as a non-negative :class:`int`.

    Parameters
    ----------
    value : int
        The candidate.
    name : str
        The parameter's name, for the message.

    Returns
    -------
    int

    Raises
    ------
    TypeError
        If ``value`` is a :class:`bool` or not an integer.
    ValueError
        If it is negative.
    """
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise TypeError(
            f"{name} must be an int, got {type(value).__name__}"
        )
    number = int(value)
    if number < 0:
        raise ValueError(f"{name} must be non-negative, got {number}")
    return number


def _as_message_bit(value: Any) -> int:
    """Return ``value`` as ``0`` or ``1``.

    Parameters
    ----------
    value : int
        The candidate.

    Returns
    -------
    int

    Raises
    ------
    ValueError
        If it is neither ``0`` nor ``1``.
    """
    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(
            f"message bits are 0 or 1, got {value!r}. A run signs one bit and "
            f"the two distributions are independent."
        )
    return int(value)


def _as_verifier(party: Any) -> Party:
    """Return ``party`` as Bob or Charlie.

    Parameters
    ----------
    party : Party or str
        The candidate.

    Returns
    -------
    Party

    Raises
    ------
    TypeError
        If it is neither a :class:`~sih141.protocol.params.Party` nor a string.
    ValueError
        If it is Alice or names no party.
    """
    if isinstance(party, Party):
        resolved = party
    elif isinstance(party, str):
        try:
            resolved = Party(party)
        except ValueError as unknown:
            raise ValueError(
                f"party must name a verifier, got {party!r}; the verifiers are "
                f"{[member.value for member in VERIFIERS]}."
            ) from unknown
    else:
        raise TypeError(
            f"party must be a Party or a string, got {type(party).__name__}"
        )
    if resolved is Party.ALICE:
        raise ValueError(
            "Alice is not in Phase C': she holds no measurement record and "
            "reports no matched count. Count starvation is a recipient's "
            "attack -- pass Party.BOB or Party.CHARLIE."
        )
    return resolved


def _message_for(
    messages: Mapping[Party | str, MatchedCountMessage], party: Party
) -> MatchedCountMessage:
    """Return one verifier's message from a mapping keyed either way.

    The :class:`~sih141.protocol.tally.CountExchange` protocol admits both
    :class:`~sih141.protocol.params.Party` and :class:`str` keys, and a seam
    that only handled one of them would fail on a harness that used the other
    -- silently, since the failure would be a :exc:`KeyError` inside an
    adversary and would look like the attack not firing.

    Parameters
    ----------
    messages : mapping
        As handed to the seam.
    party : Party
        The verifier wanted.

    Returns
    -------
    MatchedCountMessage

    Raises
    ------
    TypeError
        If the entry is not a
        :class:`~sih141.protocol.tally.MatchedCountMessage`.
    ValueError
        If the mapping has no entry for ``party``.
    """
    for key in (party, party.value):
        if key in messages:
            message = messages[key]
            if not isinstance(message, MatchedCountMessage):
                raise TypeError(
                    f"messages[{key!r}] must be a MatchedCountMessage, got "
                    f"{type(message).__name__}; the seam is called with the "
                    f"pair the session computed."
                )
            return message
    raise ValueError(
        f"the count exchange needs a message from {party.value}, and the "
        f"mapping has none. Phase C' is defined pairwise over both verifiers."
    )


def _counterpart_of(party: Party) -> Party:
    """Return the other verifier.

    Parameters
    ----------
    party : Party
        Bob or Charlie, already resolved.

    Returns
    -------
    Party
    """
    return Party.CHARLIE if party is Party.BOB else Party.BOB


def _starver_party(attack: Any) -> Party:
    """Return the party a probed candidate reports for.

    Parameters
    ----------
    attack : object
        The candidate adversary. A :class:`CountStarver` says which verifier it
        is; anything else is assumed to be Charlie, which is the default the
        probe's frozen messages are shaped for.

    Returns
    -------
    Party
    """
    party = getattr(attack, "party", Party.CHARLIE)
    return party if isinstance(party, Party) else _as_verifier(party)
