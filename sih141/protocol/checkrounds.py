"""Sampled parameter estimation: where the channel statistics come from.

Phase 4 needs to say things like "this channel is depolarising at ``p = 0.3``"
or "this link is not entangled at all". Before this module there was nowhere
honest for such a number to come from.
:func:`sih141.protocol.distribute.distribute_to_recipient` built a full
:class:`~sih141.core.teleport.TeleportationResult` for every key position and
threw it away, and the two obvious repairs are both wrong:

* **Keep everything.** At :data:`~sih141.protocol.params.DEFAULT_PARAMS` that is
  ``115200 x 2 recipients x 2 message bits = 460800`` results per session, and
  -- far worse -- a diagnostic published for *every* position is a diagnostic
  published for every position **of the key**. The recipient's outcome at
  position ``i`` is exactly what a forger wants.
* **Read the statistics off the verification step.** The mismatch rate a
  verifier computes is a statistic of the *revealed key*, so it exists only
  after Phase B, only for matched positions, and only for a run that reached a
  verdict. It cannot answer "should this run have happened at all?".

This module implements the third answer, the one QKD has used since BB84:
**sample**. A random subset of the run's positions is designated in advance as
*check rounds*; those pairs are spent on measurement rather than on key, their
outcomes are published, and the positions are removed from the key. What is
published is then independent of the signing key, because those positions never
carry any.

.. _check-round-anatomy:

What a check round is
---------------------
Every position of a run consumes one entanglement resource, drawn from the
``resource_factory`` seam. A **key round** spends it on teleportation: Alice
Bell-measures the payload against her half, the recipient measures what arrives.
A **check round** spends the same pair on a measurement of the pair itself:
Alice measures her half, the recipient measures his, and the two outcomes are
published with their settings. Two kinds are drawn:

``CheckRole.QBER``
    Both halves are measured in the **same** basis, drawn uniformly from
    ``params.bases``. The ideal :math:`|\\Phi^{+}\\rangle` has
    :math:`\\langle XX\\rangle = +1`, :math:`\\langle YY\\rangle = -1`,
    :math:`\\langle ZZ\\rangle = +1` (:data:`IDEAL_PAULI_CORRELATION`), so the
    round is an *error* whenever the product of the two eigenvalues disagrees
    with that sign.
``CheckRole.CHSH``
    Alice measures at one of :data:`CHSH_ALICE_ANGLES`, the recipient at one of
    :data:`CHSH_RECIPIENT_ANGLES` -- both in the :math:`x`-:math:`z` plane, both
    drawn uniformly and independently -- and the product of the eigenvalues is
    accumulated into the four CHSH correlators.

.. _check-round-qber-identity:

Why the QBER arm measures the right thing (exactly, not approximately)
----------------------------------------------------------------------
The check round measures the *resource*; the protocol cares about the
*teleported key*. For the whole Bell-diagonal family these are the same number,
basis by basis, and the derivation is short enough to give in full.

Write the resource as :math:`\\rho = \\sum_B \\lambda_B |B\\rangle\\!\\langle B|`
over :data:`~sih141.core.states.BELL_ORDER`. The four Bell states have
correlators

.. code-block:: text

    <ZZ>     <XX>     <YY>
    Phi+  +1   +1       -1
    Psi+  -1   +1       +1
    Phi-  +1   -1       +1
    Psi-  -1   -1       -1

so the check-round error rate in each basis -- the probability the product
disagrees with the ideal sign -- is

.. code-block:: text

    q_Z = (1 - T_zz)/2 = lam(Psi+) + lam(Psi-)
    q_X = (1 - T_xx)/2 = lam(Phi-) + lam(Psi-)
    q_Y = (1 + T_yy)/2 = lam(Phi-) + lam(Psi+)

Teleportation through that same resource is the Pauli channel that applies
:math:`I, X, Z, XZ` with probabilities
:math:`\\lambda_{\\Phi^{+}}, \\lambda_{\\Psi^{+}}, \\lambda_{\\Phi^{-}},
\\lambda_{\\Psi^{-}}` (the correction is exact on the :math:`\\Phi^{+}` branch
and each other branch leaves exactly the Pauli labelling the resource's
deviation). A matched position in basis :math:`a` errs precisely when the
applied Pauli anticommutes with :math:`\\sigma_a`, so the key mismatch rates are

.. code-block:: text

    Z:  X and Y anticommute  ->  lam(Psi+) + lam(Psi-)
    X:  Z and Y anticommute  ->  lam(Phi-) + lam(Psi-)
    Y:  X and Z anticommute  ->  lam(Psi+) + lam(Phi-)

-- the same three expressions. **The check-round QBER in basis** :math:`a`
**equals the key mismatch rate in basis** :math:`a`, exactly, for every
Bell-diagonal resource: Werner, dephasing, amplitude-damping-after-twirl, every
Pauli channel. For the Werner family both collapse further to :math:`p/2`,
which is :func:`~sih141.protocol.analysis.depolarising_error_rate` -- the very
function :data:`~sih141.protocol.params.DEFAULT_S_A` was sized against.
``tests/test_protocol_checkrounds.py`` pins the identity on a Bell-diagonal
resource that is *not* Werner, because a Werner-only test cannot tell the
per-basis identity from the averaged one.

The claim is about Bell-diagonal resources, and that is stated rather than
hidden: a resource with off-diagonal Bell coherences can have a check-round rate
that differs from its key rate, and no test here says otherwise.

.. _chsh-prediction:

What CHSH predicts, derived
---------------------------
For a state with correlation tensor :math:`T`, a setting pair in the
:math:`x`-:math:`z` plane at angles :math:`\\alpha, \\beta` has correlator
:math:`E = \\sin\\alpha\\sin\\beta\\,T_{xx} + \\cos\\alpha\\cos\\beta\\,T_{zz}`.
For :math:`|\\Phi^{+}\\rangle` both are :math:`1`, so
:math:`E = \\cos(\\alpha - \\beta)`, and the shipped settings
:math:`(0, \\pi/2)` against :math:`(\\pi/4, -\\pi/4)` give
:math:`S = 3\\cos(\\pi/4) + \\cos(\\pi/4) = 2\\sqrt{2}`
(:data:`IDEAL_CHSH`) -- Tsirelson's bound, so the settings are optimal and not
merely serviceable.

The Werner state :math:`\\rho(p) = (1-p)|\\Phi^{+}\\rangle\\!\\langle\\Phi^{+}|
+ p\\,\\mathbb{1}/4` has the same :math:`T` scaled by :math:`(1-p)` -- the
identity term contributes nothing to any correlator -- so **every** correlator,
and therefore :math:`S`, scales linearly:

.. code-block:: text

    S(p) = (1 - p) * 2 sqrt(2)                  depolarising_chsh(p)

That is a derivation, not a fit, and it inverts: a measured :math:`S` implies
:math:`p = 1 - S/(2\\sqrt{2})` (:meth:`ChshEstimate.implied_depolarising`), which
implies a QBER of :math:`p/2`, which is the quantity ``s_a`` is a budget for.
The chain closes.

.. _check-fraction:

Choosing the check fraction, by derivation
------------------------------------------
Check rounds are bought with key. A fraction ``f`` of positions spent on
estimation leaves ``(1 - f) L`` carrying key, and *every* security bound in the
scheme is exponential in the matched count, which is proportional to that. The
question is therefore not "what feels like enough" but "what is the smallest
sample that resolves the quantity the thresholds are set against". Two
requirements fix it. Both are stated at
:data:`CHECK_CONFIDENCE` (``0.99``, two-sided, :math:`z = 2.5758`).

**R1 -- the QBER arm must resolve Bob's noise budget.** ``s_a = 1/64`` is a
*decision* threshold: the run is inside the budget or it is not. Ask for a
half-width of ``s_a / 4``, so that a channel sitting at the budget and a
noiseless one have intervals separated by ``s_a / 2`` with nothing overlapping.
At a rate of ``s_a`` the normal form needs

.. code-block:: text

    n_q >= z^2 s_a (1 - s_a) / (s_a/4)^2 = 16 z^2 (1 - s_a) / s_a = 6688

**R2 -- the CHSH arm must resolve the same budget in ``p``.** ``s_a`` is a
budget on the depolarising strength ``p_a = 2 s_a = 1/32``, and
``dS/dp = -2 sqrt(2)``, so resolving ``p_a`` means a half-width of
``2 sqrt(2) p_a``. Each cell is a mean of ``+-1`` products, and at the ideal
point ``1 - E^2 = 1/2`` in all four, so ``Var(S) = 8 / n_S`` for balanced cells:

.. code-block:: text

    n_S >= 8 z^2 / (2 sqrt(2) p_a)^2 = z^2 / p_a^2 = 6795

The weaker ask -- merely *certify* a violation of the classical bound ``2`` on
an honest channel -- needs ``8 z^2 / (2 sqrt(2) - 2)^2 = 78`` rounds and is not
what sizes anything. R2 is the binding version because a Bell test that cannot
resolve the budget cannot answer "is this deviation real or is it sampling
noise?", which is the question Phase 4 asks.

The two requirements come out almost equal -- ``6795 / (6688 + 6795) = 0.504``
-- so :data:`CHECK_CHSH_WEIGHT` is ``1/2`` **because the arithmetic says so**,
not for symmetry. Their sum is ``13483``, which at ``L = 115200`` is a fraction
of ``0.1170``; rounding up to the next binary fraction gives
:data:`~sih141.protocol.params.DEFAULT_CHECK_FRACTION` ``= 1/8``.

**And the cost is paid in key length, not in the bound.** Spending ``1/8`` of
``L = 115200`` drops the enforced repudiation bound from ``1.4139e-09`` to
``1.8853e-08``, a factor of thirteen; the honest response is to buy the sample
rather than to quietly publish the weaker number, so
:data:`~sih141.protocol.params.CHECKED_PARAMS` runs at ``L = 131664`` -- the
smallest multiple of ``24`` above ``115200 * 8/7`` -- whose signing length
``115206`` restores the bound to ``1.4124e-09``. Every one of those numbers is a
doctest below.

The counts, not the fraction, are what the requirements bind. ``f`` is the
operational knob; a deployment at another ``L`` should call
:func:`required_check_rounds` and derive its own, which is why that function
exists and why :data:`~sih141.protocol.params.DEFAULT_CHECK_FRACTION` is
documented as "the fraction that meets the counts at ``DEFAULT_PARAMS``'s
length" rather than as a universal constant.

.. _check-timing:

Who may know the check set, and when
------------------------------------
The positions are drawn from the **recipients'** stream
(:ref:`sih141.protocol.session <two-streams>`), never Alice's, and
:meth:`~sih141.protocol.params.ProtocolParams.sifted` is what verification then
runs under. Three separate statements, which are easy to run together and mean
different things:

* **The channel adversary must not know the check set while attacking.** This is
  the property the estimate rests on, and it is bought by *timing*: the resource
  factory is called for a check round exactly as for a key round -- same call,
  same :class:`~sih141.protocol.distribute.ResourceContext`, in the same order --
  so nothing on the wire distinguishes them.
  ``test_the_factory_cannot_tell_a_check_round_from_a_key_round`` is the test,
  and it is the load-bearing one.
* **Alice must know it at measurement time**, because a check round asks her to
  measure her half at an announced angle instead of Bell-measuring it against a
  payload, and one qubit cannot do both. This is the structural price of a
  teleportation-based protocol: a genuine two-wing Bell test needs two
  measurements, and the payload leg of a teleportation is a *preparation*, so no
  choice of settings on it can violate a Bell inequality. She learns the set
  only after the pairs are through the channel, which is exactly the ordering of
  sifting in QKD, and her honesty at that point is assumption **(AUTH)** --
  already load-bearing everywhere else in this package
  (:mod:`sih141.protocol.analysis` section 0b).
* **Alice must not know it when she draws her key**, and does not: the key is
  drawn from her own stream before any of this, and
  :meth:`CheckRoundPlan.sift_key` selects a subsequence of it. The retained
  elements are the *same objects* she drew, so no bias is possible by
  construction -- which is a stronger statement than "the retained key tests
  uniform", and both are tested.

This is therefore **not** a device-independent test. It certifies the resource
under the assumption that both endpoints measure as instructed. Saying so is the
point; a CHSH number quoted without it would be claiming far more than the
architecture delivers.

The numbers above, as executable claims
---------------------------------------
Per D5, and per the three wrong prose numbers this project has already shipped,
every load-bearing figure above is restated here as a test.

>>> import math
>>> from sih141.protocol.checkrounds import (
...     CHECK_CHSH_WEIGHT,
...     CHECK_CONFIDENCE,
...     CLASSICAL_CHSH_BOUND,
...     IDEAL_CHSH,
...     depolarising_chsh,
...     normal_quantile,
...     required_check_rounds,
... )
>>> from sih141.protocol.params import (
...     CHECKED_PARAMS, DEFAULT_CHECK_FRACTION, DEFAULT_PARAMS,
... )
>>> from sih141.protocol.verify import enforced_repudiation_bound

The two bounds a CHSH number is read against, and the depolarising law:

>>> f"{IDEAL_CHSH:.4f}", f"{CLASSICAL_CHSH_BOUND:.4f}"
('2.8284', '2.0000')
>>> f"{depolarising_chsh(0.0):.4f}", f"{depolarising_chsh(0.3):.4f}"
('2.8284', '1.9799')
>>> depolarising_chsh(1.0)
0.0

The sample sizes R1 and R2 ask for, and the weight that follows from them:

>>> f"{normal_quantile(0.5 + CHECK_CONFIDENCE / 2):.4f}"
'2.5758'
>>> budget = required_check_rounds(DEFAULT_PARAMS)
>>> budget.qber_rounds, budget.chsh_rounds, budget.total
(6688, 6795, 13483)
>>> f"{budget.chsh_rounds / budget.total:.4f}"
'0.5040'
>>> CHECK_CHSH_WEIGHT
0.5
>>> f"{budget.fraction:.4f}"
'0.1170'
>>> budget.fraction <= DEFAULT_CHECK_FRACTION == 0.125
True

The weaker "just certify a violation" ask, which sizes nothing:

>>> z = normal_quantile(0.5 + CHECK_CONFIDENCE / 2)
>>> math.ceil(8 * z ** 2 / (IDEAL_CHSH - CLASSICAL_CHSH_BOUND) ** 2)
78

What ``1/8`` costs at ``DEFAULT_PARAMS``'s length, and what buying the sample
back costs instead -- the two numbers that must never be confused:

>>> spent = DEFAULT_PARAMS.with_check_fraction(DEFAULT_CHECK_FRACTION)
>>> spent.check_count, spent.signing_length, spent.expected_matched
(14400, 100800, 33600.0)
>>> f"{enforced_repudiation_bound(spent):.4e}"
'1.8853e-08'
>>> f"{enforced_repudiation_bound(DEFAULT_PARAMS):.4e}"
'1.4139e-09'

>>> CHECKED_PARAMS.key_length, CHECKED_PARAMS.check_count
(131664, 16458)
>>> CHECKED_PARAMS.signing_length, CHECKED_PARAMS.expected_matched
(115206, 38402.0)
>>> f"{enforced_repudiation_bound(CHECKED_PARAMS):.4e}"
'1.4124e-09'
>>> enforced_repudiation_bound(CHECKED_PARAMS) <= enforced_repudiation_bound(
...     DEFAULT_PARAMS)
True

And the sample that key length buys clears both requirements:

>>> CHECKED_PARAMS.check_count // 2 >= budget.qber_rounds
True
>>> CHECKED_PARAMS.check_count - CHECKED_PARAMS.check_count // 2 >= budget.chsh_rounds
True

Notes
-----
Canonical state type (D1)
    The resource is accepted as a :class:`~qiskit.quantum_info.Statevector`, a
    :class:`~qiskit.quantum_info.DensityMatrix` or a raw array and coerced
    through :func:`sih141.core.states.as_density`, exactly as
    :func:`~sih141.core.teleport.teleport` does.
Qubit ordering (D2)
    Resource qubit ``0`` is **Alice's** half and qubit ``1`` is the recipient's.
    That is not a convention chosen here: :func:`~sih141.core.teleport.teleport`
    builds its register as ``resource.tensor(payload)``, which places the
    resource's qubit ``0`` at register index ``1`` (the sender's half) and its
    qubit ``1`` at index ``2`` (the receiver's). A check round must read the
    same pair the same way round or a one-sided attack would be attributed to
    the wrong party, and the tests pin it with an **asymmetric** resource --
    :math:`|\\Phi^{+}\\rangle` cannot tell the two conventions apart.
Determinism (D3)
    All randomness flows through an injected keyword-only ``rng`` resolved by
    :func:`sih141.core.rng.resolve_rng`. :func:`draw_check_plan` is the only
    function here that draws a plan, and it must be given the *recipients'*
    stream. Observing one check round consumes **exactly two** variates, which
    is what :func:`~sih141.core.teleport.teleport` plus the recipient's
    measurement consumes on a key round -- see
    :ref:`sih141.protocol.distribute <check-round-lockstep>`.
Attack randomness (D6)
    Nothing here derives randomness from a session seed or closes over one. An
    adversary that wants to fake check statistics must be built with its own
    generator like every other adversary.
No machine learning (D4)
    Closed-form statistics: a Wilson score interval, a Hoeffding tail bound, a
    normal quantile obtained by bisecting :func:`math.erfc`, and four means. No
    estimator here is fitted to data, and the two channel predictions
    (:func:`depolarising_chsh` and the QBER identity above) are derived from the
    resource's algebra rather than regressed onto it.

See Also
--------
sih141.protocol.distribute.distribute_to_recipient_with_checks : Runs a plan.
sih141.protocol.params.ProtocolParams.signing_length : The key that survives.
sih141.protocol.analysis.depolarising_error_rate : ``p / 2``, the other half of
    the prediction chain.
"""

from __future__ import annotations

import enum
import math
import numbers
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeAlias

import numpy as np
from qiskit.quantum_info import DensityMatrix, Operator

from sih141.core.measure import projective_measure
from sih141.core.paulis import PauliBasis
from sih141.core.rng import resolve_rng
from sih141.core.states import StateLike, as_density
from sih141.protocol.keys import PrivateKey
from sih141.protocol.params import (
    Party,
    ProtocolParams,
    _as_message_bit,
    _as_party,
)
from sih141.protocol.records import RecipientRecord

__all__ = [
    "CHECK_CONFIDENCE",
    "CHECK_CHSH_WEIGHT",
    "CHSH_ALICE_ANGLES",
    "CHSH_RECIPIENT_ANGLES",
    "CLASSICAL_CHSH_BOUND",
    "IDEAL_CHSH",
    "IDEAL_PAULI_CORRELATION",
    "CheckLog",
    "CheckRole",
    "CheckRoundBudget",
    "CheckRoundPlan",
    "ChshEstimate",
    "ChshObservation",
    "ChshRound",
    "Interval",
    "QberEstimate",
    "QberObservation",
    "QberRound",
    "depolarising_chsh",
    "draw_check_plan",
    "estimate_chsh",
    "estimate_qber",
    "normal_quantile",
    "observe_chsh_round",
    "observe_qber_round",
    "required_check_rounds",
]


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

IDEAL_CHSH: Final[float] = 2.0 * math.sqrt(2.0)
"""float: Tsirelson's bound, ``2.8284``, reached by the shipped settings.

The value :math:`|\\Phi^{+}\\rangle` gives under :data:`CHSH_ALICE_ANGLES`
against :data:`CHSH_RECIPIENT_ANGLES`; the module docstring derives it. It is
also the maximum any quantum state can give under any settings, so a measured
statistic above it is sampling noise, never physics -- which is why
:func:`estimate_chsh` clips its interval at the *algebraic* range and not here.
"""

CLASSICAL_CHSH_BOUND: Final[float] = 2.0
"""float: The CHSH bound of every local hidden-variable model, ``2``.

The number a measured statistic has to beat before "the resource was entangled
when it arrived" is a claim rather than a hope. A separable resource -- a kept
GHZ share, an intercepted-and-resent pair, a classically correlated mixture --
cannot exceed it under any settings.
"""

CHSH_ALICE_ANGLES: Final[tuple[float, float]] = (0.0, math.pi / 2.0)
"""Alice's two CHSH settings, as angles in the :math:`x`-:math:`z` plane.

``0`` is the :math:`Z` axis and ``pi/2`` the :math:`X` axis. Paired with
:data:`CHSH_RECIPIENT_ANGLES` these attain :data:`IDEAL_CHSH`.
"""

CHSH_RECIPIENT_ANGLES: Final[tuple[float, float]] = (
    math.pi / 4.0,
    -math.pi / 4.0,
)
"""The recipient's two CHSH settings, at :math:`\\pm\\pi/4`.

Halfway between Alice's two, which is what makes all four correlators
:math:`\\pm 1/\\sqrt{2}` and the combination maximal.
"""

IDEAL_PAULI_CORRELATION: Final[Mapping[PauliBasis, int]] = {
    PauliBasis.X: 1,
    PauliBasis.Y: -1,
    PauliBasis.Z: 1,
}
"""The sign :math:`|\\Phi^{+}\\rangle` gives when both halves are measured alike.

:math:`\\langle XX\\rangle = +1`, :math:`\\langle YY\\rangle = -1`,
:math:`\\langle ZZ\\rangle = +1`. The :math:`Y` sign is the one that is easy to
get wrong and the one that matters: :math:`|\\Phi^{+}\\rangle` is
*anti*-correlated in :math:`Y`, so a QBER arm that scored :math:`Y` rounds as
errors whenever the outcomes differed would report a flat ``1/3`` on a perfect
channel.
"""

CHECK_CONFIDENCE: Final[float] = 0.99
"""float: The default two-sided confidence level for every interval here.

``0.99``, i.e. :math:`\\alpha = 0.01` and :math:`z = 2.5758`. Chosen to sit far
enough below the scheme's other failure probabilities (``1e-9``-ish) that a
parameter-estimation false alarm is never the dominant way an honest run is
questioned, while staying loose enough that the sample sizes it implies
(:func:`required_check_rounds`) cost a fraction of the key rather than a
multiple of it. It is a design target, like
:data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET`, and does not have to be
revisited when ``L`` changes.
"""

CHECK_CHSH_WEIGHT: Final[float] = 0.5
"""float: The share of check rounds spent on the CHSH arm.

``1/2``, and derived rather than chosen for symmetry: requirements R1 and R2 of
the module docstring ask for ``6688`` and ``6795`` rounds respectively, whose
ratio is ``0.5040``. Rounding that to ``1/2`` over-provisions the CHSH arm by
under one percent. :meth:`CheckRoundPlan.split` applies it, giving the CHSH arm
the floor so that an odd check count spends its spare round on QBER, the arm
whose requirement binds ``s_a`` directly.
"""

_QBER_METHODS: Final[frozenset[str]] = frozenset({"wilson", "hoeffding"})
_CHSH_METHODS: Final[frozenset[str]] = frozenset({"normal", "hoeffding"})

QberMethod: TypeAlias = Literal["wilson", "hoeffding"]
"""Interval method for :func:`estimate_qber`."""

ChshMethod: TypeAlias = Literal["normal", "hoeffding"]
"""Interval method for :func:`estimate_chsh`."""

_CHSH_ALGEBRAIC_BOUND: Final[float] = 4.0
"""The largest ``|S|`` four numbers in ``[-1, 1]`` can combine to."""

#: Resource qubit carrying Alice's half of the pair (D2; see the module Notes).
_ALICE_QUBIT: Final[int] = 0

#: Resource qubit carrying the recipient's half.
_RECIPIENT_QUBIT: Final[int] = 1


# --------------------------------------------------------------------------- #
# Small numerics                                                               #
# --------------------------------------------------------------------------- #


def normal_quantile(probability: float) -> float:
    """Return :math:`\\Phi^{-1}(p)`, the standard normal quantile.

    Obtained by bisecting :func:`math.erfc` rather than from a table of fitted
    rational coefficients, so there is no approximation to audit and no magic
    constant to mistype: the result is exact to double precision for every
    ``probability`` strictly inside ``(0, 1)``.

    Parameters
    ----------
    probability : float
        A probability in the open interval ``(0, 1)``.

    Returns
    -------
    float
        The value ``x`` with ``P(Z <= x) == probability`` for a standard normal
        ``Z``.

    Raises
    ------
    TypeError
        If ``probability`` is a boolean or not a real number.
    ValueError
        If ``probability`` is not finite or does not lie strictly in ``(0, 1)``.
        The endpoints are infinite and there is no useful answer to return.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import normal_quantile
    >>> f"{abs(normal_quantile(0.5)):.12f}"
    '0.000000000000'
    >>> f"{normal_quantile(0.975):.6f}"
    '1.959964'
    >>> f"{normal_quantile(0.995):.6f}"
    '2.575829'
    """
    value = _as_unit_interval(probability, "probability", strict=True)
    low, high = -40.0, 40.0
    for _ in range(200):
        middle = 0.5 * (low + high)
        if 0.5 * math.erfc(-middle / math.sqrt(2.0)) < value:
            low = middle
        else:
            high = middle
    return 0.5 * (low + high)


def _two_sided_z(confidence: float) -> float:
    """Return the ``z`` multiplier for a two-sided interval at ``confidence``.

    Parameters
    ----------
    confidence : float
        The coverage level, strictly inside ``(0, 1)``.

    Returns
    -------
    float
        ``Phi^-1(0.5 + confidence / 2)``.
    """
    level = _as_unit_interval(confidence, "confidence", strict=True)
    return normal_quantile(0.5 + level / 2.0)


def _as_unit_interval(value: Any, name: str, *, strict: bool) -> float:
    """Coerce and range-check a probability-like argument.

    Parameters
    ----------
    value : float
        The candidate.
    name : str
        The argument name, quoted in error messages.
    strict : bool
        ``True`` to require the open interval ``(0, 1)``, ``False`` for the
        half-open ``[0, 1)``.

    Returns
    -------
    float
        ``value`` as a plain float.

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite or is out of range.
    """
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a real number, got the boolean {value!r}")
    if not isinstance(value, numbers.Real):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}"
        )
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite, got {result!r}")
    lower_ok = result > 0.0 if strict else result >= 0.0
    if not (lower_ok and result < 1.0):
        span = "(0, 1)" if strict else "[0, 1)"
        raise ValueError(f"{name} must lie in {span}, got {result!r}")
    return result


def _as_count(value: Any, name: str, *, minimum: int = 0) -> int:
    """Coerce and range-check a non-negative integer count.

    Parameters
    ----------
    value : int
        The candidate.
    name : str
        The argument name, quoted in error messages.
    minimum : int, optional
        The smallest acceptable value.

    Returns
    -------
    int
        ``value`` as a plain int.

    Raises
    ------
    ValueError
        If ``value`` is a boolean, not an integer, or below ``minimum``.
    """
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, got the boolean {value!r}")
    if not isinstance(value, numbers.Integral):
        raise ValueError(
            f"{name} must be an integer, got {type(value).__name__}"
        )
    result = int(value)
    if result < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {result}")
    return result


def _as_eigenvalue_outcome(value: Any, name: str) -> int:
    """Coerce a measured eigenvalue to ``+1`` or ``-1``.

    Parameters
    ----------
    value : int
        The candidate.
    name : str
        The argument name, quoted in error messages.

    Returns
    -------
    int
        ``1`` or ``-1``.

    Raises
    ------
    ValueError
        If ``value`` is a boolean or is not ``+1``/``-1``. Booleans are refused
        for the reason :func:`sih141.protocol.params._as_eigenvalue` gives:
        ``True`` reads as ``+1`` but means bit ``1``, which is ``-1``.
    """
    if isinstance(value, bool):
        raise ValueError(
            f"{name} must be the Pauli eigenvalue +1 or -1, got the boolean "
            f"{value!r}; convert with eigenvalue = 1 - 2 * bit."
        )
    if not isinstance(value, numbers.Integral):
        raise ValueError(
            f"{name} must be the integer +1 or -1, got {type(value).__name__}"
        )
    result = int(value)
    if result not in (1, -1):
        raise ValueError(
            f"{name} must be +1 or -1, got {result!r}. These are measurement "
            f"eigenvalues, not bits."
        )
    return result


def _as_setting(value: Any, name: str) -> int:
    """Coerce a CHSH setting index to ``0`` or ``1``.

    Parameters
    ----------
    value : int
        The candidate.
    name : str
        The argument name, quoted in error messages.

    Returns
    -------
    int
        ``0`` or ``1``.

    Raises
    ------
    ValueError
        If ``value`` is a boolean or is not ``0``/``1``.
    """
    if isinstance(value, bool):
        raise ValueError(
            f"{name} must be the integer 0 or 1, got the boolean {value!r}"
        )
    if not isinstance(value, numbers.Integral):
        raise ValueError(
            f"{name} must be the integer 0 or 1, got {type(value).__name__}"
        )
    result = int(value)
    if result not in (0, 1):
        raise ValueError(
            f"{name} must index one of the two CHSH settings (0 or 1), got "
            f"{result!r}. Two settings per wing is what makes the inequality a "
            f"CHSH inequality."
        )
    return result


def depolarising_chsh(depolarising_parameter: float) -> float:
    """Return the CHSH statistic a Werner resource of strength ``p`` yields.

    ``(1 - p) * 2 sqrt(2)``, derived in the module docstring under
    :ref:`chsh-prediction`: the maximally mixed component of
    ``rho(p) = (1-p)|Phi+><Phi+| + p I/4`` contributes zero to every correlator,
    so the whole correlation tensor -- and therefore ``S`` -- scales by
    ``1 - p``. This is the analytic prediction Phase 4 compares a measured
    statistic against; it is not a fit to anything.

    Parameters
    ----------
    depolarising_parameter : float
        ``p`` in ``[0, 1]``: the weight of the maximally mixed component of the
        Werner resource. ``0`` is the ideal pair, ``1`` is white noise.

    Returns
    -------
    float
        The predicted ``S``. Crosses :data:`CLASSICAL_CHSH_BOUND` at
        ``p = 1 - 1/sqrt(2) = 0.2929``, which is the largest depolarising
        strength this test can still certify entanglement through.

    Raises
    ------
    TypeError
        If ``depolarising_parameter`` is a boolean or not a real number.
    ValueError
        If it is not finite or lies outside ``[0, 1]``.

    See Also
    --------
    sih141.protocol.analysis.depolarising_error_rate : ``p / 2``, the QBER the
        same resource produces, on both the check rounds and the key.
    ChshEstimate.implied_depolarising : The inverse, with its interval.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import depolarising_chsh
    >>> f"{depolarising_chsh(0.0):.4f}"
    '2.8284'
    >>> f"{depolarising_chsh(0.3):.4f}"
    '1.9799'
    >>> f"{depolarising_chsh(1 - 1 / 2 ** 0.5):.4f}"
    '2.0000'
    >>> depolarising_chsh(1.0)
    0.0
    """
    if isinstance(depolarising_parameter, bool):
        raise TypeError(
            f"depolarising_parameter must be a real number in [0, 1], got the "
            f"boolean {depolarising_parameter!r}"
        )
    if not isinstance(depolarising_parameter, numbers.Real):
        raise TypeError(
            f"depolarising_parameter must be a real number in [0, 1], got "
            f"{type(depolarising_parameter).__name__}"
        )
    value = float(depolarising_parameter)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(
            f"depolarising_parameter must be a finite number in [0, 1], got "
            f"{value!r}. It is the weight of the maximally mixed component of "
            f"the Werner resource, so it is a probability."
        )
    return (1.0 - value) * IDEAL_CHSH


# --------------------------------------------------------------------------- #
# Sample sizing                                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CheckRoundBudget:
    """How many check rounds a parameter set's thresholds actually require.

    The output of :func:`required_check_rounds`, and the object that turns the
    module docstring's :ref:`check-fraction` derivation into something a
    deployment at another ``L`` can call rather than copy.

    Attributes
    ----------
    qber_rounds : int
        Requirement R1: the sample the QBER arm needs to resolve ``s_a`` at the
        requested resolution.
    chsh_rounds : int
        Requirement R2: the sample the CHSH arm needs to resolve the
        corresponding depolarising strength.
    confidence : float
        The two-sided level both were computed at.
    key_length : int
        The ``L`` the fraction is expressed against.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import required_check_rounds
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> budget = required_check_rounds(DEFAULT_PARAMS)
    >>> budget.qber_rounds, budget.chsh_rounds, budget.total
    (6688, 6795, 13483)
    >>> f"{budget.fraction:.4f}"
    '0.1170'
    """

    qber_rounds: int
    chsh_rounds: int
    confidence: float
    key_length: int

    @property
    def total(self) -> int:
        """int: ``qber_rounds + chsh_rounds``, the whole check sample."""
        return self.qber_rounds + self.chsh_rounds

    @property
    def fraction(self) -> float:
        """float: :attr:`total` as a fraction of :attr:`key_length`.

        The *minimum* usable
        :attr:`~sih141.protocol.params.ProtocolParams.check_fraction` at this
        ``L``; round **up** to a value that is convenient to divide, never down.
        """
        return self.total / self.key_length

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the budget.

        Returns
        -------
        dict
            Keys ``"qber_rounds"``, ``"chsh_rounds"``, ``"total"``,
            ``"fraction"``, ``"confidence"``, ``"key_length"``.
        """
        return {
            "qber_rounds": self.qber_rounds,
            "chsh_rounds": self.chsh_rounds,
            "total": self.total,
            "fraction": self.fraction,
            "confidence": self.confidence,
            "key_length": self.key_length,
        }


def required_check_rounds(
    params: ProtocolParams,
    *,
    qber_resolution: float | None = None,
    depolarising_resolution: float | None = None,
    confidence: float = CHECK_CONFIDENCE,
) -> CheckRoundBudget:
    """Size the check sample from the thresholds it has to resolve.

    Implements requirements R1 and R2 of the module docstring's
    :ref:`check-fraction` section. Both are normal-form sample sizes, which is
    the right form here: they size a sample, and using the conservative
    Hoeffding form for *sizing* would triple the key loss to buy precision the
    decision does not use. The interval a run actually reports may still be
    taken distribution-free -- ``method="hoeffding"`` on either estimator --
    and that choice is independent of this one.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set. Supplies ``s_a`` (the threshold both requirements are
        stated against) and ``key_length`` (only to express the answer as a
        fraction).
    qber_resolution : float or None, optional
        Keyword-only. R1's target half-width for the QBER interval. Defaults to
        ``params.s_a / 4``, which separates a channel *at* the budget from a
        noiseless one by half the budget with no overlap.
    depolarising_resolution : float or None, optional
        Keyword-only. R2's target half-width for the depolarising strength
        inferred from CHSH. Defaults to ``2 * params.s_a``, the depolarising
        strength ``s_a`` is a budget for, so the Bell test resolves the budget
        rather than merely detecting its existence.
    confidence : float, optional
        Keyword-only. Two-sided level for both. Defaults to
        :data:`CHECK_CONFIDENCE`.

    Returns
    -------
    CheckRoundBudget
        The two counts, their sum, and the fraction of ``params.key_length``
        they represent.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or a resolution or the
        confidence is not a real number.
    ValueError
        If a resolution is not strictly positive, if ``qber_resolution``
        exceeds ``s_a`` (an interval wider than the threshold it is testing
        cannot decide anything about it), or if ``confidence`` is outside
        ``(0, 1)``.

    Notes
    -----
    R1 evaluates the binomial variance **at** ``s_a`` rather than at the
    worst-case ``1/2``. That is deliberate and it is what makes the sample
    affordable: the question is whether a channel *at the budget* is
    distinguishable, and at a rate of ``1/64`` the variance is ``0.0154``
    against the worst case ``0.25``. Evaluating at ``1/2`` would demand
    ``z^2 / (4 w^2) = 108800`` rounds, nearly the whole key, to answer a
    question about a rate that is nowhere near ``1/2``.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import required_check_rounds
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> required_check_rounds(DEFAULT_PARAMS).total
    13483
    >>> loose = required_check_rounds(
    ...     DEFAULT_PARAMS, qber_resolution=DEFAULT_PARAMS.s_a / 2)
    >>> loose.qber_rounds
    1672
    >>> tight = required_check_rounds(DEFAULT_PARAMS, confidence=0.999)
    >>> tight.total > required_check_rounds(DEFAULT_PARAMS).total
    True
    """
    checked = _as_params(params)
    level = _as_unit_interval(confidence, "confidence", strict=True)
    z = _two_sided_z(level)

    rate = checked.s_a
    width = (
        rate / 4.0
        if qber_resolution is None
        else _as_positive(qber_resolution, "qber_resolution")
    )
    if rate <= 0.0:
        raise ValueError(
            "cannot size a QBER check sample against s_a = 0: a threshold of "
            "zero admits no noise at all, so no finite sample separates a "
            "channel at the threshold from a perfect one. Use a parameter set "
            "with a positive s_a, or pass qber_resolution explicitly."
        )
    if width > rate:
        raise ValueError(
            f"qber_resolution ({width!r}) exceeds s_a ({rate!r}). An interval "
            f"wider than the threshold it is testing cannot decide whether the "
            f"channel is inside the budget: the interval around an estimate of "
            f"0 would already contain s_a. Try s_a / 4 = {rate / 4.0!r}."
        )
    qber_rounds = math.ceil(z * z * rate * (1.0 - rate) / (width * width))

    strength = (
        2.0 * rate
        if depolarising_resolution is None
        else _as_positive(depolarising_resolution, "depolarising_resolution")
    )
    # Var(S) = sum_ij (1 - E_ij^2) / n_ij = 8 / n for balanced cells at the
    # ideal point, and dS/dp = -IDEAL_CHSH, so a half-width of
    # IDEAL_CHSH * strength in S is a half-width of `strength` in p.
    chsh_half_width = IDEAL_CHSH * strength
    chsh_rounds = math.ceil(8.0 * z * z / (chsh_half_width * chsh_half_width))

    return CheckRoundBudget(
        qber_rounds=qber_rounds,
        chsh_rounds=chsh_rounds,
        confidence=level,
        key_length=checked.key_length,
    )


def _as_positive(value: Any, name: str) -> float:
    """Coerce and check a strictly positive finite float.

    Parameters
    ----------
    value : float
        The candidate.
    name : str
        The argument name, quoted in error messages.

    Returns
    -------
    float
        ``value`` as a plain float.

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite or is not strictly positive.
    """
    if isinstance(value, bool):
        raise TypeError(
            f"{name} must be a positive real number, got the boolean {value!r}"
        )
    if not isinstance(value, numbers.Real):
        raise TypeError(
            f"{name} must be a positive real number, got "
            f"{type(value).__name__}"
        )
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise ValueError(
            f"{name} must be a finite, strictly positive resolution, got "
            f"{result!r}. It is the half-width the sample is sized to achieve, "
            f"and a non-positive one demands an infinite sample."
        )
    return result


def _as_params(params: Any) -> ProtocolParams:
    """Return ``params`` unchanged, refusing anything that is not a set of them.

    Parameters
    ----------
    params : ProtocolParams
        The candidate.

    Returns
    -------
    ProtocolParams
        ``params`` itself.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}. "
            f"Start from DEFAULT_PARAMS, CHECKED_PARAMS or DEMO_PARAMS."
        )
    return params


# --------------------------------------------------------------------------- #
# The plan                                                                     #
# --------------------------------------------------------------------------- #


class CheckRole(enum.StrEnum):
    """What a check round is spent on.

    A :class:`enum.StrEnum`, so a member *is* its label and a Phase 5 record or
    a Phase 6 dashboard row needs no bespoke encoder -- the same treatment
    :class:`~sih141.protocol.params.Party` gets.

    Attributes
    ----------
    QBER : CheckRole
        Both halves measured in the same basis from ``params.bases``; feeds
        :func:`estimate_qber`.
    CHSH : CheckRole
        The two halves measured at independently drawn Bell-test settings;
        feeds :func:`estimate_chsh`.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import CheckRole
    >>> CheckRole.QBER, str(CheckRole.CHSH)
    (<CheckRole.QBER: 'qber'>, 'chsh')
    """

    QBER = "qber"
    CHSH = "chsh"


@dataclass(frozen=True)
class QberRound:
    """One planned QBER check round: a position and the basis both wings use.

    Attributes
    ----------
    position : int
        The key index ``0 .. L-1`` this round occupies.
    basis : PauliBasis
        The basis **both** halves are measured in. Drawn uniformly from
        ``params.bases``, so the estimate averages over the same alphabet the
        key does.
    """

    position: int
    basis: PauliBasis

    def __post_init__(self) -> None:
        """Coerce the position and check the basis has a known ideal sign."""
        object.__setattr__(
            self, "position", _as_count(self.position, "position")
        )
        if not isinstance(self.basis, PauliBasis):
            object.__setattr__(
                self, "basis", PauliBasis(str(self.basis).strip().upper())
            )
        if self.basis not in IDEAL_PAULI_CORRELATION:
            raise ValueError(
                f"basis {self.basis!r} has no ideal two-wing correlation on "
                f"record, so a round in it could not be scored; expected one "
                f"of {sorted(b.value for b in IDEAL_PAULI_CORRELATION)}."
            )

    @property
    def role(self) -> CheckRole:
        """CheckRole: :attr:`CheckRole.QBER`, always."""
        return CheckRole.QBER

    @property
    def ideal_correlation(self) -> int:
        """int: The product :math:`|\\Phi^{+}\\rangle` gives in this basis.

        :data:`IDEAL_PAULI_CORRELATION` looked up for :attr:`basis`: ``+1`` for
        :math:`X` and :math:`Z`, ``-1`` for :math:`Y`.
        """
        return IDEAL_PAULI_CORRELATION[self.basis]


@dataclass(frozen=True)
class ChshRound:
    """One planned CHSH check round: a position and one setting per wing.

    Attributes
    ----------
    position : int
        The key index ``0 .. L-1`` this round occupies.
    alice_setting : int
        ``0`` or ``1``, indexing :data:`CHSH_ALICE_ANGLES`.
    recipient_setting : int
        ``0`` or ``1``, indexing :data:`CHSH_RECIPIENT_ANGLES`.
    """

    position: int
    alice_setting: int
    recipient_setting: int

    def __post_init__(self) -> None:
        """Coerce the position and check both settings index a shipped angle."""
        object.__setattr__(
            self, "position", _as_count(self.position, "position")
        )
        object.__setattr__(
            self,
            "alice_setting",
            _as_setting(self.alice_setting, "alice_setting"),
        )
        object.__setattr__(
            self,
            "recipient_setting",
            _as_setting(self.recipient_setting, "recipient_setting"),
        )

    @property
    def role(self) -> CheckRole:
        """CheckRole: :attr:`CheckRole.CHSH`, always."""
        return CheckRole.CHSH

    @property
    def cell(self) -> int:
        """int: The correlator cell ``2 * alice_setting + recipient_setting``.

        The index :class:`ChshEstimate` reports correlators and counts under,
        in the order ``E(a0,b0), E(a0,b1), E(a1,b0), E(a1,b1)``, which is the
        order the CHSH combination ``+ + + -`` is written in.
        """
        return 2 * self.alice_setting + self.recipient_setting

    @property
    def angles(self) -> tuple[float, float]:
        """tuple of float: ``(alice_angle, recipient_angle)`` in radians."""
        return (
            CHSH_ALICE_ANGLES[self.alice_setting],
            CHSH_RECIPIENT_ANGLES[self.recipient_setting],
        )


@dataclass(frozen=True)
class CheckRoundPlan:
    """Which positions of a run are check rounds, and what each one measures.

    Drawn once per message bit by :func:`draw_check_plan` from the
    **recipients'** stream, and **shared by both recipients**. Sharing is not an
    optimisation: symmetrisation (:mod:`sih141.protocol.symmetrise`) exchanges
    the two recipients' entries position by position, and verification scores
    one declaration against both records, so Bob and Charlie must retain the
    *same* positions or the two logs stop indexing the same key. The settings
    are shared with them, which is harmless -- the two links carry independent
    pairs, so the two logs are independent samples of two channels, and nothing
    on the wire reveals a setting until the pairs are already through.

    Frozen, so a plan cannot be edited between the two recipients' runs, and
    made of plain values, so it serialises.

    Attributes
    ----------
    key_length : int
        The ``L`` this plan was drawn for. A plan is only valid against a
        parameter set of the same length.
    qber_rounds : tuple of QberRound
        The QBER arm, in position order.
    chsh_rounds : tuple of ChshRound
        The CHSH arm, in position order.

    Raises
    ------
    ValueError
        If a position is out of range ``0 .. key_length - 1``, if any position
        appears twice (in either arm or across both), if the plan is empty, or
        if it designates every position -- a run with no signing positions has
        no key to sign with.

    See Also
    --------
    draw_check_plan : The only sanctioned way to build one.
    sih141.protocol.params.ProtocolParams.sifted : The parameter set the
        retained positions are verified under.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.checkrounds import draw_check_plan
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=48, check_fraction=0.25)
    >>> plan = draw_check_plan(params, rng=np.random.default_rng(11))
    >>> plan.check_count, len(plan.signing_positions)
    (12, 36)
    >>> plan.check_count == len(plan.qber_rounds) + len(plan.chsh_rounds)
    True
    >>> set(plan.positions) & set(plan.signing_positions)
    set()
    """

    key_length: int
    qber_rounds: tuple[QberRound, ...]
    chsh_rounds: tuple[ChshRound, ...]

    def __post_init__(self) -> None:
        """Coerce the fields and refuse a plan that cannot be run."""
        object.__setattr__(
            self, "key_length", _as_count(self.key_length, "key_length", minimum=1)
        )
        object.__setattr__(self, "qber_rounds", tuple(self.qber_rounds))
        object.__setattr__(self, "chsh_rounds", tuple(self.chsh_rounds))

        positions = [round_.position for round_ in self.qber_rounds]
        positions.extend(round_.position for round_ in self.chsh_rounds)
        for position in positions:
            if not 0 <= position < self.key_length:
                raise ValueError(
                    f"check-round position {position} is outside the key "
                    f"0 .. {self.key_length - 1}. A plan is drawn for one key "
                    f"length and is not portable to another; draw a fresh one "
                    f"with draw_check_plan(params, rng=...)."
                )
        if len(set(positions)) != len(positions):
            repeated = sorted({p for p in positions if positions.count(p) > 1})
            raise ValueError(
                f"check-round positions must be distinct, got repeats "
                f"{repeated}. One position carries one entanglement resource, "
                f"so it can be spent on the key or on one check round, never "
                f"on two."
            )
        if not positions:
            raise ValueError(
                "a check-round plan must designate at least one position; an "
                "empty plan estimates nothing and would publish a channel "
                "statistic with no sample behind it. Run without a plan if no "
                "estimation is wanted."
            )
        if len(positions) >= self.key_length:
            raise ValueError(
                f"a check-round plan must leave at least one signing position, "
                f"but it designates all {len(positions)} of "
                f"{self.key_length}. Check positions are excluded from the key "
                f"(see ProtocolParams.signing_length), so a plan that takes "
                f"every position leaves nothing to sign."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def check_count(self) -> int:
        """int: How many positions this plan diverts from the key."""
        return len(self.qber_rounds) + len(self.chsh_rounds)

    @property
    def signing_length(self) -> int:
        """int: How many positions survive into the key, ``L - check_count``."""
        return self.key_length - self.check_count

    @property
    def positions(self) -> tuple[int, ...]:
        """tuple of int: Every check position, ascending."""
        return tuple(
            sorted(
                [round_.position for round_ in self.qber_rounds]
                + [round_.position for round_ in self.chsh_rounds]
            )
        )

    @property
    def signing_positions(self) -> tuple[int, ...]:
        """tuple of int: Every retained position, ascending.

        The index map from the sifted key back to the distributed run: entry
        ``j`` of a sifted record was position ``signing_positions[j]`` of the
        original.
        """
        checked = set(self.positions)
        return tuple(i for i in range(self.key_length) if i not in checked)

    def is_check(self, position: int) -> bool:
        """Return whether ``position`` is a check round.

        Parameters
        ----------
        position : int
            A key index.

        Returns
        -------
        bool

        Raises
        ------
        ValueError
            If ``position`` is not an integer in range.
        """
        index = _as_count(position, "position")
        if index >= self.key_length:
            raise ValueError(
                f"position {index} is outside the key 0 .. "
                f"{self.key_length - 1}"
            )
        return index in set(self.positions)

    def round_at(self, position: int) -> QberRound | ChshRound | None:
        """Return the planned round at ``position``, or ``None`` for a key round.

        Parameters
        ----------
        position : int
            A key index.

        Returns
        -------
        QberRound or ChshRound or None

        Raises
        ------
        ValueError
            If ``position`` is not an integer in range.
        """
        index = _as_count(position, "position")
        if index >= self.key_length:
            raise ValueError(
                f"position {index} is outside the key 0 .. "
                f"{self.key_length - 1}"
            )
        return self.rounds_by_position().get(index)

    def rounds_by_position(self) -> dict[int, QberRound | ChshRound]:
        """Return the plan indexed by position, for a single pass over the run.

        :meth:`round_at` builds this on every call, which is fine for a lookup
        or two and quadratic over a whole run; a distribution loop should build
        it once and index it.
        :func:`~sih141.protocol.distribute.distribute_to_recipient_with_checks`
        does exactly that.

        Returns
        -------
        dict
            Position to planned round, for the check positions only. Key rounds
            are absent rather than mapped to ``None``, so ``get(i)`` returning
            ``None`` *is* the "this is a key round" test.
        """
        rounds: dict[int, QberRound | ChshRound] = {
            round_.position: round_ for round_ in self.qber_rounds
        }
        rounds.update({round_.position: round_ for round_ in self.chsh_rounds})
        return rounds

    # -- sifting ------------------------------------------------------------ #

    def sift_key(self, key: PrivateKey) -> PrivateKey:
        """Return ``key`` with the check positions removed.

        The retained elements are the **same objects** Alice drew, in the same
        order, re-indexed to ``0 .. signing_length - 1``. That is why excluding
        check positions cannot bias the key: no element is altered, and the
        subset is chosen by the recipients' stream, which is independent of the
        key's contents. Uniformity of the retained key is therefore a
        consequence rather than a hope, and the tests check both.

        Parameters
        ----------
        key : PrivateKey
            Alice's full-length key for one message bit.

        Returns
        -------
        PrivateKey
            A key of length :attr:`signing_length`, tagged with the same message
            bit. Check it against ``params.sifted()``, not against ``params``.

        Raises
        ------
        TypeError
            If ``key`` is not a :class:`~sih141.protocol.keys.PrivateKey`.
        ValueError
            If ``len(key)`` differs from :attr:`key_length`.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.checkrounds import draw_check_plan
        >>> from sih141.protocol.keys import generate_private_key
        >>> from sih141.protocol.params import ProtocolParams
        >>> params = ProtocolParams(key_length=48, check_fraction=0.25)
        >>> plan = draw_check_plan(params, rng=np.random.default_rng(2))
        >>> key = generate_private_key(params, 0, rng=np.random.default_rng(3))
        >>> sifted = plan.sift_key(key)
        >>> len(sifted) == params.signing_length == 36
        True
        >>> sifted.check_against(params.sifted())
        >>> all(
        ...     sifted[j] == key[i]
        ...     for j, i in enumerate(plan.signing_positions)
        ... )
        True
        """
        if not isinstance(key, PrivateKey):
            raise TypeError(
                f"key must be a PrivateKey, got {type(key).__name__}"
            )
        if len(key) != self.key_length:
            raise ValueError(
                f"key has {len(key)} elements but this plan was drawn for a key "
                f"length of {self.key_length}. A plan indexes positions of one "
                f"specific run; sifting a key of another length would silently "
                f"retain the wrong positions."
            )
        return PrivateKey(
            message_bit=key.message_bit,
            elements=tuple(key[i] for i in self.signing_positions),
        )

    def sift_record(self, record: RecipientRecord) -> RecipientRecord:
        """Return ``record`` with the check positions removed.

        The counterpart of :meth:`sift_key` for a recipient's log. Provided for
        a caller who distributed without a plan and wants to apply one after the
        fact -- :func:`~sih141.protocol.distribute.distribute_to_recipient_with_checks`
        never builds the unsifted record in the first place, because a check
        position has no key measurement to record.

        Parameters
        ----------
        record : RecipientRecord
            A full-length log.

        Returns
        -------
        RecipientRecord
            A log of length :attr:`signing_length`, carrying the same party,
            message bit and session identifier.

        Raises
        ------
        TypeError
            If ``record`` is not a
            :class:`~sih141.protocol.records.RecipientRecord`.
        ValueError
            If ``len(record)`` differs from :attr:`key_length`.
        """
        if not isinstance(record, RecipientRecord):
            raise TypeError(
                f"record must be a RecipientRecord, got "
                f"{type(record).__name__}"
            )
        if len(record) != self.key_length:
            raise ValueError(
                f"record has {len(record)} entries but this plan was drawn for "
                f"a key length of {self.key_length}."
            )
        kept = self.signing_positions
        sifted = RecipientRecord.from_measurements(
            record.party,
            record.message_bit,
            [record.bases[i] for i in kept],
            [record.eigenvalues[i] for i in kept],
        )
        return sifted.with_session_id(record.session_id)

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the plan.

        Returns
        -------
        dict
            Keys ``"key_length"``, ``"qber_rounds"`` and ``"chsh_rounds"``. The
            bases are :class:`~sih141.core.paulis.PauliBasis` members, which are
            strings, so the result passes straight to :func:`json.dumps`.

        Examples
        --------
        >>> import json
        >>> import numpy as np
        >>> from sih141.protocol.checkrounds import CheckRoundPlan, draw_check_plan
        >>> from sih141.protocol.params import ProtocolParams
        >>> params = ProtocolParams(key_length=32, check_fraction=0.25)
        >>> plan = draw_check_plan(params, rng=np.random.default_rng(5))
        >>> restored = CheckRoundPlan.from_dict(json.loads(json.dumps(plan.to_dict())))
        >>> restored == plan
        True
        """
        return {
            "key_length": self.key_length,
            "qber_rounds": [
                {"position": round_.position, "basis": round_.basis}
                for round_ in self.qber_rounds
            ],
            "chsh_rounds": [
                {
                    "position": round_.position,
                    "alice_setting": round_.alice_setting,
                    "recipient_setting": round_.recipient_setting,
                }
                for round_ in self.chsh_rounds
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CheckRoundPlan:
        """Rebuild a plan from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must carry ``"key_length"``, ``"qber_rounds"`` and
            ``"chsh_rounds"``.

        Returns
        -------
        CheckRoundPlan
            A validated instance.

        Raises
        ------
        ValueError
            If a required key is missing, if unknown keys are present, or if the
            rebuilt plan fails validation.
        """
        known = {"key_length", "qber_rounds", "chsh_rounds"}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(
                f"unknown CheckRoundPlan field(s) {unknown}; expected "
                f"{sorted(known)}."
            )
        missing = sorted(known - set(data))
        if missing:
            raise ValueError(
                f"CheckRoundPlan.from_dict requires {missing}; a plan with a "
                f"missing arm would silently estimate one statistic and report "
                f"nothing about the other."
            )
        return cls(
            key_length=data["key_length"],
            qber_rounds=tuple(
                QberRound(
                    position=entry["position"],
                    basis=PauliBasis(str(entry["basis"]).upper()),
                )
                for entry in data["qber_rounds"]
            ),
            chsh_rounds=tuple(
                ChshRound(
                    position=entry["position"],
                    alice_setting=entry["alice_setting"],
                    recipient_setting=entry["recipient_setting"],
                )
                for entry in data["chsh_rounds"]
            ),
        )


def draw_check_plan(
    params: ProtocolParams,
    *,
    rng: np.random.Generator | None = None,
    chsh_weight: float = CHECK_CHSH_WEIGHT,
) -> CheckRoundPlan:
    """Draw the check positions, their roles and their settings.

    **Give this the recipients' stream, never Alice's.** The whole value of a
    sampled estimate is that the party being estimated cannot steer the sample;
    in :class:`~sih141.protocol.session.QDSSession` terms that is
    ``self._recipient_rng``, the generator the symmetrisation coins come from
    and the one no seam is handed (:ref:`sih141.protocol.session <two-streams>`).

    Parameters
    ----------
    params : ProtocolParams
        The parameter set. Its
        :attr:`~sih141.protocol.params.ProtocolParams.check_count` fixes how
        many positions are drawn and its ``bases`` fix the QBER alphabet.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Resolved through
        :func:`sih141.core.rng.resolve_rng`.
    chsh_weight : float, optional
        Keyword-only. The share of check rounds spent on the CHSH arm; defaults
        to :data:`CHECK_CHSH_WEIGHT`. The CHSH arm takes the **floor**, so an
        odd check count spends its spare round on QBER.

    Returns
    -------
    CheckRoundPlan
        A plan for one message bit, to be shared by both recipients.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, ``chsh_weight`` is not
        a real number, or ``rng`` is neither ``None`` nor a
        :class:`numpy.random.Generator`.
    ValueError
        If ``params.check_fraction`` is ``0`` -- there is nothing to draw, and
        returning an empty plan would let a caller believe estimation was
        happening when it was not -- or if ``chsh_weight`` is outside
        ``[0, 1)``.

    Notes
    -----
    Variates consumed: one :meth:`~numpy.random.Generator.permutation` of ``L``
    to choose the positions, one uniform integer per QBER round for its basis,
    and two per CHSH round for the two settings. A permutation rather than
    repeated rejection sampling, so the count does not depend on how many
    collisions happen to occur and a seeded plan is reproducible.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.checkrounds import draw_check_plan
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=120, check_fraction=0.125)
    >>> plan = draw_check_plan(params, rng=np.random.default_rng(7))
    >>> plan.check_count, len(plan.chsh_rounds), len(plan.qber_rounds)
    (15, 7, 8)
    >>> plan.signing_length == params.signing_length == 105
    True
    >>> other = draw_check_plan(params, rng=np.random.default_rng(7))
    >>> other == plan
    True
    """
    checked = _as_params(params)
    weight = _as_unit_interval(chsh_weight, "chsh_weight", strict=False)
    if checked.check_count <= 0:
        raise ValueError(
            f"params.check_fraction is {checked.check_fraction!r}, which "
            f"designates no check rounds at L = {checked.key_length}, so there "
            f"is no plan to draw. A plan with no rounds would publish channel "
            f"statistics with an empty sample behind them. Set a check "
            f"fraction -- params.with_check_fraction(DEFAULT_CHECK_FRACTION) "
            f"-- or run without a plan if no estimation is wanted."
        )
    generator = resolve_rng(rng)

    chosen = generator.permutation(checked.key_length)[: checked.check_count]
    positions = sorted(int(index) for index in chosen)
    chsh_count = int(math.floor(weight * len(positions)))
    chsh_positions = positions[:chsh_count]
    qber_positions = positions[chsh_count:]

    alphabet = checked.bases
    qber_rounds = tuple(
        QberRound(
            position=position,
            basis=alphabet[int(generator.integers(len(alphabet)))],
        )
        for position in qber_positions
    )
    chsh_rounds = tuple(
        ChshRound(
            position=position,
            alice_setting=int(generator.integers(2)),
            recipient_setting=int(generator.integers(2)),
        )
        for position in chsh_positions
    )
    return CheckRoundPlan(
        key_length=checked.key_length,
        qber_rounds=qber_rounds,
        chsh_rounds=chsh_rounds,
    )


# --------------------------------------------------------------------------- #
# Observations                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class QberObservation:
    """What one QBER check round produced.

    Attributes
    ----------
    position : int
        The key index the round occupied.
    basis : PauliBasis
        The basis both halves were measured in.
    alice_eigenvalue : int
        Alice's outcome, ``+1`` or ``-1``.
    recipient_eigenvalue : int
        The recipient's outcome, ``+1`` or ``-1``.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis
    >>> from sih141.protocol.checkrounds import QberObservation
    >>> QberObservation(0, PauliBasis.Y, 1, -1).is_error
    False
    >>> QberObservation(0, PauliBasis.Y, 1, 1).is_error
    True
    """

    position: int
    basis: PauliBasis
    alice_eigenvalue: int
    recipient_eigenvalue: int

    def __post_init__(self) -> None:
        """Coerce and validate the two outcomes and the basis."""
        object.__setattr__(
            self, "position", _as_count(self.position, "position")
        )
        if not isinstance(self.basis, PauliBasis):
            object.__setattr__(
                self, "basis", PauliBasis(str(self.basis).strip().upper())
            )
        if self.basis not in IDEAL_PAULI_CORRELATION:
            raise ValueError(
                f"basis {self.basis!r} has no ideal two-wing correlation on "
                f"record; expected one of "
                f"{sorted(b.value for b in IDEAL_PAULI_CORRELATION)}."
            )
        object.__setattr__(
            self,
            "alice_eigenvalue",
            _as_eigenvalue_outcome(self.alice_eigenvalue, "alice_eigenvalue"),
        )
        object.__setattr__(
            self,
            "recipient_eigenvalue",
            _as_eigenvalue_outcome(
                self.recipient_eigenvalue, "recipient_eigenvalue"
            ),
        )

    @property
    def correlation(self) -> int:
        """int: The product of the two outcomes, ``+1`` or ``-1``."""
        return self.alice_eigenvalue * self.recipient_eigenvalue

    @property
    def is_error(self) -> bool:
        """bool: Whether the product disagrees with the ideal sign.

        The ideal sign is :data:`IDEAL_PAULI_CORRELATION` for :attr:`basis`, so
        a :math:`Y` round errs when the outcomes **agree**. Getting that
        backwards is the single most likely bug in a QBER arm and the reason the
        sign lives in a table rather than in a comparison.
        """
        return self.correlation != IDEAL_PAULI_CORRELATION[self.basis]


@dataclass(frozen=True)
class ChshObservation:
    """What one CHSH check round produced.

    Attributes
    ----------
    position : int
        The key index the round occupied.
    alice_setting : int
        ``0`` or ``1``, indexing :data:`CHSH_ALICE_ANGLES`.
    recipient_setting : int
        ``0`` or ``1``, indexing :data:`CHSH_RECIPIENT_ANGLES`.
    alice_eigenvalue : int
        Alice's outcome, ``+1`` or ``-1``.
    recipient_eigenvalue : int
        The recipient's outcome, ``+1`` or ``-1``.
    """

    position: int
    alice_setting: int
    recipient_setting: int
    alice_eigenvalue: int
    recipient_eigenvalue: int

    def __post_init__(self) -> None:
        """Coerce and validate the settings and the two outcomes."""
        object.__setattr__(
            self, "position", _as_count(self.position, "position")
        )
        object.__setattr__(
            self,
            "alice_setting",
            _as_setting(self.alice_setting, "alice_setting"),
        )
        object.__setattr__(
            self,
            "recipient_setting",
            _as_setting(self.recipient_setting, "recipient_setting"),
        )
        object.__setattr__(
            self,
            "alice_eigenvalue",
            _as_eigenvalue_outcome(self.alice_eigenvalue, "alice_eigenvalue"),
        )
        object.__setattr__(
            self,
            "recipient_eigenvalue",
            _as_eigenvalue_outcome(
                self.recipient_eigenvalue, "recipient_eigenvalue"
            ),
        )

    @property
    def correlation(self) -> int:
        """int: The product of the two outcomes, ``+1`` or ``-1``."""
        return self.alice_eigenvalue * self.recipient_eigenvalue

    @property
    def cell(self) -> int:
        """int: ``2 * alice_setting + recipient_setting``, the correlator cell."""
        return 2 * self.alice_setting + self.recipient_setting


@dataclass(frozen=True)
class CheckLog:
    """Every check-round observation one recipient made on one message bit.

    What gets published. It carries no key material by construction: the
    positions in it were spent on measurement, so they are exactly the positions
    the key does *not* contain.

    Attributes
    ----------
    party : Party
        The recipient whose link these rounds tested. Alice is refused: a check
        round is a statement about one link, and she is at the other end of both.
    message_bit : int
        Which of the two distributions these rounds belong to.
    qber : tuple of QberObservation
        The QBER arm, in position order.
    chsh : tuple of ChshObservation
        The CHSH arm, in position order.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party, or if ``message_bit`` is not
        ``0``/``1``.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import CheckLog
    >>> from sih141.protocol.params import Party
    >>> log = CheckLog(Party.BOB, 0, (), ())
    >>> log.round_count
    0
    """

    party: Party
    message_bit: int
    qber: tuple[QberObservation, ...]
    chsh: tuple[ChshObservation, ...]

    def __post_init__(self) -> None:
        """Coerce the tags and refuse Alice."""
        resolved = _as_party(self.party)
        if resolved is Party.ALICE:
            raise ValueError(
                "a CheckLog belongs to a recipient, not to Alice: a check round "
                "measures one link, and she is the common endpoint of both. "
                "Tag it Party.BOB or Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        object.__setattr__(self, "qber", tuple(self.qber))
        object.__setattr__(self, "chsh", tuple(self.chsh))

    @property
    def round_count(self) -> int:
        """int: How many check rounds this log records, both arms together."""
        return len(self.qber) + len(self.chsh)

    @property
    def positions(self) -> tuple[int, ...]:
        """tuple of int: Every observed check position, ascending."""
        return tuple(
            sorted(
                [entry.position for entry in self.qber]
                + [entry.position for entry in self.chsh]
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the log.

        This is what "published" means: the whole object, raw observations and
        all, so that anyone can recompute the estimate rather than take a
        reported number on trust. Publishing the estimate alone would make the
        interval unauditable.

        Returns
        -------
        dict
            Keys ``"party"``, ``"message_bit"``, ``"qber"`` and ``"chsh"``.

        Examples
        --------
        >>> import json
        >>> from sih141.core.paulis import PauliBasis
        >>> from sih141.protocol.checkrounds import CheckLog, QberObservation
        >>> from sih141.protocol.params import Party
        >>> log = CheckLog(
        ...     Party.CHARLIE, 1, (QberObservation(4, PauliBasis.Y, 1, -1),), ()
        ... )
        >>> CheckLog.from_dict(json.loads(json.dumps(log.to_dict()))) == log
        True
        """
        return {
            "party": self.party,
            "message_bit": self.message_bit,
            "qber": [
                {
                    "position": entry.position,
                    "basis": entry.basis,
                    "alice_eigenvalue": entry.alice_eigenvalue,
                    "recipient_eigenvalue": entry.recipient_eigenvalue,
                }
                for entry in self.qber
            ],
            "chsh": [
                {
                    "position": entry.position,
                    "alice_setting": entry.alice_setting,
                    "recipient_setting": entry.recipient_setting,
                    "alice_eigenvalue": entry.alice_eigenvalue,
                    "recipient_eigenvalue": entry.recipient_eigenvalue,
                }
                for entry in self.chsh
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CheckLog:
        """Rebuild a log from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must carry ``"party"``, ``"message_bit"``, ``"qber"`` and
            ``"chsh"``.

        Returns
        -------
        CheckLog
            A validated instance, from which
            :func:`estimate_qber` and :func:`estimate_chsh` reproduce the
            published numbers exactly.

        Raises
        ------
        ValueError
            If a required key is missing, if unknown keys are present, or if the
            rebuilt log fails validation.
        """
        known = {"party", "message_bit", "qber", "chsh"}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(
                f"unknown CheckLog field(s) {unknown}; expected {sorted(known)}."
            )
        missing = sorted(known - set(data))
        if missing:
            raise ValueError(
                f"CheckLog.from_dict requires {missing}; a log with a missing "
                f"arm would restore as though that arm had produced no rounds, "
                f"which is the one thing an empty sample must never be "
                f"confused with."
            )
        return cls(
            party=data["party"],
            message_bit=data["message_bit"],
            qber=tuple(
                QberObservation(
                    position=entry["position"],
                    basis=PauliBasis(str(entry["basis"]).upper()),
                    alice_eigenvalue=entry["alice_eigenvalue"],
                    recipient_eigenvalue=entry["recipient_eigenvalue"],
                )
                for entry in data["qber"]
            ),
            chsh=tuple(
                ChshObservation(
                    position=entry["position"],
                    alice_setting=entry["alice_setting"],
                    recipient_setting=entry["recipient_setting"],
                    alice_eigenvalue=entry["alice_eigenvalue"],
                    recipient_eigenvalue=entry["recipient_eigenvalue"],
                )
                for entry in data["chsh"]
            ),
        )


# --------------------------------------------------------------------------- #
# The physics of one check round                                               #
# --------------------------------------------------------------------------- #


def _rotation(angle: float) -> Operator:
    """Return the unitary carrying an :math:`x`-:math:`z` axis onto :math:`Z`.

    Measuring the observable :math:`\\cos\\theta\\,Z + \\sin\\theta\\,X` is the
    same as evolving by :math:`R_y(-\\theta)` and measuring :math:`Z`, because
    :math:`R_y(\\theta) Z R_y(\\theta)^{\\dagger} = \\cos\\theta\\,Z +
    \\sin\\theta\\,X`.

    Parameters
    ----------
    angle : float
        ``theta``, in radians, measured from the :math:`Z` axis towards
        :math:`X`.

    Returns
    -------
    qiskit.quantum_info.Operator
        :math:`R_y(-\\theta)`.
    """
    half = -angle / 2.0
    cosine, sine = math.cos(half), math.sin(half)
    return Operator(
        np.array([[cosine, -sine], [sine, cosine]], dtype=complex)
    )


def _as_resource(resource: StateLike) -> DensityMatrix:
    """Coerce and check a two-qubit entanglement resource.

    Parameters
    ----------
    resource : StateLike
        A :class:`~qiskit.quantum_info.Statevector`, a
        :class:`~qiskit.quantum_info.DensityMatrix` or a raw array (D1).

    Returns
    -------
    qiskit.quantum_info.DensityMatrix
        The validated pair.

    Raises
    ------
    ValueError
        If ``resource`` is ``None`` -- which
        :func:`~sih141.core.teleport.teleport` reads as "use the ideal pair", so
        forwarding it here would let a mis-wired attack look like a clean
        channel -- or is not a physical two-qubit state.
    """
    if resource is None:
        raise ValueError(
            "a check round needs an explicit two-qubit entanglement resource; "
            "None is teleport()'s way of asking for the ideal |Phi+> pair and "
            "is not accepted here, because a mis-wired attack would then be "
            "indistinguishable from a clean channel. Pass ideal_resource() if "
            "a clean pair is what you meant."
        )
    state = as_density(resource)
    if state.num_qubits != 2:
        raise ValueError(
            f"a check round measures the two halves of one entanglement "
            f"resource, so it needs a two-qubit state, got "
            f"{state.num_qubits}. Qubit 0 is Alice's half and qubit 1 the "
            f"recipient's, matching the register teleport() builds."
        )
    return state


def _measure_both_wings(
    resource: StateLike,
    alice_basis: PauliBasis,
    recipient_basis: PauliBasis,
    *,
    alice_angle: float = 0.0,
    recipient_angle: float = 0.0,
    rng: np.random.Generator | None = None,
) -> tuple[int, int]:
    """Measure both halves of a pair and return the two eigenvalues.

    Alice's half is qubit ``0`` and the recipient's is qubit ``1`` (D2). The
    two measurements are made **sequentially on the collapsing register**, so
    the recipient's outcome is drawn from its correct conditional distribution
    rather than from a marginal -- which for an entangled pair is the whole
    point.

    Parameters
    ----------
    resource : StateLike
        The two-qubit pair.
    alice_basis, recipient_basis : PauliBasis
        The Pauli each wing is read out in *after* its rotation. For the CHSH
        arm both are :attr:`~sih141.core.paulis.PauliBasis.Z` and the angles do
        the work; for the QBER arm both are the drawn basis and the angles are
        zero.
    alice_angle, recipient_angle : float, optional
        Keyword-only. Rotations applied before readout, in the
        :math:`x`-:math:`z` plane.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). **Exactly two** variates are consumed, one per wing.

    Returns
    -------
    tuple of int
        ``(alice_eigenvalue, recipient_eigenvalue)``, each ``+1`` or ``-1``.
    """
    state: DensityMatrix = _as_resource(resource)
    if alice_angle:
        state = state.evolve(_rotation(alice_angle), qargs=[_ALICE_QUBIT])
    if recipient_angle:
        state = state.evolve(
            _rotation(recipient_angle), qargs=[_RECIPIENT_QUBIT]
        )
    generator = resolve_rng(rng)
    alice = projective_measure(state, _ALICE_QUBIT, alice_basis, rng=generator)
    recipient = projective_measure(
        alice.post_state, _RECIPIENT_QUBIT, recipient_basis, rng=generator
    )
    return alice.eigenvalue, recipient.eigenvalue


def observe_qber_round(
    resource: StateLike,
    round_: QberRound,
    *,
    rng: np.random.Generator | None = None,
) -> QberObservation:
    """Spend one pair on a matched-basis correlation measurement.

    Both halves are measured in ``round_.basis``. On the ideal pair the product
    of the two outcomes is :data:`IDEAL_PAULI_CORRELATION` with probability one,
    so an error is a deviation of the resource -- and, by the identity derived
    in the module docstring under :ref:`check-round-qber-identity`, exactly the
    rate at which a *matched key position* over that resource would mismatch.

    Parameters
    ----------
    resource : StateLike
        The two-qubit pair, as handed over by the ``resource_factory`` seam.
    round_ : QberRound
        The planned round: its position and basis.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Exactly two variates are consumed.

    Returns
    -------
    QberObservation
        The two outcomes, tagged with the position and basis.

    Raises
    ------
    TypeError
        If ``round_`` is not a :class:`QberRound`.
    ValueError
        If ``resource`` is ``None`` or is not a physical two-qubit state.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.paulis import PauliBasis
    >>> from sih141.core.states import BellState, bell_state
    >>> from sih141.protocol.checkrounds import QberRound, observe_qber_round
    >>> pair = bell_state(BellState.PHI_PLUS)
    >>> rng = np.random.default_rng(19)
    >>> [
    ...     observe_qber_round(pair, QberRound(0, basis), rng=rng).is_error
    ...     for basis in (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)
    ... ]
    [False, False, False]
    """
    if not isinstance(round_, QberRound):
        raise TypeError(
            f"round_ must be a QberRound, got {type(round_).__name__}. Draw "
            f"one with draw_check_plan(params, rng=...)."
        )
    alice, recipient = _measure_both_wings(
        resource, round_.basis, round_.basis, rng=rng
    )
    return QberObservation(
        position=round_.position,
        basis=round_.basis,
        alice_eigenvalue=alice,
        recipient_eigenvalue=recipient,
    )


def observe_chsh_round(
    resource: StateLike,
    round_: ChshRound,
    *,
    rng: np.random.Generator | None = None,
) -> ChshObservation:
    """Spend one pair on one cell of the CHSH inequality.

    Each wing is rotated to its planned setting and read out in :math:`Z`; the
    product of the two eigenvalues is one sample of the correlator
    ``E(a_i, b_j)``.

    Parameters
    ----------
    resource : StateLike
        The two-qubit pair.
    round_ : ChshRound
        The planned round: its position and the two setting indices.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Exactly two variates are consumed.

    Returns
    -------
    ChshObservation
        The two outcomes, tagged with the position and the settings.

    Raises
    ------
    TypeError
        If ``round_`` is not a :class:`ChshRound`.
    ValueError
        If ``resource`` is ``None`` or is not a physical two-qubit state.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.states import BellState, bell_state
    >>> from sih141.protocol.checkrounds import ChshRound, observe_chsh_round
    >>> observation = observe_chsh_round(
    ...     bell_state(BellState.PHI_PLUS),
    ...     ChshRound(3, 0, 0),
    ...     rng=np.random.default_rng(23),
    ... )
    >>> observation.cell, observation.correlation in (1, -1)
    (0, True)
    """
    if not isinstance(round_, ChshRound):
        raise TypeError(
            f"round_ must be a ChshRound, got {type(round_).__name__}. Draw "
            f"one with draw_check_plan(params, rng=...)."
        )
    alice_angle, recipient_angle = round_.angles
    alice, recipient = _measure_both_wings(
        resource,
        PauliBasis.Z,
        PauliBasis.Z,
        alice_angle=alice_angle,
        recipient_angle=recipient_angle,
        rng=rng,
    )
    return ChshObservation(
        position=round_.position,
        alice_setting=round_.alice_setting,
        recipient_setting=round_.recipient_setting,
        alice_eigenvalue=alice,
        recipient_eigenvalue=recipient,
    )


# --------------------------------------------------------------------------- #
# Intervals and estimates                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Interval:
    """A two-sided confidence interval, with the method that produced it.

    The method is part of the value rather than a footnote, because the two on
    offer answer different questions: ``"wilson"``/``"normal"`` are calibrated
    (coverage close to the stated level) and ``"hoeffding"`` is a genuine
    distribution-free *bound* (coverage at least the stated level, usually far
    more). A report that mixes them without saying which is which is not
    reporting a confidence level at all.

    Attributes
    ----------
    low, high : float
        The endpoints, ``low <= high``.
    confidence : float
        The nominal two-sided coverage.
    method : str
        How it was built.

    Raises
    ------
    ValueError
        If the endpoints are not finite and ordered, or ``confidence`` is
        outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import Interval
    >>> interval = Interval(0.01, 0.03, 0.99, "wilson")
    >>> interval.covers(0.02), interval.covers(0.05)
    (True, False)
    >>> f"{interval.half_width:.4f}"
    '0.0100'
    """

    low: float
    high: float
    confidence: float
    method: str

    def __post_init__(self) -> None:
        """Coerce the endpoints and check they are ordered and finite."""
        object.__setattr__(self, "low", float(self.low))
        object.__setattr__(self, "high", float(self.high))
        object.__setattr__(
            self,
            "confidence",
            _as_unit_interval(self.confidence, "confidence", strict=True),
        )
        object.__setattr__(self, "method", str(self.method))
        if not (math.isfinite(self.low) and math.isfinite(self.high)):
            raise ValueError(
                f"interval endpoints must be finite, got "
                f"[{self.low!r}, {self.high!r}]"
            )
        if self.low > self.high:
            raise ValueError(
                f"interval endpoints must satisfy low <= high, got "
                f"[{self.low!r}, {self.high!r}]"
            )

    @property
    def width(self) -> float:
        """float: ``high - low``."""
        return self.high - self.low

    @property
    def half_width(self) -> float:
        """float: Half the width, the usual "+/-" a report quotes."""
        return 0.5 * self.width

    def covers(self, value: float) -> bool:
        """Return whether ``value`` lies inside the closed interval.

        Parameters
        ----------
        value : float
            The candidate, typically a truth being checked against or a
            prediction being tested.

        Returns
        -------
        bool
        """
        return self.low <= float(value) <= self.high

    def excludes(self, value: float) -> bool:
        """Return whether ``value`` lies strictly outside the interval.

        The negation of :meth:`covers`, spelled out because "the interval
        excludes the classical bound" is the sentence a Bell test exists to
        license and reads badly as ``not covers``.

        Parameters
        ----------
        value : float
            The candidate.

        Returns
        -------
        bool
        """
        return not self.covers(value)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the interval.

        Returns
        -------
        dict
            Keys ``"low"``, ``"high"``, ``"confidence"``, ``"method"``.
        """
        return {
            "low": self.low,
            "high": self.high,
            "confidence": self.confidence,
            "method": self.method,
        }


@dataclass(frozen=True)
class QberEstimate:
    """The QBER arm's answer: a rate, an interval, and the sample behind them.

    Attributes
    ----------
    errors : int
        Rounds whose product disagreed with the ideal sign.
    rounds : int
        Rounds in the sample.
    interval : Interval
        The confidence interval on the underlying rate.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import Interval, QberEstimate
    >>> estimate = QberEstimate(30, 2000, Interval(0.010, 0.022, 0.99, "wilson"))
    >>> estimate.estimate
    0.015
    >>> estimate.within_budget(1 / 64)
    False
    >>> estimate.within_budget(1 / 16)
    True
    """

    errors: int
    rounds: int
    interval: Interval

    def __post_init__(self) -> None:
        """Coerce the counts and check the sample is self-consistent."""
        object.__setattr__(self, "errors", _as_count(self.errors, "errors"))
        object.__setattr__(
            self, "rounds", _as_count(self.rounds, "rounds", minimum=1)
        )
        if self.errors > self.rounds:
            raise ValueError(
                f"errors ({self.errors}) cannot exceed rounds ({self.rounds}); "
                f"a rate above 1 is not a rate."
            )

    @property
    def estimate(self) -> float:
        """float: The point estimate ``errors / rounds``."""
        return self.errors / self.rounds

    @property
    def half_width(self) -> float:
        """float: The interval's half-width."""
        return self.interval.half_width

    def within_budget(self, threshold: float) -> bool:
        """Return whether the whole interval sits at or below ``threshold``.

        The conservative reading, and the one a decision should use: the channel
        is inside the budget only if the *upper* limit is, so sampling error
        counts against the claim rather than for it.

        Parameters
        ----------
        threshold : float
            The budget, typically ``params.s_a``.

        Returns
        -------
        bool
        """
        return self.interval.high <= float(threshold)

    def implied_depolarising(self) -> Interval:
        """Map the rate interval to one on the depolarising strength ``p``.

        ``p = 2 q`` -- the inverse of
        :func:`~sih141.protocol.analysis.depolarising_error_rate` -- applied to
        both endpoints. The map is increasing and affine, so the transformed
        interval has exactly the same coverage.

        Returns
        -------
        Interval
            On ``p``, clipped to ``[0, 1]``.
        """
        return Interval(
            low=min(1.0, max(0.0, 2.0 * self.interval.low)),
            high=min(1.0, max(0.0, 2.0 * self.interval.high)),
            confidence=self.interval.confidence,
            method=self.interval.method,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the estimate.

        Returns
        -------
        dict
            Keys ``"errors"``, ``"rounds"``, ``"estimate"``, ``"interval"``.
        """
        return {
            "errors": self.errors,
            "rounds": self.rounds,
            "estimate": self.estimate,
            "interval": self.interval.to_dict(),
        }


@dataclass(frozen=True)
class ChshEstimate:
    """The CHSH arm's answer: four correlators, the statistic, and an interval.

    Attributes
    ----------
    correlators : tuple of float
        ``(E(a0,b0), E(a0,b1), E(a1,b0), E(a1,b1))``, in cell order.
    counts : tuple of int
        How many rounds landed in each cell, same order.
    interval : Interval
        The confidence interval on ``S``.

    Examples
    --------
    >>> from sih141.protocol.checkrounds import ChshEstimate, Interval
    >>> estimate = ChshEstimate(
    ...     (0.70, 0.71, 0.70, -0.71),
    ...     (500, 500, 500, 500),
    ...     Interval(2.74, 2.90, 0.99, "normal"),
    ... )
    >>> f"{estimate.statistic:.2f}"
    '2.82'
    >>> estimate.violates_classical_bound, estimate.consistent_with_ideal
    (True, True)
    """

    correlators: tuple[float, float, float, float]
    counts: tuple[int, int, int, int]
    interval: Interval

    def __post_init__(self) -> None:
        """Coerce the four cells and check they are correlators."""
        correlators = tuple(float(value) for value in self.correlators)
        counts = tuple(_as_count(value, "counts entry") for value in self.counts)
        if len(correlators) != 4 or len(counts) != 4:
            raise ValueError(
                f"a CHSH estimate has exactly four cells -- two settings per "
                f"wing -- got {len(correlators)} correlators and "
                f"{len(counts)} counts."
            )
        for value in correlators:
            if not math.isfinite(value) or not -1.0 <= value <= 1.0:
                raise ValueError(
                    f"each correlator is a mean of +-1 products and must lie "
                    f"in [-1, 1], got {value!r}"
                )
        object.__setattr__(self, "correlators", correlators)
        object.__setattr__(self, "counts", counts)

    @property
    def statistic(self) -> float:
        """float: ``S = E(a0,b0) + E(a0,b1) + E(a1,b0) - E(a1,b1)``.

        The sign pattern ``+ + + -`` is what makes the combination a CHSH
        expression; the minus sits on the last cell, which is the pairing whose
        ideal correlator is ``-1/sqrt(2)``.
        """
        first, second, third, fourth = self.correlators
        return first + second + third - fourth

    @property
    def rounds(self) -> int:
        """int: The whole CHSH sample, summed over the four cells."""
        return sum(self.counts)

    @property
    def violates_classical_bound(self) -> bool:
        """bool: Whether the interval sits strictly above ``2``.

        The claim "the resource was entangled when it arrived", stated so that
        sampling error counts against it: the *lower* limit has to clear
        :data:`CLASSICAL_CHSH_BOUND`, not the point estimate.
        """
        return self.interval.low > CLASSICAL_CHSH_BOUND

    @property
    def consistent_with_ideal(self) -> bool:
        """bool: Whether the interval covers :data:`IDEAL_CHSH`.

        The honest-channel test. ``False`` says the deviation from
        ``2 sqrt(2)`` is larger than sampling noise explains -- which is the
        question Phase 4 asks of every channel it attacks.
        """
        return self.interval.covers(IDEAL_CHSH)

    def implied_depolarising(self) -> Interval:
        """Map the ``S`` interval to one on the depolarising strength ``p``.

        Inverts :func:`depolarising_chsh`: ``p = 1 - S / (2 sqrt(2))``. The map
        is affine and *decreasing*, so the endpoints swap; the transformed
        interval has the same coverage **for a resource that really is Werner**,
        and none at all for one that is not. That caveat is the whole content of
        the method: it converts a Bell-test number into the language ``s_a`` is
        written in, under a stated model, and clips to ``[0, 1]`` because ``p``
        is a probability.

        Returns
        -------
        Interval
            On ``p``.
        """
        low = 1.0 - self.interval.high / IDEAL_CHSH
        high = 1.0 - self.interval.low / IDEAL_CHSH
        return Interval(
            low=min(1.0, max(0.0, low)),
            high=min(1.0, max(0.0, high)),
            confidence=self.interval.confidence,
            method=self.interval.method,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the estimate.

        Returns
        -------
        dict
            Keys ``"correlators"``, ``"counts"``, ``"statistic"``,
            ``"interval"``.
        """
        return {
            "correlators": list(self.correlators),
            "counts": list(self.counts),
            "statistic": self.statistic,
            "interval": self.interval.to_dict(),
        }


def estimate_qber(
    observations: Iterable[QberObservation],
    *,
    confidence: float = CHECK_CONFIDENCE,
    method: QberMethod = "wilson",
) -> QberEstimate:
    """Estimate the channel's error rate from the QBER arm, with an interval.

    Parameters
    ----------
    observations : iterable of QberObservation
        The sample. Logs from several recipients or several message bits may be
        chained -- ``estimate_qber(bob.qber + charlie.qber)`` -- but only if the
        links being pooled are believed to be the same channel; two different
        links pooled into one rate report the average of two things and detect
        neither.
    confidence : float, optional
        Keyword-only. Two-sided level. Defaults to :data:`CHECK_CONFIDENCE`.
    method : {'wilson', 'hoeffding'}, optional
        Keyword-only. ``'wilson'`` (default) is the score interval: closed form,
        coverage close to nominal, and well behaved at rates near ``0`` where a
        Wald interval collapses to a point and covers nothing. ``'hoeffding'``
        is the distribution-free bound ``q +- sqrt(ln(2/alpha) / (2n))``, valid
        at every ``n`` with coverage *at least* the stated level -- use it when
        the number is going into a security claim rather than a report.

    Returns
    -------
    QberEstimate
        The count, the sample size and the interval.

    Raises
    ------
    TypeError
        If an element is not a :class:`QberObservation`.
    ValueError
        If the sample is empty -- a rate needs a denominator, the same rule
        :func:`sih141.protocol.verify.verify` applies to matched sets -- if
        ``confidence`` is outside ``(0, 1)``, or if ``method`` is unknown.

    Notes
    -----
    The Wilson interval is
    ``(k + z^2/2) / (n + z^2)  +-  z/(n + z^2) sqrt(k(n-k)/n + z^2/4)``, which is
    the exact inversion of the score test and needs no continuity correction to
    behave at the boundaries. At ``k = 0`` it returns ``[0, z^2/(n + z^2)]``,
    which is the right answer -- "no errors seen, so the rate is below about
    ``z^2/n``" -- where a Wald interval would return the point ``[0, 0]`` and
    claim certainty from an absence.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis
    >>> from sih141.protocol.checkrounds import QberObservation, estimate_qber
    >>> clean = [
    ...     QberObservation(i, PauliBasis.Z, 1, 1) for i in range(400)
    ... ]
    >>> estimate = estimate_qber(clean)
    >>> estimate.errors, estimate.estimate
    (0, 0.0)
    >>> estimate.interval.low
    0.0
    >>> f"{estimate.interval.high:.4f}"
    '0.0163'
    >>> wide = estimate_qber(clean, method="hoeffding")
    >>> wide.half_width > estimate.half_width
    True
    """
    sample = list(observations)
    for entry in sample:
        if not isinstance(entry, QberObservation):
            raise TypeError(
                f"every element must be a QberObservation, got "
                f"{type(entry).__name__}. The QBER arm and the CHSH arm are "
                f"different measurements and cannot be pooled."
            )
    rounds = len(sample)
    if rounds == 0:
        raise ValueError(
            "cannot estimate a QBER from an empty sample: a rate needs a "
            "denominator. Draw a plan with a positive check fraction, or do "
            "not publish a channel statistic for this run."
        )
    level = _as_unit_interval(confidence, "confidence", strict=True)
    chosen = _as_qber_method(method)
    errors = sum(1 for entry in sample if entry.is_error)

    if chosen == "wilson":
        low, high = _wilson_interval(errors, rounds, level)
    else:
        low, high = _hoeffding_rate_interval(errors, rounds, level)
    return QberEstimate(
        errors=errors,
        rounds=rounds,
        interval=Interval(
            low=low, high=high, confidence=level, method=chosen
        ),
    )


def _as_qber_method(method: Any) -> QberMethod:
    """Validate the QBER interval method.

    Parameters
    ----------
    method : str
        The candidate.

    Returns
    -------
    str
        The method, lower-cased.

    Raises
    ------
    ValueError
        If ``method`` names neither interval.
    TypeError
        If ``method`` is not a string.
    """
    if not isinstance(method, str):
        raise TypeError(
            f"method must be a string, got {type(method).__name__}"
        )
    chosen = method.strip().lower()
    if chosen not in _QBER_METHODS:
        raise ValueError(
            f"unknown QBER interval method {method!r}; expected 'wilson' (the "
            f"calibrated score interval, for reporting) or 'hoeffding' (the "
            f"distribution-free bound, for a security claim)."
        )
    return chosen  # type: ignore[return-value]


def _wilson_interval(
    errors: int, rounds: int, confidence: float
) -> tuple[float, float]:
    """Return the Wilson score interval for a binomial proportion.

    Parameters
    ----------
    errors : int
        Successes observed.
    rounds : int
        Trials.
    confidence : float
        Two-sided level.

    Returns
    -------
    tuple of float
        ``(low, high)``, clipped to ``[0, 1]``.
    """
    z = _two_sided_z(confidence)
    z_squared = z * z
    denominator = rounds + z_squared
    centre = (errors + z_squared / 2.0) / denominator
    spread = (
        z
        / denominator
        * math.sqrt(
            errors * (rounds - errors) / rounds + z_squared / 4.0
        )
    )
    return max(0.0, centre - spread), min(1.0, centre + spread)


def _hoeffding_rate_interval(
    errors: int, rounds: int, confidence: float
) -> tuple[float, float]:
    """Return the distribution-free Hoeffding interval for a proportion.

    Parameters
    ----------
    errors : int
        Successes observed.
    rounds : int
        Trials.
    confidence : float
        Two-sided level; the tail budget ``alpha = 1 - confidence`` is split
        evenly between the two sides.

    Returns
    -------
    tuple of float
        ``(low, high)``, clipped to ``[0, 1]``.
    """
    alpha = 1.0 - confidence
    half = math.sqrt(math.log(2.0 / alpha) / (2.0 * rounds))
    estimate = errors / rounds
    return max(0.0, estimate - half), min(1.0, estimate + half)


def estimate_chsh(
    observations: Iterable[ChshObservation],
    *,
    confidence: float = CHECK_CONFIDENCE,
    method: ChshMethod = "normal",
) -> ChshEstimate:
    """Estimate the CHSH statistic from the Bell-test arm, with an interval.

    Parameters
    ----------
    observations : iterable of ChshObservation
        The sample. The four cells are disjoint sets of rounds, hence
        independent, which is what lets their variances be added.
    confidence : float, optional
        Keyword-only. Two-sided level. Defaults to :data:`CHECK_CONFIDENCE`.
    method : {'normal', 'hoeffding'}, optional
        Keyword-only. ``'normal'`` (default) uses the four cells' plug-in
        variances, ``Var(S) = sum (1 - E^2) / n``: calibrated, and the form the
        sample sizes in :func:`required_check_rounds` were derived from.
        ``'hoeffding'`` sums a per-cell distribution-free half-width
        ``sqrt(2 ln(8/alpha) / n)`` -- the ``8`` is a union bound over four cells
        and two tails -- giving coverage at least the stated level at every
        ``n``.

    Returns
    -------
    ChshEstimate
        The four correlators, their counts and the interval on ``S``.

    Raises
    ------
    TypeError
        If an element is not a :class:`ChshObservation`.
    ValueError
        If any of the four cells is empty -- a correlator with no rounds behind
        it is not zero, it is undefined, and treating it as zero would report a
        two-setting experiment as a CHSH test -- if ``confidence`` is outside
        ``(0, 1)``, or if ``method`` is unknown.

    Notes
    -----
    The interval is clipped to the **algebraic** range ``[-4, 4]`` and not to
    Tsirelson's ``+-2 sqrt(2)``. Quantum mechanics bounds the *true* statistic
    by ``2 sqrt(2)``, but the *estimate* may exceed it by sampling noise, and an
    interval clipped at the quantum bound would assume the conclusion the test
    exists to check -- a resource that is somehow super-quantum, or an
    experimenter's error that mimics one, would be silently rendered as "exactly
    at Tsirelson".

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.states import BellState, bell_state
    >>> from sih141.protocol.checkrounds import (
    ...     ChshRound, estimate_chsh, observe_chsh_round
    ... )
    >>> rng = np.random.default_rng(2026)
    >>> pair = bell_state(BellState.PHI_PLUS)
    >>> sample = [
    ...     observe_chsh_round(
    ...         pair, ChshRound(i, i // 2 % 2, i % 2), rng=rng
    ...     )
    ...     for i in range(2000)
    ... ]
    >>> estimate = estimate_chsh(sample)
    >>> estimate.violates_classical_bound, estimate.consistent_with_ideal
    (True, True)
    >>> estimate.counts
    (500, 500, 500, 500)
    """
    sample = list(observations)
    for entry in sample:
        if not isinstance(entry, ChshObservation):
            raise TypeError(
                f"every element must be a ChshObservation, got "
                f"{type(entry).__name__}. The QBER arm and the CHSH arm are "
                f"different measurements and cannot be pooled."
            )
    level = _as_unit_interval(confidence, "confidence", strict=True)
    chosen = _as_chsh_method(method)

    totals = [0, 0, 0, 0]
    counts = [0, 0, 0, 0]
    for entry in sample:
        totals[entry.cell] += entry.correlation
        counts[entry.cell] += 1
    empty = [cell for cell, count in enumerate(counts) if count == 0]
    if empty:
        raise ValueError(
            f"CHSH cell(s) {empty} have no rounds, so their correlators are "
            f"undefined; the statistic needs all four of E(a0,b0), E(a0,b1), "
            f"E(a1,b0) and E(a1,b1). Treating an empty cell as 0 would report "
            f"a two-setting experiment as a Bell test. The sample of "
            f"{len(sample)} round(s) is either too small or was drawn with a "
            f"degenerate setting distribution."
        )
    correlators = tuple(
        total / count for total, count in zip(totals, counts, strict=True)
    )

    statistic = correlators[0] + correlators[1] + correlators[2] - correlators[3]
    if chosen == "normal":
        z = _two_sided_z(level)
        variance = sum(
            (1.0 - value * value) / count
            for value, count in zip(correlators, counts, strict=True)
        )
        half = z * math.sqrt(variance)
    else:
        alpha = 1.0 - level
        half = sum(
            math.sqrt(2.0 * math.log(8.0 / alpha) / count) for count in counts
        )
    return ChshEstimate(
        correlators=correlators,  # type: ignore[arg-type]
        counts=tuple(counts),  # type: ignore[arg-type]
        interval=Interval(
            low=max(-_CHSH_ALGEBRAIC_BOUND, statistic - half),
            high=min(_CHSH_ALGEBRAIC_BOUND, statistic + half),
            confidence=level,
            method=chosen,
        ),
    )


def _as_chsh_method(method: Any) -> ChshMethod:
    """Validate the CHSH interval method.

    Parameters
    ----------
    method : str
        The candidate.

    Returns
    -------
    str
        The method, lower-cased.

    Raises
    ------
    ValueError
        If ``method`` names neither interval.
    TypeError
        If ``method`` is not a string.
    """
    if not isinstance(method, str):
        raise TypeError(
            f"method must be a string, got {type(method).__name__}"
        )
    chosen = method.strip().lower()
    if chosen not in _CHSH_METHODS:
        raise ValueError(
            f"unknown CHSH interval method {method!r}; expected 'normal' (the "
            f"plug-in variance form the sample sizes were derived from) or "
            f"'hoeffding' (the distribution-free bound, union-bounded over the "
            f"four cells)."
        )
    return chosen  # type: ignore[return-value]
