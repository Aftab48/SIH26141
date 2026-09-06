"""The security curves: what the scheme's own failure probabilities do to ``L``.

This is the Phase 5 family the submission is judged on. Everything else the
sweep measures is about the *detector*; this is about the *protocol*, and the
three questions it answers are the three a reviewer will ask.

1. **Repudiation.** *How often does a signer who really is trying to repudiate
   succeed against the shipped protocol, as the key length grows, and how does
   the enforced a-priori bound track that rate?*
2. **Forgery.** *How often does a forged declaration get accepted, as the key
   length grows, for the outside forger and for the binding one -- a recipient
   who holds half the target's evidence?*
3. **The floors.** *Where do the two matched-count floors start to bite, and
   below which key length does a run carry no security claim at all?*

.. _demo-scale-limitation:

Where demo-scale runs cannot demonstrate non-repudiation, stated plainly
-----------------------------------------------------------------------
The single most important thing this module produces is not a rate; it is a
statement about what a rate can and cannot show, and it is better said here
than discovered by a judge.

At :data:`~sih141.protocol.params.DEFAULT_PARAMS` the enforced repudiation
bound is ``1.41e-09``. No feasible number of sampled runs comes within nine
orders of magnitude of confirming that, so the measured arm has to run at key
lengths where the *bound itself* is worthless. It is worthless over exactly the
range where measurement is possible:

>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.verify import enforced_repudiation_bound
>>> [round(enforced_repudiation_bound(ProtocolParams(key_length=L)), 3)
...  for L in (192, 600, 1200, 4800)]
[0.994, 0.943, 0.864, 0.481]

So the honest reading of the measured curve is a *lower* bound on the scheme's
quality and never a confirmation of the claim. At the top of the ladder --
``L = 768``, the strongest tilt available at that length, four hundred runs --
the three numbers a reader has to keep apart are these, and they are written as
executable claims rather than as prose because prose is where this project has
already shipped five wrong figures:

>>> from sih141.detect.statistics import wilson_interval
>>> from sih141.protocol.analysis import repudiation_probability
>>> measured_upper = wilson_interval(0, 400, confidence=0.99).high
>>> exact = repudiation_probability(
...     ProtocolParams(key_length=768), mismatch_probability=0.041
... )
>>> proven = enforced_repudiation_bound(ProtocolParams(key_length=768))
>>> round(measured_upper, 4), float(f"{exact:.3g}"), round(proven, 4)
(0.0163, 0.000584, 0.9212)
>>> round(measured_upper / exact, 1), round(proven / measured_upper, 1)
(27.9, 56.5)

A measurement of ``0/400`` therefore says "at most 1.6%", the truth is
``5.8e-04`` -- twenty-eight times smaller than anything the sample could have
resolved -- and the proof allows ``0.921``, fifty-seven times looser than the
measurement. The proof is vacuous over exactly the range a measurement can
reach, and the region where the claim actually lives is unreachable by both:

>>> f"{enforced_repudiation_bound(ProtocolParams(key_length=115200)):.4e}"
'1.4139e-09'

**Demo-scale runs cannot demonstrate non-repudiation.** They can demonstrate
that the mechanism works, that the attack is real, and that the rate falls the
way the exponent says; the number itself rests on the proof.

What that argument needs, and what :func:`repudiation_reduction` prints, is the
proven column and the measured column side by side with the word on each and
never in the same column (Phase 3 constraint 6).

.. _security-denominators:

Denominators and aborts
-----------------------
Phase 3 constraint 1: a no-verdict is not a rejection, and "aborts counted as
rejections" is forbidden. Every rate here is over **runs whose adversary
actually engaged**, read off the adversary's own log:

* *Repudiation.* Numerator: runs with
  :attr:`~sih141.protocol.session.SessionTranscript.repudiated`. Denominator:
  runs where the tilt flipped at least one delivered state. Runs that reached
  no verdict **are in the denominator and are not repudiations** -- a refusal
  means Bob did not accept, so the repudiation event did not occur -- and they
  get their own column so that nobody has to take this sentence on trust. That
  is also the denominator the proven bound is stated over, which is why the two
  columns can be read against each other at all.
* *Forgery.* Numerator: runs the targeted verifier accepted. Denominator: runs
  where the forger's declaration actually differed from Alice's. Rejections and
  no-verdicts are separate columns and sum with the acceptances to the
  denominator exactly.

An arm whose adversary engaged on no run contributes ``no trials`` rather than
``0.000``; :class:`~sih141.eval.records.GroundTruth` refuses ``engaged=True``
with a zero count outright.

.. _security-timing:

The count ordering is a column, and here is what it costs to forget
-------------------------------------------------------------------
Phase 3 constraint 2 says never to pool across ``count_exchange_timing``. This
family is where that constraint stops being a rule and becomes a number, so it
is written as an executable one: the same recipient-forgery attack, the same
key length, the same seeds, the same shipped code, and the only difference is
when the recipients compare matched counts.

>>> import numpy as np
>>> from sih141.protocol.session import (
...     COUNTS_AFTER_FORWARDING, COUNTS_BEFORE_FORWARDING, QDSSession
... )
>>> def outcomes(timing, trials=12):
...     tally = {"accepted": 0, "rejected": 0, "no verdict": 0}
...     for seed in range(trials):
...         bob = LoggingRecipientForger(rng=np.random.default_rng(70 + seed))
...         run = QDSSession(
...             ProtocolParams(key_length=96), forwarder=bob,
...             count_exchange_timing=timing,
...             rng=np.random.default_rng(300 + seed),
...         ).run(0)
...         charlie = run.charlie
...         tally["no verdict" if charlie is None else
...               "accepted" if charlie.accepted else "rejected"] += 1
...     return tally
>>> outcomes(COUNTS_BEFORE_FORWARDING)
{'accepted': 0, 'rejected': 0, 'no verdict': 12}
>>> outcomes(COUNTS_AFTER_FORWARDING)
{'accepted': 3, 'rejected': 9, 'no verdict': 0}

Under the earlier ordering the pooled matched count is undefined once Bob has
substituted the declaration, so both verifiers refuse and the attack is a
**denial of transfer**. Under the later one Charlie scores the forgery and it
succeeds at the closed-form rate. Pooling the two would publish ``3/24 = 12.5%``
as "the recipient forgery rate", a figure that describes neither run. The
grouping key of every table below carries the ordering, and
:func:`~sih141.eval.reduce.group_records` splits a cell that produced both.

.. _security-truth:

Ground truth, and why the detector cannot reach it
--------------------------------------------------
Phase 3 constraint 4. Which runs the tilt touched, how many states it flipped
and which link it aimed at live on the adversary's own counters, are attached
to :class:`~sih141.eval.records.GroundTruth` *after*
:func:`~sih141.detect.detector.detect` has already returned, and are never an
argument to anything the detector sees. A tilt of strength zero flips nothing,
is byte-identical to an honest run, and is scored as one.

Note also constraint 7:
:attr:`~sih141.protocol.session.SessionTranscript.repudiated` is used here as
the **outcome of a labelled experiment**, never as a detector signal. It cannot
tell signer misbehaviour from channel noise from recipient forgery, which is
exactly why the harness has to know the truth and the detector must not.

Regenerating everything
-----------------------
.. code-block:: text

    python tools/sweep.py run repudiation-curve --trials 400 --workers 20
    python tools/sweep.py run forgery-curve     --trials 400 --workers 20
    python tools/sweep.py reduce repudiation-curve
    python tools/sweep.py reduce forgery-curve
    python tools/sweep.py reduce repudiation-curve --charts docs/figures

Examples
--------
The two experiments and the shape of their ladders:

>>> from sih141.eval.experiments import experiment
>>> experiment("repudiation-curve").cell_names[:5]
('l24', 'l48', 'l96', 'l132', 'l138')
>>> experiment("forgery-curve").cell_names[:4]
('eve9', 'eve15', 'eve24', 'eve30')

The floor crossover, which is where a run first carries a security claim at
all, and the per-verifier floor's own crossover well above it:

>>> from sih141.eval.security import FLOOR_CROSSOVER, PER_VERIFIER_CROSSOVER
>>> FLOOR_CROSSOVER, PER_VERIFIER_CROSSOVER
(137, 273)
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.verify import (
...     minimum_matched_count, minimum_pooled_matched_count
... )
>>> [(L, minimum_matched_count(ProtocolParams(key_length=L)),
...      minimum_pooled_matched_count(ProtocolParams(key_length=L)))
...  for L in (136, 137, 272, 273)]
[(136, 1, 1), (137, 1, 2), (272, 1, 55), (273, 2, 55)]

Below ``137`` both floors are ``1`` -- "abort only on an empty matched set" --
and :attr:`~sih141.detect.statistics.TranscriptStatistics.security_claim` is
``False``. The ladder deliberately straddles it: a curve that started at
``L = 192`` would hide the part of the story a reviewer is most likely to
find on their own.
"""

from __future__ import annotations

import math
from typing import Any, Final, Mapping, Sequence

import numpy as np
from qiskit.quantum_info import Statevector

from sih141.attacks.forgery import OutsideForger, RecipientForger
from sih141.core.rng import resolve_rng
from sih141.detect.statistics import wilson_interval
from sih141.detect.thresholds_rate import dominance_noise_level
from sih141.protocol.analysis import (
    binary_kl_divergence,
    forgery_probability,
    recipient_forgery_probability,
    repudiation_probability,
)
from sih141.protocol.params import DEFAULT_PARAMS, Party, ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
    SessionTranscript,
)
from sih141.protocol.signature import Signature
from sih141.protocol.symmetrise import no_symmetrisation
from sih141.protocol.verify import (
    guaranteed_pooled_matched_count,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

from . import reduce as reduce_module
from .experiments import (
    DEFAULT_EPS,
    EXPERIMENTS,
    SCENARIO_PROBE_OPTIONS,
    SCENARIOS,
    Cell,
    Experiment,
    claim,
)
from .records import GroundTruth, TrialRecord
from .reduce import (
    CONFIDENCE,
    Table,
    escape_xml,
    group_records,
    measured_rate,
    refused_run,
)
from .seeds import TrialSeeds

__all__ = [
    "CONTROL_TILT",
    "FLOOR_CROSSOVER",
    "FLOOR_LADDER",
    "FORGERY_TRIALS",
    "LoggingOutsideForger",
    "LoggingRecipientForger",
    "OUTSIDE_LADDER",
    "PER_VERIFIER_CROSSOVER",
    "RECIPIENT_LADDER",
    "REPUDIATION_LADDER",
    "REPUDIATION_TRIALS",
    "SECURITY_PROBE_OPTIONS",
    "SECURITY_SCENARIOS",
    "SIGNER_CUTS",
    "TILT_CEILING",
    "TILT_RESOLUTION",
    "TiltingPreparation",
    "VERIFIER_CUTS",
    "averaged_bound_log10",
    "enforced_bound_log10",
    "floor_table",
    "forgery_reduction",
    "forgery_table",
    "gap_table",
    "optimal_tilt",
    "orthogonal_state",
    "outside_forgery_bound_log10",
    "outside_forgery_scenario",
    "recipient_forgery_bound_log10",
    "recipient_forgery_scenario",
    "register",
    "repudiated_from_verdicts",
    "repudiation_curve_table",
    "repudiation_reduction",
    "repudiation_scenario",
    "security_charts",
    "security_claim_at",
]


FLOOR_CROSSOVER: Final[int] = 137
"""int: The smallest signing length at which *either* matched-count floor bites.

Below it :func:`~sih141.protocol.verify.minimum_matched_count` and
:func:`~sih141.protocol.verify.minimum_pooled_matched_count` are both ``1``, so
the abort rule degenerates to "a rate needs a denominator",
:attr:`~sih141.detect.statistics.TranscriptStatistics.security_claim` is
``False``, and every number the run produces still computes cheerfully. The
pooled floor is the one that bites first, at twice the mean of the per-verifier
count; see :data:`PER_VERIFIER_CROSSOVER` for the other one.

Pinned as a doctest rather than written in prose, because it is the boundary
this family's ladder is built to straddle:

>>> from sih141.eval.security import FLOOR_CROSSOVER, security_claim_at
>>> security_claim_at(FLOOR_CROSSOVER - 1), security_claim_at(FLOOR_CROSSOVER)
(False, True)
"""

PER_VERIFIER_CROSSOVER: Final[int] = 273
"""int: The smallest signing length at which the *per-verifier* floor bites.

``m_min > 1`` from here up. Twice :data:`FLOOR_CROSSOVER` minus one, and the
factor of two is not a coincidence: the pooled count has twice the mean, so its
Chernoff form has something to say at half the key length.

>>> from sih141.eval.security import PER_VERIFIER_CROSSOVER
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.verify import minimum_matched_count
>>> [minimum_matched_count(ProtocolParams(key_length=L))
...  for L in (PER_VERIFIER_CROSSOVER - 1, PER_VERIFIER_CROSSOVER)]
[1, 2]
"""

REPUDIATION_TRIALS: Final[int] = 400
"""int: Default trials per repudiation cell.

Four hundred, and the number is load-bearing rather than round: at the top of
the ladder it is what makes the measurement's 99% upper limit *visible* beside
the exact probability, which is the whole content of
:ref:`demo-scale-limitation`. Raising it moves the top of the ladder along by
about one rung per factor of three and never reaches the region the security
claim lives in.
"""

FORGERY_TRIALS: Final[int] = 400
"""int: Default trials per forgery cell. Same reasoning as
:data:`REPUDIATION_TRIALS`."""

CONTROL_TILT: Final[float] = 0.30
"""float: Tilt strength for the unsymmetrised positive control.

Deliberately far above every rung's optimum. The control is not measuring a
rate; it is answering "did the adversary act at all?" for the rows that report
zero, and it wants an unmissable answer.
"""

REPUDIATION_LADDER: Final[tuple[tuple[int, float], ...]] = (
    (24, 0.085),
    (48, 0.059),
    (96, 0.047),
    (132, 0.043),
    (138, 0.043),
    (192, 0.044),
    (300, 0.042),
    (384, 0.042),
    (600, 0.041),
    (768, 0.041),
)
"""tuple: ``(key_length, tilt strength)`` for the measured repudiation ladder.

Each strength is the argument that maximises
:func:`~sih141.protocol.analysis.repudiation_probability` at that key length --
the best move available to this Alice, not a number that made a table look
better (D7). :func:`optimal_tilt` recomputes it and
``tests/test_eval_security.py`` checks every rung, so the constants cannot
drift away from the function that produced them.

The ladder straddles :data:`FLOOR_CROSSOVER`: ``132`` carries no security claim
and ``138`` carries one, on either side of the boundary.

>>> from sih141.eval.security import REPUDIATION_LADDER, optimal_tilt
>>> from sih141.protocol.params import ProtocolParams
>>> optimal_tilt(ProtocolParams(key_length=96))
0.047
>>> [L for L, _ in REPUDIATION_LADDER][:4]
[24, 48, 96, 132]
"""

RECIPIENT_LADDER: Final[tuple[int, ...]] = (96, 192, 384, 768, 1200)
"""tuple: Key lengths for the recipient-forgery ladder, run at both orderings.

Stops at ``1200`` because that is the last rung whose exact acceptance
probability -- ``0.0140`` -- is above the resolution of four hundred trials.
Beyond it the closed form carries the curve and the measurement would only
report zero.
"""

OUTSIDE_LADDER: Final[tuple[int, ...]] = (9, 15, 24, 30)
"""tuple: Key lengths for the outside-forgery anchor.

Absurdly short, and that is the point: Eve holds nothing, her per-scored-
position mismatch rate is a fair coin, and her acceptance probability is
``1.1e-12`` by ``L = 192``. These four rungs are the only ones where
:func:`~sih141.protocol.analysis.forgery_probability` can be checked against a
measurement at all, and checking a published closed form against a measurement
somewhere is worth more than quoting it everywhere.
"""

FLOOR_LADDER: Final[tuple[int, ...]] = (
    24,
    48,
    96,
    132,
    136,
    137,
    138,
    140,
    192,
    272,
    273,
    300,
    384,
    600,
    768,
    1200,
    2400,
    4800,
    9600,
    19200,
    115200,
)
"""tuple: Key lengths for the analytic floor table.

Includes both crossovers and both of their predecessors, so the step is visible
rather than inferred, and ends at :data:`~sih141.protocol.params.DEFAULT_PARAMS`
so the row a security claim is actually made at appears in the same table as
the rows a measurement was made at. Every key length that turns up in the
records is added to this list by :func:`floor_table`, so the table always
covers what ran.
"""

TILT_RESOLUTION: Final[int] = 1000
"""int: Denominator of :func:`optimal_tilt`'s candidate grid.

Candidates are ``k / TILT_RESOLUTION``, so the answer is a three-decimal number
**exactly** rather than a continuous optimum rounded afterwards. Rounding after
optimising is how a search returns a value that is not the best of the values it
could return: the first version of this function did that and answered ``0.086``
at ``L = 24``, where ``0.085`` is better.
"""

TILT_CEILING: Final[float] = 0.2
"""float: Largest strength :func:`optimal_tilt` considers.

Well above every rung's optimum, and far above ``s_v = 1/16``: beyond it both
verifiers reject and the run is a signature failure rather than a repudiation.
"""


# --------------------------------------------------------------------------- #
# 1. The adversaries
# --------------------------------------------------------------------------- #


def orthogonal_state(payload: Any) -> Statevector:
    """Return the one-qubit state orthogonal to ``payload``.

    For a Pauli eigenstate this is the eigenstate of the same basis with the
    opposite eigenvalue, which is what a repudiating Alice sends when she wants
    a recipient's matched positions to disagree with what she will declare. The
    formula is basis-free -- ``|psi> = (a, b)`` goes to ``(-conj(b), conj(a))``
    -- because the payload seam is handed a state, not a key element, and a map
    that had to be told the basis would be reading something the seam
    deliberately does not carry.

    Parameters
    ----------
    payload : Statevector or array-like
        A pure one-qubit state.

    Returns
    -------
    qiskit.quantum_info.Statevector
        The orthogonal state, freshly constructed.

    Raises
    ------
    TypeError
        If ``payload`` cannot be read as a state vector.
    ValueError
        If it is not one qubit.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.eval.security import orthogonal_state
    >>> from sih141.protocol.keys import KeyElement
    >>> flipped = orthogonal_state(KeyElement("Z", 1).state())
    >>> bool(np.allclose(np.asarray(flipped.data), [0.0, 1.0]))
    True

    It really is the opposite eigenstate, in every basis of the alphabet, and
    the overlap with what was sent is exactly zero:

    >>> for basis in ("X", "Y", "Z"):
    ...     sent = KeyElement(basis, 1).state()
    ...     flipped = orthogonal_state(sent)
    ...     opposite = KeyElement(basis, -1).state()
    ...     overlap = abs(np.vdot(np.asarray(sent.data),
    ...                           np.asarray(flipped.data)))
    ...     fidelity = abs(np.vdot(np.asarray(opposite.data),
    ...                            np.asarray(flipped.data)))
    ...     print(basis, round(overlap, 12), round(fidelity, 12))
    X 0.0 1.0
    Y 0.0 1.0
    Z 0.0 1.0
    """
    try:
        vector = Statevector(payload)
    except Exception as error:  # pragma: no cover - qiskit's own message
        raise TypeError(
            f"payload must be readable as a one-qubit Statevector, got "
            f"{type(payload).__name__}"
        ) from error
    data = np.asarray(vector.data, dtype=complex)
    if data.shape != (2,):
        raise ValueError(
            f"payload must be a single qubit, got dimension {data.shape}. "
            f"The payload seam is called once per key position and a position "
            f"carries one qubit."
        )
    first, second = data
    return Statevector(
        np.array([-np.conj(second), np.conj(first)], dtype=complex)
    )


class TiltingPreparation:
    """A repudiating Alice on the payload line: she sometimes sends the opposite.

    A :data:`~sih141.protocol.distribute.PayloadMap`. At each delivered
    position, independently, she prepares the *orthogonal* eigenstate with
    probability ``strength`` instead of the one she will declare. A recipient
    whose measurement basis matches the declaration then reads the opposite
    eigenvalue and records a mismatch, so the strength is exactly the
    per-matched-position mismatch probability ``q`` of
    :func:`~sih141.protocol.analysis.repudiation_probability` -- which makes
    that function an independent closed form for what this adversary achieves,
    rather than a loosely related one.

    She repudiates when the two recipients' rates land on opposite sides of the
    thresholds: ``r_B <= s_a`` and ``r_C > s_v``. She has no way to arrange
    that; she can only choose ``q`` and hope, which is why the rate falls like
    the exponent and why :func:`optimal_tilt` exists.

    **She owns her randomness and never reads the session's** (D3, D6). The
    generator is mandatory: a payload map that quietly drew fresh entropy would
    make its run irreproducible from the recorded seed, which is the one thing
    D9 does not survive.

    **She draws on every call, before deciding anything.** The seam is invoked
    on check rounds too, and a map whose own stream advanced only on the rounds
    it cared about would publish the check set as the gaps in its consumption
    (:mod:`sih141.protocol.distribute`). Drawing first and filtering afterwards
    costs one variate and closes that channel.

    Parameters
    ----------
    strength : float
        ``q`` in ``[0, 1]``: the probability of flipping any one delivered
        state.
    rng : numpy.random.Generator
        Keyword-only and **required**. Hers alone.
    message_bit : int
        Keyword-only. Only the distribution for this bit is attacked; the other
        bit's states are delivered honestly, since it is the declared one that
        the verifiers score.
    target : Party, str or None, optional
        Keyword-only. ``None`` attacks both recipients' deliveries -- the
        symmetric family. Naming one recipient attacks only his, which is the
        classical repudiation attack the symmetrisation exchange exists to
        defeat.

    Attributes
    ----------
    calls : int
        Positions the seam was offered, over every party and both bits.
    flips : int
        Positions actually replaced. This is the number
        :class:`~sih141.eval.records.GroundTruth` is told, so a strength of zero
        reports an honest run rather than a missed detection.
    flips_by_party : dict
        ``party -> flips``, so a targeted arm can prove it aimed where it said.

    Raises
    ------
    TypeError
        If ``rng`` is not a :class:`numpy.random.Generator`, or ``strength`` is
        not a real number.
    ValueError
        If ``strength`` is outside ``[0, 1]`` or not finite.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.eval.security import TiltingPreparation
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> alice = TiltingPreparation(
    ...     0.25, rng=np.random.default_rng(4), message_bit=0
    ... )
    >>> run = QDSSession(
    ...     ProtocolParams(key_length=96), payload_map=alice,
    ...     rng=np.random.default_rng(9),
    ... ).run(0)
    >>> alice.calls, alice.flips > 0
    (384, True)
    >>> sorted(alice.flips_by_party)
    ['Bob', 'Charlie']

    A strength of zero touches nothing, and the run is then an honest run:

    >>> quiet = TiltingPreparation(
    ...     0.0, rng=np.random.default_rng(4), message_bit=0
    ... )
    >>> _ = QDSSession(
    ...     ProtocolParams(key_length=48), payload_map=quiet,
    ...     rng=np.random.default_rng(9),
    ... ).run(0)
    >>> quiet.flips
    0

    She draws once per call whatever she decides, so her stream length is a
    constant of the run and carries no information about it:

    >>> counted = TiltingPreparation(
    ...     1.0, rng=np.random.default_rng(1), message_bit=1, target="Bob"
    ... )
    >>> _ = QDSSession(
    ...     ProtocolParams(key_length=48), payload_map=counted,
    ...     rng=np.random.default_rng(2),
    ... ).run(1)
    >>> counted.calls, counted.flips, counted.flips_by_party
    (192, 48, {'Bob': 48})
    """

    def __init__(
        self,
        strength: float,
        *,
        rng: np.random.Generator,
        message_bit: int,
        target: Party | str | None = None,
    ) -> None:
        if not isinstance(rng, np.random.Generator):
            raise TypeError(
                f"rng must be a numpy.random.Generator, got "
                f"{type(rng).__name__}. It is mandatory: an adversary that "
                f"draws its own entropy makes the trial irreproducible from "
                f"its recorded seed (D3, D9)."
            )
        value = float(strength)
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError(f"strength must lie in [0, 1], got {strength!r}")
        self._strength = value
        self._rng = resolve_rng(rng)
        self._message_bit = int(message_bit)
        self._target = None if target is None else str(target)
        self.calls = 0
        self.flips = 0
        self.flips_by_party: dict[str, int] = {}

    @property
    def strength(self) -> float:
        """float: The flip probability ``q``."""
        return self._strength

    @property
    def target(self) -> str | None:
        """str or None: The recipient whose deliveries are attacked."""
        return self._target

    def __repr__(self) -> str:
        """Return a representation naming the knob and the traffic."""
        return (
            f"TiltingPreparation(strength={self._strength!r}, "
            f"target={self._target!r}, calls={self.calls}, "
            f"flips={self.flips})"
        )

    def __call__(self, payload: Any, context: Any) -> Any:
        """Return the state to deliver, flipped with probability ``strength``.

        Parameters
        ----------
        payload : Statevector
            The eigenstate the honest protocol would have sent.
        context : ResourceContext
            Which recipient, which message bit and which position.

        Returns
        -------
        Statevector
            Either ``payload`` unchanged or its orthogonal partner.
        """
        self.calls += 1
        # Draw first, decide after: the seam is called on check rounds too, and
        # a stream that advanced only on the positions this adversary cared
        # about would leak which positions those were.
        draw = float(self._rng.random())
        if int(context.message_bit) != self._message_bit:
            return payload
        party = str(context.party)
        if self._target is not None and party != self._target:
            return payload
        if draw >= self._strength:
            return payload
        self.flips += 1
        self.flips_by_party[party] = self.flips_by_party.get(party, 0) + 1
        return orthogonal_state(payload)


class LoggingOutsideForger:
    """:class:`~sih141.attacks.forgery.OutsideForger`, plus a record of her footprint.

    The forgery itself is entirely the shipped adversary's: this wrapper adds
    one thing, a count of the positions on which her declaration actually
    differs from the key Alice distributed. That count is what
    :class:`~sih141.eval.records.GroundTruth` is given, so an arm reporting zero
    acceptances can prove it forged something -- Phase 4's replay arm reported a
    clean ``0/40`` while having forwarded honestly, and the shape of that defect
    is a counter nobody kept.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only and required; hers alone (D6).

    Attributes
    ----------
    calls : int
        Declarations made. One per run.
    substituted_positions : int
        Positions where her declaration differs from Alice's key, summed over
        calls. About ``2L/3`` for an independent draw over a three-basis
        alphabet, since a position agrees only when both the basis and the
        eigenvalue happen to coincide.

    Raises
    ------
    TypeError
        If ``rng`` is not a generator.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.eval.security import LoggingOutsideForger
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> eve = LoggingOutsideForger(rng=np.random.default_rng(1))
    >>> run = QDSSession(
    ...     ProtocolParams(key_length=48), signer=eve,
    ...     rng=np.random.default_rng(2),
    ... ).run(0)
    >>> eve.calls, eve.substituted_positions > 24
    (1, True)
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        if not isinstance(rng, np.random.Generator):
            raise TypeError(
                f"rng must be a numpy.random.Generator, got "
                f"{type(rng).__name__}"
            )
        self._inner = OutsideForger(rng=rng)
        self.calls = 0
        self.substituted_positions = 0

    def __repr__(self) -> str:
        """Return a representation naming the traffic."""
        return (
            f"LoggingOutsideForger(calls={self.calls}, "
            f"substituted={self.substituted_positions})"
        )

    def __call__(
        self,
        message_bit: int,
        keys: Any,
        params: ProtocolParams,
        *,
        records: Mapping[int, Any],
    ) -> Signature:
        """Declare Eve's own key, and log how far it is from Alice's.

        Parameters
        ----------
        message_bit : int
            The bit being signed.
        keys : tuple of PrivateKey
            Alice's committed pair. Used **only** to measure the footprint,
            after the forged declaration exists; the forger itself never sees
            it (the wrapped :class:`~sih141.attacks.forgery.OutsideForger`
            ignores the argument by construction).
        params : ProtocolParams
            The parameter set.
        records : mapping
            Keyword-only. Passed straight through and ignored.

        Returns
        -------
        Signature
            Eve's declaration.
        """
        self.calls += 1
        forged = self._inner(message_bit, keys, params, records=records)
        genuine = keys[int(message_bit)]
        self.substituted_positions += sum(
            1
            for honest, declared in zip(
                genuine.elements, forged.declared_key.elements
            )
            if honest != declared
        )
        return forged


class LoggingRecipientForger:
    """:class:`~sih141.attacks.forgery.RecipientForger`, plus a record of his footprint.

    Bob accepts Alice's declaration and hands Charlie one built from his own raw
    log. The wrapper counts the positions on which the forwarded declaration
    differs from what Alice sent, which is what makes ``engaged`` a measurement
    rather than an assumption: a forwarder that returned the declaration
    unchanged would be an honest Bob, and the run must be scored as one.

    It declares ``view`` keyword-only **with no default**, which is how
    :class:`~sih141.protocol.session.Forwarder` decides that this seam wants
    Bob's :class:`~sih141.protocol.records.RecipientView`.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only and required; his alone (D6). The optimal forger draws
        nothing, so this generator is untouched in practice -- which is a
        property of the adversary, not a wiring mistake.

    Attributes
    ----------
    calls : int
        Declarations forwarded. One per run.
    substituted_positions : int
        Positions where the forwarded declaration differs from Alice's.

    Raises
    ------
    TypeError
        If ``rng`` is not a generator.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.eval.security import LoggingRecipientForger
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import (
    ...     COUNTS_AFTER_FORWARDING, QDSSession
    ... )
    >>> bob = LoggingRecipientForger(rng=np.random.default_rng(1))
    >>> run = QDSSession(
    ...     ProtocolParams(key_length=48), forwarder=bob,
    ...     count_exchange_timing=COUNTS_AFTER_FORWARDING,
    ...     rng=np.random.default_rng(2),
    ... ).run(0)
    >>> bob.calls, bob.substituted_positions > 0
    (1, True)
    >>> run.forwarding_altered_signature
    True
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        if not isinstance(rng, np.random.Generator):
            raise TypeError(
                f"rng must be a numpy.random.Generator, got "
                f"{type(rng).__name__}"
            )
        self._inner = RecipientForger(rng=rng)
        self.calls = 0
        self.substituted_positions = 0

    def __repr__(self) -> str:
        """Return a representation naming the traffic."""
        return (
            f"LoggingRecipientForger(calls={self.calls}, "
            f"substituted={self.substituted_positions})"
        )

    def __call__(
        self, signature: Signature, params: ProtocolParams, *, view: Any
    ) -> Signature:
        """Forward a declaration built from Bob's own log, and log the diff.

        Parameters
        ----------
        signature : Signature
            Alice's genuine declaration, which Bob has already accepted.
        params : ProtocolParams
            The scored parameter set.
        view : RecipientView
            Keyword-only, no default: Bob's own evidence, and the only thing he
            holds.

        Returns
        -------
        Signature
            What Charlie will score.
        """
        self.calls += 1
        forged = self._inner(signature, params, view=view)
        self.substituted_positions += sum(
            1
            for honest, declared in zip(
                signature.declared_key.elements, forged.declared_key.elements
            )
            if honest != declared
        )
        return forged


# --------------------------------------------------------------------------- #
# 2. Picking the tilt
# --------------------------------------------------------------------------- #


def optimal_tilt(
    params: ProtocolParams,
    *,
    resolution: int = TILT_RESOLUTION,
    ceiling: float = TILT_CEILING,
) -> float:
    """Return the tilt strength that maximises the in-model repudiation rate.

    An exhaustive search over the candidates ``k / resolution`` for
    ``0 < k / resolution <= ceiling``, maximising
    :func:`~sih141.protocol.analysis.repudiation_probability`. Exhaustive over
    a grid rather than a root find because the objective is a sum of binomial
    tails and is only piecewise smooth in ``q``, and the grid is the *answer's*
    grid rather than an intermediate one -- so the value returned is the best of
    the values that can be returned. An earlier version optimised continuously
    and rounded afterwards, which answered ``0.086`` at ``L = 24`` where
    ``0.085`` scores higher.

    **This is a choice about the adversary, not about a threshold.** D7 forbids
    tuning a *detector* threshold on attack data; choosing the best move
    available to a modelled attacker is the opposite -- publishing the rate a
    weaker Alice achieves would overstate the scheme.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the rung runs at.
    resolution : int, optional
        Keyword-only. Denominator of the candidate grid.
    ceiling : float, optional
        Keyword-only. Largest strength considered.

    Returns
    -------
    float
        A candidate from the grid, so at the default resolution a number with
        three decimal places and no floating-point residue.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`.
    ValueError
        If ``resolution`` or ``ceiling`` leaves no candidate.

    Notes
    -----
    Costs ``resolution * ceiling`` evaluations of an ``O(L^2)`` sum: about
    ``1.3 s`` at ``L = 192`` and ``6 s`` at ``L = 768``. It derives
    :data:`REPUDIATION_LADDER`'s constants and is called by the test that
    checks them; it is never called inside the sweep.

    Examples
    --------
    >>> from sih141.eval.security import optimal_tilt
    >>> from sih141.protocol.params import ProtocolParams
    >>> optimal_tilt(ProtocolParams(key_length=24))
    0.085
    >>> optimal_tilt(ProtocolParams(key_length=48))
    0.059

    It really is a maximum, and the neighbours on its own grid are worse -- so
    the published rate is the best this Alice can do, not merely a plausible
    one:

    >>> from sih141.protocol.analysis import repudiation_probability
    >>> params = ProtocolParams(key_length=48)
    >>> best = repudiation_probability(params, mismatch_probability=0.059)
    >>> neighbours = [
    ...     repudiation_probability(params, mismatch_probability=q)
    ...     for q in (0.058, 0.060, 0.030, 0.118)
    ... ]
    >>> all(value < best for value in neighbours)
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be ProtocolParams, got {type(params).__name__}"
        )
    steps = int(float(ceiling) * int(resolution))
    if int(resolution) <= 0 or steps < 1:
        raise ValueError(
            f"resolution={resolution!r} and ceiling={ceiling!r} leave no "
            f"candidate strength to search"
        )
    best_value = -1.0
    best_q = 1.0 / int(resolution)
    for index in range(1, steps + 1):
        candidate = index / int(resolution)
        value = repudiation_probability(params, mismatch_probability=candidate)
        if value > best_value:
            best_value, best_q = value, candidate
    return best_q


def security_claim_at(key_length: int) -> bool:
    """Return whether a run of this signing length carries a security claim.

    ``True`` exactly when at least one matched-count floor is non-degenerate,
    which is the same rule
    :attr:`~sih141.detect.statistics.TranscriptStatistics.security_claim`
    applies to a transcript -- restated here as a function of the length alone,
    so a table can print the column for a key length nobody ran.

    Parameters
    ----------
    key_length : int
        The signing length. For a run with check rounds this is
        :attr:`~sih141.protocol.params.ProtocolParams.signing_length`, not
        ``L``.

    Returns
    -------
    bool

    Examples
    --------
    >>> from sih141.eval.security import security_claim_at
    >>> [security_claim_at(L) for L in (24, 136, 137, 192)]
    [False, False, True, True]
    """
    params = ProtocolParams(key_length=int(key_length))
    return (
        minimum_matched_count(params) > 1
        or minimum_pooled_matched_count(params) > 1
    )


# --------------------------------------------------------------------------- #
# 3. Bounds in log space, because the interesting ones underflow
# --------------------------------------------------------------------------- #


def averaged_bound_log10(
    *, trials: int, match_probability: float, exponent: float
) -> float:
    """Return ``log10`` of an exponential bound averaged over the matched count.

    The closed form every bound in :mod:`sih141.protocol.analysis` reduces to
    when the matched count is not conditioned on:

    .. code-block:: text

        bound = (1 - p + p exp(-exponent)) ** trials

    evaluated in log space, because the numbers this family has to print do not
    fit in a float. The outside forger's bound at
    :data:`~sih141.protocol.params.DEFAULT_PARAMS` is ``10 ** -6553``;
    :func:`~sih141.protocol.analysis.forgery_bound` returns ``0.0`` for it,
    which is an underflow and would print as a **bound of exactly zero** -- a
    claim no proof supports.

    This is also the second route the published bounds are checked by: it is
    written from the inequality rather than called from the library, and
    ``tests/test_eval_security.py`` asserts the two agree wherever the library's
    answer is representable.

    Parameters
    ----------
    trials : int
        ``L`` for a per-verifier statistic, ``2L`` for a pooled one.
    match_probability : float
        The probability a position is scored, in ``(0, 1]``.
    exponent : float
        The per-scored-position exponent, in nats.

    Returns
    -------
    float
        Base-ten logarithm of the bound; ``0.0`` for a vacuous one.

    Raises
    ------
    ValueError
        If ``trials`` is negative, ``match_probability`` is outside ``(0, 1]``,
        or ``exponent`` is negative.

    Examples
    --------
    >>> from sih141.eval.security import averaged_bound_log10
    >>> from sih141.protocol.analysis import binary_kl_divergence, forgery_bound
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=192)
    >>> exponent = binary_kl_divergence(params.threshold_for(Party.CHARLIE), 0.5)
    >>> mine = averaged_bound_log10(
    ...     trials=params.key_length,
    ...     match_probability=params.match_probability,
    ...     exponent=exponent,
    ... )
    >>> round(mine, 6)
    -10.922193
    >>> import math
    >>> round(math.log10(forgery_bound(params, method="kl")), 6)
    -10.922193

    And at the shipped parameter set, where the library underflows to a zero
    that no proof supports:

    >>> default = ProtocolParams(key_length=115200)
    >>> exponent = binary_kl_divergence(
    ...     default.threshold_for(Party.CHARLIE), 0.5
    ... )
    >>> round(averaged_bound_log10(
    ...     trials=default.key_length,
    ...     match_probability=default.match_probability,
    ...     exponent=exponent,
    ... ))
    -6553
    >>> forgery_bound(default, method="kl")
    0.0
    """
    count = int(trials)
    probability = float(match_probability)
    power = float(exponent)
    if count < 0:
        raise ValueError(f"trials must be non-negative, got {count}")
    if not 0.0 < probability <= 1.0:
        raise ValueError(
            f"match_probability must lie in (0, 1], got {probability!r}"
        )
    if power < 0.0:
        raise ValueError(f"exponent must be non-negative, got {power!r}")
    factor = 1.0 - probability + probability * math.exp(-power)
    if factor <= 0.0:  # pragma: no cover - unreachable for p <= 1
        return -math.inf
    return count * math.log10(factor)


def enforced_bound_log10(params: ProtocolParams) -> float:
    """Return ``log10`` of the enforced a-priori repudiation bound.

    ``exp(-max(2 m_min, M_min) * gap**2 / 8)``, in log space, recomputed from
    the floors and the gap rather than read back from
    :func:`~sih141.protocol.verify.enforced_repudiation_bound`. The second route
    matters here for the same reason it does in
    :func:`averaged_bound_log10`: at
    :data:`~sih141.protocol.params.DEFAULT_PARAMS` the answer is ``1.41e-09``
    and prints fine, but the table is meant to keep working when a longer key
    is added to :data:`FLOOR_LADDER`.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`~sih141.protocol.params.ProtocolParams`.

    Examples
    --------
    >>> import math
    >>> from sih141.eval.security import enforced_bound_log10
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> from sih141.protocol.verify import enforced_repudiation_bound
    >>> round(enforced_bound_log10(DEFAULT_PARAMS), 9)
    -8.849571793
    >>> round(math.log10(enforced_repudiation_bound(DEFAULT_PARAMS)), 9)
    -8.849571793
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be ProtocolParams, got {type(params).__name__}"
        )
    floor = guaranteed_pooled_matched_count(params)
    return -floor * params.gap**2 / 8.0 / math.log(10.0)


def outside_forgery_bound_log10(params: ProtocolParams) -> float:
    """Return ``log10`` of the outside forger's acceptance bound, KL form.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set. The bound is stated at Charlie's threshold, the
        looser of the two and therefore the easier target.

    Returns
    -------
    float

    Examples
    --------
    >>> from sih141.eval.security import outside_forgery_bound_log10
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> round(outside_forgery_bound_log10(DEFAULT_PARAMS))
    -6553
    """
    threshold = params.threshold_for(Party.CHARLIE)
    return averaged_bound_log10(
        trials=params.key_length,
        match_probability=params.match_probability,
        exponent=binary_kl_divergence(threshold, 0.5),
    )


def recipient_forgery_bound_log10(params: ProtocolParams) -> float:
    """Return ``log10`` of the recipient forger's acceptance bound, KL form.

    The binding adversary: he holds his own raw log, and after the
    symmetrisation exchange half of it is precisely Charlie's evidence, so his
    per-scored-position mismatch rate is the optimal ``1/12`` rather than a fair
    coin. ``s_v = 1/16`` sits three quarters of the way to it, and the whole
    security claim is the distance between those two numbers.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    float

    Examples
    --------
    >>> from sih141.eval.security import recipient_forgery_bound_log10
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> round(recipient_forgery_bound_log10(DEFAULT_PARAMS), 4)
    -102.9493

    Which is the ``1e-103`` the project publishes, and it agrees with the
    library's own float wherever that float exists:

    >>> import math
    >>> from sih141.protocol.analysis import recipient_forgery_bound
    >>> round(math.log10(recipient_forgery_bound(DEFAULT_PARAMS, method="kl")), 4)
    -102.9493
    """
    threshold = params.threshold_for(Party.CHARLIE)
    return averaged_bound_log10(
        trials=params.key_length,
        match_probability=params.forger_scored_fraction,
        exponent=binary_kl_divergence(threshold, params.forger_floor),
    )


def _format_log10(value: float) -> str:
    """Render a base-ten logarithm as a probability a reader can compare.

    Parameters
    ----------
    value : float
        ``log10`` of a probability.

    Returns
    -------
    str
        Ordinary scientific notation where the number is representable, and
        ``10^-4690`` where it is not. Never ``0.000e+00``: a bound of exactly
        zero is a claim no proof in this package makes.
    """
    if value >= 0.0:
        return "1.000e+00"
    if value > -300.0:
        return f"{10.0 ** value:.3e}"
    return f"10^{value:.1f}"


# --------------------------------------------------------------------------- #
# 4. The scenarios
# --------------------------------------------------------------------------- #


def _require(cell: Cell, name: str) -> Any:
    """Return a mandatory scenario option, or explain what is missing.

    Parameters
    ----------
    cell : Cell
        The cell being run.
    name : str
        The option key.

    Returns
    -------
    object

    Raises
    ------
    KeyError
        If the option is absent. There are no defaults in this family: every
        one of these options changes what the arm measures, and a default turns
        a typo into an arm that runs, reports something, and measures the wrong
        thing.
    """
    options = cell.scenario_options
    if name not in options:
        raise KeyError(
            f"cell {cell.name!r} names no {name!r} in scenario_options. This "
            f"family defaults none of them: each one changes what the arm "
            f"measures, and a silent default is how an inert arm reports a "
            f"clean zero."
        )
    return options[name]


def _session(cell: Cell, seeds: TrialSeeds, **wiring: Any) -> SessionTranscript:
    """Build and run one session with the cell's ordering and exchange.

    Parameters
    ----------
    cell : Cell
        The cell being run; ``scenario_options`` must name
        ``count_exchange_timing``.
    seeds : TrialSeeds
        The trial's seeds. Only the session half is used here.
    **wiring
        Seams handed to :class:`~sih141.protocol.session.QDSSession`.

    Returns
    -------
    SessionTranscript

    Raises
    ------
    KeyError
        If ``count_exchange_timing`` is absent.
    ValueError
        If it names neither ordering.
    """
    timing = str(_require(cell, "count_exchange_timing"))
    if timing not in (COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING):
        raise ValueError(
            f"cell {cell.name!r} asks for count_exchange_timing {timing!r}; "
            f"the two orderings are "
            f"{[COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING]}"
        )
    session = QDSSession(
        cell.params,
        rng=seeds.session_rng(),
        count_exchange_timing=timing,
        **wiring,
    )
    return session.run(cell.message_bit)


def repudiation_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Run one session against a repudiating Alice, and label it from her log.

    Parameters
    ----------
    cell : Cell
        ``scenario_options`` must name ``strength`` (the tilt ``q``),
        ``count_exchange_timing`` and ``symmetrised``; ``target`` is optional
        and names one recipient.
    seeds : TrialSeeds
        The trial's seeds. The session gets
        :meth:`~sih141.eval.seeds.TrialSeeds.session_rng` and the tilt gets
        :meth:`~sih141.eval.seeds.TrialSeeds.adversary_rng`, and neither is
        ever handed the other's (D3, D6).

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` is the number of states the tilt actually replaced,
        read off its own counter, so a run it happened to leave alone is scored
        as the honest run it is.

    Raises
    ------
    KeyError
        If a mandatory option is absent.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.security import repudiation_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> cell = experiment("repudiation-curve").cell("l96")
    >>> run, truth = repudiation_scenario(
    ...     cell, trial_seeds("repudiation-curve", "l96", 0)
    ... )
    >>> truth.hypothesis, truth.engaged, truth.engaged_count > 0
    ('repudiation', True, True)
    >>> run.symmetrised
    True

    The unsymmetrised control is the same adversary against the variant that
    has no non-repudiation at all, and it exists so that a rung reporting zero
    can be told from a rung whose attack stopped working:

    >>> control = experiment("repudiation-curve").cell("unsym192")
    >>> run, truth = repudiation_scenario(
    ...     control, trial_seeds("repudiation-curve", "unsym192", 0)
    ... )
    >>> run.symmetrised, run.repudiated
    (False, True)
    >>> truth.targeted_link
    'Charlie'
    """
    strength = float(_require(cell, "strength"))
    symmetrised = bool(_require(cell, "symmetrised"))
    target = cell.scenario_options.get("target")
    alice = TiltingPreparation(
        strength,
        rng=seeds.adversary_rng(),
        message_bit=cell.message_bit,
        target=target,
    )
    wiring: dict[str, Any] = {"payload_map": alice}
    if not symmetrised:
        wiring["symmetriser"] = no_symmetrisation
    transcript = _session(cell, seeds, **wiring)
    flips = int(alice.flips)
    return transcript, GroundTruth(
        hypothesis=cell.truth_hypothesis,
        engaged=flips > 0,
        engaged_count=flips,
        targeted_link=None if target is None else str(target),
        detectable=cell.detectable,
        notes=cell.notes,
    )


def outside_forgery_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Run one session against Eve on the signer seam, and label it from her log.

    Her declaration reaches **both** verifiers, so one run measures her against
    ``s_a`` and ``s_v`` at once and the table carries both columns.

    Parameters
    ----------
    cell : Cell
        ``scenario_options`` must name ``count_exchange_timing``.
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)

    Raises
    ------
    KeyError
        If ``count_exchange_timing`` is absent.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.security import outside_forgery_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> cell = experiment("forgery-curve").cell("eve24")
    >>> run, truth = outside_forgery_scenario(
    ...     cell, trial_seeds("forgery-curve", "eve24", 0)
    ... )
    >>> truth.hypothesis, truth.engaged
    ('outside-forgery', True)
    >>> truth.engaged_count > 12
    True
    """
    eve = LoggingOutsideForger(rng=seeds.adversary_rng())
    transcript = _session(cell, seeds, signer=eve)
    footprint = int(eve.substituted_positions)
    return transcript, GroundTruth(
        hypothesis=cell.truth_hypothesis,
        engaged=footprint > 0,
        engaged_count=footprint,
        targeted_link=None,
        detectable=cell.detectable,
        notes=cell.notes,
    )


def recipient_forgery_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Run one session against Bob forging to Charlie, and label it from his log.

    Parameters
    ----------
    cell : Cell
        ``scenario_options`` must name ``count_exchange_timing``, which is the
        column this arm turns on: see :ref:`security-timing`.
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged`` is ``True`` only when the forwarded declaration really
        differs from Alice's. A forwarder that passed it through would be an
        honest Bob and the run would be an honest run.

    Raises
    ------
    KeyError
        If ``count_exchange_timing`` is absent.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.security import recipient_forgery_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> cell = experiment("forgery-curve").cell("bob96after")
    >>> run, truth = recipient_forgery_scenario(
    ...     cell, trial_seeds("forgery-curve", "bob96after", 0)
    ... )
    >>> truth.hypothesis, truth.engaged, run.forwarding_altered_signature
    ('recipient-forgery', True, True)

    Under the earlier ordering the same attack cannot be scored at all -- both
    verifiers refuse, because a substituted declaration leaves the pooled
    matched count undefined:

    >>> before = experiment("forgery-curve").cell("bob96before")
    >>> run, _ = recipient_forgery_scenario(
    ...     before, trial_seeds("forgery-curve", "bob96before", 0)
    ... )
    >>> run.aborted, run.charlie is None
    (True, True)
    """
    bob = LoggingRecipientForger(rng=seeds.adversary_rng())
    transcript = _session(cell, seeds, forwarder=bob)
    footprint = int(bob.substituted_positions)
    return transcript, GroundTruth(
        hypothesis=cell.truth_hypothesis,
        engaged=footprint > 0,
        engaged_count=footprint,
        targeted_link=str(Party.CHARLIE),
        detectable=cell.detectable,
        notes=cell.notes,
    )


SECURITY_SCENARIOS: Final[dict[str, Any]] = {
    "security-tilt": repudiation_scenario,
    "security-outside-forgery": outside_forgery_scenario,
    "security-recipient-forgery": recipient_forgery_scenario,
}
"""dict: This family's scenarios, by name.

Prefixed, because :data:`~sih141.eval.experiments.SCENARIOS` is shared by every
Phase 5 family and two families registering ``outside-forgery`` would silently
give whichever imported last. :func:`register` refuses a collision rather than
resolving one.
"""


SECURITY_PROBE_OPTIONS: Final[dict[str, dict[str, Any]]] = {
    "security-tilt": {
        "strength": 0.25,
        "symmetrised": True,
        "count_exchange_timing": COUNTS_BEFORE_FORWARDING,
    },
    "security-outside-forgery": {
        "count_exchange_timing": COUNTS_BEFORE_FORWARDING
    },
    "security-recipient-forgery": {
        "count_exchange_timing": COUNTS_BEFORE_FORWARDING
    },
}
"""dict: The smallest ``scenario_options`` that make each scenario run at all.

Every scenario in this family refuses a missing option rather than defaulting
it (:func:`_require`), because a defaulted typo is how an inert arm comes to
report a clean zero. The price is that none of them can be constructed
generically, and ``tests/test_eval_harness.py`` has a contract test that runs
*every* registered scenario twice at one seed pair and compares -- so a family
that registers a scenario has to say how to build one.
:func:`register` copies these into
:data:`~sih141.eval.experiments.SCENARIO_PROBE_OPTIONS`.

Nothing here reaches a published number: these are the harness's probe values,
not a cell's. The cells carry their own, and
``tests/test_eval_security.py`` checks that every registered cell does.

>>> from sih141.eval.experiments import SCENARIO_PROBE_OPTIONS
>>> sorted(name for name in SCENARIO_PROBE_OPTIONS if name.startswith("security-"))
['security-outside-forgery', 'security-recipient-forgery', 'security-tilt']
"""


# --------------------------------------------------------------------------- #
# 5. The cells
# --------------------------------------------------------------------------- #


def _repudiation_cells() -> tuple[Cell, ...]:
    """Build the repudiation experiment's cells, in table order.

    Returns
    -------
    tuple of Cell
        The measured ladder first, then the ordering control, then the
        unsymmetrised positive controls. ``check_fraction`` is zero throughout:
        this family measures the *signing* statistics, so every check round
        would be a position spent on a question it does not ask. The
        consequence is that the channel detector family is withheld on every
        run, which the standard detection table reports as ``not evaluated``
        and never as passed (Phase 3 constraint 8).
    """
    cells: list[Cell] = []
    for length, strength in REPUDIATION_LADDER:
        claim = "carries a security claim" if security_claim_at(length) else (
            "NO security claim: both matched-count floors degenerate to 1"
        )
        cells.append(
            Cell(
                name=f"l{length}",
                params=ProtocolParams(key_length=length),
                scenario="security-tilt",
                scenario_options={
                    "strength": strength,
                    "symmetrised": True,
                    "count_exchange_timing": COUNTS_BEFORE_FORWARDING,
                },
                truth_hypothesis="repudiation",
                notes=(
                    f"symmetric tilt q={strength} on both deliveries; {claim}"
                ),
            )
        )
    control_length = 192
    control_strength = dict(REPUDIATION_LADDER)[control_length]
    cells.append(
        Cell(
            name=f"l{control_length}after",
            params=ProtocolParams(key_length=control_length),
            scenario="security-tilt",
            scenario_options={
                "strength": control_strength,
                "symmetrised": True,
                "count_exchange_timing": COUNTS_AFTER_FORWARDING,
            },
            truth_hypothesis="repudiation",
            notes=(
                f"the l{control_length} rung under the other count ordering; "
                f"the ordering control, so 'the ordering does not move this "
                f"attack' is measured rather than assumed"
            ),
        )
    )
    for length in (192, 384, 768):
        cells.append(
            Cell(
                name=f"unsym{length}",
                params=ProtocolParams(key_length=length),
                scenario="security-tilt",
                scenario_options={
                    "strength": CONTROL_TILT,
                    "symmetrised": False,
                    "target": str(Party.CHARLIE),
                    "count_exchange_timing": COUNTS_BEFORE_FORWARDING,
                },
                truth_hypothesis="repudiation",
                notes=(
                    "POSITIVE CONTROL: the same adversary against the variant "
                    "with no symmetrisation exchange, where repudiation "
                    "succeeds at every key length. A rung above that reports "
                    "zero is a rung where the attack failed, not one where it "
                    "was never mounted."
                ),
            )
        )
    return tuple(cells)


def _forgery_cells() -> tuple[Cell, ...]:
    """Build the forgery experiment's cells, in table order.

    Returns
    -------
    tuple of Cell
        Eve's four short anchors, one ordering control for her, then the
        recipient forger at five key lengths under **both** count orderings --
        which is the arm where the ordering changes the answer rather than
        merely being recorded.
    """
    cells: list[Cell] = []
    for length in OUTSIDE_LADDER:
        cells.append(
            Cell(
                name=f"eve{length}",
                params=ProtocolParams(key_length=length),
                scenario="security-outside-forgery",
                scenario_options={
                    "count_exchange_timing": COUNTS_BEFORE_FORWARDING
                },
                truth_hypothesis="outside-forgery",
                notes=(
                    "Eve on the signer seam; her declaration reaches both "
                    "verifiers. NO security claim at this length."
                ),
            )
        )
    cells.append(
        Cell(
            name="eve24after",
            params=ProtocolParams(key_length=24),
            scenario="security-outside-forgery",
            scenario_options={
                "count_exchange_timing": COUNTS_AFTER_FORWARDING
            },
            truth_hypothesis="outside-forgery",
            notes="the eve24 anchor under the other ordering; the control",
        )
    )
    for length in RECIPIENT_LADDER:
        for suffix, timing in (
            ("before", COUNTS_BEFORE_FORWARDING),
            ("after", COUNTS_AFTER_FORWARDING),
        ):
            cells.append(
                Cell(
                    name=f"bob{length}{suffix}",
                    params=ProtocolParams(key_length=length),
                    scenario="security-recipient-forgery",
                    scenario_options={"count_exchange_timing": timing},
                    truth_hypothesis="recipient-forgery",
                    notes=(
                        f"Bob forging to Charlie, counts exchanged {suffix} "
                        f"forwarding. The two orderings give different "
                        f"answers to this attack and are never pooled."
                    ),
                )
            )
    return tuple(cells)


_SINGLETON: dict[str, Experiment] = {}
"""dict: This family's experiments, built once and reused ever after.

Lazy rather than module-level constants, because a :class:`Cell` validates its
scenario against :data:`~sih141.eval.experiments.SCENARIOS` on construction and
this family's scenarios are not there until :func:`register` has put them
there. Reused rather than rebuilt so that :func:`register` can decide by
*identity* whether a slot is this family's or somebody else's: a rebuilt
experiment is equal but distinct, and the collision check would fire on the
second call and make ``register`` non-idempotent.
"""


def _built(name: str, build: Any) -> Experiment:
    """Return this family's experiment ``name``, building it at most once.

    Parameters
    ----------
    name : str
        Experiment name, and the cache key.
    build : callable
        Zero-argument builder, called only on a miss.

    Returns
    -------
    Experiment
        The same object on every call, so :func:`register` is idempotent.
    """
    made = _SINGLETON.get(name)
    if made is None:
        made = build()
        _SINGLETON[name] = made
    return made


def _repudiation_experiment() -> Experiment:
    """Build the repudiation experiment.

    Returns
    -------
    Experiment
    """
    return Experiment(
        name="repudiation-curve",
        description=(
            "How often a repudiating signer succeeds against the shipped "
            "protocol, against key length, with the proven a-priori bound "
            "beside the measured rate and an unsymmetrised positive control."
        ),
        trials=REPUDIATION_TRIALS,
        cells=_repudiation_cells(),
    )


def _forgery_experiment() -> Experiment:
    """Build the forgery experiment.

    Returns
    -------
    Experiment
    """
    return Experiment(
        name="forgery-curve",
        description=(
            "How often a forged declaration is accepted, against key length, "
            "for the outside forger and for the binding one -- a recipient "
            "who holds half the target's evidence -- at both count orderings."
        ),
        trials=FORGERY_TRIALS,
        cells=_forgery_cells(),
    )


# --------------------------------------------------------------------------- #
# 6. The reductions
# --------------------------------------------------------------------------- #


def repudiated_from_verdicts(record: TrialRecord) -> bool:
    """Recompute the repudiation event from the recorded verdicts.

    The second route. ``transcript_summary["repudiated"]`` is the transcript's
    own property, computed inside the session from its
    :class:`~sih141.protocol.verify.VerificationResult` objects; this rebuilds
    the same event from the verdict strings, which
    :func:`~sih141.eval.records.transcript_summary` wrote from
    ``results_by_party`` and ``aborts_by_party``. The two must agree on every
    record, and ``tests/test_eval_security.py`` asserts that they do -- a check
    that would be vacuous if the table read one field and the test read the
    same one.

    Parameters
    ----------
    record : TrialRecord
        One trial.

    Returns
    -------
    bool
        ``True`` iff Bob accepted, Charlie rejected, the forwarding hop left
        the declaration alone, and the run is one coherent session. A refusal
        at either verifier is **not** a repudiation: a verifier who reached no
        verdict did not reject.

    Examples
    --------
    >>> from sih141.eval.experiments import experiment, run_trial
    >>> from sih141.eval.security import repudiated_from_verdicts
    >>> record = run_trial(experiment("repudiation-curve"), "unsym192", 0)
    >>> repudiated_from_verdicts(record)
    True
    >>> record.transcript_summary["repudiated"]
    True
    """
    summary = record.transcript_summary
    verdicts: Mapping[str, str] = summary["verdicts"]
    return (
        verdicts.get(str(Party.BOB)) == "accepted"
        and verdicts.get(str(Party.CHARLIE)) == "rejected"
        and not bool(summary["forwarding_altered_signature"])
        and bool(summary["session_coherent"])
    )


def _params_of(record: TrialRecord) -> ProtocolParams:
    """Rebuild the parameter set a record ran under.

    Parameters
    ----------
    record : TrialRecord
        One trial.

    Returns
    -------
    ProtocolParams
    """
    return ProtocolParams.from_dict(record.params)


def _option(experiment_name: str, cell: str, key: str) -> Any:
    """Return one scenario option for a cell, from the registry.

    Parameters
    ----------
    experiment_name : str
        Which experiment.
    cell : str
        Which cell.
    key : str
        The option.

    Returns
    -------
    object or None
        ``None`` when the experiment or the cell has left the registry. Rows
        for such a cell still appear -- ordering by the registry must not
        become filtering by it -- with the columns that needed the option
        marked unknown rather than guessed.
    """
    registered = EXPERIMENTS.get(experiment_name)
    if registered is None:
        return None
    try:
        return registered.cell(cell).scenario_options.get(key)
    except KeyError:
        return None


def _verdict(record: TrialRecord, party: Party) -> str:
    """Return one party's verdict on a run.

    Parameters
    ----------
    record : TrialRecord
        One trial.
    party : Party
        Bob or Charlie.

    Returns
    -------
    str
        ``"accepted"``, ``"rejected"``, ``"refused"``, or ``"not asked"`` for a
        party the protocol never put the question to -- a third thing again,
        and never folded into a refusal.
    """
    return str(record.transcript_summary["verdicts"].get(str(party), "not asked"))


def repudiation_curve_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate the measured repudiation rate against the proven bound.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order; see
        :func:`~sih141.eval.reduce.group_records`.

    Returns
    -------
    Table
        One row per ``(cell, count_exchange_timing)``. Three columns carry
        probabilities and they are three different kinds of claim, so the
        header says which each is: ``repudiated (measured)`` is a measurement
        with a sample size and a Wilson interval, ``exact in-model P``
        (:func:`~sih141.protocol.analysis.repudiation_probability`) is the
        closed form for this adversary's own family, and ``enforced bound
        (proven)`` holds for **every** signer strategy.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Notes
    -----
    The denominator is runs whose tilt engaged, and the runs that reached no
    verdict are inside it: a refusal means Bob did not accept, so the
    repudiation event did not occur. That is also the denominator the proven
    bound is stated over, which is what lets the two columns be read against
    each other -- and ``no verdict`` is printed as its own column so that the
    sentence is checkable rather than trusted.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.security import repudiation_curve_table
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("repudiation-curve"), store,
    ...                        trials=2, cells=["unsym192"], workers=1,
    ...                        in_process=True, quiet=True)
    ...     table = repudiation_curve_table(list(store.read_experiment(
    ...         "repudiation-curve")))
    ...     table.columns[:4]
    ...     table.rows[0][0], table.rows[0][3], table.rows[0][8]
    ('cell', 'key_length', 'count ordering', 'symmetrised')
    ('unsym192', 'no', '2/2 = 1.0000 [0.2316, 1.0000]')
    """
    if not records:
        raise ValueError("repudiation_curve_table needs at least one record")
    rows: list[tuple[Any, ...]] = []
    grouped = group_records(records, cell_order=cell_order)
    for (cell, timing), group in grouped.items():
        params = _params_of(group[0])
        engaged = [r for r in group if r.truth.attacked]
        idle = len(group) - len(engaged)
        repudiations = sum(1 for r in engaged if repudiated_from_verdicts(r))
        refusals = sum(1 for r in engaged if refused_run(r))
        bob_accepted = sum(
            1 for r in engaged if _verdict(r, Party.BOB) == "accepted"
        )
        symmetrised = {bool(r.transcript_summary["symmetrised"]) for r in group}
        strength = _option(group[0].experiment, cell, "strength")
        target = _option(group[0].experiment, cell, "target")
        if strength is None:
            exact = "unknown (cell not in the registry)"
            tilt = "unknown"
        else:
            tilt = f"{float(strength):.3f}"
            # The closed form describes ONE family: a signer who tilts both
            # deliveries independently at rate q, against the symmetrised
            # protocol. Printing it on a row that ran something else -- an
            # aimed tilt, or the variant with no exchange -- would put a
            # 2.3e-09 next to a measured 8/8 and read as a contradiction
            # rather than as a column that does not apply.
            if symmetrised != {True} or target is not None:
                exact = "n/a: closed form assumes the symmetrised, untargeted family"
            else:
                exact = (
                    f"{repudiation_probability(params, mismatch_probability=float(strength)):.3e}"
                )
        mean_flips = (
            sum(int(r.truth.engaged_count or 0) for r in group) / len(group)
        )
        rows.append(
            (
                cell,
                params.key_length,
                timing,
                "yes" if symmetrised == {True} else
                "no" if symmetrised == {False} else "mixed",
                tilt,
                len(group),
                len(engaged),
                idle,
                measured_rate(repudiations, len(engaged), places=4),
                refusals,
                bob_accepted,
                f"{mean_flips:.1f}",
                exact,
                _format_log10(enforced_bound_log10(params)),
                "yes" if security_claim_at(params.signing_length) else "no",
            )
        )
    return Table(
        slug="repudiation-curve",
        title="Repudiation against key length: measured, exact and proven",
        columns=(
            "cell",
            "key_length",
            "count ordering",
            "symmetrised",
            "tilt q",
            "runs",
            "engaged",
            "not engaged",
            "repudiated (measured)",
            "no verdict",
            "Bob accepted",
            "mean states flipped",
            "exact in-model P (closed form)",
            "enforced bound (proven)",
            "security claim",
        ),
        rows=tuple(rows),
        command=command,
        notes=_repudiation_notes(rows, dominance=_dominance_note(records)),
    )


def _dominance_note(records: Sequence[TrialRecord]) -> str:
    """Return the mismatch detector's dominance crossover at this family's scale.

    Phase 3 constraint 9 asks for
    :func:`~sih141.detect.thresholds_rate.dominance_noise_level` beside every
    mismatch-rate detection rate. This family's own tables publish protocol
    *outcomes* rather than detector signals, but ``tools/sweep.py reduce``
    prints the standard detection table immediately above these, and its
    ``flagged`` column includes the mismatch-rate members -- so the number
    belongs here, where a reader of that column will see it.

    Parameters
    ----------
    records : Sequence of TrialRecord
        The trials being reduced. Their observed per-verifier matched counts
        set the scale.

    Returns
    -------
    str
        Empty when no record carries a matched count.
    """
    counts: list[int] = []
    for record in records:
        counts.extend(
            int(value) for value in record.transcript_summary["matched"].values()
        )
    counts = [value for value in counts if value > 0]
    if not counts:
        return ""
    params = _params_of(records[0])
    # The budget the trials were actually scored at, not this module's default:
    # a cell run at another eps would get a crossover it never saw.
    budgets = {float(record.eps) for record in records}
    eps = max(budgets) if len(budgets) == 1 else DEFAULT_EPS
    low, high = min(counts), max(counts)
    return (
        "DOMINANCE (Phase 3 constraint 9), for the detection table printed "
        "above these: the mismatch-rate detector stops adding anything over a "
        "verifier's own cut once the link error rate exceeds "
        f"dominance_noise_level, which over the matched counts these runs "
        f"produced (|M_R| from {low} to {high}) is "
        f"{dominance_noise_level(low, params.s_v, eps=eps):.6f} to "
        f"{dominance_noise_level(high, params.s_v, eps=eps):.6f} at "
        f"Charlie's cut -- far below the design noise level 2 s_a = "
        f"{2 * params.s_a:.5f}, and at the short end essentially zero. At "
        "demo scale that detector is dominated on any link that is noisy at "
        "all. It is not dominated here only because these runs are on a "
        "genuinely noiseless link, so the noiseless null is the truth and the "
        "mismatches come from Alice."
    )


def _repudiation_notes(
    rows: Sequence[tuple[Any, ...]], *, dominance: str = ""
) -> tuple[str, ...]:
    """Build the repudiation table's footnotes, including the sharp one.

    Parameters
    ----------
    rows : Sequence of tuple
        The rows already built, so the note about the top of the ladder quotes
        the row it is about instead of a remembered number.
    dominance : str, optional
        Keyword-only. The dominance note from :func:`_dominance_note`, if the
        records supported one.

    Returns
    -------
    tuple of str
    """
    notes = [
        "DENOMINATOR: `engaged` -- runs whose tilt actually replaced at least "
        "one delivered state, read off the adversary's own counter. "
        "`not engaged` runs are byte-identical to honest runs and are scored "
        "as honest runs, not as missed repudiations.",
        "ABORTS: the `no verdict` runs are INSIDE the denominator and are NOT "
        "repudiations. A verifier who reached no verdict did not accept, so "
        "the repudiation event did not occur; and that is the same "
        "denominator the proven bound is stated over, which is what lets the "
        "two columns be compared at all. No column here sums a refusal with a "
        "rejection.",
        "`repudiated (measured)` is a MEASUREMENT with a sample size, shown as "
        f"k/n with a {CONFIDENCE:.0%} Wilson interval. There is no "
        "false-negative bound and there cannot be one from a transcript.",
        "`exact in-model P` is repudiation_probability(params, q): the exact "
        "closed form for THIS adversary's family -- a signer who tilts both "
        "deliveries independently at rate q -- and an independent route to "
        "the same number. It is not a bound over all strategies.",
        "`enforced bound (proven)` is exp(-max(2 m_min, M_min) gap^2 / 8), "
        "which holds for EVERY signer strategy with no independence "
        "assumption. Measured and proven never share a column.",
        "`security claim` is False where both matched-count floors degenerate "
        "to 1. Those rows are still real measurements of a real protocol; what "
        "they carry no claim about is the bound.",
        "`count ordering` is a column, never averaged over (Phase 3 "
        "constraint 2). The l192after row is the control that says so for "
        "this attack rather than assuming it.",
        "`exact in-model P` reads `n/a` on any row that did not run the "
        "family it describes -- an aimed tilt, or the variant with no "
        "symmetrisation exchange. A number there would look like a "
        "contradiction of the measurement rather than a column that does not "
        "apply.",
        "The `unsym*` rows are a POSITIVE CONTROL, not a result: the same "
        "adversary against the variant with no symmetrisation exchange, where "
        "repudiation succeeds at every key length. They are what tells a rung "
        "reporting zero apart from a rung whose attack was never mounted.",
        "transcript.repudiated is used here as the OUTCOME of a labelled "
        "experiment, never as a detector signal: it cannot tell signer "
        "misbehaviour from channel noise from recipient forgery (Phase 3 "
        "constraint 7), which is exactly why the harness knows the truth and "
        "the detector does not.",
        "The link is noiseless and the detector was given the noiseless null, "
        "so the null here IS the truth; the mismatches these runs show come "
        "from Alice's preparation and not from the wire.",
    ]
    if dominance:
        notes.append(dominance)
    zeros = [
        row
        for row in rows
        if isinstance(row[8], str)
        and row[8].startswith("0/")
        and not str(row[12]).startswith("n/a")
    ]
    if zeros:
        # The longest key that measured zero, not the first: that is the row
        # where the gap between what a sample can see and where the claim
        # lives is widest, and it is the row the sentence is about.
        worst = max(zeros, key=lambda row: int(row[1]))
        notes.append(
            "WHERE DEMO-SCALE RUNS CANNOT DEMONSTRATE NON-REPUDIATION: "
            f"the {worst[0]} row measures {worst[8]}, whose upper limit is "
            f"still far above the exact probability {worst[12]} and far below "
            f"the proven bound {worst[13]}. The proof is loose over exactly "
            "the range a measurement can reach, and the region the security "
            "claim lives in (1.4e-09 at L=115200) is unreachable by both. A "
            "measured zero here is evidence the mechanism works, never "
            "confirmation of the bound."
        )
    return tuple(notes)


def floor_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate the matched-count floors and what they buy, against key length.

    Purely analytic: every column is a closed form in the parameter set, so no
    column here is a measurement and none is labelled one. The records are used
    for one thing -- marking which rows a measurement was actually made at, so
    that a reader can tell a rung of the curve from an extrapolation of it.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order. Their key lengths are added to :data:`FLOOR_LADDER`.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Unused; accepted so the signature matches the reduction
        contract.

    Returns
    -------
    Table
        One row per key length, ascending.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.security import floor_table
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("repudiation-curve"), store,
    ...                        trials=1, cells=["l24"], workers=1,
    ...                        in_process=True, quiet=True)
    ...     table = floor_table(list(store.read_experiment(
    ...         "repudiation-curve")))
    >>> table.columns[:5]
    ('key_length', 'm_min', 'M_min', 'floor on M', 'security claim')
    >>> [row[:5] for row in table.rows if row[0] in (136, 137, 273)]
    [(136, 1, 1, 2, 'no'), (137, 1, 2, 2, 'yes'), (273, 2, 55, 55, 'yes')]
    """
    del cell_order
    lengths = set(FLOOR_LADDER)
    for record in records:
        lengths.add(int(_params_of(record).signing_length))
    measured = {int(_params_of(record).signing_length) for record in records}
    rows: list[tuple[Any, ...]] = []
    for length in sorted(lengths):
        params = ProtocolParams(key_length=length)
        rows.append(
            (
                length,
                minimum_matched_count(params),
                minimum_pooled_matched_count(params),
                guaranteed_pooled_matched_count(params),
                "yes" if security_claim_at(length) else "no",
                f"{params.gap:.6f}",
                _format_log10(enforced_bound_log10(params)),
                _format_log10(recipient_forgery_bound_log10(params)),
                _format_log10(outside_forgery_bound_log10(params)),
                "yes" if length in measured else "-",
            )
        )
    return Table(
        slug="security-floors",
        title="Matched-count floors and the bounds they buy, by key length",
        columns=(
            "key_length",
            "m_min",
            "M_min",
            "floor on M",
            "security claim",
            "gap s_v - s_a",
            "enforced repudiation bound (proven)",
            "recipient-forgery bound (proven)",
            "outside-forgery bound (proven)",
            "measured here",
        ),
        rows=tuple(rows),
        command=command,
        notes=(
            "EVERY column here is a closed form in the parameter set. None is "
            "a measurement and none is labelled one; `measured here` says "
            "only which key lengths this sweep also ran trials at.",
            f"`security claim` turns on at L = {FLOOR_CROSSOVER}, where the "
            "POOLED floor first exceeds 1. The per-verifier floor does not "
            f"bite until L = {PER_VERIFIER_CROSSOVER}. Below the crossover "
            "both floors are 1 -- 'abort only on an empty matched set' -- and "
            "every number in the run still computes cheerfully, which is why "
            "the column exists.",
            "The bounds are the KL form, which is never weaker than the "
            "Hoeffding one. They are printed from log10 rather than from the "
            "library's float: forgery_bound underflows to 0.0 at L = 115200, "
            "and a bound of exactly zero is a claim no proof supports.",
            "`floor on M` is max(2 m_min, M_min), the pooled evidence base the "
            "shipped rules guarantee on any run that reaches a verdict. It is "
            "what the enforced repudiation bound is evaluated at.",
            "The enforced bound is a-priori and holds for every signer "
            "strategy. The per-run bound a completed run should quote is "
            "repudiation_bound at its OWN observed M, which every transcript "
            "carries as repudiation_guarantee.",
        ),
    )


VERIFIER_CUTS: Final[tuple[float, ...]] = (
    1.0 / 32.0,
    3.0 / 64.0,
    1.0 / 16.0,
    5.0 / 64.0,
    0.08,
)
"""tuple: The ``s_v`` values :func:`gap_table` walks, with ``s_a`` held fixed.

Strictly below the recipient forger's ``1/12`` floor, which
:class:`~sih141.protocol.params.ProtocolParams` refuses to cross: at or above
it the optimal forger's own mismatch rate is inside the acceptance region and
there is no forgery guarantee left to state. The last rung, ``0.08``, is 96% of
the way there and is what that costs.
"""

SIGNER_CUTS: Final[tuple[float, ...]] = (
    0.0,
    1.0 / 128.0,
    1.0 / 64.0,
    1.0 / 32.0,
    3.0 / 64.0,
)
"""tuple: The ``s_a`` values :func:`gap_table` walks, with ``s_v`` held fixed.

``s_a`` is a noise budget rather than a security parameter: an honest signature
survives a link of depolarising strength up to ``2 s_a``, so shrinking it to
buy gap buys the gap out of the scheme's tolerance for a real channel.
"""


def gap_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate what the ``s_a`` / ``s_v`` gap buys and what it costs.

    The gap ``s_v - s_a`` is the whole content of the repudiation exponent --
    ``exp(-M gap^2 / 8)`` -- so every way of widening it improves the
    repudiation bound. Neither way is free, and the table exists because the two
    prices are paid in different currencies and a single-column view of the gap
    hides both:

    * raising ``s_v`` walks the acceptance threshold towards the recipient
      forger's ``1/12`` floor, and the forgery bound degrades to ``1`` as it
      arrives -- there is then no forgery guarantee at all;
    * lowering ``s_a`` walks it towards zero, and the link noise an honest
      signature survives, ``2 s_a``, goes with it.

    Purely analytic, at :data:`~sih141.protocol.params.DEFAULT_PARAMS`' key
    length, which is the only place these numbers describe a claim anyone
    makes. The records are not read; the parameter is accepted so the signature
    matches the reduction contract.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Unused.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Unused.

    Returns
    -------
    Table
        One row per parameter set, the shipped one marked.

    Examples
    --------
    >>> from sih141.eval.security import gap_table
    >>> table = gap_table([])
    >>> table.columns[:4]
    ('knob', 's_a', 's_v', 'gap s_v - s_a')

    The shipped set is a rung of both ladders, which is what makes them
    comparable: each one is a walk away from the same point.

    >>> shipped = [row for row in table.rows if row[7] == "SHIPPED"]
    >>> len(shipped), shipped[0][1], shipped[0][2]
    (2, '0.015625', '0.062500')
    >>> shipped[0][4:7] == shipped[1][4:7]
    True

    Widening the gap by pushing ``s_v`` up improves the repudiation bound by
    eight orders of magnitude and destroys the forgery bound on the way -- from
    ``1.12e-103`` at the shipped cut to ``3.50e-03``, a hundred orders of
    magnitude of forgery security spent to buy eight of repudiation:

    >>> widest = [row for row in table.rows if row[0] == "s_v"][-1]
    >>> widest[2], widest[4], widest[5]
    ('0.080000', '2.039e-17', '3.502e-03')
    >>> shipped[0][4], shipped[0][5]
    ('1.414e-09', '1.124e-103')

    Lowering ``s_a`` buys the same gap out of a different pocket: the
    repudiation bound improves and the link noise an honest signature survives
    goes to zero with it.

    >>> quietest = [row for row in table.rows if row[0] == "s_a"][0]
    >>> quietest[1], quietest[4], quietest[5], quietest[6]
    ('0.000000', '1.851e-16', '1.124e-103', '0.00000')
    """
    del records, cell_order
    rows: list[tuple[Any, ...]] = []
    for knob, values in (("s_v", VERIFIER_CUTS), ("s_a", SIGNER_CUTS)):
        for value in values:
            params = DEFAULT_PARAMS.with_changes(**{knob: value})
            shipped = (
                params.s_a == DEFAULT_PARAMS.s_a
                and params.s_v == DEFAULT_PARAMS.s_v
            )
            rows.append(
                (
                    knob,
                    f"{params.s_a:.6f}",
                    f"{params.s_v:.6f}",
                    f"{params.gap:.6f}",
                    _format_log10(enforced_bound_log10(params)),
                    _format_log10(recipient_forgery_bound_log10(params)),
                    f"{2 * params.s_a:.5f}",
                    "SHIPPED" if shipped else "-",
                )
            )
    return Table(
        slug="security-gap",
        title=(
            "What the s_a / s_v gap buys and what it costs, at L = "
            f"{DEFAULT_PARAMS.key_length}"
        ),
        columns=(
            "knob",
            "s_a",
            "s_v",
            "gap s_v - s_a",
            "enforced repudiation bound (proven)",
            "recipient-forgery bound (proven)",
            "link noise tolerated 2 s_a",
            "",
        ),
        rows=tuple(rows),
        command=command,
        notes=(
            "EVERY column is a closed form at the shipped key length. None is "
            "a measurement.",
            "Both bounds are exponential in the gap, and every way of widening "
            "it costs something: raising s_v walks the acceptance threshold "
            f"towards the recipient forger's floor of "
            f"{DEFAULT_PARAMS.forger_floor:.6f}, where the forgery bound "
            "reaches 1 and there is no guarantee left; lowering s_a shrinks "
            "the link noise an honest signature survives, which is 2 s_a.",
            "ProtocolParams REFUSES an s_v at or above the forger floor unless "
            "allow_forgeable is set, so the ladder stops at 0.08 -- 96% of the "
            "way there, and the row that shows what the last few percent cost.",
            "The shipped s_v = 1/16 is three quarters of the floor. That is "
            "the choice this table exists to make checkable rather than "
            "assert: it buys 1.41e-09 repudiation and 1.12e-103 recipient "
            "forgery at once, and neither neighbour on this ladder does. The "
            "next rung up spends about a hundred orders of magnitude of "
            "forgery security to buy eight of repudiation, which is what "
            "'three quarters of the floor' is protecting.",
        ),
    )


def forgery_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate the measured forgery rate against the exact and proven ones.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order.

    Returns
    -------
    Table
        One row per ``(cell, count_exchange_timing)``. Charlie is the target in
        both arms -- his threshold ``s_v`` is the looser of the two -- so his
        three outcome counts are separate columns and sum to the denominator
        exactly. Bob's acceptance is a fourth column for Eve, who reaches both
        verifiers, and is ``forger`` for the recipient arm, where Bob is the
        adversary rather than a target.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.security import forgery_table
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("forgery-curve"), store, trials=2,
    ...                        cells=["bob96before"], workers=1,
    ...                        in_process=True, quiet=True)
    ...     table = forgery_table(list(store.read_experiment("forgery-curve")))
    ...     table.rows[0][1], table.rows[0][3], table.rows[0][8]
    ('recipient-forgery', 'before-forwarding', 2)

    Both runs end in a refusal at Charlie, not a rejection, and the row says so
    rather than reporting a clean zero:

    >>> table.rows[0][6], table.rows[0][7]
    ('0/2 = 0.0000 [0.0000, 0.7684]', 0)
    """
    if not records:
        raise ValueError("forgery_table needs at least one record")
    rows: list[tuple[Any, ...]] = []
    for (cell, timing), group in group_records(
        records, cell_order=cell_order
    ).items():
        params = _params_of(group[0])
        hypotheses = sorted({r.truth.hypothesis for r in group})
        adversary = ", ".join(hypotheses)
        engaged = [r for r in group if r.truth.attacked]
        idle = len(group) - len(engaged)
        accepted = sum(
            1 for r in engaged if _verdict(r, Party.CHARLIE) == "accepted"
        )
        rejected = sum(
            1 for r in engaged if _verdict(r, Party.CHARLIE) == "rejected"
        )
        refused = sum(
            1
            for r in engaged
            if _verdict(r, Party.CHARLIE) in ("refused", "not asked")
        )
        outside = hypotheses == ["outside-forgery"]
        if outside:
            bob_cell: Any = measured_rate(
                sum(1 for r in engaged if _verdict(r, Party.BOB) == "accepted"),
                len(engaged),
                places=4,
            )
            exact = f"{forgery_probability(params):.4e}"
            proven = _format_log10(outside_forgery_bound_log10(params))
        else:
            bob_cell = "forger"
            exact = f"{recipient_forgery_probability(params):.4e}"
            proven = _format_log10(recipient_forgery_bound_log10(params))
        rows.append(
            (
                cell,
                adversary,
                params.key_length,
                timing,
                len(group),
                len(engaged),
                measured_rate(accepted, len(engaged), places=4),
                rejected,
                refused,
                idle,
                bob_cell,
                exact,
                proven,
                "yes" if security_claim_at(params.signing_length) else "no",
            )
        )
    return Table(
        slug="forgery-curve",
        title="Forgery against key length: measured, exact and proven",
        columns=(
            "cell",
            "adversary",
            "key_length",
            "count ordering",
            "runs",
            "engaged",
            "Charlie accepted (measured)",
            "Charlie rejected",
            "Charlie no verdict",
            "not engaged",
            "Bob accepted (measured)",
            "exact P (closed form)",
            "proven bound",
            "security claim",
        ),
        rows=tuple(rows),
        command=command,
        notes=(
            "DENOMINATOR: `engaged` -- runs where the forger's declaration "
            "really differed from Alice's, counted position by position on the "
            "adversary's own log. `Charlie accepted` + `Charlie rejected` + "
            "`Charlie no verdict` = `engaged`, exactly.",
            "ABORTS: `Charlie no verdict` is a REFUSAL, not a rejection, and "
            "it is never folded into one. Under the before-forwarding "
            "ordering the recipient-forgery rows are ALL refusals: a "
            "substituted declaration leaves CHARLIE'S pooled matched count "
            "undefined, so Bob accepts the genuine declaration he was sent "
            "and Charlie alone reaches no verdict. The attack is a denial "
            "of transfer rather than a detected forgery.",
            "COUNT ORDERING IS A COLUMN AND HERE IS WHY (Phase 3 constraint "
            "2): the same attack against the same code gives all refusals "
            "before forwarding and a real acceptance rate after it. Pooling "
            "the two would publish a figure describing neither.",
            f"`Charlie accepted (measured)` carries a {CONFIDENCE:.0%} Wilson "
            "interval and the word `measured`. `proven bound` holds against "
            "the stated adversary model. They never share a column.",
            "`exact P (closed form)` is forgery_probability for Eve and "
            "recipient_forgery_probability for Bob -- the exact acceptance "
            "probability under each one's stated adversary model, and the "
            "independent route the measurement is checked against.",
            "`Bob accepted` reads `forger` on the recipient rows because Bob "
            "IS the adversary there; it is not a hypothesis that was ruled "
            "out and not a zero.",
            "Eve's rungs stop at L = 30 because her acceptance probability is "
            "1.1e-12 by L = 192: they anchor the closed form to a measurement "
            "where one is possible at all, and the closed form carries the "
            "curve from there. The recipient forger is the binding adversary "
            "and the one a security claim should quote.",
        ),
    )


def repudiation_reduction(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    expected: Mapping[str, int] | None = None,
) -> list[Table]:
    """Return the repudiation experiment's own tables.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command, stamped on both tables.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order.
    expected : Mapping or None, optional
        Keyword-only. Per-cell trial counts the sweep asked for, part of the
        :data:`~sih141.eval.reduce.EXTRA_REDUCTIONS` contract. This family
        builds no completeness footnote of its own -- the outcome table
        :func:`~sih141.eval.reduce.reduce_experiment` prepends carries the
        check -- so it is accepted and unused rather than dropped from the
        signature, which would make the call fail.

    Returns
    -------
    list of Table
        The curve, then the two analytic tables it has to be read against:
        where the floors bite, and what the gap the exponent is made of costs.
    """
    return [
        repudiation_curve_table(
            records, command=command, cell_order=cell_order
        ),
        floor_table(records, command=command, cell_order=cell_order),
        gap_table(records, command=command, cell_order=cell_order),
    ]


def forgery_reduction(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    expected: Mapping[str, int] | None = None,
) -> list[Table]:
    """Return the forgery experiment's own tables.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order.
    expected : Mapping or None, optional
        Keyword-only. Accepted and unused; see
        :func:`repudiation_reduction`.

    Returns
    -------
    list of Table
    """
    return [
        forgery_table(records, command=command, cell_order=cell_order),
        floor_table(records, command=command, cell_order=cell_order),
    ]


# --------------------------------------------------------------------------- #
# 7. The chart
# --------------------------------------------------------------------------- #

_CHART_WIDTH: Final[int] = 900
_CHART_HEIGHT: Final[int] = 560
_CHART_LEFT: Final[int] = 88
_CHART_RIGHT: Final[int] = 40
_CHART_TOP: Final[int] = 56
_CHART_BOTTOM: Final[int] = 118
_CHART_FLOOR_LOG10: Final[float] = -6.0
"""float: Bottom of the chart's log axis.

Six decades is what a four-hundred-trial measurement plus its interval and the
exact closed form all fit inside. The proven bound is order one over this whole
range and sits at the top; that visual is the point of the figure.
"""


def _chart_y(value: float) -> float:
    """Map a probability to a vertical pixel on the log axis.

    Parameters
    ----------
    value : float
        A probability in ``[0, 1]``; zero and anything below the floor are
        clamped to the axis bottom.

    Returns
    -------
    float
    """
    span = _CHART_HEIGHT - _CHART_TOP - _CHART_BOTTOM
    if value <= 0.0:
        exponent = _CHART_FLOOR_LOG10
    else:
        exponent = max(_CHART_FLOOR_LOG10, min(0.0, math.log10(value)))
    fraction = (exponent - _CHART_FLOOR_LOG10) / (0.0 - _CHART_FLOOR_LOG10)
    return _CHART_TOP + span * (1.0 - fraction)


def _chart_x(index: int, count: int) -> float:
    """Map a ladder rung to a horizontal pixel.

    Parameters
    ----------
    index : int
        Zero-based rung.
    count : int
        Number of rungs.

    Returns
    -------
    float
    """
    span = _CHART_WIDTH - _CHART_LEFT - _CHART_RIGHT
    if count <= 1:
        return _CHART_LEFT + span / 2.0
    return _CHART_LEFT + span * index / (count - 1)


def security_charts(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> dict[str, str]:
    """Render the repudiation curve as an SVG, with error bars.

    Three series on one log axis, which is the whole argument of
    :ref:`demo-scale-limitation` in one picture: the measured rate with its
    Wilson interval, the exact in-model probability, and the proven a-priori
    bound sitting at the top of the chart across the entire measurable range.

    Only the symmetrised rungs at the default ordering are plotted; the
    ordering control and the unsymmetrised positive controls are not points on
    this curve and drawing them on it would be a category error.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. Printed on the figure -- a chart is a published number
        and D9 applies to it exactly as it does to a table.
    cell_order : Sequence of str or None, optional
        Keyword-only. Rung order.

    Returns
    -------
    dict
        Filename to SVG text. Empty when no rung of the ladder is present,
        which is different from an empty figure.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.security import security_charts
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("repudiation-curve"), store,
    ...                        trials=2, cells=["l24", "l48"], workers=1,
    ...                        in_process=True, quiet=True)
    ...     charts = security_charts(list(store.read_experiment(
    ...         "repudiation-curve")), command="demo")
    >>> sorted(charts)
    ['repudiation-curve.svg']
    >>> charts["repudiation-curve.svg"].startswith("<svg")
    True
    >>> "demo" in charts["repudiation-curve.svg"]
    True
    """
    ladder = {f"l{length}" for length, _ in REPUDIATION_LADDER}
    points: list[dict[str, Any]] = []
    for (cell, timing), group in group_records(
        records, cell_order=cell_order
    ).items():
        if cell not in ladder or timing != COUNTS_BEFORE_FORWARDING:
            continue
        params = _params_of(group[0])
        engaged = [r for r in group if r.truth.attacked]
        if not engaged:
            continue
        successes = sum(1 for r in engaged if repudiated_from_verdicts(r))
        interval = wilson_interval(
            successes, len(engaged), confidence=CONFIDENCE
        )
        strength = _option(group[0].experiment, cell, "strength")
        exact = (
            None
            if strength is None
            else repudiation_probability(
                params, mismatch_probability=float(strength)
            )
        )
        points.append(
            {
                "cell": cell,
                "key_length": params.key_length,
                "rate": successes / len(engaged),
                "low": float(interval.low),
                "high": float(interval.high),
                "successes": successes,
                "trials": len(engaged),
                "exact": exact,
                "proven": 10.0 ** enforced_bound_log10(params),
            }
        )
    if not points:
        return {}
    points.sort(key=lambda p: p["key_length"])
    return {"repudiation-curve.svg": _render_curve(points, command)}


def _render_curve(points: Sequence[Mapping[str, Any]], command: str) -> str:
    """Render the repudiation curve's SVG text.

    Parameters
    ----------
    points : Sequence of Mapping
        As built by :func:`security_charts`, ascending in key length.
    command : str
        The regenerating command, printed on the figure.

    Returns
    -------
    str
    """
    count = len(points)
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_CHART_WIDTH}" '
        f'height="{_CHART_HEIGHT}" viewBox="0 0 {_CHART_WIDTH} '
        f'{_CHART_HEIGHT}" font-family="DejaVu Sans, Verdana, sans-serif">',
        f'<rect width="{_CHART_WIDTH}" height="{_CHART_HEIGHT}" '
        f'fill="#ffffff"/>',
        f'<text x="{_CHART_LEFT}" y="28" font-size="17" font-weight="bold">'
        f"Repudiation against key length</text>",
        f'<text x="{_CHART_LEFT}" y="46" font-size="12" fill="#444444">'
        f"measured rate with {CONFIDENCE:.0%} Wilson interval, the exact "
        f"in-model probability, and the proven a-priori bound</text>",
    ]
    for decade in range(int(_CHART_FLOOR_LOG10), 1):
        y = _chart_y(10.0**decade)
        parts.append(
            f'<line x1="{_CHART_LEFT}" y1="{y:.1f}" '
            f'x2="{_CHART_WIDTH - _CHART_RIGHT}" y2="{y:.1f}" '
            f'stroke="#e4e4e4" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{_CHART_LEFT - 10}" y="{y + 4:.1f}" font-size="11" '
            f'text-anchor="end" fill="#666666">1e{decade}</text>'
        )
    for index, point in enumerate(points):
        x = _chart_x(index, count)
        parts.append(
            f'<text x="{x:.1f}" y="{_CHART_HEIGHT - _CHART_BOTTOM + 20:.1f}" '
            f'font-size="11" text-anchor="middle" fill="#444444">'
            f'{point["key_length"]}</text>'
        )
    parts.append(
        f'<text x="{_CHART_WIDTH / 2:.0f}" '
        f'y="{_CHART_HEIGHT - _CHART_BOTTOM + 40:.0f}" font-size="12" '
        f'text-anchor="middle" fill="#444444">key length L</text>'
    )

    proven = " ".join(
        f"{_chart_x(i, count):.1f},{_chart_y(float(p['proven'])):.1f}"
        for i, p in enumerate(points)
    )
    parts.append(
        f'<polyline points="{proven}" fill="none" stroke="#b30000" '
        f'stroke-width="2.5" stroke-dasharray="7 4"/>'
    )
    # Indexed by position rather than by value: two rungs whose dictionaries
    # happened to be equal would both resolve to the first one's abscissa.
    exacts = [
        (index, point)
        for index, point in enumerate(points)
        if point["exact"] is not None
    ]
    if exacts:
        exact_path = " ".join(
            f"{_chart_x(index, count):.1f},{_chart_y(float(p['exact'])):.1f}"
            for index, p in exacts
        )
        parts.append(
            f'<polyline points="{exact_path}" fill="none" stroke="#0057b8" '
            f'stroke-width="2"/>'
        )
    for index, point in enumerate(points):
        x = _chart_x(index, count)
        low = _chart_y(float(point["low"]))
        high = _chart_y(float(point["high"]))
        parts.append(
            f'<line x1="{x:.1f}" y1="{high:.1f}" x2="{x:.1f}" '
            f'y2="{low:.1f}" stroke="#111111" stroke-width="1.6"/>'
        )
        for cap in (low, high):
            parts.append(
                f'<line x1="{x - 5:.1f}" y1="{cap:.1f}" x2="{x + 5:.1f}" '
                f'y2="{cap:.1f}" stroke="#111111" stroke-width="1.6"/>'
            )
        if float(point["rate"]) > 0.0:
            parts.append(
                f'<circle cx="{x:.1f}" cy="{_chart_y(float(point["rate"])):.1f}"'
                f' r="4" fill="#111111"/>'
            )
        else:
            parts.append(
                f'<text x="{x:.1f}" y="{low + 15:.1f}" font-size="10" '
                f'text-anchor="middle" fill="#111111">0/'
                f'{point["trials"]}</text>'
            )
    legend_y = _CHART_HEIGHT - 56
    parts.append(
        f'<line x1="{_CHART_LEFT}" y1="{legend_y}" '
        f'x2="{_CHART_LEFT + 26}" y2="{legend_y}" stroke="#b30000" '
        f'stroke-width="2.5" stroke-dasharray="7 4"/>'
        f'<text x="{_CHART_LEFT + 32}" y="{legend_y + 4}" font-size="11">'
        f"enforced bound (PROVEN, every signer strategy)</text>"
    )
    parts.append(
        f'<line x1="{_CHART_LEFT + 330}" y1="{legend_y}" '
        f'x2="{_CHART_LEFT + 356}" y2="{legend_y}" stroke="#0057b8" '
        f'stroke-width="2"/>'
        f'<text x="{_CHART_LEFT + 362}" y="{legend_y + 4}" font-size="11">'
        f"exact in-model P (closed form)</text>"
    )
    parts.append(
        f'<circle cx="{_CHART_LEFT + 13}" cy="{legend_y + 20}" r="4" '
        f'fill="#111111"/>'
        f'<text x="{_CHART_LEFT + 32}" y="{legend_y + 24}" font-size="11">'
        f"measured, with {CONFIDENCE:.0%} Wilson interval; a bar reaching the "
        f"axis floor is 0/n</text>"
    )
    if command:
        parts.append(
            f'<text x="{_CHART_LEFT}" y="{_CHART_HEIGHT - 12}" font-size="10" '
            f'fill="#666666">Regenerate: {escape_xml(command)}</text>'
        )
    else:
        parts.append(
            f'<text x="{_CHART_LEFT}" y="{_CHART_HEIGHT - 12}" font-size="10" '
            f'fill="#b30000">no command recorded -- this figure is not '
            f"reproducible and must not be published (D9)</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 8. Registration
# --------------------------------------------------------------------------- #


def register(
    *,
    scenarios: dict[str, Any] | None = None,
    experiments: dict[str, Any] | None = None,
) -> None:
    """Add this family's scenarios, experiments and reductions to the registries.

    Called once at import. Idempotent, and it refuses a name another family has
    already taken rather than resolving the collision by import order.

    Parameters
    ----------
    scenarios : dict or None, optional
        Keyword-only. Defaults to
        :data:`~sih141.eval.experiments.SCENARIOS`.
    experiments : dict or None, optional
        Keyword-only. Defaults to
        :data:`~sih141.eval.experiments.EXPERIMENTS`.

    Raises
    ------
    RuntimeError
        If any name -- scenario, probe options, experiment, reduction or chart
        renderer -- is taken by something else.

    Notes
    -----
    Every registry this function writes to goes through
    :func:`~sih141.eval.experiments.claim`, which raises in *both* directions.
    An earlier version of this function guarded only the scenario names and
    used ``setdefault`` or an ``is None`` test for the experiments, the
    reductions and the chart, and assigned the probe options outright. Those
    are the two silent halves of a collision: yielding leaves this family
    registered nowhere, so its cells never run and the sweep looks like a
    family nobody wrote, and overwriting takes the other family's key. The
    scenario direction had a test and the other four did not, which is why
    they disagreed with the ROC family's guard for as long as they did.

    Examples
    --------
    >>> from sih141.eval.security import register
    >>> register()                      # already done at import; a no-op
    >>> register(scenarios={"security-tilt": len}, experiments={})
    Traceback (most recent call last):
        ...
    RuntimeError: scenario 'security-tilt' is already registered...

    An experiment name held by another family raises too, rather than leaving
    this family's two experiments unregistered:

    >>> register(scenarios={}, experiments={"forgery-curve": "someone else's"})
    Traceback (most recent call last):
        ...
    RuntimeError: experiment 'forgery-curve' is already registered...
    """
    target_scenarios = SCENARIOS if scenarios is None else scenarios
    target_experiments = EXPERIMENTS if experiments is None else experiments
    for name, function in SECURITY_SCENARIOS.items():
        claim(target_scenarios, name, function, "scenario")
    for name, options in SECURITY_PROBE_OPTIONS.items():
        claim(SCENARIO_PROBE_OPTIONS, name, options, "probe options")
    # After the scenarios, never before: building the cells validates each
    # one's scenario against the live registry.
    claim(
        target_experiments,
        "repudiation-curve",
        _built("repudiation-curve", _repudiation_experiment),
        "experiment",
    )
    claim(
        target_experiments,
        "forgery-curve",
        _built("forgery-curve", _forgery_experiment),
        "experiment",
    )
    claim(
        reduce_module.EXTRA_REDUCTIONS,
        "repudiation-curve",
        repudiation_reduction,
        "reduction",
    )
    claim(
        reduce_module.EXTRA_REDUCTIONS,
        "forgery-curve",
        forgery_reduction,
        "reduction",
    )
    claim(
        reduce_module.EXTRA_CHARTS,
        "repudiation-curve",
        security_charts,
        "chart renderer",
    )


register()
