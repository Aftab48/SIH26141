"""Protocol parameters, parties and the two acceptance thresholds.

This module holds the *numbers* the teleportation-based quantum digital
signature (QDS) scheme is parameterised by, and -- more importantly -- the
validation that refuses parameter sets which quietly destroy one of the three
security properties. Every rejection message says which property dies, because
a silently-accepted bad threshold pair produces a protocol that runs perfectly
and proves nothing.

The three parties
-----------------
Alice
    The signer. Draws the private keys, prepares the public-key eigenstates and
    teleports one copy to each recipient. Holds no measurement record.
Bob
    First recipient and verifier. Accepts when his mismatch rate satisfies
    ``r_B <= s_a``.
Charlie
    Second recipient and verifier. Accepts when ``r_C <= s_v``. Charlie is not
    optional: transferability is a statement about a *second* verifier, so a
    two-party implementation demonstrates nothing.

The two thresholds, and why the gap has to exist
------------------------------------------------
The scheme fixes ``0 <= s_a < s_v < forger_floor``. Both verifiers apply the
same counting rule to the same kind of data and differ only in where they cut::

    Bob     accepts iff  r_B <= s_a      (the tighter, "authentication" cut)
    Charlie accepts iff  r_C <= s_v      (the looser, "verification" cut)

``s_v > s_a`` gives **transferability**. Both recipients hold one record per key
position, each made in a basis drawn uniformly and independently, so on an
honest run both mismatch rates are ``0`` exactly and both cuts are noise
budgets measured from that zero. A signature inside Bob's tight cut is
therefore overwhelmingly likely to sit inside Charlie's looser one, and Bob can
forward what he accepted knowing Charlie will accept it too.

``s_a > 0`` gives **non-repudiation** operating room -- but only in combination
with the *symmetrisation* step (:mod:`sih141.protocol.symmetrise`), which is
what actually forces Bob's and Charlie's evidence to be exchangeable. Without
it the guarantee is simply false: Alice distributes to the two recipients
independently, so she can send Bob the declared eigenstate and Charlie its
orthogonal partner and repudiate with probability ``1`` at every ``L``. After
symmetrisation the two recipients privately and secretly re-assign the two
copies of every position between themselves, so Alice cannot know which of her
two preparations will be scored by which verifier, and

.. code-block:: text

    P(repudiation | records, declaration) <= exp(-M * (s_v - s_a)**2 / 8)

where ``M = m_B + m_C`` is the *total* number of matched records held by the two
verifiers together **on the run being reported**. The derivation is in
:mod:`sih141.protocol.analysis` section 4b-i and in ``docs/PHASE2.md``; the
structural point is that it conditions on the records *and on the declaration*
and uses only the recipients' private coins, so it holds for every Alice
strategy rather than for one modelled family. The bound is exponential in ``M``,
and ``M`` grows linearly in :attr:`ProtocolParams.key_length`, so the guarantee
is bought with key length.

**Two things it is not.** It is not a number you can quote before the run: for
that you need either the ``M``-averaged form
(:func:`sih141.protocol.analysis.averaged_repudiation_bound`, ``6.9e-10``
below), which additionally assumes **the declared bases are independent of the
recipients' logged bases** and is therefore *false* against a signer who reads
them -- the shipped ``Signer`` seam hands over both raw logs -- or the
unconditional figure :func:`sih141.protocol.verify.enforced_repudiation_bound`
returns, ``1.4139e-09`` at these defaults.
And it is not a guarantee against a signer *starving* the evidence: a run whose
``M`` is small gets a bound near ``1``, correctly, which is why the floors exist.
``docs/PHASE2.md`` section 6b states both limits in full.

**What the unconditional figure rests on: three rules, jointly.** This paragraph
used to credit the per-verifier matched-count floor
(:func:`sih141.protocol.verify.minimum_matched_count`, ``m_min = 36555``) with
an unconditional ``1.9e-9`` on its own. That is precisely the claim
:mod:`sih141.protocol.analysis` section 4b-iii disproves, and it is repeated
here so a reader who met it in an older copy can recognise it. A per-verifier
floor bounds one branch -- Bob accepts and Charlie reaches a verdict of
*reject* -- and leaves open a third outcome it creates itself: Charlie holding a
matched set that is non-empty but **below his own floor**, on which he returns no
verdict. A signer who reads the recipients' logged bases aims ``M`` at
``2 m_min`` and wins that outcome on a single fair coin, with probability
tending to ``1/2``; closed form ``0.432`` at ``L = 360`` and ``0.466``
at ``L = 600``; measured ``78/200``, ``85/200`` and ``87/200`` across runs -- see
:ref:`split-coin-provenance` before quoting a count. No key length touches it, because nothing about the *rate* is being
deviated -- only the count. The guarantee needs all three of

* the **per-verifier floor**, ``m_B >= m_min`` and ``m_C >= m_min``;
* the **pooled floor**, ``m_B + m_C >= M_min = 74190``, carried by one integer
  each way over the recipients' own channel (:mod:`sih141.protocol.tally`) and
  worth having because ``M_min - 2 m_min = 1080 > 0``, so the total the attack
  aims at is refused outright rather than priced; and
* the **joint consequence**, that a verifier below his own floor takes the other
  down with him
  (:attr:`sih141.protocol.verify.AbortReason.COUNTERPART_BELOW_FLOOR`), which
  removes the third outcome from the outcome space instead of bounding it.

Together they force ``M >= max(2 m_min, M_min) = 74190`` on every run that
reaches a verdict, hence ``exp(-74190 * gap**2 / 8) = 1.4139e-09``. Remove any
one of the three and the number is not weakened by a factor; the guarantee is
gone. Sections 4b-iii and 4b-iv of :mod:`sih141.protocol.analysis` derive both
halves.

``s_v < forger_floor`` gives **unforgeability**. ``1/2`` -- the rate an
adversary with no information about the key produces -- is only the crude
bound; the threshold that actually binds is the rate a *recipient* turned
forger achieves, computed by :attr:`ProtocolParams.forger_floor`, and it is
what :meth:`ProtocolParams.__post_init__` enforces.

The forger floor, computed rather than asserted
-----------------------------------------------
Suppose Bob tries to pass off a key Alice never signed. After symmetrisation
Charlie's record at position ``i`` is Bob's own measurement (with probability
``1/2``, when the pair was swapped) or Charlie's own (otherwise), and Bob knows
which. His best strategy is:

* **Swapped position** (probability ``1/2``). Bob knows Charlie's entry exactly,
  because he supplied it. He declares that basis and that eigenvalue: the
  position is matched with probability ``1`` and mismatches with probability
  ``0``.
* **Retained position** (probability ``1/2``). Charlie holds his own measurement
  of an independent copy. Bob declares his own record; the position is matched
  with probability ``1/|B|``, and given a match, Bob's basis was Alice's with
  probability ``1/|B|`` (both then read the true eigenvalue and agree) and
  otherwise the two outcomes are independent fair coins. Mismatch probability
  given a match is therefore ``(1 - 1/|B|) / 2``.

Collecting terms, the scored fraction is ``(|B| + 1) / (2|B|)`` and the mismatch
rate Charlie sees is

.. code-block:: text

    forger_floor = (|B| - 1) / (2 |B| (|B| + 1))

which is ``1/12`` for the three-basis alphabet ``{X, Y, Z}``. Symmetrisation
therefore costs a factor of four in the floor -- ``1/3`` before, ``1/12`` after
-- and that is the price of non-repudiation, paid in key length. It is not
optional: the ``1/3`` version of this protocol has no non-repudiation at all.

**The floor is optimal, not merely compliant.** A cheating Bob who deviates at
receipt time -- measuring in some intermediate (Breidbart-like) basis, or with
an arbitrary POVM -- cannot beat it. Write his declaration ``(d, w)`` as a
function of the outcome ``k`` of a POVM ``{E_k}``, let ``g = P(d = a, w = v)``
and ``h = P(d = a, w != v)`` against the six uniformly drawn eigenstates
``rho_{a,v} = (I + v sigma_a)/2``. The mismatch rate on retained positions is
``(1 - (g - h)) / 2`` and

.. code-block:: text

    g - h = (1/6) sum_k Tr(E_k (rho_{d_k, w_k} - rho_{d_k, -w_k}))
          = (1/6) sum_k Tr(E_k  w_k sigma_{d_k})
          = (1/6) sum_k alpha_k (m_k . n_k)
          <= (1/6) sum_k alpha_k  =  (1/6) Tr(I)  =  1/3

writing ``E_k = alpha_k (I + m_k . sigma) / 2`` with ``|m_k| <= 1``, and using
that a qubit POVM sums to the identity, whose trace is ``2``. So the retained
rate is at least ``(1 - 1/3)/2 = 1/3`` for every POVM, and the octahedron POVM
``E_k = rho_k / 3`` attains it -- exactly as well as the compliant strategy, not
better. An earlier version of this docstring claimed a Breidbart-style
measurement does better and reserved a factor of two in ``s_v`` for it; the
claim was false and the margin is now justified by the forgery *probability*
instead: what fixes ``s_v`` is that ``D(s_v || forger_floor)`` has to be large
enough that ``exp(-Theta(L))`` is a number worth quoting, not a fear of an
unquantified attack.

Authentication is a precondition, not a result
---------------------------------------------
Every threshold here is a statement about a *named* signer, and nothing in this
package names one. The classical and quantum channels from Alice to each
recipient are **assumed authenticated**; an adversary who controls both the
distribution seam and the signing seam -- distributing her own key states and
then signing her own key -- is accepted by both verifiers with probability
``1``, at ``QBER = 0``, transferably, at every parameter set on this page. That
is inherent to measurement-based QDS rather than a defect of these numbers, and
it is stated as assumption **(AUTH)** in :mod:`sih141.protocol.analysis` section
0b, beside (IND). *Partial* impersonation -- one seam, not both -- is caught
cold by ``s_a`` and ``s_v`` doing exactly what they are sized to do.

The numbers above, as executable claims
---------------------------------------
This project runs ``pytest --doctest-modules`` over ``sih141``, so a figure
written as a doctest is re-derived on every run while the same figure written as
prose is unverifiable by construction. The load-bearing numbers of this module
are therefore restated here as tests -- including those documented on
:data:`DEFAULT_PARAMS` and :data:`DEMO_PARAMS`, whose attribute docstrings
:mod:`doctest` cannot reach.

>>> import math
>>> from sih141.protocol.analysis import (
...     averaged_repudiation_bound,
...     binary_kl_divergence,
...     depolarising_error_rate,
...     matched_statistics,
...     recipient_forgery_bound,
...     repudiation_bound,
... )
>>> from sih141.protocol.params import (
...     CHECKED_PARAMS, DEFAULT_PARAMS, DEMO_PARAMS,
... )
>>> from sih141.protocol.verify import (
...     enforced_repudiation_bound,
...     minimum_matched_count,
...     minimum_pooled_matched_count,
... )

The parameter set itself, and the gap the two cuts leave:

>>> DEFAULT_PARAMS.key_length, DEFAULT_PARAMS.s_a, DEFAULT_PARAMS.s_v
(115200, 0.015625, 0.0625)
>>> DEFAULT_PARAMS.gap == 1 / 16 - 1 / 64 == 3 / 64
True
>>> DEFAULT_PARAMS.forger_floor == 1 / 12
True
>>> DEFAULT_PARAMS.s_v == 0.75 * DEFAULT_PARAMS.forger_floor
True

What the ``s_v`` margin buys, and what ``s_a`` is a budget for:

>>> f"{binary_kl_divergence(DEFAULT_PARAMS.s_v, DEFAULT_PARAMS.forger_floor):.6f}"
'0.003088'
>>> f"{recipient_forgery_bound(DEFAULT_PARAMS, method='kl'):.1e}"
'1.1e-103'
>>> depolarising_error_rate(0.03125) == DEFAULT_PARAMS.s_a
True

The matched counts ``L`` was rounded to keep integral -- ``L/3`` per verifier
and twice that pooled:

>>> statistics = matched_statistics(DEFAULT_PARAMS)
>>> statistics.expected, 2 * statistics.expected
(38400.0, 76800.0)

The two conditional repudiation figures. Both need (IND), which the shipped
``Signer`` seam gives away, so neither may be published alone:

>>> f"{repudiation_bound(DEFAULT_PARAMS, matched_records=76800):.4e}"
'6.9040e-10'
>>> averaged = averaged_repudiation_bound(
...     DEFAULT_PARAMS, signer_sees_recipient_bases=False)
>>> f"{averaged:.4e}"
'6.9173e-10'

The unconditional figure, and the fact that it is *not* the per-verifier
floor's. ``max(2 * m_min, M_min)`` is ``M_min``, so the pooled floor is the
binding one; the last line is the number this docstring used to attribute to the
per-verifier floor alone, kept executable so it cannot be mistaken for the
shipped bound again:

>>> m_min = minimum_matched_count(DEFAULT_PARAMS)
>>> M_min = minimum_pooled_matched_count(DEFAULT_PARAMS)
>>> m_min, M_min, M_min - 2 * m_min
(36555, 74190, 1080)
>>> max(2 * m_min, M_min) == M_min
True
>>> f"{enforced_repudiation_bound(DEFAULT_PARAMS):.4e}"
'1.4139e-09'
>>> f"{math.exp(-M_min * DEFAULT_PARAMS.gap ** 2 / 8):.4e}"
'1.4139e-09'
>>> f"{math.exp(-2 * m_min * DEFAULT_PARAMS.gap ** 2 / 8):.4e}"
'1.9022e-09'

:data:`DEMO_PARAMS` carries no security claim, and that is a number too:

>>> f"{repudiation_bound(DEMO_PARAMS, matched_records=128):.2f}"
'0.97'

Sampled parameter estimation, and the honest propagation of what it costs.
:data:`CHECKED_PARAMS` spends an eighth of its rounds on measuring the channel;
the shortened :attr:`ProtocolParams.signing_length` is what every floor and
every bound is then computed from, so the checked set is *not weaker* than the
unchecked one -- it is longer:

>>> CHECKED_PARAMS.check_count, CHECKED_PARAMS.signing_length
(16458, 115206)
>>> CHECKED_PARAMS.expected_matched
38402.0
>>> minimum_matched_count(CHECKED_PARAMS), minimum_pooled_matched_count(
...     CHECKED_PARAMS)
(36557, 74194)
>>> f"{enforced_repudiation_bound(CHECKED_PARAMS):.4e}"
'1.4124e-09'
>>> enforced_repudiation_bound(CHECKED_PARAMS) <= enforced_repudiation_bound(
...     DEFAULT_PARAMS)
True

The substitution that makes it work: verification runs under
:meth:`ProtocolParams.sifted`, whose ``key_length`` *is* the signing length, and
which is indistinguishable from the checked set in every derived quantity:

>>> sifted = CHECKED_PARAMS.sifted()
>>> sifted.key_length, sifted.check_fraction
(115206, 0.0)
>>> (sifted.expected_matched, minimum_matched_count(sifted),
...  minimum_pooled_matched_count(sifted)) == (
...     CHECKED_PARAMS.expected_matched,
...     minimum_matched_count(CHECKED_PARAMS),
...     minimum_pooled_matched_count(CHECKED_PARAMS))
True

The shipped fraction is derived, not chosen, and it meets its own requirement at
this length -- :mod:`sih141.protocol.checkrounds` shows the arithmetic:

>>> from sih141.protocol.checkrounds import required_check_rounds
>>> required_check_rounds(CHECKED_PARAMS).total
13483
>>> CHECKED_PARAMS.check_count >= required_check_rounds(CHECKED_PARAMS).total
True
>>> DEFAULT_PARAMS.check_count, DEFAULT_PARAMS.has_check_rounds
(0, False)

Notes
-----
Determinism (D3)
    Nothing in this module consumes randomness.
No machine learning (D4)
    Closed-form arithmetic only.
Shared coercions
    :func:`_as_basis` and :func:`_as_eigenvalue` live here because
    :mod:`sih141.protocol.keys` and :mod:`sih141.protocol.records` both need
    them and this is the module they both already depend on. They are private to
    the package.
"""

from __future__ import annotations

import enum
import math
import numbers
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final

from sih141.core.paulis import PauliBasis

__all__ = [
    "Party",
    "VERIFIERS",
    "ProtocolParams",
    "COMPLIANT_FORGER_RATE_THREE_BASIS",
    "UNSYMMETRISED_FORGER_RATE_THREE_BASIS",
    "DEFAULT_S_A",
    "DEFAULT_S_V",
    "DEFAULT_BASES",
    "DEFAULT_CHECK_FRACTION",
    "DEFAULT_PARAMS",
    "DEMO_PARAMS",
    "CHECKED_PARAMS",
    "DEMO_CHECKED_PARAMS",
]


class Party(enum.StrEnum):
    """One of the three roles in the protocol.

    A :class:`enum.StrEnum`, so a member *is* its label: ``Party.BOB == "Bob"``
    and :func:`json.dumps` accepts members directly, as values and as dictionary
    keys. That matches the treatment of :class:`sih141.core.paulis.PauliBasis`
    and :class:`sih141.core.states.BellState`, so a Phase 5 result record or a
    Phase 6 dashboard row needs no bespoke encoder.

    Attributes
    ----------
    ALICE : Party
        The signer. Holds the private keys; holds no measurement record and has
        no acceptance threshold, so :meth:`ProtocolParams.threshold_for` refuses
        her.
    BOB : Party
        First recipient, threshold ``s_a``.
    CHARLIE : Party
        Second recipient, threshold ``s_v``.

    Examples
    --------
    >>> import json
    >>> from sih141.protocol.params import Party
    >>> json.dumps({Party.BOB: 0, Party.CHARLIE: 1})
    '{"Bob": 0, "Charlie": 1}'
    >>> Party.CHARLIE.is_verifier
    True
    """

    ALICE = "Alice"
    BOB = "Bob"
    CHARLIE = "Charlie"

    @property
    def is_verifier(self) -> bool:
        """bool: ``True`` for the two recipients, ``False`` for Alice."""
        return self is not Party.ALICE


VERIFIERS: Final[tuple[Party, Party]] = (Party.BOB, Party.CHARLIE)
"""The two verifying parties, in protocol order (Bob first, then Charlie)."""


COMPLIANT_FORGER_RATE_THREE_BASIS: Final[float] = 1.0 / 12.0
"""Mismatch rate a recipient-turned-forger achieves against the ``{X,Y,Z}`` set.

``(|B| - 1) / (2 |B| (|B| + 1)) = 1/12`` for ``|B| = 3``, *after* the
symmetrisation step of :mod:`sih141.protocol.symmetrise`. The module docstring
derives it and shows it is optimal over all POVMs, and
:attr:`ProtocolParams.forger_floor` is the general expression.
"""

UNSYMMETRISED_FORGER_RATE_THREE_BASIS: Final[float] = 1.0 / 3.0
"""The same rate for a protocol *without* symmetrisation, ``(1 - 1/3) / 2 = 1/3``.

Kept because it is the number Phase 3 measures when it disables symmetrisation
to demonstrate why the step exists, and because it is also -- by a coincidence
of the same arithmetic -- the rate produced by counting unmatched positions,
the classic implementation bug of this protocol family
(:attr:`ProtocolParams.unmatched_noise_rate`).
"""

DEFAULT_BASES: Final[tuple[PauliBasis, ...]] = (
    PauliBasis.X,
    PauliBasis.Y,
    PauliBasis.Z,
)
"""The three-basis (six-state) alphabet, in :class:`PauliBasis` sort order."""

DEFAULT_S_A: Final[float] = 1.0 / 64.0
"""Bob's acceptance threshold, ``0.015625``.

Chosen as a noise budget rather than as a security knob: a noiseless honest run
gives ``r_B = 0`` exactly, and teleportation through a Werner resource of
parameter ``p`` induces a depolarising channel whose matched-position error rate
is ``p / 2``. Bob therefore still accepts honest signatures up to
``p = 2 * s_a = 3.125%`` depolarising noise in the entanglement resource, which
covers the noise levels Phase 3 injects.
"""

DEFAULT_S_V: Final[float] = 1.0 / 16.0
"""Charlie's acceptance threshold, ``0.0625``.

Three quarters of :data:`COMPLIANT_FORGER_RATE_THREE_BASIS` (``1/12``), which is
the rate an optimal recipient forger achieves. The margin is set by what it
buys, not by fear: ``D(1/16 || 1/12) = 0.003088`` nats, which at
:data:`DEFAULT_PARAMS`'s key length puts the recipient-forgery bound at
``1e-103``. Pushing ``s_v`` closer to the floor cheapens the key and weakens
that exponent; pushing it lower costs key length through the ``s_v - s_a`` gap
in the repudiation bound.
"""

DEFAULT_CHECK_FRACTION: Final[float] = 0.125
"""The share of positions spent on sampled parameter estimation, ``1/8``.

Not a taste. :mod:`sih141.protocol.checkrounds` derives two sample-size
requirements -- the QBER arm must resolve ``s_a`` to ``s_a/4`` (``6688``
rounds), the CHSH arm must resolve the corresponding depolarising strength
``2 s_a`` (``6795`` rounds) -- whose sum ``13483`` is ``0.1170`` of
:data:`DEFAULT_PARAMS`'s ``L``, rounded **up** to the next binary fraction.
:func:`sih141.protocol.checkrounds.required_check_rounds` recomputes it for any
other parameter set, and should be called rather than this constant copied: what
the requirements bind is the *count*, and the fraction that delivers it shrinks
as ``L`` grows.

Applied to :data:`DEFAULT_PARAMS` it would cost a factor of thirteen in the
enforced repudiation bound. :data:`CHECKED_PARAMS` pays in key length instead;
both numbers are doctests in the :mod:`sih141.protocol.checkrounds` module
docstring, side by side, so the cheap one cannot be quoted by mistake.
"""

_DEFAULT_KEY_LENGTH: Final[int] = 115200
_DEMO_KEY_LENGTH: Final[int] = 192

_CHECKED_KEY_LENGTH: Final[int] = 131664
"""``L`` for :data:`CHECKED_PARAMS`: the smallest multiple of 24 above ``115200 * 8/7``.

A multiple of ``8`` so the check count is exact, and of ``24`` so the surviving
:attr:`ProtocolParams.signing_length` stays divisible by ``3`` and the expected
matched count is an integer -- the same tidiness ``115200`` was chosen for.
"""


def _as_basis(basis: PauliBasis | str, *, name: str = "basis") -> PauliBasis:
    """Coerce a basis argument to :class:`~sih141.core.paulis.PauliBasis`.

    Shared by :mod:`sih141.protocol.keys` and :mod:`sih141.protocol.records` so
    that a basis read back from a JSON log (where it is a plain ``"X"``) and a
    basis produced in-process are handled identically.

    Parameters
    ----------
    basis : PauliBasis or str
        A member, or its label as a case-insensitive string.
    name : str, optional
        The argument name to quote in error messages.

    Returns
    -------
    PauliBasis
        The corresponding member.

    Raises
    ------
    ValueError
        If ``basis`` is a string that names no basis.
    TypeError
        If ``basis`` is neither a :class:`PauliBasis` nor a string.
    """
    if isinstance(basis, PauliBasis):
        return basis
    if isinstance(basis, str):
        try:
            return PauliBasis(basis.strip().upper())
        except ValueError:
            raise ValueError(
                f"{name} must name a measurement basis: expected 'X', 'Y' or "
                f"'Z' (case-insensitive) or a PauliBasis member, got "
                f"{basis!r}"
            ) from None
    raise TypeError(
        f"{name} must be a PauliBasis (or the string 'X', 'Y', 'Z'), got "
        f"{type(basis).__name__}"
    )


def _as_eigenvalue(eigenvalue: int, *, name: str = "eigenvalue") -> int:
    """Validate a Pauli eigenvalue and return it as a plain :class:`int`.

    Parameters
    ----------
    eigenvalue : int
        Must be ``+1`` or ``-1``. Booleans are rejected explicitly: they are
        integers in Python, so ``True`` would silently pass as ``+1`` while
        meaning "bit 1", which is ``-1``.
    name : str, optional
        The argument name to quote in error messages.

    Returns
    -------
    int
        ``1`` or ``-1``.

    Raises
    ------
    ValueError
        If ``eigenvalue`` is anything other than ``+1`` or ``-1``.
    """
    if isinstance(eigenvalue, bool):
        raise ValueError(
            f"{name} must be the Pauli eigenvalue +1 or -1, got the boolean "
            f"{eigenvalue!r}. Booleans look like measurement bits and would be "
            f"read with the wrong sign; convert with "
            f"eigenvalue = 1 - 2 * bit (bit 0 -> +1, bit 1 -> -1)."
        )
    if not isinstance(eigenvalue, numbers.Integral):
        raise ValueError(
            f"{name} must be the integer +1 or -1, got {type(eigenvalue).__name__}"
        )
    value = int(eigenvalue)
    if value not in (1, -1):
        raise ValueError(
            f"{name} must be +1 or -1, got {value!r}. These are Pauli "
            f"eigenvalues, not measurement bits; convert with "
            f"eigenvalue = 1 - 2 * bit (bit 0 -> +1, bit 1 -> -1)."
        )
    return value


def _as_message_bit(message_bit: int, *, name: str = "message_bit") -> int:
    """Validate a message bit and return it as a plain :class:`int`.

    Parameters
    ----------
    message_bit : int
        Must be ``0`` or ``1``. The distribution phase runs once per future
        message bit, so every key and every record is tagged with the bit it
        belongs to and the two families can never be crossed by accident.
    name : str, optional
        The argument name to quote in error messages.

    Returns
    -------
    int
        ``0`` or ``1``.

    Raises
    ------
    ValueError
        If ``message_bit`` is a boolean or anything other than ``0``/``1``.
        Booleans are refused so that a ``True`` meant as "yes, signed" cannot
        silently select the key for bit 1.
    """
    if isinstance(message_bit, bool):
        raise ValueError(
            f"{name} must be the integer 0 or 1, got the boolean "
            f"{message_bit!r}. Pass int({message_bit!r}) if you really mean "
            f"the key for message bit {int(message_bit)}."
        )
    if not isinstance(message_bit, numbers.Integral):
        raise ValueError(
            f"{name} must be the integer 0 or 1, got {type(message_bit).__name__}"
        )
    value = int(message_bit)
    if value not in (0, 1):
        raise ValueError(
            f"{name} must be 0 or 1, got {value!r}. Distribution runs once per "
            f"future message bit, so exactly two key families exist."
        )
    return value


def _as_threshold(value: Any, name: str) -> float:
    """Coerce and range-check one acceptance threshold.

    Parameters
    ----------
    value : float
        The threshold, a mismatch *rate* in ``[0, 1)``.
    name : str
        ``"s_a"`` or ``"s_v"``, quoted in error messages.

    Returns
    -------
    float
        The threshold as a plain float.

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite, or is negative.
    """
    if isinstance(value, bool):
        raise TypeError(
            f"{name} must be a real number in [0, 0.5), got the boolean "
            f"{value!r}"
        )
    if not isinstance(value, numbers.Real):
        raise TypeError(
            f"{name} must be a real number in [0, 0.5), got "
            f"{type(value).__name__}"
        )
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        raise ValueError(
            f"{name} must be a finite mismatch rate in [0, 0.5), got {result!r}"
        )
    if result < 0.0:
        raise ValueError(
            f"{name} must be non-negative, got {result!r}. It is a mismatch "
            f"*rate*, the fraction of matched positions on which the "
            f"recipient's outcome disagrees with the declared eigenvalue, so it "
            f"lives in [0, 1) by construction. A negative threshold would make "
            f"the party reject every signature including honest noiseless ones, "
            f"which have rate exactly 0."
        )
    return result


def _as_check_fraction(value: Any) -> float:
    """Coerce and range-check the sampled-estimation fraction.

    Parameters
    ----------
    value : float
        The fraction of positions to spend on check rounds, in ``[0, 1)``.

    Returns
    -------
    float
        The fraction as a plain float.

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite, is negative, or is ``1`` or more -- a run
        that checks every position has no key left to sign with.
    """
    if isinstance(value, bool):
        raise TypeError(
            f"check_fraction must be a real number in [0, 1), got the boolean "
            f"{value!r}"
        )
    if not isinstance(value, numbers.Real):
        raise TypeError(
            f"check_fraction must be a real number in [0, 1), got "
            f"{type(value).__name__}"
        )
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        raise ValueError(
            f"check_fraction must be a finite fraction in [0, 1), got "
            f"{result!r}"
        )
    if result < 0.0:
        raise ValueError(
            f"check_fraction must be non-negative, got {result!r}. It is the "
            f"share of the run's positions diverted from the key to sampled "
            f"parameter estimation; 0 disables estimation entirely."
        )
    if result >= 1.0:
        raise ValueError(
            f"check_fraction must be strictly less than 1, got {result!r}. "
            f"Check positions are excluded from the key, so a fraction of 1 "
            f"leaves signing_length = 0 and there is nothing left to sign. "
            f"Try DEFAULT_CHECK_FRACTION = {DEFAULT_CHECK_FRACTION!r}."
        )
    return result


@dataclass(frozen=True)
class ProtocolParams:
    """The parameter set one QDS run is executed under.

    Frozen and hashable, so a parameter set can be used as a dictionary key in a
    Phase 5 sweep and can never be edited half-way through a run. Use
    :meth:`with_changes` to derive a variant.

    Parameters
    ----------
    key_length : int
        ``L``, the number of *rounds* per recipient per message bit --
        equivalently the number of entanglement resources the run consumes on
        each link, and the number of key elements Alice draws. Must be positive.
        With ``check_fraction > 0`` some of those rounds are spent on parameter
        estimation instead of on key, so the key that survives is
        :attr:`signing_length`, not ``L``. Only the *matched* positions of what
        survives carry information, so the statistically useful length is
        ``signing_length / len(bases)``; see :attr:`expected_matched`.
    s_a : float, optional
        Bob's acceptance threshold. Defaults to :data:`DEFAULT_S_A`.
    s_v : float, optional
        Charlie's acceptance threshold. Defaults to :data:`DEFAULT_S_V`.
    bases : sequence of PauliBasis, optional
        The alphabet Alice and the recipients both draw from, uniformly. Order
        is preserved and is part of the identity of the parameter set, because
        it fixes which integer a generator draw maps to. Defaults to
        :data:`DEFAULT_BASES`, i.e. ``(X, Y, Z)``.
    allow_forgeable : bool, optional
        Opt in to a parameter set whose ``s_v`` sits at or above
        :attr:`forger_floor`, i.e. one that accepts a recipient forgery
        outright. Defaults to ``False``, which *rejects* such a set at
        construction. Phase 3 sweeps that deliberately walk past the floor set
        this to ``True``, which is exactly the point: an intentional insecure
        sweep now looks different from a mistyped config, and the flag is part
        of the parameter set's identity and serialisation, so a transcript
        records that the run was known to be forgeable.
    check_fraction : float, optional
        The share of the run's positions diverted from the key to *sampled
        parameter estimation* -- check rounds
        (:mod:`sih141.protocol.checkrounds`). Defaults to ``0.0``, which is the
        historical behaviour exactly: no estimation, and every derived quantity
        below unchanged. With a positive fraction,
        ``check_count = floor(check_fraction * key_length)`` positions are spent
        on measuring the channel and are **excluded from the key**, so the key
        that gets signed and verified has :attr:`signing_length` elements and
        *every* derived security quantity -- :attr:`expected_matched`, both
        matched-count floors, the enforced repudiation bound -- is computed from
        that, never from ``L``. Verification runs under :meth:`sifted`.

    Raises
    ------
    TypeError
        If a threshold is a boolean or a non-real, ``bases`` is not a sequence
        of bases, ``allow_forgeable`` is not a bool, or ``check_fraction`` is a
        boolean or a non-real.
    ValueError
        If ``key_length`` is not a positive integer; if ``bases`` is empty,
        holds duplicates, or holds fewer than two bases; if a threshold is
        negative or non-finite; if ``s_a >= s_v``; if ``s_v >= 0.5``; if
        ``s_v >= forger_floor`` without ``allow_forgeable=True``; if
        ``check_fraction`` is negative, non-finite or at least ``1``; or if a
        positive ``check_fraction`` rounds to no check rounds at all. Every
        message names the security property that the rejected value would
        destroy.

    Attributes
    ----------
    key_length : int
    s_a : float
    s_v : float
    bases : tuple of PauliBasis
    allow_forgeable : bool
    check_fraction : float

    See Also
    --------
    DEFAULT_PARAMS : The documented security-grade parameter set.
    CHECKED_PARAMS : The same, with check rounds and the bound preserved.
    DEMO_PARAMS : A short set for interactive runs, with no security claim.

    Examples
    --------
    >>> from sih141.protocol.params import ProtocolParams, Party
    >>> params = ProtocolParams(key_length=115200)
    >>> params.expected_matched
    38400.0
    >>> params.threshold_for(Party.BOB) < params.threshold_for(Party.CHARLIE)
    True
    >>> ProtocolParams(key_length=64, s_a=0.4, s_v=0.2)
    Traceback (most recent call last):
        ...
    ValueError: s_a must be strictly less than s_v, ...
    >>> ProtocolParams(key_length=600, s_a=0.02, s_v=0.2)
    Traceback (most recent call last):
        ...
    ValueError: s_v must be strictly below the forger floor, ...
    >>> ProtocolParams(key_length=600, s_a=0.02, s_v=0.2, allow_forgeable=True).s_v
    0.2

    Spending an eighth of the run on estimation shortens the key, and every
    derived quantity follows the key rather than the nominal length:

    >>> checked = ProtocolParams(key_length=115200, check_fraction=0.125)
    >>> checked.check_count, checked.signing_length
    (14400, 100800)
    >>> checked.expected_matched
    33600.0
    >>> checked.sifted().key_length, checked.sifted().check_fraction
    (100800, 0.0)
    """

    key_length: int
    s_a: float = DEFAULT_S_A
    s_v: float = DEFAULT_S_V
    bases: tuple[PauliBasis, ...] = DEFAULT_BASES
    allow_forgeable: bool = False
    check_fraction: float = 0.0

    def __post_init__(self) -> None:
        """Coerce the fields and reject every parameter set that is not secure.

        Order matters: ``bases`` is validated first because the ``key_length``
        message quotes the alphabet size, and the thresholds are validated
        individually before they are compared, so that a caller who passes two
        bad values is told about the first one rather than about their ordering.
        """
        object.__setattr__(self, "bases", _validate_bases(self.bases))
        object.__setattr__(
            self, "key_length", _validate_key_length(self.key_length, self.bases)
        )
        object.__setattr__(self, "s_a", _as_threshold(self.s_a, "s_a"))
        object.__setattr__(self, "s_v", _as_threshold(self.s_v, "s_v"))
        if not isinstance(self.allow_forgeable, bool):
            raise TypeError(
                f"allow_forgeable must be a bool, got "
                f"{type(self.allow_forgeable).__name__}. It is an explicit "
                f"opt-in to an insecure parameter set, not a tuning knob."
            )
        object.__setattr__(
            self, "check_fraction", _as_check_fraction(self.check_fraction)
        )
        if self.check_fraction > 0.0 and self.check_count < 1:
            raise ValueError(
                f"check_fraction={self.check_fraction!r} designates "
                f"floor({self.check_fraction!r} * {self.key_length}) = 0 check "
                f"rounds, so nothing would be estimated while the parameter "
                f"set claims estimation is happening -- the worst of both. "
                f"Either raise the fraction to at least "
                f"{1.0 / self.key_length!r}, lengthen the key, or set "
                f"check_fraction=0.0 to say plainly that this run publishes no "
                f"channel statistics."
            )
        if self.check_count >= self.key_length:
            raise ValueError(
                f"check_fraction={self.check_fraction!r} designates all "
                f"{self.check_count} of {self.key_length} positions as check "
                f"rounds, leaving signing_length=0. Check positions are "
                f"excluded from the key, so there would be nothing to sign."
            )

        if self.s_a >= self.s_v:
            raise ValueError(
                f"s_a must be strictly less than s_v, got s_a={self.s_a!r} and "
                f"s_v={self.s_v!r}. The whole scheme lives in the gap between "
                f"them. s_v > s_a is TRANSFERABILITY: Bob's acceptance region "
                f"is contained in Charlie's, so a signature inside Bob's tight "
                f"cut sits inside Charlie's looser one and can be forwarded. "
                f"s_a > 0 is the room that makes NON-REPUDIATION work: after "
                f"the recipients' symmetrisation exchange, Alice cannot craft a "
                f"signature that squeaks past Bob and fails Charlie, because "
                f"the exchange splits her preparations between them and pushing "
                f"Charlie's rate above s_v pushes Bob's above s_a with it. With "
                f"s_a >= s_v both "
                f"guarantees invert -- Charlie becomes strictly harder to "
                f"satisfy than Bob, so Bob can accept signatures he cannot "
                f"forward. Try s_a={DEFAULT_S_A!r}, s_v={DEFAULT_S_V!r}."
            )
        if self.s_v >= 0.5:
            raise ValueError(
                f"s_v must be strictly less than 0.5, got {self.s_v!r}. On "
                f"matched positions an adversary who knows nothing about the "
                f"private key produces mismatches at rate exactly 1/2, so a "
                f"verification threshold at or above 1/2 accepts pure noise and "
                f"UNFORGEABILITY is gone outright. 0.5 is only the crude bound: "
                f"the rate an optimal recipient forger actually achieves "
                f"against this alphabet is {self.forger_floor!r} "
                f"(= (|B| - 1) / (2 |B| (|B| + 1)) with "
                f"|B| = {len(self.bases)}), and s_v must sit below that, not "
                f"merely below 0.5. Try s_v={DEFAULT_S_V!r}."
            )
        if self.s_v >= self.forger_floor and not self.allow_forgeable:
            raise ValueError(
                f"s_v must be strictly below the forger floor, got "
                f"s_v={self.s_v!r} with forger_floor={self.forger_floor!r} "
                f"(= (|B| - 1) / (2 |B| (|B| + 1)) for |B| = "
                f"{len(self.bases)}). That floor is the mismatch rate an "
                f"optimal recipient forger achieves against the second "
                f"verifier -- Bob declaring, per position, what he knows of "
                f"Charlie's record -- so a threshold at or above it accepts "
                f"that forgery outright and UNFORGEABILITY is gone. It is the "
                f"threshold that binds, not the crude 1/2. Try "
                f"s_v={DEFAULT_S_V!r}, or pass allow_forgeable=True if this is "
                f"a deliberate Phase 3 sweep past the floor; the flag is part "
                f"of the parameter set's identity and serialisation, so the "
                f"resulting transcripts record that the run was known to be "
                f"forgeable."
            )

    # -- derived quantities ------------------------------------------------- #

    @property
    def match_probability(self) -> float:
        """float: Probability that a recipient's basis matches Alice's, ``1/|B|``.

        Both draw uniformly and independently from :attr:`bases`, so this is
        ``1 / len(bases)`` -- ``1/3`` for the default alphabet.
        """
        return 1.0 / len(self.bases)

    @property
    def check_count(self) -> int:
        """int: How many of the ``L`` positions are spent on check rounds.

        ``floor(check_fraction * key_length)``, and ``0`` for a parameter set
        with no estimation. Floor rather than nearest, so the realised fraction
        never exceeds the requested one and a config file cannot buy a longer
        sample than it asked for.
        """
        return int(math.floor(self.check_fraction * self.key_length))

    @property
    def signing_length(self) -> int:
        """int: The key length that survives estimation, ``L - check_count``.

        **The effective key length**, and the one every security quantity in the
        scheme is computed from. Equal to :attr:`key_length` exactly when
        ``check_fraction`` is ``0``, which is why turning check rounds off
        leaves every published number untouched.

        The distinction is load-bearing rather than cosmetic. Check positions
        are spent on measuring the channel, so they carry no key and are
        excluded before anything is signed; a floor or a bound computed from
        ``L`` instead would be claiming evidence the run does not have. See
        :attr:`expected_matched` and :meth:`sifted`.
        """
        return self.key_length - self.check_count

    @property
    def has_check_rounds(self) -> bool:
        """bool: Whether this parameter set runs sampled parameter estimation."""
        return self.check_count > 0

    @property
    def expected_matched(self) -> float:
        """float: Expected number of matched positions, ``signing_length / |B|``.

        The statistically useful length of a key. Every security bound in the
        scheme is exponential in this, not in :attr:`key_length`, because
        unmatched positions carry no information and are discarded --
        and, since the ``check_fraction`` of positions spent on estimation carry
        no key either, it is computed from :attr:`signing_length` rather than
        from ``L``. With ``check_fraction = 0`` the two coincide and this is the
        familiar ``L / |B|``.

        Both matched-count floors
        (:func:`sih141.protocol.verify.minimum_matched_count`,
        :func:`sih141.protocol.verify.minimum_pooled_matched_count`) and hence
        :func:`sih141.protocol.verify.enforced_repudiation_bound` read this
        property and nothing else, so the shortening propagates to them without
        any of those functions having to know check rounds exist. That is the
        whole mechanism, and what stops a future edit quietly pointing it back
        at ``L`` is
        ``test_every_derived_quantity_follows_the_signing_length`` in
        ``tests/test_protocol_checkrounds.py``, which asserts that a checked set
        and a plain set of its signing length agree term for term.
        """
        return self.signing_length * self.match_probability

    @property
    def gap(self) -> float:
        """float: ``s_v - s_a``, strictly positive by construction.

        The exponent of the repudiation bound is proportional to its square, so
        halving the gap costs a factor of four in key length.
        """
        return self.s_v - self.s_a

    @property
    def unmatched_noise_rate(self) -> float:
        """float: ``(1 - 1/|B|) / 2``, the cost of scoring unmatched positions.

        If a verifier counts every position instead of only the matched ones,
        the ``1 - 1/|B|`` unmatched positions contribute a fair coin each and
        the reported rate picks up exactly this much pure noise -- ``1/3`` for
        the ``{X, Y, Z}`` alphabet. That is the classic implementation bug of
        this protocol family (:mod:`sih141.protocol.verify`), and the symptom is
        that both verifiers reject every honest signature on a *perfect*
        channel.

        By a coincidence of the same arithmetic it is also the mismatch rate a
        compliant recipient forger would achieve in a variant of this protocol
        *without* the symmetrisation step
        (:data:`UNSYMMETRISED_FORGER_RATE_THREE_BASIS`). The two quantities are
        unrelated in meaning; see :attr:`forger_floor` for the rate that
        actually binds here.
        """
        return (1.0 - self.match_probability) / 2.0

    @property
    def forger_scored_fraction(self) -> float:
        """float: ``(|B| + 1) / (2|B|)``, the fraction of positions a recipient
        forger gets scored.

        Half the positions were supplied to the second verifier by the forger
        himself during symmetrisation, so his declaration matches there with
        probability ``1``; the retained half is matched with the usual
        ``1/|B|``. Equals ``2/3`` for the ``{X, Y, Z}`` alphabet, against the
        ``1/3`` an outside forger achieves.
        """
        return (1.0 + self.match_probability) / 2.0

    @property
    def forger_floor(self) -> float:
        """float: Mismatch rate an optimal recipient forger achieves.

        ``(|B| - 1) / (2 |B| (|B| + 1))``: ``1/12`` for the ``{X, Y, Z}``
        alphabet and ``1/12`` again for a two-basis (BB84-style) one, since
        fewer bases raise the per-position mismatch rate but shrink the matched
        set by the same factor. The derivation, and the POVM argument that no
        cheating measurement strategy beats it, are in the module docstring.

        This is the threshold that really binds :attr:`s_v`, and unlike in
        earlier versions it **is** enforced by :meth:`__post_init__`: a
        parameter set with ``s_v >= forger_floor`` is refused unless
        :attr:`allow_forgeable` is set, so a Phase 3 sweep past the floor is
        explicit rather than indistinguishable from a typo.
        """
        size = float(len(self.bases))
        return (size - 1.0) / (2.0 * size * (size + 1.0))

    @property
    def is_forgeable(self) -> bool:
        """bool: ``True`` when ``s_v`` sits at or above :attr:`forger_floor`.

        Only ever ``True`` for a set constructed with
        :attr:`allow_forgeable`, since :meth:`__post_init__` refuses the
        combination otherwise. Phase 3 reads it to label a sweep point.
        """
        return self.s_v >= self.forger_floor

    def threshold_for(self, party: Party | str) -> float:
        """Return the acceptance threshold of a verifying party.

        Parameters
        ----------
        party : Party or str
            :attr:`Party.BOB` or :attr:`Party.CHARLIE`, or the corresponding
            label.

        Returns
        -------
        float
            :attr:`s_a` for Bob, :attr:`s_v` for Charlie.

        Raises
        ------
        ValueError
            If ``party`` is :attr:`Party.ALICE`, who signs rather than verifies
            and therefore has no threshold, or is not a party at all.
        TypeError
            If ``party`` is neither a :class:`Party` nor a string.

        Examples
        --------
        >>> from sih141.protocol.params import DEMO_PARAMS, Party
        >>> DEMO_PARAMS.threshold_for("Bob") == DEMO_PARAMS.s_a
        True
        """
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice has no acceptance threshold: she is the signer, not a "
                "verifier, and keeps no measurement record to compute a "
                "mismatch rate from. Ask for Party.BOB (threshold s_a) or "
                "Party.CHARLIE (threshold s_v)."
            )
        return self.s_a if resolved is Party.BOB else self.s_v

    def with_changes(self, **changes: Any) -> ProtocolParams:
        """Return a new parameter set with some fields replaced.

        A thin wrapper over :func:`dataclasses.replace`, so the result is fully
        re-validated. Provided because the instance is frozen and a Phase 5
        sweep over ``key_length`` or ``s_v`` should not have to import
        :mod:`dataclasses`.

        Parameters
        ----------
        **changes
            Field names and their new values.

        Returns
        -------
        ProtocolParams
            A new, validated instance.

        Examples
        --------
        >>> from sih141.protocol.params import DEMO_PARAMS
        >>> DEMO_PARAMS.with_changes(key_length=48).key_length
        48
        """
        return replace(self, **changes)

    def with_check_fraction(self, check_fraction: float) -> ProtocolParams:
        """Return the same parameter set with a different check fraction.

        A named spelling of ``with_changes(check_fraction=...)``, because
        turning sampled estimation on is a security-relevant decision -- it
        shortens the key and therefore every bound -- and deserves to be
        greppable.

        Parameters
        ----------
        check_fraction : float
            The new fraction, in ``[0, 1)``. See
            :data:`DEFAULT_CHECK_FRACTION`, and
            :func:`sih141.protocol.checkrounds.required_check_rounds` for the
            fraction *this* ``L`` actually needs.

        Returns
        -------
        ProtocolParams
            A new, validated instance.

        Examples
        --------
        >>> from sih141.protocol.params import DEFAULT_CHECK_FRACTION, DEMO_PARAMS
        >>> checked = DEMO_PARAMS.with_check_fraction(DEFAULT_CHECK_FRACTION)
        >>> checked.check_count, checked.signing_length
        (24, 168)
        >>> checked.with_check_fraction(0.0) == DEMO_PARAMS
        True
        """
        return replace(self, check_fraction=check_fraction)

    def sifted(self) -> ProtocolParams:
        """Return the parameter set the *retained* key is verified under.

        Identical in every threshold, with ``key_length`` cut to
        :attr:`signing_length` and ``check_fraction`` cleared -- the run's check
        rounds have already happened and are not to be spent twice.

        This is the object to hand to :func:`sih141.protocol.verify.verify`,
        :meth:`sih141.protocol.keys.PrivateKey.check_against` and
        :meth:`sih141.protocol.records.RecipientRecord.check_against` after a
        checked distribution, because those all require the key and the record
        to be exactly ``key_length`` long and a sifted pair is
        ``signing_length`` long. Every derived quantity is unchanged by the
        substitution -- ``self.expected_matched == self.sifted().expected_matched``
        by construction -- so verifying under the sifted set applies the same
        floors and the same bound the checked set advertises.

        **And it is mandatory before anything in**
        :mod:`sih141.protocol.analysis`. That module counts Bernoulli trials
        against ``key_length`` *directly* -- ``Binomial(L, 1/|B|)``,
        ``Binomial(2L, 1/|B|)`` -- rather than through
        :attr:`expected_matched`, because when it was written a run had no
        rounds that were not key positions. Handed a set with check rounds it
        would therefore count the diverted positions as key and return a bound
        that is too good, which is exactly the silent weakening this whole
        feature exists to avoid. The two floors and
        :func:`sih141.protocol.verify.enforced_repudiation_bound` are safe
        either way -- they read only :attr:`expected_matched` -- but
        :func:`~sih141.protocol.analysis.forgery_bound`,
        :func:`~sih141.protocol.analysis.recipient_forgery_bound`,
        :func:`~sih141.protocol.analysis.averaged_repudiation_bound`,
        :func:`~sih141.protocol.analysis.matched_statistics` and their
        neighbours are not. Call them as ``forgery_bound(params.sifted())``.
        ``test_the_analytic_bounds_must_be_given_the_sifted_parameters`` in
        ``tests/test_protocol_checkrounds.py`` pins the discrepancy, and its
        direction, so it stays visible rather than becoming folklore.

        Returns
        -------
        ProtocolParams
            A validated instance; ``self`` unchanged when there are no check
            rounds.

        Examples
        --------
        >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
        >>> checked = ProtocolParams(key_length=115200, check_fraction=0.125)
        >>> checked.sifted().key_length
        100800
        >>> checked.sifted().expected_matched == checked.expected_matched
        True
        >>> checked.sifted().sifted() == checked.sifted()
        True
        >>> DEFAULT_PARAMS.sifted() == DEFAULT_PARAMS
        True
        """
        if not self.has_check_rounds:
            return replace(self, check_fraction=0.0)
        return replace(
            self, key_length=self.signing_length, check_fraction=0.0
        )

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the parameter set.

        Returns
        -------
        dict
            Keys ``"key_length"``, ``"s_a"``, ``"s_v"``, ``"bases"``,
            ``"allow_forgeable"`` and ``"check_fraction"``. The bases are
            :class:`PauliBasis` members, which are strings, so the result
            passes straight to :func:`json.dumps`.

        Examples
        --------
        >>> import json
        >>> from sih141.protocol.params import ProtocolParams
        >>> json.loads(json.dumps(ProtocolParams(key_length=9).to_dict()))["bases"]
        ['X', 'Y', 'Z']
        >>> ProtocolParams(key_length=9).to_dict()["check_fraction"]
        0.0
        """
        return {
            "key_length": self.key_length,
            "s_a": self.s_a,
            "s_v": self.s_v,
            "bases": list(self.bases),
            "allow_forgeable": self.allow_forgeable,
            "check_fraction": self.check_fraction,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProtocolParams:
        """Rebuild a parameter set from :meth:`to_dict` output or a config file.

        Parameters
        ----------
        data : mapping
            Must contain ``"key_length"``; ``"s_a"``, ``"s_v"`` and ``"bases"``
            fall back to the module defaults when absent.

        Returns
        -------
        ProtocolParams
            A validated instance.

        Raises
        ------
        ValueError
            If ``"key_length"`` is missing, if unknown keys are present (a typo
            in a config file must fail loudly rather than silently leave a
            threshold at its default), or if validation fails.

        Examples
        --------
        >>> from sih141.protocol.params import ProtocolParams
        >>> ProtocolParams.from_dict({"key_length": 12, "bases": ["z", "x"]}).bases
        (<PauliBasis.Z: 'Z'>, <PauliBasis.X: 'X'>)
        """
        known = {
            "key_length",
            "s_a",
            "s_v",
            "bases",
            "allow_forgeable",
            "check_fraction",
        }
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(
                f"unknown ProtocolParams field(s) {unknown}; expected any of "
                f"{sorted(known)}. Unknown keys are rejected rather than "
                f"ignored so a mistyped config entry cannot leave a threshold "
                f"silently at its default."
            )
        if "key_length" not in data:
            raise ValueError(
                "ProtocolParams.from_dict requires 'key_length'; there is no "
                "sensible default key length, because it is what every security "
                "bound is exponential in."
            )
        return cls(
            key_length=data["key_length"],
            s_a=data.get("s_a", DEFAULT_S_A),
            s_v=data.get("s_v", DEFAULT_S_V),
            bases=data.get("bases", DEFAULT_BASES),
            allow_forgeable=data.get("allow_forgeable", False),
            check_fraction=data.get("check_fraction", 0.0),
        )


def _as_party(party: Party | str) -> Party:
    """Coerce a party argument to :class:`Party`.

    Parameters
    ----------
    party : Party or str
        A member or its label, case-insensitive.

    Returns
    -------
    Party
        The corresponding member.

    Raises
    ------
    ValueError
        If ``party`` is a string naming no party.
    TypeError
        If ``party`` is neither a :class:`Party` nor a string.
    """
    if isinstance(party, Party):
        return party
    if isinstance(party, str):
        cleaned = party.strip().capitalize()
        try:
            return Party(cleaned)
        except ValueError:
            raise ValueError(
                f"unknown party {party!r}; expected 'Alice', 'Bob' or "
                f"'Charlie' (case-insensitive) or a Party member"
            ) from None
    raise TypeError(
        f"party must be a Party (or the string 'Alice', 'Bob', 'Charlie'), got "
        f"{type(party).__name__}"
    )


def _validate_bases(bases: Sequence[PauliBasis | str]) -> tuple[PauliBasis, ...]:
    """Coerce and check the measurement-basis alphabet.

    Parameters
    ----------
    bases : sequence of PauliBasis or str
        The alphabet. Order is preserved.

    Returns
    -------
    tuple of PauliBasis
        The alphabet as an immutable tuple.

    Raises
    ------
    TypeError
        If ``bases`` is not a sequence, or is a bare string (``"XYZ"`` is a
        sequence of characters and would silently work, which is not the
        intended spelling).
    ValueError
        If the alphabet is empty, holds duplicates, or holds a single basis.
    """
    if isinstance(bases, str):
        raise TypeError(
            f"bases must be a sequence of PauliBasis members, not the string "
            f"{bases!r}. A string would iterate character by character; write "
            f"(PauliBasis.X, PauliBasis.Y, PauliBasis.Z) or ['X', 'Y', 'Z']."
        )
    if not isinstance(bases, Sequence):
        raise TypeError(
            f"bases must be a sequence of PauliBasis members, got "
            f"{type(bases).__name__}"
        )
    resolved = tuple(_as_basis(basis, name="bases entry") for basis in bases)
    if not resolved:
        raise ValueError(
            "bases must not be empty: Alice and the recipients both draw their "
            "measurement bases uniformly from this alphabet, so an empty one "
            "leaves nothing to draw."
        )
    if len(set(resolved)) != len(resolved):
        duplicates = sorted({b for b in resolved if resolved.count(b) > 1})
        raise ValueError(
            f"bases must not repeat a basis, got duplicates "
            f"{[b.value for b in duplicates]}. A repeated entry silently "
            f"doubles that basis's draw probability, which changes the match "
            f"probability and therefore every security bound, without changing "
            f"anything visible in a run."
        )
    if len(resolved) < 2:
        raise ValueError(
            f"bases must hold at least two bases, got "
            f"{[b.value for b in resolved]}. With a single basis every "
            f"recipient's basis matches Alice's, the public key states are "
            f"perfectly distinguishable by the measurement the protocol itself "
            f"prescribes, and the compliant-forger mismatch rate drops to 0: "
            f"UNFORGEABILITY is not merely weakened but absent."
        )
    return resolved


def _validate_key_length(key_length: int, bases: tuple[PauliBasis, ...]) -> int:
    """Coerce and check ``L``.

    Parameters
    ----------
    key_length : int
        The proposed key length.
    bases : tuple of PauliBasis
        The already-validated alphabet, used only to quote the expected number
        of matched positions in the error message.

    Returns
    -------
    int
        ``key_length`` as a plain int.

    Raises
    ------
    ValueError
        If ``key_length`` is a boolean, not an integer, or not positive.
    """
    if isinstance(key_length, bool):
        raise ValueError(
            f"key_length must be a positive integer, got the boolean "
            f"{key_length!r}"
        )
    if not isinstance(key_length, numbers.Integral):
        raise ValueError(
            f"key_length must be a positive integer, got "
            f"{type(key_length).__name__}. It counts key elements, so a "
            f"fractional value is meaningless; use int(...) at the config "
            f"boundary."
        )
    value = int(key_length)
    if value <= 0:
        raise ValueError(
            f"key_length must be positive, got {value}. It is the number of "
            f"key elements drawn per message bit, and only the matched "
            f"positions -- about key_length / {len(bases)} of them -- carry any "
            f"information. Every failure probability in the scheme is "
            f"exp(-Theta(matched positions)), so a non-positive length leaves "
            f"nothing to verify and no bound at all."
        )
    return value


DEFAULT_PARAMS: Final[ProtocolParams] = ProtocolParams(
    key_length=_DEFAULT_KEY_LENGTH,
    s_a=DEFAULT_S_A,
    s_v=DEFAULT_S_V,
    bases=DEFAULT_BASES,
)
"""The documented security-grade parameter set: ``L = 115200``, ``s_a = 1/64``, ``s_v = 1/16``.

Every number is chosen, not inherited:

``bases = (X, Y, Z)``
    The six-state alphabet. Three bases rather than BB84's two leave the
    recipient-forger floor unchanged at ``1/12`` -- fewer bases raise the
    per-position mismatch rate but shrink the matched set by the same factor --
    and buy a larger *scored* fraction for the honest run, hence a shorter key
    for the same repudiation exponent.
``s_v = 1/16``
    Three quarters of the ``1/12`` recipient-forger floor
    (:attr:`ProtocolParams.forger_floor`), which is optimal over all POVMs and
    therefore not a rate any cheating measurement improves on. The margin is
    sized by what it buys: ``D(1/16 || 1/12) = 0.003088`` nats gives a
    recipient-forgery bound of ``1e-103`` at this key length.
``s_a = 1/64``
    A noise budget. Honest noiseless runs give ``r_B = 0`` exactly; a Werner
    teleportation resource of parameter ``p`` induces a depolarising channel of
    matched-position error rate ``p / 2``, so honest signatures survive up to
    ``p = 3.125%``.
``L = 115200``
    ``115200 / 3 = 38400`` matched positions per verifier exactly, so
    ``E[M] = 76800`` matched records across the pair. With
    ``gap = 1/16 - 1/64 = 3/64``, the symmetrisation repudiation bound
    ``exp(-M gap**2 / 8)`` evaluates to ``exp(-21.09) = 6.9e-10`` *at that
    expected* ``M``, and its average over ``M ~ Binomial(2L, 1/3)`` --
    ``(1 - 1/3 + exp(-gap**2/8)/3)**(2L)`` -- to the same ``6.9173e-10``.
    Rounded to a multiple of three so the expected matched count is an integer
    and the tables in the Phase 5 report have no spurious fractions.

    **That average is not the key length's security claim**, because it needs
    the declaration to be independent of the recipients' logged bases and the
    ``Signer`` seam hands them over. What ``L`` actually buys, unconditionally,
    is ``exp(-max(2 m_min, M_min) * gap**2 / 8) = exp(-74190 * gap**2 / 8) =
    1.4139e-09`` (:func:`sih141.protocol.verify.enforced_repudiation_bound`) --
    the same order, honestly obtained.

    **That figure belongs to three rules jointly**, not to the per-verifier
    floor: ``m_B, m_C >= 36555``, *and* the pooled ``m_B + m_C >= 74190``, *and*
    the joint consequence that a verifier below his own floor takes the other
    down with him. An earlier version of this docstring attributed
    ``exp(-2 * 36555 * gap**2 / 8) = 1.9022e-09`` to the per-verifier floor
    alone; that bounds only the branch in which Charlie rejects, and leaves the
    third outcome -- Charlie non-empty but under his own floor, no verdict --
    open at about ``1/2`` at every ``L``. See the module docstring above and
    :mod:`sih141.protocol.analysis` sections 4b-iii and 4b-iv.

    The forgery bounds below are unaffected: their independence hypothesis is
    part of their stated adversary model rather than an unstated one.

    Every number in this docstring is checked as a doctest in the *module*
    docstring, under "The numbers above, as executable claims" -- :mod:`doctest`
    does not collect attribute docstrings, so a figure written only here is
    prose, and prose is what let the ``1.9e-9`` attribution above survive
    until an audit went looking for it.

The key is long because the bound is honest. The earlier ``L = 6912`` was
computed from ``exp(-m gap**2 / 2)`` with ``gap = 13/96``, an expression that
assumed Bob's and Charlie's records were i.i.d. given the declaration -- which
nothing in the protocol forced, and which a repudiating Alice broke with
probability ``1``. Symmetrisation makes a uniform bound available at all; it
costs a factor of four in the forger floor (hence a smaller usable gap) and a
factor of two in the exponent's constant, and ``115200 / 6912 = 16.7`` is the
product of those two prices.

Cost, stated plainly: a full two-message-bit setup teleports
``2 recipients * 2 message bits * 115200 = 460800`` qubits. That is the price of
a sub-nanoprobability bound and it is why :data:`DEMO_PARAMS` exists.
"""

DEMO_PARAMS: Final[ProtocolParams] = ProtocolParams(
    key_length=_DEMO_KEY_LENGTH,
    s_a=DEFAULT_S_A,
    s_v=DEFAULT_S_V,
    bases=DEFAULT_BASES,
)
"""A short parameter set for interactive runs, tests and the Phase 6 dashboard.

Identical thresholds to :data:`DEFAULT_PARAMS`, so the decision rule being
demonstrated is *the same* decision rule; only ``L`` is cut, from 115200 to 192.

**No security claim attaches to this set.** With 128 expected matched records
across the pair the repudiation bound is ``exp(-0.035) = 0.97`` -- order one,
i.e. no bound worth the name. Use it to watch the protocol run and to keep the
test suite fast; never to report a security number.
"""

CHECKED_PARAMS: Final[ProtocolParams] = ProtocolParams(
    key_length=_CHECKED_KEY_LENGTH,
    s_a=DEFAULT_S_A,
    s_v=DEFAULT_S_V,
    bases=DEFAULT_BASES,
    check_fraction=DEFAULT_CHECK_FRACTION,
)
"""The security-grade set **with** sampled parameter estimation: ``L = 131664``, ``f = 1/8``.

:data:`DEFAULT_PARAMS` has no legitimate source for a channel statistic: the
distribution phase measures nothing it publishes, so any QBER or CHSH number
quoted beside it would have been invented. This set fixes that and pays for it
in the only currency that keeps the security claim intact -- key length.

``check_fraction = 1/8``
    :data:`DEFAULT_CHECK_FRACTION`, derived in
    :mod:`sih141.protocol.checkrounds` from two sample-size requirements rather
    than chosen. ``16458`` of the ``131664`` rounds are spent on estimation,
    split evenly between the QBER and CHSH arms, and each arm's ``8229`` rounds
    clears its requirement (``6688`` and ``6795``).
``L = 131664``
    ``115200 * 8/7`` rounded up to a multiple of ``24``, so that
    :attr:`~ProtocolParams.signing_length` ``= 115206`` is at least
    :data:`DEFAULT_PARAMS`'s whole key length and stays divisible by ``3``.
    Every floor and every bound is computed from that signing length, so the
    enforced repudiation bound is ``1.4124e-09`` -- *no weaker* than the
    ``1.4139e-09`` of the unchecked set.

**The alternative that must not be shipped by accident** is spending the
fraction out of ``L = 115200`` itself: that leaves ``100800`` signing positions,
``33600`` expected matched, and an enforced bound of ``1.8853e-08`` -- thirteen
times weaker, with nothing to show for it but a shorter run. Both figures are
doctests in :mod:`sih141.protocol.checkrounds`, printed side by side, so the
cheap one cannot be mistaken for this one.

Cost, stated plainly: ``2 recipients * 2 message bits * 131664 = 526656``
entanglement resources per full setup, against ``460800`` unchecked. Parameter
estimation costs 14% more quantum communication and buys the right to say
anything at all about the channel.
"""

DEMO_CHECKED_PARAMS: Final[ProtocolParams] = ProtocolParams(
    key_length=_DEMO_KEY_LENGTH,
    s_a=DEFAULT_S_A,
    s_v=DEFAULT_S_V,
    bases=DEFAULT_BASES,
    check_fraction=DEFAULT_CHECK_FRACTION,
)
"""A short set with check rounds, for interactive runs and the test suite.

:data:`DEMO_PARAMS` plus :data:`DEFAULT_CHECK_FRACTION`: ``L = 192``, of which
``24`` are check rounds and ``168`` carry key.

**No security claim attaches to this set, and no statistical one either.** Its
``24`` check rounds are three orders of magnitude below what
:func:`sih141.protocol.checkrounds.required_check_rounds` asks for, so the
intervals it produces are honest but far too wide to decide anything -- which is
itself worth demonstrating, since an interval that says "somewhere between 0 and
0.4" is exactly what a too-small sample should say. Use it to watch the
mechanism; never to report a channel number.
"""
