"""Impersonation: Mallory stands where Alice stands, on one seam or on both.

The adversary here is not a forger. A forger declares a key he does not hold the
states for, and the mismatch rate catches him. Mallory does something simpler
and, on one branch, strictly better: she draws a key pair of her **own** and
runs the protocol correctly with it. Whether that works depends entirely on how
many of Alice's seams she has seized, and the two answers are as far apart as
two answers can be.

.. _impersonation-scopes:

The three scopes, and why they are three and not one
----------------------------------------------------
:class:`ImpersonationScope` names which of the two Alice-side seams
(:class:`~sih141.protocol.session.Distributor`,
:class:`~sih141.protocol.session.Signer`) Mallory holds:

.. code-block:: text

    scope            Phase A distributed by   Phase B declared by   expectation
    ---------------------------------------------------------------------------
    NONE             Alice                    Alice                 the control
    DISTRIBUTION     Mallory (her key)        Alice (her own key)   r ~ 1/2
    SIGNING          Alice                    Mallory (her key)     r ~ 1/2
    FULL             Mallory (her key)        Mallory (same key)    r  = 0

``FULL`` is the whole content of assumption **(AUTH)** in
:mod:`sih141.protocol.analysis`, made executable. Mallory distributes states
for a key she drew, then declares that key. Every recipient's log agrees with
the declaration exactly as it would with Alice's, because it *is* a correct run
-- of somebody else's protocol instance. There is no counting rule over the
recipients' logs that can separate it from an honest run, and this module does
not pretend to find one: it measures the acceptance rate so that the cost of
(AUTH) is a number rather than a paragraph. This scope is **out of model** by
assumption and must never be quoted as a break of the scheme.

``DISTRIBUTION`` and ``SIGNING`` are in model, and they fail for the same
arithmetic reason, reached along two different routes. See :ref:`half-a-half`.

.. _half-a-half:

Why one seam gives exactly one half, on both routes
---------------------------------------------------
Write ``d_i, v_i`` for the declared basis and eigenvalue at position ``i``,
``c_i, o_i`` for the recipient's measurement basis and outcome. Position ``i``
is scored exactly when ``c_i == d_i``; the run's rate is the fraction of scored
positions with ``o_i != v_i``.

*Signing seam only.* Alice distributed ``(a_i, u_i)`` and the recipient measured
it in ``c_i``, so ``o_i`` is a function of Alice's key and the recipient's own
uniform draw. Mallory's ``v_i`` is a fair coin she tossed with her own
generator, independent of both. Conditioned on the position being scored,
``P(o_i != v_i) = 1/2`` whatever ``o_i`` turned out to be.

*Distribution seam only.* Mallory distributed ``(a'_i, u'_i)`` and Alice
declared her true ``(a_i, u_i)``, so a position is scored when ``c_i == a_i``,
and then ``o_i`` is the outcome of measuring Mallory's eigenstate in Alice's
basis. If ``a'_i == a_i`` (probability ``1/n``) the outcome is ``u'_i``, a fair
coin independent of ``u_i``; otherwise the Born rule makes it a fair coin
directly. Either way ``P(o_i != u_i) = 1/2``.

So both partial scopes are ``Binomial(m, 1/2) / m`` on the matched set, against
thresholds of ``1/64`` and ``1/16``. That is the prediction this module
measures, and it is a per-position statement, so it does not depend on ``L``.

.. _impersonation-invisibles:

What does *not* move, and what that costs Phase 4
--------------------------------------------------
The matched set is ``{i : c_i == d_i}``. Both of its inputs -- the declared
bases and the recipients' uniform draws -- are untouched by an impersonator, who
substitutes *values* and never the sampling law. So the matched counts are
unchanged, and under ``DISTRIBUTION`` they are unchanged in the sharpest
possible sense: Alice declares the same key she would have declared, the
recipients draw the same bases from the same stream, and the matched set is
**identical position for position** to the control run at the same session seed.
:func:`matched_sets_identical` checks that rather than asserting it.

The consequence for Phase 4 is the useful part of this module: under partial
impersonation the mismatch rate is the *only* transcript statistic that moves,
and under full impersonation nothing moves at all. See :func:`detector_signals`.

.. _impersonation-d6:

D6
--
:class:`Impersonator` takes its own :class:`numpy.random.Generator` and draws
her key pair from it, lazily and cached per ``(message_bit, key_length)`` so
that the distribution seam and the signing seam of one adversary declare the
*same* key -- which is the only reason ``FULL`` works at all. Nothing here reads
the session's generator: the distributor is handed Alice's stream and passes it
straight to :func:`~sih141.protocol.distribute.distribute_public_key_with_checks`
for the teleportation it is *supposed* to drive, and Mallory's own choices come
from her own generator only. Both halves of
:func:`~sih141.attacks.isolation.check_attack_isolation` are run over this class
in the test suite, on each seam separately.

Examples
--------
A control run and a signing-seam impersonation at the same session seed. The
key length is deliberately small and carries **no security claim** (both floors
degenerate below ``L = 140``); it is here to show the mechanism cheaply.

>>> import numpy as np
>>> from sih141.attacks.impersonation import (
...     ImpersonationScope, run_impersonation)
>>> from sih141.protocol.params import ProtocolParams
>>> demo = ProtocolParams(key_length=48)
>>> control = run_impersonation(
...     ImpersonationScope.NONE, demo,
...     session_seed=4, attack_rng=np.random.default_rng(0))
>>> control.accepted_by_both, control.bob_rate
(True, 0.0)

>>> attacked = run_impersonation(
...     ImpersonationScope.SIGNING, demo,
...     session_seed=4, attack_rng=np.random.default_rng(0))
>>> attacked.accepted_by_both, attacked.transferable
(False, False)
>>> attacked.bob_rate > 0.25
True

The full seizure is accepted, and is indistinguishable from the control by every
number in the verdict:

>>> whole = run_impersonation(
...     ImpersonationScope.FULL, demo,
...     session_seed=4, attack_rng=np.random.default_rng(0))
>>> whole.accepted_by_both, whole.bob_rate, whole.charlie_rate
(True, 0.0, 0.0)

See Also
--------
sih141.attacks.isolation : The D6 check every adversary here satisfies.
sih141.protocol.analysis : Where (AUTH) is stated and what it excludes.
"""

from __future__ import annotations

import enum
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from sih141.attacks.statistics import two_sided_z, wilson_bounds
from sih141.protocol.checkrounds import CheckRoundPlan, Interval
from sih141.protocol.distribute import (
    PayloadMap,
    RecipientDistribution,
    ResourceFactory,
    distribute_public_key_with_checks,
)
from sih141.protocol.keys import PrivateKey, generate_private_key
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.records import RecipientRecord
from sih141.protocol.session import QDSSession, SessionTranscript
from sih141.protocol.signature import Signature

__all__ = [
    "DEMO_MEASUREMENT_PARAMS",
    "MATCHED_IDENTICAL_TRIALS",
    "MEASURED",
    "MEASUREMENT_PARAMS",
    "ImpersonationMeasurement",
    "ImpersonationScope",
    "ImpersonationTrial",
    "Impersonator",
    "MeasuredRun",
    "detector_signals",
    "distributor_probe",
    "impersonation_seams",
    "matched_sets_identical",
    "measure_impersonation",
    "run_impersonation",
    "session_seeds",
    "shipped_summary",
    "signing_probe",
    "wilson_interval",
]


#: Confidence level every interval in this module is reported at.
CONFIDENCE: Final[float] = 0.95

#: The parameter set the shipped table in :data:`MEASURED` was measured under.
#: ``L = 192`` is the demonstration scale: both floors are non-degenerate
#: (``m_min = 1``, ``M_min = 22`` against ``E[m] = 64`` per recipient), so a run
#: reaches a verdict rather than aborting, while a session costs about a second.
MEASUREMENT_PARAMS: Final[ProtocolParams] = ProtocolParams(key_length=192)

#: A cheap parameter set for doctests and fast tests. **Carries no security
#: claim**: below ``L = 140`` both floors degenerate, so a run under it
#: demonstrates mechanism only.
DEMO_MEASUREMENT_PARAMS: Final[ProtocolParams] = ProtocolParams(key_length=48)

#: First session seed used by :func:`session_seeds`. Arbitrary, fixed, and
#: unrelated to any seed an adversary in this module is ever built from -- D6
#: is about the two never meeting.
FIRST_SESSION_SEED: Final[int] = 900_000


class ImpersonationScope(enum.StrEnum):
    """Which of Alice's two seams Mallory holds.

    A :class:`enum.StrEnum` so a scope drops into a transcript, a JSON blob and
    a Phase 5 results table without an encoder.

    Attributes
    ----------
    NONE
        Neither. The control run, kept as a member rather than as a separate
        code path so that the attacked and unattacked arms of an experiment are
        produced by the same function at the same seeds.
    DISTRIBUTION
        Phase A only: Mallory sends states for her own key, Alice declares hers.
    SIGNING
        Phase B only: Alice's states, Mallory's declaration. This is the
        external forger of :mod:`sih141.protocol.analysis` section 3, reached
        by seizing a seam rather than by guessing.
    FULL
        Both. Out of model by assumption (AUTH); see the module docstring.

    Examples
    --------
    >>> from sih141.attacks.impersonation import ImpersonationScope
    >>> ImpersonationScope.FULL.is_partial, ImpersonationScope.FULL.in_model
    (False, False)
    >>> ImpersonationScope.SIGNING.is_partial
    True
    >>> sorted(str(scope) for scope in ImpersonationScope if scope.is_partial)
    ['distribution', 'signing']
    """

    NONE = "none"
    DISTRIBUTION = "distribution"
    SIGNING = "signing"
    FULL = "full"

    @property
    def takes_distribution(self) -> bool:
        """bool: True when Mallory drives Phase A."""
        return self in (ImpersonationScope.DISTRIBUTION, ImpersonationScope.FULL)

    @property
    def takes_signing(self) -> bool:
        """bool: True when Mallory declares in Phase B."""
        return self in (ImpersonationScope.SIGNING, ImpersonationScope.FULL)

    @property
    def is_partial(self) -> bool:
        """bool: True for exactly one seam -- the in-model, caught-cold cases."""
        return self.takes_distribution != self.takes_signing

    @property
    def in_model(self) -> bool:
        """bool: False only for :attr:`FULL`, which (AUTH) assumes away.

        A scope that is not in model may be measured and reported, but its
        acceptance rate is a statement about the *assumption*, never about the
        protocol's soundness.
        """
        return self is not ImpersonationScope.FULL


# --------------------------------------------------------------------------- #
# Small coercions
# --------------------------------------------------------------------------- #


def _as_scope(scope: ImpersonationScope | str) -> ImpersonationScope:
    """Return ``scope`` as an :class:`ImpersonationScope`.

    Parameters
    ----------
    scope : ImpersonationScope or str

    Returns
    -------
    ImpersonationScope

    Raises
    ------
    ValueError
        If it names no member.
    """
    if isinstance(scope, ImpersonationScope):
        return scope
    try:
        return ImpersonationScope(str(scope).lower())
    except ValueError:
        known = ", ".join(str(member) for member in ImpersonationScope)
        raise ValueError(
            f"unknown impersonation scope {scope!r}; expected one of {known}. "
            f"The scope names which of Alice's two seams Mallory holds, and "
            f"the answer changes the result completely -- see "
            f"the module docstring."
        ) from None


def _as_verifier(party: Party | str) -> Party:
    """Return ``party`` as a verifier, refusing Alice.

    Parameters
    ----------
    party : Party or str

    Returns
    -------
    Party

    Raises
    ------
    ValueError
        If it is Alice or names no party.
    """
    try:
        resolved = Party(str(party))
    except ValueError:
        raise ValueError(
            f"unknown party {party!r}; expected Bob or Charlie"
        ) from None
    if not resolved.is_verifier:
        raise ValueError(
            f"{resolved!s} keeps no record and reaches no verdict, so there is "
            f"no rate to report for her. Ask about Bob or Charlie."
        )
    return resolved


def _rate(mismatches: int | None, matched: int | None) -> float | None:
    """Return ``mismatches / matched``, or ``None`` when there was no verdict.

    Parameters
    ----------
    mismatches : int or None
    matched : int or None

    Returns
    -------
    float or None
    """
    if mismatches is None or matched is None or matched == 0:
        return None
    return mismatches / matched


class Impersonator:
    """Mallory: she runs the protocol correctly, with a key pair of her own.

    One object serves both seams, and that is the point of it being an object.
    :meth:`distribute` and :meth:`sign` consult the same cache, so under
    :attr:`ImpersonationScope.FULL` the key whose states were teleported is the
    key that gets declared. Two independent adversaries, one per seam, would
    produce two different keys and would measure as two partial impersonations
    stacked -- which is a different and much weaker attack.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, and **hers** (D6). Every key element she declares comes
        from this generator and from nothing else. Never pass the generator or
        the seed handed to :class:`~sih141.protocol.session.QDSSession`; see
        :mod:`sih141.attacks.isolation`.

    Raises
    ------
    TypeError
        If ``rng`` is not a :class:`numpy.random.Generator`. Integer seeds are
        refused deliberately: an adversary built from an integer is one call
        away from being built from *the session's* integer.

    Attributes
    ----------
    keys : mapping
        Read-only view of what she has drawn so far, keyed by
        ``(message_bit, key_length)``. Empty until a seam is called, because the
        draws are lazy.

    Notes
    -----
    Keys are cached on ``(message_bit, key_length)`` rather than on
    ``message_bit`` alone because a run that reserves check rounds distributes
    at the full length and declares at the sifted one. :meth:`distribute` sifts
    her key with the plan it is given and files the result under the sifted
    length, so :meth:`sign` finds it and ``FULL`` survives check rounds.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.impersonation import Impersonator
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=12)
    >>> mallory = Impersonator(rng=np.random.default_rng(11))
    >>> declaration = mallory.sign(0, (), params, records={})
    >>> len(declaration), declaration.message_bit
    (12, 0)

    The same key twice, because a signer and a distributor that disagree are two
    attacks rather than one:

    >>> mallory.key_for(0, params) is declaration.declared_key
    True
    >>> sorted(mallory.keys)
    [(0, 12)]

    Her draws are hers. A second Mallory on the same seed declares the same key;
    on a different seed she does not:

    >>> twin = Impersonator(rng=np.random.default_rng(11))
    >>> twin.key_for(0, params) == mallory.key_for(0, params)
    True
    >>> other = Impersonator(rng=np.random.default_rng(12))
    >>> other.key_for(0, params) == mallory.key_for(0, params)
    False
    """

    def __init__(self, *, rng: np.random.Generator) -> None:
        if not isinstance(rng, np.random.Generator):
            raise TypeError(
                f"rng must be a numpy.random.Generator, got "
                f"{type(rng).__name__}. Convention D6: an adversary owns its "
                f"randomness and is constructed from a generator of its own. "
                f"An integer seed is refused because the natural next step is "
                f"to reuse the harness seed, which would let this adversary "
                f"rebuild the session's private streams."
            )
        self._rng = rng
        self._keys: dict[tuple[int, int], PrivateKey] = {}

    def __repr__(self) -> str:
        """Return a debugging representation naming what she has drawn."""
        drawn = ", ".join(
            f"bit {bit} at L={length}" for bit, length in sorted(self._keys)
        )
        return f"Impersonator({drawn or 'nothing drawn yet'})"

    @property
    def keys(self) -> Mapping[tuple[int, int], PrivateKey]:
        """Mapping: the keys drawn so far, keyed by ``(message_bit, length)``."""
        return dict(self._keys)

    def key_for(self, message_bit: int, params: ProtocolParams) -> PrivateKey:
        """Return Mallory's key for one bit and length, drawing it if needed.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.
        params : ProtocolParams
            Supplies the length and the basis alphabet. Only
            ``params.key_length`` and ``params.bases`` are read, so passing the
            session's scored parameters and its full parameters selects two
            different cache entries, which is exactly what check rounds need.

        Returns
        -------
        PrivateKey
            The same object on every later call for the same
            ``(message_bit, key_length)``.

        Raises
        ------
        TypeError
            If ``params`` is not a :class:`ProtocolParams`.
        ValueError
            If ``message_bit`` is not ``0`` or ``1``.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.impersonation import Impersonator
        >>> from sih141.protocol.params import ProtocolParams
        >>> mallory = Impersonator(rng=np.random.default_rng(3))
        >>> key = mallory.key_for(1, ProtocolParams(key_length=9))
        >>> len(key), key.message_bit
        (9, 1)
        >>> mallory.key_for(1, ProtocolParams(key_length=9)) is key
        True
        """
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got {type(params).__name__}"
            )
        if isinstance(message_bit, bool) or message_bit not in (0, 1):
            raise ValueError(
                f"message_bit must be 0 or 1, got {message_bit!r}. Mallory "
                f"commits to one key per future message bit exactly as Alice "
                f"does."
            )
        cache_key = (int(message_bit), params.key_length)
        cached = self._keys.get(cache_key)
        if cached is None:
            cached = generate_private_key(params, int(message_bit), rng=self._rng)
            self._keys[cache_key] = cached
        return cached

    def distribute(
        self,
        key: PrivateKey,
        params: ProtocolParams,
        *,
        parties: Sequence[Party | str] = VERIFIERS,
        resource_factory: ResourceFactory | None = None,
        rng: np.random.Generator | None = None,
        check_plan: CheckRoundPlan | None = None,
        payload_map: PayloadMap | None = None,
    ) -> dict[Party, RecipientDistribution]:
        """Phase A, run honestly -- on Mallory's key instead of Alice's.

        A :class:`~sih141.protocol.session.Distributor`. Nothing about the
        channel is degraded: the states really are teleported, the check rounds
        really are executed, and a channel monitor watching this link sees an
        ideal one. Only the *identity* of the key is substituted, which is what
        makes this impersonation rather than tampering.

        Parameters
        ----------
        key : PrivateKey
            Alice's key for this bit. **Read for its message bit only**, never
            for its contents: an impersonator who copied Alice's key would not
            be impersonating her, he would be her.
        params : ProtocolParams
            The full parameter set, at the unsifted length.
        parties : sequence of Party or str, optional
            Keyword-only. Passed through.
        resource_factory : callable or None, optional
            Keyword-only. Passed through, tap and all.
        rng : numpy.random.Generator or None, optional
            Keyword-only. The session's **Alice-side** stream, used only to
            drive the teleportation it is meant to drive. Mallory's own choices
            never come from it (D6, :ref:`impersonation-d6`).
        check_plan : CheckRoundPlan or None, optional
            Keyword-only. Executed as given, and used to sift her key so that
            :meth:`sign` declares the right one.
        payload_map : callable or None, optional
            Keyword-only. Passed through.

        Returns
        -------
        dict of Party to RecipientDistribution
            Whatever
            :func:`~sih141.protocol.distribute.distribute_public_key_with_checks`
            returned for her key.

        Raises
        ------
        TypeError, ValueError
            As the honest distributor, plus :meth:`key_for`'s own checks.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.impersonation import Impersonator
        >>> from sih141.protocol.keys import generate_private_key
        >>> from sih141.protocol.params import Party, ProtocolParams
        >>> params = ProtocolParams(key_length=6)
        >>> alice = generate_private_key(params, 0, rng=np.random.default_rng(1))
        >>> mallory = Impersonator(rng=np.random.default_rng(2))
        >>> sent = mallory.distribute(
        ...     alice, params, rng=np.random.default_rng(3))
        >>> sorted(sent) == [Party.BOB, Party.CHARLIE]
        True
        >>> mallory.key_for(0, params) == alice
        False
        """
        mine = self.key_for(key.message_bit, params)
        if check_plan is not None:
            sifted = check_plan.sift_key(mine)
            self._keys[(int(key.message_bit), len(sifted))] = sifted
        return distribute_public_key_with_checks(
            mine,
            params,
            parties=parties,
            resource_factory=resource_factory,
            rng=rng,
            check_plan=check_plan,
            payload_map=payload_map,
        )

    def sign(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey] | tuple[()],
        params: ProtocolParams,
        *,
        records: Mapping[int, Mapping[Party, RecipientRecord]],
    ) -> Signature:
        """Phase B, run honestly -- on Mallory's key instead of Alice's.

        A :class:`~sih141.protocol.session.Signer`.

        Parameters
        ----------
        message_bit : int
            The bit to declare.
        keys : tuple
            Alice's committed pair. **Ignored entirely**, and that is the whole
            attack: Mallory does not hold it, does not need it, and declaring
            from it would make her Alice rather than an impersonator. Accepted
            as an empty tuple too, so the seam can be exercised standalone.
        params : ProtocolParams
            The session's *scored* parameters, which fix the declared length.
        records : mapping
            Keyword-only. **Ignored**: no impersonator in the threat model holds
            a recipient's log, and this attack does not need one. Reading it
            would move Mallory into the over-powered two-log signer of
            :ref:`sih141.protocol.session <two-log-signer>`, which is a
            different adversary.

        Returns
        -------
        Signature
            Her key for ``message_bit`` at ``params.key_length``, unbound; the
            session attaches the round identifier itself
            (:meth:`~sih141.protocol.session.QDSSession._bind_to_round`), so the
            declaration is scored on its contents and never rejected as a
            replay.

        Raises
        ------
        TypeError, ValueError
            As :meth:`key_for`.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.impersonation import Impersonator
        >>> from sih141.protocol.params import ProtocolParams
        >>> params = ProtocolParams(key_length=9)
        >>> mallory = Impersonator(rng=np.random.default_rng(4))
        >>> declaration = mallory.sign(1, (), params, records={})
        >>> declaration.message_bit, len(declaration)
        (1, 9)
        """
        del keys, records  # An impersonator holds neither. That is the model.
        return Signature(
            message_bit=int(message_bit),
            declared_key=self.key_for(message_bit, params),
        )


def impersonation_seams(
    mallory: Impersonator, scope: ImpersonationScope | str
) -> dict[str, Any]:
    """Return the :class:`~sih141.protocol.session.QDSSession` keywords for a scope.

    One place decides which seams a scope seizes, so the measurement code, the
    tests and any Phase 5 driver cannot drift apart about what "partial" means.

    Parameters
    ----------
    mallory : Impersonator
        The adversary whose bound methods go into the seams.
    scope : ImpersonationScope or str
        Which seams she holds.

    Returns
    -------
    dict
        Keyword arguments, ready to splat. Empty for
        :attr:`ImpersonationScope.NONE`.

    Raises
    ------
    TypeError
        If ``mallory`` is not an :class:`Impersonator`.
    ValueError
        If ``scope`` names no member.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.impersonation import (
    ...     ImpersonationScope, Impersonator, impersonation_seams)
    >>> mallory = Impersonator(rng=np.random.default_rng(0))
    >>> sorted(impersonation_seams(mallory, ImpersonationScope.FULL))
    ['distributor', 'signer']
    >>> sorted(impersonation_seams(mallory, "signing"))
    ['signer']
    >>> impersonation_seams(mallory, ImpersonationScope.NONE)
    {}
    """
    if not isinstance(mallory, Impersonator):
        raise TypeError(
            f"mallory must be an Impersonator, got {type(mallory).__name__}"
        )
    resolved = _as_scope(scope)
    seams: dict[str, Any] = {}
    if resolved.takes_distribution:
        seams["distributor"] = mallory.distribute
    if resolved.takes_signing:
        seams["signer"] = mallory.sign
    return seams


@dataclass(frozen=True)
class ImpersonationTrial:
    """One session, reduced to the numbers an impersonation experiment needs.

    Frozen and made of built-ins, so a list of these is a Phase 5 table already.

    A verifier that reached no verdict -- an abort on one of the four evidence
    checks -- is recorded with ``None`` counts rather than dropped, because
    "no verdict" is a distinct outcome from "rejected" and pooling them would
    inflate whichever of the two the reader cares about.

    Parameters
    ----------
    scope : ImpersonationScope
        Which seams Mallory held.
    session_seed : int
        The harness's seed for this run. Recorded so a surprising trial can be
        replayed exactly; it is never shown to the adversary (D6).
    key_length : int
        ``L``, recorded on every trial because a rate without one is
        uninterpretable -- which is the defect this module was asked to fix in
        the shipped (AUTH) figures.
    message_bit : int
        The bit signed.
    bob_matched, charlie_matched : int or None
        ``|M_R|`` per verifier; ``None`` if that verifier aborted.
    bob_mismatches, charlie_mismatches : int or None
        ``e_R`` per verifier; ``None`` if that verifier aborted.
    bob_accepted, charlie_accepted : bool or None
        The verdicts; ``None`` if that verifier aborted.
    transferable : bool
        The transcript's own verdict on the run as a whole.

    Examples
    --------
    >>> from sih141.attacks.impersonation import (
    ...     ImpersonationScope, ImpersonationTrial)
    >>> trial = ImpersonationTrial(
    ...     scope=ImpersonationScope.SIGNING, session_seed=1, key_length=48,
    ...     message_bit=0, bob_matched=16, charlie_matched=18,
    ...     bob_mismatches=8, charlie_mismatches=9,
    ...     bob_accepted=False, charlie_accepted=False, transferable=False)
    >>> trial.bob_rate, trial.accepted_by_both
    (0.5, False)
    >>> trial.reached_verdicts
    True
    """

    scope: ImpersonationScope
    session_seed: int
    key_length: int
    message_bit: int
    bob_matched: int | None
    charlie_matched: int | None
    bob_mismatches: int | None
    charlie_mismatches: int | None
    bob_accepted: bool | None
    charlie_accepted: bool | None
    transferable: bool

    @property
    def bob_rate(self) -> float | None:
        """float or None: ``r_Bob``, or ``None`` if Bob reached no verdict."""
        return _rate(self.bob_mismatches, self.bob_matched)

    @property
    def charlie_rate(self) -> float | None:
        """float or None: ``r_Charlie``, or ``None`` if he reached no verdict."""
        return _rate(self.charlie_mismatches, self.charlie_matched)

    @property
    def reached_verdicts(self) -> bool:
        """bool: True when both verifiers scored rather than aborting."""
        return self.bob_accepted is not None and self.charlie_accepted is not None

    @property
    def accepted_by_both(self) -> bool:
        """bool: True only when both verifiers accepted.

        The attacker's success criterion, and the strict one: a declaration Bob
        takes and Charlie refuses has not been transferred, and a scheme whose
        selling point is transferability must not score it as a win.
        """
        return bool(self.bob_accepted) and bool(self.charlie_accepted)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of every field.

        Returns
        -------
        dict
        """
        return {
            "scope": str(self.scope),
            "session_seed": self.session_seed,
            "key_length": self.key_length,
            "message_bit": self.message_bit,
            "bob_matched": self.bob_matched,
            "charlie_matched": self.charlie_matched,
            "bob_mismatches": self.bob_mismatches,
            "charlie_mismatches": self.charlie_mismatches,
            "bob_accepted": self.bob_accepted,
            "charlie_accepted": self.charlie_accepted,
            "transferable": self.transferable,
        }


def session_seeds(trials: int, *, first: int = FIRST_SESSION_SEED) -> tuple[int, ...]:
    """Return ``trials`` consecutive session seeds.

    A named function rather than an inline ``range`` so that every arm of an
    experiment provably uses the *same* seeds, which is what makes the control
    and the attacked arm paired rather than merely comparable.

    Parameters
    ----------
    trials : int
        How many, at least ``1``.
    first : int, optional
        Keyword-only. The first seed.

    Returns
    -------
    tuple of int

    Raises
    ------
    ValueError
        If ``trials`` is not a positive integer or ``first`` is negative.

    Examples
    --------
    >>> from sih141.attacks.impersonation import session_seeds
    >>> session_seeds(3, first=10)
    (10, 11, 12)
    """
    if isinstance(trials, bool) or not isinstance(trials, (int, np.integer)):
        raise TypeError(f"trials must be an int, got {type(trials).__name__}")
    if int(trials) < 1:
        raise ValueError(f"trials must be at least 1, got {int(trials)}")
    if isinstance(first, bool) or not isinstance(first, (int, np.integer)):
        raise TypeError(f"first must be an int, got {type(first).__name__}")
    if int(first) < 0:
        raise ValueError(f"first must be non-negative, got {int(first)}")
    return tuple(int(first) + index for index in range(int(trials)))


def run_impersonation(
    scope: ImpersonationScope | str,
    params: ProtocolParams = MEASUREMENT_PARAMS,
    *,
    session_seed: int,
    attack_rng: np.random.Generator,
    message_bit: int = 0,
) -> ImpersonationTrial:
    """Run one session under one scope and reduce it to an :class:`ImpersonationTrial`.

    The session's generator is built here, from ``session_seed``, and the
    adversary is built from ``attack_rng``. The two never meet: that separation
    is the whole of D6 and it is why this function takes a seed for one and a
    generator for the other rather than one seed for both.

    Parameters
    ----------
    scope : ImpersonationScope or str
        Which seams Mallory holds. :attr:`ImpersonationScope.NONE` builds an
        adversary and installs none of her, which is the control arm.
    params : ProtocolParams, optional
        Defaults to :data:`MEASUREMENT_PARAMS`.
    session_seed : int
        Keyword-only. The harness's seed, hers to know and never Mallory's.
    attack_rng : numpy.random.Generator
        Keyword-only. Mallory's own generator (D6). Advanced by the call, so
        passing one generator across a loop gives each trial a fresh key.
    message_bit : int, optional
        Keyword-only, ``0`` or ``1``.

    Returns
    -------
    ImpersonationTrial

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or ``attack_rng`` is not
        a generator.
    ValueError
        If ``scope`` names no member, or ``message_bit`` is not ``0``/``1``.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.impersonation import (
    ...     ImpersonationScope, run_impersonation, DEMO_MEASUREMENT_PARAMS)
    >>> trial = run_impersonation(
    ...     ImpersonationScope.DISTRIBUTION, DEMO_MEASUREMENT_PARAMS,
    ...     session_seed=7, attack_rng=np.random.default_rng(1))
    >>> trial.scope, trial.key_length, trial.accepted_by_both
    (<ImpersonationScope.DISTRIBUTION: 'distribution'>, 48, False)
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    resolved = _as_scope(scope)
    mallory = Impersonator(rng=attack_rng)
    session = QDSSession(
        params,
        rng=np.random.default_rng(int(session_seed)),
        **impersonation_seams(mallory, resolved),
    )
    transcript = session.run(int(message_bit))
    return _reduce(transcript, resolved, int(session_seed), params)


def _reduce(
    transcript: SessionTranscript,
    scope: ImpersonationScope,
    session_seed: int,
    params: ProtocolParams,
) -> ImpersonationTrial:
    """Turn one transcript into one trial row.

    Parameters
    ----------
    transcript : SessionTranscript
        The finished run.
    scope : ImpersonationScope
        The scope it was run under.
    session_seed : int
        The seed it was run at.
    params : ProtocolParams
        Read only for ``key_length``, and the *scored* length is what a rate is
        over, so a checked run reports the sifted length.

    Returns
    -------
    ImpersonationTrial
    """
    scored = params.sifted() if params.has_check_rounds else params
    bob, charlie = transcript.bob, transcript.charlie
    return ImpersonationTrial(
        scope=scope,
        session_seed=session_seed,
        key_length=scored.key_length,
        message_bit=transcript.message_bit,
        bob_matched=None if bob is None else bob.matched_count,
        charlie_matched=None if charlie is None else charlie.matched_count,
        bob_mismatches=None if bob is None else bob.mismatches,
        charlie_mismatches=None if charlie is None else charlie.mismatches,
        bob_accepted=None if bob is None else bob.accepted,
        charlie_accepted=None if charlie is None else charlie.accepted,
        transferable=transcript.transferable,
    )


@dataclass(frozen=True)
class ImpersonationMeasurement:
    """A whole experimental arm: many trials at one scope, with intervals.

    Parameters
    ----------
    scope : ImpersonationScope
    key_length : int
        ``L``, the same for every trial in the arm. Carried here as well as on
        every trial so that a summary line cannot be quoted without it.
    trials : tuple of ImpersonationTrial

    Raises
    ------
    ValueError
        If there are no trials, or if the trials disagree about scope or key
        length -- an arm that mixes scopes is not an arm.

    Examples
    --------
    >>> from sih141.attacks.impersonation import (
    ...     ImpersonationMeasurement, ImpersonationScope, ImpersonationTrial)
    >>> rows = tuple(
    ...     ImpersonationTrial(
    ...         scope=ImpersonationScope.SIGNING, session_seed=seed,
    ...         key_length=48, message_bit=0, bob_matched=16,
    ...         charlie_matched=16, bob_mismatches=8, charlie_mismatches=8,
    ...         bob_accepted=False, charlie_accepted=False, transferable=False)
    ...     for seed in range(10)
    ... )
    >>> arm = ImpersonationMeasurement(
    ...     ImpersonationScope.SIGNING, 48, rows)
    >>> arm.successes, arm.trial_count, arm.success_rate
    (0, 10, 0.0)
    >>> arm.mismatch_rate("Bob")
    0.5
    """

    scope: ImpersonationScope
    key_length: int
    trials: tuple[ImpersonationTrial, ...]

    def __post_init__(self) -> None:
        """Coerce the fields and refuse an arm that mixes scopes or lengths."""
        object.__setattr__(self, "scope", _as_scope(self.scope))
        object.__setattr__(self, "trials", tuple(self.trials))
        if not self.trials:
            raise ValueError(
                "an ImpersonationMeasurement needs at least one trial: a rate "
                "with no denominator is not a measurement."
            )
        for trial in self.trials:
            if not isinstance(trial, ImpersonationTrial):
                raise TypeError(
                    f"every trial must be an ImpersonationTrial, got "
                    f"{type(trial).__name__}"
                )
            if trial.scope is not self.scope:
                raise ValueError(
                    f"trial at session seed {trial.session_seed} has scope "
                    f"{trial.scope!s}, but this arm is {self.scope!s}. Arms are "
                    f"compared against each other, so mixing scopes inside one "
                    f"would average two different experiments into a number "
                    f"describing neither."
                )
            if trial.key_length != self.key_length:
                raise ValueError(
                    f"trial at session seed {trial.session_seed} ran at "
                    f"L = {trial.key_length}, but this arm is L = "
                    f"{self.key_length}. Every rate here is conditional on L."
                )

    @property
    def trial_count(self) -> int:
        """int: how many sessions this arm is."""
        return len(self.trials)

    @property
    def successes(self) -> int:
        """int: sessions accepted by **both** verifiers.

        The strict criterion of :attr:`ImpersonationTrial.accepted_by_both`.
        """
        return sum(1 for trial in self.trials if trial.accepted_by_both)

    @property
    def success_rate(self) -> float:
        """float: :attr:`successes` over :attr:`trial_count`."""
        return self.successes / self.trial_count

    @property
    def success_interval(self) -> Interval:
        """Interval: Wilson score interval for :attr:`success_rate`."""
        return wilson_interval(self.successes, self.trial_count)

    @property
    def aborts(self) -> int:
        """int: sessions in which some verifier reached no verdict at all."""
        return sum(1 for trial in self.trials if not trial.reached_verdicts)

    def accepted_by(self, party: Party | str) -> int:
        """Return how many sessions one verifier accepted.

        Parameters
        ----------
        party : Party or str
            ``Bob`` or ``Charlie``.

        Returns
        -------
        int
        """
        chosen = _as_verifier(party)
        return sum(
            1
            for trial in self.trials
            if (
                trial.bob_accepted
                if chosen is Party.BOB
                else trial.charlie_accepted
            )
        )

    def matched_total(self, party: Party | str) -> int:
        """Return one verifier's pooled ``sum |M_R|`` over the arm.

        Parameters
        ----------
        party : Party or str

        Returns
        -------
        int
        """
        chosen = _as_verifier(party)
        return sum(
            (trial.bob_matched if chosen is Party.BOB else trial.charlie_matched)
            or 0
            for trial in self.trials
        )

    def mismatch_total(self, party: Party | str) -> int:
        """Return one verifier's pooled ``sum e_R`` over the arm.

        Parameters
        ----------
        party : Party or str

        Returns
        -------
        int
        """
        chosen = _as_verifier(party)
        return sum(
            (
                trial.bob_mismatches
                if chosen is Party.BOB
                else trial.charlie_mismatches
            )
            or 0
            for trial in self.trials
        )

    def mismatch_rate(self, party: Party | str) -> float:
        """Return one verifier's **pooled** mismatch rate over the arm.

        Pooled over positions, ``sum e_R / sum |M_R|``, not averaged over runs.
        The two differ, and the pooled one is the estimator of the per-position
        Bernoulli parameter that :ref:`half-a-half` predicts; a mean of
        per-run rates weights a run with a small matched set as heavily as one
        with a large one and estimates something nobody asked about.

        Parameters
        ----------
        party : Party or str

        Returns
        -------
        float

        Raises
        ------
        ValueError
            If the arm scored no positions at all for that verifier.
        """
        matched = self.matched_total(party)
        if matched == 0:
            raise ValueError(
                f"no positions were scored for {_as_verifier(party)!s} in this "
                f"arm, so there is no mismatch rate to report. Every trial "
                f"aborted before a verdict; look at .aborts."
            )
        return self.mismatch_total(party) / matched

    def mismatch_interval(self, party: Party | str) -> Interval:
        """Return the Wilson interval for :meth:`mismatch_rate`.

        Parameters
        ----------
        party : Party or str

        Returns
        -------
        Interval
        """
        return wilson_interval(
            self.mismatch_total(party), self.matched_total(party)
        )

    def summary(self) -> str:
        """Return a one-line human summary naming the scope, ``L`` and the rate.

        Returns
        -------
        str
        """
        return (
            f"{self.scope!s} at L={self.key_length}: "
            f"{self.successes}/{self.trial_count} accepted by both, "
            f"r_Bob={self.mismatch_rate(Party.BOB):.4f}, "
            f"r_Charlie={self.mismatch_rate(Party.CHARLIE):.4f}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the arm's headline numbers.

        Returns
        -------
        dict
        """
        return {
            "scope": str(self.scope),
            "key_length": self.key_length,
            "trials": self.trial_count,
            "successes": self.successes,
            "success_rate": self.success_rate,
            "success_interval": self.success_interval.to_dict(),
            "aborts": self.aborts,
            "bob": {
                "accepted": self.accepted_by(Party.BOB),
                "matched_total": self.matched_total(Party.BOB),
                "mismatch_total": self.mismatch_total(Party.BOB),
                "mismatch_rate": self.mismatch_rate(Party.BOB),
                "mismatch_interval": self.mismatch_interval(Party.BOB).to_dict(),
            },
            "charlie": {
                "accepted": self.accepted_by(Party.CHARLIE),
                "matched_total": self.matched_total(Party.CHARLIE),
                "mismatch_total": self.mismatch_total(Party.CHARLIE),
                "mismatch_rate": self.mismatch_rate(Party.CHARLIE),
                "mismatch_interval": self.mismatch_interval(
                    Party.CHARLIE
                ).to_dict(),
            },
        }


def measure_impersonation(
    scope: ImpersonationScope | str,
    params: ProtocolParams = MEASUREMENT_PARAMS,
    *,
    seeds: Sequence[int] | None = None,
    trials: int = 200,
    attack_rng: np.random.Generator,
    message_bit: int = 0,
) -> ImpersonationMeasurement:
    """Run one arm of the experiment and return it with its intervals.

    Parameters
    ----------
    scope : ImpersonationScope or str
        Which seams Mallory holds.
    params : ProtocolParams, optional
        Defaults to :data:`MEASUREMENT_PARAMS`.
    seeds : sequence of int or None, optional
        Keyword-only. The session seeds, one per trial. ``None`` uses
        :func:`session_seeds`. **Pass the same sequence to every arm**: the
        control and the attacked arms are then paired, and
        :func:`matched_sets_identical` becomes checkable.
    trials : int, optional
        Keyword-only. How many seeds to generate when ``seeds`` is ``None``.
    attack_rng : numpy.random.Generator
        Keyword-only. Mallory's generator, advanced across the loop so each
        trial gets a fresh key pair.
    message_bit : int, optional
        Keyword-only.

    Returns
    -------
    ImpersonationMeasurement

    Raises
    ------
    TypeError, ValueError
        As :func:`run_impersonation`, plus :class:`ImpersonationMeasurement`'s
        own consistency checks.

    Examples
    --------
    Four trials at a length that carries no security claim -- mechanism only:

    >>> import numpy as np
    >>> from sih141.attacks.impersonation import (
    ...     DEMO_MEASUREMENT_PARAMS, ImpersonationScope, measure_impersonation)
    >>> arm = measure_impersonation(
    ...     ImpersonationScope.FULL, DEMO_MEASUREMENT_PARAMS, trials=4,
    ...     attack_rng=np.random.default_rng(0))
    >>> arm.successes, arm.trial_count, arm.mismatch_rate("Bob")
    (4, 4, 0.0)
    """
    resolved = _as_scope(scope)
    chosen = session_seeds(trials) if seeds is None else tuple(int(s) for s in seeds)
    if not chosen:
        raise ValueError("seeds must hold at least one session seed")
    rows = tuple(
        run_impersonation(
            resolved,
            params,
            session_seed=seed,
            attack_rng=attack_rng,
            message_bit=message_bit,
        )
        for seed in chosen
    )
    scored = params.sifted() if params.has_check_rounds else params
    return ImpersonationMeasurement(resolved, scored.key_length, rows)


def matched_sets_identical(
    control: ImpersonationMeasurement, attacked: ImpersonationMeasurement
) -> bool:
    """Return whether two paired arms agree on every matched count, trial by trial.

    The executable form of the claim in :ref:`impersonation-invisibles`. It is
    expected to hold for :attr:`ImpersonationScope.DISTRIBUTION` against the
    control -- Alice declares the key she always would, the recipients draw the
    same bases from the same stream, so ``{i : c_i == d_i}`` is untouched -- and
    **not** for :attr:`ImpersonationScope.SIGNING` or
    :attr:`ImpersonationScope.FULL`, where Mallory's declared bases move the
    matched set to a different subset of the same size. Both facts are worth
    having as a test rather than as a sentence.

    Parameters
    ----------
    control : ImpersonationMeasurement
        Normally the :attr:`ImpersonationScope.NONE` arm.
    attacked : ImpersonationMeasurement
        Another arm at the same seeds.

    Returns
    -------
    bool
        True when every paired trial reports the same ``|M_Bob|`` and
        ``|M_Charlie|``.

    Raises
    ------
    ValueError
        If the two arms are not paired -- different lengths, or different
        session seeds in a different order. Comparing unpaired arms would
        answer a question nobody asked.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.impersonation import (
    ...     DEMO_MEASUREMENT_PARAMS, ImpersonationScope, matched_sets_identical,
    ...     measure_impersonation, session_seeds)
    >>> seeds = session_seeds(3)
    >>> control = measure_impersonation(
    ...     ImpersonationScope.NONE, DEMO_MEASUREMENT_PARAMS, seeds=seeds,
    ...     attack_rng=np.random.default_rng(0))
    >>> swapped = measure_impersonation(
    ...     ImpersonationScope.DISTRIBUTION, DEMO_MEASUREMENT_PARAMS,
    ...     seeds=seeds, attack_rng=np.random.default_rng(0))
    >>> matched_sets_identical(control, swapped)
    True
    """
    for name, arm in (("control", control), ("attacked", attacked)):
        if not isinstance(arm, ImpersonationMeasurement):
            raise TypeError(
                f"{name} must be an ImpersonationMeasurement, got "
                f"{type(arm).__name__}"
            )
    if control.trial_count != attacked.trial_count:
        raise ValueError(
            f"the arms are not paired: {control.trial_count} control trials "
            f"against {attacked.trial_count} attacked. Run both over the same "
            f"seed sequence -- see session_seeds."
        )
    control_seeds = [trial.session_seed for trial in control.trials]
    attacked_seeds = [trial.session_seed for trial in attacked.trials]
    if control_seeds != attacked_seeds:
        raise ValueError(
            "the arms are not paired: they used different session seeds, or "
            "the same seeds in a different order. A matched-count comparison "
            "is only meaningful trial by trial."
        )
    return all(
        left.bob_matched == right.bob_matched
        and left.charlie_matched == right.charlie_matched
        for left, right in zip(control.trials, attacked.trials, strict=True)
    )


def wilson_interval(
    successes: int, trials: int, *, confidence: float = CONFIDENCE
) -> Interval:
    """Return the Wilson score interval for a binomial proportion.

    The same closed form
    :func:`sih141.protocol.checkrounds.estimate_qber` uses, re-exposed here as a
    public function over a bare count pair, so that an attack's measured rate
    ships with an interval rather than a bare number.

    Parameters
    ----------
    successes : int
        ``0 <= successes <= trials``.
    trials : int
        At least ``1``.
    confidence : float, optional
        Keyword-only, in ``(0, 1)``. Two-sided.

    Returns
    -------
    Interval
        Tagged ``"wilson"``, clipped to ``[0, 1]``.

    Raises
    ------
    TypeError
        If the counts are not integers or ``confidence`` is not a real number.
    ValueError
        If the counts are out of range or ``confidence`` is outside ``(0, 1)``.

    Notes
    -----
    Wilson rather than Wald because two of this module's four arms sit at a rate
    of exactly ``0`` or exactly ``1``, where a Wald interval collapses to a
    single point and covers nothing at all.

    Examples
    --------
    >>> from sih141.attacks.impersonation import wilson_interval
    >>> interval = wilson_interval(0, 200)
    >>> interval.low, round(interval.high, 4), interval.method
    (0.0, 0.0188, 'wilson')
    >>> perfect = wilson_interval(200, 200)
    >>> round(perfect.low, 4), perfect.high
    (0.9812, 1.0)
    >>> half = wilson_interval(6400, 12800)
    >>> round(half.low, 4), round(half.high, 4)
    (0.4913, 0.5087)
    """
    if isinstance(successes, bool) or not isinstance(
        successes, (int, np.integer)
    ):
        raise TypeError(
            f"successes must be an int, got {type(successes).__name__}"
        )
    if isinstance(trials, bool) or not isinstance(trials, (int, np.integer)):
        raise TypeError(f"trials must be an int, got {type(trials).__name__}")
    hits, total = int(successes), int(trials)
    if total < 1:
        raise ValueError(f"trials must be at least 1, got {total}")
    if not 0 <= hits <= total:
        raise ValueError(
            f"successes must satisfy 0 <= successes <= trials, got "
            f"{hits} of {total}"
        )
    if isinstance(confidence, bool) or not isinstance(
        confidence, (int, float, np.floating)
    ):
        raise TypeError(
            f"confidence must be a real number, got {type(confidence).__name__}"
        )
    level = float(confidence)
    if not 0.0 < level < 1.0:
        raise ValueError(
            f"confidence must lie strictly inside (0, 1), got {level}"
        )
    # One implementation for the suite, in sih141.attacks.statistics, which is
    # also where the exact-at-the-ends clamping is explained (:ref:`float-dust`).
    low, high = wilson_bounds(hits, total, z=_two_sided_z(level))
    return Interval(low, high, level, "wilson")


def _two_sided_z(confidence: float) -> float:
    """Return the two-sided normal quantile for ``confidence``.

    Parameters
    ----------
    confidence : float
        In ``(0, 1)``.

    Returns
    -------
    float
        ``Phi^-1(1 - (1 - confidence) / 2)``, by bisection on
        :func:`math.erf`, so no SciPy dependency is introduced for one quantile.
    """
    return two_sided_z(confidence)


# --------------------------------------------------------------------------- #
# The shipped measurement
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MeasuredRun:
    """One published row of :data:`MEASURED`, with its own arithmetic checked.

    A frozen record of a measurement that was actually run, rather than a number
    typed into prose. Every field a reader would quote is here -- including
    ``key_length``, whose absence is exactly what an auditor flagged in the
    ``(AUTH)`` figures this table replaces -- and ``__post_init__`` recomputes
    the rate from the counts, so a stale edit to one of them fails at import.

    Parameters
    ----------
    scope : ImpersonationScope
    key_length : int
        ``L``. There is no such thing as an impersonation rate without one.
    trials : int
        Sessions run.
    successes : int
        Sessions accepted by **both** verifiers.
    bob_mismatches, bob_matched : int
        Pooled ``sum e_Bob`` and ``sum |M_Bob|`` over the arm.
    charlie_mismatches, charlie_matched : int
        The same for Charlie.

    Raises
    ------
    ValueError
        If any count is out of range.

    Examples
    --------
    >>> from sih141.attacks.impersonation import MEASURED, ImpersonationScope
    >>> row = MEASURED[ImpersonationScope.FULL]
    >>> row.key_length, row.trials, row.successes
    (192, 200, 200)
    >>> row.success_rate, row.bob_rate, row.charlie_rate
    (1.0, 0.0, 0.0)
    """

    scope: ImpersonationScope
    key_length: int
    trials: int
    successes: int
    bob_mismatches: int
    bob_matched: int
    charlie_mismatches: int
    charlie_matched: int

    def __post_init__(self) -> None:
        """Coerce the scope and refuse a row whose counts cannot be real."""
        object.__setattr__(self, "scope", _as_scope(self.scope))
        if self.key_length < 1:
            raise ValueError(f"key_length must be positive, got {self.key_length}")
        if self.trials < 1:
            raise ValueError(f"trials must be at least 1, got {self.trials}")
        if not 0 <= self.successes <= self.trials:
            raise ValueError(
                f"successes must satisfy 0 <= successes <= trials, got "
                f"{self.successes} of {self.trials}"
            )
        for errors, matched, who in (
            (self.bob_mismatches, self.bob_matched, "Bob"),
            (self.charlie_mismatches, self.charlie_matched, "Charlie"),
        ):
            if matched < 1:
                raise ValueError(
                    f"{who} must have scored at least one position for a rate "
                    f"to exist, got {matched}"
                )
            if not 0 <= errors <= matched:
                raise ValueError(
                    f"{who}'s mismatches must satisfy 0 <= e <= |M|, got "
                    f"{errors} of {matched}"
                )
            if matched > self.trials * self.key_length:
                raise ValueError(
                    f"{who} cannot have scored {matched} positions in "
                    f"{self.trials} trials of length {self.key_length}"
                )

    @property
    def success_rate(self) -> float:
        """float: acceptance by both verifiers, over the arm."""
        return self.successes / self.trials

    @property
    def success_interval(self) -> Interval:
        """Interval: Wilson interval for :attr:`success_rate`."""
        return wilson_interval(self.successes, self.trials)

    @property
    def bob_rate(self) -> float:
        """float: pooled ``r_Bob = sum e / sum |M|``."""
        return self.bob_mismatches / self.bob_matched

    @property
    def charlie_rate(self) -> float:
        """float: pooled ``r_Charlie``."""
        return self.charlie_mismatches / self.charlie_matched

    def rate_for(self, party: Party | str) -> float:
        """Return the pooled mismatch rate for one verifier.

        Parameters
        ----------
        party : Party or str

        Returns
        -------
        float
        """
        return (
            self.bob_rate
            if _as_verifier(party) is Party.BOB
            else self.charlie_rate
        )

    def interval_for(self, party: Party | str) -> Interval:
        """Return the Wilson interval for one verifier's pooled rate.

        Parameters
        ----------
        party : Party or str

        Returns
        -------
        Interval
        """
        if _as_verifier(party) is Party.BOB:
            return wilson_interval(self.bob_mismatches, self.bob_matched)
        return wilson_interval(self.charlie_mismatches, self.charlie_matched)

    def summary(self) -> str:
        """Return the row as one quotable line, ``L`` included.

        Returns
        -------
        str
        """
        return (
            f"{self.scope!s} L={self.key_length} n={self.trials}: "
            f"accepted {self.successes}/{self.trials}, "
            f"r_Bob={self.bob_rate:.4f}, r_Charlie={self.charlie_rate:.4f}"
        )


def _row(
    scope: ImpersonationScope,
    trials: int,
    successes: int,
    bob: tuple[int, int],
    charlie: tuple[int, int],
) -> MeasuredRun:
    """Build one :data:`MEASURED` row at :data:`MEASUREMENT_PARAMS`.

    Parameters
    ----------
    scope : ImpersonationScope
    trials, successes : int
    bob, charlie : tuple of int
        ``(mismatches, matched)`` pooled over the arm.

    Returns
    -------
    MeasuredRun
    """
    return MeasuredRun(
        scope=scope,
        key_length=MEASUREMENT_PARAMS.key_length,
        trials=trials,
        successes=successes,
        bob_mismatches=bob[0],
        bob_matched=bob[1],
        charlie_mismatches=charlie[0],
        charlie_matched=charlie[1],
    )


#: The measurement this module was written to produce: 200 independent sessions
#: per scope at ``L = 192``, message bit ``0``, one shared seed sequence across
#: all four arms (:func:`session_seeds`), Mallory's generator seeded ``4242``
#: and never the session's. Reproduce any row with
#: ``measure_impersonation(scope, MEASUREMENT_PARAMS, trials=200,
#: attack_rng=np.random.default_rng(4242))``.
#:
#: Read the two partial rows against the ``1/2`` of :ref:`half-a-half` and the
#: ``FULL`` row against assumption (AUTH), never against the protocol.
MEASURED: Final[Mapping[ImpersonationScope, MeasuredRun]] = {
    ImpersonationScope.NONE: _row(
        ImpersonationScope.NONE, 200, 200, (0, 12774), (0, 12696)
    ),
    ImpersonationScope.FULL: _row(
        ImpersonationScope.FULL, 200, 200, (0, 12706), (0, 12798)
    ),
    ImpersonationScope.SIGNING: _row(
        ImpersonationScope.SIGNING, 200, 0, (6420, 12870), (6484, 12870)
    ),
    ImpersonationScope.DISTRIBUTION: _row(
        ImpersonationScope.DISTRIBUTION, 200, 0, (6426, 12774), (6344, 12696)
    ),
}

#: How many of the 200 paired trials behind :data:`MEASURED` had matched counts
#: identical to the control at the same session seed, per scope. The
#: ``DISTRIBUTION`` entry is the measured form of :ref:`impersonation-invisibles`
#: -- Alice declares what she always would and the recipients draw the same
#: bases, so the matched set cannot move -- and the ``SIGNING`` entry is what
#: stops that from being a vacuous claim about a comparison that always holds.
#:
#: Examples
#: --------
#: >>> from sih141.attacks.impersonation import (
#: ...     MATCHED_IDENTICAL_TRIALS, ImpersonationScope)
#: >>> MATCHED_IDENTICAL_TRIALS[ImpersonationScope.DISTRIBUTION]
#: 200
#: >>> MATCHED_IDENTICAL_TRIALS[ImpersonationScope.SIGNING]
#: 0
MATCHED_IDENTICAL_TRIALS: Final[Mapping[ImpersonationScope, int]] = {
    ImpersonationScope.NONE: 200,
    ImpersonationScope.FULL: 0,
    ImpersonationScope.SIGNING: 0,
    ImpersonationScope.DISTRIBUTION: 200,
}


def shipped_summary() -> tuple[str, ...]:
    """Return :data:`MEASURED` as four quotable lines, one per scope.

    Every headline number this module publishes passes through here, which is
    why this function exists at all: prose is what the live test mechanism
    cannot check (D5), so the table is printed by an executable example instead
    of being described by one.

    Returns
    -------
    tuple of str
        One line per scope, in the order control, full, signing, distribution.

    Examples
    --------
    >>> from sih141.attacks.impersonation import shipped_summary
    >>> for line in shipped_summary():
    ...     print(line)
    none L=192 n=200: accepted 200/200, r_Bob=0.0000, r_Charlie=0.0000
    full L=192 n=200: accepted 200/200, r_Bob=0.0000, r_Charlie=0.0000
    signing L=192 n=200: accepted 0/200, r_Bob=0.4988, r_Charlie=0.5038
    distribution L=192 n=200: accepted 0/200, r_Bob=0.5031, r_Charlie=0.4997

    The two partial arms sit on ``1/2`` -- the prediction of
    :ref:`half-a-half` -- with intervals that say so:

    >>> from sih141.attacks.impersonation import MEASURED, ImpersonationScope
    >>> row = MEASURED[ImpersonationScope.SIGNING]
    >>> interval = row.interval_for("Charlie")
    >>> f"[{interval.low:.4f}, {interval.high:.4f}]", interval.covers(0.5)
    ('[0.4952, 0.5124]', True)

    And the acceptance rates are separated as far as two rates can be, with no
    overlap left for sampling error to explain away:

    >>> whole = MEASURED[ImpersonationScope.FULL].success_interval
    >>> half = MEASURED[ImpersonationScope.SIGNING].success_interval
    >>> f"{whole.low:.4f}", f"{half.high:.4f}"
    ('0.9812', '0.0188')

    The matched counts, meanwhile, did not move at all under the distribution
    scope, and moved in every trial under the signing scope:

    >>> from sih141.attacks.impersonation import MATCHED_IDENTICAL_TRIALS
    >>> (MATCHED_IDENTICAL_TRIALS[ImpersonationScope.DISTRIBUTION],
    ...  MATCHED_IDENTICAL_TRIALS[ImpersonationScope.SIGNING])
    (200, 0)
    """
    order = (
        ImpersonationScope.NONE,
        ImpersonationScope.FULL,
        ImpersonationScope.SIGNING,
        ImpersonationScope.DISTRIBUTION,
    )
    return tuple(MEASURED[scope].summary() for scope in order)


def detector_signals() -> dict[str, dict[str, Any]]:
    """Return what a Phase 4 detector could read, and whether it moves.

    The deliverable of this module for the next phase, as data rather than as a
    paragraph. Each entry says what the statistic is, what it does under partial
    impersonation, what it does under full impersonation, and -- the load-bearing
    part -- whether it is reachable from
    :meth:`~sih141.protocol.session.QDSSession.transcript` at all.

    Returns
    -------
    dict
        Statistic name to a mapping with keys ``"honest"``, ``"partial"``,
        ``"full"``, ``"reachable"`` and ``"note"``.

    Notes
    -----
    The summary a reader should take away: **under partial impersonation the
    mismatch rate is the only signal, and under full impersonation there is no
    signal at all**. Every other transcript statistic is a function of the
    declared bases and the recipients' own uniform draws, and an impersonator
    substitutes values without touching either law.

    Examples
    --------
    >>> from sih141.attacks.impersonation import detector_signals
    >>> signals = detector_signals()
    >>> signals["mismatch_rate"]["partial"], signals["mismatch_rate"]["full"]
    ('~0.5', '0.0')
    >>> all(entry["reachable"] for entry in signals.values())
    True
    >>> sorted(
    ...     name for name, entry in signals.items()
    ...     if entry["partial"] == entry["honest"]
    ... )
    ['channel_qber', 'matched_count', 'pooled_matched_count', 'signer_identity']
    """
    return {
        "mismatch_rate": {
            "honest": "~0.0",
            "partial": "~0.5",
            "full": "0.0",
            "reachable": True,
            "note": (
                "VerificationResult.rate, per verifier, on the transcript. The "
                "only statistic that moves under partial impersonation, and it "
                "moves the whole way."
            ),
        },
        "matched_count": {
            "honest": "~L/3",
            "partial": "~L/3",
            "full": "~L/3",
            "reachable": True,
            "note": (
                "VerificationResult.matched_count. Binomial(L, 1/3) in every "
                "scope: an impersonator substitutes values, never the sampling "
                "law. Under the DISTRIBUTION scope it is identical position "
                "for position to the control at the same session seed -- see "
                "matched_sets_identical."
            ),
        },
        "pooled_matched_count": {
            "honest": "~2L/3",
            "partial": "~2L/3",
            "full": "~2L/3",
            "reachable": True,
            "note": (
                "SessionTranscript.pooled_matched_count, from Phase C'. The "
                "floors it feeds are an evidence-liveness control, not an "
                "impersonation detector, and this row is why."
            ),
        },
        "channel_qber": {
            "honest": "~0.0",
            "partial": "~0.0",
            "full": "~0.0",
            "reachable": True,
            "note": (
                "Check-round QBER, when the parameter set reserves check "
                "rounds. An impersonating distributor teleports faithfully over "
                "an ideal resource, so the channel looks perfect while the key "
                "is somebody else's: the channel monitor and the mismatch rate "
                "are measuring different things and this attack separates them."
            ),
        },
        "signer_identity": {
            "honest": "absent",
            "partial": "absent",
            "full": "absent",
            "reachable": True,
            "note": (
                "Nothing in Signature, RecipientRecord, VerificationResult or "
                "SessionTranscript names or binds a signer; the round "
                "identifier binds a declaration to a distribution, not to a "
                "person. Reachable in the sense that its absence is checkable, "
                "which is the honest reading of assumption (AUTH). This is why "
                "the FULL scope is undetectable rather than merely hard."
            ),
        },
    }


# --------------------------------------------------------------------------- #
# Isolation probes
# --------------------------------------------------------------------------- #


def signing_probe() -> Any:
    """Return a :class:`~sih141.attacks.isolation.DecisionProbe` for :meth:`Impersonator.sign`.

    Wraps :func:`sih141.attacks.isolation.signer_probe`, which replays one
    frozen honest distribution into the candidate, so the only thing that can
    move the declaration between calls is the candidate itself.

    Returns
    -------
    DecisionProbe
        ``(mallory, session_seed) -> Signature``.

    Examples
    --------
    >>> from sih141.attacks.impersonation import Impersonator, signing_probe
    >>> from sih141.attacks.isolation import assert_attack_isolated
    >>> assert_attack_isolated(Impersonator, signing_probe()).isolated
    True
    """
    from sih141.attacks.isolation import signer_probe

    inner = signer_probe()

    def probe(attack: Any, session_seed: int) -> Any:
        """Declare through the candidate's signing seam and return what it said."""
        return inner(attack.sign, session_seed)

    return probe


def distributor_probe(
    params: ProtocolParams = ProtocolParams(key_length=12),
) -> Any:
    """Return a :class:`~sih141.attacks.isolation.DecisionProbe` for :meth:`Impersonator.distribute`.

    The decision read back is **the key Mallory chose to send**, never the
    records that came out. The records are a function of the session's Alice-side
    stream by construction -- they are the teleportation the seam is supposed to
    drive -- so returning them would make check (a) fail for an entirely honest
    reason and would say nothing about the adversary. What D6 asks about this
    seam is whether the *substituted key* moves with the session's randomness,
    and that is what this returns.

    Parameters
    ----------
    params : ProtocolParams, optional
        A small parameter set; the probe runs a real distribution, so keep it
        cheap. It carries no security claim and is not meant to.

    Returns
    -------
    DecisionProbe
        ``(mallory, session_seed) -> tuple of str``, her declared key labels.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`.

    Examples
    --------
    >>> from sih141.attacks.impersonation import Impersonator, distributor_probe
    >>> from sih141.attacks.isolation import assert_attack_isolated
    >>> assert_attack_isolated(Impersonator, distributor_probe()).isolated
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )

    def probe(attack: Any, session_seed: int) -> Any:
        """Distribute once through the candidate; report the key it substituted."""
        alice = generate_private_key(params, 0, rng=np.random.default_rng(1_234))
        attack.distribute(
            alice, params, rng=np.random.default_rng(int(session_seed))
        )
        return attack.key_for(0, params).labels

    return probe
