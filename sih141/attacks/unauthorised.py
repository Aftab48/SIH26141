"""Unauthorised verification: three routes to a verdict nobody granted.

The problem statement's Objective 2 names *unauthorized verification attempts*
among the threats to detect, and until this module the package had no vocabulary
for one: :class:`~sih141.protocol.params.Party` admits Alice, Bob and Charlie and
nothing else, so a party outside the authorised recipient set is not
representable, and there was nothing to measure.

An **unauthorised verification attempt** is a party outside the round's
authorised recipient set attempting to reach a verdict on Alice's declaration.
Verification consumes exactly one resource -- a
:class:`~sih141.protocol.records.RecipientRecord` bound to a distribution round
-- so the threat decomposes by how that party obtains one, and the three routes
have three different answers.

.. code-block:: text

    route                       how he gets a record        what happens
    ---------------------------------------------------------------------------
    U1  fabricated              invents the entries         verdict is VOID
    U2  leaked                  a recipient's log, stolen   UNDETECTABLE
    U3  tapped                  measures the Phase A wire   already covered

.. _u1-void:

U1: the fabricated record, and why the finding is not "he is caught"
--------------------------------------------------------------------
The party holds no distribution data and invents ``(index, basis, eigenvalue)``
entries. :data:`~sih141.protocol.params.DEFAULT_BASES` is ``(X, Y, Z)`` so
``|B| = 3``: his fabricated basis coincides with the declared one at rate
``1/3``, and on those matched positions his fabricated eigenvalue is a fair coin
against a declaration he had no hand in, so his mismatch rate concentrates on
``1/2``. Both thresholds are noise budgets measured from zero -- ``s_a = 1/64``,
``s_v = 1/16`` -- so he rejects a genuine signature with overwhelming
probability.

That he rejects is the uninteresting half. The finding is that his verdict
carries **no information about the signature at all**: the same fabricated
record scored against a declaration Alice never made lands on the same ``1/2``,
because neither rate depends on the declaration's contents. His accept/reject
decision is a function of his own coins. Verification by him is therefore *void*
rather than merely unauthorised, and reporting his rejection as a detection would
be reporting the outcome of an experiment that was never run.
:class:`UnauthorisedMeasurement` measures both rates and
:attr:`~UnauthorisedMeasurement.verdict_independent_of_declaration` is the
comparison.

The ``1/2`` is the same arithmetic as
:class:`sih141.attacks.forgery.OutsideForger`'s, reached from the other side of
the table: she declares a key against a real log, he scores a real declaration
against an invented log, and independence between the two columns gives a fair
coin either way.

.. _u2-leak:

U2: the leaked record, and the assumption it forces into the open
------------------------------------------------------------------
The party holds a genuine recipient's log, obtained by any means outside the
protocol -- a copied file, a shared machine, a compromised backup. He then
verifies exactly as its owner would. There is nothing for a detector to read:
:func:`~sih141.protocol.verify.verify` is a pure function of the declaration, the
record and the parameters, so two calls on the same three arguments return the
same eight fields, and a transcript written by the thief is byte-identical to
one written by the owner.

**No count is published for this route, deliberately.** A count would compare
one verdict against another verdict reached from the same three objects, which
is the purity above evaluated twice rather than an observation about theft, and
it would carry the authority of a measurement while restating a premise. The
parity with :mod:`sih141.attacks.impersonation`'s ``200/200`` under (AUTH) does
not hold either: there an impersonator runs a whole distribution and signing
with a key of her own and the verifiers accept, which is an experiment that
could have come out the other way. U2 is undetectable by construction, and a
construction is argued.

What the route produces instead is an assumption, in the register of
:doc:`SECURITY.md </SECURITY>` section 2, beside **(AUTH)** and **Private
coins**, where it is now a row:

    **(RECORD SECRECY)** A recipient's log is held only by the recipient it
    names. If it fails, the holder of a copy reaches the owner's verdicts and
    no field of any transcript differs.

Like (AUTH), this is a property of the deployment and not of the counting rules,
and it is out of model by assumption rather than defended against.

.. _u3-tap:

U3: the tapped record reduces to channel manipulation
------------------------------------------------------
The party builds his own record by intercepting the teleported qubits in Phase A.
No-cloning forbids copying the travelling half, so to learn an eigenvalue he must
measure it, and measuring one half of :math:`|\\Phi^{+}\\rangle` collapses both.
That is :class:`sih141.attacks.channel.InterceptResend` exactly: same seam
(:data:`~sih141.protocol.distribute.ResourceFactory`), same physics, same damage.
The resource he leaves behind has the tensor
:func:`~sih141.attacks.channel.collapse_tensor` of the axes he draws from, whose
QBER is :data:`TAPPED_LINK_QBER` -- one third, against a check-round arm sized to
resolve ``s_a = 1/64`` to a quarter of itself.

So there is no second detector to build here, and building one would publish a
second rate for one adversary. :func:`tapped_record_reduction` states the
correspondence as data with the citations attached, anchored on the one number
the reduction turns on. It is an **argument with a measured anchor, not an
end-to-end measurement**: what is measured here is the QBER the collapsed
resource produces, computed from
:func:`~sih141.attacks.channel.qber_from_tensor`; what is argued is that a party
assembling a record off the wire has no route to that record other than the
measurement which produces it. The end-to-end detection numbers for this
adversary are :mod:`sih141.attacks.channel`'s and are not restated here.

.. _authorisation-is-self-declared:

What an authorisation check can and cannot do
----------------------------------------------
An enforcement layer that refuses verification by a party outside the authorised
set has exactly one thing to test: the identity the record declares.
:attr:`RecipientRecord.party <sih141.protocol.records.RecipientRecord.party>` is
that identity, and it is written by whoever built the record.

**A leaked record still says "Bob".** So an authorisation check refuses U1 at the
interface -- the fabricator has to name somebody, and naming a party the round
did not authorise is refused before any counting happens -- and is powerless
against U2, because the thief presents the owner's record with the owner's name
on it and passes the check the owner would pass. That is not an implementation
gap to be closed later: a log carries no field binding it to a holder, none is
derivable from the two columns, and the round identifier binds a declaration to
a *round* and never to a person.

It is also not something to report as a count. ``session.records[bit][party]``
is tagged with ``party`` or the session refuses the distribution
(:meth:`QDSSession.distribute <sih141.protocol.session.QDSSession.distribute>`),
so "the stolen record still names its owner" is an invariant enforced upstream,
and counting it over 200 trials would be 200 repetitions of a structural
identity.

Standing rules
--------------
D3
    :class:`UnauthorisedFabricator` takes its own keyword-only
    :class:`numpy.random.Generator` and draws every entry from it.
    :func:`fabricator_probe` runs both halves of
    :func:`~sih141.attacks.isolation.check_attack_isolation` over it rather than
    asserting the property, and :func:`measure_unauthorised` refuses an attack
    generator that is the stream one of its own session seeds produces. The
    harness's own draws come off a third stream (:data:`CONTROL_STREAM`), so the
    adversary's records are not downstream of how many numbers the harness
    happened to want.
D4
    Counting, one Wilson interval imported from
    :mod:`sih141.attacks.statistics`, and one closed-form QBER from
    :mod:`sih141.attacks.channel`. Nothing is fitted to anything.
D5
    The published counts live in :data:`MEASURED` and are printed by
    :func:`shipped_summary`, which is a doctest.

See Also
--------
sih141.attacks.forgery : The outside forger's ``1/2``, the same arithmetic seen
    from the declaration's side.
sih141.attacks.impersonation : The (AUTH) demonstration, which is an experiment
    where U2 is a construction, and the session seeds this module reuses.
sih141.attacks.channel : Where U3 already lives.
sih141.protocol.verify : The function all three routes are trying to reach.

Examples
--------
One fabricated record against one genuine declaration, at the scale the shipped
table was measured under. ``L = 192`` is a demonstration length and carries **no
security claim** of its own -- the acceptance probabilities of
:mod:`sih141.protocol.analysis` are exponentials in ``L`` and say nothing at 192
-- but the floors are non-degenerate there, so every run reaches a verdict and
what is exhibited is a *rate*:

>>> import numpy as np
>>> from sih141.attacks.unauthorised import MEASUREMENT_PARAMS, run_unauthorised
>>> from sih141.protocol.params import Party
>>> trials = run_unauthorised(
...     MEASUREMENT_PARAMS, session_seed=900_000, attack_rng=np.random.default_rng(7)
... )
>>> bob = trials[Party.BOB]
>>> bob.owner_accepted, bob.fabricated_accepted
(True, False)

The genuine record is what makes that non-vacuous: the same declaration, scored
against the log the round actually produced, mismatches at a rate of exactly
zero, so the ``True`` above is a control clearing the threshold rather than a
threshold loose enough to accept anything. That zero is asserted directly in
``tests/test_attack_unauthorised.py``. The fabricator's rate is the contrast,
and it is a rate rather than a refusal: he is scored, and he scores ``1/2``.

>>> bob.fabricated_rate > 0.3
True
"""

from __future__ import annotations

import dataclasses
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from sih141.attacks.channel import (
    PAULI_AXES,
    collapse_tensor,
    qber_from_tensor,
)
# Re-exported rather than rewritten: the session seeds have to be the same
# base the sibling attack tables use, or two arms that look paired are not.
from sih141.attacks.impersonation import session_seeds
from sih141.attacks.isolation import DecisionProbe, derived_from_seed, same_stream
from sih141.attacks.statistics import wilson_bounds
from sih141.protocol.keys import generate_private_key
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.records import RecipientRecord
from sih141.protocol.session import QDSSession
from sih141.protocol.signature import Signature, sign
from sih141.protocol.verify import (
    MatchedSetTooSmall,
    VerificationResult,
    verify,
)

__all__ = [
    "ATTACK_SEED",
    "CONTROL_STREAM",
    "FABRICATED_MATCHED_FRACTION",
    "FABRICATED_MISMATCH_RATE",
    "MEASURED",
    "MEASUREMENT_PARAMS",
    "TAPPED_LINK_QBER",
    "UnauthorisedFabricator",
    "UnauthorisedHolder",
    "UnauthorisedMeasurement",
    "UnauthorisedTrial",
    "fabricator_probe",
    "measure_unauthorised",
    "run_unauthorised",
    "session_seeds",
    "shipped_summary",
    "tapped_record_reduction",
    "verdict_digest",
]


FABRICATED_MATCHED_FRACTION: Final[float] = 1.0 / 3.0
"""float: Share of positions a fabricated record is scored on, ``1 / |B|``.

The fabricator's basis at a position is drawn from
:data:`~sih141.protocol.params.DEFAULT_BASES` independently of the declared one,
so the two coincide at ``1/3``. It is the same fraction an honest recipient
scores on, which is why the matched count is not a signal here: he is inventing
values, not changing the sampling law.
"""

FABRICATED_MISMATCH_RATE: Final[float] = 0.5
"""float: A fabricated record's mismatch rate among scored positions.

A fair coin. Conditioned on the basis matching, his invented eigenvalue is
independent of the declared one, so the two disagree half the time whatever the
declaration says. Equal to
:data:`sih141.attacks.forgery.OUTSIDE_FORGER_MISMATCH_RATE`, and for the same
reason read from the other end: independence between the declaration and the log
gives ``1/2`` whichever of the two the adversary supplied.
"""

TAPPED_LINK_QBER: Final[float] = 1.0 / 3.0
"""float: QBER on a link whose travelling half was measured and re-sent.

The single number the U3 reduction turns on, computed rather than quoted:
``qber_from_tensor(collapse_tensor(PAULI_AXES))``. A party assembling his own
record off the Phase A wire has to measure to learn anything, and measuring one
half of :math:`|\\Phi^{+}\\rangle` collapses the pair, so the resource he leaves
is the one :class:`sih141.attacks.channel.InterceptResend` leaves. Read against
``s_a = 1/64`` and against the check-round sample sizes of
:mod:`sih141.protocol.checkrounds`, which are chosen to resolve ``s_a`` to a
quarter of itself.
"""

MEASUREMENT_PARAMS: Final[ProtocolParams] = ProtocolParams(key_length=192)
"""The parameter set :data:`MEASURED` was produced under.

``L = 192`` is the demonstration scale this project already uses for attack
tables (:data:`sih141.attacks.impersonation.MEASUREMENT_PARAMS`): both floors are
non-degenerate (``m_min = 1``, ``M_min = 22`` against an expected 64 matched
positions per recipient), so every run reaches a verdict rather than aborting,
and a session costs under half a second. The doctests in this module run at the
same length rather than at a cheaper one, so that no example demonstrates the
mechanism under conditions the published table was not taken under.
"""

ATTACK_SEED: Final[int] = 4242
"""The attack generator's seed behind every row of :data:`MEASURED`.

Recorded because D9 asks for it: the table is reproducible from this integer, the
session seeds :func:`session_seeds` produces, and the command quoted on
:data:`MEASURED`.
"""

CONTROL_STREAM: Final[int] = 1
"""Stream label the harness folds in beside a session seed for its own draws.

:func:`run_unauthorised` needs a key of its own for the declaration nobody
distributed states for, and neither of the two generators already in the room
can supply it. The session's would make that declaration Alice's, which is the
one thing it must not be; the adversary's would put the harness and the
fabricator on consecutive draws off one stream, so the number of values the
control arm happened to want would shift every fabricated record after it. So
the harness seeds ``numpy.random.default_rng((session_seed, CONTROL_STREAM))``,
a stream keyed by the seed already recorded on every trial and disjoint from
both. D3 is unaffected in its stated direction either way -- the adversary never
sees session randomness -- but trial-by-trial provenance is easier to follow
when each of the three roles draws from its own stream.
"""


# --------------------------------------------------------------------------- #
# Small coercions and shared guards
# --------------------------------------------------------------------------- #


def _as_verifier(party: Party | str) -> Party:
    """Return ``party`` as one of the two recipients, refusing Alice.

    Parameters
    ----------
    party : Party or str

    Returns
    -------
    Party

    Raises
    ------
    ValueError
        If it names Alice, or names nobody.
    """
    try:
        resolved = Party(str(party))
    except ValueError:
        raise ValueError(
            f"unknown party {party!r}; expected Bob or Charlie. Those are the "
            f"only identities a record can carry, so an unauthorised verifier "
            f"has to claim one of them; see the module docstring on what an "
            f"authorisation check can and cannot do."
        ) from None
    if not resolved.is_verifier:
        raise ValueError(
            f"{resolved!s} keeps no record and reaches no verdict, so there is "
            f"no verification for anyone to attempt in her name."
        )
    return resolved


def _as_generator(value: Any, name: str) -> np.random.Generator:
    """Return ``value`` as a generator, refusing integer seeds (D3)."""
    if not isinstance(value, np.random.Generator):
        raise TypeError(
            f"{name} must be a numpy.random.Generator, got "
            f"{type(value).__name__}. Convention D3: an adversary owns its "
            f"randomness. An integer seed is refused because the natural next "
            f"step is to reuse the harness seed, and then every rate below is a "
            f"statement about one stream read twice."
        )
    return value


def _as_positive(value: Any, name: str) -> int:
    """Return ``value`` as a positive integer count."""
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    count = int(value)
    if count < 1:
        raise ValueError(
            f"{name} must be at least 1, got {count}. A rate with no "
            f"denominator is not a wide measurement, it is the absence of one."
        )
    return count


def _refuse_shared_stream(
    attack_rng: np.random.Generator, seeds: Sequence[int], *, where: str
) -> None:
    """Refuse an attack generator built from one of the session seeds (D3).

    The two arguments are a generator and a list of integers precisely so that a
    caller cannot pass one number and get both. Nothing stops a caller writing
    ``session_seed=7`` beside ``attack_rng=numpy.random.default_rng(7)`` though,
    and those are one stream:
    :class:`~sih141.protocol.session.QDSSession` derives Alice's stream, the
    recipients' stream and the binding stream from a single draw off its
    generator, so an adversary holding it predicts the very bases his fabricated
    record is about to be scored against, and his ``1/2`` would become something
    else entirely for a reason that has nothing to do with the protocol.

    Parameters
    ----------
    attack_rng : numpy.random.Generator
        The adversary's own generator.
    seeds : sequence of int or tuple of int
        Every stream spec the caller is about to build a generator from: a
        session seed on its own, or the tuple a derived stream is seeded with.
        Both shapes are refused, because the harness draws its control
        declaration off ``(session_seed, CONTROL_STREAM)`` and an adversary
        handed that stream reads the control rather than an independent draw.
    where : str
        The calling function's name, quoted in the message.

    Raises
    ------
    ValueError
        If ``attack_rng`` is the stream any of ``seeds`` produces.

    Notes
    -----
    :mod:`sih141.attacks.impersonation` carries the same guard for D6, with its
    own message. Two copies, against the four Wilson intervals
    :mod:`sih141.attacks.statistics` was written to collapse; if a third module
    needs this one, it belongs in :mod:`sih141.attacks.isolation` beside
    :func:`~sih141.attacks.isolation.derived_from_seed` rather than in a third
    place.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.unauthorised import _refuse_shared_stream
    >>> _refuse_shared_stream(
    ...     np.random.default_rng(4242), (900_000,), where="demo"
    ... ) is None
    True
    >>> try:
    ...     _refuse_shared_stream(
    ...         np.random.default_rng(900_000), (900_000,), where="demo"
    ...     )
    ... except ValueError as error:
    ...     print(str(error).splitlines()[0])
    demo: attack_rng is the stream session seed 900000 produces (D3).
    """
    for seed in seeds:
        # A spec is a scalar seed or the tuple form a derived stream is
        # built from. CONTROL_STREAM made the second shape reachable, and a
        # guard that only knew the first would wave it through.
        if isinstance(seed, tuple):
            shared = same_stream(attack_rng, np.random.default_rng(seed))
        else:
            shared = derived_from_seed(attack_rng, int(seed))
        if shared:
            raise ValueError(
                f"{where}: attack_rng is the stream session seed {seed} "
                f"produces (D3).\n"
                f"They are different objects and the same randomness. A "
                f"fabricator drawing from the session's stream can reproduce "
                f"the bases his record will be scored against, and the measured "
                f"mismatch rate would then describe a collusion rather than an "
                f"outsider.\n"
                f"Seed the adversary from something unrelated to the session "
                f"seeds; see ATTACK_SEED and session_seeds."
            )


def verdict_digest(result: VerificationResult) -> str:
    """Return a canonical text form of one verdict, for byte comparison.

    Used where two verdicts have to be compared as whole transcripts rather than
    as accept/reject bits, which is a stronger statement than ``==`` on two
    :class:`~sih141.protocol.verify.VerificationResult` objects: a dataclass
    comparison would still pass if a field were added and left out of the
    comparison. Serialising every field to sorted JSON and comparing the strings
    says what "no field differs" says.

    It reports equality; it does not establish that any two verdicts *should*
    differ. Two calls on the same three arguments agree because
    :func:`~sih141.protocol.verify.verify` is pure, and nothing here publishes
    that agreement as a measurement (:ref:`u2-leak`).

    Parameters
    ----------
    result : VerificationResult
        A verdict.

    Returns
    -------
    str
        Sorted-key JSON of every field.

    Raises
    ------
    TypeError
        If ``result`` is not a :class:`~sih141.protocol.verify.VerificationResult`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.unauthorised import verdict_digest
    >>> from sih141.protocol.distribute import distribute_to_recipient
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.verify import verify
    >>> params = ProtocolParams(key_length=24)
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
    >>> record = distribute_to_recipient(
    ...     key, params, party=Party.BOB, rng=np.random.default_rng(2)
    ... )
    >>> digest = verdict_digest(verify(sign(0, key, params), record, params))
    >>> print(digest)  # doctest: +NORMALIZE_WHITESPACE
    {"accepted": true, "key_length": 24, "matched_count": 7, "message_bit": 0,
     "mismatches": 0, "party": "Bob", "rate": 0.0, "threshold": 0.015625}
    """
    if not isinstance(result, VerificationResult):
        raise TypeError(
            f"result must be a VerificationResult, got {type(result).__name__}"
        )
    return json.dumps(
        dataclasses.asdict(result), sort_keys=True, separators=(", ", ": ")
    )


# --------------------------------------------------------------------------- #
# U1: the party who holds nothing
# --------------------------------------------------------------------------- #


class UnauthorisedFabricator:
    """The party who holds no distribution data and invents a record (D3).

    He was not a recipient of the round. There is no log in his hands, so he
    writes one: an ``(index, basis, eigenvalue)`` triple per position, the basis
    drawn uniformly from the parameter set's alphabet and the eigenvalue from a
    fair coin, all from **his own** generator. Then he calls
    :func:`~sih141.protocol.verify.verify` with it, exactly as a recipient would.

    Nothing in the protocol refuses him at that call. A record names its holder
    and nothing else (:class:`~sih141.protocol.records.RecipientRecord`), so the
    only identity in play is the one he writes into the ``party`` field, and the
    verifier's own floors are the only things his invented log has to clear. It
    clears them: his matched count is
    :data:`FABRICATED_MATCHED_FRACTION` of ``L`` in expectation, which is what an
    honest recipient's is.

    What he cannot do is learn anything. See :ref:`u1-void`.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, and his (D3). Every basis and every eigenvalue comes from
        it and from nothing else. Integer seeds are refused.
    claims : Party or str, optional
        Keyword-only. The identity he writes into the record, defaulting to
        :attr:`~sih141.protocol.params.Party.BOB`. He has to name one of the two
        recipients because those are the only values the type admits, and that
        constraint is the finding rather than a limitation of the model: see
        :ref:`authorisation-is-self-declared`.

    Attributes
    ----------
    claims : Party
        The self-declared identity.
    records_built : int
        How many logs he has written. One per verification attempt.

    Raises
    ------
    TypeError
        If ``rng`` is not a :class:`numpy.random.Generator`.
    ValueError
        If ``claims`` names Alice or names nobody.

    See Also
    --------
    UnauthorisedHolder : The party who holds a real one, and is invisible.
    sih141.attacks.forgery.OutsideForger : The same ``1/2``, from the
        declaration's side.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.unauthorised import UnauthorisedFabricator
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=12)
    >>> outsider = UnauthorisedFabricator(rng=np.random.default_rng(5))
    >>> record = outsider.fabricate(params, message_bit=0)
    >>> len(record), record.party, outsider.records_built
    (12, <Party.BOB: 'Bob'>, 1)

    His record is a function of his own generator and of nothing else, so two
    fabricators on one seed write one log:

    >>> twin = UnauthorisedFabricator(rng=np.random.default_rng(5))
    >>> twin.fabricate(params, message_bit=0) == record
    True

    And the identity on it is the one he chose, not one the round granted:

    >>> impostor = UnauthorisedFabricator(
    ...     rng=np.random.default_rng(6), claims=Party.CHARLIE
    ... )
    >>> impostor.fabricate(params, message_bit=0).party
    <Party.CHARLIE: 'Charlie'>
    """

    def __init__(
        self,
        *,
        rng: np.random.Generator,
        claims: Party | str = Party.BOB,
    ) -> None:
        self._rng = _as_generator(rng, "rng")
        self.claims = _as_verifier(claims)
        self.records_built = 0

    def __repr__(self) -> str:
        """Return a debugging representation naming the claim and the traffic."""
        return (
            f"UnauthorisedFabricator(claims={self.claims!s}, "
            f"records_built={self.records_built})"
        )

    def fabricate(
        self,
        params: ProtocolParams,
        *,
        message_bit: int,
        session_id: str | None = None,
    ) -> RecipientRecord:
        """Write one invented log at the scored length.

        Parameters
        ----------
        params : ProtocolParams
            The *scored* parameter set. Supplies the length and the basis
            alphabet; a record of any other length is refused by
            :func:`~sih141.protocol.verify.verify` as a wiring error rather than
            scored, so the fabricator has to get this right to attempt anything
            at all.
        message_bit : int
            Keyword-only, ``0`` or ``1``. Which distribution run he claims his
            log came from.
        session_id : str or None, optional
            Keyword-only. The round identifier he stamps the log with, or
            ``None`` for a log naming no round. The identifier is announced in
            Phase A in the clear and is carried on the declaration he is
            scoring, so copying it costs him nothing; leaving it off makes the
            round check inert instead, since that check compares a declaration
            against the *record's* stamp and an unstamped record has none to
            disagree with. Neither route is an authorisation check, which is the
            point: the binding names a round, not a person.

        Returns
        -------
        RecipientRecord
            Flagged ``symmetrised=True``, because a log claiming to have come
            through Phase A' is what a recipient of this round would hold and
            the flag is provenance he is free to write.

        Raises
        ------
        TypeError
            If ``params`` is not a
            :class:`~sih141.protocol.params.ProtocolParams`.
        ValueError
            If ``message_bit`` is not ``0`` or ``1``.

        Notes
        -----
        Draws exactly two arrays of length ``L`` from his own generator, so the
        number of draws depends on the key length and never on the session.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.attacks.unauthorised import UnauthorisedFabricator
        >>> from sih141.protocol.params import ProtocolParams
        >>> record = UnauthorisedFabricator(
        ...     rng=np.random.default_rng(2)
        ... ).fabricate(ProtocolParams(key_length=9), message_bit=1)
        >>> record.message_bit, record.symmetrised, record.session_id is None
        (1, True, True)
        """
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got {type(params).__name__}. "
                f"Pass the scored set: a record at the unsifted length is "
                f"refused by verify() before any counting happens."
            )
        if isinstance(message_bit, bool) or message_bit not in (0, 1):
            raise ValueError(
                f"message_bit must be 0 or 1, got {message_bit!r}. The two "
                f"distribution runs share no key, so a log has to claim one of "
                f"them."
            )
        bases = params.bases
        length = params.key_length
        chosen = self._rng.integers(len(bases), size=length)
        coins = self._rng.integers(2, size=length)
        self.records_built += 1
        return RecipientRecord.from_measurements(
            self.claims,
            int(message_bit),
            [bases[int(index)] for index in chosen],
            [1 if int(coin) == 0 else -1 for coin in coins],
            symmetrised=True,
            session_id=session_id,
        )


def fabricator_probe(
    params: ProtocolParams = ProtocolParams(key_length=12),
) -> DecisionProbe:
    """Return a :class:`~sih141.attacks.isolation.DecisionProbe` for U1.

    The decision read back is the fabricated log itself, reduced to comparable
    labels. That is the right quantity for D3: the fabricator observes nothing
    of the session at all -- he is handed no view, no records and no declaration
    -- so there is nothing to hold fixed across probe calls, and check (a) asks
    the whole of what there is to ask, namely whether his log moves when the
    session seed does.

    Parameters
    ----------
    params : ProtocolParams, optional
        A small parameter set; the probe runs no session, so this only sets how
        many entries are compared.

    Returns
    -------
    DecisionProbe
        ``(attack, session_seed) -> tuple of tuple``, his fabricated entries.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.

    Examples
    --------
    >>> from sih141.attacks.unauthorised import (
    ...     UnauthorisedFabricator, fabricator_probe)
    >>> from sih141.attacks.isolation import assert_attack_isolated
    >>> assert_attack_isolated(
    ...     UnauthorisedFabricator, fabricator_probe()
    ... ).isolated
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )

    def probe(attack: Any, session_seed: int) -> Any:
        """Fabricate once; report the log. The seed is deliberately unused."""
        del session_seed  # An isolated fabricator cannot see it. That is check (a).
        record = attack.fabricate(params, message_bit=0)
        return tuple(
            (entry.basis.value, entry.eigenvalue) for entry in record.entries
        )

    return probe


# --------------------------------------------------------------------------- #
# U2: the party who holds somebody else's
# --------------------------------------------------------------------------- #


class UnauthorisedHolder:
    """The party who holds a genuine recipient's log, obtained outside the protocol.

    He is not the owner. He runs no distribution, measures nothing and draws no
    coins; he opens a file. What he then does is call
    :func:`~sih141.protocol.verify.verify` with the owner's three arguments, and
    :func:`~sih141.protocol.verify.verify` is pure, so he gets the owner's answer
    -- every field of it.

    There is no adversary model to state here beyond the theft itself, and no
    randomness for D3 to be about: this class draws nothing, which is why it
    takes no generator. It exists to give the assumption **(RECORD SECRECY)** of
    :ref:`u2-leak` something executable to point at, and so that :attr:`claims`
    names, in one place, the thing an authorisation check would have to test and
    the reason it cannot help (:ref:`authorisation-is-self-declared`). It
    produces no rate: what it does is not an experiment with an outcome, and the
    module publishes no count for this route.

    Parameters
    ----------
    record : RecipientRecord
        The stolen log, verbatim. Frozen, so possession is the whole of the
        theft: there is nothing for him to alter that would leave it a record of
        the round he wants a verdict on.

    Attributes
    ----------
    record : RecipientRecord
    verifications : int
        How many verdicts he has reached.

    Raises
    ------
    TypeError
        If ``record`` is not a
        :class:`~sih141.protocol.records.RecipientRecord`.

    See Also
    --------
    UnauthorisedFabricator : The party who holds nothing, and learns nothing.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.unauthorised import UnauthorisedHolder, verdict_digest
    >>> from sih141.protocol.distribute import distribute_to_recipient
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.verify import verify
    >>> params = ProtocolParams(key_length=24)
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
    >>> owned = distribute_to_recipient(
    ...     key, params, party=Party.BOB, rng=np.random.default_rng(2)
    ... )
    >>> declaration = sign(0, key, params)
    >>> thief = UnauthorisedHolder(owned)
    >>> stolen = thief.verify(declaration, params)
    >>> stolen.accepted, stolen.matched_count, stolen.mismatches
    (True, 7, 0)

    He reaches the owner's verdict, field for field, and the reason is visible
    in the line above rather than in a table: it is the owner's three arguments
    through a pure function, so this holds by construction and is not evidence
    of anything beyond itself.

    >>> verdict_digest(stolen) == verdict_digest(verify(declaration, owned, params))
    True

    The record he presents still names its owner, which is the whole of what an
    authorisation check has to work with:

    >>> thief.claims
    <Party.BOB: 'Bob'>
    """

    def __init__(self, record: RecipientRecord) -> None:
        if not isinstance(record, RecipientRecord):
            raise TypeError(
                f"record must be a RecipientRecord, got {type(record).__name__}."
                f" This adversary is defined by holding a genuine one; a "
                f"fabricated log is UnauthorisedFabricator's route and has a "
                f"different answer."
            )
        self.record = record
        self.verifications = 0

    def __repr__(self) -> str:
        """Return a debugging representation naming whose log he holds."""
        return (
            f"UnauthorisedHolder(claims={self.claims!s}, "
            f"verifications={self.verifications})"
        )

    @property
    def claims(self) -> Party:
        """Party: The identity on the stolen record, which is its owner's.

        Not a choice he makes. A leaked record still says "Bob", so this is
        simultaneously what an authorisation check reads and the reason it
        refuses nobody here.
        """
        return self.record.party

    def verify(
        self, signature: Signature, params: ProtocolParams
    ) -> VerificationResult:
        """Reach the owner's verdict on ``signature``.

        Parameters
        ----------
        signature : Signature
            The declaration to score.
        params : ProtocolParams
            The scored parameter set.

        Returns
        -------
        VerificationResult
            Field for field what the owner would have got.

        Raises
        ------
        TypeError, ValueError, MatchedSetTooSmall
            Exactly as :func:`~sih141.protocol.verify.verify`, since that is
            what this is.
        """
        self.verifications += 1
        return verify(signature, self.record, params)


# --------------------------------------------------------------------------- #
# One trial
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class UnauthorisedTrial:
    """One session, one verifier, reduced to the numbers the three routes need.

    Frozen and made of built-ins and one
    :class:`~sih141.protocol.params.Party`, so a list of these is a Phase 5 table
    already.

    Three verdicts are reached against one declaration from one session, which
    is what makes them comparable: the owner's on his own log (the control), the
    fabricator's on his invented log, and the fabricator's on a declaration
    Alice never made. The last of those is not a
    forgery experiment -- :mod:`sih141.attacks.forgery` owns that -- it is the
    instrument that turns "his verdict is uncorrelated with the truth" into a
    comparison of two rates.

    The thief of U2 reaches a fourth verdict and no field here records it. His
    verdict comes from the control's own three arguments through a pure
    function, so a column for it would be the control column copied
    (:ref:`u2-leak`).

    Parameters
    ----------
    party : Party
        The recipient whose identity is in play.
    session_seed : int
        The harness's seed for this run, recorded so a surprising trial replays
        exactly. Never shown to the adversary (D3).
    key_length : int
        ``L``. A rate without one is uninterpretable.
    message_bit : int
        The bit signed.
    owner_accepted : bool
        Whether the genuine record accepted the genuine declaration. The control
        that stops every other row being vacuous.
    fabricated_accepted : bool or None
        The fabricator's verdict, or ``None`` if his invented log did not clear
        the matched-count floor and he reached none.
    fabricated_matched, fabricated_mismatches : int or None
        ``|M|`` and ``e`` for the fabricated record against the genuine
        declaration. ``None`` together with
        :attr:`fabricated_accepted` on a trial that reached no verdict.
    forged_matched, forged_mismatches : int or None
        The same fabricated record against a declaration nobody distributed
        states for, and ``None`` on the same terms: that arm can be refused the
        floor independently of the other, so it has its own refusal to report.

    Examples
    --------
    >>> from sih141.attacks.unauthorised import UnauthorisedTrial
    >>> from sih141.protocol.params import Party
    >>> trial = UnauthorisedTrial(
    ...     party=Party.BOB, session_seed=900_000, key_length=192,
    ...     message_bit=0, owner_accepted=True, fabricated_accepted=False,
    ...     fabricated_matched=64, fabricated_mismatches=32,
    ...     forged_matched=66, forged_mismatches=33,
    ... )
    >>> trial.fabricated_rate, trial.reached_verdict, trial.forged_scored
    (0.5, True, True)
    """

    party: Party
    session_seed: int
    key_length: int
    message_bit: int
    owner_accepted: bool
    fabricated_accepted: bool | None
    fabricated_matched: int | None
    fabricated_mismatches: int | None
    forged_matched: int | None
    forged_mismatches: int | None

    @property
    def reached_verdict(self) -> bool:
        """bool: Whether the fabricated log cleared the floor and was scored."""
        return self.fabricated_accepted is not None

    @property
    def forged_scored(self) -> bool:
        """bool: The same, for the arm scored against the forged declaration.

        Read separately because it can differ: the two arms are the same log
        against two declarations, and the matched-count floor is a property of
        the pair. A refusal on either is a trial that contributed nothing to
        that arm's counts, and :attr:`UnauthorisedMeasurement.forged_no_verdict`
        is where it has to be recorded, or the denominator of
        :attr:`UnauthorisedMeasurement.forged_rate` shrinks with nobody
        counting.
        """
        return self.forged_matched is not None

    @property
    def fabricated_rate(self) -> float | None:
        """float or None: ``e / |M|`` on the genuine declaration."""
        if not self.fabricated_matched:
            return None
        return (self.fabricated_mismatches or 0) / self.fabricated_matched

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of every field.

        Returns
        -------
        dict
        """
        row = dataclasses.asdict(self)
        row["party"] = str(self.party)
        return row


# --------------------------------------------------------------------------- #
# One arm
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class UnauthorisedMeasurement:
    """A whole arm: many trials against one verifier, pooled, with intervals.

    Counts rather than rates are the fields, so two arms re-pool by addition and
    nobody can average two rates over different denominators. Every rate here is
    a property.

    Parameters
    ----------
    party : Party
        The recipient whose identity is in play.
    key_length : int
        ``L``, the same for every trial in the arm.
    trials : int
        Sessions run. Positive.
    owner_accepted : int
        Trials on which the genuine record accepted the genuine declaration.
        Expected to equal :attr:`trials`; a shortfall means the control failed
        and every other number in the arm is describing a broken run.
    fabricated_accepted : int
        Trials on which the fabricated record accepted the genuine declaration.
    fabricated_no_verdict : int
        Trials on which the fabricated log failed the matched-count floor. In the
        denominator of :attr:`fabricated_acceptance_rate` and not in its
        numerator: a refusal to score is not an acceptance.
    fabricated_matched, fabricated_mismatches : int
        Pooled over the trials that reached a verdict.
    forged_no_verdict : int
        The same refusal count for the forged-declaration arm, which is not
        implied by :attr:`fabricated_no_verdict`: the floor is a property of a
        declaration and a record together, so one arm can be refused where the
        other was scored. Without it the denominator of :attr:`forged_rate`
        could shrink with no field saying so, and
        :attr:`verdict_independent_of_declaration` would compare an interval
        over a sample size nobody recorded.
    forged_matched, forged_mismatches : int
        Pooled the same way, against a declaration nobody distributed states
        for.

    Raises
    ------
    TypeError
        If ``party`` is not a party, or a count is not an integer.
    ValueError
        If ``party`` is Alice, if ``trials`` is not positive, or if any count is
        out of range.

    Examples
    --------
    >>> from sih141.attacks.unauthorised import MEASURED
    >>> from sih141.protocol.params import Party
    >>> arm = MEASURED[Party.BOB]
    >>> arm.trials, arm.owner_accepted, arm.fabricated_accepted
    (200, 200, 0)
    >>> arm.verdict_independent_of_declaration
    True
    """

    party: Party
    key_length: int
    trials: int
    owner_accepted: int
    fabricated_accepted: int
    fabricated_no_verdict: int
    fabricated_matched: int
    fabricated_mismatches: int
    forged_no_verdict: int
    forged_matched: int
    forged_mismatches: int

    def __post_init__(self) -> None:
        """Coerce the party and refuse an arm whose counts cannot be real."""
        object.__setattr__(self, "party", _as_verifier(self.party))
        object.__setattr__(
            self, "key_length", _as_positive(self.key_length, "key_length")
        )
        object.__setattr__(self, "trials", _as_positive(self.trials, "trials"))
        for name in (
            "owner_accepted",
            "fabricated_accepted",
            "fabricated_no_verdict",
            "forged_no_verdict",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(
                value, (int, np.integer)
            ):
                raise TypeError(
                    f"{name} must be an int, got {type(value).__name__}"
                )
            if not 0 <= int(value) <= self.trials:
                raise ValueError(
                    f"{name} must satisfy 0 <= n <= trials, got {int(value)} of "
                    f"{self.trials}"
                )
            object.__setattr__(self, name, int(value))
        for errors, matched, label in (
            (self.fabricated_mismatches, self.fabricated_matched, "fabricated"),
            (self.forged_mismatches, self.forged_matched, "forged"),
        ):
            if isinstance(matched, bool) or not isinstance(
                matched, (int, np.integer)
            ):
                raise TypeError(f"{label}_matched must be an int")
            if isinstance(errors, bool) or not isinstance(
                errors, (int, np.integer)
            ):
                raise TypeError(f"{label}_mismatches must be an int")
            if not 0 <= int(errors) <= int(matched):
                raise ValueError(
                    f"{label}_mismatches must satisfy 0 <= e <= |M|, got "
                    f"{int(errors)} of {int(matched)}; mismatches are counted "
                    f"within the matched set only."
                )
            if int(matched) > self.trials * self.key_length:
                raise ValueError(
                    f"{label}_matched is {int(matched)}, which is more "
                    f"positions than {self.trials} trials of length "
                    f"{self.key_length} contain."
                )

    # -- derived rates ------------------------------------------------------ #

    @property
    def scored_trials(self) -> int:
        """int: Trials on which the fabricated log was scored."""
        return self.trials - self.fabricated_no_verdict

    @property
    def fabricated_acceptance_rate(self) -> float:
        """float: How often the fabricated record accepted, over all trials."""
        return self.fabricated_accepted / self.trials

    @property
    def fabricated_acceptance_interval(self) -> tuple[float, float]:
        """tuple of float: 95% Wilson interval for the acceptance rate."""
        return wilson_bounds(self.fabricated_accepted, self.trials)

    @property
    def matched_fraction(self) -> float:
        """float: ``|M| / L`` for the fabricated record.

        Expected to sit on :data:`FABRICATED_MATCHED_FRACTION`. It is not a
        detection signal and is reported so that a reader can see it is not: an
        invented log matches as often as an honest one, because inventing values
        does not change the sampling law over bases.
        """
        positions = self.scored_trials * self.key_length
        if positions == 0:
            return float("nan")
        return self.fabricated_matched / positions

    @property
    def fabricated_rate(self) -> float:
        """float: Mismatch rate on the genuine declaration. ``nan`` if unscored."""
        if self.fabricated_matched == 0:
            return float("nan")
        return self.fabricated_mismatches / self.fabricated_matched

    @property
    def fabricated_interval(self) -> tuple[float, float]:
        """tuple of float: 95% Wilson interval for :attr:`fabricated_rate`."""
        if self.fabricated_matched == 0:
            return (0.0, 1.0)
        return wilson_bounds(self.fabricated_mismatches, self.fabricated_matched)

    @property
    def forged_rate(self) -> float:
        """float: The same record's rate on a declaration Alice never made."""
        if self.forged_matched == 0:
            return float("nan")
        return self.forged_mismatches / self.forged_matched

    @property
    def forged_interval(self) -> tuple[float, float]:
        """tuple of float: 95% Wilson interval for :attr:`forged_rate`."""
        if self.forged_matched == 0:
            return (0.0, 1.0)
        return wilson_bounds(self.forged_mismatches, self.forged_matched)

    @property
    def verdict_independent_of_declaration(self) -> bool:
        """bool: Whether the two mismatch intervals overlap.

        The executable form of :ref:`u1-void`. If the rate a fabricated record
        assigns a genuine declaration and the rate it assigns a declaration
        nobody distributed states for are not separated by the data, then his
        verdict is not a reading of the signature and calling it a verification
        is a category error.

        Overlap of two 95% intervals is a deliberately weak test in the
        direction that matters: it fails loudly if the two rates ever part
        company, and it is not evidence of exact equality.

        ``False`` when either arm scored nothing, and ``False`` when either arm
        refused a single trial the floor. The second is the stricter of the two
        and is deliberate: a refusal removes positions from one denominator and
        not the other, so the arms stop being the same experiment run twice, and
        an overlap read across them would be an overlap of two intervals about
        different samples. Comparing the two rates is the whole of what this
        property is for, so it declines rather than compares.
        """
        if self.fabricated_no_verdict or self.forged_no_verdict:
            return False
        if self.fabricated_matched == 0 or self.forged_matched == 0:
            return False
        low, high = self.fabricated_interval
        other_low, other_high = self.forged_interval
        return low <= other_high and other_low <= high

    def summary(self) -> str:
        """Return the arm as one quotable line, ``L`` and ``n`` included.

        Returns
        -------
        str

        Examples
        --------
        >>> from sih141.attacks.unauthorised import MEASURED
        >>> from sih141.protocol.params import Party
        >>> print(MEASURED[Party.CHARLIE].summary())
        Charlie L=192 n=200: owner 200/200, fabricated 0/200 accepted at r=0.5043 (forged r=0.5042)
        """
        return (
            f"{self.party!s} L={self.key_length} n={self.trials}: "
            f"owner {self.owner_accepted}/{self.trials}, "
            f"fabricated {self.fabricated_accepted}/{self.trials} accepted at "
            f"r={self.fabricated_rate:.4f} (forged r={self.forged_rate:.4f})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the arm's headline numbers.

        Returns
        -------
        dict
        """
        row = dataclasses.asdict(self)
        row["party"] = str(self.party)
        row["matched_fraction"] = self.matched_fraction
        row["fabricated_rate"] = self.fabricated_rate
        row["fabricated_interval"] = list(self.fabricated_interval)
        row["forged_rate"] = self.forged_rate
        row["forged_interval"] = list(self.forged_interval)
        row["verdict_independent_of_declaration"] = (
            self.verdict_independent_of_declaration
        )
        return row


# --------------------------------------------------------------------------- #
# The experiment
# --------------------------------------------------------------------------- #


def run_unauthorised(
    params: ProtocolParams = MEASUREMENT_PARAMS,
    *,
    session_seed: int,
    attack_rng: np.random.Generator,
    message_bit: int = 0,
) -> dict[Party, UnauthorisedTrial]:
    """Run one honest session and attempt verification on it three ways.

    The session is honest throughout: Alice distributes, Alice declares, and
    every number here is about who is allowed to *score* that declaration rather
    than about who produced it. One session serves both verifiers, so the two
    rows returned are paired and share a declaration.

    The forged declaration the third arm is scored against is the harness's,
    built from the round opening the harness already holds so that it names the
    same round and the comparison isolates the declaration's contents. Three
    roles draw here and each has its own stream: the session draws from
    ``session_seed``, the fabricator from ``attack_rng`` and nothing else (D3),
    and the harness's key for that forged declaration from
    ``default_rng((session_seed, CONTROL_STREAM))``. The fabricator never
    receives the opening and never sees any of the other two streams.

    Parameters
    ----------
    params : ProtocolParams, optional
        Defaults to :data:`MEASUREMENT_PARAMS`.
    session_seed : int
        Keyword-only. The harness's seed, and never the adversary's (D3).
    attack_rng : numpy.random.Generator
        Keyword-only. The fabricator's own generator, advanced by the call so
        that a loop gives each trial a fresh invented log.
    message_bit : int, optional
        Keyword-only, ``0`` or ``1``.

    Returns
    -------
    dict of Party to UnauthorisedTrial
        One row per verifier, keyed by
        :data:`~sih141.protocol.params.VERIFIERS`.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or ``attack_rng`` is
        not a generator.
    ValueError
        If ``message_bit`` is not ``0``/``1``, or ``attack_rng`` is the stream
        ``session_seed`` produces (D3).

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.unauthorised import MEASUREMENT_PARAMS, run_unauthorised
    >>> from sih141.protocol.params import Party
    >>> rows = run_unauthorised(
    ...     MEASUREMENT_PARAMS, session_seed=900_001,
    ...     attack_rng=np.random.default_rng(4242),
    ... )
    >>> sorted(rows) == [Party.BOB, Party.CHARLIE]
    True
    >>> rows[Party.CHARLIE].owner_accepted
    True
    >>> rows[Party.CHARLIE].fabricated_accepted
    False
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    _as_generator(attack_rng, "attack_rng")
    if isinstance(message_bit, bool) or message_bit not in (0, 1):
        raise ValueError(f"message_bit must be 0 or 1, got {message_bit!r}")
    _refuse_shared_stream(
        attack_rng,
        (int(session_seed), (int(session_seed), CONTROL_STREAM)),
        where="run_unauthorised",
    )

    bit = int(message_bit)
    session = QDSSession(params, rng=np.random.default_rng(int(session_seed)))
    session.distribute()
    declaration = session.sign(bit)
    scored = session.scored_params
    # The harness's own opening and the harness's own stream, so the forged
    # declaration names the round the fabricated record was stamped with and
    # costs the adversary's generator no draws. Nothing here reaches him.
    forged = sign(
        bit,
        generate_private_key(
            scored,
            bit,
            rng=np.random.default_rng((int(session_seed), CONTROL_STREAM)),
        ),
        scored,
        session_opening=session.opening_for(bit),
    )

    rows: dict[Party, UnauthorisedTrial] = {}
    for party in VERIFIERS:
        owned = session.records[bit][party]
        control = verify(declaration, owned, scored)

        outsider = UnauthorisedFabricator(rng=attack_rng, claims=party)
        invented = outsider.fabricate(
            scored, message_bit=bit, session_id=declaration.session_id
        )
        genuine_arm = _score(declaration, invented, scored)
        forged_arm = _score(forged, invented, scored)

        rows[party] = UnauthorisedTrial(
            party=party,
            session_seed=int(session_seed),
            key_length=scored.key_length,
            message_bit=bit,
            owner_accepted=control.accepted,
            fabricated_accepted=genuine_arm[0],
            fabricated_matched=genuine_arm[1],
            fabricated_mismatches=genuine_arm[2],
            forged_matched=forged_arm[1],
            forged_mismatches=forged_arm[2],
        )
    return rows


def _score(
    declaration: Signature, record: RecipientRecord, params: ProtocolParams
) -> tuple[bool | None, int | None, int | None]:
    """Score one declaration against one record, reporting a refusal as ``None``.

    A fabricated log can fail the matched-count floor at a small ``L``, and
    :func:`~sih141.protocol.verify.verify` raises rather than returning in that
    case. A refusal to score is not a rejection and must not be counted as one
    (:class:`~sih141.protocol.verify.VerificationAbort`), so it arrives here as
    three ``None`` values and lands in ``fabricated_no_verdict``.

    Parameters
    ----------
    declaration : Signature
    record : RecipientRecord
    params : ProtocolParams

    Returns
    -------
    tuple
        ``(accepted, matched_count, mismatches)``, or ``(None, None, None)``.
    """
    try:
        result = verify(declaration, record, params)
    except MatchedSetTooSmall:
        return (None, None, None)
    return (result.accepted, result.matched_count, result.mismatches)


def measure_unauthorised(
    params: ProtocolParams = MEASUREMENT_PARAMS,
    *,
    seeds: Sequence[int] | None = None,
    trials: int = 200,
    attack_rng: np.random.Generator,
    message_bit: int = 0,
) -> dict[Party, UnauthorisedMeasurement]:
    """Run the whole experiment and return one pooled arm per verifier.

    Parameters
    ----------
    params : ProtocolParams, optional
        Defaults to :data:`MEASUREMENT_PARAMS`.
    seeds : sequence of int or None, optional
        Keyword-only. The session seeds, one per trial. ``None`` uses
        :func:`session_seeds`.
    trials : int, optional
        Keyword-only. How many seeds to generate when ``seeds`` is ``None``.
    attack_rng : numpy.random.Generator
        Keyword-only. The fabricator's generator, advanced across the loop.
    message_bit : int, optional
        Keyword-only.

    Returns
    -------
    dict of Party to UnauthorisedMeasurement

    Raises
    ------
    TypeError, ValueError
        As :func:`run_unauthorised`. The D3 stream guard runs over the whole
        seed list before the first session, so a collision at seed 137 is
        reported before any of the 200 runs is spent.

    Examples
    --------
    Four trials, which is enough to see the two ends of the range and nothing
    like enough to quote a rate from:

    >>> import numpy as np
    >>> from sih141.attacks.unauthorised import MEASUREMENT_PARAMS, measure_unauthorised
    >>> from sih141.protocol.params import Party
    >>> arms = measure_unauthorised(
    ...     MEASUREMENT_PARAMS, trials=4, attack_rng=np.random.default_rng(4242)
    ... )
    >>> bob = arms[Party.BOB]
    >>> bob.owner_accepted, bob.fabricated_accepted
    (4, 0)
    >>> bob.fabricated_no_verdict, bob.forged_no_verdict
    (0, 0)
    """
    if not isinstance(attack_rng, np.random.Generator):
        raise TypeError(
            f"attack_rng must be a numpy.random.Generator, got "
            f"{type(attack_rng).__name__} (D3)"
        )
    chosen = (
        session_seeds(trials)
        if seeds is None
        else tuple(int(seed) for seed in seeds)
    )
    if not chosen:
        raise ValueError("seeds must hold at least one session seed")
    _refuse_shared_stream(attack_rng, chosen, where="measure_unauthorised")

    rows: dict[Party, list[UnauthorisedTrial]] = {
        party: [] for party in VERIFIERS
    }
    for seed in chosen:
        for party, trial in run_unauthorised(
            params,
            session_seed=seed,
            attack_rng=attack_rng,
            message_bit=message_bit,
        ).items():
            rows[party].append(trial)
    return {party: _pool(party, trials) for party, trials in rows.items()}


def _pool(
    party: Party, trials: Sequence[UnauthorisedTrial]
) -> UnauthorisedMeasurement:
    """Add up one verifier's trials into an arm.

    Parameters
    ----------
    party : Party
    trials : sequence of UnauthorisedTrial
        All at one key length; the first one's is used and the rest are checked
        against it.

    Returns
    -------
    UnauthorisedMeasurement

    Raises
    ------
    ValueError
        If the sequence is empty or the trials disagree about the key length.
        Every rate here is conditional on ``L``, so an arm that mixes lengths is
        not an arm.
    """
    if not trials:
        raise ValueError(
            "an UnauthorisedMeasurement needs at least one trial: a rate with "
            "no denominator is not a measurement."
        )
    length = trials[0].key_length
    for trial in trials:
        if trial.key_length != length:
            raise ValueError(
                f"trial at session seed {trial.session_seed} ran at "
                f"L = {trial.key_length}, but this arm is L = {length}."
            )
    return UnauthorisedMeasurement(
        party=party,
        key_length=length,
        trials=len(trials),
        owner_accepted=sum(1 for row in trials if row.owner_accepted),
        fabricated_accepted=sum(
            1 for row in trials if row.fabricated_accepted
        ),
        fabricated_no_verdict=sum(
            1 for row in trials if not row.reached_verdict
        ),
        fabricated_matched=sum((row.fabricated_matched or 0) for row in trials),
        fabricated_mismatches=sum(
            (row.fabricated_mismatches or 0) for row in trials
        ),
        forged_no_verdict=sum(1 for row in trials if not row.forged_scored),
        forged_matched=sum((row.forged_matched or 0) for row in trials),
        forged_mismatches=sum((row.forged_mismatches or 0) for row in trials),
    )


# --------------------------------------------------------------------------- #
# The shipped measurement
# --------------------------------------------------------------------------- #


#: The measurement this module was written to produce: 200 independent honest
#: sessions at ``L = 192``, message bit ``0``, session seeds from
#: :func:`session_seeds`, the fabricator's generator seeded :data:`ATTACK_SEED`
#: and never the session's, and the harness's control declaration on the
#: stream :data:`CONTROL_STREAM` names. Both verifiers are scored against the
#: same declaration in each session, so the two rows are paired.
#:
#: Reproduce either row with (D9)::
#:
#:     python -c "
#:     import numpy as np
#:     from sih141.attacks.unauthorised import (
#:         ATTACK_SEED, MEASUREMENT_PARAMS, measure_unauthorised)
#:     arms = measure_unauthorised(
#:         MEASUREMENT_PARAMS, trials=200,
#:         attack_rng=np.random.default_rng(ATTACK_SEED))
#:     print(*(arm.summary() for arm in arms.values()), sep=chr(10))"
MEASURED: Final[Mapping[Party, UnauthorisedMeasurement]] = {
    Party.BOB: UnauthorisedMeasurement(
        party=Party.BOB,
        key_length=192,
        trials=200,
        owner_accepted=200,
        fabricated_accepted=0,
        fabricated_no_verdict=0,
        fabricated_matched=12883,
        fabricated_mismatches=6434,
        forged_no_verdict=0,
        forged_matched=12864,
        forged_mismatches=6499,
    ),
    Party.CHARLIE: UnauthorisedMeasurement(
        party=Party.CHARLIE,
        key_length=192,
        trials=200,
        owner_accepted=200,
        fabricated_accepted=0,
        fabricated_no_verdict=0,
        fabricated_matched=12774,
        fabricated_mismatches=6442,
        forged_no_verdict=0,
        forged_matched=12649,
        forged_mismatches=6378,
    ),
}


def shipped_summary() -> tuple[str, ...]:
    """Return :data:`MEASURED` as two quotable lines, one per verifier.

    Every headline number this module publishes passes through here. Prose is
    what the test mechanism cannot check (D5), so the table is printed by an
    executable example rather than described by one.

    Returns
    -------
    tuple of str
        Bob's line, then Charlie's.

    Examples
    --------
    >>> from sih141.attacks.unauthorised import shipped_summary
    >>> for line in shipped_summary():
    ...     print(line)
    Bob L=192 n=200: owner 200/200, fabricated 0/200 accepted at r=0.4994 (forged r=0.5052)
    Charlie L=192 n=200: owner 200/200, fabricated 0/200 accepted at r=0.5043 (forged r=0.5042)

    The two U1 rates are separated by nothing, which is the finding: the
    fabricator scores a genuine declaration and a declaration nobody distributed
    states for at the same rate, so his verdict is not a reading of either.

    >>> from sih141.attacks.unauthorised import MEASURED
    >>> from sih141.protocol.params import Party
    >>> arm = MEASURED[Party.BOB]
    >>> low, high = arm.fabricated_interval
    >>> f"[{low:.4f}, {high:.4f}]", arm.verdict_independent_of_declaration
    ('[0.4908, 0.5081]', True)

    And the matched fraction says why that is not a detection: an invented log
    is scored on as many positions as an honest one.

    >>> f"{arm.matched_fraction:.4f}"
    '0.3355'

    Only U1 appears here. U2 publishes no count, because the thief's verdict is
    the owner's three arguments through a pure function and a table of that
    would be a table of :func:`~sih141.protocol.verify.verify`'s determinism
    (:ref:`u2-leak`); U3's numbers are :mod:`sih141.attacks.channel`'s and are
    not restated (:func:`tapped_record_reduction`).
    """
    return tuple(MEASURED[party].summary() for party in VERIFIERS)


def tapped_record_reduction() -> dict[str, Any]:
    """Return the U3 argument as data, with its citations and its one number.

    U3 is not measured end to end here and this function is where that is said
    rather than implied. A party assembling a record from the Phase A wire has to
    measure the travelling half to learn an eigenvalue, no-cloning leaves him no
    other route, and measuring it is
    :class:`sih141.attacks.channel.InterceptResend`. So the detection numbers for
    him already exist, in :mod:`sih141.attacks.channel` and in the check-round
    threshold family of :mod:`sih141.protocol.checkrounds`, and a second detector
    here would publish a second rate for one adversary.

    Returns
    -------
    dict
        Keys ``"claim"``, ``"mechanism"``, ``"reduces_to"``, ``"detected_by"``,
        ``"measured"``, ``"argued"`` and ``"qber"``. The ``"qber"`` entry is
        computed on the spot from
        :func:`~sih141.attacks.channel.collapse_tensor` and
        :func:`~sih141.attacks.channel.qber_from_tensor` rather than quoted, so
        a change to either moves it here too.

    Examples
    --------
    >>> from sih141.attacks.unauthorised import tapped_record_reduction
    >>> reduction = tapped_record_reduction()
    >>> reduction["reduces_to"]
    'sih141.attacks.channel.InterceptResend'
    >>> round(reduction["qber"], 6)
    0.333333

    What is measured is the QBER the collapsed resource produces. What is
    argued is the step before it, and the entry says so in its own words:

    >>> import textwrap
    >>> print(textwrap.fill(reduction["argued"], 70))
    No-cloning leaves no route to an eigenvalue except measuring for it,
    so a party building a record off the wire is an intercept-resend
    adversary. That step is an argument, not a measurement.
    """
    return {
        "claim": (
            "A party who taps Phase A to build his own record is already "
            "covered by the channel threshold family."
        ),
        "mechanism": (
            "Measuring one half of a Bell pair collapses both, so an "
            "eigenvalue learned off the wire is an eigenvalue destroyed on it."
        ),
        "reduces_to": "sih141.attacks.channel.InterceptResend",
        "detected_by": (
            "check-round QBER and CHSH, sih141.protocol.checkrounds, sized to "
            "resolve s_a = 1/64 to a quarter of itself"
        ),
        "measured": (
            "qber_from_tensor(collapse_tensor(PAULI_AXES)), the QBER the "
            "collapsed resource leaves on the tapped link"
        ),
        "argued": (
            "No-cloning leaves no route to an eigenvalue except measuring for "
            "it, so a party building a record off the wire is an "
            "intercept-resend adversary. That step is an argument, not a "
            "measurement."
        ),
        "qber": qber_from_tensor(collapse_tensor(PAULI_AXES)),
    }


def _self_check() -> None:
    """Run the arithmetic this module claims, cheaply, and raise on a surprise.

    One runnable check for the whole file, so ``python -m
    sih141.attacks.unauthorised`` says whether the mechanism still holds without
    paying for the 200-trial table.
    """
    arms = measure_unauthorised(
        MEASUREMENT_PARAMS,
        trials=8,
        attack_rng=np.random.default_rng(ATTACK_SEED),
    )
    for party, arm in arms.items():
        assert arm.owner_accepted == arm.trials, party
        assert arm.fabricated_accepted == 0, party
        assert arm.fabricated_no_verdict == 0, party
        assert arm.forged_no_verdict == 0, party
        assert math.isclose(
            arm.fabricated_rate, FABRICATED_MISMATCH_RATE, abs_tol=0.12
        ), party
        assert math.isclose(
            arm.matched_fraction, FABRICATED_MATCHED_FRACTION, abs_tol=0.06
        ), party
    assert math.isclose(tapped_record_reduction()["qber"], TAPPED_LINK_QBER)
    print(*shipped_summary(), sep="\n")


if __name__ == "__main__":  # pragma: no cover
    _self_check()
