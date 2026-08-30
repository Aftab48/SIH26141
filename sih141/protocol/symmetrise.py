"""Phase A': the recipients privately re-assign their copies of the public key.

This module is the step that makes non-repudiation *true* rather than merely
asserted, and it is the one piece of the protocol that neither Alice nor the
channel takes part in.

Why the protocol does not work without it
-----------------------------------------
Alice distributes to Bob and to Charlie in two independent runs. She prepares
each eigenstate twice from its classical label and consumes fresh entanglement
each time (:mod:`sih141.protocol.distribute`), so **nothing in the physics ties
the two deliveries together**. A dishonest Alice exploits that directly:

.. code-block:: text

    at each of a chosen fraction f of positions:
        send Bob     |basis_i, eigenvalue_i>      (the state she will declare)
        send Charlie |basis_i, -eigenvalue_i>     (its orthogonal partner)

Bob's matched positions then all agree with the declaration, ``r_B = 0``, and he
accepts; Charlie's matched positions disagree on the attacked fraction,
``r_C ~ f``, and he rejects for ``f > s_v``. That is the repudiation event, and
it happens with probability ``1`` at every key length. Measured through the
package's own seams before this module existed: ``L = 192`` gave
``r_B = 0.0000`` accepted and ``r_C = 0.4032`` rejected, 40 times out of 40 over
independent seeds -- against a quoted repudiation bound of ``7e-10``.

No amount of key length fixes it, because the failure is not statistical. The
old bound assumed "conditioned on the declaration, Bob's and Charlie's records
are i.i.d.", and an asymmetric Alice simply is not in that family. The
measurement-based QDS literature (Dunjko-Wallden-Andersson 2014; Amiri et al.
2016) buys the assumption rather than assuming it, by having the recipients
**secretly exchange a random half of their key elements** after distribution.
This module is that step.

What it does
------------
For each position ``i`` independently, Bob and Charlie toss a fair coin over
their private authenticated channel and, if it comes up heads, swap their two
records for that position:

.. code-block:: text

    coin_i = 0:   Bob keeps his own entry i,      Charlie keeps his own
    coin_i = 1:   Bob takes Charlie's entry i,    Charlie takes Bob's

Each verifier still ends up with exactly one record per position, so nothing
downstream changes shape: :class:`~sih141.protocol.records.RecipientRecord`
keeps its ``0 .. L-1`` index invariant and
:func:`sih141.protocol.verify.verify` is untouched. Half of each verifier's
final evidence was measured by the *other* verifier, and Alice does not know
which half.

Why that is enough
------------------
Fix the two recipients' raw records -- whatever Alice sent, however asymmetric,
adversarial or entangled her preparation was. The coins are the only randomness
left, and they are hers to neither see nor influence. Let ``s = (s_a + s_v)/2``
and define, per position, the coin-dependent contribution to
``W = e_B - s * m_B``. Then:

* ``e_B + e_C`` and ``m_B + m_C = M`` are *coin-independent constants*: the
  coins only decide who scores which of the two records.
* Hence ``E[W] = (E - s M) / 2`` where ``E = e_B + e_C``, and repudiation --
  ``r_B <= s_a`` and ``r_C > s_v`` -- forces ``W`` at least ``(s_v - s_a) M / 4``
  *below* its mean.
* ``W`` is a sum of ``L`` independent two-point variables whose ranges are zero
  except on positions where at least one of the two records is matched, of which
  there are at most ``M``. Hoeffding gives ``exp(-M (s_v - s_a)**2 / 8)``.

The bound is conditional on the records **and on the declaration**, so it holds
for every Alice strategy: there is no adversary model left to be wrong about.
That is :func:`sih141.protocol.analysis.repudiation_bound`, which takes the
observed ``M = m_B + m_C`` as a mandatory argument, and it is the statement this
exchange earns.

**The averaged form is a weaker claim and it is easy to quote by mistake.**
Averaging ``exp(-M gap^2/8)`` over ``M ~ Binomial(2L, 1/|B|)`` is exact by the
binomial generating function and gives the far more quotable ``6.9e-10`` at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` -- but ``Binomial(2L, 1/|B|)`` is
the law of the matched count only while **the declared bases are independent of
the recipients' logged bases**. Alice does not control the basis draws; she does
not have to, she only has to *see* them, and
:class:`~sih141.protocol.session.QDSSession` hands the ``Signer`` seam both raw
logs. A signer that reads them pins ``M = 13`` at every ``L`` and repudiates with
probability ``1/2``. So the average is
:func:`sih141.protocol.analysis.averaged_repudiation_bound`, it carries a
mandatory ``signer_sees_recipient_bases`` argument to make the hypothesis
impossible to omit, and it must never be published as unconditional. The
unconditional figure the shipped code is entitled to is
:func:`sih141.protocol.verify.enforced_repudiation_bound` (``1.4139e-09``),
which rests on matched-count floors rather than on independence -- but on
**three rules jointly**, and an earlier version of this paragraph credited one
of them alone with ``1.9e-9``. That attribution is the exact claim
:mod:`sih141.protocol.analysis` section 4b-iii disproves. The per-verifier floor
``m_R >= 36555`` bounds only the branch in which Charlie reaches a verdict of
*reject*; on its own it leaves open a third outcome it creates itself -- Charlie
holding a matched set that is non-empty but below **his own** floor, so he
returns no verdict -- and a log-reading Alice reaches that outcome on one fair
coin, with probability tending to ``1/2`` at every key length (closed form ``0.432`` at
``L = 360`` and ``0.466`` at ``L = 600``; measured ``78/200``, ``85/200`` and
``87/200`` across runs -- see :ref:`split-coin-provenance`). What closes it is the
pooled floor ``m_B + m_C >= 74190`` (:mod:`sih141.protocol.tally`), which
strictly exceeds
``2 * 36555`` and so refuses the aimed-at total outright, together with the
joint consequence that a verifier below his own floor takes the other down with
him (:attr:`sih141.protocol.verify.AbortReason.COUNTERPART_BELOW_FLOOR`), which
deletes the third outcome from the outcome space. Per-verifier floor **and**
pooled floor **and** joint consequence; drop any one and the guarantee is gone
rather than merely smaller. See :mod:`sih141.protocol.analysis` sections 4b-iii
and 4b-iv, and ``docs/PHASE2.md`` section 6b.

What it costs
-------------
A recipient forger now knows half of the other verifier's evidence exactly: at
every swapped position he supplied the entry himself. Declaring it truthfully
there is matched with probability ``1`` and mismatches with probability ``0``,
so his overall rate drops from ``(1 - 1/|B|)/2 = 1/3`` to

.. code-block:: text

    forger_floor = (|B| - 1) / (2 |B| (|B| + 1))  =  1/12   for |B| = 3

(:attr:`sih141.protocol.params.ProtocolParams.forger_floor`). ``s_v`` has to sit
below that instead of below ``1/3``, the usable ``s_v - s_a`` gap shrinks with
it, and the key length needed for a given repudiation bound grows accordingly --
from ``6912`` to ``115200`` at the shipped defaults. That is the honest price of
a guarantee that holds against an adversary rather than against a model of one.

The Phase 3 seam
----------------
:func:`no_symmetrisation` is a drop-in replacement that returns the raw records
unchanged, wired through :class:`~sih141.protocol.session.QDSSession`'s
``symmetriser`` argument. It exists so Phase 3 can *demonstrate* the attack
above rather than take this docstring's word for it, and so the two runs differ
in exactly one callable. It is not a tuning knob: a run made with it has no
non-repudiation, and the records it returns are flagged unsymmetrised, so
:func:`sih141.protocol.verify.verify_all` refuses them unless the caller says
otherwise in as many words.

The numbers above, as executable claims
--------------------------------------
Prose numbers are unverifiable by construction; this project runs
``pytest --doctest-modules`` over ``sih141``, so the figures this docstring
leans on are written as tests and a stale one fails the suite instead of waiting
for an auditor.

>>> import math
>>> from sih141.protocol.analysis import (
...     averaged_repudiation_bound, repudiation_bound)
>>> from sih141.protocol.params import (
...     DEFAULT_PARAMS, UNSYMMETRISED_FORGER_RATE_THREE_BASIS)
>>> from sih141.protocol.verify import (
...     enforced_repudiation_bound,
...     minimum_matched_count,
...     minimum_pooled_matched_count,
... )

What symmetrisation costs: the forger floor falls from ``(1 - 1/|B|)/2 = 1/3``
to ``1/12`` -- a factor of four -- and the key length rises from ``6912`` to
``115200``.

>>> UNSYMMETRISED_FORGER_RATE_THREE_BASIS == 1 / 3
True
>>> DEFAULT_PARAMS.forger_floor == 1 / 12
True
>>> UNSYMMETRISED_FORGER_RATE_THREE_BASIS / DEFAULT_PARAMS.forger_floor
4.0
>>> DEFAULT_PARAMS.key_length
115200

What it earns, and what it does not. The averaged form needs (IND), which the
shipped ``Signer`` seam gives away; a signer who reads the logs pins ``M = 13``,
where the *conditional* bound correctly reports no protection at all.

>>> averaged = averaged_repudiation_bound(
...     DEFAULT_PARAMS, signer_sees_recipient_bases=False)
>>> f"{averaged:.1e}"
'6.9e-10'
>>> f"{repudiation_bound(DEFAULT_PARAMS, matched_records=13):.4f}"
'0.9964'

The unconditional figure, and the weaker number the per-verifier floor alone
supports -- kept executable so the two are never confused again:

>>> m_min = minimum_matched_count(DEFAULT_PARAMS)
>>> M_min = minimum_pooled_matched_count(DEFAULT_PARAMS)
>>> m_min, M_min, M_min > 2 * m_min
(36555, 74190, True)
>>> f"{enforced_repudiation_bound(DEFAULT_PARAMS):.4e}"
'1.4139e-09'
>>> f"{math.exp(-2 * m_min * DEFAULT_PARAMS.gap ** 2 / 8):.4e}"
'1.9022e-09'

Notes
-----
Authentication (AUTH)
    This module makes Bob's and Charlie's evidence exchangeable, which is what
    non-repudiation needs. It does **not** bind either delivery to Alice: the
    coins are tossed over the recipients' own authenticated channel, and the
    records they swap carry no signer identity. An adversary who owns both the
    distribution seam and the signing seam is symmetrised exactly like an honest
    Alice and accepted by both verifiers. See assumption (AUTH) in
    :mod:`sih141.protocol.analysis` section 0b.
Determinism (D3)
    One keyword-only ``rng``, resolved through
    :func:`sih141.core.rng.resolve_rng`. Exactly one variate is drawn per
    symmetrisation call: a single ``L``-long array of coins, so the number of
    generator calls does not depend on ``L`` and a clean run and an attacked run
    stay comparable position by position.
Whose randomness this is
    The coins belong to Bob and Charlie jointly. In simulation they come from
    the session's generator like everything else, but no seam is offered that
    would let a signer or a distributor read or set them -- that is deliberate,
    and it is why ``symmetriser`` takes the records and an ``rng`` rather than
    an explicit coin sequence.
Canonical state type (D1), qubit ordering (D2)
    No state is touched; this phase is entirely classical bookkeeping over
    already-measured records.
No machine learning (D4)
    ``L`` fair coins and a swap.

See Also
--------
sih141.protocol.distribute.distribute_public_key : Produces the raw pair.
sih141.protocol.verify.verify_all : Refuses a raw pair by default.
sih141.protocol.analysis.repudiation_bound : The bound this step earns.

References
----------
.. [1] V. Dunjko, P. Wallden and E. Andersson, "Quantum Digital Signatures
       without Quantum Memory", Phys. Rev. Lett. 112, 040502 (2014).
.. [2] R. Amiri, P. Wallden, A. Kent and E. Andersson, "Secure Quantum
       Signatures Using Insecure Quantum Channels", Phys. Rev. A 93, 032325
       (2016).

Examples
--------
>>> import numpy as np
>>> from sih141.protocol.distribute import distribute_public_key
>>> from sih141.protocol.keys import generate_private_key
>>> from sih141.protocol.params import Party, ProtocolParams
>>> from sih141.protocol.symmetrise import symmetrise_records
>>> params = ProtocolParams(key_length=12)
>>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
>>> raw = distribute_public_key(key, params, rng=np.random.default_rng(2))
>>> swapped = symmetrise_records(raw, rng=np.random.default_rng(3))
>>> swapped[Party.BOB].symmetrised
True
>>> sorted(swapped[Party.BOB].bases + swapped[Party.CHARLIE].bases) == sorted(
...     raw[Party.BOB].bases + raw[Party.CHARLIE].bases
... )
True
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

import numpy as np

from sih141.core.rng import resolve_rng
from sih141.protocol.params import VERIFIERS, Party, _as_party
from sih141.protocol.records import RecipientRecord

__all__ = [
    "Symmetriser",
    "symmetrise_records",
    "no_symmetrisation",
]


class Symmetriser(Protocol):
    """Callable that runs Phase A' on one message bit's pair of raw records.

    :func:`symmetrise_records` is the honest implementation and the default;
    :func:`no_symmetrisation` is the Phase 3 replacement that skips the step so
    that the attack it defends against can be demonstrated. A replacement must
    return one record per party it was given, each of the same length and
    message bit as the input.
    """

    def __call__(
        self,
        records: Mapping[Party | str, RecipientRecord],
        *,
        rng: np.random.Generator | None = None,
    ) -> dict[Party, RecipientRecord]:
        """Return the recipients' post-exchange records, keyed by party."""
        ...


def _checked_pair(
    records: Mapping[Party | str, RecipientRecord],
) -> tuple[RecipientRecord, RecipientRecord]:
    """Validate the mapping and return ``(Bob's record, Charlie's record)``.

    Parameters
    ----------
    records : mapping of Party to RecipientRecord
        Exactly what :func:`sih141.protocol.distribute.distribute_public_key`
        returns: one raw log per verifier.

    Returns
    -------
    tuple of RecipientRecord
        Bob's log then Charlie's, in :data:`~sih141.protocol.params.VERIFIERS`
        order regardless of the mapping's own order.

    Raises
    ------
    TypeError
        If ``records`` is not a mapping, or a value is not a
        :class:`~sih141.protocol.records.RecipientRecord`.
    ValueError
        If either verifier is missing, if a record is filed under the wrong
        party, if the two logs differ in length or message bit, or if either is
        already symmetrised.
    """
    if not isinstance(records, Mapping):
        raise TypeError(
            f"records must be a mapping of Party to RecipientRecord, got "
            f"{type(records).__name__}; distribute_public_key returns exactly "
            f"that."
        )
    resolved: dict[Party, RecipientRecord] = {}
    for party, record in records.items():
        key = _as_party(party)
        if not isinstance(record, RecipientRecord):
            raise TypeError(
                f"records[{key.value!r}] must be a RecipientRecord, got "
                f"{type(record).__name__}"
            )
        if record.party is not key:
            raise ValueError(
                f"records is keyed by {key.value!r} but the record stored "
                f"there belongs to {record.party.value!r}. The exchange moves "
                f"entries between two named verifiers, so a mislabelled key "
                f"would hand each of them the wrong half."
            )
        resolved[key] = record

    missing = [party.value for party in VERIFIERS if party not in resolved]
    if missing:
        raise ValueError(
            f"symmetrisation needs both verifiers' records, missing "
            f"{missing}. The step *is* an exchange between Bob and Charlie: "
            f"with one recipient there is nothing to exchange, and with one "
            f"recipient the protocol has no transferability and no "
            f"non-repudiation to protect in the first place."
        )
    extra = sorted(set(resolved) - set(VERIFIERS))
    if extra:
        raise ValueError(
            f"symmetrisation takes exactly the two verifiers' records, got "
            f"extra entries for {[party.value for party in extra]}. The "
            f"exchange is defined pairwise."
        )

    bob, charlie = resolved[Party.BOB], resolved[Party.CHARLIE]
    if bob.message_bit != charlie.message_bit:
        raise ValueError(
            f"the two records are from different distribution runs: Bob's is "
            f"for message bit {bob.message_bit} and Charlie's for bit "
            f"{charlie.message_bit}. Only the two copies of the *same* key "
            f"position may be exchanged; swapping across bits would hand a "
            f"verifier evidence about a key he will never be shown."
        )
    if len(bob) != len(charlie):
        raise ValueError(
            f"the two records have different lengths, {len(bob)} and "
            f"{len(charlie)}. The exchange is positional -- entry i of one log "
            f"trades places with entry i of the other -- so the two logs must "
            f"cover the same key positions."
        )
    for record in (bob, charlie):
        if record.symmetrised:
            raise ValueError(
                f"{record.party.value}'s record has already been symmetrised. "
                f"A second exchange is not harmless: it re-randomises an "
                f"assignment Alice has already been committed against, and "
                f"the bound conditions on one round of coins. Symmetrise the "
                f"raw records from distribution exactly once."
            )
    return bob, charlie


def symmetrise_records(
    records: Mapping[Party | str, RecipientRecord],
    *,
    rng: np.random.Generator | None = None,
) -> dict[Party, RecipientRecord]:
    """Privately re-assign the two recipients' copies of every key position.

    Phase A'. For each position an independent fair coin decides whether Bob and
    Charlie swap their records for it; the coins are drawn from ``rng`` and are
    never revealed. Each verifier keeps exactly one record per position, so the
    logs that come out have the same shape as the ones that went in and every
    downstream module is unchanged.

    Parameters
    ----------
    records : mapping of Party to RecipientRecord
        The raw pair from
        :func:`sih141.protocol.distribute.distribute_public_key`: one log per
        verifier, same length, same message bit, neither already symmetrised.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Resolved through
        :func:`sih141.core.rng.resolve_rng`. One ``L``-long array of coins is
        drawn per call.

    Returns
    -------
    dict of Party to RecipientRecord
        The post-exchange logs, keyed by party in
        :data:`~sih141.protocol.params.VERIFIERS` order, each flagged
        :attr:`~sih141.protocol.records.RecipientRecord.symmetrised`.

    Raises
    ------
    TypeError
        If ``records`` is not a mapping of parties to records, or ``rng`` is
        neither ``None`` nor a :class:`numpy.random.Generator`.
    ValueError
        If a verifier is missing, a record is filed under the wrong party, the
        two logs disagree in length or message bit, or either has already been
        symmetrised.

    See Also
    --------
    no_symmetrisation : The Phase 3 replacement that skips the step.
    sih141.protocol.analysis.repudiation_bound : The guarantee this earns.

    Notes
    -----
    Conservation, which is what makes the Hoeffding argument work: the multiset
    of entries is preserved exactly. Every record that went in comes out, at the
    same index, held by one verifier or the other. So ``e_B + e_C`` and
    ``m_B + m_C`` are the same numbers before and after, and the coins decide
    only their split.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.symmetrise import symmetrise_records
    >>> raw = {
    ...     Party.BOB: RecipientRecord.from_measurements(
    ...         "Bob", 0, ["X", "X"], [1, 1]
    ...     ),
    ...     Party.CHARLIE: RecipientRecord.from_measurements(
    ...         "Charlie", 0, ["Z", "Z"], [-1, -1]
    ...     ),
    ... }
    >>> swapped = symmetrise_records(raw, rng=np.random.default_rng(1))
    >>> [b.value for b in swapped[Party.BOB].bases]      # position 1 swapped
    ['X', 'Z']
    >>> [b.value for b in swapped[Party.CHARLIE].bases]
    ['Z', 'X']
    """
    bob, charlie = _checked_pair(records)
    generator = resolve_rng(rng)
    length = len(bob)

    # One draw for the whole exchange, so the generator advances by the same
    # amount whatever L is doing elsewhere in the run.
    coins = generator.integers(0, 2, size=length).astype(bool)

    bob_entries = [
        charlie.entries[index] if swap else bob.entries[index]
        for index, swap in enumerate(coins)
    ]
    charlie_entries = [
        bob.entries[index] if swap else charlie.entries[index]
        for index, swap in enumerate(coins)
    ]

    return {
        Party.BOB: RecipientRecord(
            party=Party.BOB,
            message_bit=bob.message_bit,
            entries=tuple(bob_entries),
            symmetrised=True,
        ),
        Party.CHARLIE: RecipientRecord(
            party=Party.CHARLIE,
            message_bit=charlie.message_bit,
            entries=tuple(charlie_entries),
            symmetrised=True,
        ),
    }


def no_symmetrisation(
    records: Mapping[Party | str, RecipientRecord],
    *,
    rng: np.random.Generator | None = None,
) -> dict[Party, RecipientRecord]:
    """Return the raw records unchanged. **Destroys non-repudiation.**

    The Phase 3 replacement for :func:`symmetrise_records`, provided so that the
    attack the exchange defends against can be run and measured rather than
    asserted: pass it as ``QDSSession(..., symmetriser=no_symmetrisation)`` and a
    signer that sends the two recipients different states gets Bob to accept
    what Charlie rejects, deterministically, at any key length.

    Parameters
    ----------
    records : mapping of Party to RecipientRecord
        The raw pair. Validated exactly as :func:`symmetrise_records` validates
        it, so that a mis-wired experiment fails the same way in both arms.
    rng : numpy.random.Generator or None, optional
        Keyword-only, accepted for signature compatibility and **not used**: no
        coins are tossed, so no randomness is consumed and the session's stream
        is identical to the symmetrised arm's up to this point.

    Returns
    -------
    dict of Party to RecipientRecord
        The same two records, still flagged
        :attr:`~sih141.protocol.records.RecipientRecord.symmetrised` ``False``.
        :func:`sih141.protocol.verify.verify_all` therefore refuses them unless
        the caller passes ``require_symmetrised=False``, which is the second
        place an experiment has to say out loud that it is running the insecure
        variant.

    Raises
    ------
    TypeError
        As :func:`symmetrise_records`.
    ValueError
        As :func:`symmetrise_records`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.symmetrise import no_symmetrisation
    >>> raw = {
    ...     Party.BOB: RecipientRecord.from_measurements("Bob", 0, ["X"], [1]),
    ...     Party.CHARLIE: RecipientRecord.from_measurements(
    ...         "Charlie", 0, ["Z"], [-1]
    ...     ),
    ... }
    >>> kept = no_symmetrisation(raw)
    >>> kept[Party.BOB] is raw[Party.BOB], kept[Party.BOB].symmetrised
    (True, False)
    """
    del rng  # No coins are tossed; see the Parameters section.
    bob, charlie = _checked_pair(records)
    return {Party.BOB: bob, Party.CHARLIE: charlie}
