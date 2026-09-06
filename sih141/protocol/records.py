"""The recipients' classical measurement logs -- the whole of what they store.

This module is where the "reduces the practical deployment complexities" claim
in the problem statement is cashed out. Gottesman-Chuang QDS asks each recipient
to *hold* the quantum public key until a signature turns up, which means
long-lived quantum memory and is the reason that line of work never deployed.
Here, following the measurement-based QDS of Dunjko-Wallden-Andersson (2014) and
Amiri et al. (2016), each recipient measures every qubit the instant it arrives,
in a basis drawn uniformly at random, and keeps

.. code-block:: text

    (index, chosen_basis, outcome_eigenvalue)

and nothing else. After distribution there is no quantum state anywhere in the
system: no quantum memory, no decoherence clock, no storage attack surface. A
:class:`RecipientRecord` is that log, and it is the *only* thing a verifier
brings to verification.

The classic implementation bug this type exists to prevent
----------------------------------------------------------
A record entry says which basis the recipient *chose*, not which basis Alice
declared -- at measurement time nobody knows Alice's basis, because the private
key is not revealed until the signing phase. When the key finally arrives, the
verifier splits its own positions in two:

.. code-block:: text

    matched    M_R = { i : record_basis_i == declared_basis_i }
    unmatched  everything else

Only ``M_R`` is counted. On an unmatched position the recipient measured a
conjugate observable, so the outcome is a fair coin *regardless of whether the
signature is honest*: it carries exactly zero bits about the key. Counting those
positions as mismatches drives every rate towards ``1/3`` (for a three-basis
alphabet, ``(1 - 1/|B|) / 2``), which sits above ``s_v`` in any sane parameter
set, so an implementation with this bug rejects honest signatures at both
verifiers and looks like a noise problem rather than a logic error.

This module therefore stores the chosen basis explicitly on every entry and
never pre-filters. Splitting matched from unmatched is
:mod:`sih141.protocol.verify`'s job, done against a key it is given.

Raw logs and symmetrised logs
-----------------------------
A record carries one bit of provenance beyond its data:
:attr:`RecipientRecord.symmetrised`. A *raw* log is what came off the channel;
a *symmetrised* one has been through
:func:`sih141.protocol.symmetrise.symmetrise_records`, in which Bob and Charlie
privately re-assign their two copies of every position between themselves.

The two are indistinguishable as data -- same shape, same columns, same
distribution on an honest run -- and the difference is worth an entire security
property. Alice prepares the two recipients' copies independently, so against a
pair of raw logs she can send Bob the eigenstate she declares and Charlie its
orthogonal partner, and repudiate with probability ``1``. After symmetrisation
she does not know which of her two preparations each verifier will score, and
the pair becomes exchangeable, which is what every non-repudiation bound in
:mod:`sih141.protocol.analysis` conditions on. What the flag does *not* buy is
independence between the declaration and the bases logged here: the exchange
hides its own coins from the signer, not the logs, and
:class:`~sih141.protocol.session.QDSSession` hands the ``Signer`` seam both raw
ones. So the per-run bound
(:func:`sih141.protocol.analysis.repudiation_bound`, at the observed
``m_B + m_C``) is what a symmetrised pair earns, while the ``M``-averaged
``6.9e-10`` needs an assumption these records cannot supply -- see
:mod:`sih141.protocol.analysis` section 4b. Nor does the flag say anything about
*who* prepared the states: that is assumption (AUTH), the next section. The
flag is carried so that
:func:`sih141.protocol.verify.verify_all` can refuse a raw pair instead of
quietly scoring one, and so that a transcript read back from disk still says
which protocol produced it.

What a record does not say: who signed
-------------------------------------
An entry says which basis was chosen and what came out. It does **not** say who
prepared the state that produced it, and no field on :class:`RecordEntry`,
:class:`RecipientRecord`, :class:`~sih141.protocol.signature.Signature`,
:class:`~sih141.protocol.verify.VerificationResult` or
:class:`~sih141.protocol.session.SessionTranscript` names or binds a signer.
This is worth stating as a *precondition* rather than leaving implicit, in
exactly the way assumption (IND) is stated, because the demo will be asked about
it:

**(AUTH) -- the classical and quantum channels from Alice to each recipient are
assumed authenticated.** Verification here is a counting rule over the two
columns above, and a counting rule can only ask whether the declaration agrees
with what was measured. It cannot ask whose states were measured. An adversary
who controls **both** seams -- distributing her own key states and then signing
her own key -- produces records that are honest records of *her* protocol run,
so both verifiers accept: ``200/200`` at Bob and at Charlie, pooled mismatch
rate ``0.0000`` at each, ``transferable=True``, measured through the shipped
seams by :mod:`sih141.attacks.impersonation` at ``L = 192`` over ``n = 200``
sessions per arm -- the same acceptance the ``none`` control earns.
That is not a defect of this module, of the thresholds or of the floors; it is
the standing assumption of measurement-based QDS (Dunjko-Wallden-Andersson 2014;
Amiri et al. 2016), which derives everything else *given* authenticated channels
from the signer.

**Partial impersonation is caught cold, and by the mismatch rate alone.** An
adversary who seizes only one of the two seams is the forger the thresholds are
sized against: ``0/200`` accepted under either single-seam scope, at pooled
mismatch rates ``0.4988`` (Bob) and ``0.5038`` (Charlie) when only the signing
seam is seized and ``0.5031`` and ``0.4997`` when only the distribution seam
is, against the ``1/2`` a declaration uncorrelated with these records
produces. Note what is *unchanged* in those runs -- the matched-count *law*,
which is not the same as the counts. The matched set is
``{i : record_basis_i == declared_basis_i}`` and both columns are drawn
uniformly and independently of the adversary, so its distribution is fixed. The
realised counts do move where the adversary holds the signing seam:
:data:`~sih141.attacks.impersonation.MATCHED_IDENTICAL_TRIALS` records
``200/200`` runs identical to the control under the distribution seam and
``0/200`` under the signing seam.
The mismatch rate is the only signal a record carries, which is why (AUTH) has
to be assumed rather than checked, and why the matched-count floors in
:mod:`sih141.protocol.verify` are an evidence-liveness control and not an
impersonation detector. See :mod:`sih141.protocol.analysis` section 0b.

The numbers above, as executable claims
---------------------------------------
``pytest --doctest-modules`` runs over ``sih141``, so the figures this docstring
leans on are tests: a prose number is unverifiable by construction and is how
stale figures survive to a judge.

>>> from sih141.protocol.analysis import (
...     averaged_repudiation_bound, repudiation_bound)
>>> from sih141.protocol.params import (
...     DEFAULT_PARAMS, UNSYMMETRISED_FORGER_RATE_THREE_BASIS)
>>> from sih141.protocol.records import RecipientRecord

The rate an unmatched-position bug drives every verifier towards --
``(1 - 1/|B|) / 2 = 1/3``, the whole point of storing the chosen basis -- sits
above both thresholds, which is why the bug looks like noise:

>>> UNSYMMETRISED_FORGER_RATE_THREE_BASIS == 1 / 3
True
>>> UNSYMMETRISED_FORGER_RATE_THREE_BASIS > DEFAULT_PARAMS.s_v
True
>>> DEFAULT_PARAMS.s_a, DEFAULT_PARAMS.s_v
(0.015625, 0.0625)

A partial impersonator is a different number and a larger one: his declaration
is uncorrelated with these records, so on a *matched* position the two agree by
a fair coin and the measured ``QBER`` sits at ``1/2``, far above ``s_v``.

>>> 0.5 > DEFAULT_PARAMS.s_v > DEFAULT_PARAMS.s_a > 0
True

The (AUTH) paragraphs above quote acceptance counts and mismatch rates. Those
are not prose: they are the rows :mod:`sih141.attacks.impersonation` measured
through the shipped seams, and this is the table they print. The four figures
this section used to quote were retired rather than corrected: they named no
``L``, no ``n`` and no estimator, so there was nothing in them to reproduce.
See :mod:`sih141.protocol.analysis` section 0b, which carries the digits and
the reason.

>>> from sih141.attacks.impersonation import shipped_summary
>>> for row in shipped_summary():
...     print(row)
none L=192 n=200: accepted 200/200, r_Bob=0.0000, r_Charlie=0.0000
full L=192 n=200: accepted 200/200, r_Bob=0.0000, r_Charlie=0.0000
signing L=192 n=200: accepted 0/200, r_Bob=0.4988, r_Charlie=0.5038
distribution L=192 n=200: accepted 0/200, r_Bob=0.5031, r_Charlie=0.4997

The ``M``-averaged figure this docstring says these records cannot earn, beside
the per-run figure a symmetrised pair does earn at the expected ``M``:

>>> averaged = averaged_repudiation_bound(
...     DEFAULT_PARAMS, signer_sees_recipient_bases=False)
>>> f"{averaged:.1e}"
'6.9e-10'
>>> f"{repudiation_bound(DEFAULT_PARAMS, matched_records=76800):.1e}"
'6.9e-10'

And the provenance bit itself, which is the one thing a record says about the
protocol that produced it -- and says nothing about who signed:

>>> record = RecipientRecord.from_measurements("Bob", 0, ["X", "Z"], [1, -1])
>>> record.symmetrised
False
>>> sorted(record.to_dict())
['entries', 'message_bit', 'party', 'session_id', 'symmetrised']

-- and the round it came from, which is the second piece of provenance and the
one a verifier checks a declaration against (:ref:`sih141.protocol.verify's
<replay>` replay defence). It is ``None`` on a log straight off the channel,
because raw measurements do not say which round they belong to until Alice's
announcement is attached:

>>> record.session_id is None
True
>>> record.with_session_id("9f3c").session_id
'9f3c'

.. _recipient-view:

One recipient's holdings, as a type rather than as a comment
------------------------------------------------------------
:class:`RecipientRecord` is one log. A *run* has four of them -- two message
bits times two verifiers -- and both of the objects that carry them,
:attr:`sih141.protocol.session.QDSSession.records` and
:attr:`~sih141.protocol.session.QDSSession.raw_records`, are nested mappings
holding **both** recipients' logs. That is right for the harness, which has to
schedule the run, and wrong for an adversary, which does not.

The Phase 2 audit found the consequence: mounting a recipient-flavoured
adversary meant reaching into ``session.raw_records``, so a "Bob" attack was
silently handed Charlie's log as well and the author had to *self-police* to
stay inside the threat model. A forging Bob who reads Charlie's record is not a
forging Bob; he is the two-log signer of
:ref:`sih141.protocol.session <two-log-signer>`, whose measured numbers are
already documented as outside the model the bounds are stated for. Nothing in
the API distinguished the two, and the only thing standing between an honest
mistake and a published fiction was a paragraph.

:class:`RecipientView` is that distinction expressed as a type: one party, one
message bit, that party's raw log, that party's post-exchange log, and that
party's own matched count when a declaration has arrived. Nothing else is stored
and nothing else is reachable -- no session, no key, no generator, and in
particular no object belonging to the counterpart:

>>> from sih141.protocol.params import Party
>>> from sih141.protocol.records import RecipientRecord, recipient_views
>>> raw = {
...     0: {
...         Party.BOB: RecipientRecord.from_measurements(
...             "Bob", 0, ["X", "Z"], [1, -1]),
...         Party.CHARLIE: RecipientRecord.from_measurements(
...             "Charlie", 0, ["Y", "Y"], [-1, 1]),
...     }
... }
>>> post = {
...     0: {
...         Party.BOB: RecipientRecord.from_measurements(
...             "Bob", 0, ["X", "Y"], [1, 1], symmetrised=True),
...         Party.CHARLIE: RecipientRecord.from_measurements(
...             "Charlie", 0, ["Y", "Z"], [-1, -1], symmetrised=True),
...     }
... }
>>> views = recipient_views(0, raw_records=raw, records=post)
>>> bob = views[Party.BOB]
>>> bob.party, len(bob), bob.matched_count
(<Party.BOB: 'Bob'>, 2, None)
>>> {record.party for record in (bob.raw_record, bob.record)}
{<Party.BOB: 'Bob'>}
>>> import dataclasses
>>> sorted(field.name for field in dataclasses.fields(bob))
['matched_count', 'message_bit', 'party', 'raw_record', 'record']

The narrowing happens once, in :meth:`RecipientView.for_party` or
:func:`recipient_views`, and it is the *harness* that calls it -- somebody has
to hold both logs in order to split them. What the split buys is that the
adversary downstream of it cannot un-split them, which is why the check that
matters is reachability from the view and not the shape of the call that built
it. ``tests/test_protocol_keys.py`` walks the object graph out of a view and
asserts that no :class:`RecipientRecord` belonging to the counterpart, and no
:class:`~sih141.protocol.keys.PrivateKey`, session or generator, is anywhere in
it.

One thing the view deliberately does *not* try to hide is a shared
:class:`RecordEntry`. After Phase A' roughly half of Bob's post-exchange entries
**are**, by object identity, entries that came off Charlie's raw log -- that is
what the exchange means, and those entries are now Bob's own evidence. The
invariant is about whole logs, not about the entries inside them.

Notes
-----
Authentication (AUTH)
    Assumed, never checked; see "What a record does not say: who signed" above
    and :mod:`sih141.protocol.analysis` section 0b.
Determinism (D3)
    Nothing here consumes randomness; the basis choice and the outcome are both
    made in :mod:`sih141.protocol.distribute`, which threads the injected
    generator.
Qubit ordering (D2)
    :attr:`RecordEntry.index` is the position in the key, ``0 .. L-1``, matching
    :class:`sih141.protocol.keys.PrivateKey` element order. It is not a
    little-endian register position; each key qubit is teleported and measured
    on its own, so no multi-qubit bitstring label is ever formed.
No machine learning (D4)
    Plain tabular data.
"""

from __future__ import annotations

import numbers
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, overload

from sih141.core.paulis import PauliBasis
from sih141.protocol.params import (
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_basis,
    _as_eigenvalue,
    _as_message_bit,
    _as_party,
)

__all__ = [
    "RecordEntry",
    "RecipientRecord",
    "RecipientView",
    "recipient_views",
]


@dataclass(frozen=True)
class RecordEntry:
    """One line of a recipient's log: what was measured where, and what came out.

    Frozen and hashable.

    Parameters
    ----------
    index : int
        Position in the key, ``0 .. L-1``. Non-negative.
    basis : PauliBasis or str
        The basis the *recipient* chose, drawn uniformly and independently of
        Alice's. Not necessarily the basis Alice declared -- that is the whole
        point; see the module docstring.
    eigenvalue : int
        The measured Pauli eigenvalue, ``+1`` or ``-1``.

    Raises
    ------
    ValueError
        If ``index`` is negative or not an integer, ``basis`` names no basis, or
        ``eigenvalue`` is not ``+1``/``-1``.
    TypeError
        If ``basis`` is neither a :class:`PauliBasis` nor a string.

    Examples
    --------
    >>> from sih141.protocol.records import RecordEntry
    >>> entry = RecordEntry(3, "X", -1)
    >>> entry.bit
    1
    """

    index: int
    basis: PauliBasis
    eigenvalue: int

    def __post_init__(self) -> None:
        """Validate the index and coerce the basis and eigenvalue."""
        if isinstance(self.index, bool) or not isinstance(
            self.index, numbers.Integral
        ):
            raise ValueError(
                f"index must be a non-negative integer position in the key, got "
                f"{self.index!r} of type {type(self.index).__name__}"
            )
        object.__setattr__(self, "index", int(self.index))
        if self.index < 0:
            raise ValueError(
                f"index must be non-negative, got {self.index}. It is the "
                f"position of this qubit in the private key, counted from 0."
            )
        object.__setattr__(self, "basis", _as_basis(self.basis, name="basis"))
        object.__setattr__(self, "eigenvalue", _as_eigenvalue(self.eigenvalue))

    @property
    def bit(self) -> int:
        """int: The classical bit, ``0`` for ``+1`` and ``1`` for ``-1``.

        Same mapping as :attr:`sih141.core.measure.MeasurementOutcome.bit` and
        :attr:`sih141.protocol.keys.KeyElement.bit`, so declared and measured
        values compare directly in either representation.
        """
        return (1 - self.eigenvalue) // 2

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            ``{"index": int, "basis": PauliBasis, "eigenvalue": int}``.
        """
        return {
            "index": self.index,
            "basis": self.basis,
            "eigenvalue": self.eigenvalue,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RecordEntry:
        """Rebuild an entry from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"index"``, ``"basis"`` and ``"eigenvalue"``.

        Returns
        -------
        RecordEntry

        Raises
        ------
        KeyError
            If a field is missing.
        """
        return cls(
            index=data["index"],
            basis=data["basis"],
            eigenvalue=data["eigenvalue"],
        )


@dataclass(frozen=True)
class RecipientRecord:
    """One recipient's complete classical log for one message bit.

    Immutable: frozen, hashable, and the entries are copied into a
    :class:`tuple` at construction, so a builder that keeps mutating its working
    list cannot retroactively change a record that has already been handed to a
    verifier.

    Parameters
    ----------
    party : Party or str
        :attr:`Party.BOB` or :attr:`Party.CHARLIE`. Alice is refused: she signs
        and keeps no record.
    message_bit : int
        ``0`` or ``1`` -- which of the two distribution runs this log came from.
    entries : sequence of RecordEntry
        One entry per distributed qubit. Their indices must be exactly
        ``0, 1, ..., len(entries) - 1`` in ascending order.
    symmetrised : bool, optional
        Provenance, not data: ``True`` once this log has been through
        :func:`sih141.protocol.symmetrise.symmetrise_records`, which privately
        re-assigns the two recipients' copies of each position between them.
        Defaults to ``False``, which is what
        :func:`~sih141.protocol.distribute.distribute_to_recipient` produces --
        a *raw* log, straight off the channel.

        The flag exists because the difference is not visible in the data and
        is worth an entire security property. A pair of raw logs supports no
        non-repudiation claim whatsoever: Alice prepares the two recipients'
        copies independently, so she can send Bob the declared eigenstate and
        Charlie its orthogonal partner and separate the two verdicts with
        probability ``1``. :func:`sih141.protocol.verify.verify_all` therefore
        refuses a raw pair by default rather than silently scoring it, and
        :class:`~sih141.protocol.session.SessionTranscript` records the flag so
        that a run read back from disk still says which protocol it ran.
    session_id : str or None, optional
        Which distribution round produced this log:
        :func:`sih141.protocol.signature.session_identifier` as Alice announced
        it in Phase A, before any declaration existed. Provenance again rather
        than data, and the *anchor* of the replay defence -- a verifier checks a
        declaration against the identifier on his own record, which is the one
        end of the comparison no signer can reach.

        ``None`` means the log names no round, which is what
        :func:`~sih141.protocol.distribute.distribute_to_recipient` produces on
        its own and what every log written before the binding existed is. A
        verifier holding one has nothing to compare and scores exactly as
        before; see :ref:`sih141.protocol.verify's <replay>` account of why the
        record and not the signature is the side that decides.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party; if ``message_bit`` is not
        ``0``/``1``; if ``entries`` is empty; if the indices are not exactly
        ``0 .. n-1`` in order; or if ``session_id`` is the empty string.
    TypeError
        If ``entries`` is not a sequence of :class:`RecordEntry`,
        ``symmetrised`` is not a :class:`bool`, or ``session_id`` is neither a
        string nor ``None``.

    Attributes
    ----------
    party : Party
    message_bit : int
    entries : tuple of RecordEntry
    symmetrised : bool
    session_id : str or None

    Notes
    -----
    A record names its *holder* and never its signer. There is no field here
    binding these entries to Alice, and none is checkable from the two columns:
    the channels from the signer are assumed authenticated (assumption (AUTH),
    module docstring and :mod:`sih141.protocol.analysis` section 0b). A verifier
    that needs signer authenticity must obtain it from the channel, not from
    this type.

    The index sequence is checked rather than assumed because the verifier reads
    the record positionally against the key. A dropped, duplicated or reordered
    entry would silently shift every subsequent comparison by one and turn an
    honest signature into a rate near ``(1 - 1/|B|) / 2`` -- the same symptom as
    the unmatched-position bug, and just as invisible.

    Examples
    --------
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.records import RecipientRecord
    >>> record = RecipientRecord.from_measurements(
    ...     Party.BOB, 0, ["X", "Z", "Y"], [1, -1, 1]
    ... )
    >>> len(record), record.party
    (3, <Party.BOB: 'Bob'>)
    """

    party: Party
    message_bit: int
    entries: tuple[RecordEntry, ...]
    symmetrised: bool = False
    session_id: str | None = None

    def __post_init__(self) -> None:
        """Validate the party and bit, then freeze and check the entry indices."""
        resolved = _as_party(self.party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice holds no measurement record: she prepares and teleports "
                "the public-key states and keeps the private key, but never "
                "measures. A RecipientRecord belongs to Party.BOB or "
                "Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )

        entries = self.entries
        if isinstance(entries, (str, bytes)) or not isinstance(
            entries, Sequence
        ):
            raise TypeError(
                f"entries must be a sequence of RecordEntry, got "
                f"{type(entries).__name__}"
            )
        frozen = tuple(entries)
        for position, entry in enumerate(frozen):
            if not isinstance(entry, RecordEntry):
                raise TypeError(
                    f"entries[{position}] must be a RecordEntry, got "
                    f"{type(entry).__name__}. Build the record with "
                    f"RecipientRecord.from_measurements(...) if you have plain "
                    f"basis and eigenvalue sequences."
                )
        if not frozen:
            raise ValueError(
                "a recipient record must have at least one entry: an empty log "
                "has no matched positions, so the mismatch rate is 0/0 and no "
                "accept/reject decision exists."
            )
        for position, entry in enumerate(frozen):
            if entry.index != position:
                raise ValueError(
                    f"entries must be indexed 0..{len(frozen) - 1} in ascending "
                    f"order, one per distributed qubit; entries[{position}] has "
                    f"index {entry.index}. The verifier reads this log "
                    f"positionally against the private key, so a gap, a "
                    f"duplicate or a reordering shifts every later comparison "
                    f"and turns an honest signature into a near-chance mismatch "
                    f"rate."
                )
        object.__setattr__(self, "entries", frozen)
        if not isinstance(self.symmetrised, bool):
            raise TypeError(
                f"symmetrised must be a bool, got "
                f"{type(self.symmetrised).__name__}. It is provenance -- "
                f"whether this log has been through symmetrise_records -- not a "
                f"count or a rate."
            )
        if self.session_id is not None and not isinstance(self.session_id, str):
            raise TypeError(
                f"session_id must be a string or None, got "
                f"{type(self.session_id).__name__}. It is the identifier Alice "
                f"announced with the distribution -- see "
                f"sih141.protocol.signature.session_identifier -- not a count "
                f"or an index."
            )
        if self.session_id == "":
            raise ValueError(
                "session_id must be non-empty or None. An empty identifier "
                "would match no declaration and yet claim to name a round, so "
                "every verification against this log would refuse; a log that "
                "names no round says so with None and is scored as before."
            )

    # -- alternative constructor -------------------------------------------- #

    @classmethod
    def from_measurements(
        cls,
        party: Party | str,
        message_bit: int,
        bases: Sequence[PauliBasis | str],
        eigenvalues: Sequence[int],
        *,
        symmetrised: bool = False,
        session_id: str | None = None,
    ) -> RecipientRecord:
        """Build a record from parallel basis and eigenvalue sequences.

        The convenience constructor for :mod:`sih141.protocol.distribute`, which
        accumulates the recipient's chosen bases and measured eigenvalues as it
        teleports qubit after qubit. Indices are assigned ``0 .. L-1`` in the
        order given.

        Parameters
        ----------
        party : Party or str
            :attr:`Party.BOB` or :attr:`Party.CHARLIE`.
        message_bit : int
            ``0`` or ``1``.
        bases : sequence of PauliBasis or str
            The bases the recipient chose, in key order.
        eigenvalues : sequence of int
            The measured eigenvalues, in the same order.
        symmetrised : bool, optional
            Keyword-only provenance flag, forwarded verbatim; see the class
            docstring. Defaults to ``False``, because the caller that builds a
            log out of raw measurements is by definition building a raw log.
        session_id : str or None, optional
            Keyword-only, forwarded verbatim. Defaults to ``None``: raw
            measurements alone do not say which round they came from, and
            :meth:`with_session_id` is how the announcement gets attached.

        Returns
        -------
        RecipientRecord

        Raises
        ------
        ValueError
            If the two sequences have different lengths, or any validation in
            :class:`RecordEntry` or :meth:`__post_init__` fails.

        Examples
        --------
        >>> from sih141.protocol.records import RecipientRecord
        >>> record = RecipientRecord.from_measurements(
        ...     "Charlie", 1, ("Z", "Z"), (-1, 1)
        ... )
        >>> record.eigenvalues
        (-1, 1)
        """
        basis_list = list(bases)
        value_list = list(eigenvalues)
        if len(basis_list) != len(value_list):
            raise ValueError(
                f"bases and eigenvalues must be the same length, got "
                f"{len(basis_list)} and {len(value_list)}. They are two columns "
                f"of one log: entry i is the basis chosen for qubit i and the "
                f"eigenvalue it produced."
            )
        entries = tuple(
            RecordEntry(index=index, basis=basis, eigenvalue=eigenvalue)
            for index, (basis, eigenvalue) in enumerate(
                zip(basis_list, value_list, strict=True)
            )
        )
        return cls(
            party=party,
            message_bit=message_bit,
            entries=entries,
            symmetrised=symmetrised,
            session_id=session_id,
        )

    def with_session_id(self, session_id: str | None) -> RecipientRecord:
        """Return a copy of this log stamped with the round it came from.

        The record is frozen and the identifier arrives as a separate
        announcement, so attaching it is a rebuild rather than an assignment.
        The entries are shared by reference; they are immutable.

        Parameters
        ----------
        session_id : str or None
            :func:`sih141.protocol.signature.session_identifier` as announced
            with the distribution, or ``None`` to clear it.

        Returns
        -------
        RecipientRecord
            A new record; ``self`` is unchanged.

        Raises
        ------
        TypeError
            If ``session_id`` is neither a string nor ``None``.
        ValueError
            If it is the empty string.

        See Also
        --------
        sih141.protocol.verify.verify : Where the stamp is checked.

        Examples
        --------
        >>> from sih141.protocol.records import RecipientRecord
        >>> raw = RecipientRecord.from_measurements("Bob", 0, ["X"], [1])
        >>> stamped = raw.with_session_id("9f3c")
        >>> stamped.session_id, raw.session_id
        ('9f3c', None)
        >>> stamped.entries is raw.entries
        True
        """
        return RecipientRecord(
            party=self.party,
            message_bit=self.message_bit,
            entries=self.entries,
            symmetrised=self.symmetrised,
            session_id=session_id,
        )

    # -- sequence protocol -------------------------------------------------- #

    def __len__(self) -> int:
        """int: The number of logged qubits, equal to the key length ``L``."""
        return len(self.entries)

    @overload
    def __getitem__(self, index: int) -> RecordEntry: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[RecordEntry, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> RecordEntry | tuple[RecordEntry, ...]:
        """Return entry ``index``, or a tuple for a slice.

        Because the indices are validated to be ``0 .. L-1`` in order,
        ``record[i].index == i`` always holds, so positional and logical
        indexing coincide.

        Parameters
        ----------
        index : int or slice

        Returns
        -------
        RecordEntry or tuple of RecordEntry
        """
        return self.entries[index]

    def __iter__(self) -> Iterator[RecordEntry]:
        """Iterate over the entries in key order."""
        return iter(self.entries)

    # -- derived views ------------------------------------------------------ #

    @property
    def length(self) -> int:
        """int: The number of logged qubits, the same number :func:`len` gives."""
        return len(self.entries)

    @property
    def bases(self) -> tuple[PauliBasis, ...]:
        """tuple of PauliBasis: The bases the recipient chose, in key order.

        Compare these against
        :attr:`sih141.protocol.keys.PrivateKey.bases` to build the matched set.
        """
        return tuple(entry.basis for entry in self.entries)

    @property
    def eigenvalues(self) -> tuple[int, ...]:
        """tuple of int: The measured eigenvalues, in key order."""
        return tuple(entry.eigenvalue for entry in self.entries)

    @property
    def bits(self) -> tuple[int, ...]:
        """tuple of int: The measured outcomes as classical bits."""
        return tuple(entry.bit for entry in self.entries)

    def check_against(self, params: ProtocolParams) -> None:
        """Raise if this record does not belong to ``params``.

        Parameters
        ----------
        params : ProtocolParams
            The parameter set the record is claimed to belong to.

        Raises
        ------
        ValueError
            If the log length differs from ``params.key_length``, or the
            recipient measured in a basis outside ``params.bases``.

        Examples
        --------
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.records import RecipientRecord
        >>> record = RecipientRecord.from_measurements("Bob", 0, ["X", "Y"], [1, 1])
        >>> record.check_against(ProtocolParams(key_length=2)) is None
        True
        """
        if len(self.entries) != params.key_length:
            raise ValueError(
                f"{self.party.value}'s record has {len(self.entries)} entries "
                f"but params.key_length is {params.key_length}. One qubit is "
                f"distributed and measured per key element, so the two must "
                f"agree exactly."
            )
        allowed = set(params.bases)
        stray = sorted({b.value for b in self.bases if b not in allowed})
        if stray:
            raise ValueError(
                f"{self.party.value}'s record uses basis/bases {stray}, which "
                f"are not in params.bases "
                f"{[b.value for b in params.bases]}. The recipient draws "
                f"uniformly from the declared alphabet; anything else changes "
                f"the match probability the security bounds assume."
            )

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the whole log.

        Returns
        -------
        dict
            ``{"party": Party, "message_bit": int, "entries": [...],
            "symmetrised": bool, "session_id": str | None}``. :class:`Party` and
            :class:`PauliBasis` are both :class:`enum.StrEnum`, so the result
            passes to :func:`json.dumps` unchanged.
        """
        return {
            "party": self.party,
            "message_bit": self.message_bit,
            "entries": [entry.to_dict() for entry in self.entries],
            "symmetrised": self.symmetrised,
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RecipientRecord:
        """Rebuild a record from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"party"``, ``"message_bit"`` and ``"entries"``.
            ``"symmetrised"`` is optional and defaults to ``False`` -- the
            conservative reading, since a log written before the flag existed
            was produced by a run that had no symmetrisation step.
            ``"session_id"`` is optional in the same way and for the same
            reason, and defaults to ``None``: a log written before the binding
            existed names no round, and restoring it into one that *claimed* a
            round would be inventing provenance rather than reading it.

        Returns
        -------
        RecipientRecord

        Raises
        ------
        KeyError
            If a field is missing.
        """
        return cls(
            party=data["party"],
            message_bit=data["message_bit"],
            entries=tuple(
                RecordEntry.from_dict(item) for item in data["entries"]
            ),
            symmetrised=data.get("symmetrised", False),
            session_id=data.get("session_id"),
        )




def _as_matched_count(value: Any, length: int) -> int:
    """Coerce and range-check a recipient's own matched count.

    Parameters
    ----------
    value : object
        The count claimed. Must be a non-boolean integer.
    length : int
        The log length ``L``; the count is a size of a subset of ``0 .. L-1``.

    Returns
    -------
    int

    Raises
    ------
    ValueError
        If ``value`` is not an integer, is a :class:`bool`, is negative, or
        exceeds ``length``.
    """
    if isinstance(value, bool) or not isinstance(value, numbers.Integral):
        raise ValueError(
            f"matched_count must be a non-negative integer or None, got "
            f"{value!r} of type {type(value).__name__}. It is |M_R|, the number "
            f"of positions this recipient may score, and None means no "
            f"declaration has arrived yet."
        )
    count = int(value)
    if not 0 <= count <= length:
        raise ValueError(
            f"matched_count must lie in 0..{length}, got {count}. The matched "
            f"set is a subset of this recipient's own {length} logged "
            f"positions, so a count outside that range describes a different "
            f"run."
        )
    return count


def _narrow(
    records: Mapping[int, Mapping[Party | str, RecipientRecord]],
    message_bit: int,
    party: Party,
    *,
    name: str,
) -> RecipientRecord:
    """Pull one party's log for one message bit out of a session-shaped mapping.

    Parameters
    ----------
    records : mapping
        Keyed by message bit, then by party, as
        :attr:`sih141.protocol.session.QDSSession.records` and
        :attr:`~sih141.protocol.session.QDSSession.raw_records` both are.
    message_bit : int
        The bit to select. Already validated by the caller.
    party : Party
        The verifier to select. Already resolved by the caller.
    name : str
        The argument name, for error messages.

    Returns
    -------
    RecipientRecord

    Raises
    ------
    TypeError
        If ``records`` or the inner value is not a mapping.
    ValueError
        If the bit or the party is absent.
    """
    if not isinstance(records, Mapping):
        raise TypeError(
            f"{name} must be a mapping of message bit to (mapping of party to "
            f"RecipientRecord), got {type(records).__name__}. Pass "
            f"session.raw_records or session.records straight through."
        )
    if message_bit not in records:
        raise ValueError(
            f"{name} has no entry for message bit {message_bit}; it holds "
            f"{sorted(records)}. A run distributes for both bits, so a mapping "
            f"missing one came from a partial or hand-built distribution."
        )
    by_party = records[message_bit]
    if not isinstance(by_party, Mapping):
        raise TypeError(
            f"{name}[{message_bit}] must be a mapping of party to "
            f"RecipientRecord, got {type(by_party).__name__}"
        )
    resolved = {_as_party(key): value for key, value in by_party.items()}
    if party not in resolved:
        raise ValueError(
            f"{name}[{message_bit}] has no log for {party.value}; it holds "
            f"{sorted(member.value for member in resolved)}. A view is one "
            f"recipient's holdings, so the log it is built from has to be "
            f"present."
        )
    return resolved[party]


@dataclass(frozen=True)
class RecipientView:
    """Everything one recipient holds for one message bit, and nothing else.

    The threat-model boundary of :ref:`recipient-view`, expressed as a type. A
    recipient-flavoured adversary -- a forging Bob, a Charlie who lies about his
    count -- is handed one of these instead of
    :attr:`sih141.protocol.session.QDSSession.raw_records`, and therefore
    *cannot* read the counterpart's evidence even by accident. Staying inside
    the threat model stops being a discipline the attack author has to remember
    and becomes the only thing the object supports.

    Frozen and hashable, over frozen fields. There is no session here, no
    private key, no generator and no log belonging to the other verifier;
    ``tests/test_protocol_keys.py`` walks the object graph and pins that.

    Parameters
    ----------
    party : Party or str
        :attr:`Party.BOB` or :attr:`Party.CHARLIE`. Alice is refused: she holds
        no log, so there is no view of the run from where she stands.
    message_bit : int
        ``0`` or ``1`` -- which distribution run these logs came from. A view
        covers one bit, because a recipient scores one declaration against one
        run and the two runs share nothing.
    raw_record : RecipientRecord
        What this recipient measured for himself, before Phase A'. Must be this
        party's, tagged with this bit, and **not** already symmetrised. This is
        the log a forging recipient declares: after the exchange roughly half of
        it *is* the other verifier's evidence, which is what makes it worth more
        to him than his own post-exchange log (see
        :ref:`sih141.protocol.session <phase3-seams>`).
    record : RecipientRecord
        What this recipient will actually be scored on, after Phase A'. Same
        party, same bit, same length. On a run wired with
        :func:`sih141.protocol.symmetrise.no_symmetrisation` this is the raw log
        itself, and :attr:`symmetrised` says so.
    matched_count : int or None, optional
        ``|M_R|``, the number of positions this recipient may score against the
        declaration -- and ``None``, the default, while no declaration has
        arrived. It is deliberately optional rather than computed: a view built
        at the end of Phase A cannot know it, because the key is not revealed
        until Phase B, and a type that pretended otherwise would be the
        unmatched-position bug in a new costume. Fill it in with
        :meth:`with_matched_count` once the declaration is in hand.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party; if ``message_bit`` is not
        ``0``/``1``; if either record belongs to another party, another bit or
        another length; if ``raw_record`` is already symmetrised; or if
        ``matched_count`` is out of range.
    TypeError
        If either record is not a :class:`RecipientRecord`.

    Attributes
    ----------
    party : Party
    message_bit : int
    raw_record : RecipientRecord
    record : RecipientRecord
    matched_count : int or None

    See Also
    --------
    recipient_views : Build both verifiers' views from one run in a single call.
    sih141.protocol.keys.key_from_record : Turn one of these logs into the
        declaration a recipient-flavoured adversary makes of it.
    sih141.protocol.verify.matched_positions : Where ``matched_count`` comes
        from once a declaration exists -- ``len(matched_positions(signature,
        view.record))``, fed back in through :meth:`with_matched_count`.

    Notes
    -----
    **What the counterpart's floor needs, and why it is not here.** Phase C'
    (:mod:`sih141.protocol.tally`) has each verifier announce his matched count
    to the other, so a view eventually coexists with a number that came *from*
    the counterpart. That number is one integer the protocol says the recipient
    receives; it is not a field of this type, because a view is what a recipient
    holds *of his own*, and mixing a received message into it would blur exactly
    the line the type exists to draw. Pass the counterpart's count alongside the
    view, as :func:`sih141.protocol.verify.verify` already takes it alongside a
    record.

    Examples
    --------
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.records import RecipientRecord, RecipientView
    >>> raw = RecipientRecord.from_measurements("Bob", 0, ["X", "Z"], [1, -1])
    >>> post = RecipientRecord.from_measurements(
    ...     "Bob", 0, ["X", "Y"], [1, 1], symmetrised=True
    ... )
    >>> view = RecipientView(Party.BOB, 0, raw, post)
    >>> view.party, len(view), view.symmetrised, view.matched_count
    (<Party.BOB: 'Bob'>, 2, True, None)
    >>> view.with_matched_count(1).matched_count
    1
    """

    party: Party
    message_bit: int
    raw_record: RecipientRecord
    record: RecipientRecord
    matched_count: int | None = None

    def __post_init__(self) -> None:
        """Resolve the party and check both logs really are that party's."""
        resolved = _as_party(self.party)
        if not resolved.is_verifier:
            raise ValueError(
                f"a RecipientView belongs to a verifier, "
                f"{[member.value for member in VERIFIERS]}, not to "
                f"{resolved.value}. Alice prepares, teleports and signs; she "
                f"measures nothing and holds no log, so there is no view of the "
                f"run from where she stands."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )

        for name, record in (
            ("raw_record", self.raw_record),
            ("record", self.record),
        ):
            if not isinstance(record, RecipientRecord):
                raise TypeError(
                    f"{name} must be a RecipientRecord, got "
                    f"{type(record).__name__}. Build a view from the logs a "
                    f"session hands back, or with "
                    f"RecipientView.for_party(party, bit, raw_records=..., "
                    f"records=...)."
                )
            if record.party is not resolved:
                raise ValueError(
                    f"{name} is {record.party.value}'s log but this view is "
                    f"{resolved.value}'s. A view holds one recipient's evidence "
                    f"and nothing of the other's; filing the counterpart's log "
                    f"under this party would hand a {resolved.value}-flavoured "
                    f"adversary exactly the evidence the threat model says he "
                    f"does not have."
                )
            if record.message_bit != self.message_bit:
                raise ValueError(
                    f"{name} is tagged with message bit {record.message_bit} "
                    f"but this view is for bit {self.message_bit}. The two "
                    f"distribution runs share no key and no evidence, so a "
                    f"mixed view scores one run's declaration against the "
                    f"other's log."
                )

        if len(self.raw_record) != len(self.record):
            raise ValueError(
                f"raw_record has {len(self.raw_record)} entries and record has "
                f"{len(self.record)}. Phase A' re-assigns the recipients' "
                f"copies position by position and creates none, so the two logs "
                f"are the same length by construction; a difference means they "
                f"came from different runs."
            )
        if self.raw_record.symmetrised:
            raise ValueError(
                "raw_record is flagged symmetrised, so it is not a raw log. "
                "The raw log is what this recipient measured for himself, "
                "straight off the channel and before the private exchange; it "
                "is what a forging recipient declares, and passing the "
                "post-exchange log twice would silently give him the half of "
                "the evidence the counterpart does *not* hold."
            )

        if self.matched_count is not None:
            object.__setattr__(
                self,
                "matched_count",
                _as_matched_count(self.matched_count, len(self.record)),
            )

    # -- alternative constructors ------------------------------------------- #

    @classmethod
    def for_party(
        cls,
        party: Party | str,
        message_bit: int,
        *,
        raw_records: Mapping[int, Mapping[Party | str, RecipientRecord]],
        records: Mapping[int, Mapping[Party | str, RecipientRecord]],
        matched_count: int | None = None,
    ) -> RecipientView:
        """Narrow a run's two nested log mappings down to one recipient's view.

        The narrowing point, and the *only* place both recipients' logs are in
        scope at once: somebody has to hold the pair in order to split it, and
        that somebody is the harness, never the adversary. What the split buys
        is that nothing downstream can put the pair back together -- see
        :ref:`recipient-view`.

        Parameters
        ----------
        party : Party or str
            The verifier whose view is wanted.
        message_bit : int
            ``0`` or ``1``.
        raw_records : mapping
            Keyed by message bit then by party, exactly the shape of
            :attr:`sih141.protocol.session.QDSSession.raw_records`.
        records : mapping
            The same shape, holding the post-exchange logs -- i.e.
            :attr:`sih141.protocol.session.QDSSession.records`.
        matched_count : int or None, optional
            Forwarded verbatim; ``None`` until a declaration exists.

        Returns
        -------
        RecipientView

        Raises
        ------
        TypeError
            If either mapping is not nested mappings of records.
        ValueError
            If either mapping lacks this bit or this party, or if any check in
            :meth:`__post_init__` fails.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import Party, ProtocolParams
        >>> from sih141.protocol.records import RecipientView
        >>> from sih141.protocol.session import QDSSession
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=12), rng=np.random.default_rng(3)
        ... )
        >>> _ = session.distribute()
        >>> view = RecipientView.for_party(
        ...     Party.BOB,
        ...     0,
        ...     raw_records=session.raw_records,
        ...     records=session.records,
        ... )
        >>> view.party, len(view), view.symmetrised
        (<Party.BOB: 'Bob'>, 12, True)
        """
        resolved = _as_party(party)
        bit = _as_message_bit(message_bit)
        return cls(
            party=resolved,
            message_bit=bit,
            raw_record=_narrow(raw_records, bit, resolved, name="raw_records"),
            record=_narrow(records, bit, resolved, name="records"),
            matched_count=matched_count,
        )

    def with_matched_count(self, matched_count: int | None) -> RecipientView:
        """Return a copy of this view carrying ``matched_count``.

        The view is frozen, and the count only becomes knowable in Phase C, so
        filling it in is a rebuild rather than an assignment. Everything else is
        shared by reference; the records are immutable.

        Parameters
        ----------
        matched_count : int or None
            ``|M_R|``, in ``0 .. len(self)``, or ``None`` to clear it.

        Returns
        -------
        RecipientView
            A new view; ``self`` is unchanged.

        Raises
        ------
        ValueError
            If the count is not an integer in range.

        Examples
        --------
        >>> from sih141.protocol.records import RecipientRecord, RecipientView
        >>> raw = RecipientRecord.from_measurements("Bob", 1, ["X"], [1])
        >>> view = RecipientView("Bob", 1, raw, raw)
        >>> view.with_matched_count(1).matched_count, view.matched_count
        (1, None)
        """
        return RecipientView(
            party=self.party,
            message_bit=self.message_bit,
            raw_record=self.raw_record,
            record=self.record,
            matched_count=matched_count,
        )

    # -- derived views ------------------------------------------------------ #

    def __len__(self) -> int:
        """int: The number of logged positions, equal to the key length ``L``."""
        return len(self.record)

    @property
    def length(self) -> int:
        """int: The key length ``L``, the same number :func:`len` gives."""
        return len(self.record)

    @property
    def symmetrised(self) -> bool:
        """bool: Whether Phase A' actually ran on this recipient's log.

        Read off :attr:`record`, which is what the verifier is scored on.
        ``False`` means the run was wired with
        :func:`sih141.protocol.symmetrise.no_symmetrisation` and supports no
        non-repudiation claim at all.
        """
        return self.record.symmetrised

    @property
    def has_matched_count(self) -> bool:
        """bool: Whether ``|M_R|`` is known yet.

        ``False`` before a declaration exists, which is every moment of Phase A
        and Phase A'. Distinct from ``matched_count == 0``, which is a run
        whose declaration this recipient can score at no position at all.
        """
        return self.matched_count is not None

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of one recipient's holdings.

        Returns
        -------
        dict
            ``{"party": Party, "message_bit": int, "raw_record": {...},
            "record": {...}, "matched_count": int | None}``. :class:`Party` is a
            :class:`enum.StrEnum`, so the result passes to :func:`json.dumps`
            unchanged.
        """
        return {
            "party": self.party,
            "message_bit": self.message_bit,
            "raw_record": self.raw_record.to_dict(),
            "record": self.record.to_dict(),
            "matched_count": self.matched_count,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RecipientView:
        """Rebuild a view from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"party"``, ``"message_bit"``, ``"raw_record"`` and
            ``"record"``. ``"matched_count"`` is optional and defaults to
            ``None`` -- the honest reading, since a stored view that omits it
            was written before any declaration existed.

        Returns
        -------
        RecipientView

        Raises
        ------
        KeyError
            If a required field is missing.
        """
        return cls(
            party=data["party"],
            message_bit=data["message_bit"],
            raw_record=RecipientRecord.from_dict(data["raw_record"]),
            record=RecipientRecord.from_dict(data["record"]),
            matched_count=data.get("matched_count"),
        )


def recipient_views(
    message_bit: int,
    *,
    raw_records: Mapping[int, Mapping[Party | str, RecipientRecord]],
    records: Mapping[int, Mapping[Party | str, RecipientRecord]],
    matched_counts: Mapping[Party | str, int] | None = None,
) -> dict[Party, RecipientView]:
    """Split one run's logs into one :class:`RecipientView` per verifier.

    The harness-side one-liner: hand it what a session hands back and get the
    two disjoint views the two recipient-flavoured adversaries are entitled to.
    Both views are built here, in one call, because that is the last place the
    pair is legitimately in scope (:ref:`recipient-view`).

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1``.
    raw_records : mapping
        Pre-exchange logs, keyed by message bit then party --
        :attr:`sih141.protocol.session.QDSSession.raw_records`.
    records : mapping
        Post-exchange logs, same shape --
        :attr:`sih141.protocol.session.QDSSession.records`.
    matched_counts : mapping of Party to int, optional
        Each verifier's own ``|M_R|``, when a declaration has already arrived.
        Missing parties get ``None``. Note that this is each recipient's *own*
        count, not the counterpart's: the counterpart's arrives as a Phase C'
        message and is not part of any view.

    Returns
    -------
    dict of Party to RecipientView
        Keyed by party in :data:`~sih141.protocol.params.VERIFIERS` order.

    Raises
    ------
    TypeError
        If a mapping is not nested mappings of records, or ``matched_counts`` is
        not a mapping.
    ValueError
        If a verifier or the message bit is missing from either mapping, or if
        any check in :class:`RecipientView` fails.

    See Also
    --------
    RecipientView.for_party : Build just one of the two.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.records import recipient_views
    >>> from sih141.protocol.session import QDSSession
    >>> session = QDSSession(
    ...     ProtocolParams(key_length=12), rng=np.random.default_rng(4)
    ... )
    >>> _ = session.distribute()
    >>> views = recipient_views(
    ...     1, raw_records=session.raw_records, records=session.records
    ... )
    >>> [party.value for party in views]
    ['Bob', 'Charlie']
    >>> views[Party.BOB].record is views[Party.CHARLIE].record
    False
    """
    bit = _as_message_bit(message_bit)
    if matched_counts is None:
        counts: dict[Party, int] = {}
    elif isinstance(matched_counts, Mapping):
        counts = {
            _as_party(key): value for key, value in matched_counts.items()
        }
    else:
        raise TypeError(
            f"matched_counts must be a mapping of party to int, or None, got "
            f"{type(matched_counts).__name__}"
        )
    return {
        party: RecipientView.for_party(
            party,
            bit,
            raw_records=raw_records,
            records=records,
            matched_count=counts.get(party),
        )
        for party in VERIFIERS
    }
