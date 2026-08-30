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
so both verifiers accept: ``60/60`` at Bob and ``60/60`` at Charlie, ``QBER``
exactly ``0.0000``, ``transferable=True``, measured through the shipped seams.
That is not a defect of this module, of the thresholds or of the floors; it is
the standing assumption of measurement-based QDS (Dunjko-Wallden-Andersson 2014;
Amiri et al. 2016), which derives everything else *given* authenticated channels
from the signer.

**Partial impersonation is caught cold, and by the mismatch rate alone.** An
adversary who seizes only one of the two seams is the forger the thresholds are
sized against: ``0/60`` accepted, at ``QBER = 0.4987`` (Bob) and ``0.4806``
(Charlie), against the ``1/2`` a declaration uncorrelated with these records
produces. Note what is *unchanged* in those runs -- the matched counts. The
matched set is ``{i : record_basis_i == declared_basis_i}`` and both columns are
drawn uniformly and independently of the adversary, so no impersonator moves it.
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
['entries', 'message_bit', 'party', 'symmetrised']

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
    Party,
    ProtocolParams,
    _as_basis,
    _as_eigenvalue,
    _as_message_bit,
    _as_party,
)

__all__ = ["RecordEntry", "RecipientRecord"]


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

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party; if ``message_bit`` is not
        ``0``/``1``; if ``entries`` is empty; or if the indices are not exactly
        ``0 .. n-1`` in order.
    TypeError
        If ``entries`` is not a sequence of :class:`RecordEntry`, or
        ``symmetrised`` is not a :class:`bool`.

    Attributes
    ----------
    party : Party
    message_bit : int
    entries : tuple of RecordEntry
    symmetrised : bool

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
            "symmetrised": bool}``. :class:`Party` and :class:`PauliBasis` are
            both :class:`enum.StrEnum`, so the result passes to
            :func:`json.dumps` unchanged.
        """
        return {
            "party": self.party,
            "message_bit": self.message_bit,
            "entries": [entry.to_dict() for entry in self.entries],
            "symmetrised": self.symmetrised,
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
        )
