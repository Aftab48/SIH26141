"""Phase B: signing -- Alice declares the private key on an authenticated channel.

Signing in this scheme is a purely classical act and it is startlingly plain:
Alice sends the recipients the message bit ``b`` together with the *whole*
private key ``k_b`` she drew in Phase A. That declaration **is** the signature.
There is no hash, no trapdoor, no one-way function, and nothing quantum happens
here at all -- the last quantum operation in the run finished when
:func:`sih141.protocol.distribute.distribute_to_recipient` returned.

Why revealing the key is not giving the game away
-------------------------------------------------
The usual reflex -- "a signature that hands over the private key cannot be
secure" -- is a reflex about *computational* signatures, where the key must stay
secret because possessing it is what lets you sign. Here the key is not a
capability, it is a *claim*, and the security was already bought in Phase A:

* Each recipient holds a classical log of one measurement per key position, made
  in a basis of their own uniform choosing, **before** the key was declared.
* On the roughly ``1/|B|`` of positions where their basis happened to be the one
  Alice now declares, only the true ``k_b`` reproduces their outcome. Anybody
  else's guess disagrees on half of those positions.
* Which positions those are is known to the recipient and to nobody else, so a
  forger cannot aim: he must be right almost everywhere or he is caught.

So the key is safe to publish at signing time precisely because it is *useless*
to anyone who did not distribute the matching quantum states first, and Alice
cannot distribute states that agree with a key she has not yet drawn. This is
the same reason a one-time signature can reveal its preimages: the commitment
came first.

The two keys, and why ``k_{1-b}`` stays sealed
----------------------------------------------
A run draws two independent keys, ``k_0`` and ``k_1``, and distributes both
before Alice knows which bit she will sign (see
:func:`sih141.protocol.keys.generate_key_pair`). Signing bit ``b`` reveals
``k_b`` only. ``k_{1-b}`` is drawn from independent randomness, so the
declaration says nothing about it and the *other* bit remains signable -- or,
more to the point, remains unforgeable. :class:`Signature` therefore carries the
message bit and refuses to be built around a key tagged with a different one:
signing a ``1`` with the key whose states were distributed as the ``0`` is a bug
that would otherwise show up only as two verifiers rejecting for no visible
reason.

Assumption: the classical channel is authenticated
--------------------------------------------------
Phase B runs over a channel that is **authenticated but not secret**. Secrecy is
not needed -- an eavesdropper who reads ``k_b`` learns nothing he can use,
because he holds no measurement record and forging requires agreeing with
records he never saw. Authentication *is* needed: an active adversary who could
replace the declaration in flight would simply substitute his own key, and no
counting rule at the far end can undo that. This is a standing assumption of
every QDS construction in the literature (Gottesman-Chuang 2001;
Dunjko-Wallden-Andersson 2014; Amiri et al. 2016), inherited from the
key-distribution setting, and it is stated here rather than buried because it is
the one thing this module does not and cannot enforce.

One bit per run, and no *uncovered* free-text label
----------------------------------------------------
:class:`Signature` signs a single bit, because a single distribution run
authenticates a single bit. A longer message needs one independent (key pair,
distribution) per bit, at the cost quoted in
:data:`sih141.protocol.params.DEFAULT_PARAMS`.

There is deliberately no human-readable ``message`` string on the signature. It
would be pleasant on a dashboard and it would be a real vulnerability: nothing
in the protocol binds such a label to the key, so an adversary could rewrite
``"transfer 10"`` to ``"transfer 10000"`` and every verifier would still accept,
having checked only the bit. **A label that is not covered by the verification
rule is worse than no label**, so this module refuses to carry one.

:attr:`Signature.context` is the exception that proves the rule, and it is an
exception only because it *is* covered: it is hashed into
:attr:`Signature.session_id`, the verifier recomputes that identifier from the
declaration in front of him and compares it against the one his own record was
stamped with at distribution time, and a context altered after distribution
therefore produces an identifier no record carries. See :ref:`session-binding`.

.. _session-binding:

Which round is this? -- the session identifier
-----------------------------------------------
A declaration on its own says nothing about *when* it was made. Before this
existed, :class:`Signature` carried ``(message_bit, declared_key)`` and
:class:`~sih141.protocol.records.RecipientRecord` carried no run identifier at
all, so a captured signature re-presented after the run was over verified again
at rate ``0.0`` and was accepted -- measured 6/6 at
:data:`~sih141.protocol.params.DEMO_PARAMS` -- and a signature paired with
*another run's* records failed only on the rate, which is a statistical
accident rather than a rule. The key states in QDS are genuinely one-time, so a
declaration and a set of records belong to exactly one distribution round;
pairing them across rounds should be impossible by construction.

What the identifier is derived from::

    opening    128 bits drawn fresh per (round, message bit) by the signer,
               kept secret until Phase B and then revealed on the signature
    context    the application's instruction-and-nonce string, or None
    session_id = blake2b(tag | message_bit | key_length | opening | context)

Alice announces ``session_id`` with the distribution in Phase A; each recipient
stamps it on his log (:attr:`~sih141.protocol.records.RecipientRecord.session_id`).
In Phase B she reveals ``(opening, context)`` on the signature, and
:func:`sih141.protocol.verify.verify` **recomputes** the identifier and compares.

Three properties, and one non-property, all of which matter:

*The declared key is deliberately not in it.* Folding the key into the digest is
the obvious move and it is wrong: the verifier can only recompute from the key
he was *declared*, so every forgery -- a declaration whose key is not the one
distributed -- would produce a mismatching identifier and be reported as a
refusal to score rather than as a rejection. That would silently convert the
scheme's headline forgery detection into a plumbing error and empty every
Phase 3 forgery table. The identifier names the round; the rate judges the key.

*It cannot be relabelled.* :class:`Signature` has no settable identifier field;
:attr:`~Signature.session_id` is a property computed from the opening. To make
one round's signature carry another round's identifier an adversary must find an
opening that hashes to it, and the opening of a round that has not yet been
signed exists only in the signer's hands. Relabelling is a preimage problem, not
an assignment.

*It is hiding until Phase B.* The opening is uniform and secret while the round
is live, so the announced identifier is independent of everything else in the
run. In particular it commits to nothing about the *unsigned* key ``k_{1-b}``,
which stays information-theoretically sealed exactly as before -- a digest of
the key material would have been a computational handle on it, and this scheme
does not have one anywhere else.

*What a signer can still do, stated plainly.* She can reuse her own opening and
give two rounds one identifier. She gains nothing by it: the two rounds' keys
differ, so a declaration replayed across them is rejected on the rate; and each
verifier's :class:`~sih141.protocol.verify.ConsumedRecords` ledger grants one
verdict per identifier, so two rounds sharing an identifier are *one* round to
every verifier rather than two. Freshness of the opening is specified
(:func:`fresh_opening`), and the defence does not rest on her honouring it.

Notes
-----
Determinism (D3)
    :func:`fresh_opening` is the one function here that draws, through a
    keyword-only ``rng`` resolved by :func:`sih141.core.rng.resolve_rng`.
    Everything else is pure: all the run's other randomness was spent drawing
    the key (:mod:`sih141.protocol.keys`) and distributing it
    (:mod:`sih141.protocol.distribute`).
No machine learning (D4)
    Field selection, validation and one unkeyed hash.

See Also
--------
sih141.protocol.keys.generate_key_pair : Draws the two keys a run commits to.
sih141.protocol.verify.verify : Phase C, which consumes what :func:`sign` emits.
sih141.protocol.verify.ConsumedRecords : The ledger that spends an identifier.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from sih141.core.paulis import PauliBasis
from sih141.core.rng import resolve_rng
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import ProtocolParams, _as_message_bit

__all__ = [
    "Signature",
    "fresh_context",
    "fresh_opening",
    "session_identifier",
    "sign",
]


_OPENING_BYTES: Final[int] = 16
"""int: Width of a session opening, in bytes.

``16`` -- 128 bits, drawn fresh per (round, message bit). It has to be wide
enough that two honest rounds never collide and that guessing an unsigned
round's opening is hopeless; it does not have to be wider, because it is
revealed in Phase B and is never a long-term secret.
"""

_SESSION_ID_BYTES: Final[int] = 16
"""int: Bytes of :func:`hashlib.blake2b` output kept in a session identifier.

Matches :data:`sih141.protocol.verify._DECLARATION_DIGEST_BYTES`, so the two
fingerprints a run carries are the same width and cannot be mistaken for each
other by length alone. What it must resist is a *preimage* search -- relabelling
one round's declaration with another round's identifier -- and 128 bits is far
past that.
"""

_SESSION_TAG: Final[bytes] = b"sih141.protocol.signature/session-id/v1"
"""bytes: Domain separator for :func:`session_identifier`.

Distinct from the tag :func:`sih141.protocol.verify._declaration_digest` uses,
so that a declaration fingerprint and a session identifier can never be equal by
accident and a caller who swaps the two gets a mismatch rather than a pass.
"""


def session_identifier(
    message_bit: int,
    key_length: int,
    *,
    opening: str,
    context: str | None = None,
) -> str:
    """Return the identifier of one distribution round.

    The value Alice announces with the Phase A distribution, each recipient
    stamps on his log, and :func:`sih141.protocol.verify.verify` recomputes from
    the declaration in front of it. :ref:`session-binding` gives the reasoning;
    the short version is that a declaration and a set of records belong to one
    distribution round, and this is what makes pairing them across rounds fail
    by rule instead of by luck.

    Note what is **absent**: the declared key. Including it would make every
    forgery -- a declaration whose key is not the one distributed -- recompute to
    a mismatching identifier and be reported as a refusal to score instead of a
    rejection, which would empty the scheme's forgery statistics into the abort
    column. The identifier names the round; the mismatch rate judges the key.

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1``. Each bit of a run gets its own key, its own distribution
        and therefore its own identifier.
    key_length : int
        ``L``. Bound in so that a run cannot share an identifier with a run of a
        different size even if an opening were reused.
    opening : str
        The round's secret opening, as hex -- :func:`fresh_opening` draws one.
        Keyword-only. Must be non-empty.
    context : str or None, optional
        Keyword-only. The application's instruction-and-nonce string, covered by
        the identifier and therefore by the verification rule; see
        :func:`fresh_context`. ``None`` and the empty string are distinguished,
        because "no context was ever declared" and "the empty context was
        declared" are different claims.

    Returns
    -------
    str
        A 32-character lowercase hex digest.

    Raises
    ------
    TypeError
        If ``opening`` is not a string, or ``context`` is neither a string nor
        ``None``.
    ValueError
        If ``message_bit`` is not ``0``/``1``, if ``key_length`` is not a
        positive integer, or if ``opening`` is empty.

    See Also
    --------
    fresh_opening : Draws an opening.
    fresh_context : Builds a context that carries a freshness nonce.
    Signature.session_id : The property that calls this.

    Notes
    -----
    Consumes no randomness (D3): an unkeyed hash of a length-prefixed encoding.
    The encoding is injective -- every variable-length part is preceded by its
    own byte length -- so exactly one ``(message_bit, key_length, opening,
    context)`` produces any digest, and a context ending in a delimiter cannot
    impersonate a longer opening.

    Examples
    --------
    >>> from sih141.protocol.signature import session_identifier
    >>> first = session_identifier(0, 192, opening="a3f1")
    >>> len(first), first == session_identifier(0, 192, opening="a3f1")
    (32, True)
    >>> first == session_identifier(1, 192, opening="a3f1")
    False
    >>> first == session_identifier(0, 192, opening="a3f2")
    False

    The context is covered, which is what lets a signature carry one at all:

    >>> labelled = session_identifier(0, 192, opening="a3f1", context="pay 10")
    >>> labelled in (first, session_identifier(
    ...     0, 192, opening="a3f1", context="pay 10000"
    ... ))
    False

    ``None`` and ``""`` are different declarations, not the same one:

    >>> session_identifier(0, 192, opening="a3f1", context="") == first
    False
    """
    bit = _as_message_bit(message_bit)
    length = _as_key_length(key_length)
    if not isinstance(opening, str):
        raise TypeError(
            f"opening must be a string, got {type(opening).__name__}; "
            f"fresh_opening(rng=...) draws one."
        )
    if not opening:
        raise ValueError(
            "opening must be non-empty. It is the secret this round's "
            "identifier commits to, and an empty one commits to nothing: two "
            "rounds would share an identifier and a replayed declaration would "
            "pair with the wrong records."
        )
    if context is not None and not isinstance(context, str):
        raise TypeError(
            f"context must be a string or None, got {type(context).__name__}"
        )
    opening_bytes = opening.encode("utf-8")
    # A leading marker byte separates "no context" from the empty context, and a
    # length prefix on each variable-length field keeps the encoding injective.
    if context is None:
        context_bytes = b"\x00"
    else:
        context_bytes = b"\x01" + context.encode("utf-8")
    payload = b"|".join(
        (
            _SESSION_TAG,
            str(bit).encode("ascii"),
            str(length).encode("ascii"),
            str(len(opening_bytes)).encode("ascii"),
            opening_bytes,
            str(len(context_bytes)).encode("ascii"),
            context_bytes,
        )
    )
    return hashlib.blake2b(payload, digest_size=_SESSION_ID_BYTES).hexdigest()


def _as_key_length(value: Any) -> int:
    """Coerce and range-check a key length.

    Parameters
    ----------
    value : object
        The claimed ``L``. Must be a non-boolean integer of at least ``1``.

    Returns
    -------
    int

    Raises
    ------
    ValueError
        If it is not a positive integer.
    """
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise ValueError(
            f"key_length must be a positive integer, got {value!r} of type "
            f"{type(value).__name__}"
        )
    length = int(value)
    if length < 1:
        raise ValueError(
            f"key_length must be at least 1, got {length}; a run with no key "
            f"positions distributes nothing and has no round to identify."
        )
    return length


def fresh_opening(*, rng: np.random.Generator | None = None) -> str:
    """Draw the secret opening for one distribution round.

    Called once per ``(round, message bit)`` by whoever is running Phase A --
    :meth:`sih141.protocol.session.QDSSession.distribute` does it from a stream
    of its own -- and kept secret until Phase B, when the signature reveals it.

    Parameters
    ----------
    rng : numpy.random.Generator or None, optional
        Keyword-only, resolved by :func:`sih141.core.rng.resolve_rng` (D3).

    Returns
    -------
    str
        ``2 * 16 = 32`` lowercase hex characters, 128 bits of entropy.

    See Also
    --------
    session_identifier : What the opening is committed to.

    Notes
    -----
    The one function in this module that consumes randomness. It must come from
    an injected generator (D3) rather than a module-level default: an opening
    that a Phase 3 adversary can reproduce is an opening he can relabel a
    declaration with, and reproducibility of the harness is what makes that easy
    to do by accident.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.signature import fresh_opening
    >>> opening = fresh_opening(rng=np.random.default_rng(0))
    >>> len(opening), opening == fresh_opening(rng=np.random.default_rng(0))
    (32, True)
    >>> opening == fresh_opening(rng=np.random.default_rng(1))
    False
    """
    return resolve_rng(rng).bytes(_OPENING_BYTES).hex()


def fresh_context(instruction: str, nonce: str) -> str:
    """Combine an application instruction with a freshness nonce.

    The thin, entirely classical half of the replay defence, and deliberately
    not quantum-specific. The protocol authenticates a *bit*; an application
    authenticates an instruction, and the same instruction re-presented is the
    ordinary replay every signature scheme has to answer. Feeding the pair
    through here and into :attr:`Signature.context` puts it under the session
    identifier, so a distinct nonce is a distinct round and a verifier's
    :class:`~sih141.protocol.verify.ConsumedRecords` ledger grants one verdict
    per round: a genuinely valid signed instruction cannot be executed twice.

    Parameters
    ----------
    instruction : str
        What the bit means to the application, e.g. ``"transfer 10 to Bob"``.
    nonce : str
        Anything unique to this authorisation -- a UUID, a counter, an ISO
        timestamp. Supplied rather than generated: uniqueness is a property of
        the application's namespace, and a nonce drawn here would be random
        (breaking the harness's reproducibility) or seed-derived (repeating
        exactly when a replay does, which is the mistake
        :class:`~sih141.protocol.session.SessionTranscript`'s ``run_id`` field
        already documents).

    Returns
    -------
    str
        ``"<len(instruction)>:<instruction>#<nonce>"`` -- length-prefixed, so
        that no ``(instruction, nonce)`` pair can be rewritten into another one
        by moving the delimiter.

    Raises
    ------
    TypeError
        If either argument is not a string.
    ValueError
        If ``nonce`` is empty, which would make the context no fresher than the
        instruction alone.

    See Also
    --------
    session_identifier : Where the context is covered.

    Examples
    --------
    >>> from sih141.protocol.signature import fresh_context
    >>> fresh_context("pay 10", "2026-08-31T09:00:00Z")
    '6:pay 10#2026-08-31T09:00:00Z'
    >>> fresh_context("pay 10", "a") == fresh_context("pay 10", "b")
    False

    Length prefixing is what stops two different pairs colliding:

    >>> fresh_context("pay", "10#x") == fresh_context("pay#10", "x")
    False
    """
    if not isinstance(instruction, str):
        raise TypeError(
            f"instruction must be a string, got {type(instruction).__name__}"
        )
    if not isinstance(nonce, str):
        raise TypeError(f"nonce must be a string, got {type(nonce).__name__}")
    if not nonce:
        raise ValueError(
            "nonce must be non-empty: it is the whole freshness content of the "
            "context, and an empty one makes two authorisations of the same "
            "instruction indistinguishable."
        )
    return f"{len(instruction)}:{instruction}#{nonce}"


@dataclass(frozen=True)
class Signature:
    """What Alice sends in Phase B: a message bit and the key she claims signs it.

    Frozen and hashable. Every field is classical, so a signature serialises with
    :func:`json.dumps` and can be logged, replayed and diffed -- which is what
    Phase 3 needs in order to hand a verifier a *tampered* one.

    The key is named ``declared_key`` rather than ``key`` on purpose. From the
    verifier's side it is an assertion under test, not a fact: verification is
    exactly the act of asking how well this claim explains a measurement record
    that was made before the claim existed.

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1`` -- the bit being signed. Booleans are refused, as
        everywhere else in the package, because ``True`` reads as ``1`` while
        usually meaning "yes".
    declared_key : PrivateKey
        The private key Alice declares for that bit. Its own
        :attr:`~sih141.protocol.keys.PrivateKey.message_bit` must equal
        ``message_bit``.
    session_opening : str or None, optional
        The distribution round's secret opening, revealed here and nowhere
        earlier. ``None`` means an *unbound* declaration -- one from a run that
        announced no identifier -- which is what every signature built before
        :ref:`session-binding` existed is, and which a verifier holding an
        equally unbound record still scores exactly as before.
    context : str or None, optional
        The application's instruction-and-nonce string
        (:func:`fresh_context`), fixed when the opening was drawn. It is the one
        free-text label this module carries, and it is carried only because
        :attr:`session_id` covers it: alter it after distribution and the
        identifier no longer matches any record. ``None`` and ``""`` are
        different declarations.

    Raises
    ------
    TypeError
        If ``declared_key`` is not a :class:`~sih141.protocol.keys.PrivateKey`,
        or if ``session_opening`` or ``context`` is neither a string nor
        ``None``.
    ValueError
        If ``message_bit`` is not ``0``/``1``, if the key is tagged with the
        other bit, or if ``session_opening`` is the empty string -- an opening
        that commits to nothing is not the same as declaring none, and only the
        second is representable.

    Attributes
    ----------
    message_bit : int
    declared_key : PrivateKey
    session_opening : str or None
    context : str or None

    See Also
    --------
    sign : Build one from a key or from the two-key pair a run commits to.
    sih141.protocol.verify.verify : Score a signature against one record.
    session_identifier : How :attr:`session_id` is derived, and from what.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.signature import sign
    >>> params = ProtocolParams(key_length=9)
    >>> keys = generate_key_pair(params, rng=np.random.default_rng(20260141))
    >>> signature = sign(1, keys, params)
    >>> signature.message_bit, len(signature)
    (1, 9)
    >>> signature.declared_key is keys[1]
    True

    An unbound declaration names no round; a bound one names exactly one:

    >>> signature.session_id is None
    True
    >>> bound = sign(1, keys, params, session_opening="9c2e", context="pay 10")
    >>> len(bound.session_id)
    32
    >>> bound.session_id == sign(
    ...     1, keys, params, session_opening="9c2e", context="pay 11"
    ... ).session_id
    False
    """

    message_bit: int
    declared_key: PrivateKey
    session_opening: str | None = None
    context: str | None = None

    def __post_init__(self) -> None:
        """Validate the bit, the key's own bit, and the session fields."""
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        if self.session_opening is not None and not isinstance(
            self.session_opening, str
        ):
            raise TypeError(
                f"session_opening must be a string or None, got "
                f"{type(self.session_opening).__name__}; fresh_opening(rng=...) "
                f"draws one and QDSSession.distribute() keeps it."
            )
        if self.session_opening == "":
            raise ValueError(
                "session_opening must be non-empty or None. An empty opening "
                "would commit to nothing, so every round would share one "
                "identifier and a replayed declaration would pair with the "
                "wrong records; declare no opening instead, which says "
                "honestly that this declaration names no round."
            )
        if self.context is not None and not isinstance(self.context, str):
            raise TypeError(
                f"context must be a string or None, got "
                f"{type(self.context).__name__}; it is the application's "
                f"instruction-and-nonce string, not a structured object."
            )
        if not isinstance(self.declared_key, PrivateKey):
            raise TypeError(
                f"declared_key must be a PrivateKey, got "
                f"{type(self.declared_key).__name__}. The signature *is* the "
                f"private key for the signed bit; build one with "
                f"generate_private_key(params, message_bit, rng=...)."
            )
        if self.declared_key.message_bit != self.message_bit:
            raise ValueError(
                f"cannot sign message bit {self.message_bit} with the key drawn "
                f"for bit {self.declared_key.message_bit}. A run distributes "
                f"quantum states for k_0 and k_1 separately, so a recipient's "
                f"record for one bit has no relationship to the other key: "
                f"declaring the wrong one gives a mismatch rate near "
                f"(1 - 1/|B|)/2 at both verifiers and looks like a channel "
                f"problem rather than a mix-up. Use sign(message_bit, keys) and "
                f"let it pick."
            )

    # -- sequence-flavoured views ------------------------------------------- #

    def __len__(self) -> int:
        """int: The declared key length ``L``."""
        return len(self.declared_key)

    def __iter__(self) -> Iterator[KeyElement]:
        """Iterate over the declared key elements, in key order."""
        return iter(self.declared_key)

    @property
    def length(self) -> int:
        """int: The declared key length ``L``, the same number :func:`len` gives."""
        return len(self.declared_key)

    @property
    def bases(self) -> tuple[PauliBasis, ...]:
        """tuple of PauliBasis: The declared bases, in key order.

        The sequence a verifier intersects with its own choices to build the
        matched set ``M_R``.
        """
        return self.declared_key.bases

    @property
    def eigenvalues(self) -> tuple[int, ...]:
        """tuple of int: The declared eigenvalues, in key order."""
        return self.declared_key.eigenvalues

    @property
    def bits(self) -> tuple[int, ...]:
        """tuple of int: The declared eigenvalues as classical ``0``/``1`` bits."""
        return self.declared_key.bits

    @property
    def session_id(self) -> str | None:
        """str or None: Which distribution round this declaration belongs to.

        :func:`session_identifier` of :attr:`session_opening` and
        :attr:`context`, or ``None`` on an unbound declaration. A *property*
        rather than a field, and that is the load-bearing part: there is nowhere
        to write an identifier of one's choosing, so an adversary who wants one
        round's declaration to pass another round's binding check has to find an
        opening that hashes to that round's identifier. See
        :ref:`session-binding`.

        Examples
        --------
        >>> from sih141.protocol.keys import KeyElement, PrivateKey
        >>> from sih141.protocol.signature import Signature
        >>> key = PrivateKey(0, (KeyElement("X", 1),))
        >>> Signature(0, key).session_id is None
        True
        >>> Signature(0, key, session_opening="7b").session_id == Signature(
        ...     0, key, session_opening="7b"
        ... ).session_id
        True

        The identifier does not depend on the declared key, so a forgery is
        scored on its mismatch rate rather than refused as the wrong round:

        >>> forged = PrivateKey(0, (KeyElement("X", -1),))
        >>> Signature(0, key, session_opening="7b").session_id == Signature(
        ...     0, forged, session_opening="7b"
        ... ).session_id
        True
        """
        if self.session_opening is None:
            return None
        return session_identifier(
            self.message_bit,
            len(self.declared_key),
            opening=self.session_opening,
            context=self.context,
        )

    def check_against(self, params: ProtocolParams) -> None:
        """Raise if the declared key does not belong to ``params``.

        A thin delegation to
        :meth:`sih141.protocol.keys.PrivateKey.check_against`, provided so that
        the verification path can validate a signature without reaching through
        it for the key.

        Parameters
        ----------
        params : ProtocolParams
            The parameter set the signature is claimed to belong to.

        Raises
        ------
        ValueError
            If the declared key length differs from ``params.key_length``, or
            the key uses a basis outside ``params.bases``.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.keys import generate_private_key
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.signature import sign
        >>> params = ProtocolParams(key_length=5)
        >>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
        >>> sign(0, key).check_against(params) is None
        True
        """
        self.declared_key.check_against(params)

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the signature.

        Returns
        -------
        dict
            ``{"message_bit": int, "declared_key": {...},
            "session_opening": str | None, "context": str | None}``. The nested
            value is :meth:`sih141.protocol.keys.PrivateKey.to_dict` output.
            :attr:`session_id` is **not** stored: it is derived, and writing it
            down would create a second, forgeable copy of the one field whose
            unforgeability rests on there being no place to put one.

        Examples
        --------
        >>> import json
        >>> import numpy as np
        >>> from sih141.protocol.keys import generate_private_key
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.signature import Signature, sign
        >>> key = generate_private_key(
        ...     ProtocolParams(key_length=3), 1, rng=np.random.default_rng(2)
        ... )
        >>> blob = json.dumps(sign(1, key).to_dict())
        >>> Signature.from_dict(json.loads(blob)) == sign(1, key)
        True
        >>> sorted(sign(1, key).to_dict())
        ['context', 'declared_key', 'message_bit', 'session_opening']

        A bound declaration round-trips to the same round:

        >>> bound = sign(1, key, session_opening="4d", context="pay 10")
        >>> restored = Signature.from_dict(json.loads(json.dumps(bound.to_dict())))
        >>> restored == bound and restored.session_id == bound.session_id
        True
        """
        return {
            "message_bit": self.message_bit,
            "declared_key": self.declared_key.to_dict(),
            "session_opening": self.session_opening,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Signature:
        """Rebuild a signature from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"message_bit"`` and ``"declared_key"``.
            ``"session_opening"`` and ``"context"`` are optional and default to
            ``None`` -- a declaration serialised before
            :ref:`session-binding` existed names no round, which is the truth
            about it, and it restores into an object that says so rather than
            into one that claims a round it cannot prove.

        Returns
        -------
        Signature

        Raises
        ------
        KeyError
            If a required field is missing.
        ValueError
            If the rebuilt key is tagged with the other message bit.
        """
        return cls(
            message_bit=data["message_bit"],
            declared_key=PrivateKey.from_dict(data["declared_key"]),
            session_opening=data.get("session_opening"),
            context=data.get("context"),
        )


def sign(
    message_bit: int,
    keys: PrivateKey | Sequence[PrivateKey],
    params: ProtocolParams | None = None,
    *,
    session_opening: str | None = None,
    context: str | None = None,
) -> Signature:
    """Sign one message bit by declaring the key that was distributed for it.

    Phase B in one call. Nothing is computed from the message: the signature is
    the key itself, and the whole of its strength was established when the
    corresponding quantum states were teleported and measured in Phase A (see
    the module docstring).

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1``, the bit to sign.
    keys : PrivateKey or sequence of PrivateKey
        Either the single key for that bit, or the two-key pair
        :func:`sih141.protocol.keys.generate_key_pair` returns -- in which case
        ``keys[message_bit]`` is selected. Passing the pair is the safer
        spelling: the selection cannot then be made by hand and made wrong.
    params : ProtocolParams or None, optional
        When given, the selected key is checked against it with
        :meth:`sih141.protocol.keys.PrivateKey.check_against`, so a key drawn
        under a different parameter set is refused at signing time rather than
        surfacing as an unexplained rejection at both verifiers.
    session_opening : str or None, optional
        Keyword-only. The opening of the distribution round this declaration
        belongs to, drawn in Phase A by :func:`fresh_opening` and revealed here.
        ``None`` produces an unbound declaration, which is what a caller with no
        round to name can honestly emit and what every signature built before
        :ref:`session-binding` existed is.
    context : str or None, optional
        Keyword-only. The application's instruction-and-nonce string
        (:func:`fresh_context`), fixed at distribution and covered by the
        identifier.

    Returns
    -------
    Signature
        A frozen declaration of ``(message_bit, key, session_opening,
        context)``. The key is the very object passed in, not a copy;
        :class:`~sih141.protocol.keys.PrivateKey` is immutable, so sharing it is
        safe and identity comparisons hold.

    Raises
    ------
    TypeError
        If ``keys`` is neither a :class:`~sih141.protocol.keys.PrivateKey` nor a
        sequence of them, ``params`` is given but is not a
        :class:`~sih141.protocol.params.ProtocolParams`, or a session field is
        neither a string nor ``None``.
    ValueError
        If ``message_bit`` is not ``0``/``1``; if ``keys`` is a sequence that is
        not exactly ``(key_for_bit_0, key_for_bit_1)`` in that order; if a
        single key is passed that is tagged with the other bit; or if the
        selected key does not belong to ``params``.

    See Also
    --------
    sih141.protocol.keys.generate_key_pair : Produces the ``keys`` pair.
    sih141.protocol.verify.verify : The other half of the transaction.

    Notes
    -----
    Consumes no randomness (D3) and touches no quantum state: by the time this
    runs, the only trace of the public key left in the system is the recipients'
    classical logs.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.signature import sign
    >>> params = ProtocolParams(key_length=12)
    >>> keys = generate_key_pair(params, rng=np.random.default_rng(7))
    >>> sign(0, keys, params).declared_key is keys[0]
    True
    >>> sign(1, keys, params).declared_key is keys[1]
    True

    Naming the round is one keyword, and it changes nothing about the key:

    >>> bound = sign(0, keys, params, session_opening="e01d")
    >>> bound.declared_key is keys[0], len(bound.session_id)
    (True, 32)
    """
    bit = _as_message_bit(message_bit)

    if isinstance(keys, PrivateKey):
        selected = keys
    elif isinstance(keys, (str, bytes)) or not isinstance(keys, Sequence):
        raise TypeError(
            f"keys must be a PrivateKey or the (k_0, k_1) pair from "
            f"generate_key_pair, got {type(keys).__name__}"
        )
    else:
        pair = tuple(keys)
        for position, candidate in enumerate(pair):
            if not isinstance(candidate, PrivateKey):
                raise TypeError(
                    f"keys[{position}] must be a PrivateKey, got "
                    f"{type(candidate).__name__}"
                )
        if len(pair) != 2:
            raise ValueError(
                f"keys must hold exactly the two keys a run commits to, "
                f"(k_0, k_1), got {len(pair)}. Alice draws both before she knows "
                f"which bit she will sign, and distributes quantum states for "
                f"both; a run with one key can only ever sign one predetermined "
                f"bit, which is not a signature scheme."
            )
        tags = tuple(candidate.message_bit for candidate in pair)
        if tags != (0, 1):
            raise ValueError(
                f"keys must be ordered (key_for_bit_0, key_for_bit_1); the pair "
                f"given is tagged {tags}. Index it with the message bit -- "
                f"keys[b] is the key for bit b -- which is what "
                f"generate_key_pair returns."
            )
        selected = pair[bit]

    if selected.message_bit != bit:
        raise ValueError(
            f"cannot sign message bit {bit} with the key drawn for bit "
            f"{selected.message_bit}. Pass the (k_0, k_1) pair instead of a "
            f"single key and let sign() select, or draw the key with "
            f"generate_private_key(params, {bit}, rng=...)."
        )

    if params is not None:
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams or None, got "
                f"{type(params).__name__}"
            )
        selected.check_against(params)

    return Signature(
        message_bit=bit,
        declared_key=selected,
        session_opening=session_opening,
        context=context,
    )
