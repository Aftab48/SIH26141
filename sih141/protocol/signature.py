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

One bit per run, and no free-text label
---------------------------------------
:class:`Signature` signs a single bit, because a single distribution run
authenticates a single bit. A longer message needs one independent (key pair,
distribution) per bit, at the cost quoted in
:data:`sih141.protocol.params.DEFAULT_PARAMS`.

There is deliberately no human-readable ``message`` string on the signature. It
would be pleasant on a dashboard and it would be a real vulnerability: nothing
in the protocol binds such a label to the key, so an adversary could rewrite
``"transfer 10"`` to ``"transfer 10000"`` and every verifier would still accept,
having checked only the bit. A label that is not covered by the verification
rule is worse than no label, so this module refuses to carry one.

Notes
-----
Determinism (D3)
    Nothing in this module consumes randomness. All of it was spent drawing the
    key (:mod:`sih141.protocol.keys`) and distributing it
    (:mod:`sih141.protocol.distribute`).
No machine learning (D4)
    Field selection and validation only.

See Also
--------
sih141.protocol.keys.generate_key_pair : Draws the two keys a run commits to.
sih141.protocol.verify.verify : Phase C, which consumes what :func:`sign` emits.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sih141.core.paulis import PauliBasis
from sih141.protocol.keys import KeyElement, PrivateKey
from sih141.protocol.params import ProtocolParams, _as_message_bit

__all__ = ["Signature", "sign"]


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

    Raises
    ------
    TypeError
        If ``declared_key`` is not a :class:`~sih141.protocol.keys.PrivateKey`.
    ValueError
        If ``message_bit`` is not ``0``/``1``, or if the key is tagged with the
        other bit.

    Attributes
    ----------
    message_bit : int
    declared_key : PrivateKey

    See Also
    --------
    sign : Build one from a key or from the two-key pair a run commits to.
    sih141.protocol.verify.verify : Score a signature against one record.

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
    """

    message_bit: int
    declared_key: PrivateKey

    def __post_init__(self) -> None:
        """Validate the bit and check that the key was drawn for that same bit."""
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
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
            ``{"message_bit": int, "declared_key": {...}}``, the nested value
            being :meth:`sih141.protocol.keys.PrivateKey.to_dict` output.

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
        """
        return {
            "message_bit": self.message_bit,
            "declared_key": self.declared_key.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Signature:
        """Rebuild a signature from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"message_bit"`` and ``"declared_key"``.

        Returns
        -------
        Signature

        Raises
        ------
        KeyError
            If a field is missing.
        ValueError
            If the rebuilt key is tagged with the other message bit.
        """
        return cls(
            message_bit=data["message_bit"],
            declared_key=PrivateKey.from_dict(data["declared_key"]),
        )


def sign(
    message_bit: int,
    keys: PrivateKey | Sequence[PrivateKey],
    params: ProtocolParams | None = None,
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

    Returns
    -------
    Signature
        A frozen declaration of ``(message_bit, key)``. The key is the very
        object passed in, not a copy; :class:`~sih141.protocol.keys.PrivateKey`
        is immutable, so sharing it is safe and identity comparisons hold.

    Raises
    ------
    TypeError
        If ``keys`` is neither a :class:`~sih141.protocol.keys.PrivateKey` nor a
        sequence of them, or ``params`` is given but is not a
        :class:`~sih141.protocol.params.ProtocolParams`.
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

    return Signature(message_bit=bit, declared_key=selected)
