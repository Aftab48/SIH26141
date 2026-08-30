"""Alice's private keys and the quantum public keys derived from them.

One QDS run needs two private keys, one per future message bit ``b in {0, 1}``,
drawn *before* Alice knows which bit she will sign. A private key is a list of
``L`` elements, each a uniformly drawn measurement basis paired with a uniformly
drawn Pauli eigenvalue::

    k_b = [(basis_1, eigenvalue_1), ..., (basis_L, eigenvalue_L)]

The corresponding quantum public key is the product state

.. code-block:: text

    |PK_b> = |basis_1, eigenvalue_1> (x) ... (x) |basis_L, eigenvalue_L>

whose factors are exactly :func:`sih141.core.paulis.eigenstate`.

Two copies is not cloning
-------------------------
Alice sends one copy of the public key to Bob and one to Charlie, and this is the
single most common reviewer objection to the construction, so it is worth
stating precisely: **the no-cloning theorem is not violated, and is not even
engaged.**

No-cloning forbids a machine that maps an *unknown* state ``|psi>`` to
``|psi> (x) |psi>`` for every ``|psi>``. Alice is not that machine. She holds the
*classical description* ``(basis_i, eigenvalue_i)`` -- she drew it herself from
her own generator -- and she runs a state *preparation* device twice on that
description. Preparing two copies of a known state is exactly as ordinary as
printing a document twice, and it is what
:func:`public_key_states` does: it calls :func:`eigenstate` once per recipient,
each call constructing a fresh state from the classical label.

The distinction is operational, not semantic. A cloner would let Bob copy a key
qubit he received without knowing its description, and that is what
unforgeability rests on being impossible; Bob genuinely cannot do it, which is
why his best forging strategy leaks -- at rate ``1/3`` on the positions the
second verifier measured for himself, and ``1/12`` overall once the
symmetrisation exchange is taken into account (see
:attr:`sih141.protocol.params.ProtocolParams.forger_floor`, and
:attr:`~sih141.protocol.params.ProtocolParams.unmatched_noise_rate` for the
former). Nothing about Alice knowing her own key helps him.

Why the product state is never materialised
-------------------------------------------
:func:`public_key_states` returns ``L`` single-qubit
:class:`~qiskit.quantum_info.Statevector` factors, not their tensor product. At
the default ``L = 115200`` the product would be a vector of ``2**115200``
amplitudes. It is also unnecessary: the state is a product, every factor is
teleported independently through its own fresh Bell pair, and every recipient
measures each qubit separately on arrival. Nothing in the protocol ever needs the
joint vector, and building it would be the one step that made an otherwise
linear-cost protocol impossible to simulate.

Notes
-----
Determinism (D3)
    :func:`generate_private_key` and :func:`generate_key_pair` take a keyword-only
    ``rng`` resolved through :func:`sih141.core.rng.resolve_rng`, and consume
    exactly two variates per key element: one to choose the basis, one to choose
    the eigenvalue, in that order. That per-decision discipline matches the core
    layer, so a seeded stream is reproducible across the whole stack.
Qubit ordering (D2)
    Key element ``i`` corresponds to the ``i``-th teleported qubit. The elements
    are an ordered list indexed from 0; no multi-qubit register label is formed
    here, so little-endian bitstring ordering does not arise until
    :mod:`sih141.protocol.distribute`.
No machine learning (D4)
    Uniform sampling and table lookup only.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, overload

import numpy as np
from qiskit.quantum_info import Statevector

from sih141.core.paulis import PauliBasis, eigenstate, eigenstate_label
from sih141.core.rng import resolve_rng
from sih141.protocol.params import (
    ProtocolParams,
    _as_basis,
    _as_eigenvalue,
    _as_message_bit,
)

__all__ = [
    "KeyElement",
    "PrivateKey",
    "generate_private_key",
    "generate_key_pair",
    "public_key_states",
]


@dataclass(frozen=True)
class KeyElement:
    """One position of a private key: a basis and the eigenvalue in it.

    Frozen and hashable. The pair is the complete classical description of one
    qubit of the quantum public key, which is why Alice can prepare that qubit
    as many times as she has recipients (see the module docstring).

    Parameters
    ----------
    basis : PauliBasis or str
        The measurement basis, drawn uniformly from
        :attr:`sih141.protocol.params.ProtocolParams.bases`. Strings are
        accepted and coerced so that a key read back from a JSON log
        round-trips.
    eigenvalue : int
        ``+1`` or ``-1`` -- a Pauli eigenvalue, never a measurement bit.

    Raises
    ------
    ValueError
        If ``basis`` names no basis, or ``eigenvalue`` is not ``+1``/``-1``.
        Booleans are rejected explicitly: ``True`` reads as ``+1`` but means
        "bit 1", which is ``-1``.
    TypeError
        If ``basis`` is neither a :class:`PauliBasis` nor a string.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis
    >>> from sih141.protocol.keys import KeyElement
    >>> element = KeyElement(PauliBasis.Y, -1)
    >>> element.label, element.bit
    ('-i', 1)
    """

    basis: PauliBasis
    eigenvalue: int

    def __post_init__(self) -> None:
        """Coerce ``basis`` to a member and validate ``eigenvalue``."""
        object.__setattr__(self, "basis", _as_basis(self.basis))
        object.__setattr__(self, "eigenvalue", _as_eigenvalue(self.eigenvalue))

    @property
    def bit(self) -> int:
        """int: The classical bit, ``0`` for ``+1`` and ``1`` for ``-1``.

        The project-wide mapping ``bit = (1 - eigenvalue) // 2``, identical to
        :attr:`sih141.core.measure.MeasurementOutcome.bit`, so a declared
        eigenvalue and a measured one compare in whichever representation the
        caller prefers.
        """
        return (1 - self.eigenvalue) // 2

    @property
    def label(self) -> str:
        """str: The ket label of the state, e.g. ``'+'``, ``'-i'``, ``'0'``."""
        return eigenstate_label(self.basis, self.eigenvalue)

    def state(self) -> Statevector:
        """Return the single-qubit public-key state for this element.

        Returns
        -------
        qiskit.quantum_info.Statevector
            A freshly constructed eigenstate; every call builds a new object, so
            two recipients receive two independent preparations rather than two
            references to one.

        Examples
        --------
        >>> from sih141.protocol.keys import KeyElement
        >>> KeyElement("X", -1).state().data.round(6)
        array([ 0.707107+0.j, -0.707107+0.j])
        """
        return eigenstate(self.basis, self.eigenvalue)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            ``{"basis": PauliBasis, "eigenvalue": int}``. ``PauliBasis`` is a
            :class:`enum.StrEnum`, so the result passes to :func:`json.dumps`
            unchanged.
        """
        return {"basis": self.basis, "eigenvalue": self.eigenvalue}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> KeyElement:
        """Rebuild an element from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"basis"`` and ``"eigenvalue"``.

        Returns
        -------
        KeyElement

        Raises
        ------
        KeyError
            If either field is missing.
        """
        return cls(basis=data["basis"], eigenvalue=data["eigenvalue"])


@dataclass(frozen=True)
class PrivateKey:
    """Alice's private key for one message bit: an immutable sequence of elements.

    Frozen, hashable, and it does not expose a mutable container: whatever
    sequence is handed to the constructor is copied into a :class:`tuple`, so a
    caller who keeps and later mutates the list they passed in cannot change a
    key that has already been used to prepare states.

    The key is tagged with the message bit it was drawn for. Distribution runs
    once per future bit, so two independent keys exist at all times, and tagging
    them is what stops :mod:`sih141.protocol.signature` from signing a ``1`` with
    the key whose states were distributed as the ``0``.

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1``, the future message bit this key belongs to.
    elements : sequence of KeyElement
        The ``L`` key positions, in order. Copied into a tuple. Must be
        non-empty.

    Raises
    ------
    ValueError
        If ``message_bit`` is not ``0``/``1`` (booleans rejected), or
        ``elements`` is empty.
    TypeError
        If ``elements`` is not a sequence, or holds anything but
        :class:`KeyElement` instances.

    Attributes
    ----------
    message_bit : int
    elements : tuple of KeyElement

    See Also
    --------
    generate_private_key : Draw one, uniformly, from a seeded generator.
    public_key_states : The quantum public key, factor by factor.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import ProtocolParams
    >>> key = generate_private_key(
    ...     ProtocolParams(key_length=4), 0, rng=np.random.default_rng(20260141)
    ... )
    >>> len(key), key.message_bit
    (4, 0)
    >>> isinstance(key.elements, tuple)
    True
    """

    message_bit: int
    elements: tuple[KeyElement, ...]

    def __post_init__(self) -> None:
        """Validate the tag and copy the elements into an immutable tuple."""
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        elements = self.elements
        if isinstance(elements, (str, bytes)) or not isinstance(
            elements, Sequence
        ):
            raise TypeError(
                f"elements must be a sequence of KeyElement, got "
                f"{type(elements).__name__}"
            )
        frozen = tuple(elements)
        for position, element in enumerate(frozen):
            if not isinstance(element, KeyElement):
                raise TypeError(
                    f"elements[{position}] must be a KeyElement, got "
                    f"{type(element).__name__}. Build one with "
                    f"KeyElement(basis, eigenvalue); a bare (basis, eigenvalue) "
                    f"tuple is not accepted, because it has no validation and "
                    f"would let a measurement bit through as an eigenvalue."
                )
        if not frozen:
            raise ValueError(
                "a private key must have at least one element: with no "
                "elements there are no matched positions, the mismatch rate is "
                "0/0, and no verifier can reach a decision."
            )
        object.__setattr__(self, "elements", frozen)

    # -- sequence protocol -------------------------------------------------- #

    def __len__(self) -> int:
        """int: The key length ``L``."""
        return len(self.elements)

    @overload
    def __getitem__(self, index: int) -> KeyElement: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[KeyElement, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> KeyElement | tuple[KeyElement, ...]:
        """Return element ``index``, or a tuple for a slice.

        Parameters
        ----------
        index : int or slice
            Position in the key, indexed from 0.

        Returns
        -------
        KeyElement or tuple of KeyElement
        """
        return self.elements[index]

    def __iter__(self) -> Iterator[KeyElement]:
        """Iterate over the elements in key order."""
        return iter(self.elements)

    # -- derived views ------------------------------------------------------ #

    @property
    def length(self) -> int:
        """int: The key length ``L``, the same number :func:`len` returns."""
        return len(self.elements)

    @property
    def bases(self) -> tuple[PauliBasis, ...]:
        """tuple of PauliBasis: The declared bases, in key order.

        This is the sequence a verifier compares its own measurement bases
        against to build the matched set ``M_R``.
        """
        return tuple(element.basis for element in self.elements)

    @property
    def eigenvalues(self) -> tuple[int, ...]:
        """tuple of int: The declared eigenvalues, in key order."""
        return tuple(element.eigenvalue for element in self.elements)

    @property
    def bits(self) -> tuple[int, ...]:
        """tuple of int: The declared eigenvalues as classical bits."""
        return tuple(element.bit for element in self.elements)

    @property
    def labels(self) -> tuple[str, ...]:
        """tuple of str: Ket labels of the public-key factors, for logs."""
        return tuple(element.label for element in self.elements)

    def check_against(self, params: ProtocolParams) -> None:
        """Raise if this key does not belong to ``params``.

        Called by the signing and verification paths before a key is used, so
        that a key drawn under one parameter set cannot be verified under
        another -- a mismatch that would otherwise show up only as a strange
        acceptance rate.

        Parameters
        ----------
        params : ProtocolParams
            The parameter set the key is claimed to belong to.

        Raises
        ------
        ValueError
            If the key length differs from ``params.key_length``, or the key
            uses a basis outside ``params.bases``.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.keys import generate_private_key
        >>> from sih141.protocol.params import ProtocolParams
        >>> params = ProtocolParams(key_length=8)
        >>> key = generate_private_key(params, 1, rng=np.random.default_rng(1))
        >>> key.check_against(params) is None
        True
        """
        if len(self.elements) != params.key_length:
            raise ValueError(
                f"private key has {len(self.elements)} elements but "
                f"params.key_length is {params.key_length}. The verifier's "
                f"record has one entry per distributed qubit, so a length "
                f"mismatch means the key and the record came from different "
                f"runs."
            )
        allowed = set(params.bases)
        stray = sorted({b.value for b in self.bases if b not in allowed})
        if stray:
            raise ValueError(
                f"private key uses basis/bases {stray}, which are not in "
                f"params.bases {[b.value for b in params.bases]}. The match "
                f"probability, and therefore every security bound, is computed "
                f"from the declared alphabet."
            )

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the key.

        Returns
        -------
        dict
            ``{"message_bit": int, "elements": [{"basis": ..., "eigenvalue":
            ...}, ...]}``.
        """
        return {
            "message_bit": self.message_bit,
            "elements": [element.to_dict() for element in self.elements],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PrivateKey:
        """Rebuild a key from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"message_bit"`` and ``"elements"``.

        Returns
        -------
        PrivateKey

        Raises
        ------
        KeyError
            If either field is missing.
        """
        return cls(
            message_bit=data["message_bit"],
            elements=tuple(
                KeyElement.from_dict(item) for item in data["elements"]
            ),
        )


def generate_private_key(
    params: ProtocolParams,
    message_bit: int,
    *,
    rng: np.random.Generator | None = None,
) -> PrivateKey:
    """Draw one private key uniformly at random.

    Each of the ``params.key_length`` elements gets a basis drawn uniformly from
    ``params.bases`` and an eigenvalue drawn uniformly from ``{+1, -1}``,
    independently across elements.

    Parameters
    ----------
    params : ProtocolParams
        Supplies the key length and the basis alphabet.
    message_bit : int
        ``0`` or ``1``, the future message bit this key is for.
    rng : numpy.random.Generator or None, optional
        Keyword-only, resolved through :func:`sih141.core.rng.resolve_rng`. Pass
        a seeded generator for a reproducible run; ``None`` draws fresh entropy.

    Returns
    -------
    PrivateKey
        A key of length ``params.key_length`` tagged with ``message_bit``.

    Raises
    ------
    ValueError
        If ``message_bit`` is not ``0``/``1``.
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or ``rng`` is neither
        ``None`` nor a :class:`numpy.random.Generator` (integer seeds are
        refused by :func:`resolve_rng`, by design).

    Notes
    -----
    Exactly two variates are consumed per element, basis first and eigenvalue
    second, so the stream position after the call is deterministic in
    ``params.key_length`` alone. With the default alphabet ``(X, Y, Z)`` the
    basis draw is stream-identical to
    :func:`sih141.core.paulis.random_basis`, which draws one integer from the
    same three-element order; the two are interchangeable and a test pins that.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=6)
    >>> first = generate_private_key(params, 0, rng=np.random.default_rng(7))
    >>> second = generate_private_key(params, 0, rng=np.random.default_rng(7))
    >>> first == second
    True
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    bit = _as_message_bit(message_bit)
    generator = resolve_rng(rng)
    alphabet = params.bases
    elements = []
    for _ in range(params.key_length):
        basis = alphabet[int(generator.integers(len(alphabet)))]
        eigenvalue = 1 - 2 * int(generator.integers(2))
        elements.append(KeyElement(basis, eigenvalue))
    return PrivateKey(message_bit=bit, elements=tuple(elements))


def generate_key_pair(
    params: ProtocolParams, *, rng: np.random.Generator | None = None
) -> tuple[PrivateKey, PrivateKey]:
    """Draw the two independent private keys a run needs, one per message bit.

    Alice must commit to both keys before she knows which bit she will sign --
    distribution happens once per future message bit -- so they are drawn
    together here.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    rng : numpy.random.Generator or None, optional
        Keyword-only, resolved through :func:`sih141.core.rng.resolve_rng`. One
        generator is threaded through both draws, so the keys are independent
        without needing two seeds.

    Returns
    -------
    tuple of PrivateKey
        ``(key_for_bit_0, key_for_bit_1)``. Index it with the message bit:
        ``keys[b]`` is the key for bit ``b``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or ``rng`` is invalid.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> keys = generate_key_pair(
    ...     ProtocolParams(key_length=32), rng=np.random.default_rng(20260141)
    ... )
    >>> [key.message_bit for key in keys]
    [0, 1]
    >>> keys[0].elements == keys[1].elements
    False
    """
    generator = resolve_rng(rng)
    return (
        generate_private_key(params, 0, rng=generator),
        generate_private_key(params, 1, rng=generator),
    )


def public_key_states(key: PrivateKey) -> tuple[Statevector, ...]:
    """Return the quantum public key as its ``L`` single-qubit factors.

    Factor ``i`` is ``eigenstate(key[i].basis, key[i].eigenvalue)``, i.e. the
    ``+1`` or ``-1`` eigenstate of the ``i``-th declared Pauli observable. The
    tensor product of the returned states *is* the public key ``|PK_b>``; it is
    deliberately not formed (see the module docstring).

    Call this once per recipient. Every call constructs fresh
    :class:`~qiskit.quantum_info.Statevector` objects from the classical key
    description, which is a state *preparation*, not a copy of an unknown state,
    and therefore no-cloning does not apply.

    Parameters
    ----------
    key : PrivateKey
        The private key whose public counterpart is wanted.

    Returns
    -------
    tuple of qiskit.quantum_info.Statevector
        ``len(key)`` normalised single-qubit states, in key order.

    Raises
    ------
    TypeError
        If ``key`` is not a :class:`PrivateKey`.

    See Also
    --------
    sih141.core.paulis.eigenstate : The single-qubit constructor used here.
    sih141.core.paulis.verify_eigenstate : Numeric check of the eigen relation.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.paulis import PauliBasis, pauli_matrix
    >>> from sih141.protocol.keys import KeyElement, PrivateKey, public_key_states
    >>> key = PrivateKey(0, (KeyElement(PauliBasis.Y, -1), KeyElement("Z", 1)))
    >>> states = public_key_states(key)
    >>> vector = states[0].data
    >>> bool(np.allclose(pauli_matrix("Y") @ vector, -1 * vector))
    True
    """
    if not isinstance(key, PrivateKey):
        raise TypeError(
            f"key must be a PrivateKey, got {type(key).__name__}. Draw one with "
            f"generate_private_key(params, message_bit, rng=...)."
        )
    return tuple(element.state() for element in key.elements)
