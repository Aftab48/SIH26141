"""Tests for :mod:`sih141.protocol.params`, :mod:`~sih141.protocol.keys` and
:mod:`~sih141.protocol.records`.

Three things are being pinned here, in order of how badly they fail silently.

1. **Parameter validation.** A parameter set with ``s_a >= s_v`` or
   ``s_v >= 1/2`` runs perfectly and proves nothing, so each rejection is
   asserted to fire *and* to name the security property it protects. The
   messages are part of the contract: a judge asking "why does the gap exist?"
   gets the answer from the exception itself.
2. **The eigenstate correspondence.** ``public_key_states(key)[i]`` is checked
   against the Pauli algebra directly -- ``P|psi> = lambda|psi>`` with ``P`` the
   matrix of the ``i``-th declared basis -- not merely against
   :func:`sih141.core.paulis.eigenstate`, so that an off-by-one between key
   elements and states would fail even if both sides used the same helper.
3. **Immutability.** Frozen instances, tuple storage, and -- the one that a
   naive dataclass gets wrong -- a list handed to the constructor is *copied*,
   so a caller who mutates it afterwards cannot retroactively change a key or a
   record that has already been used.
4. **The recipient boundary.** :class:`~sih141.protocol.records.RecipientView`
   is a threat-model statement written as a type: one recipient's holdings, and
   no path from them to the other recipient's. "No path" is checked by crawling
   the object graph out of a view, and -- because a crawl that found nothing
   would pass for every possible defect -- the same crawl is first pointed at
   the session's own mapping and asserted to reach both recipients' logs and
   both private keys.

Determinism (D3) is checked by seeding: identical seeds give identical keys, and
the basis draw is asserted to be stream-identical to
:func:`sih141.core.paulis.random_basis` on the default alphabet.
:func:`~sih141.protocol.keys.key_from_record` is asserted to consume none.
"""

from __future__ import annotations

import dataclasses
import json
import math
import types
from collections import Counter
from collections.abc import Mapping

import numpy as np
import pytest
from qiskit.quantum_info import Statevector

from sih141.core.paulis import (
    PauliBasis,
    eigenstate,
    eigenstate_label,
    pauli_matrix,
    random_basis,
)
from sih141.protocol import (
    COMPLIANT_FORGER_RATE_THREE_BASIS,
    UNSYMMETRISED_FORGER_RATE_THREE_BASIS,
    DEFAULT_BASES,
    DEFAULT_PARAMS,
    DEFAULT_S_A,
    DEFAULT_S_V,
    DEMO_PARAMS,
    VERIFIERS,
    KeyElement,
    Party,
    PrivateKey,
    ProtocolParams,
    QDSSession,
    RecipientRecord,
    RecipientView,
    RecordEntry,
    Signature,
    generate_key_pair,
    generate_private_key,
    key_from_record,
    public_key_states,
    recipient_views,
)

TOL = 1e-12

SEED = 20260141

ALL_ELEMENTS = [
    (basis, eigenvalue)
    for basis in (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)
    for eigenvalue in (1, -1)
]


def _params(length: int = 8, **changes: object) -> ProtocolParams:
    """Build a small valid parameter set for a test."""
    return ProtocolParams(key_length=length, **changes)  # type: ignore[arg-type]


# ==========================================================================
# ProtocolParams -- construction and derived quantities
# ==========================================================================


def test_params_stores_exactly_what_it_was_given() -> None:
    """Fields round-trip, and ``bases`` is stored as a tuple."""
    params = ProtocolParams(
        key_length=99,
        s_a=0.01,
        s_v=0.06,
        bases=[PauliBasis.Z, PauliBasis.X],
    )
    assert params.key_length == 99
    assert params.s_a == pytest.approx(0.01)
    assert params.s_v == pytest.approx(0.06)
    assert params.bases == (PauliBasis.Z, PauliBasis.X)
    assert isinstance(params.bases, tuple)
    assert params.allow_forgeable is False


def test_params_is_frozen_and_hashable() -> None:
    """Frozen so a run cannot be re-parameterised half-way through."""
    params = _params()
    with pytest.raises(dataclasses.FrozenInstanceError):
        params.key_length = 10  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        params.s_v = 0.4  # type: ignore[misc]
    assert hash(params) == hash(_params())
    assert {params, _params()} == {params}


def test_params_copies_a_mutable_bases_list() -> None:
    """A list passed in is copied, not aliased."""
    alphabet = [PauliBasis.X, PauliBasis.Y, PauliBasis.Z]
    params = ProtocolParams(key_length=4, bases=alphabet)
    alphabet.clear()
    assert params.bases == (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)


def test_params_coerces_string_bases() -> None:
    """Bases read back from a JSON config arrive as plain strings."""
    params = ProtocolParams(key_length=4, bases=["z", "X"])
    assert params.bases == (PauliBasis.Z, PauliBasis.X)


def test_match_probability_and_expected_matched() -> None:
    """m = L / |B|; only matched positions carry information."""
    params = ProtocolParams(key_length=6912)
    assert params.match_probability == pytest.approx(1.0 / 3.0)
    assert params.expected_matched == pytest.approx(2304.0)
    two_basis = ProtocolParams(
        key_length=100, bases=(PauliBasis.X, PauliBasis.Z)
    )
    assert two_basis.match_probability == pytest.approx(0.5)
    assert two_basis.expected_matched == pytest.approx(50.0)


def test_gap_is_positive_and_equals_the_threshold_difference() -> None:
    """The gap is what both transferability and non-repudiation are bought with."""
    params = ProtocolParams(key_length=8, s_a=0.02, s_v=0.08)
    assert params.gap == pytest.approx(0.06)
    assert params.gap > 0.0


def test_forger_floor_is_one_twelfth_after_symmetrisation() -> None:
    """``(|B| - 1) / (2|B|(|B| + 1))``, derived here rather than read off.

    A recipient forger declares, at every position, what he knows of the other
    verifier's log. After the symmetrisation exchange:

    * half the positions were supplied *by him*, so his declaration matches with
      probability 1 and mismatches with probability 0;
    * on the other half the target holds his own measurement, matched with
      probability ``1/|B|``, and given a match the two disagree with probability
      ``(1 - 1/|B|)/2``.

    Scored fraction ``(|B| + 1)/(2|B|)``, mismatch rate
    ``(|B| - 1)/(2|B|(|B| + 1))`` -- ``1/12`` for three bases, and ``1/12``
    again for two, since fewer bases raise the per-match rate but shrink the
    matched set by the same factor.
    """
    three = ProtocolParams(key_length=8)
    assert three.forger_floor == pytest.approx(1.0 / 12.0)
    assert three.forger_scored_fraction == pytest.approx(2.0 / 3.0)
    assert COMPLIANT_FORGER_RATE_THREE_BASIS == pytest.approx(1.0 / 12.0)

    two = ProtocolParams(key_length=8, bases=(PauliBasis.X, PauliBasis.Z))
    assert two.forger_floor == pytest.approx(1.0 / 12.0)
    assert two.forger_scored_fraction == pytest.approx(0.75)

    # The pre-symmetrisation rate is a different quantity and keeps its own
    # name: it is also what counting unmatched positions costs.
    assert three.unmatched_noise_rate == pytest.approx(1.0 / 3.0)
    assert two.unmatched_noise_rate == pytest.approx(0.25)
    assert UNSYMMETRISED_FORGER_RATE_THREE_BASIS == pytest.approx(1.0 / 3.0)


def test_s_v_at_or_above_the_forger_floor_is_refused_unless_opted_in() -> None:
    """The floor is enforced, not merely documented.

    ``s_v >= forger_floor`` accepts a recipient forgery outright, so the
    constructor refuses it. A Phase 3 sweep past the floor says so with
    ``allow_forgeable=True``; the flag is a field, so it is part of the
    parameter set's identity and reaches every transcript the run produces.
    That is what distinguishes an intentional insecure sweep from a typo.
    """
    with pytest.raises(ValueError) as excinfo:
        ProtocolParams(key_length=600, s_a=0.02, s_v=0.2)
    message = str(excinfo.value)
    assert "strictly below the forger floor" in message
    assert "UNFORGEABILITY" in message
    assert "allow_forgeable=True" in message

    forgeable = ProtocolParams(
        key_length=600, s_a=0.02, s_v=0.2, allow_forgeable=True
    )
    assert forgeable.s_v == 0.2
    assert forgeable.is_forgeable
    assert not ProtocolParams(key_length=600).is_forgeable

    # Exactly at the floor is refused too: the bound is strict.
    with pytest.raises(ValueError, match="forger floor"):
        ProtocolParams(key_length=600, s_a=0.02, s_v=1.0 / 12.0)


def test_allow_forgeable_must_be_a_bool() -> None:
    """It is an explicit opt-in to an insecure set, not a tuning knob."""
    with pytest.raises(TypeError, match="allow_forgeable must be a bool"):
        ProtocolParams(key_length=8, allow_forgeable=1)  # type: ignore[arg-type]


def test_threshold_for_maps_bob_to_s_a_and_charlie_to_s_v() -> None:
    """Bob applies the tight cut, Charlie the loose one."""
    params = ProtocolParams(key_length=8, s_a=0.02, s_v=0.08)
    assert params.threshold_for(Party.BOB) == pytest.approx(0.02)
    assert params.threshold_for(Party.CHARLIE) == pytest.approx(0.08)
    assert params.threshold_for("bob") == params.s_a
    assert params.threshold_for("CHARLIE") == params.s_v
    assert params.threshold_for(Party.BOB) < params.threshold_for(Party.CHARLIE)


def test_threshold_for_alice_is_refused_with_a_reason() -> None:
    """Alice signs; she keeps no record, so she has no mismatch rate to cut."""
    with pytest.raises(ValueError) as excinfo:
        _params().threshold_for(Party.ALICE)
    message = str(excinfo.value).lower()
    assert "signer" in message
    assert "verifier" in message


def test_threshold_for_rejects_a_non_party() -> None:
    """A typo in a party name must fail loudly."""
    with pytest.raises(ValueError, match="unknown party"):
        _params().threshold_for("Dave")
    with pytest.raises(TypeError, match="party must be a Party"):
        _params().threshold_for(3)  # type: ignore[arg-type]


def test_with_changes_revalidates() -> None:
    """The derived set is a fresh validated instance, not a patched copy."""
    params = _params()
    assert params.with_changes(key_length=32).key_length == 32
    with pytest.raises(ValueError, match="strictly less than s_v"):
        params.with_changes(s_a=0.9)


# ==========================================================================
# ProtocolParams -- the rejections, and the reasons they give
# ==========================================================================


def test_rejects_s_a_greater_or_equal_s_v_citing_both_properties() -> None:
    """s_a >= s_v inverts transferability and non-repudiation; say so."""
    for s_a, s_v in ((0.2, 0.2), (0.3, 0.1), (0.49, 0.4)):
        with pytest.raises(ValueError) as excinfo:
            ProtocolParams(key_length=8, s_a=s_a, s_v=s_v)
        message = str(excinfo.value)
        assert "s_a must be strictly less than s_v" in message
        assert "TRANSFERABILITY" in message
        assert "NON-REPUDIATION" in message


def test_rejects_s_v_at_or_above_one_half_citing_unforgeability() -> None:
    """A threshold at 1/2 accepts pure noise."""
    for s_v in (0.5, 0.6, 1.0, 12.0):
        with pytest.raises(ValueError) as excinfo:
            ProtocolParams(key_length=8, s_a=0.01, s_v=s_v)
        message = str(excinfo.value)
        assert "s_v must be strictly less than 0.5" in message
        assert "UNFORGEABILITY" in message
        # The message must also name the tighter bound that really binds.
        assert "0.333" in message or "1/" in message


def test_s_v_just_below_one_half_is_accepted_only_when_opted_in() -> None:
    """The 0.5 bound is strict, but the forger floor binds first.

    ``0.4999999`` clears the crude ``s_v < 1/2`` check and is still far above
    the ``1/12`` floor, so it needs the explicit opt-in -- which is the whole
    point of having both checks.
    """
    params = ProtocolParams(
        key_length=8, s_a=0.1, s_v=0.4999999, allow_forgeable=True
    )
    assert params.s_v < 0.5
    assert params.is_forgeable


def test_rejects_non_positive_key_length_citing_the_exponential_bound() -> None:
    """L <= 0 leaves nothing to verify and no bound at all."""
    for length in (0, -1, -6912):
        with pytest.raises(ValueError) as excinfo:
            ProtocolParams(key_length=length)
        message = str(excinfo.value)
        assert "key_length must be positive" in message
        assert "matched" in message


def test_rejects_non_integer_and_boolean_key_length() -> None:
    """A fractional or boolean key length is a config error, not a rounding job."""
    with pytest.raises(ValueError, match="positive integer"):
        ProtocolParams(key_length=8.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="boolean"):
        ProtocolParams(key_length=True)  # type: ignore[arg-type]


def test_rejects_negative_threshold() -> None:
    """A mismatch rate lives in [0, 1); a negative cut rejects even r = 0."""
    with pytest.raises(ValueError, match="s_a must be non-negative"):
        ProtocolParams(key_length=8, s_a=-0.01, s_v=0.2)
    with pytest.raises(ValueError, match="s_v must be non-negative"):
        ProtocolParams(key_length=8, s_a=0.1, s_v=-0.2)


def test_rejects_boolean_and_non_real_thresholds() -> None:
    """Booleans and strings are refused before they are silently floated."""
    with pytest.raises(TypeError, match="boolean"):
        ProtocolParams(key_length=8, s_a=False, s_v=0.2)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="real number"):
        ProtocolParams(key_length=8, s_a="0.1", s_v=0.2)  # type: ignore[arg-type]


def test_rejects_non_finite_thresholds() -> None:
    """NaN would make every comparison False and every party reject silently."""
    with pytest.raises(ValueError, match="finite"):
        ProtocolParams(key_length=8, s_a=math.nan, s_v=0.06)
    with pytest.raises(ValueError, match="finite"):
        ProtocolParams(key_length=8, s_a=0.1, s_v=math.inf)


def test_s_a_may_be_zero() -> None:
    """The specification allows 0 <= s_a; a noiseless honest run gives r = 0."""
    params = ProtocolParams(key_length=8, s_a=0.0, s_v=0.06)
    assert params.s_a == 0.0
    assert params.gap == pytest.approx(0.06)


def test_rejects_empty_duplicate_and_single_basis_alphabets() -> None:
    """Each failure names what it breaks."""
    with pytest.raises(ValueError, match="must not be empty"):
        ProtocolParams(key_length=8, bases=())
    with pytest.raises(ValueError) as excinfo:
        ProtocolParams(key_length=8, bases=(PauliBasis.X, PauliBasis.X))
    assert "must not repeat" in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        ProtocolParams(key_length=8, bases=(PauliBasis.Z,))
    assert "UNFORGEABILITY" in str(excinfo.value)


def test_rejects_a_bare_string_alphabet() -> None:
    """"XYZ" iterates character by character and would silently work."""
    with pytest.raises(TypeError, match="not the string"):
        ProtocolParams(key_length=8, bases="XYZ")  # type: ignore[arg-type]


def test_rejects_an_unknown_basis_label() -> None:
    """A typo in a config alphabet must fail at load, not at measurement."""
    with pytest.raises(ValueError, match="must name a measurement basis"):
        ProtocolParams(key_length=8, bases=["X", "W"])


# ==========================================================================
# ProtocolParams -- defaults and serialisation
# ==========================================================================


def test_default_params_satisfy_the_specification_inequalities() -> None:
    """0 <= s_a < s_v < 1/2 for both shipped sets."""
    for params in (DEFAULT_PARAMS, DEMO_PARAMS):
        assert 0.0 <= params.s_a < params.s_v < 0.5
        assert params.key_length > 0
        assert params.bases == DEFAULT_BASES


def test_default_thresholds_are_the_documented_numbers() -> None:
    """s_a = 1/64 (a noise budget), s_v = 1/16 (below the 1/12 forger floor)."""
    assert DEFAULT_S_A == pytest.approx(1.0 / 64.0)
    assert DEFAULT_S_V == pytest.approx(1.0 / 16.0)
    assert DEFAULT_PARAMS.s_a == DEFAULT_S_A
    assert DEFAULT_PARAMS.s_v == DEFAULT_S_V
    assert DEMO_PARAMS.s_a == DEFAULT_S_A
    assert DEMO_PARAMS.s_v == DEFAULT_S_V


def test_default_s_v_sits_below_the_compliant_forger_floor() -> None:
    """Three quarters of the floor: the documented margin, asserted.

    Not a factor of two any more. The floor is optimal over all POVMs (see the
    params module docstring), so the margin is sized by the exponent it buys --
    ``D(1/16 || 1/12)`` -- rather than as insurance against a cheating
    measurement that does not exist.
    """
    assert DEFAULT_PARAMS.s_v == pytest.approx(
        0.75 * DEFAULT_PARAMS.forger_floor
    )
    assert DEFAULT_PARAMS.s_v < DEFAULT_PARAMS.forger_floor
    assert not DEFAULT_PARAMS.is_forgeable


def test_default_key_length_delivers_the_documented_repudiation_bound() -> None:
    """The symmetrisation bound is 6.9e-10 at the default and useless at the demo.

    Recomputed here from the expression in the params docstring rather than read
    off ``analysis.averaged_repudiation_bound``, so the documented figure and the
    shipped implementation are two independent statements that have to agree::

        (1 - 1/n)**L + (1 - 1/n + exp(-gap**2 / 8)/n)**(2L)

    with ``M ~ Binomial(2L, 1/n)`` the total matched records held by the pair.

    That last line is an assumption, not a fact: ``M`` is binomial only while the
    declared bases are independent of the recipients' logged bases, which a
    signer reading both raw logs is not. So ``6.9e-10`` is the *averaged* figure
    and carries that hypothesis with it -- see ``analysis`` section 4b-ii and
    ``docs/PHASE2.md`` section 6b. What this test pins is that the key length
    still delivers the documented number under the documented hypothesis; the
    per-run guarantee is ``analysis.repudiation_bound`` at the observed count.
    """

    def bound(params: ProtocolParams) -> float:
        stay = 1.0 - params.match_probability
        factor = stay + params.match_probability * math.exp(
            -params.gap**2 / 8.0
        )
        return (
            math.exp(2 * params.key_length * math.log(factor))
            + stay**params.key_length
        )

    assert bound(DEFAULT_PARAMS) == pytest.approx(6.9e-10, rel=0.05)
    assert bound(DEFAULT_PARAMS) < 1e-9
    assert bound(DEMO_PARAMS) > 0.1


def test_default_key_length_is_a_multiple_of_the_alphabet_size() -> None:
    """So the expected matched count is an integer, as documented."""
    assert DEFAULT_PARAMS.key_length % len(DEFAULT_PARAMS.bases) == 0
    assert DEFAULT_PARAMS.expected_matched == int(
        DEFAULT_PARAMS.expected_matched
    )


def test_params_round_trip_through_json() -> None:
    """to_dict/from_dict survives a real JSON encode-decode cycle."""
    params = ProtocolParams(key_length=48, s_a=0.02, s_v=0.06)
    restored = ProtocolParams.from_dict(json.loads(json.dumps(params.to_dict())))
    assert restored == params
    assert hash(restored) == hash(params)

    # The insecure opt-in is part of the identity and survives the trip, so a
    # stored transcript still says the run was known to be forgeable.
    forgeable = ProtocolParams(
        key_length=48, s_a=0.02, s_v=0.25, allow_forgeable=True
    )
    assert (
        ProtocolParams.from_dict(json.loads(json.dumps(forgeable.to_dict())))
        == forgeable
    )
    assert forgeable != params


def test_from_dict_rejects_unknown_and_missing_fields() -> None:
    """A mistyped config key must not silently leave a threshold at its default."""
    with pytest.raises(ValueError, match="unknown ProtocolParams field"):
        ProtocolParams.from_dict({"key_length": 8, "s_x": 0.1})
    with pytest.raises(ValueError, match="requires 'key_length'"):
        ProtocolParams.from_dict({"s_a": 0.1, "s_v": 0.2})


def test_from_dict_falls_back_to_the_documented_defaults() -> None:
    """Only key_length is mandatory."""
    params = ProtocolParams.from_dict({"key_length": 30})
    assert params == ProtocolParams(key_length=30)


# ==========================================================================
# Party
# ==========================================================================


def test_party_is_a_str_enum_and_json_serialisable() -> None:
    """Matches the PauliBasis/BellState contract fixed in Phase 1."""
    assert Party.BOB == "Bob"
    assert str(Party.CHARLIE) == "Charlie"
    assert json.dumps({Party.BOB: 1, Party.CHARLIE: 2}) == (
        '{"Bob": 1, "Charlie": 2}'
    )
    assert json.dumps([Party.ALICE]) == '["Alice"]'


def test_verifiers_are_bob_then_charlie_and_alice_is_not_one() -> None:
    """Charlie is required: transferability needs a second verifier."""
    assert VERIFIERS == (Party.BOB, Party.CHARLIE)
    assert all(party.is_verifier for party in VERIFIERS)
    assert not Party.ALICE.is_verifier


# ==========================================================================
# KeyElement
# ==========================================================================


@pytest.mark.parametrize(("basis", "eigenvalue"), ALL_ELEMENTS)
def test_key_element_bit_label_and_state_agree_with_the_core(
    basis: PauliBasis, eigenvalue: int
) -> None:
    """bit = (1 - eigenvalue)//2, and the state is the core eigenstate."""
    element = KeyElement(basis, eigenvalue)
    assert element.bit == (1 - eigenvalue) // 2
    assert element.bit in (0, 1)
    assert element.label == eigenstate_label(basis, eigenvalue)
    assert np.array_equal(
        element.state().data, eigenstate(basis, eigenvalue).data
    )


def test_key_element_is_frozen_hashable_and_coerces_string_bases() -> None:
    """Immutable, and a basis read back from JSON arrives as a string."""
    element = KeyElement("y", -1)
    assert element.basis is PauliBasis.Y
    with pytest.raises(dataclasses.FrozenInstanceError):
        element.eigenvalue = 1  # type: ignore[misc]
    assert hash(element) == hash(KeyElement(PauliBasis.Y, -1))


def test_key_element_rejects_bits_masquerading_as_eigenvalues() -> None:
    """0 is a bit, not an eigenvalue; True is the same trap with a costume on."""
    with pytest.raises(ValueError) as excinfo:
        KeyElement(PauliBasis.X, 0)
    assert "1 - 2 * bit" in str(excinfo.value)
    with pytest.raises(ValueError, match="boolean"):
        KeyElement(PauliBasis.X, True)
    with pytest.raises(ValueError, match="boolean"):
        KeyElement(PauliBasis.X, False)


def test_key_element_round_trips_through_json() -> None:
    """StrEnum bases encode without a bespoke encoder."""
    element = KeyElement(PauliBasis.Z, -1)
    restored = KeyElement.from_dict(json.loads(json.dumps(element.to_dict())))
    assert restored == element


# ==========================================================================
# PrivateKey -- structure and immutability
# ==========================================================================


def test_private_key_behaves_as_an_immutable_sequence() -> None:
    """len/index/slice/iterate, and every view is a tuple."""
    elements = [KeyElement(basis, value) for basis, value in ALL_ELEMENTS]
    key = PrivateKey(0, elements)
    assert len(key) == 6
    assert key.length == 6
    assert key[0] == elements[0]
    assert key[-1] == elements[-1]
    assert key[1:3] == tuple(elements[1:3])
    assert list(key) == elements
    assert isinstance(key.elements, tuple)
    assert isinstance(key.bases, tuple)
    assert isinstance(key.eigenvalues, tuple)


def test_private_key_does_not_expose_the_list_it_was_given() -> None:
    """The single most important immutability property: the input is copied.

    A key that has already been used to prepare and teleport states must not
    change afterwards, so mutating the caller's list must be a no-op.
    """
    elements = [KeyElement(PauliBasis.X, 1), KeyElement(PauliBasis.Z, -1)]
    key = PrivateKey(1, elements)
    snapshot = key.elements
    elements.append(KeyElement(PauliBasis.Y, 1))
    elements[0] = KeyElement(PauliBasis.Z, -1)
    assert key.elements == snapshot
    assert len(key) == 2
    assert key[0] == KeyElement(PauliBasis.X, 1)


def test_private_key_is_frozen_and_hashable() -> None:
    """Frozen instance, and hashable because every field is immutable."""
    key = PrivateKey(0, (KeyElement(PauliBasis.X, 1),))
    with pytest.raises(dataclasses.FrozenInstanceError):
        key.message_bit = 1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        key.elements = ()  # type: ignore[misc]
    twin = PrivateKey(0, [KeyElement(PauliBasis.X, 1)])
    assert key == twin
    assert hash(key) == hash(twin)
    assert {key, twin} == {key}


def test_private_key_derived_views_line_up_element_by_element() -> None:
    """bases/eigenvalues/bits/labels are parallel to elements."""
    key = PrivateKey(1, [KeyElement(basis, value) for basis, value in ALL_ELEMENTS])
    assert key.bases == tuple(basis for basis, _ in ALL_ELEMENTS)
    assert key.eigenvalues == tuple(value for _, value in ALL_ELEMENTS)
    assert key.bits == tuple((1 - value) // 2 for _, value in ALL_ELEMENTS)
    assert key.labels == tuple(
        eigenstate_label(basis, value) for basis, value in ALL_ELEMENTS
    )


def test_private_key_rejects_a_bad_message_bit() -> None:
    """Exactly two key families exist; booleans are refused explicitly."""
    element = (KeyElement(PauliBasis.X, 1),)
    with pytest.raises(ValueError, match="must be 0 or 1"):
        PrivateKey(2, element)
    with pytest.raises(ValueError, match="boolean"):
        PrivateKey(True, element)  # type: ignore[arg-type]


def test_private_key_rejects_empty_and_malformed_element_lists() -> None:
    """0/0 is not a mismatch rate, and a bare tuple has no validation."""
    with pytest.raises(ValueError, match="at least one element"):
        PrivateKey(0, ())
    with pytest.raises(TypeError, match="must be a KeyElement"):
        PrivateKey(0, [(PauliBasis.X, 1)])  # type: ignore[list-item]
    with pytest.raises(TypeError, match="must be a sequence"):
        PrivateKey(0, 5)  # type: ignore[arg-type]


def test_private_key_round_trips_through_json() -> None:
    """A key logged to disk comes back identical."""
    key = PrivateKey(1, [KeyElement(basis, value) for basis, value in ALL_ELEMENTS])
    restored = PrivateKey.from_dict(json.loads(json.dumps(key.to_dict())))
    assert restored == key


def test_check_against_catches_length_and_alphabet_mismatches() -> None:
    """A key from another run must not be verifiable under these parameters."""
    params = ProtocolParams(key_length=3)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    assert key.check_against(params) is None
    with pytest.raises(ValueError, match="params.key_length"):
        key.check_against(ProtocolParams(key_length=4))
    narrow = ProtocolParams(key_length=2, bases=(PauliBasis.X, PauliBasis.Y))
    off_alphabet = PrivateKey(
        0, [KeyElement(PauliBasis.Z, 1), KeyElement(PauliBasis.X, -1)]
    )
    with pytest.raises(ValueError, match="not in params.bases"):
        off_alphabet.check_against(narrow)


# ==========================================================================
# generate_private_key -- distribution, determinism, D3
# ==========================================================================


def test_generated_key_has_the_right_shape_and_alphabet() -> None:
    """Length L, bases from params.bases, eigenvalues in {+1, -1}."""
    params = ProtocolParams(key_length=64)
    key = generate_private_key(params, 1, rng=np.random.default_rng(SEED))
    assert len(key) == 64
    assert key.message_bit == 1
    assert set(key.bases) <= set(params.bases)
    assert set(key.eigenvalues) <= {1, -1}
    assert all(isinstance(value, int) for value in key.eigenvalues)


def test_generated_key_respects_a_restricted_alphabet() -> None:
    """Only bases in params.bases are ever drawn."""
    params = ProtocolParams(key_length=200, bases=(PauliBasis.X, PauliBasis.Z))
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    assert set(key.bases) == {PauliBasis.X, PauliBasis.Z}


def test_generation_is_reproducible_under_a_seeded_generator() -> None:
    """D3: same seed, same key; different seed, different key."""
    params = ProtocolParams(key_length=128)
    first = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    second = generate_private_key(params, 0, rng=np.random.default_rng(SEED))
    other = generate_private_key(params, 0, rng=np.random.default_rng(SEED + 1))
    assert first == second
    assert first != other


def test_generation_consumes_two_variates_per_element_basis_first() -> None:
    """The stream discipline is pinned, not incidental.

    With the default alphabet the basis draw is exactly what
    :func:`sih141.core.paulis.random_basis` does -- one integer over (X, Y, Z) --
    so the two are interchangeable, and the eigenvalue draw follows it.
    """
    params = ProtocolParams(key_length=3)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))

    reference = np.random.default_rng(SEED)
    expected_bases = []
    expected_values = []
    for _ in range(3):
        expected_bases.append(random_basis(rng=reference))
        expected_values.append(1 - 2 * int(reference.integers(2)))
    assert key.bases == tuple(expected_bases)
    assert key.eigenvalues == tuple(expected_values)


def test_generation_advances_one_shared_stream() -> None:
    """Two keys drawn from one generator differ; the generator is not restarted."""
    params = ProtocolParams(key_length=64)
    generator = np.random.default_rng(SEED)
    first = generate_private_key(params, 0, rng=generator)
    second = generate_private_key(params, 1, rng=generator)
    assert first.elements != second.elements


def test_generation_rejects_an_integer_seed() -> None:
    """D3: seeds are converted once, at the boundary, never at a call site."""
    with pytest.raises(TypeError, match="Integer seeds are rejected"):
        generate_private_key(_params(), 0, rng=SEED)  # type: ignore[arg-type]


def test_generation_without_an_rng_still_works() -> None:
    """rng=None is the documented fresh-entropy path, not a bug."""
    key = generate_private_key(ProtocolParams(key_length=16), 0)
    assert len(key) == 16


def test_generation_rejects_bad_params_and_message_bit() -> None:
    """Actionable errors on the two easy call-site mistakes."""
    with pytest.raises(TypeError, match="params must be a ProtocolParams"):
        generate_private_key(8, 0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="must be 0 or 1"):
        generate_private_key(_params(), 7)


def test_generated_bases_and_eigenvalues_are_uniform() -> None:
    """Uniformity is a security assumption, so it is measured, not assumed.

    Five-sigma bands from the binomial standard deviations at this sample size;
    a biased sampler would shift the match probability and silently invalidate
    every bound in params.py without failing any other assertion.
    """
    count = 6000
    params = ProtocolParams(key_length=count)
    key = generate_private_key(params, 0, rng=np.random.default_rng(SEED))

    basis_counts = Counter(key.bases)
    expected_basis = count / 3.0
    basis_sigma = math.sqrt(count * (1 / 3) * (2 / 3))
    for basis in DEFAULT_BASES:
        assert abs(basis_counts[basis] - expected_basis) < 5 * basis_sigma

    value_counts = Counter(key.eigenvalues)
    value_sigma = math.sqrt(count * 0.25)
    for value in (1, -1):
        assert abs(value_counts[value] - count / 2.0) < 5 * value_sigma


def test_bases_and_eigenvalues_are_drawn_independently() -> None:
    """No basis correlates with a sign; each of the six states is ~1/6."""
    count = 6000
    key = generate_private_key(
        ProtocolParams(key_length=count), 0, rng=np.random.default_rng(SEED)
    )
    pairs = Counter(zip(key.bases, key.eigenvalues, strict=True))
    assert len(pairs) == 6
    expected = count / 6.0
    sigma = math.sqrt(count * (1 / 6) * (5 / 6))
    for combination in ALL_ELEMENTS:
        assert abs(pairs[combination] - expected) < 5 * sigma


# ==========================================================================
# generate_key_pair
# ==========================================================================


def test_key_pair_is_tagged_and_indexable_by_the_message_bit() -> None:
    """keys[b] is the key for bit b."""
    keys = generate_key_pair(
        ProtocolParams(key_length=32), rng=np.random.default_rng(SEED)
    )
    assert len(keys) == 2
    for bit, key in enumerate(keys):
        assert key.message_bit == bit
        assert len(key) == 32


def test_key_pair_keys_are_independent() -> None:
    """Alice commits to both before knowing which bit she will sign."""
    keys = generate_key_pair(
        ProtocolParams(key_length=64), rng=np.random.default_rng(SEED)
    )
    assert keys[0].elements != keys[1].elements


def test_key_pair_is_reproducible() -> None:
    """One seed, one stream, both keys."""
    params = ProtocolParams(key_length=16)
    first = generate_key_pair(params, rng=np.random.default_rng(SEED))
    second = generate_key_pair(params, rng=np.random.default_rng(SEED))
    assert first == second


def test_key_pair_matches_two_sequential_single_draws() -> None:
    """The pair is exactly bit 0 then bit 1 off one shared generator."""
    params = ProtocolParams(key_length=8)
    pair = generate_key_pair(params, rng=np.random.default_rng(SEED))
    generator = np.random.default_rng(SEED)
    expected = (
        generate_private_key(params, 0, rng=generator),
        generate_private_key(params, 1, rng=generator),
    )
    assert pair == expected


# ==========================================================================
# public_key_states -- the eigenstate correspondence
# ==========================================================================


def test_public_key_state_i_is_the_eigenstate_of_declared_basis_i() -> None:
    """The required check: P_i |psi_i> = lambda_i |psi_i>, position by position.

    Verified against the Pauli *matrices* rather than against
    :func:`sih141.core.paulis.eigenstate`, so that an off-by-one between key
    elements and returned states would fail here even though both sides would
    otherwise agree with each other.
    """
    key = PrivateKey(0, [KeyElement(basis, value) for basis, value in ALL_ELEMENTS])
    states = public_key_states(key)
    assert len(states) == len(key)
    for element, state in zip(key, states, strict=True):
        vector = state.data
        observable = pauli_matrix(element.basis.value)
        assert np.allclose(
            observable @ vector, element.eigenvalue * vector, atol=TOL, rtol=0.0
        )
        # And it is the *other* eigenvalue's eigenvector that fails, so the
        # sign convention is pinned rather than merely self-consistent.
        assert not np.allclose(
            observable @ vector, -element.eigenvalue * vector, atol=TOL, rtol=0.0
        )


def test_public_key_states_are_a_random_key_read_positionally() -> None:
    """Same check on a generated key, against a freshly built expectation."""
    params = ProtocolParams(key_length=48)
    key = generate_private_key(params, 1, rng=np.random.default_rng(SEED))
    states = public_key_states(key)
    assert len(states) == 48
    for index, state in enumerate(states):
        expected = eigenstate(key[index].basis, key[index].eigenvalue)
        assert np.array_equal(state.data, expected.data)


def test_public_key_states_are_normalised_single_qubit_statevectors() -> None:
    """Every factor is a valid one-qubit state."""
    key = generate_private_key(
        ProtocolParams(key_length=24), 0, rng=np.random.default_rng(SEED)
    )
    for state in public_key_states(key):
        assert isinstance(state, Statevector)
        assert state.dims() == (2,)
        assert state.data.shape == (2,)
        assert float(np.vdot(state.data, state.data).real) == pytest.approx(
            1.0, abs=TOL
        )


def test_two_calls_give_two_independent_preparations_not_one_object() -> None:
    """Bob's copy and Charlie's copy are separate preparations.

    This is the no-cloning point in code: Alice runs the preparation twice from
    the classical description, so the two recipients never share an object and
    nothing is copied from an unknown state.
    """
    key = generate_private_key(
        ProtocolParams(key_length=8), 0, rng=np.random.default_rng(SEED)
    )
    for_bob = public_key_states(key)
    for_charlie = public_key_states(key)
    assert len(for_bob) == len(for_charlie) == 8
    for bob_state, charlie_state in zip(for_bob, for_charlie, strict=True):
        assert bob_state is not charlie_state
        assert np.array_equal(bob_state.data, charlie_state.data)


def test_public_key_states_rejects_a_non_key() -> None:
    """The argument is a PrivateKey, not a bare list of elements."""
    with pytest.raises(TypeError, match="key must be a PrivateKey"):
        public_key_states([KeyElement(PauliBasis.X, 1)])  # type: ignore[arg-type]


# ==========================================================================
# RecordEntry
# ==========================================================================


@pytest.mark.parametrize(("basis", "eigenvalue"), ALL_ELEMENTS)
def test_record_entry_bit_mapping_matches_the_project_convention(
    basis: PauliBasis, eigenvalue: int
) -> None:
    """+1 -> bit 0, -1 -> bit 1, the same mapping as MeasurementOutcome."""
    entry = RecordEntry(0, basis, eigenvalue)
    assert entry.bit == (1 - eigenvalue) // 2
    assert entry.basis is basis
    assert entry.eigenvalue == eigenvalue


def test_record_entry_is_frozen_and_hashable() -> None:
    """A logged measurement is not editable after the fact."""
    entry = RecordEntry(2, "Z", -1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.eigenvalue = 1  # type: ignore[misc]
    assert hash(entry) == hash(RecordEntry(2, PauliBasis.Z, -1))


def test_record_entry_rejects_bad_indices_and_eigenvalues() -> None:
    """Positions count from 0; outcomes are eigenvalues, not bits."""
    with pytest.raises(ValueError, match="non-negative"):
        RecordEntry(-1, PauliBasis.X, 1)
    with pytest.raises(ValueError, match="non-negative integer"):
        RecordEntry(1.5, PauliBasis.X, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative integer"):
        RecordEntry(True, PauliBasis.X, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="1 - 2 \\* bit"):
        RecordEntry(0, PauliBasis.X, 0)


def test_record_entry_accepts_numpy_integer_indices() -> None:
    """Distribution loops index with numpy scalars; store plain ints."""
    entry = RecordEntry(np.int64(4), PauliBasis.Y, -1)
    assert entry.index == 4
    assert isinstance(entry.index, int)


# ==========================================================================
# RecipientRecord
# ==========================================================================


def _record(
    party: Party = Party.BOB,
    bases: tuple[str, ...] = ("X", "Y", "Z"),
    eigenvalues: tuple[int, ...] = (1, -1, 1),
) -> RecipientRecord:
    """Build a small record for a test."""
    return RecipientRecord.from_measurements(party, 0, bases, eigenvalues)


def test_record_behaves_as_an_immutable_sequence_indexed_from_zero() -> None:
    """record[i].index == i, so positional and logical indexing coincide."""
    record = _record()
    assert len(record) == 3
    assert record.length == 3
    for index, entry in enumerate(record):
        assert entry.index == index
        assert record[index] is entry
    assert record[0:2] == record.entries[0:2]
    assert isinstance(record.entries, tuple)


def test_record_does_not_expose_the_list_it_was_given() -> None:
    """The log is copied at construction: a verifier's view cannot change."""
    entries = [RecordEntry(0, "X", 1), RecordEntry(1, "Z", -1)]
    record = RecipientRecord(Party.CHARLIE, 1, entries)
    snapshot = record.entries
    entries.append(RecordEntry(2, "Y", 1))
    entries[0] = RecordEntry(0, "Z", -1)
    assert record.entries == snapshot
    assert len(record) == 2
    assert record[0].basis is PauliBasis.X


def test_record_is_frozen_and_hashable() -> None:
    """Frozen, and hashable because every field is immutable."""
    record = _record()
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.party = Party.CHARLIE  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.entries = ()  # type: ignore[misc]
    assert hash(record) == hash(_record())


def test_record_derived_views_are_parallel_tuples() -> None:
    """bases/eigenvalues/bits line up with the entries, in key order."""
    record = _record(bases=("Z", "X", "Y"), eigenvalues=(-1, 1, -1))
    assert record.bases == (PauliBasis.Z, PauliBasis.X, PauliBasis.Y)
    assert record.eigenvalues == (-1, 1, -1)
    assert record.bits == (1, 0, 1)


def test_record_stores_the_chosen_basis_not_a_pre_filtered_match() -> None:
    """The bug this type exists to prevent.

    The recipient logs the basis it chose. It cannot know Alice's basis at
    measurement time -- the key is not revealed until the signing phase -- so no
    filtering can happen here, and nothing in the record may depend on a key.
    """
    record = _record(bases=("X", "X", "X"), eigenvalues=(1, 1, -1))
    assert record.bases == (PauliBasis.X,) * 3
    assert not hasattr(record, "matched_indices")
    assert set(record.to_dict()) == {
        "party",
        "message_bit",
        "entries",
        "symmetrised",
    }
    # "symmetrised" is provenance -- whether the recipients have run their
    # private exchange yet -- and is the one field that is not a measurement.
    assert record.to_dict()["symmetrised"] is False


def test_record_rejects_alice() -> None:
    """Alice prepares and signs; she never measures."""
    with pytest.raises(ValueError) as excinfo:
        RecipientRecord(Party.ALICE, 0, (RecordEntry(0, "X", 1),))
    message = str(excinfo.value)
    assert "Alice holds no measurement record" in message
    assert "BOB" in message and "CHARLIE" in message


def test_record_rejects_index_gaps_duplicates_and_reordering() -> None:
    """A positional read against the key must not silently shift by one."""
    with pytest.raises(ValueError, match="ascending order"):
        RecipientRecord(Party.BOB, 0, (RecordEntry(0, "X", 1), RecordEntry(2, "Z", 1)))
    with pytest.raises(ValueError, match="ascending order"):
        RecipientRecord(Party.BOB, 0, (RecordEntry(0, "X", 1), RecordEntry(0, "Z", 1)))
    with pytest.raises(ValueError, match="ascending order"):
        RecipientRecord(Party.BOB, 0, (RecordEntry(1, "X", 1), RecordEntry(0, "Z", 1)))
    with pytest.raises(ValueError, match="ascending order"):
        RecipientRecord(Party.BOB, 0, (RecordEntry(1, "X", 1),))


def test_record_rejects_empty_and_malformed_entry_lists() -> None:
    """0/0 is not a mismatch rate."""
    with pytest.raises(ValueError, match="at least one entry"):
        RecipientRecord(Party.BOB, 0, ())
    with pytest.raises(TypeError, match="must be a RecordEntry"):
        RecipientRecord(Party.BOB, 0, [(0, "X", 1)])  # type: ignore[list-item]
    with pytest.raises(TypeError, match="must be a sequence"):
        RecipientRecord(Party.BOB, 0, 3)  # type: ignore[arg-type]


def test_record_rejects_a_bad_message_bit() -> None:
    """Every log is tagged with the distribution run it came from."""
    with pytest.raises(ValueError, match="must be 0 or 1"):
        RecipientRecord(Party.BOB, 5, (RecordEntry(0, "X", 1),))


def test_from_measurements_assigns_indices_in_order() -> None:
    """The constructor distribute.py uses: two parallel columns become a log."""
    record = RecipientRecord.from_measurements(
        "charlie", 1, ["Z", "X", "Y", "Z"], [1, 1, -1, -1]
    )
    assert record.party is Party.CHARLIE
    assert record.message_bit == 1
    assert [entry.index for entry in record] == [0, 1, 2, 3]
    assert record.bases == (
        PauliBasis.Z,
        PauliBasis.X,
        PauliBasis.Y,
        PauliBasis.Z,
    )
    assert record.eigenvalues == (1, 1, -1, -1)


def test_from_measurements_rejects_ragged_columns() -> None:
    """A dropped outcome must fail here, not shift every later comparison."""
    with pytest.raises(ValueError, match="same length"):
        RecipientRecord.from_measurements(Party.BOB, 0, ["X", "Y"], [1])


def test_record_check_against_catches_length_and_alphabet_mismatches() -> None:
    """A log from another run must not be verified under these parameters."""
    params = ProtocolParams(key_length=3)
    record = _record()
    assert record.check_against(params) is None
    with pytest.raises(ValueError, match="params.key_length"):
        record.check_against(ProtocolParams(key_length=4))
    narrow = ProtocolParams(key_length=3, bases=(PauliBasis.X, PauliBasis.Y))
    with pytest.raises(ValueError, match="not in params.bases"):
        record.check_against(narrow)


def test_record_round_trips_through_json() -> None:
    """Party and PauliBasis are StrEnums, so no bespoke encoder is needed."""
    record = RecipientRecord.from_measurements(
        Party.CHARLIE, 1, ("X", "Y", "Z"), (1, -1, -1)
    )
    encoded = json.dumps(record.to_dict())
    restored = RecipientRecord.from_dict(json.loads(encoded))
    assert restored == record
    decoded = json.loads(encoded)
    assert decoded["party"] == "Charlie"
    assert decoded["entries"][1]["basis"] == "Y"
    assert decoded["entries"][1]["eigenvalue"] == -1


# ==========================================================================
# Cross-module: a key and two records line up the way verification expects
# ==========================================================================


def test_a_key_and_two_independent_records_share_the_same_positions() -> None:
    """The shape verification consumes: one key, two logs, all length L.

    No verification logic is exercised here (that is verify.py's job); this only
    pins that the three objects agree on length and indexing, which is what
    makes a positional comparison legitimate.
    """
    params = ProtocolParams(key_length=32)
    generator = np.random.default_rng(SEED)
    key = generate_private_key(params, 0, rng=generator)

    records = []
    for party in VERIFIERS:
        bases = [
            params.bases[int(generator.integers(len(params.bases)))]
            for _ in range(params.key_length)
        ]
        values = [
            1 - 2 * int(generator.integers(2)) for _ in range(params.key_length)
        ]
        record = RecipientRecord.from_measurements(party, 0, bases, values)
        record.check_against(params)
        records.append(record)

    bob, charlie = records
    assert len(key) == len(bob) == len(charlie) == params.key_length
    assert bob.party is Party.BOB
    assert charlie.party is Party.CHARLIE
    assert bob.entries != charlie.entries
    for index in range(len(key)):
        assert bob[index].index == charlie[index].index == index



# ==========================================================================
# key_from_record -- reading a recipient's log as the key he declares
# ==========================================================================


def test_key_from_record_reads_the_log_column_for_column() -> None:
    """The chosen basis becomes the declared basis; the outcome, the value."""
    record = RecipientRecord.from_measurements(
        Party.BOB, 0, ["X", "Z", "Y", "X"], [1, -1, -1, 1]
    )
    declared = key_from_record(record)
    assert isinstance(declared, PrivateKey)
    assert len(declared) == len(record)
    assert declared.bases == record.bases
    assert declared.eigenvalues == record.eigenvalues
    for element, entry in zip(declared, record, strict=True):
        assert element.basis is entry.basis
        assert element.eigenvalue == entry.eigenvalue


def test_key_from_record_is_exactly_the_six_lines_it_replaces() -> None:
    """The helper exists to stop five adversaries open-coding this five ways.

    Pinned against the open-coded form so that a future change to the helper
    that quietly altered the declaration -- reversing the elements, dropping the
    tag, coercing the eigenvalue -- fails here rather than as an unexplained
    forgery rate three phases later.
    """
    record = RecipientRecord.from_measurements(
        Party.CHARLIE, 1, ["Y", "Y", "Z"], [-1, 1, -1]
    )
    open_coded = PrivateKey(
        message_bit=record.message_bit,
        elements=tuple(
            KeyElement(entry.basis, entry.eigenvalue) for entry in record
        ),
    )
    assert key_from_record(record) == open_coded


def test_key_from_record_carries_the_message_bit_across() -> None:
    """A log for bit b declares a key for bit b, or Signature refuses it."""
    for bit in (0, 1):
        record = RecipientRecord.from_measurements(Party.BOB, bit, ["X"], [1])
        assert key_from_record(record).message_bit == bit


def test_key_from_record_message_bit_can_be_overridden_for_a_test() -> None:
    """The override exists to build a deliberately cross-tagged declaration."""
    record = RecipientRecord.from_measurements(Party.BOB, 0, ["X", "Z"], [1, 1])
    crossed = key_from_record(record, message_bit=1)
    assert crossed.message_bit == 1
    assert crossed.bases == record.bases
    # ... and the cross-tagged key is exactly what a Signature refuses.
    with pytest.raises(ValueError, match="cannot sign message bit"):
        Signature(0, crossed)


def test_key_from_record_rejects_a_bad_override_bit() -> None:
    """Booleans and out-of-range bits are refused as everywhere else."""
    record = RecipientRecord.from_measurements(Party.BOB, 0, ["X"], [1])
    with pytest.raises(ValueError, match="must be 0 or 1"):
        key_from_record(record, message_bit=2)


def test_key_from_record_declares_eigenvalues_and_never_bits() -> None:
    """The silent inversion this helper exists to prevent.

    ``bit`` is ``(1 - eigenvalue) // 2``, so passing a bit where an eigenvalue
    belongs maps ``+1 -> 0`` and ``-1 -> 1``: a declaration that is wrong at
    every position, producing a forgery that fails at chance and looks like a
    channel problem.
    """
    record = RecipientRecord.from_measurements(
        Party.BOB, 0, ["X", "Z", "Y"], [1, -1, -1]
    )
    declared = key_from_record(record)
    assert declared.eigenvalues == (1, -1, -1)
    assert record.bits == (0, 1, 1)
    assert declared.eigenvalues != record.bits
    assert declared.bits == record.bits


def test_key_from_record_rejects_a_non_record() -> None:
    """A PrivateKey is not a log; the message says which log to pass."""
    key = generate_private_key(_params(4), 0, rng=np.random.default_rng(SEED))
    with pytest.raises(TypeError) as excinfo:
        key_from_record(key)  # type: ignore[arg-type]
    assert "must be a RecipientRecord" in str(excinfo.value)
    assert "view.raw_record" in str(excinfo.value)


def test_key_from_record_declares_whatever_log_it_is_handed() -> None:
    """It does not choose raw versus post-exchange; the caller does.

    A forging recipient wants his *raw* log, because after Phase A' half of it
    is the counterpart's evidence. That choice belongs to the attack, not to
    this helper, so both logs are accepted and neither is preferred.
    """
    raw = RecipientRecord.from_measurements(Party.BOB, 0, ["X", "Z"], [1, -1])
    post = RecipientRecord.from_measurements(
        Party.BOB, 0, ["Z", "Z"], [-1, -1], symmetrised=True
    )
    assert key_from_record(raw).bases == raw.bases
    assert key_from_record(post).bases == post.bases
    assert key_from_record(raw) != key_from_record(post)


def test_key_from_record_consumes_no_randomness() -> None:
    """D3: declaring a log is a reading, not a draw."""
    record = RecipientRecord.from_measurements(
        Party.BOB, 0, ["X", "Y", "Z"], [1, 1, -1]
    )
    generator = np.random.default_rng(SEED)
    before = generator.bit_generator.state
    key_from_record(record)
    assert generator.bit_generator.state == before


# ==========================================================================
# RecipientView -- the threat-model boundary, as a type
# ==========================================================================


def _view_records(
    party: Party = Party.BOB, message_bit: int = 0
) -> tuple[RecipientRecord, RecipientRecord]:
    """Return a plausible ``(raw, post-exchange)`` pair for one recipient."""
    raw = RecipientRecord.from_measurements(
        party, message_bit, ["X", "Z", "Y"], [1, -1, 1]
    )
    post = RecipientRecord.from_measurements(
        party, message_bit, ["X", "Y", "Y"], [1, 1, 1], symmetrised=True
    )
    return raw, post


def _distributed_session(
    key_length: int = 12, seed: int = SEED
) -> QDSSession:
    """Run Phase A once so the tests have real, symmetrised logs to split."""
    session = QDSSession(
        ProtocolParams(key_length=key_length), rng=np.random.default_rng(seed)
    )
    session.distribute()
    return session


def test_view_stores_exactly_the_documented_fields() -> None:
    """The field list is the boundary; adding to it must be deliberate.

    A future field that smuggled the counterpart's log, the session or a key
    into a view would defeat the whole type, and would otherwise be invisible.
    Changing this assertion is the moment to ask whether the new field belongs.
    """
    raw, post = _view_records()
    view = RecipientView(Party.BOB, 0, raw, post)
    assert [field.name for field in dataclasses.fields(view)] == [
        "party",
        "message_bit",
        "raw_record",
        "record",
        "matched_count",
    ]
    assert set(view.to_dict()) == {
        "party",
        "message_bit",
        "raw_record",
        "record",
        "matched_count",
    }


def test_view_is_frozen_and_hashable() -> None:
    """Frozen over frozen fields, so a view handed to an attack cannot move."""
    raw, post = _view_records()
    view = RecipientView(Party.BOB, 0, raw, post)
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.record = raw  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.matched_count = 3  # type: ignore[misc]
    assert hash(view) == hash(RecipientView(Party.BOB, 0, raw, post))


def test_view_derived_properties_read_the_scored_log() -> None:
    """len/length/symmetrised come off the post-exchange log, not the raw one."""
    raw, post = _view_records()
    view = RecipientView(Party.BOB, 0, raw, post)
    assert len(view) == view.length == 3
    assert raw.symmetrised is False
    assert view.symmetrised is True
    assert view.has_matched_count is False
    assert view.with_matched_count(0).has_matched_count is True


def test_view_refuses_the_counterparts_log() -> None:
    """The one mistake the type exists to make impossible."""
    bob_raw, bob_post = _view_records(Party.BOB)
    charlie_raw, charlie_post = _view_records(Party.CHARLIE)
    with pytest.raises(ValueError) as excinfo:
        RecipientView(Party.BOB, 0, charlie_raw, bob_post)
    message = str(excinfo.value)
    assert "Charlie's log but this view is Bob's" in message
    assert "threat model" in message
    with pytest.raises(ValueError, match="but this view is Bob's"):
        RecipientView(Party.BOB, 0, bob_raw, charlie_post)
    # ... and the same pair the other way round is refused too.
    with pytest.raises(ValueError, match="but this view is Charlie's"):
        RecipientView(Party.CHARLIE, 0, bob_raw, charlie_post)


def test_view_refuses_alice() -> None:
    """Alice measures nothing, so there is no view from where she stands."""
    raw, post = _view_records()
    with pytest.raises(ValueError) as excinfo:
        RecipientView(Party.ALICE, 0, raw, post)
    assert "belongs to a verifier" in str(excinfo.value)


def test_view_refuses_mixed_message_bits() -> None:
    """The two runs share no key and no evidence."""
    raw, post = _view_records(Party.BOB, 0)
    other_raw, other_post = _view_records(Party.BOB, 1)
    with pytest.raises(ValueError, match="tagged with message bit"):
        RecipientView(Party.BOB, 0, other_raw, post)
    with pytest.raises(ValueError, match="tagged with message bit"):
        RecipientView(Party.BOB, 1, other_raw, post)
    assert RecipientView(Party.BOB, 1, other_raw, other_post).message_bit == 1


def test_view_refuses_a_symmetrised_raw_record() -> None:
    """Passing the post-exchange log twice would silently change the attack.

    A forging recipient declares his *raw* log because half of it is what the
    counterpart is scored on. Handing the post-exchange log in as the raw one
    hands him precisely the half the counterpart does not hold, which is worth
    nothing -- a forgery that quietly fails at chance rather than reaching the
    ``1/12`` floor.
    """
    _, post = _view_records()
    with pytest.raises(ValueError) as excinfo:
        RecipientView(Party.BOB, 0, post, post)
    assert "not a raw log" in str(excinfo.value)


def test_view_refuses_logs_of_different_lengths() -> None:
    """Phase A' creates no positions, so the two logs are the same length."""
    raw, _ = _view_records()
    short = RecipientRecord.from_measurements(
        Party.BOB, 0, ["X"], [1], symmetrised=True
    )
    with pytest.raises(ValueError, match="entries and record has"):
        RecipientView(Party.BOB, 0, raw, short)


def test_view_refuses_non_records() -> None:
    """The message names the constructor to use instead."""
    raw, post = _view_records()
    with pytest.raises(TypeError) as excinfo:
        RecipientView(Party.BOB, 0, "not a log", post)  # type: ignore[arg-type]
    assert "RecipientView.for_party" in str(excinfo.value)


@pytest.mark.parametrize("bad", [-1, 4, 1.5, True, "2"])
def test_view_matched_count_must_be_an_in_range_integer(bad: object) -> None:
    """|M_R| is a subset size of this recipient's own logged positions."""
    raw, post = _view_records()
    with pytest.raises(ValueError, match="matched_count"):
        RecipientView(
            Party.BOB, 0, raw, post, matched_count=bad  # type: ignore[arg-type]
        )


def test_view_matched_count_defaults_to_unknown_and_takes_the_bounds() -> None:
    """None is not zero: no declaration yet, versus nothing to score."""
    raw, post = _view_records()

    def count(value: object) -> object:
        """Build a view carrying ``value`` and read the count back."""
        return RecipientView(
            Party.BOB, 0, raw, post, matched_count=value  # type: ignore[arg-type]
        ).matched_count

    assert RecipientView(Party.BOB, 0, raw, post).matched_count is None
    assert count(0) == 0
    assert count(3) == 3
    assert count(np.int64(2)) == 2


def test_with_matched_count_rebuilds_rather_than_mutating() -> None:
    """The count only becomes knowable in Phase C, and the view is frozen."""
    raw, post = _view_records()
    view = RecipientView(Party.BOB, 0, raw, post)
    filled = view.with_matched_count(2)
    assert filled is not view
    assert view.matched_count is None
    assert filled.matched_count == 2
    assert filled.raw_record is view.raw_record
    assert filled.record is view.record
    assert filled.with_matched_count(None).matched_count is None


def test_view_round_trips_through_json() -> None:
    """Party is a StrEnum, so no bespoke encoder is needed here either."""
    raw, post = _view_records(Party.CHARLIE, 1)
    view = RecipientView(Party.CHARLIE, 1, raw, post, matched_count=1)
    restored = RecipientView.from_dict(json.loads(json.dumps(view.to_dict())))
    assert restored == view
    decoded = json.loads(json.dumps(view.to_dict()))
    assert decoded["party"] == "Charlie"
    assert decoded["matched_count"] == 1
    assert decoded["record"]["symmetrised"] is True
    # A stored view that predates the count defaults to "not known yet".
    without = {key: value for key, value in view.to_dict().items()
               if key != "matched_count"}
    assert RecipientView.from_dict(without).matched_count is None


def test_for_party_narrows_a_session_shaped_mapping() -> None:
    """The narrowing point: both logs go in, one recipient's view comes out."""
    session = _distributed_session()
    view = RecipientView.for_party(
        "Bob", 1, raw_records=session.raw_records, records=session.records
    )
    assert view.party is Party.BOB
    assert view.message_bit == 1
    assert view.raw_record is session.raw_records[1][Party.BOB]
    assert view.record is session.records[1][Party.BOB]
    assert view.symmetrised is True
    assert len(view) == 12


def test_for_party_names_a_missing_bit_or_party() -> None:
    """A partial mapping is a wiring bug and must not produce a half view."""
    session = _distributed_session()
    raw = session.raw_records
    post = session.records
    with pytest.raises(ValueError, match="no entry for message bit"):
        RecipientView.for_party(
            Party.BOB, 0, raw_records={1: raw[1]}, records=post
        )
    lonely = {0: {Party.BOB: raw[0][Party.BOB]}}
    with pytest.raises(ValueError, match="no log for Charlie"):
        RecipientView.for_party(
            Party.CHARLIE, 0, raw_records=lonely, records=post
        )
    with pytest.raises(TypeError, match="must be a mapping"):
        RecipientView.for_party(
            Party.BOB, 0, raw_records=[], records=post  # type: ignore[arg-type]
        )


def test_recipient_views_splits_a_run_into_two_disjoint_views() -> None:
    """The harness-side one-liner, in VERIFIERS order."""
    session = _distributed_session()
    views = recipient_views(
        0,
        raw_records=session.raw_records,
        records=session.records,
        matched_counts={Party.BOB: 4, "Charlie": 5},
    )
    assert list(views) == list(VERIFIERS)
    assert views[Party.BOB].party is Party.BOB
    assert views[Party.CHARLIE].party is Party.CHARLIE
    assert views[Party.BOB].matched_count == 4
    assert views[Party.CHARLIE].matched_count == 5
    assert views[Party.BOB].record != views[Party.CHARLIE].record


def test_recipient_views_leaves_missing_counts_unknown() -> None:
    """Phase C' has not run yet on most of the timeline."""
    session = _distributed_session()
    views = recipient_views(
        1, raw_records=session.raw_records, records=session.records
    )
    assert all(view.matched_count is None for view in views.values())
    with pytest.raises(TypeError, match="matched_counts must be a mapping"):
        recipient_views(
            0,
            raw_records=session.raw_records,
            records=session.records,
            matched_counts=[4, 5],  # type: ignore[arg-type]
        )


# -- the reachability crawl ------------------------------------------------- #


def _reachable(root: object, *, limit: int = 50_000) -> list[object]:
    """Return every object reachable from ``root`` by fields and containers.

    Follows dataclass fields, ``__dict__`` entries, and the members of
    mappings, sequences and sets. Classes and modules are recorded but not
    descended into, since every object reaches ``object`` through its type and
    that says nothing about what a view holds.

    Strings, bytes and numbers are leaves: :class:`~sih141.protocol.params.Party`
    and :class:`~sih141.core.paulis.PauliBasis` are :class:`enum.StrEnum`
    members, so they stop here rather than dragging in the enum class.
    """
    seen: dict[int, object] = {}
    stack: list[object] = [root]
    while stack:
        if len(seen) > limit:  # pragma: no cover - a runaway crawl is a bug
            raise AssertionError(
                f"reachability crawl exceeded {limit} objects; the graph out "
                f"of this object is not the small one the test assumes"
            )
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen[id(obj)] = obj
        if isinstance(obj, (str, bytes, bytearray, int, float, complex)):
            continue
        if obj is None or isinstance(obj, (type, types.ModuleType)):
            continue
        if isinstance(obj, Mapping):
            stack.extend(obj.keys())
            stack.extend(obj.values())
            continue
        if isinstance(obj, (list, tuple, set, frozenset)):
            stack.extend(obj)
            continue
        if dataclasses.is_dataclass(obj):
            stack.extend(
                getattr(obj, field.name) for field in dataclasses.fields(obj)
            )
        namespace = getattr(obj, "__dict__", None)
        if isinstance(namespace, dict):
            stack.extend(namespace.values())
        for slot in getattr(type(obj), "__slots__", ()):
            if hasattr(obj, slot):
                stack.append(getattr(obj, slot))
    return list(seen.values())


def test_the_reachability_crawl_finds_what_it_is_supposed_to_find() -> None:
    """The positive control, without which the leak test proves nothing.

    A crawl that silently found nothing would pass the leak test for every
    possible defect. So: run it on the object the view is *carved out of* --
    the session's own nested mapping -- and assert it does reach both
    recipients' logs and the private keys. Only then does "the same crawl
    reaches none of that from a view" mean anything.
    """
    session = _distributed_session()
    found = _reachable(
        {
            "raw": session.raw_records,
            "post": session.records,
            "keys": session.keys,
        }
    )
    records = [item for item in found if isinstance(item, RecipientRecord)]
    assert len(records) == 8  # two bits x two parties x (raw, post-exchange)
    assert {record.party for record in records} == {Party.BOB, Party.CHARLIE}
    assert sum(isinstance(item, PrivateKey) for item in found) == 2
    assert any(isinstance(item, KeyElement) for item in found)


def test_no_path_out_of_a_view_reaches_the_counterparts_data() -> None:
    """The boundary, checked by reachability rather than by inspection.

    A comment saying "do not read Charlie's log" is worth nothing against an
    attack author who does not read comments. What is worth something is that
    there is no path: Bob's view reaches Bob's two logs and their entries, and
    no whole log belonging to Charlie, no private key, no signature, no session
    and no generator.
    """
    session = _distributed_session()
    views = recipient_views(
        0, raw_records=session.raw_records, records=session.records
    )
    bob = views[Party.BOB]
    charlie = views[Party.CHARLIE]

    found = _reachable(bob)
    records = [item for item in found if isinstance(item, RecipientRecord)]

    # Not vacuous: the crawl did reach Bob's own evidence.
    assert len(records) == 2
    assert {record.party for record in records} == {Party.BOB}
    assert {id(record) for record in records} == {
        id(bob.raw_record),
        id(bob.record),
    }

    # And nothing of the counterpart's, nor of Alice's.
    identities = {id(item) for item in found}
    assert id(charlie.raw_record) not in identities
    assert id(charlie.record) not in identities
    assert id(session.raw_records[0][Party.CHARLIE]) not in identities
    assert id(session.records[0][Party.CHARLIE]) not in identities
    for forbidden in (PrivateKey, Signature, QDSSession, np.random.Generator):
        assert not any(isinstance(item, forbidden) for item in found), forbidden
    # The other message bit is a different run and is not in this view either.
    assert id(session.records[1][Party.BOB]) not in identities


def test_a_view_reaches_no_entry_of_the_other_bit_or_the_other_party() -> None:
    """The same crawl, stated over entries rather than whole logs.

    Bob's post-exchange log legitimately *contains* entries that came off
    Charlie's raw log -- that is what Phase A' does, and those entries are now
    Bob's evidence. So the invariant cannot be "no shared entry". It is: every
    entry Bob's view reaches belongs to one of the two logs Bob holds.
    """
    session = _distributed_session()
    bob = RecipientView.for_party(
        Party.BOB, 0, raw_records=session.raw_records, records=session.records
    )
    found = _reachable(bob)
    entries = [item for item in found if isinstance(item, RecordEntry)]
    held = {id(entry) for entry in bob.raw_record} | {
        id(entry) for entry in bob.record
    }
    assert entries
    assert {id(entry) for entry in entries} <= held
    # ... and the shared-entry fact itself, so that a future reader does not
    # "fix" it: after the exchange some of Bob's entries are Charlie's raw ones.
    charlie_raw = session.raw_records[0][Party.CHARLIE]
    shared = sum(
        1
        for index in range(len(bob.record))
        if bob.record[index] is charlie_raw[index]
    )
    assert 0 < shared < len(bob.record)


def test_a_view_is_all_an_isolated_recipient_forger_needs() -> None:
    """The point of the pair: staying inside the model is now the easy path.

    A forging Bob written against a view *cannot* read Charlie's log, and the
    declaration he produces is the documented recipient-forgery strategy in one
    line rather than six.
    """
    session = _distributed_session(key_length=24)
    bob = RecipientView.for_party(
        Party.BOB, 0, raw_records=session.raw_records, records=session.records
    )
    forged = Signature(0, key_from_record(bob.raw_record))
    assert len(forged) == 24
    assert forged.bases == bob.raw_record.bases
    assert forged.eigenvalues == bob.raw_record.eigenvalues
    # He declares his own measurements, which agree with Alice's key exactly
    # where his basis happened to be hers -- and nowhere else.
    truth = session.keys[0]
    agreeing = [
        index
        for index in range(24)
        if forged.declared_key[index] == truth[index]
    ]
    matched = [
        index for index in range(24) if forged.bases[index] == truth.bases[index]
    ]
    assert set(agreeing) <= set(matched)
