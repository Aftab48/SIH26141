"""Quantum core for SIH26141.

This subpackage holds the physics layer that every later phase builds on:
Pauli algebra and single-qubit bases (:mod:`sih141.core.paulis`), state
construction and entanglement measures (:mod:`sih141.core.states`), projective
measurement (:mod:`sih141.core.measure`), teleportation
(:mod:`sih141.core.teleport`) and the single randomness entry point
(:mod:`sih141.core.rng`).

Everything a later phase needs is re-exported here, so the whole Phase 1 API is
reachable from one import::

    from sih141.core import PauliBasis, bell_state, teleport, projective_measure

The names below are the *entire* supported surface.  Anything not listed in
:data:`__all__` is private to Phase 1 and may change without notice; in
particular the leading-underscore helpers inside the submodules are not part of
the contract even though the test suite reaches into some of them.

Project-wide conventions
------------------------
Canonical state type (D1)
    Any function that returns a post-measurement or post-channel state returns a
    :class:`qiskit.quantum_info.DensityMatrix`. Pure states may be *built* as
    :class:`qiskit.quantum_info.Statevector`; public functions that *accept* a
    state accept either (or a raw array) and normalise through the single shared
    helper :func:`as_density`.
Qubit ordering (D2)
    Qiskit little-endian throughout. Qubit 0 is the **rightmost** character of a
    bitstring label, so the label ``"01"`` means qubit 1 is in state
    :math:`|0\\rangle` and qubit 0 is in state :math:`|1\\rangle`.
Determinism (D3)
    Every function that consumes randomness takes a keyword-only ``rng``
    argument resolved through :func:`resolve_rng`. The ``numpy.random``
    module-level functions and the stdlib :mod:`random` module are never used.
    A scalar seed arriving from a CLI flag, a JSON run description or a config
    file is turned into a generator **once**, at the boundary, by
    :func:`seed_to_generator`; that is the only sanctioned conversion.
No machine learning (D4)
    Pure linear algebra and classical statistics only.

Notes
-----
One name is deliberately overloaded: :func:`teleport` is re-exported here as the
*function*, because that is what callers actually want.  It therefore shadows the
submodule attribute of the same name, and that has one sharp edge worth knowing
before Phase 2 trips over it.

Works as expected::

    from sih141.core import teleport                      # the function
    from sih141.core.teleport import teleport_circuit     # any submodule member
    importlib.import_module("sih141.core.teleport")       # the module

Does **not** do what it looks like::

    import sih141.core.teleport as t                      # binds the FUNCTION

The ``import ... as`` form finishes by looking the name up as an attribute of the
parent package, and this module has rebound that attribute to the function.  The
plain ``from``-import is unaffected because it resolves through
:data:`sys.modules`.  The behaviour is pinned by
``tests/test_integration.py::test_teleport_name_resolves_to_the_function_not_the_submodule``.
"""

from sih141.core.measure import (
    MeasurementOutcome,
    bell_measure,
    born_probabilities,
    expectation,
    joint_probability,
    measure_qubits,
    projective_measure,
    sample_counts,
)
from sih141.core.paulis import (
    BASIS_CHANGE,
    PAULI_I,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    PauliBasis,
    basis_change_circuit,
    eigenstate,
    eigenstate_label,
    pauli_matrix,
    random_basis,
    verify_eigenstate,
)
from sih141.core.rng import resolve_rng, seed_to_generator
from sih141.core.states import (
    BELL_ORDER,
    BellState,
    StateLike,
    as_density,
    bell_circuit,
    bell_state,
    concurrence,
    fidelity,
    is_normalised,
    purity,
)
from sih141.core.teleport import (
    RegisterTeleportationResult,
    TeleportationResult,
    correction_bits,
    pauli_correction,
    teleport,
    teleport_channel,
    teleport_circuit,
    teleport_in_register,
)

__all__ = [
    # -- randomness (D3) ---------------------------------------------------- #
    "resolve_rng",
    "seed_to_generator",
    # -- Pauli algebra and single-qubit bases ------------------------------- #
    "PauliBasis",
    "PAULI_I",
    "PAULI_X",
    "PAULI_Y",
    "PAULI_Z",
    "pauli_matrix",
    "eigenstate",
    "eigenstate_label",
    "BASIS_CHANGE",
    "basis_change_circuit",
    "random_basis",
    "verify_eigenstate",
    # -- states, entanglement measures and the canonical validator ---------- #
    "BellState",
    "BELL_ORDER",
    "StateLike",
    "bell_state",
    "bell_circuit",
    "as_density",
    "fidelity",
    "purity",
    "concurrence",
    "is_normalised",
    # -- projective measurement --------------------------------------------- #
    "MeasurementOutcome",
    "born_probabilities",
    "projective_measure",
    "measure_qubits",
    "joint_probability",
    "sample_counts",
    "expectation",
    "bell_measure",
    # -- teleportation ------------------------------------------------------ #
    "TeleportationResult",
    "RegisterTeleportationResult",
    "pauli_correction",
    "correction_bits",
    "teleport",
    "teleport_in_register",
    "teleport_channel",
    "teleport_circuit",
]
