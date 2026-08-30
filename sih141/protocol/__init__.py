"""Teleportation-based quantum digital signatures (Phase 2).

The scheme implemented here is measurement-based QDS (Dunjko-Wallden-Andersson
2014; Amiri et al. 2016) with teleportation-based key distribution. It is chosen
over Gottesman-Chuang (2001) for one operational reason, which is the reason the
problem statement gives: Gottesman-Chuang requires each recipient to *store* the
quantum public key until a signature arrives, i.e. long-lived quantum memory.
Here the recipients measure on receipt and keep a classical log, so after
distribution there is no quantum state anywhere in the system.

The run, end to end
-------------------
**Phase A -- distribution**, executed once per future message bit ``b in {0, 1}``:

1. Alice draws a private key ``k_b = [(basis_i, eigenvalue_i)]`` of length ``L``,
   each basis uniform over ``{X, Y, Z}`` and each eigenvalue uniform over
   ``{+1, -1}`` (:func:`~sih141.protocol.keys.generate_private_key`).
2. The quantum public key is the product state of the corresponding eigenstates
   (:func:`~sih141.protocol.keys.public_key_states`).
3. Alice teleports one copy to Bob and one to Charlie, consuming a fresh Bell
   pair per qubit. She prepares each eigenstate twice *from its classical
   description*; this is state preparation, not cloning, and the argument is
   spelled out in :mod:`sih141.protocol.keys`. Note what does **not** cross the
   channel: the key states themselves never traverse it, only entanglement and
   two classical bits per qubit.
4. Each recipient immediately measures qubit ``i`` in a uniformly random basis
   and stores ``(i, chosen_basis, outcome_eigenvalue)``
   (:class:`~sih141.protocol.records.RecipientRecord`). No quantum memory is
   retained.

**Phase A' -- symmetrisation**: Bob and Charlie, over their own authenticated
channel and out of Alice's sight, toss one fair coin per position and swap their
two records wherever it comes up heads
(:func:`~sih141.protocol.symmetrise.symmetrise_records`). Alice therefore cannot
know which of her two preparations each verifier will score. This step is not
decoration: without it she can send Bob the eigenstate she declares and Charlie
its orthogonal partner, and repudiate with probability ``1`` at every key length.
It costs a factor of four in the recipient-forger floor -- ``1/3`` before,
``1/12`` after -- and that is what the key length pays for.

**Phase B -- signing**: Alice sends ``(message, k_b)`` to Bob over an
authenticated classical channel.

**Phase C -- verification**: recipient ``R`` intersects its own bases with the
declared ones to get the matched set ``M_R``, counts disagreements ``e_R`` on
those positions only, and compares ``r_R = e_R / |M_R|`` against its threshold --
``s_a`` for Bob, ``s_v`` for Charlie. Unmatched positions carry no information
and are discarded; see :mod:`sih141.protocol.records` for why counting them is
the classic bug in this family of protocols.

Where the two thresholds come from, and why ``s_a < s_v < 1/2``, is derived in
:mod:`sih141.protocol.params`.

Modules
-------
:mod:`~sih141.protocol.params`
    :class:`~sih141.protocol.params.ProtocolParams`,
    :class:`~sih141.protocol.params.Party`, and the documented default parameter
    sets.
:mod:`~sih141.protocol.keys`
    Private keys and the quantum public key.
:mod:`~sih141.protocol.records`
    The recipients' immutable classical logs.
:mod:`~sih141.protocol.distribute`
    Phase A itself: teleportation of the public key and immediate measurement on
    receipt. Its ``resource_factory`` argument is the seam Phase 3's channel
    attacks are mounted through.
:mod:`~sih141.protocol.symmetrise`
    Phase A': the recipients' private exchange, and the reason non-repudiation
    holds at all. :func:`~sih141.protocol.symmetrise.no_symmetrisation` is the
    seam Phase 3 uses to run the insecure variant and measure the attack.
:mod:`~sih141.protocol.signature`
    Phase B: :class:`~sih141.protocol.signature.Signature` and
    :func:`~sih141.protocol.signature.sign`. The signature *is* the private key,
    declared over an authenticated classical channel.
:mod:`~sih141.protocol.verify`
    Phase C: :func:`~sih141.protocol.verify.verify`,
    :func:`~sih141.protocol.verify.verify_all` and the
    :class:`~sih141.protocol.verify.VerificationResult` they return. This is
    where the matched/unmatched split is enforced.
:mod:`~sih141.protocol.session`
    Orchestration: :class:`~sih141.protocol.session.QDSSession` runs the phases
    in order and freezes the result into a JSON-serialisable
    :class:`~sih141.protocol.session.SessionTranscript`. Its five keyword-only
    seams -- ``resource_factory``, ``distributor``, ``symmetriser``, ``signer``
    and ``forwarder`` -- are how the Phase 3 attack suite attaches without
    editing any protocol module.
:mod:`~sih141.protocol.analysis`
    Closed forms only, no simulation: the matched-set and honest-rate
    statistics, the two forgery probabilities (outside adversary and the
    binding recipient one), the repudiation guarantee, and the robustness
    tail. Everything it exports is re-exported here, so Phase 3 onwards never
    needs to reach into a submodule.

Examples
--------
>>> import numpy as np
>>> from sih141.protocol import ProtocolParams, QDSSession
>>> transcript = QDSSession(
...     ProtocolParams(key_length=24), rng=np.random.default_rng(0)
... ).run(1)
>>> transcript.transferable
True
"""

from sih141.protocol.analysis import (
    FORGER_MATCHED_MISMATCH_PROBABILITY,
    BoundMethod,
    HonestStatistics,
    MatchedStatistics,
    binary_kl_divergence,
    depolarising_error_rate,
    forgery_bound,
    forgery_probability,
    hoeffding_exponent,
    honest_abort_bound,
    honest_abort_probability,
    honest_statistics,
    matched_count_distribution,
    matched_statistics,
    max_accepted_mismatches,
    recipient_forgery_bound,
    recipient_forgery_probability,
    repudiation_bound,
    repudiation_probability,
    symmetric_repudiation_bound,
)
from sih141.protocol.distribute import (
    ResourceContext,
    ResourceFactory,
    distribute_public_key,
    distribute_to_recipient,
    ideal_resource,
)
from sih141.protocol.keys import (
    KeyElement,
    PrivateKey,
    generate_key_pair,
    generate_private_key,
    public_key_states,
)
from sih141.protocol.params import (
    COMPLIANT_FORGER_RATE_THREE_BASIS,
    DEFAULT_BASES,
    DEFAULT_PARAMS,
    DEFAULT_S_A,
    DEFAULT_S_V,
    DEMO_PARAMS,
    UNSYMMETRISED_FORGER_RATE_THREE_BASIS,
    VERIFIERS,
    Party,
    ProtocolParams,
)
from sih141.protocol.records import RecipientRecord, RecordEntry
from sih141.protocol.session import (
    MESSAGE_BITS,
    Distributor,
    Forwarder,
    QDSSession,
    SessionTranscript,
    Signer,
    honest_forwarder,
    honest_signer,
)
from sih141.protocol.signature import Signature, sign
from sih141.protocol.symmetrise import (
    Symmetriser,
    no_symmetrisation,
    symmetrise_records,
)
from sih141.protocol.verify import (
    VerificationResult,
    matched_positions,
    mismatch_positions,
    verify,
    verify_all,
)

__all__ = [
    # -- parameters and roles ----------------------------------------------- #
    "Party",
    "VERIFIERS",
    "ProtocolParams",
    "COMPLIANT_FORGER_RATE_THREE_BASIS",
    "UNSYMMETRISED_FORGER_RATE_THREE_BASIS",
    "DEFAULT_S_A",
    "DEFAULT_S_V",
    "DEFAULT_BASES",
    "DEFAULT_PARAMS",
    "DEMO_PARAMS",
    # -- keys ---------------------------------------------------------------- #
    "KeyElement",
    "PrivateKey",
    "generate_private_key",
    "generate_key_pair",
    "public_key_states",
    # -- recipients' classical logs ------------------------------------------ #
    "RecordEntry",
    "RecipientRecord",
    # -- Phase A: distribution ----------------------------------------------- #
    "ResourceContext",
    "ResourceFactory",
    "ideal_resource",
    "distribute_to_recipient",
    "distribute_public_key",
    # -- Phase A': the recipients' private exchange --------------------------- #
    "Symmetriser",
    "symmetrise_records",
    "no_symmetrisation",
    # -- Phase B: signing ----------------------------------------------------- #
    "Signature",
    "sign",
    # -- Phase C: verification ------------------------------------------------ #
    "VerificationResult",
    "matched_positions",
    "mismatch_positions",
    "verify",
    "verify_all",
    # -- orchestration, and the Phase 3 attack seams -------------------------- #
    "MESSAGE_BITS",
    "Distributor",
    "Signer",
    "Forwarder",
    "honest_signer",
    "honest_forwarder",
    "SessionTranscript",
    "QDSSession",
    # -- closed-form analysis ------------------------------------------------- #
    "FORGER_MATCHED_MISMATCH_PROBABILITY",
    "BoundMethod",
    "MatchedStatistics",
    "HonestStatistics",
    "binary_kl_divergence",
    "hoeffding_exponent",
    "max_accepted_mismatches",
    "matched_statistics",
    "matched_count_distribution",
    "depolarising_error_rate",
    "honest_statistics",
    "forgery_probability",
    "forgery_bound",
    "recipient_forgery_probability",
    "recipient_forgery_bound",
    "repudiation_probability",
    "repudiation_bound",
    "symmetric_repudiation_bound",
    "honest_abort_probability",
    "honest_abort_bound",
]
