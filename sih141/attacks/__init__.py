"""Phase 3: the five adversaries, and the rule that keeps their numbers honest.

Every attack here mounts on :class:`~sih141.protocol.session.QDSSession` through
its keyword-only seams (:ref:`sih141.protocol.session <phase3-seams>`). **Not one
of them needed a protocol edit to be mounted**, which is the property the seams
exist for: an attack that had to change the protocol to attach to it would be an
attack on a protocol nobody ships.

Mounting an adversary and *measuring* it are not the same thing, and one gap
turned up between them. The forging recipient could be mounted but not scored,
because the session ran Phase C' before the Bob-to-Charlie hop and the forgery
was refused on provenance instead of being verified -- so the shipped protocol's
recipient-forgery rate had never been measured, only the pre-pooled variant's.
Which declaration each recipient counts is now a named configuration
(:data:`~sih141.protocol.session.COUNTS_BEFORE_FORWARDING` and its counterpart),
and the rate agrees with the closed form. That is a new *experiment*, not a new
mechanism: on an honest run the two orderings agree position for position.

The five, by the seam each one sits on
--------------------------------------
:mod:`sih141.attacks.forgery` -- ``signer`` and ``forwarder``
    :class:`~sih141.attacks.forgery.OutsideForger` substitutes Alice's
    declaration outright and is measured against both thresholds at once.
    :class:`~sih141.attacks.forgery.RecipientForger` is a forwarding Bob who
    declares his own log to Charlie; the ``1/12`` floor he runs into, against
    the ``1/3`` he would face without Phase A', is the clearest single
    demonstration of what symmetrisation buys.

:mod:`sih141.attacks.impersonation` -- ``distributor`` and ``signer``
    Mallory runs Alice's half of the protocol with a key of her own. Seizing
    *both* seams is accepted 200/200 and is out of model by assumption (AUTH);
    seizing either one alone is accepted 0/200 at a mismatch rate of ``1/2``.
    The contrast is the result, and it is what makes (AUTH) load-bearing rather
    than decorative.

:mod:`sih141.attacks.replay` -- ``forwarder``, plus direct drives of
:func:`~sih141.protocol.verify.verify_or_abort`
    Four replay flavours against the session binding and the consumed-records
    ledger. Three are closed. The fourth -- burning a verifier's round on a
    declaration the adversary chose -- is closed only by the *ordering* of Phase
    C', which is why that ordering is now a named parameter rather than an
    accident (:data:`~sih141.protocol.session.COUNTS_BEFORE_FORWARDING`).

:mod:`sih141.attacks.channel` -- ``resource_factory`` and ``payload_map``
    A per-hop Pauli twirl, an intercept-resend, and an eavesdropper who keeps a
    share, each mountable on either line and each targetable at one recipient.
    One correlation tensor predicts both published statistics, and the module
    pins that prediction against the protocol's own closed forms so the two
    cannot drift apart.

:mod:`sih141.attacks.starvation` -- ``count_exchange``
    One recipient understates his own matched count and denies the other a
    verdict. Free, deterministic, and selective -- and it cannot be done
    quietly: the quietest denying declaration sits ``-11.54`` honest standard
    deviations below the mean at *every* key length.

The two things every one of them has to satisfy
------------------------------------------------
:mod:`sih141.attacks.isolation`
    Convention **D6** as a behavioural check: hold the adversary's generator
    fixed and vary the session seed, and its choices must not move; hold the
    session seed fixed and vary its generator, and they must. An attack that
    closes over the harness seed predicts every private symmetrisation coin --
    ``120/120`` on both message bits, demonstrated as an executable example in
    that module -- and publishes repudiation rates that are fiction while
    leaving the transcript, the seams and the printed bound looking normal.

:mod:`sih141.attacks.statistics`
    One Wilson interval and one agreement test for the whole suite. The
    agreement band is computed from the sampling standard error at the
    *predicted* rate rather than chosen by eye, because a guessed tolerance
    either passes a broken attack or fails a correct one and neither failure is
    visible.

Examples
--------
>>> import numpy as np
>>> from sih141.attacks import assert_attack_isolated, signer_probe
>>> from sih141.attacks import OutsideForger
>>> assert_attack_isolated(OutsideForger, signer_probe()).isolated
True

The agreement test the integration suite is built on, carrying the arm that could
not be measured at all until the count exchange grew an ordering -- the forging
recipient under the shipped pooled rule, as
:mod:`tests.test_phase3_integration` measures it:

>>> from sih141.attacks import agrees_within
>>> print(agrees_within(96, 300, 0.345566).summary())
AGREES: 96/300 = 0.320000 vs predicted 0.345566 (z = -0.93, band 4.0 se = 0.109824)

See Also
--------
sih141.protocol : The scheme being attacked, and the closed forms every measured
    rate above is checked against.
"""

from sih141.attacks.channel import (
    IDEAL_TENSOR,
    PAULI_AXES,
    AttackDecision,
    ChannelAttack,
    CorrelationTensor,
    DepolarisingChannel,
    InterceptResend,
    KeptShareSwap,
    attribution_survives_symmetrisation,
    chsh_from_tensor,
    collapse_tensor,
    depolarising_tensor,
    measure_chsh,
    measure_qber,
    payload_line_is_unwatched,
    qber_from_tensor,
)
from sih141.attacks.forgery import (
    OUTSIDE_FORGER_MISMATCH_RATE,
    RECIPIENT_FORGER_MISMATCH_RATE,
    UNSYMMETRISED_FORGER_MISMATCH_RATE,
    ForgeryMeasurement,
    OutsideForger,
    RecipientForger,
    measure_outside_forgery,
    measure_recipient_forgery,
)
from sih141.attacks.impersonation import (
    MEASURED,
    ImpersonationMeasurement,
    ImpersonationScope,
    ImpersonationTrial,
    Impersonator,
    MeasuredRun,
    distributor_probe,
    impersonation_seams,
    matched_sets_identical,
    measure_impersonation,
    run_impersonation,
    shipped_summary,
    signing_probe,
)
from sih141.attacks.isolation import (
    DEFAULT_ATTACK_SEEDS,
    DEFAULT_SESSION_SEEDS,
    MIN_JUSTIFICATION,
    SCENARIO_PARAMS,
    SCENARIO_SEED,
    AttackBuilder,
    AttackIsolationError,
    DecisionProbe,
    IsolationReport,
    SignerScenario,
    assert_attack_isolated,
    canonical,
    check_attack_isolation,
    forwarder_probe,
    signer_probe,
    signer_scenario,
)
from sih141.attacks.replay import (
    COUNTS_AS_RECEIVED,
    COUNTS_AS_SIGNED,
    COUNTS_NONE,
    AttackOutcome,
    ReplayCapture,
    ReplayingForwarder,
    measure_cross_session_pairing,
    measure_identifier_preimage,
    measure_ledger_denial_of_service,
    measure_ledger_poisoning,
    measure_shared_identifier,
    measure_shared_identifier_self_denial,
    measure_straight_replay,
    replay_capture,
    replay_probe,
)
from sih141.attacks.starvation import (
    CountStarver,
    StarvationDecision,
    StarvationMeasurement,
    StarvationMode,
    declaration_z_score,
    declared_versus_scored,
    denial_headroom,
    least_implausible_z,
    measure_starvation,
    pooled_branch_requirement,
    probe_messages,
    starvation_probe,
)
from sih141.attacks.statistics import (
    Z_90,
    Z_95,
    Z_99,
    AgreementVerdict,
    agrees_within,
    binomial_standard_error,
    sigma_tolerance,
    two_sided_z,
    wilson_bounds,
)

__all__ = [
    # -- D6: the check every published rate depends on ------------------------ #
    "DEFAULT_ATTACK_SEEDS",
    "DEFAULT_SESSION_SEEDS",
    "MIN_JUSTIFICATION",
    "SCENARIO_PARAMS",
    "SCENARIO_SEED",
    "AttackBuilder",
    "AttackIsolationError",
    "DecisionProbe",
    "IsolationReport",
    "SignerScenario",
    "assert_attack_isolated",
    "canonical",
    "check_attack_isolation",
    "signer_scenario",
    # -- the ready-made probes, one per seam ---------------------------------- #
    "distributor_probe",
    "forwarder_probe",
    "replay_probe",
    "signer_probe",
    "signing_probe",
    "starvation_probe",
    # -- one interval and one agreement test for the suite -------------------- #
    "Z_90",
    "Z_95",
    "Z_99",
    "AgreementVerdict",
    "agrees_within",
    "binomial_standard_error",
    "sigma_tolerance",
    "two_sided_z",
    "wilson_bounds",
    # -- forgery: the signer seam and the forwarding hop ---------------------- #
    "OUTSIDE_FORGER_MISMATCH_RATE",
    "RECIPIENT_FORGER_MISMATCH_RATE",
    "UNSYMMETRISED_FORGER_MISMATCH_RATE",
    "ForgeryMeasurement",
    "OutsideForger",
    "RecipientForger",
    "measure_outside_forgery",
    "measure_recipient_forgery",
    # -- impersonation: Alice's two seams, and assumption (AUTH) -------------- #
    "MEASURED",
    "ImpersonationMeasurement",
    "ImpersonationScope",
    "ImpersonationTrial",
    "Impersonator",
    "MeasuredRun",
    "impersonation_seams",
    "matched_sets_identical",
    "measure_impersonation",
    "run_impersonation",
    "shipped_summary",
    # -- replay: the session binding and the consumed-records ledger ---------- #
    "COUNTS_AS_RECEIVED",
    "COUNTS_AS_SIGNED",
    "COUNTS_NONE",
    "AttackOutcome",
    "ReplayCapture",
    "ReplayingForwarder",
    "measure_cross_session_pairing",
    "measure_identifier_preimage",
    "measure_ledger_denial_of_service",
    "measure_ledger_poisoning",
    "measure_shared_identifier",
    "measure_shared_identifier_self_denial",
    "measure_straight_replay",
    "replay_capture",
    # -- channel: the quantum link, on both of its lines ---------------------- #
    "IDEAL_TENSOR",
    "PAULI_AXES",
    "AttackDecision",
    "ChannelAttack",
    "CorrelationTensor",
    "DepolarisingChannel",
    "InterceptResend",
    "KeptShareSwap",
    "attribution_survives_symmetrisation",
    "chsh_from_tensor",
    "collapse_tensor",
    "depolarising_tensor",
    "measure_chsh",
    "measure_qber",
    "payload_line_is_unwatched",
    "qber_from_tensor",
    # -- starvation: the count exchange --------------------------------------- #
    "CountStarver",
    "StarvationDecision",
    "StarvationMeasurement",
    "StarvationMode",
    "declaration_z_score",
    "declared_versus_scored",
    "denial_headroom",
    "least_implausible_z",
    "measure_starvation",
    "pooled_branch_requirement",
    "probe_messages",
]
