"""Phase 3: the adversaries, and the rule that keeps their numbers honest.

The attack suite itself is built in a later phase and attaches to
:class:`~sih141.protocol.session.QDSSession` through its six keyword-only seams
(:ref:`sih141.protocol.session <phase3-seams>`), so no protocol module changes
for any attack. What lives here first is the thing every one of those
adversaries has to satisfy before its measured rate means anything.

:mod:`sih141.attacks.isolation`
    Convention **D6** as a behavioural check. Every adversary takes its *own*
    :class:`numpy.random.Generator` as a constructor argument, and its behaviour
    must be a function of that generator and of what the threat model says it
    can observe -- never of the session's randomness.
    :func:`~sih141.attacks.isolation.assert_attack_isolated` demonstrates the
    property rather than asserting it, by holding one source of randomness fixed
    and varying the other, in both directions.

Why that is the first thing in the package and not a footnote: an attack that
closes over the seed the harness gives the session rebuilds the whole run from
it and predicts every private symmetrisation coin, which makes the repudiation
rates it reports fiction while leaving the transcript, the seams and the printed
bound looking entirely normal. The module docstring of
:mod:`sih141.attacks.isolation` demonstrates the leak as an executable example.

Examples
--------
>>> import numpy as np
>>> from sih141.attacks import assert_attack_isolated
>>> class OwnCoins:
...     def __init__(self, *, rng: np.random.Generator) -> None:
...         self.flips = rng.integers(0, 2, size=8)
>>> assert_attack_isolated(
...     OwnCoins, lambda attack, session_seed: attack.flips
... ).isolated
True
"""

from sih141.attacks.isolation import (
    DEFAULT_ATTACK_SEEDS,
    DEFAULT_SESSION_SEEDS,
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
    signer_probe,
    signer_scenario,
)

__all__ = [
    "DEFAULT_ATTACK_SEEDS",
    "DEFAULT_SESSION_SEEDS",
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
    "signer_probe",
    "signer_scenario",
]
