"""SIH26141 - Quantum-Inspired Cyber Threat Detection for Digital Signature Security.

Three packages, in the order the project builds them.

:mod:`sih141.core`
    The quantum primitives: states, Pauli algebra, projective measurement and
    teleportation. Everything above is classical bookkeeping over what this
    layer produces.

:mod:`sih141.protocol`
    Teleportation-based quantum digital signatures end to end -- key
    distribution, symmetrisation, signing, the matched-count exchange, and
    verification with its floors -- plus the closed-form analysis every measured
    rate in the project is checked against.

:mod:`sih141.attacks`
    The five adversaries of Phase 3, each mounted through the protocol's own
    seams, and the D6 isolation check that keeps their published rates honest.

Only the two subpackages are re-exported here, deliberately: the flat names live
one level down, where the module that owns each one can be found from its
qualified name. ``from sih141 import attacks, protocol`` is the intended
spelling, and ``sih141.attacks.OutsideForger`` says where to go and read.

Examples
--------
>>> import numpy as np
>>> from sih141 import attacks, protocol
>>> transcript = protocol.QDSSession(
...     protocol.ProtocolParams(key_length=192), rng=np.random.default_rng(2)
... ).run(0)
>>> transcript.transferable, transcript.repudiated
(True, False)
>>> attacks.assert_attack_isolated(
...     attacks.OutsideForger, attacks.signer_probe()
... ).isolated
True
"""

from sih141 import attacks, core, protocol

__version__ = "0.1.0"

__all__ = ["attacks", "core", "protocol", "__version__"]
