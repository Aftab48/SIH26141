# Phase 1: Quantum Core

Engineering note for `sih141.core`. Covers what exists, the three binding design
decisions and why each was taken, the derived teleportation correction table, and the
seams Phase 2 attaches to.

Status: complete. 517 tests over `sih141/core` and its integration suite, all passing.
(Up from 480 at the end of Phase 1: the Phase 2 audit added tests for four unpinned
properties of `teleport.py` and made the fidelity of a `DensityMatrix` payload exact;
see section 7.)

---

## 1. Module layout

| Module | Responsibility | Public surface |
| --- | --- | --- |
| `sih141/core/rng.py` | The single randomness entry point | `resolve_rng`, `seed_to_generator` |
| `sih141/core/paulis.py` | Pauli algebra, the three measurement bases, basis-change circuits | `PauliBasis`, `PAULI_I/X/Y/Z`, `pauli_matrix`, `eigenstate`, `eigenstate_label`, `BASIS_CHANGE`, `basis_change_circuit`, `random_basis`, `verify_eigenstate` |
| `sih141/core/states.py` | State construction, the canonical validator, entanglement measures | `BellState`, `BELL_ORDER`, `StateLike`, `bell_state`, `bell_circuit`, `as_density`, `fidelity`, `purity`, `concurrence`, `is_normalised` |
| `sih141/core/measure.py` | Born rule, true collapse, sampling, expectations, Bell measurement | `MeasurementOutcome`, `born_probabilities`, `projective_measure`, `measure_qubits`, `joint_probability`, `sample_counts`, `expectation`, `bell_measure` |
| `sih141/core/teleport.py` | The teleportation protocol, its correction table and the channel it induces | `TeleportationResult`, `RegisterTeleportationResult`, `pauli_correction`, `correction_bits`, `teleport`, `teleport_in_register`, `teleport_channel`, `teleport_circuit` |

Dependencies run strictly one way (`rng` → `paulis` → `states` → `measure` → `teleport`),
so there are no import cycles and any layer can be tested with the ones below it intact.

`sih141/core/__init__.py` re-exports every public name with an explicit `__all__` and no
wildcard imports, so Phase 2 can write:

```python
from sih141.core import PauliBasis, bell_state, teleport, projective_measure
```

**One sharp edge, deliberately taken.** `teleport` is re-exported as the *function*, which
shadows the submodule attribute of the same name. `from sih141.core.teleport import
teleport_circuit` and `importlib.import_module("sih141.core.teleport")` both work
normally, because they resolve through `sys.modules`. But `import sih141.core.teleport as
t` binds `t` to the **function**, because the `as` form ends with an attribute lookup on
the parent package. The function gets the short name because it is what callers want; the
behaviour is pinned by a test rather than left to be discovered.

---

## 2. Design decisions

### D1: The canonical state type is `DensityMatrix`

Every function that returns a post-measurement or post-channel state returns a
`qiskit.quantum_info.DensityMatrix`. Pure states may be *built* as `Statevector`; every
public function that *accepts* a state accepts `Statevector`, `DensityMatrix` or a raw
array and normalises through the one shared helper `states.as_density`.

*Why.* Phase 3 introduces depolarising channels and intercept-resend attacks, both of which
produce genuinely mixed states. Had the core been written around `Statevector`, Phase 3
would have had to either fork every function or bolt on a parallel mixed-state path: the
classic point at which two code paths drift and the noisy one stops being tested. Making
mixed states first-class from the start costs nothing here: the register is at most three
qubits, so the largest object in the project is an 8×8 matrix.

The choice has a concrete consequence that shows up throughout `measure.py`: Born
probabilities are computed as `Tr(ρP)`, never as `|⟨ψ|P|ψ⟩|²`, and collapse uses the
Lüders form `ρ → PρP / Tr(ρP)`. Both reduce to the pure-state rules as a special case, and
both stay correct when Phase 3 hands them a Werner state.

`as_density` is the single validator, and it is strict on purpose: it checks `Tr ρ = 1`,
`ρ = ρ†` and `ρ ⪰ 0`. The positivity check is the load-bearing one. A Hermitian trace-one
matrix with a negative eigenvalue still has a well-defined trace, spectrum and overlap, so
`fidelity`, `purity` and `concurrence` would all happily return a number for it; because
they clip into `[0, 1]`, that number is biased toward *"pure, maximally entangled,
undisturbed"*. That is exactly the direction that would hide an attack in Phases 3–5, so
it is rejected at the boundary instead of absorbed downstream.

### D2: Qiskit little-endian qubit ordering

Qubit 0 is the **rightmost** character of a bitstring label. A single-qubit operator on
qubit *q* of an *n*-qubit register is embedded as `1_{n-1} ⊗ … ⊗ A_q ⊗ … ⊗ 1_0`, so
amplitude indices satisfy `index = Σ_q b_q · 2^q`. Pauli strings passed to `expectation`
follow the same rule: in `"ZI"`, `Z` acts on qubit 1.

*Why.* Not because little-endian is better, but because a project that mixes conventions
produces bugs that are silent: the state is still normalised, the probabilities still sum
to 1, and only the *attribution* of an outcome to a qubit is wrong. In a detection system
that is the worst possible failure mode: the QBER estimate stays plausible while measuring
the wrong thing.

Consistency alone is not enough to catch it, so the convention is pinned by tests that use
**asymmetric** states. `|01⟩` is the workhorse: little-endian puts it at amplitude index 1,
big-endian at index 2, so a Z measurement of qubit 0 is certainly `−1` and of qubit 1
certainly `+1`. Symmetric states such as `(|00⟩+|11⟩)/√2` cannot distinguish the two
conventions at all and are never used for this purpose.

### D3: Determinism through one `rng` seam

Every function that consumes randomness takes keyword-only `rng: np.random.Generator |
None = None` and resolves it through `sih141.core.rng.resolve_rng`. `numpy.random.*`
module-level functions and the stdlib `random` module appear nowhere in the codebase.

*Why.* Phase 5 reports ROC curves and detection rates, and a number nobody can reproduce is
not evidence. Threading one generator through a whole experiment gives one reproducible stream:

```python
rng = np.random.default_rng(20260141)
a = projective_measure(state, 0, PauliBasis.Z, rng=rng)
b = projective_measure(a.post_state, 1, PauliBasis.X, rng=rng)
```

`resolve_rng` rejects integer seeds and the legacy `RandomState` with an explanatory error
rather than accepting them. Accepting a seed would look convenient and be wrong: it would
restart the stream on every call, so a loop of "random" measurements would return the same
value every time, a bug that produces perfectly plausible-looking, completely correlated
data.

Seeds do nevertheless arrive as bare integers (from a Phase 5 CLI flag, a JSON run
description, a Phase 6 config field). `seed_to_generator(seed)` is the **one sanctioned
conversion** at that boundary, and it exists precisely so that callers do not reach for
`numpy.random.default_rng` inline at each call site, which is what D3 forbids. Convert
once, thread the object thereafter:

```python
generator = seed_to_generator(args.seed)   # boundary, once per run
for trial in range(trials):                # one continuous stream
    outcome = projective_measure(state, 0, PauliBasis.Z, rng=generator)
```

It is deliberately *not* a second `resolve_rng`: it refuses generators (use `resolve_rng`),
booleans, floats and strings, so the two entry points cannot be confused. `None` means
fresh entropy, as everywhere else.

### D4: No AI/ML

Linear algebra and classical statistics only, per the problem statement. Nothing in Phase 1
learns, fits or trains.

---

## 3. The Bell-outcome → correction table

Derived, not memorised, and re-derived numerically by the test suite.

Register layout (little-endian): qubit 0 = payload, qubit 1 = sender's half of the
resource, qubit 2 = receiver's half. `teleport` builds it as
`resource.tensor(DensityMatrix(payload))`, which puts the payload on the **low** index.

With payload `|ψ⟩ = a|0⟩ + b|1⟩` and resource `|Φ⁺⟩ = (|00⟩ + |11⟩)/√2`, expanding the
three-qubit state in the Bell basis of the pair (q0, q1) gives

```
|ψ⟩₀ |Φ⁺⟩₁₂  =  ½ [ |Φ⁺⟩₀₁ (a|0⟩ + b|1⟩)₂
                  + |Ψ⁺⟩₀₁ (b|0⟩ + a|1⟩)₂
                  + |Φ⁻⟩₀₁ (a|0⟩ − b|1⟩)₂
                  + |Ψ⁻⟩₀₁ (b|0⟩ − a|1⟩)₂ ]
```

Each of the four branches carries a prefactor of ½, so **every outcome has probability
exactly 1/4 for any payload**, the reason the two classical bits leak nothing.

The classical bits are read straight off the canonical ordering
`BELL_ORDER = (Φ⁺, Ψ⁺, Φ⁻, Ψ⁻)` as `2·m₁ + m₀ = BELL_ORDER.index(outcome)`, and the
correction is `X^m₀ Z^m₁`:

| Index | Outcome | m₀ (X exp.) | m₁ (Z exp.) | Receiver holds | Correction `X^m₀ Z^m₁` |
| :---: | :--- | :---: | :---: | :--- | :--- |
| 0 | `Φ⁺` | 0 | 0 | `a\|0⟩ + b\|1⟩` = `\|ψ⟩` | `I` |
| 1 | `Ψ⁺` | 1 | 0 | `b\|0⟩ + a\|1⟩` = `X\|ψ⟩` | `X` |
| 2 | `Φ⁻` | 0 | 1 | `a\|0⟩ − b\|1⟩` = `Z\|ψ⟩` | `Z` |
| 3 | `Ψ⁻` | 1 | 1 | `b\|0⟩ − a\|1⟩` = `−XZ\|ψ⟩` | `XZ` |

Two notes on the last row. The Pauli operators are Hermitian and self-inverse, so `X` and
`Z` invert their own branches directly. For `Ψ⁻` the conditional state is `−XZ|ψ⟩`, and
since `(XZ)² = −I` the correction `XZ` returns exactly `|ψ⟩` with no residual phase.
Writing `ZX` instead would differ by a global phase (`ZX = −XZ`) and be equally correct
physically; the order is a convention, fixed here so the table has one form and the tests
can assert matrices rather than only fidelities.

`m₀` is the X exponent and corresponds to the measured bit of qubit 1; `m₁` is the Z
exponent and corresponds to the measured bit of qubit 0.

**Why the tests sweep all six Pauli eigenstates.** `{|0⟩, |1⟩}` alone cannot detect a
missing or wrong `Z` correction, because both are `Z` eigenstates and `Z` acts on them as a
global phase. Adding `{|+⟩, |−⟩}` still cannot detect a swapped `X`/`Z` pair. The
`{|+i⟩, |−i⟩}` pair is what closes the gap: the six states are the endpoints of the three
Bloch axes, and every non-identity Pauli anticommutes with two of them, so it maps four of
the six to the *orthogonal* state, the most visible error available. This is verified
directly rather than assumed, and confirmed by mutation: replacing `X` with `−iY` in the
correction table (a single sign flip, physically not a global phase) turns 23 tests red,
including exactly the `X±` and `Y±` integration cases and leaving `Z±` green.

---

## 4. Numerical policy in `measure.py`

Two constants are **derived** rather than chosen, and both are pinned by tests.

`_PROB_TOL = states._VALIDATION_TOL`. The completeness check `p₊ + p₋ = 1` must not be
tighter than the tolerance of the project's own state validator. `as_density` admits a
trace deviation up to `1e-8` and does *not* renormalise, so a tighter measurement tolerance
would reject states the project declares legal, and would blame "malformed projectors" for
ordinary input drift. `born_probabilities` additionally divides by the realised total, so
admitted drift is removed rather than propagated into the reported probabilities.

`_MIN_BRANCH_PROB = eps / _VALIDATION_TOL ≈ 2.22e-8`. Collapse evaluates `PρP`, whose
entries carry an *absolute* round-off residue of order machine epsilon while the true
entries are of order `p`. Renormalising to unit trace therefore inflates that residue to a
*relative* error of order `eps/p`, which appears as negative eigenvalues of that size.
Requiring the result to stay inside the positivity tolerance, `eps/p ≤ _VALIDATION_TOL`,
forces `p ≥ eps/_VALIDATION_TOL`. The previous hand-picked value of `1e-12` was four orders
of magnitude too permissive: it admitted branches whose "post-measurement state" was not a
density operator at all (observed smallest eigenvalue `−1.8e-7`) and which `as_density`
then rejected, so the result could not be fed back into any other function in the module.

Belt and braces: `_collapse` also projects the spectrum back onto the positive semidefinite
cone (negatives clipped, trace renormalised) so the guarantee holds *by construction*, and
refuses to do so when the negative mass exceeds `100 × _VALIDATION_TOL`; repair is a
round-off eraser, not a bug eraser. The cost is one 8×8 eigendecomposition per measurement.

The practical effect of the guard is that an outcome of probability below ~2e-8 is never
reported. That is a documented, quantified approximation, and it is precisely the regime in
which the collapsed state could not have been represented faithfully anyway. Since the
skipped weight is redistributed over the surviving branches, the realised distribution
differs from the exact Born distribution by at most (number of branches) × 2.2e-8, below
4 × 2.2e-8 for a Bell measurement. The docstrings of `projective_measure`,
`measure_qubits` and `bell_measure` all state this, because a reader who is told
"exact Born sampling" and nothing else will eventually use them for a tail statistic.

`sample_counts` has **no** such floor: it draws from an exact multinomial over the joint
distribution and never collapses anything, so a branch of probability 1e-12 is sampled at
its true rate. Rare-event and distribution-tail work belongs there; the collapsing
functions are for when the post-measurement state is actually needed.

---

## 5. What Phase 2 builds on

The QDS protocol should need no changes to this layer. The seams it attaches to:

- **Key-state generation**: `random_basis(rng=…)` and `eigenstate(basis, eigenvalue)`
  produce the BB84-style signature states; `eigenstate_label` gives the human-readable form
  for logging and for the Phase 6 dashboard.
- **Signature transmission**: `teleport(payload, resource=…, rng=…)` runs the real
  protocol (a genuine Bell measurement and collapse, not a shortcut), and
  `TeleportationResult` carries everything a verifier needs: the Bell outcome, the two
  classical bits, the receiver's state and the fidelity. The payload may be **mixed**, so a
  relayed key qubit can be fed straight back in for a second hop.
- **Relaying and entanglement swapping**: `teleport_in_register(register,
  payload_qubit=…, resource_qubits=(sender, receiver), rng=…)` is the general primitive:
  it moves one qubit of a larger register and preserves that qubit's correlations with
  every other qubit in it. Phase 2 should call this rather than reimplementing correction
  bookkeeping directly on `bell_measure`.
- **Verification readout**: `measure_qubits` for a full basis-by-basis readout with the
  collapse threaded through, `sample_counts` for shot statistics with little-endian
  bitstring keys, `expectation` for the ±1 correlators that Phase 4's CHSH and QBER
  statistics are sums of.
- **Noise and attack injection (Phase 3)**: the `resource` argument of `teleport` accepts
  any two-qubit density matrix. A Werner state `(1−p)|Φ⁺⟩⟨Φ⁺| + p·I/4` already yields the
  analytic fidelity `1 − p/2`, which the test suite verifies across eight noise levels.
  This is the hook the whole attack suite hangs from; nothing in `teleport` needs to know an
  attack occurred. Attacks on the **forward payload line** (rather than on
  the resource) attach at the `payload` argument instead, which now accepts a mixed state.
- **Analytic prediction (Phase 4/5)**: `teleport_channel(resource)` returns the induced
  single-qubit channel as a `Kraus`, so a QBER or an average fidelity can be computed
  exactly instead of sampled with `1/√N` error. Compose hops with
  `SuperOp(a).compose(SuperOp(b))`; compare channels through `Choi`, never through the
  Kraus list, which is only defined up to an isometry.
- **Statistics (Phase 4/5)**: the honest-case null distribution is already established and
  tested here: the four Bell outcomes are uniform at 1/4, and the two classical bits are
  marginally unbiased and mutually independent. Phase 4's hypothesis tests are tests
  *against this distribution*, so a biased sampler would invalidate every downstream number
  without failing a single fidelity assertion, which is why `tests/test_integration.py`
  tests uniformity with a chi-square goodness-of-fit statistic (3 dof, closed-form p-value,
  no SciPy dependency) alongside per-outcome four-sigma bands computed from the sample size.

Two invariants Phase 2 may rely on without re-checking: every state returned by this layer
passes `as_density`, and every stochastic function consumes exactly one variate per
decision from the generator it is given.

---

## 6. Small contracts fixed for Phases 4–6

Four things the core promised loosely and now promises exactly. Each was a silent-failure
seam rather than a bug: everything kept running, and only a downstream number was wrong.

### `BellState` and `PauliBasis` are `StrEnum`

Both are `enum.StrEnum`, so a member *is* its label: `BellState.PHI_PLUS == "Phi+"`,
`str(PauliBasis.X) == "X"`, and `json.dumps` accepts members directly, as values **and** as
dictionary keys. Phase 4 histograms, Phase 5 result records and the Phase 6 dashboard need
that; previously both `json.dumps` and `sorted()` raised `TypeError`. `repr` is unchanged
(`<BellState.PHI_PLUS: 'Phi+'>`), so every error message built with `{which!r}` reads
exactly as before, and `.value` still works everywhere it is used.

Ordering is documented and stable, not incidental:

- `PauliBasis` sorts as its one-character labels do: `X < Y < Z`.
- `BellState` sorts by `BELL_ORDER` (`Φ⁺, Ψ⁺, Φ⁻, Ψ⁻`) via explicit `__lt__`/`__le__`/
  `__gt__`/`__ge__`, **not** lexicographically. The string order would be
  `Phi+ < Phi- < Psi+ < Psi-` (`'+'` is 0x2B, `'-'` is 0x2D), which interleaves the phases
  and would put histogram rows out of correction-index order. `sorted(counts)` therefore
  produces protocol-order rows for free, and `member.order_index` is the correction index
  `2·m₁ + m₀`.

### The empty basis map behaves the same at both entry points

`measure_qubits(state, {})` returned `([], as_density(state))` while
`sample_counts(state, {}, n)` raised `ValueError`. A Phase 4 loop that builds a basis map
dynamically would then live or die on which of the two it happened to call.
`sample_counts` now takes the general path: zero measured qubits means 2⁰ = 1 outcome of
probability 1, so the result is `{"": shots}` (and `{}` for `shots == 0`, since zero counts
are omitted). The counts-sum-to-shots contract is preserved.

### `MeasurementOutcome.probability` is conditional, and `joint_probability` says so

The `probability` of record *k* from `measure_qubits` is `Pr(oₖ | o₀ … oₖ₋₁)`, not a
marginal; measurement *k* acts on the state the previous ones already collapsed. On `|Φ⁺⟩`
with `{0: Z, 1: Z}` the two records read `0.5` and `1.0`. A detector that averages them
gets `0.75`, which is neither qubit's marginal (both `0.5`) nor the joint probability
(`0.5`), and nothing about it looks wrong. The list is a chain-rule factorisation, so the
entries **multiply**: `joint_probability(outcomes)` is that product, exported so the correct
thing is the convenient one. Marginals come from `born_probabilities` on the *original*
state, or from `sample_counts`.

### The Bell pair order is a genuine no-op

`bell_measure`'s docstring claimed the `qubits[0]`/`qubits[1]` order mattered for `Ψ⁻`,
"where swapping the pair would flip the sign". It does flip the sign of the *vector*. But
the projector is an outer product, and `(−v)(−v)† = vv†` erases it. Measured: the four
projectors are bit-identical under the swap (max absolute difference exactly `0.0`), on two-
and three-qubit registers, adjacent pairs and not. Swapping changes no outcome label, no
probability and no collapsed state; the docstrings now say that, and a test pins it.

---

## 7. Post-audit API widening

The Phase 1 adversarial audit returned `verdict=sound` on the physics (an independent numpy
reference and a Qiskit Aer cross-check both matched to ~1e-16, and the Werner fidelity law
`1 − p/2` was exact to 12 decimals) but found two API limits that would have blocked
Phase 3. Both are now removed, and the general primitive is the one Phases 2 and 3 should
call.

### `teleport` accepts a mixed payload

`_payload_statevector` used to raise when `Tr(rho^2) != 1`, and the docstring advised
"degrade the resource instead". That is an equivalent model for *some* attacks only. It
cannot express noise or an intercept-resend acting on the **forward payload line**, and it
cannot express relaying a key qubit over **more than one hop**. Feeding the (mixed) output
of one `teleport` into the next is exactly the flow a multi-hop signature relay needs. The
teleportation algebra is linear in rho and never required purity; the restriction existed
only because `TeleportationResult.payload` was typed `Statevector` and the fidelity was
measured against it. `payload` is now `StateLike`, a mixed payload is stored **unpurified**,
and `fidelity` is measured against what was actually submitted. A pure payload still
round-trips with its exact amplitudes and global phase.

### `teleport_in_register` moves a correlated qubit

```python
result = teleport_in_register(register, payload_qubit=0, resource_qubits=(2, 3), rng=rng)
result.register        # the surviving qubits, correction already applied
result.payload_index   # where the teleported qubit landed
```

The payload no longer has to be standalone: teleporting qubit A of an entangled pair
`(A, R)` leaves the surviving pair with **concurrence still exactly 1**, and the exact joint
state is preserved (pinned with an asymmetric, non-maximally-entangled pair, since
`|Φ⁺⟩` is invariant under too much to catch a wrong table). Entanglement swapping is
therefore a three-line call. `teleport` is now a thin wrapper over this primitive (driven
from the same seed, the two agree bit for bit), so there is no second copy of the register
layout or the correction table to drift.

Index bookkeeping: tracing out the payload and the sender's half renumbers everything above
them. Survivors keep their relative order, so a qubit at index `q` moves to `q` minus the
number of consumed indices below `q`. `payload_index` is that image of `resource_qubits[1]`.

### `teleport_channel`: the protocol as a channel

`teleport_channel(resource)` returns the effective single-qubit channel, averaged over the
Bell outcomes with corrections applied, as a `qiskit.quantum_info.Kraus`. It is written in
closed form, not obtained by tomography: diagonalising `rho_res = sum_k lambda_k |v_k><v_k|`,
each outcome/branch pair contributes `K_{B,k} = U_B M_{B,k}` with

    M_{B,k}[r, p] = sum_s conj(B_{2s+p}) * sqrt(lambda_k) * (v_k)_{2r+s}

That is the teleportation identity of section 3 with the payload left as a free index.

Two limits fix the construction, both asserted through the **Choi matrix** rather than by
sampling: `teleport_channel(|Φ⁺⟩)` is the identity channel and `teleport_channel(I/4)` is
the completely depolarising channel. It also agrees with Monte-Carlo `teleport` on five
non-trivial resources, and with an independent brute-force Bell-projection reference to
`1e-12`.

**The induced channel is always a Pauli channel.** The corrections twirl the resource, so
only its diagonal in the Bell basis survives:

    E(rho) = sum_B q_B * U_B rho U_B^dagger,   q_B = <B|rho_res|B>

Three consequences worth knowing before Phase 4 is written. A QBER is a linear function of
four inner products read straight off the resource: no tomography, no sampling. Every
teleportation channel is unital and any two of them **commute**, so a multi-hop chain
depends only on the multiset of hops, not their order, even when the noise processes that
produced the resources do not commute. And a non-unital resource does *not* give a
non-unital channel: amplitude damping on the resource shows up only as a lopsided `q_B`.
For the Werner family `q = (1 − 3p/4, p/4, p/4, p/4)`, i.e. the depolarising channel of
strength `p`, which is where `F = 1 − p/2` comes from and why two hops compose as
`eta = (1−p1)(1−p2)` with `F = 1 − (1−eta)/2`. That is **not** `F1 * F2`: at
`p1 = p2 = 0.3` the truth is `0.7450`, the naive product `0.7225`.

### Two smaller audit items

- `TeleportationResult.fidelity` is set from `states.fidelity`, the clipped helper, not from
  qiskit's raw `state_fidelity`, which returns `1.000000000000001` on a large fraction of
  pure-vs-pure comparisons, while `__post_init__` hard-raises outside `[0, 1]`. The
  invariant is true by construction rather than by luck of the PSD-repair step, and a
  2000-run regression test pins it.
- `teleport`'s Notes claimed the receiver's pre-correction marginal is `I/2` "regardless of
  the payload". Payload-independence is right and is the whole no-signalling argument; the
  `I/2` half holds only when the resource is *locally* maximally mixed. Every Bell and
  Werner state is, but an amplitude-damped resource is not: for damping of strength
  `gamma` on the receiver's half of `|Φ⁺⟩` the marginal is
  `diag((1+gamma)/2, (1−gamma)/2)`. The wording now separates the two claims.

### The Phase 2 audit: fidelity must not depend on how a state was spelled

Widening `teleport` to accept a mixed payload made a second path through
`states.fidelity` reachable, and the two paths disagreed. Qiskit's `state_fidelity` takes
the exact `⟨ψ|ρ|ψ⟩` shortcut when one argument is a `Statevector` but the `sqrtm`-based
Uhlmann formula when both are `DensityMatrix`, and the `sqrtm` route carries about `1e-8`
of absolute error. So a *pure* payload handed in as a 2-D array produced a byte-identical
`received` state and a **different** reported fidelity (`0.8500000063` against the exact
`0.85`), an order of magnitude outside the `1e-9` calibration contract the Werner tests
assert everywhere else.

`states.fidelity` now detects a pure argument (`|Tr(ρ²) − 1| ≤ 1e-12`) and uses the exact
closed form `F = Tr(ρσ)`, which holds whenever *either* state is pure. It is one matrix
product: exact to machine epsilon, and cheaper than the eigendecomposition it replaces.
Only genuinely mixed-versus-mixed comparisons, which have no closed form, still go through
`sqrtm`, and a test pins that they still do; the commuting case
`F = (Σ_k √(a_k b_k))²` is not `Tr(ρσ)`, so the two branches are distinguishable.

Three further properties of `teleport.py` were correct but unasserted, and each is now
pinned by a test that the corresponding mutation fails: the receiver's post-trace index for
a hop that moves a qubit *downward* in the register (`max(0, receiver − 2)` agrees with the
right rule on every layout the old suite used), the branch-weight floor in
`teleport_channel` (raising it to `0.02` silently drops the `p/4` Kraus branches of a
Werner resource with `p ≤ 0.08` and breaks trace preservation by up to `3p/4`), and the
`bool` guard on register indices (`payload_qubit=True` would otherwise teleport qubit 1).
