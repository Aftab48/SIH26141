# Quantum-Inspired Cyber Threat Detection for Digital Signature Security

**Smart India Hackathon 2026 — Problem Statement `SIH26141`**
Organization: Egreen Quanta · Category: Software · Theme: Blockchain & Cybersecurity

---

## What this is

A software framework that detects attacks against **teleportation-based Quantum Digital
Signature (QDS)** protocols — forgery, impersonation, replay, and quantum channel
manipulation — using **quantum measurement statistics and classical hypothesis testing**,
with **no AI/ML anywhere in the detection path**.

Everything runs as a *classical simulation* of quantum mechanics. **No quantum hardware is
required.** That is what "quantum-inspired" means in the problem statement title.

## Why not just use RSA, or an ML-based intrusion detector?

| Approach | Basis of security | Broken by |
| --- | --- | --- |
| RSA / ECC signatures | Computational hardness (factoring, discrete log) | Shor's algorithm on a fault-tolerant quantum computer |
| Post-quantum signatures (ML-DSA, SLH-DSA) | Computational hardness, quantum-resistant *by assumption* | A future cryptanalytic break of the assumption |
| **Quantum Digital Signatures (this project)** | **Physics — no-cloning and measurement disturbance** | **No computational advance. The bounds are information-theoretic — but they are bounds *under stated conditions*, not magic; see [Security claims](#security-claims-stated-honestly).** |

"Information-theoretically secure" is a claim about what an adversary's *computer* cannot
do. It is not a claim that the protocol has no assumptions, and this project states its
assumptions rather than letting the phrase carry them.

The same logic drives the no-AI/ML constraint. A machine-learning detector produces an
*empirical* detection rate with no provable bound, which would silently discard the
information-theoretic guarantee that is the entire reason to prefer QDS over post-quantum
cryptography. This framework instead uses **statistical hypothesis testing against
analytically known honest-case distributions**, with thresholds derived from concentration
inequalities. That yields a *provable* false-acceptance bound rather than an observed one.

## Threat model

| Attack | What the adversary does | Detection signal |
| --- | --- | --- |
| **Forgery** | Produces a signature without the signer's private key | Basis-mismatch count exceeds threshold; success probability decays exponentially in key length |
| **Impersonation** | Poses as the signer during key distribution or signing | Authentication-round statistics deviate from honest distribution |
| **Replay** | Re-sends a previously valid (message, signature) pair | Consumed-session ledger; one-time key states |
| **Channel manipulation** | Tampers with entanglement distribution (intercept-resend, entanglement swapping, injected noise) | QBER rises; CHSH value falls from 2√2 toward the classical bound of 2 |

## Security claims, stated honestly

Phase 2 ships three guarantees. Each is given with the hypothesis it rests on, because a
bound quoted without its hypothesis is not a bound. Numbers are at `DEFAULT_PARAMS`
(`L = 115200`, `s_a = 1/64`, `s_v = 1/16`, bases `{X, Y, Z}`); all are computed by
`sih141.protocol.analysis`, which contains closed forms only and no simulation.

| Property | Bound | Rests on |
| --- | --- | --- |
| **Unforgeability**, outside adversary | `< 1e−100` | She does not hold a verifier's log. Part of the stated adversary model. |
| **Unforgeability**, recipient forger (the case that binds) | `1.1e−103` | The symmetrisation exchange reveals only the swapped entries. |
| **Non-repudiation**, a-priori | **`1.9e−09`** | **Nothing.** The matched-count floor `verify.py` enforces, not an assumption about the signer. |
| **Non-repudiation**, per completed run | `6.9e−10` on a healthy run | **Nothing.** Conditions on the run's own evidence, `M = m_B + m_C`. |
| Robustness — honest run aborts | `< 1e−9` on a 1% depolarising channel | Standard channel model. The matched-count floor adds `2.5e−31`. |

### The correction a reader should know about

An earlier version of this project published `6.9e−10` as a non-repudiation guarantee
holding "for every Alice strategy, with no model of Alice". **It does not.** That figure
averages over the matched count `M ~ Binomial(2L, 1/|B|)`, which is the law of `M` only
while the signer cannot see which bases the recipients logged — and the `Signer` seam hands
her both raw logs. A signer who reads them pins `M = 13` at *any* key length and repudiates
with probability `1/2`. Key length does not help, because the failure is not statistical.

The mathematics was never wrong; the advertising was. Three things replaced it:

1. **The per-run bound is mandatory and assumption-free.** `repudiation_bound` now requires
   the observed `M`; every transcript carries it as `repudiation_guarantee` and prints it.
   The averaged form is renamed `averaged_repudiation_bound` and refuses to answer without
   naming its hypothesis.
2. **A matched-count floor makes an unconditional number possible.** A verifier refuses to
   score a matched set below `minimum_matched_count` (`36555` here, derived from a Chernoff
   lower tail at a `2⁻⁶⁴` honest-abort budget — no tuning, no fitting, D4-clean). That
   forces `M ≥ 2 × 36555` on any run reaching two verdicts, giving `1.9e−09` **with no
   independence assumption at all** — within a factor of three of the number that used to be
   published, this time actually earned. Measured: the attack above now produces **0
   repudiations in 40 runs**, and **0 spurious aborts in 460 honest runs**.
3. **What is still open is written down.** Without the floor, *no unconditional bound below
   `1/2` exists* against a log-reading signer, at any key length — that is a proved
   limitation, not a gap in the analysis. With the per-verifier floor, one route remains: a
   signer aiming `M` at `2 × m_min` can leave the second verifier below *his* floor while
   the first accepts (measured 14 of 40 runs). That ends in a **recorded no-verdict**, never
   a reject verdict, so the bound above stands — but if a deployment counts a no-verdict as
   a failed transfer, it needs a *pooled* floor and one extra classical message. Priced in
   `docs/PHASE2.md` §6b-iii. It is not implemented.

Full derivations, the reproduction of the attack, and every measurement are in
[`docs/PHASE2.md`](docs/PHASE2.md) §6b. The cross-module agreement between the floor and the
bounds is pinned by `tests/test_protocol_reconciliation.py`.

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Project scaffold, dependencies | ✅ Complete |
| 1 | Quantum core — Pauli algebra, Bell states, projective measurement, teleportation | ✅ Complete |
| 2 | QDS protocol — key distribution, signing, verification, transferability | ✅ Complete |
| 3 | Attack suite — the four adversaries above, plus realistic channel noise | ⬜ |
| 4 | Detection engine — QBER, CHSH, mismatch statistics, Hoeffding-derived thresholds | ⬜ |
| 5 | Evaluation — forgery probability vs. key length, ROC, FAR/FRR, benchmarks | ⬜ |
| 6 | Web dashboard — live attack/detection demo | ⬜ |
| 7 | Submission docs — mathematical modelling and security analysis | ⬜ |

> **Note on scope.** The published problem statement ends with an unfilled placeholder where
> the organization's deliverables table should be (*"Add 'Delivery Table (Expected
> Deliverables)' here"*). The roadmap above is therefore our own explicit interpretation of
> the stated Objectives and Expected Solution, documented deliberately rather than left implicit.

## Setup

Requires Python 3.11+. Verified on Python 3.14.4 / Windows 11.

```bash
pip install -r requirements.txt
```

## Running the tests

```bash
python -m pytest
```

## Layout

```
sih141/core/       quantum primitives (Phase 1)
  rng.py           seeded Generator threading — all randomness is reproducible
  paulis.py        Pauli operators, eigenstates, basis-change circuits
  states.py        Bell states, density-matrix helpers, fidelity, concurrence
  measure.py       Born-rule probabilities, projective measurement, Bell measurement
  teleport.py      teleportation protocol and Pauli correction table
sih141/protocol/   the QDS protocol (Phase 2)
  params.py        parameters, parties, thresholds, and the validation that refuses
                   an insecure set
  keys.py          Alice's private keys and the quantum public key
  records.py       the recipients' immutable classical logs
  distribute.py    Phase A — teleportation and immediate measurement on receipt
  symmetrise.py    Phase A′ — the recipients' private exchange, and the reason
                   non-repudiation holds at all
  signature.py     Phase B — the declaration
  verify.py        Phase C — the matched/unmatched split, the accept rule, and the
                   matched-count floor that makes an unconditional bound possible
  session.py       orchestration, and the five seams Phase 3 attacks attach to
  analysis.py      closed forms only, no simulation: forgery, repudiation, robustness
tests/             pytest suite
docs/              engineering notes per phase
```

## Design decisions

1. **Density matrices are the canonical state type.** Phase 3 introduces noisy channels, and
   pure-state-only code would need rewriting at that point. Systems here are 1–3 qubits, so
   the cost is negligible.
2. **Little-endian qubit ordering throughout** (Qiskit convention: qubit 0 is the rightmost
   bit). Pinned by tests using asymmetric states, since symmetric states such as
   |00⟩+|11⟩ cannot distinguish the two conventions.
3. **All randomness flows through an injected `numpy.random.Generator`.** No global
   `numpy.random` or stdlib `random` calls anywhere. Reproducible seeding is a prerequisite
   for the Phase 5 evaluation to be credible.
4. **No AI/ML anywhere in the detection path.** Every threshold in the codebase is a closed
   form in the protocol parameters, derived from a concentration inequality — including the
   matched-count floor, which is a Chernoff tail at a fixed budget and not a learned or
   tuned cut. Nothing is fitted to data, so every detection number has a proof rather than
   an observed rate.
5. **Every security claim is quoted with its hypothesis.** Functions that average over an
   adversary-controllable quantity carry a mandatory argument naming the assumption, so the
   convenient number cannot be obtained by accident. See
   [Security claims](#security-claims-stated-honestly).
