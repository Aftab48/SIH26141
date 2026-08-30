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
| **Quantum Digital Signatures (this project)** | **Physics — no-cloning and measurement disturbance** | **Nothing: information-theoretically secure** |

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
sih141/core/     quantum primitives (Phase 1)
  rng.py         seeded Generator threading — all randomness is reproducible
  paulis.py      Pauli operators, eigenstates, basis-change circuits
  states.py      Bell states, density-matrix helpers, fidelity, concurrence
  measure.py     Born-rule probabilities, projective measurement, Bell measurement
  teleport.py    teleportation protocol and Pauli correction table
tests/           pytest suite
docs/            engineering notes per phase
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
