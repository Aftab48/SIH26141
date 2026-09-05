# SIH26141: Project Track

**Quantum-Inspired Cyber Threat Detection for Digital Signature Security**
Egreen Quanta · Software · Blockchain & Cybersecurity · Idea 

---

## Contents

1. [The one-paragraph version](#1-the-one-paragraph-version)
2. [Why this problem exists](#2-why-this-problem-exists)
3. [Why quantum signatures instead of post-quantum crypto](#3-why-quantum-signatures-instead-of-post-quantum-crypto)
4. [How our protocol works](#4-how-our-protocol-works)
5. [The threat model: what we assume and what we defend](#5-the-threat-model)
6. [What we detect](#6-what-we-detect)
7. [Why we are banned from using AI, and why that is correct](#7-why-we-are-banned-from-using-ai)
8. [Architecture: what the code actually contains](#8-architecture)
9. [What is built: Phases 0–2](#9-what-is-built-phases-02)
10. [Attacking ourselves: the security findings](#10-attacking-ourselves)
11. [The numbers, in one table](#11-the-numbers-in-one-table)
12. [The plan: Phases 3–7](#12-the-plan-phases-37)
13. [Known limitations we state openly](#13-known-limitations)
14. [How to run it](#14-how-to-run-it)
15. [Glossary](#15-glossary)

---

## 1. The one-paragraph version

We are building software that detects attacks on digital signatures: forgery, impersonation,
replay, and channel tampering. It sits on a signature scheme whose security comes from **the
laws of physics rather than from a hard maths problem**, and that matters because quantum
computers will break the maths every current signature depends on. Our detection layer uses
statistical hypothesis testing with **provable** bounds, not machine learning, because a
provable bound is the entire reason to use this kind of signature in the first place.
Everything runs as a classical simulation on an ordinary laptop: **no quantum hardware is
required.**

---

## 2. Why this problem exists

A digital signature has to deliver three properties. Losing any one of them makes it useless:

| Property | What it means | What breaks without it |
| --- | --- | --- |
| **Unforgeability** | Only the holder of the private key can produce a valid signature | Anyone can sign as you |
| **Non-repudiation** | The signer cannot later deny having signed | Contracts become unenforceable |
| **Transferability** | If one person accepts a signature, everyone else will too | It is a shared password, not a signature |

Today all three rest on a computation being *hard*. RSA relies on factoring large integers;
ECC relies on the elliptic-curve discrete logarithm. Both are hard for classical computers and
**both fall to Shor's algorithm** on a sufficiently large fault-tolerant quantum computer.

The consequence is not only "future signatures become forgeable." It is retroactive: every
archived document, certificate, and signed software release loses its proof of origin, because
an attacker with a quantum computer can manufacture a signature indistinguishable from the
original.

---

## 3. Why quantum signatures instead of post-quantum crypto

There are two families of answer, and the difference is the heart of our pitch.

| Approach | Security rests on | Failure mode |
| --- | --- | --- |
| **RSA / ECC** (deployed today) | Factoring / discrete log being hard | Shor's algorithm. Not hypothetical; the attack is known and published. |
| **Post-quantum cryptography** (ML-DSA, SLH-DSA) | *Different* maths believed hard even for quantum computers | A future cryptanalytic break. Nobody can prove the assumption holds. |
| **Quantum Digital Signatures**, what we build | **No-cloning and measurement disturbance** | **Nothing.** Information-theoretically secure: safe against an adversary with unlimited computing power. |

Post-quantum cryptography is a reasonable engineering answer and is being standardised. But it
replaces one *computational assumption* with another. QDS replaces the assumption with physics:

- **No-cloning:** an unknown quantum state cannot be copied. Not "cannot be copied efficiently."
  Cannot be copied at all.
- **Measurement disturbance:** measuring an unknown state in the wrong basis irreversibly
  randomises it, and leaves evidence.

These are not conjectures awaiting a proof. They are consequences of quantum mechanics, and an
attacker with infinite computing power is no better off than one with a laptop.

---

## 4. How our protocol works

### 4.1 The parties

| Party | Role |
| --- | --- |
| **Alice** | The signer |
| **Bob** | First recipient and verifier |
| **Charlie** | Second verifier: **required**, because transferability is meaningless without someone to transfer *to* |

### 4.2 Why our design differs from the textbook one

The original QDS scheme (Gottesman–Chuang, 2001) requires recipients to **store quantum states**
until a signature arrives. That needs long-lived quantum memory, which does not practically
exist. Our problem statement specifically asks for a teleportation-based scheme that "reduces
some of the practical deployment complexities associated with earlier QDS schemes."

So we combine two ideas:

- **Teleportation-based distribution.** The key states never travel down the channel. Only
  pre-shared entanglement plus two ordinary classical bits per qubit.
- **Measurement-based recipients.** Bob and Charlie measure each state the moment it arrives
  and keep only a *classical* record. **No quantum memory anywhere in the system.**

### 4.3 The phases

#### Phase A: Distribution

For each possible message bit `b ∈ {0, 1}`:

1. Alice draws a private key `k_b = [(basis_i, eigenvalue_i)]` for `i = 1 … L`, where each
   `basis_i` is uniform over `{X, Y, Z}` and each `eigenvalue_i` is uniform over `{+1, −1}`.
   At production parameters **L = 115,200**.
2. The corresponding quantum public key is the product state `⊗_i |basis_i, eigenvalue_i⟩`.
3. Alice sends **one copy to Bob and one to Charlie, by teleportation**, consuming a fresh Bell
   pair per qubit.

> **The no-cloning objection, and its answer.** People will ask how Alice can send two copies of
> a quantum state when copying is forbidden. She is not copying anything. She holds the
> *classical description* and prepares each state twice from scratch. No-cloning forbids
> duplicating an *unknown* state. This objection comes up every time, so have the answer ready.

4. On receipt, each recipient **immediately** measures qubit `i` in a uniformly random basis and
   records `(i, chosen_basis, outcome)`. The quantum state is then gone.

#### Phase A′: The recipients' symmetrisation exchange

Bob and Charlie flip a fair coin per position and **swap that fraction of their records with
each other**, privately.

This step is not decoration. Without it, Alice can send Bob one thing and Charlie another,
making Bob accept while Charlie rejects, which lets her deny her own signature. We discovered
this the hard way; see §10.

#### Phase B: Signing

Alice sends `(message, k_b)` to Bob over an authenticated classical channel. The revealed key
*is* the signature.

#### Phase C′: The matched-count exchange

Bob and Charlie exchange **one number each**: how much usable evidence they hold. If either is
holding suspiciously little, both refuse to judge rather than guessing. This closes an attack
described in §10, and it costs one extra classical message.

#### Phase C: Verification

Each recipient `R` compares their record against the declared key:

```
MATCHED    M_R = { i : basis_R,i == basis_i as declared }
MISMATCH   e_R = |{ i ∈ M_R : outcome_R,i ≠ eigenvalue_i as declared }|
RATE       r_R = e_R / |M_R|
```

A recipient chose the same basis as Alice about **one third** of the time (three bases), so
`E[|M_R|] = L/3 = 38,400` per verifier. **Unmatched positions carry no information** (the
outcome there is uniformly random) and must be discarded, never counted as mismatches. This is
the classic implementation bug in QDS, and we have an explicit test that fails if it reappears.

The verifier then applies four checks in order:

```
abort   if  |M_R| < m_min                  own floor: no verdict, NOT a rejection
abort   if  counts came from two different declarations
abort   if  |M_R| + m_counterpart < M_min  the pooled floor
abort   if  m_counterpart < m_min          his counterpart cannot score either
accept  iff r_R ≤ threshold(R)
```

with `threshold(Bob) = s_a = 1/64` and `threshold(Charlie) = s_v = 1/16`.

### 4.4 Why `s_a < s_v`

This gap is the mechanism that makes it a signature at all, and it is worth being able to
explain on demand:

- **`s_v > s_a` gives transferability.** Charlie's bar is *lower* than Bob's, so a signature
  Bob accepted is overwhelmingly likely to clear Charlie too.
- **`s_a > 0` gives non-repudiation.** Alice cannot craft something that squeaks past Bob but
  fails Charlie, because she does not know which evidence each of them holds (Phase A′).

Both failure probabilities shrink exponentially in `L`.

### 4.5 The abort rule

Aborts are recorded **separately from verdicts**, with a separate type. A refusal to judge is
not a rejection, and no statistic anywhere is allowed to average the two together. The floor
itself is *derived*, not chosen:

```
|M_R| ~ Binomial(L, 1/3),  μ = L/3
Chernoff lower tail:  P[|M| ≤ (1−δ)μ] ≤ exp(−δ²μ/2)
Honest-abort budget:  ε = 2⁻⁶⁴
                      δ = √(2 ln(1/ε) / μ)
                  m_min = ⌈(1−δ)μ⌉ = 36,555      (95.2% of the mean)
```

The pooled floor `M_min = 74,190` is derived the same way from `M = m_B + m_C ~ Binomial(2L, 1/3)`.
Total honest-abort probability is **8.0 × 10⁻³¹**, ten orders of magnitude below the security
bounds, so the abort rule can never become the dominant reason an honest run fails.

---

## 5. The threat model

**What we defend against:** an adversary with unlimited computing power who may be Alice
(trying to deny a signature), a recipient (trying to forge one), or an outsider on the channel.

**What we assume, and must say openly:**

- **The classical and quantum channels from Alice are authenticated.** If an attacker can fully
  impersonate Alice from the very start (distributing her own key states *and* signing them),
  she is accepted, because nothing in the protocol binds an identity. Measured: **60/60 accepted
  by both verifiers at QBER exactly 0.** This is inherent to every scheme in this family, not a
  defect of ours, but it is load-bearing and we state it rather than hoping nobody asks.
  *Partial* impersonation is caught cold: 0/60 accepted, QBER ≈ 0.5.
- **The symmetrisation coins are private to the recipients.** The non-repudiation proof depends
  on Alice not knowing them. We found and fixed a bug where an attack harness could read them
  (§10).
- **Recipients follow the protocol during the exchange phases.** A recipient who lies about his
  matched count can force aborts, which is a denial-of-service, not a forgery. Phase 3 measured it:
  free, deterministic, and detectable at `z <= -11.54` ([PHASE3](PHASE3.md) §6).

---

## 6. What we detect

The problem statement does not ask us to invent the signature scheme. It asks for the
**threat-detection framework layered on top of it**.

| Attack | What the adversary does | Detection signal | Status |
| --- | --- | --- | --- |
| **Forgery** | Produces a signature without the private key | Mismatch rate exceeds threshold; success decays exponentially in `L` | Implemented and measured |
| **Impersonation** | Poses as Alice during distribution | QBER jumps to ≈ 0.5 | Measured; full impersonation is out of model by assumption |
| **Replay** | Re-sends a captured `(message, signature)` pair | Round identifier on the declaration; consumed-records ledger per verifier | Built and measured: `100/100` accepted before, `0/100` after ([PHASE3](PHASE3.md) §5) |
| **Channel manipulation** | Intercept-resend, entanglement swapping, injected noise | Per-link QBER rises; CHSH falls from 2√2 toward 2 | Measured on both the entanglement line and the payload line; the per-link form also *names* the compromised party ([PHASE3](PHASE3.md) §4) |
| **Count starvation** *(we found this one)* | A recipient under-reports his matched count | The declared count as a z-score: below `-11.54` at every key length | Measured: free, deterministic, and it cannot be done quietly ([PHASE3](PHASE3.md) §6) |

CHSH separates the channel attacks cleanly:

| Channel condition | CHSH value |
| --- | --- |
| Ideal entanglement | **2.8284** (the quantum maximum, 2√2) |
| Depolarising, p = 0.3 | 1.9799 |
| Eve keeps a GHZ share | 2.0000 |
| Intercept-resend | 1.0020 |

---

## 7. Why we are banned from using AI

The brief forbids machine learning in the detection path. This reads as arbitrary and is not.

An ML detector produces an **empirical** number: "97% accurate on our test set." That is an
observation about data already seen. It carries no guarantee about tomorrow's attack, and no
bound you can put in a proof.

The entire reason to choose QDS over post-quantum cryptography is that QDS gives
**information-theoretic** security: a guarantee that holds against unlimited computing power.
Bolting an ML detector on top would silently discard exactly that guarantee, because the
system's overall security would then be capped by the weakest, unprovable component.

What we use instead is **statistical hypothesis testing against analytically known
distributions**. Because we know exactly what honest behaviour looks like mathematically, we can
derive thresholds from concentration inequalities (Hoeffding, Chernoff) that come with provable
bounds. We do not say "we caught it in testing." We say:

> *Being fooled has probability at most 1.4139 × 10⁻⁹, and here is the derivation.*

That distinction is what a knowledgeable judge will probe, and it should be the thing our demo
makes obvious.

---

## 8. Architecture

```
sih141/
  core/            the physics engine (Phase 1)
    rng.py         seeded generator discipline; all randomness is reproducible
    paulis.py      Pauli operators, the six eigenstates, basis-change circuits
    states.py      Bell states, density matrices, fidelity, concurrence
    measure.py     Born-rule probabilities, projective measurement, Bell measurement
    teleport.py    teleportation, the correction table, and the induced channel

  protocol/        the signature scheme (Phase 2)
    params.py      ProtocolParams: L, s_a, s_v, and their validation
    keys.py        private key generation, public key states
    records.py     the recipients' immutable classical logs
    distribute.py  teleportation-based distribution (Phase A)
    symmetrise.py  the recipients' exchange (Phase A′)
    signature.py   signing (Phase B)
    tally.py       the matched-count exchange (Phase C′)
    verify.py      verification, the floors, and the abort rule (Phase C)
    session.py     orchestration and the attack seams
    analysis.py    analytic closed forms; no simulation lives here

  tests/           1,418 automated tests
  docs/            per-phase engineering notes, metrics, this document
  tools/           metrics, working journal, and commit tooling
```

### Standing design rules

These are enforced across the codebase and worth knowing before you touch anything:

- **D1: density matrices are canonical.** Noisy channels arrive in Phase 3; pure-state-only
  code would have needed rewriting at the worst moment. At 1–3 qubits the cost is nil.
- **D2: little-endian qubit ordering**, pinned by tests using *asymmetric* states. Symmetric
  states like `|00⟩+|11⟩` look identical under either convention and cannot catch the bug.
- **D3: all randomness through injected generators.** No global `numpy.random`, no stdlib
  `random`, anywhere. Reproducibility is what makes the Phase 5 evaluation credible.
- **D4: no AI/ML anywhere.** See §7.
- **D5: documented numbers are executable.** `pytest` runs with `--doctest-modules`, so a
  number written as a doctest is checked on every run. Documentation that goes stale fails the
  build.

---

## 9. What is built: Phases 0–2

### Phase 0: Scaffold ✅

Python 3.14 + Qiskit 2.5.2, pinned. One command runs everything. Chosen over a browser-based
TypeScript simulator (loses Qiskit's credibility and noise models) and over a CLI-only tool
(no demo).

### Phase 1: The physics engine ✅

Five modules implementing Pauli algebra, Bell states, projective measurement and teleportation.
The correction table was **derived from first principles**, not copied.

Verification was unusually strong. An independent reviewer rebuilt the entire 3-qubit
teleportation register from scratch in raw NumPy, reusing no project code: its own index
arithmetic, its own Bell projectors, its own partial trace. The comparison covered 13 resource
families × 12 payloads × 40 seeds.

> Maximum deviation **5.55 × 10⁻¹⁶**. Werner-resource fidelity matched the closed form
> `1 − p/2` exactly to 12 decimal places. Cross-checked independently against Qiskit Aer with
> 400,000 shots.

A pleasing detail that shows the physics is right rather than merely consistent: teleporting
through a `|Ψ⁺⟩` resource gives fidelity `0.9216` for payload `[0.6, 0.8]`, which is exactly
`|⟨ψ|X|ψ⟩|²`, the correct consequence of `|Ψ⁺⟩ = (I ⊗ X)|Φ⁺⟩`. Nobody told the code that.

### Phase 2: The protocol ✅

Ten modules implementing all phases above, plus `analysis.py` containing the closed-form
security expressions. Every analytic formula was cross-checked against an **independently
written** Monte Carlo simulator; the requirement was that agreement be real evidence rather
than a tautology.

They agreed, including on the micro-parameters rather than just the headline:

| Quantity | Predicted | Measured |
| --- | --- | --- |
| Recipient forgery success | 0.481427 | 0.4933 *(Wilson 95%: 0.4681–0.5186)* |
| Forger's scored fraction | 2/3 = 0.6667 | 0.6671 |
| Forger's mismatch rate | 1/12 = 0.0833 | 0.0825 |
| Outside forgery | 0.012520 | 0.0090 and 0.0140 |

With symmetrisation switched off, the measured recipient-forgery rate moves to 0.0313 against a
prediction of 0.029393, which directly exhibits the `ρ: 1/12 → 1/3` collapse that symmetrisation
is there to prevent.

---

## 10. Attacking ourselves

We ran adversarial teams against our own protocol. **They broke it three times.** Every break
was real, reproduced by measurement, and fixed.

This is a selling point, not an embarrassment. A judge asking *"how do you know this is secure?"*
gets a far stronger answer from three measured breaks with before/after numbers than from a
clean specification nobody ever attacked.

### Break 1: Alice could deny her signature every single time

**What happened.** Our first design had Alice distribute to Bob and Charlie independently. She
simply sent Bob states matching the key she would declare and sent Charlie states that did not.

```
Bob:     r_B = 0.0000  → ACCEPT
Charlie: r_C = 0.4032  → REJECT
Result:  40 / 40 successful repudiations
```

Non-repudiation, one of the three properties a signature exists to provide, was **absent
entirely**.

**Fix.** The recipients' symmetrisation exchange (Phase A′). After: **20/20 unsymmetrised,
0/20 symmetrised.**

**Cost.** Symmetrisation makes a *recipient* the binding adversary rather than an outsider,
which quartered the forger floor from 1/3 to 1/12 and forced the key length from 6,912 to
**115,200** to hold the same guarantee.

### Break 2: we were advertising a guarantee we did not have

**What happened.** `repudiation_bound()` was documented as valid for *every* Alice strategy.
It was not: it silently assumed Alice's declared bases are independent of the recipients' logged
bases. Alice controls exactly that.

```
Published bound at production parameters:  6.9173 × 10⁻¹⁰
Measured repudiation rate:                 0.46 – 0.58
```

Nine orders of magnitude of overclaim. The *mathematics* was correct: the conditional form
returns 0.9964, correctly predicting the attack works. The error was **publishing the averaged
number as unconditional**.

**Fix.** Split into an assumption-free per-run bound and a gated averaged form, plus the
Chernoff-derived matched-count floor.

**A result fell out of it.** Worst-casing over the matched count gives 0.99973, which is useless. And
that is not slack: an explicit strategy achieves exactly 1/2 at every `L`. So:

> **No unconditional repudiation bound below 1/2 exists without an abort rule.**

That is a theorem about the protocol, now stated in `PHASE2.md`. The bug produced a real result.

### Break 3: a subtler version of the same trick

**What happened.** With only per-verifier floors, Alice aims the *total* matched count at
`2 × m_min = 73,110` and splits it evenly, so neither verifier trips its own floor and no
mismatch rate looks anomalous.

```
Before:  78/200 (0.390) at L=360,  85/200 (0.425) at L=600
After:   0/200 at both
```

The attack gets **stronger** with `L` (predicted 0.4985 at production parameters), so the
small-scale demonstration carries upward rather than being a convenient special case.

**Fix.** The pooled floor plus a joint consequence, both riding on one extra classical message
(Phase C′).

### Break 4: the harness, not the protocol

Our own attack harness leaked the symmetrisation coins: `QDSSession` passed one generator to the
adversary-controlled distribution seam and then drew the coins from *the same object*. An
attacker could clone its state and precompute every coin.

```
Repudiated 5/5 at production parameters, with every floor met,
while the transcript printed "P(repudiation) ≤ 1.414e-09"
```

**This was not a flaw in the bound.** The proof assumes the coins are private, and a real Alice
has no such access. But every attack number this project publishes comes from that harness, and
those numbers were correct only because our attack code *happened* not to peek.

**Fix.** Two cryptographically derived generator streams; the recipient stream is never handed
to any Alice-side seam. Verified in both directions, plus an exhaustive sibling hunt: object-graph
walk of all six seams, 0/4001 generator-rewind steps, 0/19 seed-reconstruction routes.

---

## 11. The numbers, in one table

| Quantity | Value | Meaning |
| --- | --- | --- |
| `L` | 115,200 | Key length at production parameters |
| `s_a` | 1/64 = 0.015625 | Bob's acceptance threshold |
| `s_v` | 1/16 = 0.0625 | Charlie's acceptance threshold |
| `m_min` | 36,555 | Per-verifier matched-count floor |
| `M_min` | 74,190 | Pooled matched-count floor |
| `M_min − 2·m_min` | 1,080 | The margin that closes Break 3; grows like √L |
| `E[\|M_R\|]` | 38,400 | Expected matched positions per verifier |
| Repudiation bound | 1.4139 × 10⁻⁹ | Unconditional, with the abort rule |
| Recipient forgery | 2.17 × 10⁻¹⁰⁵ | The binding forgery adversary |
| Honest-abort probability | 8.0 × 10⁻³¹ | Cost of the abort rule, against a 2⁻⁶⁴ budget |
| Session runtime | 2.04 ms/position | 235 s, or 3.9 minutes, for one full-scale session |
| Test suite | 3,750 tests | ~25 minutes to run |

---

## 12. The plan: Phases 3–7

### Phase 3: The attack suite *(complete, see [PHASE3.md](PHASE3.md))*

> The plan as written below is kept as a record of what was planned. All three items landed,
> and two things the plan did not anticipate turned up: the shipped Phase C' ordering made the
> recipient-forgery rate of the real protocol unmeasurable, and the replay ledger's
> denial-of-service surface was priced at zero when it is not zero. Both are in
> [PHASE3.md](PHASE3.md).


Working, measured implementations of every attack, so the numbers are evidence rather than
assertion. Three things are real work rather than plumbing:

- **Build the replay defence.** Nothing currently stops a captured signature being re-sent:
  measured, the same signature was accepted 3/3 times at rate 0.0. This needs a nonce or
  session binding inside `Signature` and a check inside `verify()`, both of which are changes to
  protocol code.
- **Add a channel-monitor seam.** `distribute_to_recipient` currently builds a full
  `TeleportationResult` per qubit (Bell outcome, correction bits, fidelity) and throws it
  away, so Phase 4 cannot see the entanglement statistics at all.
- **Restrict the signer seam** to the real threat model, keeping the over-powered version as a
  loud opt-in for attack simulation only.

Plus a `payload_map` seam, a widened forwarder, and measuring the count-starvation attack.

### Phase 4: The detection engine

The centrepiece and our strongest differentiator. Turns raw statistics into decisions, with every
threshold **derived** rather than tuned: QBER, CHSH, mismatch counts, replay ledger, and a
discriminator that separates recipient forgery from channel noise (Charlie's matched count does
this at 240σ at production parameters).

### Phase 5: Evaluation *(complete, see [PHASE5.md](PHASE5.md))*

Forgery probability against key length, ROC curves, false-accept and false-reject rates,
performance benchmarks. Full-scale statistical runs live here, and they are embarrassingly
parallel: every trial takes its own injected seed (D3), so a trial's result depends on its
seed and on nothing else.

> **The cost, measured rather than estimated.** One honest session at `DEFAULT_PARAMS`
> (`L = 115200`, `check_fraction = 0`) takes **230.2 s (3.84 min, or 1.999 ms per position)**,
> timed end to end on the target machine with nothing else running. So 200 trials is **12.8
> hours** single-threaded. Scaling is linear: 2.0–2.4 ms/position holds across `L = 192` to
> `L = 115200`, a 600× range.
>
> The original estimate in this section was "~15 hours single-threaded", which is correct and
> mildly conservative. It is recorded here that an intermediate measurement claimed 6.7
> ms/position and a 42.9-hour total, and that figure was wrong: the profiler
> (`tracemalloc`) was left attached, inflating every timing by very close to 3×. The error is
> written down rather than quietly corrected because it is this project's own named failure
> mode (a number true of the measurement rather than of the thing measured) and because a
> brief had already been written that handed it to an agent as established fact.
>
> **Confirmed independently at the start of Phase 5** by a second end-to-end run at the same
> parameters under a different seed: **235.1 s, or 2.041 ms per position**, 2.1% above the
> figure above. It is `sih141.eval.perf.MEASURED_SESSIONS`, and every total derived from it is
> a doctest over that constant rather than prose, so the totals cannot drift away from the rate
> they came from. Regenerate with
> `python tools/sweep.py perf --session-scaling --key-lengths 115200`.
>
> **The parallel figure in this section was wrong, and its replacement does not reproduce
> either.** It read "about **51 minutes** at 20 workers on this CPU's realistic 15× effective
> speedup". The 15× was an estimate and both measurements agree it is wrong. But the two
> measurements do not agree with each other: 120 sessions per point at `L = 768` gave **7.04×**
> on the first run and **10.27×** when the identical command was re-run during Phase 5
> integration. The twenty-worker wall clock held to 2.2% across the two (29.10 s and 29.75 s);
> the **single-worker baseline moved by 49%**, and the speedup is a ratio with that baseline
> underneath it. So 200 trials at `DEFAULT_PARAMS` is between **1.3 and 1.9 hours** on this
> machine depending on what else it is doing, and no single speedup number should be quoted from
> this project. The pool is not idling (17.6 of 20 workers busy on average, and the production
> sweep independently shows 19.02 of 20); the cores are simply slower when they are all awake,
> and it starts at eight workers, before any E-core is reached. Both curves, and the causes ruled
> out, are in [PHASE5.md](PHASE5.md) §11.2. Regenerate with
> `python tools/sweep.py perf --speedup --speedup-cell l768 --trials 120 --workers 1,4,8,14,20`.
>
> **Transcript size depends on the check fraction as much as on `L`.** At `check_fraction = 0`,
> which is what `DEFAULT_PARAMS` uses, a full-scale transcript is **0.226 KiB per position,
> 25.4 MiB**. At `check_fraction = 0.25` the same length is **0.330 KiB per position, 37.2 MiB**,
> because every check round publishes a channel sample. Both are measured; quoting either
> without its check fraction is how a correct number becomes a wrong one. Mixing kibibytes
> with decimal megabytes in the same sentence is how the second figure once read 26.7. The
> smaller lengths are 0.337, 0.330 and 0.325 KiB per position at `L = 96, 192, 768` with a
> quarter of positions checked; the curve dips around `L = 768` and comes back, so it is not the
> monotone amortisation an earlier draft described.
>
> **Detector latency is not a constant few milliseconds.** It is 1.54 s on a full-scale
> transcript against 2.9 ms on a 96-position one, because it is dominated by parsing the JSON,
> so it scales with `L` like everything else. Still under one percent of the session that
> produced the transcript.

**Phase 6 was built first.** The work order was 4 → 6 → 5 → 7; see the roadmap note in
`README.md` for why. Nothing in Phase 6 depends on the numbers this phase produces.

> **Results.** The production sweep ran 12,494 trials across seven experiments in 23.3 minutes at
> twenty workers, zero failures. Every figure is in [PHASE5.md](PHASE5.md) beside the one command
> that regenerates it; the reduced tables are in [`tables/`](tables) and the charts in
> [`figures/`](figures).

### Phase 6: The dashboard

FastAPI serving both the API and a static frontend: one process, one command, no Node build
step. Charts via ECharts or Plotly, **vendored locally, never from a CDN**, because venue wifi
fails and a demo that dies on an unreachable CDN is the worst possible failure.

Pick an attack → watch QBER and CHSH move → watch the floors fire → see the abort recorded as a
no-verdict, with the proven bound sitting beside the measured rate.

### Phase 7: Submission documents

The mathematical modelling write-up, the security analysis, and the full record of every attack
we ran against ourselves.

---

## 13. Known limitations

We state these rather than hoping nobody looks. Each one is worse if a judge finds it first.

- **Demo-scale runs cannot demonstrate non-repudiation.** Both floors are inert below `L ≈ 1200`,
  and the enforced bound is 0.994 at demo parameters, 0.943 at `L=600`, still 0.48 at `L=4800`.
  This section used to say "a real Alice genuinely repudiates ~3.5% of the time at `L=600`", and
  Phase 5 measured it: at `L=600` the best symmetric tilt achieves `1.936e-03` in model and
  **`1/400 = 0.0025 [0.0003, 0.0209]`** over 400 trials. 3.27% is the figure for `L ≈ 138`, and it
  is on the `l138` row of [PHASE5.md](PHASE5.md) §7. Worse for the claim: at `L = 768` the
  measurement is `0/400`, whose 99% upper limit `0.0163` is twenty-eight times coarser than the
  exact probability and fifty-six times tighter than the proven bound `0.9212`, so **neither the
  proof nor the measurement reaches the other**. Demo runs show the **mechanism**, not the
  guarantee, and the UI must say so.
- **Full impersonation succeeds with probability 1** if the channel from Alice is not
  authenticated. Inherent to this family of schemes; stated as a precondition.
- **A recipient can force aborts** by under-reporting his matched count. Denial of service, not
  forgery, but it is a real fifth attack surface and Phase 3 measured it ([PHASE3](PHASE3.md) §6).
- **The problem statement's deliverables table was left blank** by the organisation; the
  published brief ends with an unfilled placeholder. Our scope is therefore our own documented
  reading of the stated objectives, recorded deliberately rather than left implicit.

---

## 14. How to run it

Requires Python 3.11+. Verified on Python 3.14.4 / Windows 11.

```bash
pip install -r requirements.txt
```

```bash
python -m pytest
```

```bash
python tools/metrics.py
```

`docs/METRICS.md` is generated, never hand-edited; every figure in it is computed from the
codebase, including the live security parameters read straight out of the package.

---

## 15. Glossary

| Term | Plain meaning |
| --- | --- |
| **Qubit** | A quantum bit. Unlike a normal bit it can be in a combination of 0 and 1 until measured. |
| **Basis** | The "direction" you choose to measure in. We use three: X, Y, Z. Measuring in the wrong one gives a random answer. |
| **Eigenstate** | A state that gives a definite, repeatable answer when measured in a particular basis. |
| **Bell pair / entanglement** | Two particles whose measurement results are correlated no matter how far apart they are. |
| **Teleportation** | Moving a quantum state from A to B using shared entanglement and two classical bits. The state itself never crosses the channel. |
| **No-cloning** | An unknown quantum state cannot be copied. A law, not a difficulty. |
| **QBER** | Quantum Bit Error Rate: the fraction of results that disagree when they should match. Rises under attack. |
| **CHSH** | A test of how genuinely entangled a pair is. Maxes at 2√2 ≈ 2.83; anything ≤ 2 could be faked classically. |
| **Information-theoretic security** | Secure against unlimited computing power, forever. Stronger than "computationally secure". |
| **Hoeffding / Chernoff bound** | Maths tools that convert "this sample looks odd" into a provable probability of being wrong. |
| **Repudiation** | The signer denying she signed. Prevented by making Bob's and Charlie's verdicts agree. |
| **Transferability** | If Bob accepts, Charlie will too. What makes a signature a signature. |

---

*Generated figures come from `docs/METRICS.md`. Per-phase engineering detail is in
`docs/PHASE1.md` and `docs/PHASE2.md`. The running decision log is `JOURNAL.md`.*
