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

| Attack | What the adversary does | Detection signal | Measured (Phase 3) |
| --- | --- | --- | --- |
| **Forgery**, outside | Produces a signature without the signer's private key | Basis-mismatch count exceeds threshold; success decays exponentially in key length | mismatch `0.4956`/`0.5018` on a predicted `1/2`; acceptance `5/800` vs `0.0042` |
| **Forgery**, forging recipient | Forwards his own measured log as the signature | Mismatch hits the `1/12` symmetrisation floor, *and* the matched count doubles to `2L/3` | acceptance `96/300 = 0.320` vs a predicted `0.3456` |
| **Impersonation** | Poses as the signer during key distribution or signing | Mismatch rate — and *only* the mismatch rate; the matched counts do not move at all | `0/40` accepted at QBER ≈ `1/2` for either seam alone; `200/200` accepted for **both** seams, which assumption (AUTH) excludes and nothing detects |
| **Replay** | Re-sends a previously valid (message, signature) pair | Consumed-records ledger; round identifier on every declaration | `100/100` → `0/100` with the defence; cross-session `0.115` → `0/100` |
| **Channel manipulation** | Tampers with entanglement distribution (intercept-resend, kept share, injected noise) | Per-link QBER rises; CHSH falls from 2√2 — and the *per-link* form is what names the compromised party | QBER `0.0994`/`0.3306`/`0.3335` on predictions `p/2`, `1/3`, `1/3` |
| **Count starvation** | A recipient understates his own matched count and denies the other a verdict | The declared count as a z-score: any successful starvation sits below `−11.54` honest standard deviations, at every key length | denial `20/20`, deterministic and free — one integer |

## Security claims, stated honestly

Phase 2 ships three guarantees. Each is given with the hypothesis it rests on, because a
bound quoted without its hypothesis is not a bound. Numbers are at `DEFAULT_PARAMS`
(`L = 115200`, `s_a = 1/64`, `s_v = 1/16`, bases `{X, Y, Z}`); all are computed by
`sih141.protocol.analysis`, which contains closed forms only and no simulation.

| Property | Bound | Rests on |
| --- | --- | --- |
| **Unforgeability**, outside adversary | `< 1e−100` | She does not hold a verifier's log. Part of the stated adversary model. |
| **Unforgeability**, recipient forger (the case that binds) | `1.1e−103` | The symmetrisation exchange reveals only the swapped entries. |
| **Non-repudiation**, a-priori | **`1.4e−09`** | **Nothing.** The three matched-count floors `verify.py` enforces, not an assumption about the signer. |
| **Non-repudiation**, per completed run | `6.9e−10` on a healthy run | **Nothing.** Conditions on the run's own evidence, `M = m_B + m_C`. |
| Robustness — honest run aborts | `< 1e−9` on a 1% depolarising channel | Standard channel model. The matched-count floors add `8.0e−31`. |

### The correction a reader should know about

An earlier version of this project published `6.9e−10` as a non-repudiation guarantee
holding "for every Alice strategy, with no model of Alice". **It does not.** That figure
averages over the matched count `M ~ Binomial(2L, 1/|B|)`, which is the law of `M` only
while the signer cannot see which bases the recipients logged — and the `Signer` seam handed
her both raw logs. A signer who reads them pins `M = 13` at *any* key length and repudiates
with probability `1/2`. Key length does not help, because the failure is not statistical.
(Phase 3 restricted the seam: the logs are now withheld by default and shown only to a
session built with `signer_sees_recipient_logs=True`, which the transcript records. That
narrows who can break the assumption; it does not make the averaged figure quotable for a
run, which is why the per-run bound below is the one to read.)

The mathematics was never wrong; the advertising was. Three things replaced it:

1. **The per-run bound is mandatory and assumption-free.** `repudiation_bound` now requires
   the observed `M`; every transcript carries it as `repudiation_guarantee` and prints it.
   The averaged form is renamed `averaged_repudiation_bound` and refuses to answer without
   naming its hypothesis.
2. **Matched-count floors make an unconditional number possible.** A verifier refuses to
   score a matched set below `minimum_matched_count` (`36555` here, derived from a Chernoff
   lower tail at a `2⁻⁶⁴` honest-abort budget — no tuning, no fitting, D4-clean). Measured:
   the `M = 13` attack above now produces **0 repudiations in 40 runs**, and **0 spurious
   aborts in 460 honest runs**.
3. **What was still open was written down, and has since been closed.** The per-verifier
   floor left one route: a signer aiming the *pooled* count `M` at `2 × m_min` and letting
   the symmetrisation coins split it leaves the first verifier accepting a signature the
   second cannot score — no rate deviating anywhere, so no exponent applies. Measured at
   **78/200** (`L = 360`) and **85/200** (`L = 600`), tending to `1/2`.

### Closing it: one extra classical message

`tally.py` is Phase C′. Bob and Charlie each send the other a single integer — how many
positions they can score — over the channel they already share for the symmetrisation
coins. A count, never a log. That buys two rules:

* a **pooled floor** `m_B + m_C ≥ M_min` with `M_min = 74190`, derived from the same
  `2⁻⁶⁴` budget applied to `M ~ Binomial(2L, 1/3)` — exact by *conservation*, not by
  independence, since after the exchange the two counts are perfectly dependent. It exceeds
  `2 × m_min = 73110` by `1080` records, and the margin grows like `√L`, so the aimed-at
  declaration is refused rather than priced; and
* a **joint consequence**: a verifier below his own floor takes the other down with him. The
  pooled floor alone would leave a best response worth `ε^(3−2√2) = 4.9e−04`
  *independent of key length*; this removes the asymmetric outcome from the outcome space
  entirely, so "Bob accepted" implies "Charlie reached a verdict".

Result: **`1.4e−09`, unconditional, with nothing left to quote beside it** — and the attack
measures **0/200** at both key lengths after the change. The price is one message each way,
an honest-abort cost of `8.0e−31` per run against a `5.4e−20` budget, and one ordering
change: Bob's verdict is no longer local, since he must forward the declaration and hear
Charlie's count before he can accept. What remains outside the number is denial of service —
a signer who starves the evidence base aborts the run jointly, transferring nothing, which
no threshold defends against and which Alice could equally achieve by not signing.

Full derivations, the reproduction of both attacks, and every measurement are in
[`docs/PHASE2.md`](docs/PHASE2.md) §6b. The cross-module agreement between the floors and the
bounds is pinned by `tests/test_protocol_reconciliation.py`, and the pooled law and floor by
`tests/test_protocol_tally.py`.

## What Phase 3 found

Five adversaries, each mounted on the protocol's own seams. **Not one of them needed a
protocol change to be mounted**, which is what those seams were for. Mounting an adversary
and *measuring* it are not the same thing, though, and the first result below is the gap that
turned up between them. Full account in [`docs/PHASE3.md`](docs/PHASE3.md); three results are
worth stating here.

**A guarantee that could not be measured, now can be — and it holds.** The shipped session
ran the Phase C′ count exchange *before* the Bob-to-Charlie hop, so a forging recipient's
declaration was refused on provenance and the second verifier never scored it. That is a
denial of transfer, not a detection, and it made the recipient-forgery rate of the shipped
scheme unmeasurable: every published figure came from the pre-pooled variant. Which
declaration each recipient counts is now a named parameter, `count_exchange_timing`. Under
the deployment ordering the forger is scored and accepted `96/300 = 0.320` against
`recipient_forgery_probability(L=60) = 0.345566` — agreement at `z = −0.93`, and the first
measurement of the real thing.

**Symmetrisation is worth a factor of four, measured rather than argued.** Same adversary,
same code path, one seam swapped: mismatch rate `0.0863` on the `1/12` floor with Phase A′,
`0.3378` on the `1/3` floor without. The two 95% intervals, `[0.0814, 0.0915]` and
`[0.3191, 0.3570]`, do not come close to touching. That gap is what the key length pays for.

**A denial-of-service surface priced at zero is not zero.** `verify.py` reasoned that since
a round is spent only on a verdict, the only party who can burn one on a declaration that
will be rejected is the signer herself — who could equally decline to sign. The inference is
false: Phase B publishes the round's opening *on the declaration*, so anyone downstream can
mint a different declaration naming the same round, and the Bob-to-Charlie hop is exactly
where the threat model puts an adversary. Measured `300/300` at `L = 24`. What closes it is
the *ordering* of Phase C′ — not the ledger and not the round binding — and the honest price
is now written down. Both obvious repairs are worse: spending only on acceptance would give
an adaptive adversary unlimited tries at one round.

### The rule that makes the numbers mean anything

Convention **D6**: every adversary takes its own `numpy.random.Generator` and never derives
randomness from the seed the harness gives the session. This is not fastidiousness. An
attack written the natural way — one seed, so the experiment reproduces — rebuilds the whole
run from that integer and predicts **every private symmetrisation coin**, `120/120` on both
message bits, in about ten lines of public API. The mathematics is untouched; the
*experiment* becomes fiction, and it looks entirely legitimate: same seams, same transcript,
same printed bound.

`sih141/attacks/isolation.py` makes that a behavioural check — hold the attack's generator
fixed and vary the session seed, and its decisions must not move; hold the seed fixed and
vary its generator, and they must. All **14** adversary-and-seam pairs pass it in
`tests/test_phase3_isolation_suite.py`, every deliberately-defective control is still caught,
and adding a sixth adversary is one row in a table.

The first half of that check was **inert for most of Phase 3** — every probe deleted the
session seed, so all fourteen rows passed a check none of them could fail — and the audit that
found it is why the pass is now evidenced per row rather than asserted: each shipped adversary
is re-run with the session's own seed folded into its generator, through its own probe, and
check (a) has to catch it. Thirteen of the fourteen are covered directly; the fourteenth moves
with nothing at all, which is the same fact its check-(b) waiver rests on.

**A published statistic that could be steered, and now cannot be.** Besides the entanglement
line, a channel-side adversary holds two seams, and both gave the check set away for free:
`payload_map` was called on key rounds only, so the *gaps* in its call sequence were the check
set — 24 of 24 recovered at `L = 96`, precision `1.0000` against a base rate of `0.2500` — and
`channel_monitor` was called on check rounds only, so *being called* was the whole signal, 120
of 120 at `L = 480`. An adversary who read it could wreck the key and spare exactly the watched
positions, publishing a clean QBER over a corrupted link. Both seams are now called at every
position and what they return is discarded where it has no use; and a plan's reserved rounds
are **dealt between the two links**, so recovering one link's check set does not hand over the
other's. Re-measured: the payload seam's call gaps are now empty, and the monitor's call set is
every position, which contains that link's check rounds at exactly the base rate and no better.
The price is written down rather than absorbed: each link publishes half of `check_count`
rounds, per-link intervals are `√2` wider, and the claim that a one-link attack can be
*attributed* needed twice the key length to keep.

Nine mutation checks confirm the defences are actually tested — the replay ledger, the
declaration binding, check (a) of the isolation check, the route by which check (a) reaches a
candidate, the payload seam's every-position call, the channel monitor's, the per-link deal,
the last two together, and the session a channel isolation probe runs. Each turns the relevant
tests red and only those tests; the two seam mutations were measured against the *whole* suite
and cost 10 failures and 6.

Full suite: **2169 passed in 12 min 29 s**, up from 1421 at the end of Phase 2.

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Project scaffold, dependencies | ✅ Complete |
| 1 | Quantum core — Pauli algebra, Bell states, projective measurement, teleportation | ✅ Complete |
| 2 | QDS protocol — key distribution, signing, verification, transferability | ✅ Complete |
| 3 | Attack suite — the four adversaries above, plus count starvation and realistic channel noise | ✅ Complete |
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
  tally.py         Phase C′ — the recipients' matched-count exchange, one integer
                   each way, and the pooled floor it makes checkable
  verify.py        Phase C — the matched/unmatched split, the accept rule, and the
                   three matched-count floors that make an unconditional bound possible
  checkrounds.py   sampled channel estimation — QBER and CHSH on positions spent
                   on measurement instead of on key
  session.py       orchestration, and the seams Phase 3 attacks attach to
  analysis.py      closed forms only, no simulation: forgery, repudiation, robustness
sih141/attacks/    the adversaries (Phase 3)
  isolation.py     convention D6 as a behavioural check — the one every published
                   attack rate depends on
  statistics.py    one Wilson interval and one agreement test for the whole suite,
                   with the band computed from the sampling standard error
  forgery.py       the outside forger and the forging recipient
  impersonation.py Mallory on either of Alice's two seams, and on both
  replay.py        four replay flavours against the binding and the ledger
  channel.py       depolarising twirl, intercept-resend, kept share — on both the
                   entanglement line and the payload line, targetable per party
  starvation.py    a recipient who understates his own matched count
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
3. **All randomness flows through an injected `numpy.random.Generator`.** Nothing anywhere
   *draws* from global `numpy.random` or stdlib `random`. Reproducible seeding is a
   prerequisite for the Phase 5 evaluation to be credible. The one place those globals are
   touched at all is the D6 isolation check, which *writes* them for the duration of a probe
   call — and restores them exactly — so that an adversary breaking this rule is caught by a
   test rather than trusted not to.
4. **No AI/ML anywhere in the detection path.** Every threshold in the codebase is a closed
   form in the protocol parameters, derived from a concentration inequality — including the
   matched-count floor, which is a Chernoff tail at a fixed budget and not a learned or
   tuned cut. Nothing is fitted to data, so every detection number has a proof rather than
   an observed rate.
5. **Every security claim is quoted with its hypothesis.** Functions that average over an
   adversary-controllable quantity carry a mandatory argument naming the assumption, so the
   convenient number cannot be obtained by accident. See
   [Security claims](#security-claims-stated-honestly).
6. **Adversaries own their randomness** (Phase 3, convention D6). Every attack takes its own
   injected generator and may never derive one from the seed the harness gave the session.
   An attack that reuses the harness seed predicts every private symmetrisation coin while
   looking entirely legitimate, so this is enforced by a behavioural check applied to all
   five adversaries rather than by a comment.
7. **Tolerances are computed, never guessed.** Every measurement-versus-prediction assertion
   in the attack suite compares against a band of four sampling standard errors at the
   *predicted* rate. A tolerance chosen by eye either passes a broken attack or fails a
   correct one on an ordinary draw, and both failures are silent.
