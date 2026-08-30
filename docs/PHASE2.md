# Phase 2 — The QDS Protocol

Engineering note for `sih141.protocol`. Covers the protocol in precise notation, the
adversary model, the three security expressions with their derivations, why `s_a < s_v`,
the no-cloning objection and its answer, and the seams Phase 3 attaches to.

Status: complete, with one **corrected security claim** — read Section 6b before quoting a
non-repudiation number. The `6.9e−10` this document previously published as holding "for
every Alice strategy" holds only while the signer cannot see the recipients' logged bases,
and the shipped `Signer` seam hands her both raw logs. The mathematics was never wrong; the
advertising was.

**What replaces it, in the order a reader should reach for it.**

| Situation | Quote this | At `DEFAULT_PARAMS` | Assumes |
| --- | --- | --- | --- |
| A run that completed | `SessionTranscript.repudiation_guarantee` — `repudiation_bound` at the observed `M = m_B + m_C` | `6.9e−10` on a healthy run | **nothing** |
| Before any run | `verify.enforced_repudiation_bound` — the bound the shipped matched-count floor forces | `1.9e−09` | **nothing** |
| Never publish | `analysis.averaged_repudiation_bound` | `6.9e−10` | assumption (IND), which the `Signer` seam breaks |

Both honest numbers are now **implemented and enforced**, not hypothetical: `verify.py`
refuses to score a matched set below `minimum_matched_count` (`36555` at the defaults), so
`M ≥ 2·m_min` on any run that reaches two verdicts. Three limits are stated rather than
hidden, and each is measured in Section 6b: there is **no unconditional bound below `1/2`
without the abort rule** (Section 6b-iii); the rule closes the repudiation *verdict* but
leaves one *no-verdict* route open, which needs a pooled floor and one extra classical
message; and below `L = 267` the rule degenerates to `m_min = 1`, so `DEMO_PARAMS` carries
no security claim at all and says so.

---

## 1. Module layout

| Module | Responsibility | Public surface |
| --- | --- | --- |
| `params.py` | Parameters, parties, thresholds, and the validation that refuses insecure sets | `Party`, `VERIFIERS`, `ProtocolParams`, `COMPLIANT_FORGER_RATE_THREE_BASIS`, `UNSYMMETRISED_FORGER_RATE_THREE_BASIS`, `DEFAULT_S_A`, `DEFAULT_S_V`, `DEFAULT_BASES`, `DEFAULT_PARAMS`, `DEMO_PARAMS` |
| `keys.py` | Alice's private keys and the quantum public key | `KeyElement`, `PrivateKey`, `generate_private_key`, `generate_key_pair`, `public_key_states` |
| `records.py` | The recipients' immutable classical logs | `RecordEntry`, `RecipientRecord` |
| `distribute.py` | Phase A: teleportation and immediate measurement | `ResourceContext`, `ResourceFactory`, `ideal_resource`, `distribute_to_recipient`, `distribute_public_key` |
| `symmetrise.py` | Phase A′: the recipients' private exchange | `Symmetriser`, `symmetrise_records`, `no_symmetrisation` |
| `signature.py` | Phase B: the declaration | `Signature`, `sign` |
| `verify.py` | Phase C: the matched/unmatched split, the accept rule, and the matched-count floor | `VerificationResult`, `matched_positions`, `mismatch_positions`, `verify`, `verify_all`, `verify_or_abort`, `HONEST_ABORT_BUDGET`, `AbortReason`, `VerificationAbort`, `MatchedSetTooSmall`, `minimum_matched_count`, `enforced_repudiation_bound` |
| `session.py` | Orchestration and the attack seams | `MESSAGE_BITS`, `Distributor`, `Symmetriser`, `Signer`, `Forwarder`, `honest_signer`, `honest_forwarder`, `SessionTranscript`, `QDSSession` |
| `analysis.py` | Closed forms only; no simulation | `matched_statistics`, `honest_statistics`, `forgery_probability`/`_bound`, `recipient_forgery_probability`/`_bound`, `repudiation_probability`, `repudiation_bound`, `averaged_repudiation_bound`, `repudiation_bound_with_abort`, `symmetric_repudiation_bound`, `honest_abort_probability`/`_bound`, `binary_kl_divergence`, `hoeffding_exponent`, `max_accepted_mismatches`, `depolarising_error_rate`, `matched_count_distribution`, `matched_shortfall_probability`, `FORGER_MATCHED_MISMATCH_PROBABILITY`, `BoundMethod` |

Dependencies run one way: `params` → `keys` → `records` → `distribute` → `symmetrise` →
`signature` → `verify` → `session`, with `analysis` depending only on `params`. The one
edge that closes back is `verify.enforced_repudiation_bound`, which imports
`analysis.repudiation_bound_with_abort` inside the function body: it is the wiring between
the floor `verify` enforces and the number that floor buys, and it is deliberately the only
place the two meet, so verification's *rule* never depends on the analysis of it. Every
public name is re-exported from `sih141.protocol`, `analysis` included, so Phase 3 never
has to reach into a submodule; `tests/test_protocol_reconciliation.py` asserts that.

---

## 2. Notation

Fixed once and used everywhere, including in the module docstrings.

| Symbol | Meaning |
| --- | --- |
| `L` | key length, `ProtocolParams.key_length` |
| `B`, `n = \|B\|` | the basis alphabet, `{X, Y, Z}` and `n = 3` by default |
| `a_i`, `v_i` | Alice's true basis and eigenvalue at position `i` |
| `d_i`, `w_i` | the *declared* basis and eigenvalue — the signature |
| `c_i`, `o_i` | recipient `R`'s own basis draw and recorded outcome |
| `M_R`, `m` | matched set `{i : c_i = d_i}` and its size |
| `M` | `m_B + m_C`, matched records held by the two verifiers together |
| `e_R` | mismatches inside `M_R`; `r_R = e_R / m` |
| `s_a`, `s_v` | Bob's and Charlie's thresholds, `0 ≤ s_a < s_v` |
| `p_e` | per-matched-position error rate of an honest run |
| `q` | per-matched-position mismatch probability a dishonest Alice induces |

`a_i`, `v_i`, and each recipient's `c_i` are drawn independently and uniformly — `a_i, c_i`
over `B`, `v_i` over `{+1, −1}` — independently across positions.

### Assumption (IND), and where it is load-bearing

> **(IND)** The declaration `(d_i, w_i)` is statistically independent of the recipients'
> logged bases `c_i`.

Every number below that averages over a matched count — `m ~ Bin(L, 1/n)`,
`M ~ Bin(2L, 1/n)`, and so every bound quoted without an observed count — needs (IND), and
is false without it rather than merely loose. The matched set is `{i : c_i = d_i}`, so
whoever picks `d` while knowing `c` picks the matched set, and picks it small; a bound whose
exponent is linear in that set's size is then a bound on a quantity the adversary chose.

(IND) is a property of the *interface*, not a theorem about the protocol. It holds for an
honest signer and for the modelled adversaries of Section 5, because each `c_i` is drawn
privately at receipt time and never published. It does **not** hold at the shipped seams:
`QDSSession` hands the `Signer` seam both recipients' raw logs (Section 9), which is exactly
what Section 6b-ii exploits. Statements *conditioned on an observed count* need none of
this and are what a run should quote.

---

## 3. The protocol

Three parties. **Alice** signs; **Bob** is the first recipient and verifier; **Charlie** is
the second. Charlie is not optional: transferability and non-repudiation are both
statements about a *second* verifier, so neither is expressible without him.

### Phase A — distribution

Run once per future message bit `b ∈ {0, 1}`, before Alice learns which bit she will sign.

1. Alice draws `k_b = [(a_i, v_i)]_{i=1..L}`, each `a_i` uniform over `B` and each `v_i`
   uniform over `{+1, −1}`.
2. The quantum public key is the product state `⨂_i |a_i, v_i⟩`.
3. Alice sends one copy to Bob and one to Charlie **by teleportation**, consuming a fresh
   Bell pair per qubit. She prepares each eigenstate twice from its classical description.
4. On receipt, each recipient **immediately** measures qubit `i` in a basis `c_i` drawn
   uniformly from `B`, and stores `(i, c_i, o_i)`. Nothing quantum is retained.

When Phase A returns, no quantum state from the run exists anywhere: not with Alice, not in
the channel, not with the recipients. That is the property this construction exists to
have. Gottesman–Chuang QDS (2001) requires recipients to *hold* the quantum public key in
memory until a signature arrives; the measurement-based line
(Dunjko–Wallden–Andersson 2014; Amiri et al. 2016) removes the requirement by measuring on
receipt, and combining it with teleportation-based delivery is what the problem statement
means by *"reduces some of the practical deployment complexities associated with earlier
QDS schemes"*.

### Phase A′ — symmetrisation

Bob and Charlie, over their own authenticated channel and out of Alice's sight, draw one
fair coin per position and swap their two records wherever it comes up heads:

```
coin_i = 0:   Bob keeps his own entry i,      Charlie keeps his own
coin_i = 1:   Bob takes Charlie's entry i,    Charlie takes Bob's
```

Each verifier still holds exactly one record per position, so nothing downstream changes
shape. Half of each verifier's evidence was measured by the other, and **Alice does not
know which half**. Section 6 shows that this step is what makes non-repudiation true, and
Section 7 states its price.

### Phase B — signing

Alice sends `(message, k_b)` to Bob over an authenticated classical channel. The signature
*is* the private key; there is nothing else to send.

### Phase C — verification

Recipient `R` holding `[(i, c_i, o_i)]` and a declaration `[(d_i, w_i)]` computes

```
M_R = { i : c_i = d_i }
e_R = |{ i ∈ M_R : o_i ≠ w_i }|
r_R = e_R / |M_R|
abort   if   |M_R| < m_min                     no verdict, not a rejection
accept  iff  r_R ≤ threshold(R),   threshold(Bob) = s_a,  threshold(Charlie) = s_v
```

`m_min` is the matched-count floor (`verify.minimum_matched_count`), `1` for short keys and
`36555` at `DEFAULT_PARAMS`. Section 6b-iii prices what the floor buys against a repudiating
Alice, and states the one route it does not close.

Bob verifies, then forwards the declaration — never his evidence — to Charlie, who scores
his own log at the looser cut.

**Only matched positions may be scored.** On an unmatched position the recipient measured
an observable conjugate to the one the state was an eigenstate of, so the outcome is a fair
coin *whether or not the signature is honest*: it carries exactly zero bits about the key.
Counting those positions adds `(1 − 1/n)/2 = 1/3` of pure noise to every rate, which sits
above `s_v` in any sane parameter set. The symptom is that both verifiers reject every
honest signature on a *perfect* channel, which reads as a hardware problem and sends the
debugging in exactly the wrong direction. This is the classic implementation bug of the
family; `tests/test_protocol_verify.py` pins the rule with a record whose unmatched
positions *all* disagree with the declaration and which must still verify at rate `0.0`.

**The empty matched set.** If `|M_R| = 0` the rate is `0/0`, and `verify` raises rather than
inventing a verdict — the `m = 0` end of the same floor rule. Accepting would accept any
declaration on zero evidence; rejecting would be recorded as a forgery detection where no
evidence of forgery exists. Under honest declarations it happens with probability
`(1 − 1/n)^L`, and no *channel* attack can force it: the matched set depends only on the
declared bases and the recipient's own uniform draws, neither of which the channel touches.

**A declaration can force it, and the `Signer` seam is enough.** An earlier version of this
section argued the branch was unreachable through the shipped seams, on the grounds that a
declaration avoiding every basis in *Bob's* raw log still matches Bob's post-exchange record
with probability `(1/2)(1/n) = 1/6` per position. That reasoning uses one log. The seam
hands over **both**, and with `|B| = 3` some basis is absent from both logs at every
position — the third one when they differ, either of the other two when they agree — so a
declaration built that way leaves `|M_B| = |M_C| = 0` with probability 1, whatever the
exchange coins do. It is the same mechanism as Section 6b-ii with the twelve exceptions
removed. So the empty branch is reachable on purpose, a harness must expect the exception
rather than assume it away, and it must never be counted as a rejection: it is the absence
of a verdict, and Section 6b-iii is where that distinction is priced.

### Correctness

On an ideal resource, teleportation is exact, so on a matched position the recipient
re-measures the very observable the state is an eigenstate of and `o_i = v_i = w_i` with
probability 1. Hence

```
r_B = r_C = 0     exactly, not approximately
```

on any noiseless honest run, for both verifiers, for every `L`. Both thresholds are noise
budgets measured from that exact zero, and the acceptance test is `≤`, so a run landing
exactly on its threshold is accepted.

---

## 4. The no-cloning objection, and its answer

This is the most common reviewer objection to the construction, so it is answered in the
code (`distribute.py`, `keys.py`) and again here.

**The objection.** Alice sends "the same" public key to two recipients. Doesn't the
no-cloning theorem forbid that?

**The answer.** No, because nothing here copies an unknown state. Alice *holds the
classical description*: `(a_i, v_i)` is written down in her private key, so she prepares
`|a_i, v_i⟩` from scratch once per recipient. The no-cloning theorem forbids a machine that
maps an *unknown* `|ψ⟩` to `|ψ⟩|ψ⟩`; it says nothing about a state-preparation device
driven by a known label, which is what every laboratory single-photon source is. In the
implementation this is literal: `distribute_to_recipient` calls `KeyElement.state()`, which
calls `sih141.core.paulis.eigenstate(basis, eigenvalue)` — a constructor taking two
classical arguments. No state that arrives from a channel is ever copied; what arrives is
measured once and destroyed.

The theorem does its work in the other direction, and that is where the security comes
from: **a recipient cannot make a second copy of what he was sent**. He holds one
measurement outcome per position, in a basis of his own choosing, and learns Alice's basis
only when the signature arrives. That is exactly why he cannot forge — see Section 5.

A second point worth stating: the public key states never traverse the channel at all. Each
position consumes one fresh Bell pair plus two classical bits from Alice's Bell measurement.
An adversary who owns the entire forward channel sees an entangled half that is locally
maximally mixed and two bits that are uniform and independent of the payload (derived in
`sih141.core.teleport`). He can *degrade* delivery — degradation shows up as a raised
mismatch rate — but he cannot read the key off the wire.

---

## 5. Unforgeability

### 5a. The outside forger (Eve)

*Who.* Eve never received a copy of the public key and holds no measurement record.

*What she knows.* The protocol, the parameters, the message, and all public classical
traffic from Phase A — which is exactly the two teleportation correction bits per qubit.
Those are useless: each of the four Bell outcomes occurs with probability exactly `1/4` for
*any* payload, so the classical traffic is statistically independent of `(a_i, v_i)`.

*What she controls.* Every `d_i` and `w_i`, jointly, adaptively, with unbounded
computation. *What she does not control.* The verifier's basis draws `c_i`, made privately
at receipt time before any signature existed.

**Step 1 — she cannot steer the matched set.** `c_i` is uniform on `B` and independent of
everything she knows, so `P(i ∈ M_R) = 1/n` for every choice of `d_i`. Hence
`m ~ Binomial(L, 1/n)` exactly as in the honest case. Declaring a symbol outside `B` only
shrinks `M_R`, and an empty matched set is not an acceptance, so that does not help either.

Step 1 *is* (IND), and it is the step to check against the code rather than against the
prose. If a seam ever handed Eve a verifier's log, her best play would be to miss `c_i`
everywhere but one position, sit on `m = 1`, and guess that outcome: accepted with
probability `1/2`, against a `forgery_bound` of `e^{−15091}`. The honest number for that
adversary is the conditional `forgery_bound(params, matched=1) = 0.68`. Nothing in this
package leaks `c_i` to an outside forger today; the point is that the `e^{−15091}` is a
statement about the interface as much as about the mathematics.

**Step 2 — a matched position is a fair coin.** Condition on `c_i = d_i`. The conditioning
event involves only her declaration and the verifier's independent draw, so `(a_i, v_i)`
remain uniform and independent. If `a_i = c_i` then `o_i = v_i`, a uniform sign she knows
nothing about; if `a_i ≠ c_i` then `o_i` is a fair coin by the Born rule. Either way

```
P(o_i = w_i | i ∈ M_R) = 1/2
```

independently across positions, whatever strategy produced the declaration. The security is
information-theoretic, not computational.

**The probability**, with `t(m) = max{e : e/m ≤ s}`:

```
P_forge(L, s) = Σ_{m=1}^{L} C(L,m) (1/n)^m (1−1/n)^{L−m} · 2^{−m} Σ_{k=0}^{t(m)} C(m,k)
```

evaluated exactly by `forgery_probability`. Conditioned on `m`, Hoeffding and Chernoff give
`exp(−2m(1/2 − s)²)` and `exp(−m·D(s ‖ 1/2))`; averaging a bound of the form `exp(−mc)`
over `m ~ Binomial(L, 1/n)` is *exact*, because that average is a probability generating
function:

```
E[exp(−mc)] = (1 − 1/n + e^{−c}/n)^L = exp(−Lλ),   λ = −ln(1 − (1 − e^{−c})/n) > 0
```

so the bound is exponential in `L` itself. At the shipped defaults `D(1/16 ‖ 1/2) = 0.4594`
nats, `λ = 0.1310`, and at `L = 115200` the bound is `e^{−15089}`.

### 5b. The recipient forger — the case that binds

Eve is the *weakest* adversary in the model. Bob is stronger: he holds his own `L`
measurement records and, after Phase A′, he *supplied* half of Charlie's evidence and knows
which half. Quoting Eve's number as "the forgery probability" understates the real one by
thousands of orders of magnitude, so the two have separate functions.

Bob declares, at every position, his own **raw** (pre-exchange) record `(c_i, o_i)`:

* **Swapped position** (probability `1/2`). Charlie's entry *is* that record. Matched with
  probability 1, mismatch probability 0.
* **Retained position** (probability `1/2`). Charlie holds his own measurement of an
  independent copy. Matched with probability `1/n`; given a match, both measured the same
  observable, so they agree outright when Bob's basis was Alice's (probability `1/n`) and
  are independent fair coins otherwise — mismatch probability `(1 − 1/n)/2`.

Collecting, and writing `p_s` for the fraction of positions he gets scored:

```
p_s = (n + 1) / (2n)             = 2/3        ProtocolParams.forger_scored_fraction
ρ   = (n − 1) / (2n(n + 1))      = 1/12       ProtocolParams.forger_floor
```

Given "scored", the mismatch indicator is Bernoulli(`ρ`) independently across positions, so
the structure is the same double binomial as Eve's with `(1/n, 1/2)` replaced by `(p_s, ρ)`
— `recipient_forgery_probability` and `recipient_forgery_bound`.

**What Bob must not hold, which is (IND) in this adversary's shape.** `(p_s, ρ)` is computed
against Charlie's *retained* positions and presumes Bob does not know the bases Charlie
logged there. He is already granted a great deal — his own records, the identity of the
swapped positions, Charlie's entry verbatim on each of them — and one more item ends the
analysis rather than shifting it: knowing Charlie's retained bases, Bob declares a basis
that misses them, Charlie's matched set consists only of positions Bob supplied, `ρ`
collapses from `1/12` to `0`, and Charlie accepts with probability 1 at every `L`. So the
`1.1e−103` is a statement about what `symmetrise.py` reveals as much as about the POVM
bound below. The conditional form `recipient_forgery_bound(params, matched=m)` survives
either way.

**`ρ` is optimal, not merely compliant.** No measurement strategy beats it. On a retained
position Bob must guess Charlie's outcome in the declared basis from his own copy. Let his
POVM be `{E_k}` and his declaration `(d_k, w_k)` a function of the outcome; with
`g = P(d = a, w = v)` and `h = P(d = a, w ≠ v)` against the six uniformly drawn eigenstates
`ρ_{a,v} = (I + v σ_a)/2`, the retained mismatch rate is `(1 − (g − h))/2` and

```
g − h = (1/6) Σ_k Tr(E_k (ρ_{d_k, w_k} − ρ_{d_k, −w_k}))
      = (1/6) Σ_k Tr(E_k · w_k σ_{d_k})
      = (1/6) Σ_k α_k (m_k · n_k)
      ≤ (1/6) Σ_k α_k = (1/6) Tr(I) = 1/3
```

writing `E_k = α_k (I + m_k·σ)/2` with `|m_k| ≤ 1`, and using that a qubit POVM sums to the
identity, whose trace is 2. The octahedron POVM `E_k = ρ_k/3` attains the bound — exactly as
well as the compliant strategy, not better.

This matters for how `s_v` is chosen. An earlier version of this project claimed a
Breidbart-style intermediate measurement does better than the compliant rate and reserved a
factor of two in `s_v` for it. The claim is false. The margin is now justified by what it
buys instead: `D(s_v ‖ ρ)` must be large enough that `exp(−Θ(L))` is a number worth
quoting.

---

## 6. Non-repudiation

Alice repudiates when she gets Bob to accept a signature Charlie will reject: she can then
deny having signed, and Bob cannot forward what he holds.

**Two different statements live here, and conflating them is how this analysis previously
went wrong.**

### 6a. The symmetric family — exact, and not a guarantee

Suppose Alice induces the *same* per-matched-position mismatch probability `q` on both
copies, by tilting the prepared Bloch vector away from the declared axis by the same angle
for each. Then the exchange coins are irrelevant, the two records are independent, and

```
m_B ~ Bin(L, 1/n),  e_B | m_B ~ Bin(m_B, q)
m_C ~ Bin(L, 1/n),  e_C | m_C ~ Bin(m_C, q)      independent of Bob's
P_rep(q) = P(r_B ≤ s_a) · P(r_C > s_v)
```

— `repudiation_probability`, with an empty matched set counting as "not accepted" on both
sides. At `q = 0` it is not zero but `P(m_B ≥ 1)·P(m_C = 0)`: the honest runs in which
Charlie holds no evidence. That is a transferability failure, of order `(1 − 1/n)^L`.

**This is not a supremum over Alice's strategies, and its maximum over `q` is not one
either.** She prepares the two copies separately and can choose `q_B ≠ q_C`, which breaks
the factorisation the expression rests on. Against *unsymmetrised* records the strategy
"send Bob the eigenstate you declare and Charlie its orthogonal partner on a fraction `f` of
positions" gives `q_B = 0`, `q_C = 1` there and repudiates with probability **1** at every
`L` — measured through this package's own seams before Phase A′ existed: at `L = 192`,
`r_B = 0.0000` accepted and `r_C = 0.4032` rejected, 40 times out of 40 over independent
seeds, against a quoted bound of `7e−10`. No key length repairs that, because the failure is
not statistical.

### 6b-i. The per-run guarantee — uniform over every Alice strategy, assuming nothing

This is what Phase A′ buys, and the derivation deliberately assumes nothing about Alice.

Fix the two recipients' raw records — whatever she prepared, however asymmetric, adaptive or
entangled — **and fix the declaration**, whatever she computed it from, both raw logs
included. The only randomness left is the recipients' private coins, one per position, each
deciding which verifier scores which of the two records. Because the coins only *split* a
fixed collection, two quantities are coin-independent constants:

```
m_B + m_C = M     (total matched records)
e_B + e_C = E     (total mismatched records)
```

Put `s = (s_a + s_v)/2`, `gap = s_v − s_a`, and `W = e_B − s·m_B`. By coin symmetry
`E[W] = (E − sM)/2`. Repudiation requires `r_B ≤ s_a` and `r_C > s_v`, i.e.

```
e_B − s·m_B ≤ (s_a − s)·m_B = −(gap/2)·m_B
e_C − s·m_C >  (s_v − s)·m_C = +(gap/2)·m_C
```

and adding, using `(e_C − s·m_C) = (E − sM) − W`, gives `2W < (E − sM) − (gap/2)M`, that is

```
W  <  E[W] − (gap/4)·M
```

`W` is a sum of `L` independent two-point variables, one coin each. A position where
neither record is matched contributes the same value under both coin outcomes, so its range
is 0; every other position has range at most 1, and there are at most `M` of them.
Hoeffding therefore gives

```
P(repudiation | records, declaration)  ≤  exp(−2((gap/4)M)² / M)  =  exp(−M·gap²/8)
```

which is `repudiation_bound`, and which takes the observed `M = m_B + m_C` as a **mandatory**
argument — `result_bob.matched_count + result_charlie.matched_count`, both scored against the
*same* declaration, since the conservation laws are what the whole argument rests on. Note what is *not* in it: no `q`, no independence assumption about the two
recipients, no model of Alice, and no (IND) — the declaration was fixed before any of the
randomness used here was drawn, so it does not matter what it was computed from.

**The `m_C = 0` corner is inside the event, not outside it.** Charlie failing to accept
splits into `m_C ≥ 1 and r_C > s_v`, handled above, and `m_C = 0`, where there is no rate to
deviate. The second is not an exception: `m_C = 0` forces `m_B = M` and `e_B = E`, Bob's
acceptance reads `E ≤ s_a·M`, and `W − E[W] = (E − sM)/2 ≤ −(gap/4)M` — the same deviation
event, reached non-strictly, and Hoeffding is non-strict. Earlier versions of this document
added `(1 − 1/n)^L` for that corner. It was never needed, and it was the one ingredient of
the "guarantee" that spoke about the recipients' *basis draws* rather than their coins —
i.e. an (IND) statement inside a bound advertised as assumption-free. It is gone from the
per-run form.

### 6b-ii. The M-averaged number — needs (IND), which the `Signer` seam gives away

Averaging `exp(−M·gap²/8)` over `M ~ Binomial(2L, 1/n)` is exact by the same
generating-function identity as Section 5a:

```
P_rep  ≤  (1 − 1/n)^L + (1 − 1/n + exp(−gap²/8)/n)^{2L}          [needs (IND)]
```

which is `averaged_repudiation_bound`, `6.9173e−10` at `DEFAULT_PARAMS`, and which this
document previously called `repudiation_bound` and published as the unconditional
non-repudiation guarantee. **It is not one.** `M ~ Bin(2L, 1/n)` is the law of the matched
count only while (IND) holds, and `QDSSession` hands the `Signer` seam both recipients' raw
logs.

**The strategy, concretely, using no quantum resource at all.** Alice reads the two raw
logs. At every position she declares a basis appearing in *neither* — with `n = 3` there is
always one, two when the logs agree — so that position is matched at neither verifier
however the coin falls. She keeps twelve exceptions: eleven positions where the logs used
different bases, where she declares Bob's basis and Bob's outcome (one matched record,
correct); and one position where the logs used the **same** basis and recorded **opposite**
outcomes, where she declares that basis and Bob's outcome (two matched records, exactly one
wrong). Then

```
M = 11 + 2 = 13    for every L, with probability 1
P(repudiation)     = P(the one wrong record lands on Charlie) = 1/2   exactly
```

If the wrong record goes to Charlie he holds one mismatch among at most twelve matched
records (`r_C ≥ 1/12 > s_v`, rejects) while Bob holds only clean ones (`r_B = 0 ≤ s_a`,
accepts); if it goes to Bob instead, `r_B ≥ 1/12 > s_a` and he rejects. Measured in
`tests/test_protocol_analysis.py`: `M = 13` in every trial and a repudiation frequency of
`0.45`–`0.53`, at `L = 600` and at `L = 115200` alike. An independent audit measured
`0.46`–`0.58` with a different construction. Against `6.9e−10`.

Two things this attack is *not*. It is not the empty-matched-set corner — Charlie holds
evidence in every run and rejects on a rate — so it is unaffected by whatever `verify` does
about `m_C = 0`. And it does not violate 6b-i: `repudiation_bound(params,
matched_records=13) = 0.9964`, and `0.5 < 0.9964`. The mathematics was never wrong.

### 6b-iii. Is there an honest unconditional number? Only with an abort rule

Worst-casing over `M` instead of averaging is legitimate and useless: `exp(−M·gap²/8)`
decreases in `M`, and `M = 0` makes repudiation impossible because Bob has nothing to
accept, so the supremum over everything else is `exp(−gap²/8) = 0.99973`. Nor is that
slack. The strategy above achieves `1/2` at every key length, so

> **no unconditional bound below `1/2` exists for a signer who can read the recipients'
> logged bases — at any `L` whatever.**

Key length does not help, because the failure is not statistical. That is a limitation
worth publishing, not hiding: it says precisely where the guarantee comes from, and it is
the reason the per-run form is the one to quote.

What does help is refusing to score an anomalously small matched set. If Bob declines to
accept unless his own `|M_B| ≥ m_min`, then on the repudiation event `M ≥ m_B ≥ m_min`, and
off it there is nothing to bound, so

```
P(repudiation)  ≤  exp(−m_min·gap²/8)     every Alice strategy, no (IND)
```

— `repudiation_bound_with_abort`. It is *local*: Bob knows his own count without asking
anyone. And it is nearly free, because the honest count is concentrated (`sd = 160` against
a mean of `38400`):

| Rule | Floor on `M` | Unconditional bound | Honest-run cost | Shipped? |
| --- | --- | --- | --- | --- |
| Bob's own floor alone | `m_min = 36555` | `4.4e−05` | `2.5e−31` | yes |
| **both verifiers cleared it** — a reject verdict from Charlie means they did | `2·m_min = 73110` | **`1.9e−09`** | `2.5e−31` | **yes** |
| pooled floor, closing the no-verdict route below | `M_min = 75000` | `1.1e−09` + `4.6e−11` abort route | `7.8e−16` | no — costs one extra message |

(costs from `matched_shortfall_probability`; the floor itself from
`verify.minimum_matched_count`, derived in `verify.py`'s docstring from a Chernoff lower
tail at a budget of `ε = 2⁻⁶⁴` per verifier.) The middle row is what
`verify.enforced_repudiation_bound` returns and the only a-priori repudiation figure this
package publishes. It lands within a factor of three of the figure that used to be
published as unconditional — this time actually unconditional, and resting on a rule the
code enforces rather than on an assumption about what Alice can see.

**Read the event carefully, because the floor creates a third outcome.** What the table
bounds is: Bob accepts, and Charlie *reaches a verdict of reject* — or holds no matched
record at all, which 6b-i already covers. It does **not** cover Charlie holding a matched
set that is non-empty but below *his* floor, on which he returns no verdict. Whether that
counts as repudiation is a convention, and the readings differ sharply:

* As a **no-verdict abort** — which is how `verify.py` frames it, with its own reason code
  and a `MatchedSetTooSmall` raise rather than an `accepted=False` — the bound is complete.
  An honest run trips the floor with probability `~1e−31`, so the outcome is visibly
  anomalous rather than a quiet rejection.
* As a **transfer failure counted against the scheme**, the floor opens a route the exponent
  does not close. A log-reading Alice aims `M` at exactly `2·m_min`, using only clean matched
  records: Bob accepts whenever `m_B ≥ m_min`, Charlie is below his floor whenever
  `m_C < m_min`, and one fair coin per record splits a total whose mean is `M/2 = m_min`. She
  wins with probability `≈ 1/2`. No rate deviates, so no rate exponent applies.

Closing the second reading needs the counts compared. With a pooled floor `m_B + m_C ≥ M_min`
on top of the per-verifier one, Charlie's below-floor abort demands `m_C < m_min` against a
mean of `M/2 ≥ M_min/2`, which Hoeffding bounds by `exp(−2(M_min/2 − m_min)²/M_min)`, worst
at `M = M_min`. At `DEFAULT_PARAMS` with `m_min = 36555` and `M_min = 75000`: repudiation
`1.1e−9`, abort route `4.6e−11`, honest cost `7.8e−16` — an unconditional total near
`1.2e−9`.

**What is implemented, and what it measures.** `verify.py` enforces the per-verifier floor
and no pooled comparison. `analysis.py` cannot check that — it depends only on `params` —
so `repudiation_bound_with_abort` takes the floor as an argument;
`verify.enforced_repudiation_bound` is the wiring that supplies the floor actually applied,
and is what a reader should call instead of choosing a threshold.

Both readings were then run, at `L = 360` (where `m_min = 17`, the smallest tested length
whose floor exceeds the `M = 13` the attack pins) and at `DEMO_PARAMS`. The tests are in
`tests/test_protocol_reconciliation.py`; the wider sweeps below were run separately.

| Signer | Runs | Repudiation verdicts | What happened instead |
| --- | --- | --- | --- |
| starving (`M = 13`), `L = 600` | 40 | **0** | 40 no-verdict aborts at Bob |
| starving (`M = 13`), `L = 360` | 16 | **0** | 16 no-verdict aborts at Bob |
| aiming at `2·m_min`, `L = 600` | 40 | **0** | 14 Bob-accept/Charlie-no-verdict, 22 aborts at Bob, 4 clean transfers |
| starving, `DEMO_PARAMS` (`m_min = 1`) | 40 | 22 | the floor is inert below `L = 267`; see below |
| honest, `L = 600` / `L = 192` / `L = 1200` | 200 / 200 / 60 | — | **0** spurious aborts; smallest matched count `163` against a floor of `67` |

Three conclusions, and the third is a limitation rather than a result:

1. **The attack of 6b-ii is prevented, not merely bounded.** It pins `M = 13` at *every* key
   length, so at any `L` whose floor exceeds `13` — every `L ≥ 340`, and `DEFAULT_PARAMS` by
   a factor of `2800` — both verifiers refuse to score and there is no verdict to repudiate.
   It is a recorded outcome, not a crash: `run()` returns a transcript, `aborted` is `True`,
   and `transferable`, `repudiated` and `is_complete` are all `False`.
2. **The honest run is untouched.** Zero aborts in 460 seeded honest sessions across three
   parameter sets, and the analytic form is stronger than any sample: the exact binomial
   lower tail at the floor is below `ε = 2⁻⁶⁴` for every `L` tested from `192` to `115200`.
3. **The no-verdict route above is real and is not closed.** Aiming `M` at `2·m_min` produced
   Bob-accepts/Charlie-no-verdict in 14 of 40 runs. Under the framing `verify.py` uses that
   is an abort, so `enforced_repudiation_bound` stands — **0 of 40** runs produced a reject
   verdict. Under the stricter reading it is a transfer failure at rate `≈ 1/3`, and the
   per-verifier floor does not bound it. Closing it needs the pooled row of the table above.

Below `L = 267` the Chernoff tail is vacuous at this budget and `m_min` clamps to `1`, so
`DEMO_PARAMS` gets no protection: the same signer repudiated 22 times in 40 there. That is
consistent rather than alarming — `DEMO_PARAMS` publishes `enforced_repudiation_bound =
0.9995` and its docstring says no security claim attaches to it — but it is why a
demonstration key must never be quoted as a security result.

The honest per-run statement remains 6b-i at the observed `m_B + m_C`, which every
transcript now carries as `repudiation_guarantee` and prints in `summary()`; the honest
a-priori statement is the middle row of the table above. 6b-ii is quotable only with (IND)
named beside it.

### 6c. The in-model bound, kept as a yardstick

The older in-model expression — split at the midpoint, apply Hoeffding to whichever verifier
must deviate, optionally sharpen to relative entropy — survives as
`symmetric_repudiation_bound`, labelled as valid only within family 6a. Its exponent
`min_q [D(s_a‖q) + D(s_v‖q)] = 0.01563` per matched *position* is about 28 times
`gap²/8 = 0.000275` per matched *record*, once the two counts are put on the same footing
(`M = 2m`). That ratio is the price of a statement that is true rather than merely tight,
and it is paid in key length. What no exponent buys is freedom from the counting assumption
itself.

### Why the exchange has to be where it is

Phase A′ is performed **by the recipients**, after the quantum phase is over. In the
implementation it therefore lives in `QDSSession.distribute`, applied to whatever the
`distributor` seam returned — an adversary standing in Alice's place cannot skip it, because
he does not run it. And `verify_all` refuses a pair of unsymmetrised records by default,
with `require_symmetrised=False` as the explicit opt-in a Phase 3 demonstration must write
out.

The `Signer` seam is handed the **raw**, pre-exchange logs, so the exchange's *outcome* —
which coin fell which way — is never offered to whoever is holding the pen. That is what
6b-i needs, and 6b-i is fine. **It is not what 6b-ii needs.** An earlier version of this
document called the raw logs "the whole basis of 6b", which conflated the two: hiding the
coins protects the per-run bound, while the averaged bound additionally needs the *bases* in
those logs to be hidden, and they are handed over in full. The seam is right for its purpose
— a forging Bob genuinely needs the raw logs, since after Phase A′ half of Charlie's
evidence *is* Bob's raw record — but its consequence for the repudiation figure has to be
stated rather than assumed away.

---

## 7. Why `s_a < s_v`, and what the numbers are

```
s_v > s_a  ⟹  a signature Bob accepts is overwhelmingly likely to be accepted by
              Charlie                                            ⟹  TRANSFERABILITY
s_a > 0    ⟹  Alice cannot craft a signature that squeaks past Bob but fails
              Charlie                                            ⟹  NON-REPUDIATION
```

Both failure probabilities are exponentially small in `L`. Transferability is immediate from
the decision rule — Bob's acceptance region is contained in Charlie's, so on a clean channel
where both rates are exactly 0 there is no rate at which Bob accepts and Charlie does not —
and probabilistically it is the `q ≈ 0` corner of 6a. Non-repudiation is 6b, and it is
exponential in `gap²`, so halving the gap costs a factor of four in key length.

`s_v` is bounded above by the forger floor of Section 5b, not by the crude `1/2`.
`ProtocolParams.__post_init__` enforces both, and refuses `s_v ≥ forger_floor` unless
`allow_forgeable=True` is passed — a field, so it is part of the parameter set's identity and
reaches every transcript the run produces. That is what distinguishes an intentional Phase 3
sweep past the floor from a mistyped config.

### `DEFAULT_PARAMS`

| Quantity | Value | Why |
| --- | --- | --- |
| `bases` | `(X, Y, Z)` | Six-state alphabet. Leaves the forger floor at `1/12` (two bases give `1/12` too) but buys a larger scored fraction for the honest run, hence a shorter key for the same repudiation exponent. |
| `forger_floor` | `1/12 = 0.0833` | `(n − 1)/(2n(n + 1))`, optimal over all POVMs. |
| `s_v` | `1/16 = 0.0625` | Three quarters of the floor. Sized by what it buys: `D(1/16 ‖ 1/12) = 0.003088` nats gives a recipient-forgery bound of `1.1e−103`. |
| `s_a` | `1/64 = 0.015625` | A noise budget. A Werner-`p` resource gives `p_e = p/2`, so honest signatures survive up to `p = 3.125%`. |
| `L` | `115200` | `115200/3 = 38400` matched positions per verifier; `E[M] = 76800`. With `gap = 3/64`, the 6b-i bound at that evidence is `exp(−21.09) = 6.9e−10`, and so is the 6b-ii average — *under (IND)*. A multiple of 3 so the expected matched count is an integer. |
| `minimum_matched_count` | `36555` | Derived, not chosen: the Chernoff lower tail of `Bin(L, 1/3)` at a per-verifier honest-abort budget of `ε = 2⁻⁶⁴`. 4.8% below the mean; costs an honest verifier `2.5e−31`. **This is the parameter the unconditional repudiation number rests on** — `exp(−2·36555·gap²/8) = 1.9e−09` (`enforced_repudiation_bound`). It is a function of `L` and `\|B\|` alone, so it moves with `L` and needs no separate tuning. |

Cost, plainly: a full two-message-bit setup teleports `2 × 2 × 115200 = 460800` qubits.
`DEMO_PARAMS` keeps the same thresholds and cuts `L` to 192 — the same decision rule, no
security claim, and its own docstring says so.

**Why the key grew.** The earlier `L = 6912` came from `exp(−m·gap²/2)` with `gap = 13/96`,
an expression that assumed Bob's and Charlie's records were i.i.d. given the declaration —
which nothing forced. Symmetrisation makes a uniform bound available at all; it costs a
factor of four in the forger floor (hence a smaller usable gap) and a factor of two in the
exponent's constant, and `115200/6912 = 16.7` is the product of those two prices.

---

## 8. Robustness

A scheme that rejects everything is trivially unforgeable and useless, so the mirror
statement is asserted too. An honest run *aborts* at party `R` when `r_R > s` or the matched
set is empty. With `e_R | m ~ Bin(m, p_e)`:

```
P_abort(R) = (1−1/n)^L + Σ_{m≥1} P(m)·P(Bin(m, p_e) > t(m))
```

(`honest_abort_probability`). Bob's cut is tighter, so Bob dominates. For `p_e < s` the
conditional tail obeys `exp(−2m(s − p_e)²)` and `exp(−m·D(s ‖ p_e))`, and "either verifier
aborts" is `P_B + P_C − P_B·P_C` exactly, by the independence of the two records.

Hoeffding is genuinely bad here: it charges every summand the variance `1/4` its range
allows, while the actual variance is `p_e(1 − p_e)`, tiny for a low-noise channel. At
`p_e = 0` the true abort probability on `m ≥ 1` is exactly 0 while Hoeffding still reports
`exp(−2ms²)`. Use `method="kl"` whenever `p_e` is small — which is the whole operating
regime of an honest run.

At `DEFAULT_PARAMS` with a 1% depolarising channel, all three numbers are small at once:
abort `< 1e−9`, outside forgery `< 1e−100`, recipient forgery `1.1e−103` (bound; exact
`2.2e−105`), and repudiation `1.9e−09` **unconditionally**, because `verify.py` enforces
the 6b-iii floor — `6.9e−10` if you are additionally willing to assume (IND), and `≥ 1/2`
for a log-reading signer against a verifier that does *not* abort, which is what the floor
exists to prevent. The matched-count floor adds its own honest-run abort of `2.5e−31` per
verifier, twenty-two orders of magnitude below the channel's, so it never becomes the
dominant failure. That simultaneity is the only thing that makes the parameter set
meaningful, and each of the four numbers has to be quoted with the hypothesis it carries.

**A note on cost.** The exact functions are `O(L²)` summands — instant at `DEMO_PARAMS`,
about 7 seconds for either forgery probability at `DEFAULT_PARAMS`, and about 150 seconds
for `repudiation_probability`, whose rejection branch sums the long tail at every matched
count. The bounds are closed forms and are free. Sweeps, report tables and dashboards
should quote the bounds; the exact functions belong at the short key lengths where a
cross-check against simulation is affordable, which is where the test suite uses them.

---

## 9. The seams Phase 3 attaches to

`session.py` is a scheduler, not a policy. Each place an adversary can stand is a
keyword-only constructor argument holding a callable that defaults to the honest
implementation. **Nothing in `session.py` changes for any attack**, which is what makes an
attacked run and a clean run comparable rather than two different programs.

| Seam | Shape | What stands there |
| --- | --- | --- |
| `resource_factory` | `() -> state` or `(ResourceContext) -> state` | The quantum channel. Called once per key position per recipient. Werner or amplitude-damped pairs are injected noise; a factory that degrades a subset of calls is an intermittent eavesdropper. |
| `distributor` | signature of `distribute_public_key` | Phase A as a whole — an impersonator between Alice and the recipients, substituting his own states rather than degrading hers. |
| `symmetriser` | signature of `symmetrise_records` | Phase A′. Pass `no_symmetrisation` to run the insecure variant and *measure* the repudiation attack rather than take Section 6a's word for it. |
| `signer` | signature of `honest_signer` | Phase B — who is holding the pen. Receives the message bit, the keys, the parameters and the recipients' **raw** logs — *both* of them, bases included, which is what puts assumption (IND) out of reach of any a-priori repudiation figure. See 6b-ii. |
| `forwarder` | `(Signature, ProtocolParams) -> Signature` | The Bob→Charlie classical hop. An attack *between* the two verifications. |
| `run_id` | `str \| None` | Carried verbatim into the transcript for a replay ledger to key on. |

Three contracts worth knowing:

**`ResourceContext`, not call counting.** A factory taking one *required* positional
argument receives `ResourceContext(party, message_bit, position)`. An attack aimed at one
recipient should switch on `context.party` rather than infer it from the call order: the
order is documented but is not a contract, and a counter-based factory would silently follow
a re-ordering to the wrong target. A callable invocable with no arguments is called with
none, so `lambda pair=pair: pair` keeps working.

**Raw records for the signer.** The `Signer` seam gets the pre-exchange logs. That is what a
forging Bob needs — after Phase A′ half of Charlie's evidence *is* Bob's raw record, while
Bob's post-exchange record is precisely the half Charlie does not hold.
`QDSSession.raw_records` and `QDSSession.records` expose both to an experiment.

What the seam withholds is the exchange's *outcome*: the pen never learns which coin fell
which way, which is what the per-run bound of 6b-i needs and all it needs. What the seam
hands over is the two logs' *bases*, and those are enough to choose the matched set, which
is what the averaged bound of 6b-ii needs and does not get. A repudiating Alice standing at
this seam is therefore a supported experiment rather than an excluded one, and the figure
she refutes is named accordingly.

**Two declarations in the transcript.** `SessionTranscript.signature` is what Bob scored;
`forwarded_signature` is what Charlie scored when the forwarding hop altered it, and `None`
otherwise. `signature_for(party)` reads the right one. Without this a run in which the two
verifiers scored different declarations was unrepresentable, and Charlie's verdict was
silently attributed to Bob's declaration — a Phase 4 statistic would have read an attacked
run as a clean one.

### What the transcript guarantees

`SessionTranscript` is the hand-off object for Phases 4–6: frozen, JSON round-trippable, no
quantum state, no generator, no callable. Its `__post_init__` re-derives each verdict's
threshold from `params` and the party and refuses a mismatch. That guard is not cosmetic:
`VerificationResult` enforces only `accepted == (rate ≤ threshold)`, so a transcript whose
Bob verdict carries Charlie's `s_v` is internally consistent in every field and used to
reconstruct from JSON reporting `transferable=True` for a run Bob genuinely rejected.

`RecipientRecord.symmetrised` travels with the data, so a transcript read back from disk
still says which protocol produced it, and `SessionTranscript.symmetrised` and `summary()`
report it.

**`aborts` is a separate field and a separate type from `results`**, so no Phase 4/5
statistic can average a refusal to score into a rejection. A party appears in exactly one of
the two, never both; `verdict_for` raises for an aborted party; `transferable`, `repudiated`
and `is_complete` are all `False`; and `summary()` closes with `NO VERDICT` rather than
naming a composite event. **A Phase 4/5 aggregation must give aborted runs their own
bucket** — an abort is not a detection. `to_dict()` gained an `"aborts"` key, optional on the
way back in, so transcripts written before the rule still restore.

**`repudiation_guarantee` is the number a run quotes**, computed from `pooled_matched_count`
(`M = m_B + m_C`, both counts against the *same* declaration, both from actual verdicts).
`summary()` prints it on the `EVIDENCE:` line. It is `None` when the run is not a
repudiation experiment at all — an abort, an unsymmetrised run, or one the forwarding hop
altered — rather than falling back to a number those runs did not earn.

---

## 10. Determinism, and the four standing rules

**D1 — `DensityMatrix` is canonical.** Public-key factors go to `teleport` as
`Statevector`s, which is its exact-fidelity path for a pure payload; the received state is a
one-qubit density matrix. The resource may be given in either representation.

**D2 — little-endian.** Each hop is a standalone one-qubit teleportation, so the measured
index is always 0 and no multi-qubit bitstring label is formed anywhere. Record and key
indices are *positions in the key*, `0..L−1`, never register positions.

**D3 — one injected generator.** `QDSSession` resolves a single `rng` in its constructor and
threads it through key generation, both distributions and both exchanges, in that order, so
one seed reproduces the entire transcript byte for byte through `to_json`. Per message bit
and per recipient, distribution consumes exactly three variates per key position — basis
choice, Alice's Bell measurement, the recipient's projective measurement — and the exchange
consumes exactly one array draw per bit. The count does not depend on the resource, so for a
fixed seed the sequence of *chosen bases* is identical under every `resource_factory` and
only the outcomes move, which is what makes a clean run and an attacked run comparable
position by position.

**D4 — no AI/ML.** Linear algebra, uniform draws, binomial sums, two elementary
inequalities and one ternary search on a convex scalar function. Nothing is learned, fitted
or thresholded from data; the two cuts come from `ProtocolParams` and were fixed before the
run started.

---

## References

1. D. Gottesman and I. Chuang, *Quantum Digital Signatures*, arXiv:quant-ph/0105032 (2001).
2. V. Dunjko, P. Wallden and E. Andersson, *Quantum Digital Signatures without Quantum
   Memory*, Phys. Rev. Lett. **112**, 040502 (2014).
3. R. Amiri, P. Wallden, A. Kent and E. Andersson, *Secure Quantum Signatures Using Insecure
   Quantum Channels*, Phys. Rev. A **93**, 032325 (2016).
