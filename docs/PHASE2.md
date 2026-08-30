# Phase 2 — The QDS Protocol

Engineering note for `sih141.protocol`. Covers the protocol in precise notation, the
adversary model, the three security expressions with their derivations, why `s_a < s_v`,
the no-cloning objection and its answer, and the seams Phase 3 attaches to.

Status: complete.

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
| `verify.py` | Phase C: the matched/unmatched split and the accept rule | `VerificationResult`, `matched_positions`, `mismatch_positions`, `verify`, `verify_all` |
| `session.py` | Orchestration and the attack seams | `MESSAGE_BITS`, `Distributor`, `Symmetriser`, `Signer`, `Forwarder`, `honest_signer`, `honest_forwarder`, `SessionTranscript`, `QDSSession` |
| `analysis.py` | Closed forms only; no simulation | `matched_statistics`, `honest_statistics`, `forgery_probability`/`_bound`, `recipient_forgery_probability`/`_bound`, `repudiation_probability`, `repudiation_bound`, `symmetric_repudiation_bound`, `honest_abort_probability`/`_bound`, `binary_kl_divergence`, `hoeffding_exponent`, `max_accepted_mismatches`, `depolarising_error_rate`, `matched_count_distribution`, `FORGER_MATCHED_MISMATCH_PROBABILITY`, `BoundMethod` |

Dependencies run one way: `params` → `keys` → `records` → `distribute` → `symmetrise` →
`signature` → `verify` → `session`, with `analysis` depending only on `params`. Every
public name is re-exported from `sih141.protocol`, `analysis` included, so Phase 3 never
has to reach into a submodule.

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
accept  iff  r_R ≤ threshold(R),   threshold(Bob) = s_a,  threshold(Charlie) = s_v
```

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

**The empty matched set.** If `|M_R| = 0` the rate is `0/0` and `verify` raises rather than
inventing a verdict. Accepting would accept any declaration on zero evidence; rejecting
would be recorded as a forgery detection where no evidence of forgery exists. Under honest
declarations it happens with probability `(1 − 1/n)^L`. No channel attack can force it —
the matched set depends only on the declared bases and the recipient's own uniform draws.
Nor, as it turns out, can the `Signer` seam: it receives the *raw* logs while the verifier
is scored on his post-exchange record, so a declaration built to avoid every basis in Bob's
raw log still matches with probability `(1/2)(1/n) = 1/6` per position. Phase A′ bought that
incidentally. A harness should still expect the exception rather than assume it away — it
is a plumbing failure, not a verdict, and must never be counted as a rejection.

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

### 6b. The guarantee — uniform over every Alice strategy

This is what Phase A′ buys, and the derivation deliberately assumes nothing about Alice.

Fix the two recipients' raw records — whatever she prepared, however asymmetric, adaptive or
entangled. The only randomness left is the recipients' private coins, one per position, each
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
P(repudiation | records)  ≤  exp(−2((gap/4)M)² / M)  =  exp(−M·gap²/8)
```

**conditional on the records**, hence for every Alice strategy. The one case the argument
does not cover is `m_C = 0`, where Charlie's "rejection" carries no evidence; that is
bounded separately by `P(m_C = 0) = (1 − 1/n)^L`. Averaging over `M ~ Binomial(2L, 1/n)` —
the recipients' own basis draws, which Alice does not control either — is exact by the same
generating-function identity as Section 5a:

```
P_rep  ≤  (1 − 1/n)^L + (1 − 1/n + exp(−gap²/8)/n)^{2L}
```

which is `repudiation_bound`. Note what is *not* in it: no `q`, no independence assumption
about the two recipients, no model of Alice.

The older in-model expression — split at the midpoint, apply Hoeffding to whichever verifier
must deviate, optionally sharpen to relative entropy — survives as
`symmetric_repudiation_bound`, labelled as valid only within family 6a. Its exponent
`min_q [D(s_a‖q) + D(s_v‖q)] = 0.01563` per matched *position* is about 28 times
`gap²/8 = 0.000275` per matched *record*, once the two counts are put on the same footing
(`M = 2m`). That ratio is the price of a statement that is true rather than merely tight,
and it is paid in key length.

### Why the exchange has to be where it is

Phase A′ is performed **by the recipients**, after the quantum phase is over. In the
implementation it therefore lives in `QDSSession.distribute`, applied to whatever the
`distributor` seam returned — an adversary standing in Alice's place cannot skip it, because
he does not run it. The `Signer` seam is handed the **raw**, pre-exchange logs, so the
exchange's outcome is never offered to whoever is holding the pen; that is the whole basis
of 6b. And `verify_all` refuses a pair of unsymmetrised records by default, with
`require_symmetrised=False` as the explicit opt-in a Phase 3 demonstration must write out.

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
| `L` | `115200` | `115200/3 = 38400` matched positions per verifier; `E[M] = 76800`. With `gap = 3/64`, the 6b bound is `exp(−21.09) = 6.9e−10`. A multiple of 3 so the expected matched count is an integer. |

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
`2.2e−105`), repudiation `6.9e−10`. That simultaneity is the only thing that makes the
parameter set meaningful.

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
| `signer` | signature of `honest_signer` | Phase B — who is holding the pen. Receives the message bit, the keys, the parameters and the recipients' **raw** logs. |
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
Bob's post-exchange record is precisely the half Charlie does not hold — and it is what a
repudiating Alice must not have. `QDSSession.raw_records` and `QDSSession.records` expose
both to an experiment.

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
