# Security Analysis

**SIH26141: Quantum-Inspired Cyber Threat Detection for Digital Signature Security**

What the scheme guarantees, what we have measured, and the places where those two things do not
reach each other. Written for a reader who has forty minutes and has not read the code.

Every figure below carries the command that produced it. Nothing here was copied out of another
document: eight wrong prose numbers have shipped in this project and been caught, and all eight
entered by transcription rather than by arithmetic.

Three documents make up the submission and each owns its own material. The model and every
derivation behind the bounds quoted here live in [`MODELLING.md`](MODELLING.md); the
adversary-by-adversary record, with what each one was allowed to know and what it measured, is
[`ATTACKS.md`](ATTACKS.md). This one is what those two add up to as a set of claims, so where a
figure is derived elsewhere it is cited rather than re-derived.

---

## Contents

1. [Two kinds of claim](#1-two-kinds-of-claim)
2. [What is assumed](#2-what-is-assumed)
3. [The parameter set, and the two floors](#3-the-parameter-set-and-the-two-floors)
4. [Unforgeability against an outsider](#4-unforgeability-against-an-outsider)
5. [Unforgeability against a recipient: the case that binds](#5-unforgeability-against-a-recipient)
6. [Non-repudiation](#6-non-repudiation)
7. [The headline limitation](#7-the-headline-limitation)
8. [Transferability](#8-transferability)
9. [Unauthorised verification](#9-unauthorised-verification)
10. [Robustness: what an honest run costs](#10-robustness)
11. [The detector's false-alarm claim](#11-the-detectors-false-alarm-claim)
12. [Known limitations, re-checked](#12-known-limitations-re-checked)
13. [Objective 2, threat by threat](#13-objective-2-threat-by-threat)

---

## 1. Two kinds of claim

A **proven bound** is an inequality that holds for every run the scheme will ever execute, derived
from a stated adversary model and a concentration inequality. A **measured rate** is a count out
of a denominator, from runs that have happened, and it carries a confidence interval and nothing
else. The two answer different questions and they never share a column anywhere in this project.

That rule is not decoration, and the reason we keep repeating it is that we keep breaking it. Three
independent audits of Phase 6 returned twelve defects between them, and two of the ones that
survived to a shipped screen were exactly this failure: a factor of `2.944` attached by its grammar
to a pair nine orders of magnitude apart rather than to the budget-versus-bound pair it belongs to,
and a published sentence claiming both verifiers accept on every honest noisy run, false on 5 of
the 12 runs it described. The habit that follows is tedious and is the point:

- Every bound names its estimator. The recipient-forgery bound at production parameters is
  `1.1238e-103` by Kullback-Leibler and `1.1252e-29` by the Hoeffding default, seventy-four orders
  of magnitude apart, and both are correct. A figure quoted without its estimator is unusable.
- Every measurement names its denominator and its interval. `0/400` is written
  `0/400 = 0.0000 [0.0000, 0.0163]` at 99% Wilson, because the zero is the least informative part
  of it.
- A refusal to judge is never counted as a rejection. The verifier has nine distinct abort
  reasons (`python -c "from sih141.protocol.verify import AbortReason; print(list(AbortReason))"`)
  and a run that ends on any of them has produced no verdict at all. Eight need no extra argument
  from the caller, though four of those eight need the Phase C′ count exchange to have run. The
  ninth, `unauthorised-verifier`, needs a caller who names an authorised recipient set, is
  unreachable on a run that does not, and settles only the identity a record declares: a leaked
  record still names its owner, so that reason refuses the party holding no distribution data and
  nobody else. It is not evidence that the recipient set was respected; see **(RECORD SECRECY)**
  in §2. Folding any of the nine into "rejected" would turn a denial of service into a detection,
  which is how a security table flatters itself.

Convention **D9** governs the rest: a published number must be reproducible from a recorded seed
and a committed command, and the command sits next to it. Where a figure comes from a committed
reduced table, the table's own provenance block names the commit that produced it and the one line
that redraws it.

---

## 2. What is assumed

Five assumptions carry the security argument. Four of them are checked nowhere in the code, which
is why they are named rather than implied. The exception is exchange honesty, which a single-run
z-score on the declared count does test (§12).

| Name | Statement | If it fails |
| --- | --- | --- |
| **(AUTH)** | The classical and quantum channels from Alice are authenticated: a recipient knows the states he measured and the declaration he scores both came from Alice. | Full impersonation succeeds with probability 1. Measured, not argued: `200/200` accepted by both verifiers at `L = 192`, mismatch rate exactly `0.0000`, identical to the honest control in every transcript field. |
| **(IND)** | The declaration `(d_i, w_i)` is statistically independent of the recipients' logged bases `c_i`. | Every bound obtained by *averaging over* a matched count becomes false, not merely loose. Whoever chooses `d` while knowing `c` chooses the matched set, and picks it small. Bounds conditioned on the *observed* count survive untouched. |
| **Private coins** | The symmetrisation coins of Phase A′ are known only to Bob and Charlie. | Non-repudiation collapses. Our own attack harness once leaked them through a shared generator and repudiated `5/5` at production parameters with every floor met. |
| **Exchange honesty** | Recipients report their matched counts truthfully in Phase C′. | A liar forces aborts. That is denial of service rather than forgery, and it is priced in §12. |
| **(RECORD SECRECY)** | A `RecipientRecord` is held only by the recipient it names. | An unauthorised party verifying with a leaked record is byte-indistinguishable from its owner in every transcript field, so nothing in this repository detects it. The `authorised` argument to `sih141.protocol.verify.verify` tests a self-declared identity: it refuses the party who holds no distribution data, whose verdict was worthless anyway at a mismatch rate near `1/2`, and it decides nothing about a party holding a genuine log. The three routes to a record, and which of them is measured, are worked in `sih141.attacks.unauthorised`. |

(AUTH) is inherent to measurement-based QDS rather than a defect here. Dunjko, Wallden and
Andersson, and Amiri and co-authors, both assume authenticated channels from the signer and derive
what remains. The reason it is stated at every site where it is used is that the exclusion is
load-bearing: a full impersonator is running the protocol correctly as *a* signer, every number in
`sih141.protocol.analysis` is on her side, and no counting rule over the recipients' own logs can
separate her run from an honest one because there is nothing in those logs to disagree with.

*Partial* impersonation is a different animal and is caught cold. At `L = 192` over 200 sessions
per arm, an adversary holding only the signing seam is accepted `0/200` at pooled mismatch rates
`0.4988` (Bob) and `0.5038` (Charlie); holding only the distribution seam gives `0/200` at `0.5031`
and `0.4997`. Both land on one half for the same arithmetic reason reached along two routes, and
the contrast between `0/200` and `200/200` is what makes (AUTH) a number instead of a paragraph.
All four scopes are tabled in [`ATTACKS.md`](ATTACKS.md) §6, together with the two controls that
stop the argument being vacuous.

```
python -c "from sih141.attacks.impersonation import shipped_summary; print(*shipped_summary(), sep=chr(10))"
```

---

## 3. The parameter set, and the two floors

```
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol.verify import minimum_matched_count as m, minimum_pooled_matched_count as M; print(P.key_length, P.s_a, P.s_v, m(P), M(P))"
```

| Symbol | Value | What it is |
| --- | --- | --- |
| `L` | 115,200 | Key length |
| `s_a` | 1/64 = 0.015625 | Bob's acceptance threshold |
| `s_v` | 1/16 = 0.0625 | Charlie's acceptance threshold |
| `m_min` | 36,555 | Per-verifier matched-count floor |
| `M_min` | 74,190 | Pooled matched-count floor |
| `M_min − 2·m_min` | 1,080 | The margin that closes the even-split attack |
| `E[\|M_R\|]` | 38,400 | Expected matched positions per verifier |

The floors are derived, never chosen. With `|M_R| ~ Binomial(L, 1/3)` and an honest-abort budget of
`ε = 2⁻⁶⁴`, the Chernoff lower tail gives `δ = √(2 ln(1/ε)/μ) = 0.048068` and
`m_min = ⌈(1−δ)μ⌉ = 36,555`, which is 95.2% of the mean and 11.53 standard deviations below it.
That distance is `√(3 ln(1/ε)) = 11.5362` and does not depend on `L` at all, which is the fact the
count-starvation analysis later turns on. The pooled floor comes from the same inversion over
`M ~ Binomial(2L, 1/3)`, a law that holds by conservation rather than by independence, and both
derivations are set out in [`MODELLING.md`](MODELLING.md) §9 along with why the `1,080` margin is
the whole content of the pooled rule.

The floors do not bite immediately, and where they start to is worth stating precisely because the
usual summary rounds it wrong. The **pooled floor first exceeds 1 at 137 sifted positions**, where
`M_min` goes from 1 to 2. It is not 140, which is merely where it goes 2 to 3, and it is not 1200.
The per-verifier floor stays at 1 until `L = 273`. At the sweep's own check fraction of 0.25 the
nominal key length that first carries a claim is **182**, whose signing length is 137.

A floor of 2 out of an expected pooled count of 91 constrains nobody, so the honest reading is a
ratio rather than a crossover:

| `L` | `m_min` | `M_min` | `M_min / E[M]` |
| --- | --- | --- | --- |
| 137 | 1 | 2 | 0.022 |
| 192 | 1 | 22 | 0.172 |
| 384 | 22 | 106 | 0.414 |
| 528 | 52 | 176 | 0.500 |
| 768 | 106 | 299 | 0.584 |
| 4,800 | 1,224 | 2,668 | 0.834 |
| 115,200 | 36,555 | 74,190 | 0.966 |

```
python -c "
from sih141.protocol.params import ProtocolParams
from sih141.protocol.verify import minimum_matched_count as m, minimum_pooled_matched_count as M
for L in (137,192,384,528,768,4800,115200):
    p=ProtocolParams(key_length=L); print(L, m(p), M(p), round(M(p)/(2*L/3),3))"
```

So the floor becomes a real constraint somewhere around `L = 528`, where it reaches half the honest
pooled mean, and it is a genuine bar by `L = 4800`. Between 137 and roughly 500 the claim column
says yes and the arithmetic says the floor is barely there; a demo run in that band exercises the
mechanism and demonstrates no bound.

---

## 4. Unforgeability against an outsider

**The adversary.** Eve holds no copy of the public key, draws her own key, and declares it. Her
declaration is independent of the recipients' logged bases, so (IND) holds by construction and the
matched count keeps its `Binomial(L, 1/3)` law. She is scored on a third of positions and is wrong
on half of those.

**Proven.** The KL bound at production parameters is `10^-6553.3`. That exponent is printed from a
logarithm rather than from a float because `forgery_bound` underflows to `0.0` at `L = 115200`, and
a bound of exactly zero is a claim no proof supports. The Hoeffding form is looser and also
underflows. Neither number is quotable as a decimal, which is the correct outcome: this adversary
stopped mattering long before the production parameters.

**Measured.** Four rungs, 400 trials each, at key lengths where an acceptance can be seen at all:

| `L` | Charlie accepted | exact P (closed form) | z |
| --- | --- | --- | --- |
| 9 | `61/400 = 0.1525 [0.1119, 0.2044]` | 0.167794 | −0.82 |
| 15 | `26/400 = 0.0650 [0.0398, 0.1044]` | 0.062622 | +0.20 |
| 24 | `4/400 = 0.0100 [0.0030, 0.0330]` | 0.012520 | −0.45 |
| 30 | `1/400 = 0.0025 [0.0003, 0.0209]` | 0.004211 | −0.53 |

Intervals are 99% Wilson; the exact column is `forgery_probability`, an independent closed form
rather than a fit to these runs. The rungs stop at 30 because her acceptance probability is
`1.1201e-12` by `L = 192` and no sample anyone can afford separates that from zero. The KL bound
at that same length is `1.196e-11`, ten times higher. They are not two estimators of one thing:
`1.1201e-12` is the exact acceptance probability and `1.196e-11` is a bound over it, so the gap
is the bound's slack rather than a disagreement. §1's rule about naming which is which exists
for pairs exactly like that one.

```
python tools/sweep.py reduce forgery-curve
python -c "
import math
from sih141.protocol.params import ProtocolParams
from sih141.protocol.analysis import forgery_probability as f, forgery_bound as b
for L,k in ((9,61),(15,26),(24,4),(30,1)):
    e=f(ProtocolParams(key_length=L)); s=math.sqrt(e*(1-e)/400)
    print(L, round(e,6), k, round((k/400-e)/s,2))
p=ProtocolParams(key_length=192); print(192, f(p), b(p, method='kl'))"
```

The bound tracks the measurement here, and it will stop doing so. The KL bound over these four
rungs is `3.076e-01`, `1.402e-01`, `4.312e-02` and `1.965e-02`: between 2.0
and 7.9 times above what was measured, falling as the measurement falls. Compare §6, where the
bound sits near 1 across the whole measured range while the measured rate drops three orders of
magnitude beneath it. The four z-scores are unremarkable and the closed form carries the curve from
`L = 30` onward, which is what licenses reading the exact column at key lengths nobody ran.

---

## 5. Unforgeability against a recipient

The binding case, and the one a security claim should quote. Bob received and measured his own copy
of the public key, took part in the symmetrisation exchange, and now tries to make Charlie accept a
key Alice never signed. He is granted his own records, knowledge of which positions were swapped,
and Charlie's entry verbatim on each swapped position. One more item and there is no bound at all.

Symmetrisation is what makes him this strong, and the direction is worth getting right because the
obvious reading runs backwards. Without the exchange a forging recipient sits at
`(p_s, ρ) = (1/3, 1/3)`, already ahead of an outsider at `(1/3, 1/2)` because he shares her
scored fraction while beating her mismatch rate outright; with it he sits at `(2/3, 1/12)`,
scored twice as often and wrong four times less, since half of Charlie's log is his own record
handed over verbatim. At `L = 30` the exact acceptance probability is `0.481427` with the exchange
against `0.029393` without it, a factor of sixteen in the forger's favour. Phase A′ is there for
non-repudiation and this is its bill: it promotes a recipient to the binding forgery adversary,
which is what carried the production key length from 6,912 to 115,200. The mismatch rates either
side of that trade were measured, and they are in [`ATTACKS.md`](ATTACKS.md) §2.2; the argument
that no measurement strategy beats `ρ = 1/12` is [`MODELLING.md`](MODELLING.md) §6.2.

**Proven, with the estimator named.**

| Quantity | Value | What it is |
| --- | --- | --- |
| `recipient_forgery_probability(DEFAULT_PARAMS)` | `2.1726e-105` | Exact in-model probability. Not a bound. |
| `recipient_forgery_bound(..., method="kl")` | `1.1238e-103` | Proven upper bound, KL exponent |
| `recipient_forgery_bound(...)` | `1.1252e-29` | Proven upper bound, Hoeffding default |

Two valid bounds sit over the same exact figure, seventy-four orders of magnitude apart, and the
default is the loose one. An audit caught these being published under a single name. Whichever is
quoted, it must be labelled, and the exact probability must never be labelled a bound. The reason
they part company is that Hoeffding charges every summand the variance its range allows, `1/4`,
where the true variance at `ρ = 1/12` is `0.076389`; [`MODELLING.md`](MODELLING.md) §6.3 sets the
three numbers side by side and owns that comparison.

```
python -c "
from sih141.protocol.params import DEFAULT_PARAMS as P
from sih141.protocol.analysis import recipient_forgery_probability as p, recipient_forgery_bound as b
print(repr(p(P)), repr(b(P, method='kl')), repr(b(P)))"
```

**Measured, and the ordering result.** Here the sweep produced the strongest single finding in the
project, and it is a finding about experimental design rather than about cryptography. The same
attack, the same code, the same 400 trials, differing only in whether the Phase C′ matched-count
exchange happens **before** or **after** the forger forwards his declaration:

| `L` | before forwarding | after forwarding | exact P | z (after) |
| --- | --- | --- | --- | --- |
| 96 | `0/400 = 0.0000 [0.0000, 0.0163]`, all 400 refusals | `120/400 = 0.3000 [0.2446, 0.3619]` | 0.29663 | +0.15 |
| 192 | `0/400`, all 400 refusals | `63/400 = 0.1575 [0.1162, 0.2100]` | 0.20459 | −2.33 |
| 384 | `0/400`, all 400 refusals | `49/400 = 0.1225 [0.0863, 0.1710]` | 0.11260 | +0.63 |
| 768 | `0/400`, all 400 refusals | `11/400 = 0.0275 [0.0129, 0.0575]` | 0.04036 | −1.31 |
| 1,200 | `0/400`, all 400 refusals | `6/400 = 0.0150 [0.0055, 0.0403]` | 0.01400 | +0.17 |

Before forwarding, a substituted declaration leaves Charlie's pooled matched count undefined,
so Bob accepts and Charlie alone reaches no verdict, and the attack is a **denial of transfer**. After forwarding, Charlie returns a
real acceptance rate. At `L = 96` the two orderings both show 400 refusals in the aggregate column,
and they mean opposite things: before, it is Charlie who reaches no verdict; after, it is Bob, while
Charlie accepts 120 of 400. Averaging the two orderings publishes 15% and describes neither, so
`count_exchange_timing` is a column in every table and is never summed over. The full ladder, with
the refusal counts beside the acceptances and the engagement evidence behind every zero, is
[`ATTACKS.md`](ATTACKS.md) §1, which owns this result.

Five z-scores, one at −2.33. Across the nine forgery rows in this document (four outside, five
recipient) that is one excursion past two sigma where 0.41 is expected, which is what nine draws
look like. It is recorded rather than dropped.

**Where proven and measured fail to meet.** The `L = 96` row measures 0.3000 against a proven KL
bound of `8.207e-01`. The bound is real and is a factor of 2.7 above the measurement, so it excludes
nothing anybody cares about. By `L = 1200` the bound is `8.465e-02` against a measurement of 0.0150,
a factor of 5.6, and it is still the measurement doing the work. The bound only becomes the
interesting statement at key lengths where the measurement has nothing left to resolve, and the
production figure `1.1238e-103` is unreachable by any experiment. The two curves never overlap in
the useful region; they hand off, and the handoff is the exact closed form in the middle column,
which agrees with the measurement at every length we ran it.

---

## 6. Non-repudiation

**The event.** Alice signs, Bob accepts, Charlie rejects the same key, and Alice walks away from
her own signature. `SessionTranscript.repudiated` is that conjunction and nothing else.

**The theorem that governs the whole section.** Worst-casing the per-run bound `exp(−M·gap²/8)` over
the matched count is legitimate and useless: it decreases in `M`, `M = 0` makes repudiation
impossible, so the supremum over everything else is `exp(−gap²/8) = 0.99973`. That is not slack.
An explicit strategy, available to any signer who can read the recipients' logged bases, achieves
exactly 1/2 at every key length, because it engineers `M = 13` with one wrong record and lets a
single coin decide who scores it. Therefore:

> **No unconditional repudiation bound below 1/2 exists without an abort rule**, at any key length
> whatever. Key length does not help, because the failure is not statistical.

The abort rule is what buys a number. Bob accepts only when his own matched set clears `m_min`, so
on the repudiation event `M ≥ m_min`, and off it there is nothing to bound.

| Rule enforced | Floor on `M` | Proven bound |
| --- | --- | --- |
| Bob's own floor alone | 36,555 | `4.3614e-05` |
| Both verifiers' own floors | 73,110 | `1.9022e-09` |
| **The shipped rules** (`enforced_repudiation_bound`) | 74,190 | **`1.4139e-09`** |

The first two rows are not the shipped guarantee and must not be lifted out of this table. A
per-verifier floor alone leaves a third outcome open: Charlie holding a non-empty matched set below
his own floor, on which he returns no verdict, and against which a log-reading Alice aims the total
at `2·m_min` and splits it. That attack was measured at `85/200` at `L = 600` before the pooled
floor existed, and at `78/200` and `87/200` at `L = 360`; the code path
that produced those figures was removed by the fix, so they are quoted from
`sih141.protocol.params` rather than re-run here. `sih141.protocol.verify` applies the pooled floor
and makes the per-verifier floor's consequence joint, so on the shipped code "Bob accepts" implies
"Charlie reached a verdict" and the third outcome does not exist. `1.4139e-09` needs all three of
those rules.

```
python -c "
from sih141.protocol.params import DEFAULT_PARAMS as P
from sih141.protocol.verify import enforced_repudiation_bound as e, minimum_matched_count as m
from sih141.protocol.analysis import repudiation_bound_with_abort as r
print(repr(e(P)), r(P, minimum_matched_records=m(P)), r(P, minimum_matched_records=2*m(P)))"
```

This bound is a-priori, holds for **every** signer strategy, needs no (IND) and no model of Alice
at all. A completed run should quote something tighter and different: `repudiation_bound` at its
own observed `M`, which every transcript carries as `repudiation_guarantee`.

**Measured.** A signer who tilts both deliveries by the same angle, at the tilt that maximises her
chance, 400 trials per rung, count exchange before forwarding, `check_fraction = 0`:

| `L` | repudiated (measured) | exact in-model P | enforced bound (proven) |
| --- | --- | --- | --- |
| 24 | `107/394 = 0.2716 [0.2180, 0.3327]` | `2.498e-01` | `9.995e-01` |
| 48 | `66/399 = 0.1654 [0.1231, 0.2187]` | `1.569e-01` | `9.995e-01` |
| 96 | `35/400 = 0.0875 [0.0575, 0.1309]` | `6.602e-02` | `9.995e-01` |
| 132 | `18/400 = 0.0450 [0.0249, 0.0799]` | `3.639e-02` | `9.995e-01` |
| 138 | `8/400 = 0.0200 [0.0083, 0.0474]` | `3.270e-02` | `9.995e-01` |
| 192 | `14/400 = 0.0350 [0.0179, 0.0673]` | `2.951e-02` | `9.940e-01` |
| 300 | `6/400 = 0.0150 [0.0055, 0.0403]` | `1.158e-02` | `9.818e-01` |
| 384 | `2/400 = 0.0050 [0.0010, 0.0252]` | `7.100e-03` | `9.713e-01` |
| 600 | `1/400 = 0.0025 [0.0003, 0.0209]` | `1.936e-03` | `9.434e-01` |
| 768 | `0/400 = 0.0000 [0.0000, 0.0163]` | `5.845e-04` | `9.212e-01` |

The denominator is `engaged`, the runs whose tilt actually replaced at least one delivered state,
read off the adversary's own counter. Six runs at `L = 24` never engaged and are scored as honest
runs rather than as missed repudiations. The exact column is `repudiation_probability` at that
rung's tilt, an independent route to the same quantity, and it tracks the measurement over more
than two orders of magnitude.

**Read the third column against the second.** It barely moves: 0.9995 at `L = 24` and still 0.9212
at 768, while the measured rate falls by a factor of 109 from `L = 24` to `L = 600`. Divide the two
row by row and the ratio runs 3.7, 11, 50, 28, 194, 377, then 56.5 at 768 where the comparison is
against an upper limit rather than against a rate. The 50 sits out of order because the `L = 138`
rung measured 8 successes where its own closed form expected 13, and it is printed in sequence
instead of dropped to make the trend read cleanly. That is the shape of a bound doing no work at
these key lengths, and §7 is what it means.

The rung that makes the rest readable is the control. Run the identical adversary against the
variant with **no symmetrisation exchange** and it succeeds `400/400 = 1.0000 [0.9837, 1.0000]` at
`L = 192`, 384 and 768. Without that, a rung reporting zero is indistinguishable from a rung whose
attack was never mounted.

```
python tools/sweep.py reduce repudiation-curve
python -c "
from sih141.protocol.params import ProtocolParams
from sih141.protocol.analysis import repudiation_probability as r
from sih141.protocol.verify import enforced_repudiation_bound as e
for L,q in ((138,0.043),(192,0.044),(600,0.041),(768,0.041)):
    p=ProtocolParams(key_length=L); print(L, '%.4e'%r(p,mismatch_probability=q), '%.4e'%e(p))"
```

---

## 7. The headline limitation

Read this before deciding what the measurements are worth. The limitation is structural rather
than a shortage of compute, which is what makes it permanent at any scale this project could
have run.

**Demo-scale runs cannot demonstrate non-repudiation, at any scale we can run.**

Take the `L = 768` rung, the deepest one in the curve. Three numbers describe it:

```
measured        0/400 = 0.0000, 99% Wilson upper limit 0.016317
exact in-model  5.8447e-04
proven bound    0.9212
```

The measurement's upper limit is **27.9 times coarser** than the exact probability, so the
experiment cannot see the effect it is measuring even in principle at that sample size. The proven
bound is **56.5 times looser** than the same upper limit, so the proof excludes nothing the
experiment did not already exclude. Neither the proof nor the measurement reaches the other, and the
region the real claim lives in, `1.4139e-09` at `L = 115200`, is outside the range of both by a
wide margin.

```
python -c "
from sih141.attacks.impersonation import wilson_interval
from sih141.protocol.params import ProtocolParams
from sih141.protocol.analysis import repudiation_probability as r
from sih141.protocol.verify import enforced_repudiation_bound as e
p=ProtocolParams(key_length=768); hi=wilson_interval(0,400,confidence=0.99).high
ex=r(p,mismatch_probability=0.041)
print(hi, ex, e(p), hi/ex, e(p)/hi)"
```

Both gaps have a cause and neither is fixable by trying harder.

*The measurement floor.* A run of `n` trials that observes zero successes can exclude a rate of
`z²/(n + z²)` at 99% confidence and nothing smaller, which is about `6.6/n` once `n` is large. At
`n = 400` that is 0.016317. Resolving
`5.8447e-04` at `L = 768` needs **11,346 trials**, which is about 14 hours of single-stream worker
time at the 4.459 s per session that rung actually cost, and is therefore affordable. Resolving the
production claim `1.4139e-09` needs **4.69 × 10⁹ trials** at 235.092 s each: 35,000 years
single-threaded, or roughly 1,838 years at twenty workers with the sweep's observed occupancy. That
is not a budget problem.

```
python -c "
from sih141.attacks.impersonation import wilson_interval as w
lo,hi=1,10**14
while hi-lo>1:
    mid=(lo+hi)//2
    if w(0,mid,confidence=0.99).high > 1.4139e-09: lo=mid
    else: hi=mid
print(hi, hi*235.092/(365.2425*86400))"
```

*The proof floor.* The enforced bound is `exp(−max(2·m_min, M_min)·gap²/8)`, and it holds for every
signer strategy with no independence assumption and no model of the adversary. That generality is
what makes it useless at small `L`: at 768 positions the guaranteed evidence base is 299 records and
`gap² / 8 = 2.75e-04`, giving 0.9212. The bound is loose over exactly the range a measurement can
reach, and tight over exactly the range no measurement can.

**What a demo run does establish.** The mechanism. The measured curve falls by two orders of
magnitude from `L = 24` to `L = 600` and reaches zero at 768, tracking the exact closed form the
whole way; the
unsymmetrised control succeeds every time at every length; the floors fire and are recorded as
no-verdicts rather than rejections. All of that is real evidence that the machine works as
described. None of it is confirmation of the bound, and any screen or slide that shows a measured
zero beside `1.4139e-09` is inviting a reader to conclude something neither number supports.

---

## 8. Transferability

**The property.** If Bob accepts, Charlie accepts too, in the same round.
`SessionTranscript.transferable` is that conjunction plus session coherence: a transcript whose two
verdicts came from different distribution rounds records two transactions rather than one, and does
not count.

**The mechanism, and why the gap is asymmetric.** Charlie's bar is four times *looser* than Bob's,
so the same link noise trips Bob long before it troubles Charlie. That asymmetry is the whole design
and it is quantifiable at the point where it matters, the design noise ceiling `2·s_a = 0.03125`:

| Depolarising strength | error rate `p_e` | P(Bob rejects) | P(Charlie rejects) |
| --- | --- | --- | --- |
| 0.0025 | 0.00125 | 0.006630 | `2.088e-09` |
| 0.005 | 0.0025 | 0.024521 | `9.429e-08` |
| 0.010 | 0.005 | 0.084068 | `4.474e-06` |
| 0.015 | 0.0075 | 0.162657 | `4.213e-05` |
| 0.03125 | 0.015625 | 0.442601 | `2.080e-03` |

At the ceiling Bob balks 213 times more often than Charlie. A signature Bob accepted on a link that
noisy is one Charlie will almost certainly accept as well, and that is the transferability claim
stated as a ratio instead of as an adjective.

The function is called `honest_abort_probability`, and at these lengths what it returns is a
rejection rate: it covers both ways an honest signature fails to be accepted, and the
empty-matched-set term that would make it a true no-verdict is about `1e-51` at signing length
288. The columns above say rejects because that is what the number is. Keeping the two words
apart is the same rule §3 applies to the attack tables, and it applies to our own arithmetic
too.

```
python -c "
from sih141.protocol.params import ProtocolParams, Party
from sih141.protocol.analysis import honest_abort_probability as h
p=ProtocolParams(key_length=288)
for s in (0.0025,0.005,0.01,0.015,0.03125):
    print(s, h(p,error_rate=s/2,party=Party.BOB), h(p,error_rate=s/2,party=Party.CHARLIE))"
```

**Measured, noiseless.** Every honest run in the sweep was transferable. Thirty runs per cell at
signing lengths 144, 288 and 576, sixty party-verdicts per cell, all accept and none refuse; the
ROC family adds forty more at signing length 288, and forty again on an unchecked transcript at
signing length 384. No honest run in any experiment produced a split verdict.

**Measured, noisy.** The `noise` family runs 30 sessions per cell at signing length 288 through a
depolarising channel. Reading the closed form above against what those runs actually returned:

| cell | predicted rejections of 60 | observed |
| --- | --- | --- |
| clean | 0.00 | 0 |
| p0025 | 0.20 | 0 |
| p005 | 0.74 | 0 |
| p010 | 2.52 | 1 |
| p015 | 4.88 | 9 |
| p03125 | 13.34 | 16 |

The `p015` cell runs high. Under `Binomial(30, 0.162657)`, which is where essentially all of those
rejections must come from since Charlie's own rejection probability there is `4.2e-05`, observing 9 or
more has probability 0.044. One row of six at a 4.4% tail is what six rows look like, and it is
printed rather than trimmed. Note also that this table's source, `docs/tables/noise.md`, was
regenerated at commit `b52a2a9eaccd` at eight workers, not at the `f94d9feb73be` that produced the
other six tables.

**A second measurement, from a different path entirely.** Phase 6 ran twelve honest sessions
through the live dashboard at signing length 144 with the link at the design noise level, and
recorded **7 seeds where both verifiers accept and 5 where Bob rejects**, Charlie never. The closed
form at those parameters predicts Bob aborting on 6.33 of 12 and Charlie on 0.23, so the
asymmetry reproduces on a code path that shares no runner, no seed derivation and no reduction with
the sweep. A link at the design noise level costs the signature something, and the thing it costs
is Bob's acceptance rather than Charlie's, which is the direction transferability needs.

```
python -c "
from sih141.protocol.params import ProtocolParams, Party
from sih141.protocol.analysis import honest_abort_probability as h
p=ProtocolParams(key_length=144)
print(h(p,error_rate=0.015625,party=Party.BOB), h(p,error_rate=0.015625,party=Party.CHARLIE))"
```

Under a dishonest signer, a transferability failure is a repudiation, and §6 and §7 are the whole
of what can be said about it.

```
python tools/sweep.py reduce noise
python tools/sweep.py reduce honest
```

---

## 9. Unauthorised verification

**The threat, and where it comes from.** The problem statement's Objective 2 names *unauthorized
verification attempts* among what has to be detected. An unauthorised verification attempt is a
party outside the round's authorised recipient set reaching a verdict on Alice's declaration.
Verification consumes exactly one resource, a `RecipientRecord` bound to a distribution round, so
the threat decomposes by how that party obtains one, and the three routes have three different
answers: he invents a record, he holds a recipient's stolen one, or he builds one off the Phase A
wire.

**The control, and what it cannot do, said together.** `sih141.protocol.verify.verify` takes an
optional `authorised` set of parties and refuses a record whose party is outside it, before any
count is read, as `AbortReason.UNAUTHORISED_VERIFIER`. What it tests is the identity the record
*declares*, and `RecipientRecord.party` is written by whoever built the record. So it refuses the
party who holds no distribution data and had to invent an identity along with the entries, and it
is powerless against a party holding a genuine recipient's log, because that log still says "Bob"
and passes the check its owner passes. Route one is refused at the interface. Route two is
assumption **(RECORD SECRECY)** in §2, and nothing in this repository detects it. Route three is a
channel attack wearing a different name and is already screened as one. No field in a record binds
it to a holder, none is derivable from its two columns, and the round identifier binds a
declaration to a *round* rather than to a person, so the second of those is a property of the
scheme and not an implementation gap waiting on a later phase.

The whole control is off by default. `authorised=None` runs no check, `QDSSession` never names a
set, and no other number in this document was produced with one.

**U1, the fabricated record.** The party invents `(index, basis, eigenvalue)` entries and scores
the real declaration against them. `DEFAULT_BASES` is `(X, Y, Z)` so `|B| = 3`: his invented basis
coincides with the declared one at rate `1/3`, and on those positions his invented eigenvalue is a
fair coin against a declaration he had no hand in, so his mismatch rate concentrates on `1/2`. Both
thresholds are noise budgets measured from an exact zero, `s_a = 1/64` and `s_v = 1/16`, so he
rejects a genuine signature with overwhelming probability. The table below measures that rather
than proving it, and its `0/200` carries a 95% Wilson upper limit of `0.0188`. At `L = 192` over
200 independent sessions, 95% Wilson throughout:

| verifier | genuine record accepts | fabricated record accepts | matched fraction | mismatch, genuine declaration | mismatch, a declaration Alice never made |
| --- | --- | --- | --- | --- | --- |
| Bob, `s_a = 1/64` | `200/200` | `0/200 = 0.0000 [0.0000, 0.0188]` | `12883/38400 = 0.3355` | `6434/12883 = 0.4994 [0.4908, 0.5081]` | `6499/12864 = 0.5052 [0.4966, 0.5138]` |
| Charlie, `s_v = 1/16` | `200/200` | `0/200 = 0.0000 [0.0000, 0.0188]` | `12774/38400 = 0.3327` | `6442/12774 = 0.5043 [0.4956, 0.5130]` | `6378/12649 = 0.5042 [0.4955, 0.5129]` |

> Source: doctest on `sih141.attacks.unauthorised.shipped_summary` and the `MEASURED` table it
> prints, run by `python -m pytest sih141/attacks/unauthorised.py --doctest-modules`

**That he rejects is the uninteresting half.** The last two columns are the result: the same
fabricated record scores a genuine declaration and a declaration nobody distributed states for at
rates whose intervals overlap, because neither rate depends on what the declaration says. His
accept-or-reject is a function of his own coins, so his verification is *void* rather than merely
unauthorised, and reporting his rejection as a detection would report the outcome of an experiment
that was never run. The matched-fraction column says the same thing from the other side: an
invented log is scored on as many positions as an honest one, `1/3` either way, because inventing
values does not change the sampling law over bases. The `1/2` is §4's arithmetic reached from the
opposite direction, an outsider scoring a real declaration against an invented log rather than
declaring a key against a real one, and independence between the two columns gives a fair coin
either way. The genuine-record column is what stops the table being vacuous: the same declaration,
scored against the log the round actually produced, is accepted 200 times out of 200.

**U2, the leaked record.** The party holds a genuine recipient's log, obtained by any means outside
the protocol. `verify` is a pure function of the declaration, the record and the parameters, so two
calls on the same three arguments return the same eight `VerificationResult` fields and a
transcript written by the thief is byte-identical to one written by the owner. **No rate is
published for this route, deliberately.** A count would compare one verdict against another verdict
reached from the same three objects, which evaluates a premise twice rather than observing
anything, and it would carry the authority of a measurement while doing so. The parity with the
`200/200` impersonation figure in §2's (AUTH) row does not hold either: there Mallory runs a whole
distribution and a signing with a key of her own and both verifiers accept, which is an experiment
that could have come out the other way. That the stolen record still names its owner is also not a
count. `QDSSession.distribute` refuses a record tagged with another party, so it is an invariant
enforced upstream, and running it 200 times would repeat a structural identity 200 times.

**U3, the tapped record.** The party assembles his own record by intercepting the teleported qubits
in Phase A. No-cloning forbids copying the travelling half, so to learn an eigenvalue he has to
measure it, and measuring one half of a Bell pair collapses both. That is
`sih141.attacks.channel.InterceptResend` on the same seam, `ResourceFactory`, with the same physics
and the same damage, and the resource he leaves behind has a QBER of `1/3 = 0.333333` against a
per-link screen sized to resolve `s_a = 1/64` to a quarter of itself. So there is no second
detector here and no second rate: the end-to-end numbers for this adversary are the channel
campaigns of [`ATTACKS.md`](ATTACKS.md) §4. What is *measured* is the QBER the collapsed resource
produces, computed on the spot from `qber_from_tensor(collapse_tensor(PAULI_AXES))` rather than
quoted. What is *argued* is the step before it, that a party building a record off the wire has no
route to an eigenvalue except the measurement which destroys it.

**How the refusal is counted.** `UNAUTHORISED_VERIFIER` sits in `STRUCTURAL_ABORT_REASONS`, whose
members carry a false-positive probability of exactly zero under the honest null, and it is the one
member of the five whose zero is conditional. The other four are equality tests on data the honest
protocol fixes. This one is set membership on an argument the caller supplies, so the zero holds
only for a set naming the recipients the signer actually distributed to; a set that omits one
refuses him on every honest run, and that refusal is counted the same way an adversarial one is.
The detector maps the reason to `SignalKind.LEDGER`, beside replay and the already-verified record,
because the question is the same one and the answer comes from bookkeeping rather than from a
count. It remains a refusal and not a rejection, under the rule in §1: a run ending on it has
produced no verdict, and the fabricator whose verdict it withholds was carrying no information
about the signature anyway. **No operator of the shipped server ever sees one.** `sih141/audit.py` records
one event per verification outcome with the abort reason on it and `GET /api/events` serves them,
but the only writer of those events is `POST /api/run`, which runs a `QDSSession`, and the session
names no authorised set: no call site under `sih141/web/` passes `authorised` at all, and the
dashboard never fetches that endpoint. The reason is reachable from a direct caller of
`sih141.protocol.verify.verify` and from nowhere else in this repository, which is the same fact as
the paragraph above stated from the operator's side.

```
python -c "from sih141.attacks.unauthorised import shipped_summary; print(*shipped_summary(), sep=chr(10))"
python -c "from sih141.attacks.unauthorised import tapped_record_reduction; print(tapped_record_reduction()['qber'])"
```

---

## 10. Robustness

A scheme that rejects everything is trivially unforgeable and worthless, so the failure probability
of an honest run belongs in a security document rather than beside it.

At production parameters on a noiseless link the composition is

```
P_fail = honest_abort_probability                          0.0
       + 2 × matched_shortfall_probability(m_min)      2 × 2.5476e-31
       +     matched_shortfall_probability(M_min)          2.9202e-31
       = 8.0154e-31
```

against an abort budget of `2⁻⁶⁴ = 5.42e-20`. The rate term is zero because a noiseless honest run
produces no mismatch at all, so the only way to fail by the rate rule is to hold no evidence.
Twenty-one orders of magnitude separate the honest failure probability from the repudiation bound,
which is what stops the abort rule ever becoming the dominant reason an honest signature does not
stick.

```
python -c "
from sih141.protocol.params import DEFAULT_PARAMS as P
from sih141.protocol.analysis import honest_abort_probability as h, matched_shortfall_probability as s
from sih141.protocol.verify import minimum_matched_count as m, minimum_pooled_matched_count as M
print(h(P) + 2*s(P,minimum_matched=m(P)) + s(P,minimum_matched=M(P),pooled=True))"
```

The link noise an honest signature survives is `2·s_a = 0.03125`. Widening the threshold gap buys
security in both directions and costs on both sides: raising `s_v` walks Charlie's cut toward the
recipient forger's floor of 1/12, where the forgery bound reaches 1; lowering `s_a` shrinks the
noise tolerance directly. `ProtocolParams` refuses an `s_v` at or above the forger floor unless
`allow_forgeable` is set. The shipped `s_v = 1/16` is three quarters of the way to that floor and
buys `1.414e-09` repudiation and `1.124e-103` recipient forgery (KL estimator) at once. The next rung up the
ladder, `s_v = 0.078125`, spends 96.9 orders of magnitude of forgery security to buy 6.9 of
repudiation, which is what "three quarters of the floor" is protecting.

---

## 11. The detector's false-alarm claim

Three families of derived thresholds sit under the composite rule, and firing when any of them fires
inflates the family-wise error rate. The correction is a union bound, chosen over Sidak because
Sidak needs independence the families demonstrably do not have, and over Holm and Simes because a
derived threshold has a bound on a tail rather than a p-value. Dropping the members that stayed
quiet would be sharper still and is forbidden outright: that is fitting.

On an honest run at signing length 288 with a budget of `eps = 1e-09`, the proven per-run
false-positive bound is

```
3.3963533679543065e-10        slack factor 2.944 under budget
```

reproduced in-process rather than read from the table:

```
python -c "
from sih141.eval.experiments import experiment, run_trial
d = run_trial(experiment('roc'), 'honest', 0).detection
print(d['false_positive_bound'], d['slack_factor'], d['bound_is_unconditional'])"
```

Against that, the measurement: `0/98 = 0.000 [0.000, 0.063]` across the clean arms of the ROC family
at 99% Wilson. The proven number is the useful one, and the comparison is instructive precisely
because the measurement is so much weaker: `0/98` is consistent with a true false-alarm rate of
several percent, while `3.3964e-10` is a statement about every run that will ever be scored. What
the derivation buys is not a better observed rate. It is the irrelevance of the sample size.

**Where the derived detector gives ground, stated rather than tuned away.** Once the link's own
error rate is admitted into the null instead of a noiseless one, the detector separates 0 of 3
attacked arms at `eps = 1e-09` where the noiseless null separates 8 of 8, with a ninth arm marked
`undetectable-by-construction` because (AUTH) rules it out rather than because it was missed. An
adversary operating at or below the noise the protocol already tolerates is inside that tolerance,
and no threshold derived from the true null can see him. That is a result about the protocol's
observability, and it is the reason every table carries a `null_is_noiseless` column.

```
python tools/sweep.py reduce roc
```

---

## 12. Known limitations, re-checked

Each of these was re-derived from the current tree rather than copied forward.

**Demo-scale runs cannot demonstrate non-repudiation.** Holds, and §7 is the full statement. The
commonly repeated form of this, that both floors are inert below `L ≈ 1200`, is imprecise: the
pooled floor first exceeds 1 at 137 sifted positions and the per-verifier floor at 273, but neither
reaches half the honest pooled mean until `L = 528`. The enforced bound is `9.940e-01` at `L = 192`,
`9.434e-01` at 600, and still `4.806e-01` at 4,800.

**Full impersonation succeeds with probability 1** if the channel from Alice is not authenticated.
Holds. Measured `200/200` accepted by both verifiers at `L = 192` with mismatch rate exactly zero,
byte-comparable to the honest control. Excluded by assumption (AUTH), which must be stated wherever
the exclusion is used, and which is inherent to this family of schemes rather than to this
implementation. Partial impersonation on either seam is `0/200`.

**A recipient can force aborts** by under-reporting his matched count. Holds, and the price is
worth reading. The denial itself is deterministic, free, needs no key material and no quantum
resource; there is no probability in it to measure. What is expensive is plausibility. The least
implausible count that still denies sits `−11.5375` standard deviations below the honest mean at
production parameters and `−11.6047` at `L = 600`, converging from below to `−√(3 ln(1/ε)) =
−11.5362` independently of `L`. A single-run z-score on the declared count catches every successful
starvation, at a false-alarm rate bounded by the honest-abort budget the floors were already
calibrated to. It remains a real fifth attack surface and a denial of service, never a forgery.

```
python -c "
from sih141.attacks.starvation import least_implausible_z
from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
print(least_implausible_z(DEFAULT_PARAMS), least_implausible_z(ProtocolParams(key_length=600)))"
```

**The noiseless null is not the truth on a noisy link.** Holds, and §11 gives the cost: the
detector's mismatch members fire correctly on honest runs when the link is genuinely noisy, and
every reduced table therefore carries `null_is_noiseless` as a caveat on the row rather than as a
detail. At demo scale the mismatch-rate detector adds nothing over a verifier's own cut once the
link error rate passes the dominance level, which over the matched counts the repudiation runs
produced (`|M_R|` from 2 to 299) is 0.000000 to 0.009459 at Charlie's cut. That is far below the
design noise level `2·s_a = 0.03125`, so on any demo-scale link that is noisy at all, that detector
is dominated by the verifier's own threshold.

**Measured recipient forgery against the shipped protocol is not a single number.** Holds, and it is
the ordering result of §5. Under the shipped Phase C′ ordering the attack is a denial of transfer
and the acceptance rate is `0/400`; move the count exchange after forwarding and it is a forgery
with a real rate. Both are true of the same code. Any figure quoted without its ordering is a figure
about a protocol nobody runs.

**An unauthorised verifier holding a leaked record is undetectable.** Holds, and it is the boundary
of the `authorised` control §9 adds. That check tests the identity a record declares, a leaked
record declares its owner's, and no transcript field written by the thief differs from one written
by the owner. It is assumption **(RECORD SECRECY)** in §2 rather than a gap a later phase closes.
§9 works the three routes to a record and says which one is measured, which is excluded by
assumption, and which reduces to the channel screen.

**"The problem statement's deliverables table was left blank."** Does not hold, and this entry is
what re-checking it produced. `SIH26141-problem-statement.pdf` in the repository root is image-only
with no text layer, so no grep over the tree could contradict the claim and nobody rendered it;
page 2 carries a populated **Delivery Table (Expected Deliverables)** whose rows are S.No 1, 2, 3,
4 and 6, the single irregularity being that 5 is skipped in the numbering. Row 6, *Software
Framework / Prototype*, names four key components, of which the two this document touches are the
threat detection dashboard and logging of security events: Phase 6 and `sih141/audit.py` (§9).
Our scope is still our own reading, because a table of deliverables is not an order to build them
in, but it is a reading of a table and not of a placeholder. Checking it needs a PDF renderer,
which is not a project dependency; with PyMuPDF installed the page comes out as

```
python -c "import pymupdf; d = pymupdf.open('SIH26141-problem-statement.pdf'); d[1].get_pixmap(dpi=150).save('page2.png')"
```

---

## 13. Objective 2, threat by threat

Objective 2 of the problem statement, page 1, reads *"Detect digital signature forgery,
impersonation, replay attacks, and unauthorized verification attempts."* Three of its four
threats are detected. The fourth is decomposed and answered rather than detected. The material is
all in §9 and [`ATTACKS.md`](ATTACKS.md) §7; what those two do not do is put the objective's four
items in one list with what each one got, which is what a reader checking the brief against the
repository needs.

**Forgery and replay.** Detected by a derived threshold at a stated false-positive bound, with a
measured rate. At `L = 384`, `eps = 1e-9`, 40 runs per arm, the composite proven bound is
`3.3964e-10` (§11) and the sweep measures `40/40 = 1.000 [0.858, 1.000]` at 99% Wilson on outside
forgery, on recipient forgery in both count orderings, and on replay. What fires is a *group* of
hypotheses rather than a name: a transcript-only detector cannot separate the five that a
substituted declaration leaves standing, and [`PHASE4.md`](PHASE4.md) §5 lists which group each
arm produced.

**Impersonation, with an asterisk that is not a footnote.** One seam alone is detected: the
signing seam at `40/40 = 1.000 [0.858, 1.000]` in the same sweep, the distribution seam at the
same rate in the Phase 4 campaign. Both seams at once is not. Mallory holding both is accepted
`200/200` by both verifiers at mismatch rates of exactly `0.0000`, identical to the honest control
in every transcript field, and that cell is recorded as `undetectable-by-construction` rather than
as a rate because there is nothing in the recipients' logs to disagree with. It is assumption
**(AUTH)** in §2 rather than a miss, and the scope it excludes is the strongest one. *Three of
four detected* is true only with that sentence attached to it.

**Unauthorized verification attempts: decomposed and answered, not detected.** Verification
consumes one resource, a `RecipientRecord`, so §9 splits the threat by how an unauthorised party
gets one. A party who **fabricates** a record is refused at the interface by the optional
`authorised` check, and the result that matters is not the refusal: his verdict carries no
information about the signature at all. Over 200 sessions at `L = 192` he accepts `0/200`, and his
mismatch rate on Alice's genuine declaration (`0.4994` Bob, `0.5043` Charlie) and on a declaration
Alice never made (`0.5052`, `0.5042`) have overlapping intervals, so the rate does not depend on
what the declaration says. A party who verifies with a **leaked** recipient record is
byte-indistinguishable from its owner in every transcript field, and is excluded by assumption
**(RECORD SECRECY)**. A party who builds a record off the **Phase A wire** is intercept-resend
under another name and is caught at `40/40 = 1.000 [0.8577, 1.0000]` on both check fractions the
Phase 4 campaign ran: on the `channel` and `mismatch` signals at `0.25`, and on `mismatch` alone at
`0.0`, where there are no check rounds and the channel family is withheld
([`PHASE4.md`](PHASE4.md) §5). No detector in this repository fires on an unauthorised
verification attempt as such.

**What the `authorised` argument is, and what it is not.** It is not a defence in the shipped
system. `authorised=None` is the default, `QDSSession` never passes a set, no path under
`sih141/web/` passes one, and no published number anywhere in this repository was produced with
the check live. It is an interface a deployment could use, and it tests a self-declared identity:
it refuses the party who holds no distribution data and decides nothing about the party who holds
a genuine log. Calling it enforcement would describe a configuration nobody in this repository
runs.

> Sources: [`tables/roc.md`](tables/roc.md) at `eps = 1e-9`, regenerated with
> `python tools/sweep.py reduce roc`; the impersonation and unauthorised-verifier rates from the
> doctests on `sih141.attacks.impersonation.shipped_summary` and
> `sih141.attacks.unauthorised.shipped_summary`, run by
> `python -m pytest sih141/attacks/impersonation.py sih141/attacks/unauthorised.py --doctest-modules`;
> the distribution-seam and intercept-resend arms from [`PHASE4.md`](PHASE4.md) §5.

---

*Bounds and closed forms live in `sih141.protocol.analysis`; the enforced repudiation bound is
`sih141.protocol.verify.enforced_repudiation_bound`. Measured rates come from the reduced tables in
[`tables/`](tables), each of which carries its own commit and the one line that redraws it.
Per-phase engineering detail is in `docs/PHASE1.md` through `docs/PHASE6.md`.*
