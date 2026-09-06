# The protocol, as mathematics

**SIH26141 · Quantum-Inspired Cyber Threat Detection for Digital Signature Security**

What follows states the scheme as mathematics and nothing else: the states it prepares, what
a key and a signature are, what verification actually tests, and which inequality every
published bound rests on. What those bounds add up to as claims is
[`SECURITY.md`](SECURITY.md); what every adversary was allowed to know and what each one
measured is [`ATTACKS.md`](ATTACKS.md). Both cite this document for their derivations, and it
cites them wherever a number here was measured rather than computed. The engineering history is
`docs/PHASE1.md` through `docs/PHASE6.md`, which this does not replace and does not summarise.

**Every figure below carries the command that produced it, with one stated exception.** Run
them from the repository root; they take seconds, except where noted. The exception is §8,
where the measurements that found each break were taken against code the fix then removed,
so no command reproduces them today and §8 says so at the top rather than implying otherwise. That rule is convention D9, and it exists
because eight wrong numbers have shipped in this project's prose and been caught, every one
of them copied out of another document rather than run. `pyproject` runs
`pytest --doctest-modules` over `sih141/` and `tests/`, so a figure written as a doctest is
re-checked on every suite run while a figure written in prose is checked by nobody; where a
committed table already carries a number, this document cites the table instead of restating
it.

## Contents

1. [Notation](#1-notation)
2. [The physical layer](#2-the-physical-layer)
3. [A key, a signature, a verdict](#3-a-key-a-signature-a-verdict)
4. [Correctness, exactly](#4-correctness-exactly)
5. [Three assumptions, named where they bite](#5-three-assumptions-named-where-they-bite)
6. [Unforgeability: two adversaries, one of which binds](#6-unforgeability)
7. [Non-repudiation: the argument over the coins](#7-non-repudiation)
8. [Four times we broke it](#8-four-times-we-broke-it)
9. [The two floors, and where they come from](#9-the-two-floors)
10. [Why `s_a < s_v`](#10-why-s_a--s_v)
11. [The five inequalities](#11-the-five-inequalities)
12. [Where the model runs out](#12-where-the-model-runs-out)

---

## 1. Notation

Fixed once in Phase 2 and used identically in every module docstring, so a symbol here means
what it means in the code.

| Symbol | Meaning |
| --- | --- |
| `L` | key length, `ProtocolParams.key_length`; `115200` at the shipped defaults |
| `B`, `n = \|B\|` | the basis alphabet `{X, Y, Z}`, so `n = 3` |
| `a_i`, `v_i` | Alice's true basis and eigenvalue at position `i` |
| `d_i`, `w_i` | the *declared* basis and eigenvalue: together, the signature |
| `c_i`, `o_i` | recipient `R`'s own basis draw and recorded outcome |
| `M_R`, `m` | the matched set `{i : c_i = d_i}` and its size |
| `M` | `m_B + m_C`, the matched records the two verifiers hold between them |
| `e_R`, `r_R` | mismatches inside `M_R`, and the rate `e_R / m` |
| `s_a`, `s_v` | Bob's and Charlie's acceptance thresholds, `0 <= s_a < s_v` |
| `p_e` | per-matched-position error rate of an honest run |
| `rho` | per-scored-position mismatch probability a compliant recipient forger cannot beat |

`a_i`, `v_i` and each recipient's `c_i` are drawn independently and uniformly, `a_i` and
`c_i` over `B` and `v_i` over `{+1, -1}`, independently across positions.

---

## 2. The physical layer

### 2.1 What a key element is

A key element is two classical labels, a basis and a sign, and the state it names is one of
the six Pauli eigenstates. Alice writes `(a_i, v_i)` down; the quantum object
`|a_i, v_i>` is manufactured from that description, twice, once for each recipient. She never
duplicates anything she does not already know, which is the whole of the answer to the
no-cloning objection: the theorem forbids a machine mapping an unknown `|psi>` to
`|psi>|psi>`, and says nothing about a preparation device driven by two classical arguments,
which is what every laboratory single-photon source is. In the implementation the answer is
literal rather than rhetorical, since `distribute_to_recipient` calls
`KeyElement.state()`, which calls `sih141.core.paulis.eigenstate(basis, eigenvalue)`.

No-cloning does its real work in the other direction, and that is where the security comes
from: a *recipient* holds one copy, measures it once in a basis of his own choosing, and
cannot make a second. Section 6 is that observation turned into a number.

### 2.2 The teleportation identity

Nothing quantum crosses the channel. Write the payload as `|psi> = a|0> + b|1>` on qubit 0
and the shared resource as `|Phi+>` on qubits 1 and 2, then expand qubits 0 and 1 in the Bell
basis:

```
|psi>_0 (x) |Phi+>_12 = 1/2 [ |Phi+>(a|0> + b|1>)
                            + |Psi+>(b|0> + a|1>)
                            + |Phi->(a|0> - b|1>)
                            + |Psi->(b|0> - a|1>) ]_2
```

Every branch carries amplitude `1/2`, so each of the four Bell outcomes occurs with
probability exactly `1/4` for *any* payload. That is the information-theoretic reason the two
bits Alice broadcasts are worthless to an eavesdropper: their law does not depend on
`(a, b)`, so they are statistically independent of the key. The receiver's correction is read
off by inverting each conditional column, which gives `X^{m_0} Z^{m_1}` with the correction
index equal to the little-endian `2 m_1 + m_0`. The `|Psi->` row is the one that is easy to
get wrong, because `ZX = -XZ` and only one operator order leaves no residual phase under this
project's sign conventions; `sih141/core/teleport.py` derives the table rather than quoting
one, and Phase 1 checked it against an independently rebuilt register at a maximum deviation
of `5.55e-16`.

Because the derivation is linear in the density matrix, a degraded resource carries through
unchanged. For the Werner family `rho(p) = (1 - p)|Phi+><Phi+| + p I/4` the corrected
receiver state is `(1 - p)|psi><psi| + p I/2`, so the teleportation fidelity is exactly

```
F(p) = 1 - p/2
```

running from `1` on a pristine pair down to `0.5` on a maximally mixed one, which is the best
any classical measure-and-prepare strategy achieves. Five points on that line, checked
against the closed form:

```bash
python -c "import numpy as np; from qiskit.quantum_info import DensityMatrix, Statevector; from sih141.core.rng import resolve_rng; from sih141.core.states import bell_state, BellState; from sih141.core.teleport import teleport; phi=DensityMatrix(bell_state(BellState.PHI_PLUS)).data; rng=resolve_rng(np.random.default_rng(20260141)); print([round(teleport(Statevector([0.6,0.8]), resource=DensityMatrix((1-p)*phi+p*np.eye(4)/4), rng=rng).fidelity, 12) for p in (0.0,0.02,0.0625,0.5,1.0)])"
```

```
[1.0, 0.99, 0.96875, 0.75, 0.5]
```

An adversary who owns the entire forward channel therefore sees an entangled half that is
locally maximally mixed together with two uniform bits. He can degrade delivery, and
degradation raises a mismatch rate that the verifier is already measuring, but he cannot read
the key off the wire.

---

## 3. A key, a signature, a verdict

### 3.1 The four phases

Distribution runs once per possible message bit `b`, before Alice knows which bit she will
sign. She draws `k_b = [(a_i, v_i)]` for `i = 1..L`, prepares each eigenstate twice, and
teleports one copy to Bob and one to Charlie, consuming a fresh Bell pair per qubit. On
receipt each recipient immediately measures position `i` in a basis `c_i` drawn uniformly
from `B` and stores `(i, c_i, o_i)`. When distribution returns, no quantum state from the run
exists anywhere: not with Alice, not in the channel, not with the recipients. Gottesman and
Chuang's original scheme needs recipients to hold the public key in quantum memory until a
signature arrives, and this is the construction that removes the requirement.

Between distribution and signing the two *recipients* run their own exchange, out of Alice's
sight. They draw one fair coin per position and swap their two records wherever it comes up
heads, so each verifier still holds exactly one record per position, half of it measured by
the other, and Alice does not know which half. Section 8 is why that step exists.

Signing is one message: Alice sends `(message, k_b)` to Bob over an authenticated classical
channel, and the revealed key *is* the signature. Before either verdict the recipients
exchange one integer each, the count of positions each can score against the declaration, and
Section 9 is what that integer buys.

### 3.2 What verification tests

Recipient `R`, holding his log, a declaration, and his counterpart's reported count
`m_other`, computes

```
M_R = { i : c_i = d_i }
e_R = |{ i in M_R : o_i != w_i }|
r_R = e_R / |M_R|

abort   if  |M_R| < m_min                 own floor: no verdict, NOT a rejection
abort   if  the two counts describe different declarations
abort   if  |M_R| + m_other < M_min       the pooled floor
abort   if  m_other < m_min               his counterpart cannot score either
accept  iff r_R <= threshold(R),  threshold(Bob) = s_a,  threshold(Charlie) = s_v
```

The four checks that read the evidence run in that order so a failure is attributed to the
smallest thing that explains it, and each carries its own `AbortReason`. Three of them are
counting floors; the second is a provenance check, and it is there because `m_other` means
nothing unless it was counted against the same declaration this verifier is scoring, otherwise
the pooled sum mixes two runs and the floor gets enforced on a quantity that is no run's pooled
count.

A fifth check exists in the code and is outside this model. `verify` takes an optional set of
authorised parties and refuses a record naming a party outside it, before any of the four reads
a count. It tests the identity a record declares rather than any quantity defined here, it runs
only when a caller supplies the set, and its reach is [`SECURITY.md`](SECURITY.md) §9.

**Only matched positions may be scored, and this is the classic implementation bug of the
family.** On an unmatched position the recipient measured an observable conjugate to the one
the state was an eigenstate of, so his outcome is a fair coin whether the signature is honest
or forged: it carries exactly zero bits about the key. Counting those positions adds
`(1 - 1/n)/2 = 1/3` of pure noise to every rate, which sits far above `s_v`, and the symptom
is that both verifiers reject every honest signature on a *perfect* channel. That reads as a
hardware fault and sends the debugging in precisely the wrong direction, so
`tests/test_protocol_verify.py` pins the rule with a record whose unmatched positions all
disagree with the declaration and which must still verify at rate `0.0`.

The `|M_R| = 0` corner is the `m = 0` end of the same floor rule, and `verify` raises there
rather than inventing a verdict, because accepting would accept any declaration on zero
evidence while rejecting would be recorded as a forgery detection in a run that holds no
evidence of forgery. Neither is true. So aborts are a separate transcript field with a
separate type, and no downstream statistic can average a refusal to score into a rejection.

---

## 4. Correctness, exactly

On an ideal resource teleportation is exact, so on a matched position the recipient
re-measures the very observable the state is an eigenstate of and `o_i = v_i = w_i` with
probability 1. Both rates are therefore

```
r_B = r_C = 0     exactly, not approximately
```

on any noiseless honest run, for every `L`. This is worth stating precisely because both
thresholds are noise budgets measured from that exact zero rather than tolerances fitted to
observed data, and because the acceptance test is `<=`, so a run landing exactly on its
threshold is accepted. A Werner-`p` resource gives `p_e = p/2`, so an honest signature
survives a link running at up to `p = 2 s_a = 3.125%`:

```bash
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol.analysis import depolarising_error_rate as d; print(d(0.03125), P.s_a, d(0.01))"
```

```
0.015625 0.015625 0.005
```

---

## 5. Three assumptions, named where they bite

All three are stated here because each is load-bearing and none is a theorem about the
protocol. Two more carry the security argument without touching the mathematics below, namely
that the symmetrisation coins stay private and that the recipients report their counts
honestly; all five sit in one table with what each failure costs in
[`SECURITY.md`](SECURITY.md) §2.

> **(IND)** The declaration `(d_i, w_i)` is statistically independent of the recipients'
> logged bases `c_i`.

Every number that *averages* over a matched count needs (IND), and is false without it rather
than merely loose. The matched set is `{i : c_i = d_i}`, so whoever picks `d` while knowing
`c` picks the matched set, and picks it small; a bound whose exponent is linear in that set's
size then bounds a quantity the adversary chose. (IND) is a property of the interface, not of
the mathematics. It holds for an honest signer and for the modelled adversaries of Section 6,
because each `c_i` is drawn privately at receipt time and never published. It does *not* hold
at a seam that hands the signer both raw logs, and Section 8 shows what a signer does with
them.

> **(AUTH)** The classical and quantum channels from Alice are authenticated.

If an attacker can stand in Alice's place from the very start, distributing her own key
states *and* signing them, the run he produces is drawn from the honest law in every respect,
because he made both halves of it and they agree. There is no statistic to build and no
threshold that could fire. Full impersonation succeeds with probability 1, measured at
`200/200` accepted by both verifiers at a mismatch rate of exactly 0, which is what the
honest control gives too. This is inherent to every scheme in this family rather than a
defect of ours, and it is excluded by assumption; wherever the exclusion is used, the
assumption is named beside it. *Partial* impersonation is a different thing entirely and is
caught cold, at `0/200` accepted on either seam. All four scopes, with the pair of controls
that keep that comparison from being vacuous, are [`ATTACKS.md`](ATTACKS.md) §6.

> **(RECORD SECRECY)** A recipient's measurement record is held only by the recipient it
> names.

Nothing in the model binds a record to a holder. A record is an index-keyed basis column and
an eigenvalue column, plus the party label whoever built it wrote there, and verification is a
function of the declaration, the record and the parameters and of nothing else. So a party
holding a copy of Bob's record computes Bob's verdict exactly, in all eight fields of the
result, and there is no statistic over one party's holdings that separates the copy from the
original, because the two are the same object. This is the same shape of exclusion as (AUTH):
a property of the deployment, out of model by assumption rather than defended against, and
named wherever the exclusion is used.

What it does *not* exclude is a party who holds no record at all and invents one. That case is
inside the model, and it is Section 6.1's arithmetic read in the other direction. His
fabricated `c_i` agrees with the declared `d_i` with probability `1/n`, and on those positions
his fabricated eigenvalue is a fair coin against a declaration he had no hand in, so

```
P(o_i != w_i | i in M_R) = 1/2     whatever the declaration says
```

which is the same `1/2` Eve meets in 6.1, reached the same way, by independence between a
column he chose and a column he did not. The consequence is stronger than "he is rejected":
the rate does not depend on the declaration's contents, so his verdict is not a reading of the
signature at all. Measured over 200 sessions at `L = 192` in [`ATTACKS.md`](ATTACKS.md) §7,
with what an authorisation check can and cannot do about it in
[`SECURITY.md`](SECURITY.md) §9.

---

## 6. Unforgeability

### 6.1 Eve, the outside forger, who is the weak case

Eve never received a copy of the public key and holds no measurement record. She knows the
protocol, the parameters, the message, and all public classical traffic, which is exactly the
two teleportation correction bits per qubit; Section 2.2 showed those are uniform whatever
the payload. She controls every `d_i` and `w_i`, jointly and adaptively, with unbounded
computation. She does not control the verifier's basis draws, made privately at receipt time
before any signature existed.

**She cannot steer the matched set.** `c_i` is uniform on `B` and independent of everything
she knows, so `P(i in M_R) = 1/n` for every choice of `d_i` and `m ~ Binomial(L, 1/n)` exactly
as in the honest case; declaring a symbol outside `B` only shrinks `M_R`, and an empty matched
set is not an acceptance anyway. This step *is* (IND), and it is the step to check against the
code rather than against the prose.

**A matched position is a fair coin.** Condition on `c_i = d_i`. The conditioning event
involves only her declaration and the verifier's independent draw, so `(a_i, v_i)` stay
uniform and independent: if `a_i = c_i` then `o_i = v_i`, a uniform sign she knows nothing
about, and if `a_i != c_i` then `o_i` is a fair coin by the Born rule. Either way
`P(o_i = w_i | i in M_R) = 1/2`, independently across positions, whatever strategy produced
the declaration. Nothing here is computational.

The exact probability, with `t(m) = max{e : e/m <= s}`, is a double binomial:

```
P_forge(L, s) = sum_{m=1..L} C(L,m) (1/n)^m (1-1/n)^{L-m} · 2^{-m} sum_{k=0..t(m)} C(m,k)
```

Conditioned on `m`, Hoeffding gives `exp(-2m(1/2 - s)^2)` and the relative-entropy form gives
`exp(-m D(s || 1/2))`. Averaging any bound of the shape `exp(-mc)` over `m ~ Binomial(L, 1/n)`
is *exact*, because that average is a probability generating function:

```
E[exp(-mc)] = (1 - 1/n + e^{-c}/n)^L = exp(-L lambda),   lambda = -ln(1 - (1 - e^{-c})/n)
```

so the bound is exponential in `L` itself rather than in a random count. At the shipped
defaults `D(1/16 || 1/2) = 0.4594` nats and `lambda = 0.1310`, putting the outside-forgery
bound at `10^-6553.3`. The library's float underflows to `0.0` there, and a bound of exactly
zero is a claim no proof supports, so the committed tables print it from `log10`.

### 6.2 Bob, the recipient forger, who binds

Eve is the *weakest* adversary in the model, and quoting her number as "the forgery
probability" understates the real one by thousands of orders of magnitude. Bob is stronger. He
holds his own `L` measurement records, and after the recipients' exchange he supplied half of
Charlie's evidence and knows exactly which half, which is a great deal more than any outsider
ever gets.

His best compliant play is to declare his own raw pre-exchange record at every position. On a
swapped position, probability `1/2`, Charlie's entry *is* that record, so it matches with
probability 1 and never mismatches. On a retained position, also probability `1/2`, Charlie
holds his own measurement of an independent copy: matched with probability `1/n`, and given a
match the two agree outright when Bob's basis was Alice's, probability `1/n`, and are
independent fair coins otherwise. Collecting, and writing `p_s` for the fraction of positions
he gets scored,

```
p_s = (n + 1) / (2n)             = 2/3
rho = (n - 1) / (2n(n + 1))      = 1/12
```

which is the same double binomial as Eve's with `(1/n, 1/2)` replaced by `(p_s, rho)`.

**`rho` is optimal, not merely compliant, and no measurement strategy beats it.** On a
retained position Bob must guess Charlie's outcome in the declared basis from his own copy.
Let his POVM be `{E_k}` and his declaration `(d_k, w_k)` a function of the outcome; with
`g = P(d = a, w = v)` and `h = P(d = a, w != v)` against the six uniformly drawn eigenstates
`rho_{a,v} = (I + v sigma_a)/2`, the retained mismatch rate is `(1 - (g - h))/2` and

```
g - h = (1/6) sum_k Tr(E_k (rho_{d_k, w_k} - rho_{d_k, -w_k}))
      = (1/6) sum_k Tr(E_k · w_k sigma_{d_k})
      = (1/6) sum_k alpha_k (m_k · n_k)
      <= (1/6) sum_k alpha_k = (1/6) Tr(I) = 1/3
```

writing `E_k = alpha_k (I + m_k·sigma)/2` with `|m_k| <= 1`, and using that a qubit POVM sums
to the identity, whose trace is 2. The octahedron POVM `E_k = rho_k/3` attains the bound,
exactly as well as the compliant strategy and no better. An earlier version of this project
claimed a Breidbart-style intermediate measurement does better and reserved a factor of two in
`s_v` for it; the claim was false, and Section 10 gives what the margin actually buys.

### 6.3 Three numbers, and which is which

This is the place the project has been caught publishing one estimator's figure under
another's name, so all three appear together with the method that produced each.

```bash
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P, ProtocolParams as PP; from sih141.protocol import analysis as A; import math; f='%.4e'; print(f % A.recipient_forgery_probability(P)); print(f % A.recipient_forgery_bound(P, method='kl')); print(f % A.recipient_forgery_bound(P, method='hoeffding')); c=A.binary_kl_divergence(P.s_v,0.5); lam=-math.log(1-(1-math.exp(-c))/3); print('%.4f %.1f %.1f' % (lam, P.key_length*lam, P.key_length*lam/math.log(10))); print(f % A.recipient_forgery_probability(PP(key_length=96)))"
```

| Quantity | Value | What it is |
| --- | --- | --- |
| `recipient_forgery_probability` | `2.1726e-105` | the **exact in-model probability**, not a bound. Costs about 5 seconds |
| `recipient_forgery_bound(method="kl")` | `1.1238e-103` | relative-entropy bound over it, a factor of `51.73` loose |
| `recipient_forgery_bound(method="hoeffding")` | `1.1252e-29` | the **library default**, and 74.0 decades looser than the KL form |
| `lambda`, `L·lambda`, `log10` | `0.1310`, `15089.6`, `6553.3` | Eve's exponent, so her bound is `10^-6553.3` |
| `recipient_forgery_probability` at `L = 96` | `2.9663e-01` | the closed form Section 12 measures against |

The two bounds over the same exact number are decades apart because Hoeffding charges every
summand the variance its range allows, `1/4`, while the actual variance at `rho = 1/12` is
`rho(1 - rho) = 0.076389`, smaller by a factor of `3.27`. Divide the three values above and
the KL bound sits `51.73` times over the exact probability while the Hoeffding one sits
`74.00` decades over the KL bound. Use the relative-entropy form whenever the true rate is
small, which is the whole operating regime of this scheme. Quote whichever you like, but say
which: publishing one under the other's name is a mistake this project has made and had
caught.

---

## 7. Non-repudiation

Alice repudiates when she gets Bob to accept a signature Charlie will reject, since she can
then deny having signed and Bob cannot forward what he holds. The guarantee against that is
the one piece of mathematics in the project that assumes nothing whatever about her.

Fix the two recipients' raw records, whatever she prepared and however asymmetric, adaptive or
entangled, **and fix the declaration**, whatever she computed it from, both raw logs included.
The only randomness left is the recipients' private coins, one per position, each deciding
which verifier scores which of the two records. Because the coins only *split* a fixed
collection, two quantities are coin-independent constants:

```
m_B + m_C = M     total matched records
e_B + e_C = E     total mismatched records
```

Put `s = (s_a + s_v)/2`, `gap = s_v - s_a`, and `W = e_B - s·m_B`. Coin symmetry gives
`E[W] = (E - sM)/2`. Repudiation requires `r_B <= s_a` and `r_C > s_v`, that is

```
e_B - s·m_B <= (s_a - s)·m_B = -(gap/2)·m_B
e_C - s·m_C >  (s_v - s)·m_C = +(gap/2)·m_C
```

and adding, using `(e_C - s·m_C) = (E - sM) - W`, gives `W < E[W] - (gap/4)·M`. Now `W` is a
sum of `L` independent two-point variables, one coin each. A position where neither record is
matched contributes the same value under both coin outcomes, so its range is 0; every other
position has range at most 1, and there are at most `M` of them. Hoeffding therefore gives

```
P(repudiation | records, declaration)  <=  exp(-2((gap/4)M)^2 / M)  =  exp(-M gap^2 / 8)
```

Note what is absent: no tilt parameter, no independence assumption about the two recipients,
no model of Alice, and no (IND). The declaration was fixed before any randomness used here was
drawn, so what it was computed from does not enter. What the bound needs instead is `M`, and
neither verifier knows `M` alone, which is why the recipients exchange one integer each.

**Worst-casing over `M` is legitimate and useless.** `exp(-M gap^2 / 8)` decreases in `M`, and
`M = 0` makes repudiation impossible because Bob has nothing to accept, so the supremum over
everything else is `exp(-gap^2/8) = 0.99973`. That is not slack either: a signer who reads the
recipients' logged bases has an explicit strategy achieving `1/2` at every key length, given in
Section 8. So

> **no unconditional repudiation bound below `1/2` exists without an abort rule, at any `L`
> whatever.**

Key length does not help, because the failure is not statistical. Refusing to score an
anomalously thin matched set does help, and that is Section 9.

---

## 8. Four times we broke it

Adversarial teams ran against this protocol and broke it four times. Every break was real,
reproduced by measurement, and fixed, and the fourth was in our own harness rather than in
the scheme. Each is written up below with the measurement that found it and the rule that closed it.

**These are the one place in this document where a figure has no command.** Each break was
measured against the broken code, and the fix removed that code path, so the numbers below
cannot be regenerated from the tree as it stands. They are quoted from the canonical provenance
blocks in `sih141/protocol/verify.py`, which record the key length and trial count for each,
and the closed forms and post-fix figures in the rest of this section do carry their commands.
A number nobody can re-run is worth less than one they can, and saying which is which is the
only honest way to publish the first kind.

### Break 1: Alice could deny her signature every single time

The first design had Alice distribute to Bob and Charlie independently. She sent Bob states
matching the key she would declare and sent Charlie states that did not, which gives
`r_B = 0.0000` and acceptance against `r_C = 0.4032` and rejection, `40` times out of `40`
over independent seeds at `L = 192`. Non-repudiation, one of the three properties a signature
exists to provide, was absent outright, and no key length repairs it because the failure is
not statistical: she prepares the two copies separately, so she can choose `q_B != q_C` and
break the factorisation any symmetric analysis rests on.

The fix is the recipients' symmetrisation exchange, and afterwards the same adversary gets
`0/20`. Its price was steep and is stated rather than buried: making a *recipient* the binding
adversary instead of an outsider quartered the forger floor from `1/3` to `1/12`, which forced
the key length from `6,912` to `115,200` to hold the same guarantee. That factor of `16.67` is
the product of a smaller usable gap and a factor of two in the exponent's constant, and it is
reproducible rather than remembered. The pre-symmetrisation rule was `exp(-m gap^2/2)` at
`gap = 13/96` over one verifier's own count, which at `L = 6912` returns `6.6916e-10`; the
shipped rule is `exp(-M gap^2/8)` at `gap = 3/64` over the pooled count, and it needs `115371`
positions to return the same figure.

```bash
python -c "import math; g_old=13/96; g_new=3/64; old=lambda L: math.exp(-(L/3)*g_old**2/2); e_old=(1/3)*g_old**2/2; e_new=(2/3)*g_new**2/8; print('%.4e %.4f %.4f %.0f' % (old(6912), e_old/e_new, 115200/6912, -math.log(old(6912))/e_new))"
```

```
6.6916e-10 16.6914 16.6667 115371
```

The shipped `115200` is the round number just under that requirement, which is the whole of why
the exponent ratio reads `16.69` where the key-length ratio reads `16.67`. Neither figure was
carried here from another document; both come out of the block above.

### Break 2: we were advertising a guarantee we did not have

`repudiation_bound()` was documented as valid for every Alice strategy. It was not; it
silently assumed her declared bases are independent of the recipients' logged bases, which is
assumption (IND), and Alice controls exactly that. The published number at production
parameters was `6.9173e-10` against a measured repudiation rate of `0.46` to `0.58`, nine
orders of magnitude of overclaim.

The mathematics was never wrong. Its conditional form returns `0.9964` on the matched count
the attack actually produces, correctly predicting that the attack works; the error was
publishing the averaged number as unconditional. The concrete strategy uses no quantum
resource at all. Alice reads the two raw logs and at every position declares a basis appearing
in *neither*, which with `n = 3` always exists, so that position is matched at neither
verifier however the coin falls. She keeps twelve exceptions: eleven positions where the logs
used different bases, where she declares Bob's basis and Bob's outcome, giving one correct
matched record; and one position where the logs used the same basis and recorded opposite
outcomes, where she declares that basis and Bob's outcome, giving two matched records of which
exactly one is wrong. Then `M = 13` for every `L` with probability 1, and repudiation succeeds
exactly when the single wrong record lands on Charlie, which is a fair coin.

```bash
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol import analysis as A; from sih141.protocol.verify import enforced_repudiation_bound as E; f='%.4e'; print(f % E(P)); print(f % A.repudiation_bound(P, matched_records=76800)); print(f % A.averaged_repudiation_bound(P, signer_sees_recipient_bases=False)); print(f % A.repudiation_bound(P, matched_records=13)); print(f % A.repudiation_bound(P, matched_records=1))"
```

The five lines it prints, in order:

| Statement | At `DEFAULT_PARAMS` | Assumes |
| --- | --- | --- |
| `enforced_repudiation_bound`, what the shipped floors force | `1.4139e-09` | **nothing** |
| `repudiation_bound` at the honest expected `M = 76800` | `6.9040e-10` | nothing, but needs a completed run |
| `averaged_repudiation_bound`, the number that was wrong | `6.9173e-10` | **(IND)**, which a two-log seam gives away |
| `repudiation_bound` at the attack's own `M = 13` | `9.9644e-01` | nothing |
| `repudiation_bound` at `M = 1`, the useless supremum | `9.9973e-01` | nothing |

Set the fourth row beside the measurement and the whole affair resolves, since `0.5 < 0.9964`
means the attack never violated the per-run bound at all. Splitting one function into an
assumption-free per-run form and a gated averaged one is the entire fix, and a real theorem
fell out of it: the one quoted at the end of Section 7.

### Break 3: a subtler version of the same trick

With only per-verifier floors in place, Alice aims the *total* matched count at `2 m_min` and
lets the coins split it evenly, so neither verifier trips its own floor and no mismatch rate
looks anomalous anywhere. Concretely she declares exactly `2 m_min` matched records, all
correct, all on positions where the two raw logs used different bases, so each record goes to
exactly one verifier and the coins decide which; then `m_B ~ Bin(2 m_min, 1/2)` with
`e_B = e_C = 0`, and whenever `m_B > m_min` Bob accepts at rate 0 while Charlie sits below his
floor and returns no verdict. Measured with the per-verifier floor alone: `78/200` at
`L = 360` and `85/200` at `L = 600`.

Not one of those runs was a reject verdict, so the enforced bound was never violated. The
route was always a *no-verdict*, which is exactly why it had to be closed rather than bounded,
and why the abort type is kept distinct from the rejection type everywhere downstream. The
attack also gets *stronger* with `L`, predicted at `0.4985` at production parameters, so the
small-scale demonstration carries upward rather than being a convenient special case. The fix
is the pooled floor plus a joint consequence, both riding on the one classical message the
recipients already exchange, and afterwards both key lengths give `0/200`.

### Break 4: the harness, not the protocol

`QDSSession` passed one generator to the adversary-controlled distribution seam and then drew
the symmetrisation coins from the same object, so an attacker could clone its state and
precompute every coin. That repudiated `5/5` at production parameters with every floor met,
while the transcript cheerfully printed `P(repudiation) <= 1.414e-09`.

This was not a flaw in the bound. Section 7 assumes the coins are private and a real Alice has
no such access. But every attack number this project publishes comes out of that harness, and
those numbers were correct only because our attack code happened not to peek, which is not a
property anyone should rely on. The fix derives two generator streams by labelled SHA-256 from
one seed, an Alice stream and a recipient stream, and never hands the recipient stream to any
Alice-side seam. `SeedSequence.spawn` would not have worked, because numpy leaves the parent's
entropy in each child in clear and a seam holding one child could rebuild the sibling.

---

## 9. The two floors

### 9.1 Where they come from

Both floors invert a multiplicative Chernoff lower tail at a fixed honest-abort budget of
`eps = 2^-64`, and neither is chosen. For one verifier's own count, with `mu = L/n`:

```
|M_R| ~ Binomial(L, 1/n),   mu = L/n
P[|M| <= (1 - delta) mu] <= exp(-delta^2 mu / 2)
delta  = sqrt(2 ln(1/eps) / mu)
m_min  = max(1, ceil((1 - delta) mu))
```

The pooled floor is the same derivation over a different variable, `M ~ Binomial(2L, 1/n)`.
That law deserves a sentence, because the obvious derivation of it is invalid: after the
symmetrisation exchange `m_B` and `m_C` are *not* independent, since given the records
`m_C = M - m_B` with sample correlation `-1`, so convolving the two post-exchange marginals
proves nothing even though it lands on the same answer. What makes the law exact is
**conservation**. The coins re-assign a fixed multiset of `2L` entries whose bases were drawn
i.i.d. uniform, so `M` is a sum of `2L` independent indicators and the coins cannot move it at
all. Both routes were measured: `M` took exactly one value across 120 coin seeds on one fixed
pair of logs while `m_B` took 21, and the empirical law over 20,000 runs sits within `0.0064`
of the exact `Binomial(2L, 1/3)` CDF against a Kolmogorov 95% critical value of `0.0096`.

```bash
python -c "import math; from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol.verify import HONEST_ABORT_BUDGET as e; mu=P.expected_matched; d=math.sqrt(2*math.log(1/e)/mu); dM=math.sqrt(math.log(1/e)/mu); print('%.8f %.4f %d' % (d,(1-d)*mu,math.ceil((1-d)*mu))); print('%.8f %.4f %d' % (dM,(1-dM)*2*mu,math.ceil((1-dM)*2*mu)))"
```

```
0.04806756 36554.2056 36555
0.03398890 74189.6525 74190
```

At the shipped defaults that is `m_min = 36555`, which is `11.53` standard deviations below a
mean of `38400`, and `M_min = 74190` against `E[M] = 76800`.

### 9.2 The margin, which is the whole content of the pooled rule

Break 3 aims at `2 m_min`, the largest total leaving a per-verifier floor satisfiable at both
ends while starving one of them. The pooled floor strictly exceeds it. Writing
`A = sqrt(2 mu ln(1/eps))` and ignoring the two ceilings,

```
m_min = mu - A          M_min = 2 mu - sqrt(2) A
M_min - 2 m_min = (2 - sqrt(2)) A ~ 0.586 A       growing like sqrt(L)
```

```bash
python -c "import math; from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol.verify import HONEST_ABORT_BUDGET as e, minimum_matched_count as m, minimum_pooled_matched_count as M; A=math.sqrt(2*P.expected_matched*math.log(1/e)); print(M(P)-2*m(P), '%.4f' % ((2-math.sqrt(2))*A))"
```

```
1080 1081.2413
```

The shipped margin is `1080` records against the ceiling-free `1081.24`, and it is positive at
every key length where either floor bites. Because it *grows*, the closure is not an artefact
of a short demonstration key. A pooled floor on its own would still leave Alice re-aiming at
`M = M_min` and needing only the coins to leave Charlie under his own floor, a deviation of
`(1 - sqrt(2)/2) A` out of about `2 mu` fair coins, whose bound `eps^(3 - 2 sqrt 2) = 4.9e-04`
is *independent of `L`* because deviation and noise both grow like `sqrt(L)`. No key length and
no choice of floors inside the budget closes that. What closes it is making the per-verifier
floor's *consequence* joint: a verifier below his own floor takes the other down with him, so
"Bob accepts" implies "Charlie reached a verdict", the asymmetric outcome leaves the outcome
space, and the two branches Section 7 already bounds exhaust the failure space.

### 9.3 What the floors buy, what they cost, and where they switch on

Each rung of the abort rule is a floor on `M`, and a floor on `M` is a number, since Section
7's bound is `exp(-M gap^2 / 8)` and any run that reaches a verdict at all has
`M >= max(2 m_min, M_min)`:

```bash
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol import analysis as A; from sih141.protocol.verify import minimum_matched_count as m, minimum_pooled_matched_count as M; a=A.matched_shortfall_probability(P, minimum_matched=m(P)); b=A.matched_shortfall_probability(P, minimum_matched=M(P), pooled=True); B=A.repudiation_bound_with_abort; f='%d %.4e %.4e'; print(f % (m(P), B(P, minimum_matched_records=m(P)), a)); print(f % (2*m(P), B(P, minimum_matched_records=2*m(P)), 2*a)); print(f % (M(P), B(P, minimum_matched_records=M(P)), 2*a+b))"
```

```
36555 4.3614e-05 2.5476e-31
73110 1.9022e-09 5.0952e-31
74190 1.4139e-09 8.0154e-31
```

| Rule | Floor on `M` | Unconditional bound | Honest-run cost |
| --- | --- | --- | --- |
| Bob's own floor alone, which he checks without asking anyone | `36555` | `4.3614e-05` | `2.5476e-31` |
| both verifiers cleared their own | `73110` | `1.9022e-09` | `5.0952e-31` |
| **the pooled floor as well, which is what ships** | **`74190`** | **`1.4139e-09`** | `8.0154e-31` |

The bottom row is what `enforced_repudiation_bound` returns and the only a-priori repudiation
figure this package publishes. It is 2.0440 times the figure that used to be
published as unconditional, and this time it actually is unconditional, resting on rules the
code enforces rather than on an assumption about what Alice can see. Three checks cost
`8.0154e-31` per honest run between them, `21.25` orders of magnitude below that bound, so the
abort rule can never become the dominant reason an honest run fails.

The floors switch on late, and the exact crossovers matter more than they look, because a
demonstration run below them carries no security claim at all and must say so:

```bash
python -c "from sih141.protocol.params import ProtocolParams as PP; from sih141.protocol.verify import minimum_matched_count as m, minimum_pooled_matched_count as M; print(min(L for L in range(1,400) if M(PP(key_length=L))>1), min(L for L in range(1,400) if m(PP(key_length=L))>1))"
python -c "from sih141.protocol.params import ProtocolParams as PP; from sih141.protocol.verify import minimum_pooled_matched_count as M; r=[(L,PP(key_length=L,check_fraction=0.25).sifted().key_length) for L in range(8,400)]; print(next((L,n) for L,n in r if M(PP(key_length=n))>1))"
```

```
137 273
(182, 137)
```

**`137` sifted positions is the crossover**, the first key length at which the pooled floor
exceeds `1` and so refuses something the standing empty-set rule would not have refused
anyway. It is not `140`, which is merely where the floor steps from 2 to 3, and the
distinction has been got wrong here before. The per-verifier
floor does not bite until `273`. With a quarter of positions spent on check rounds the nominal
length that first carries a claim is `182`, whose signing length is `137`; every null in this
project is stated over the *sifted* count, and a null stated over the nominal one would claim
a third more evidence than the run has, in a scheme where every bound is exponential in that
count. `DEMO_PARAMS` at `L = 192` sits between the two crossovers and is protected by the
pooled floor alone, at `M_min = 22` where the per-verifier floor is still `1`. It publishes
`enforced_repudiation_bound = 0.9940` and carries no security claim, which its own docstring
says.

---

## 10. Why `s_a < s_v`

Two one-line implications, and the gap between them is the mechanism that makes this a
signature rather than a shared password:

```
s_v > s_a  =>  a signature Bob accepts is overwhelmingly likely to clear Charlie   TRANSFERABILITY
s_a > 0    =>  Alice cannot craft one that squeaks past Bob but fails Charlie      NON-REPUDIATION
```

Transferability is immediate from the decision rule, since Bob's acceptance region is
contained in Charlie's, so on a clean channel where both rates are exactly 0 there is no rate
at which Bob accepts and Charlie does not. Non-repudiation is Section 7, exponential in
`gap^2`, so halving the gap costs a factor of four in key length.

What bounds `s_v` above is the recipient forger's floor of `1/12` from Section 6.2, not the
crude `1/2`, and `ProtocolParams.__post_init__` refuses an `s_v` at or above it unless
`allow_forgeable=True` is passed. That is a field rather than a flag, so it reaches every
transcript the run produces and an intentional sweep past the floor can never be mistaken for
a mistyped config. The shipped `s_v = 1/16` is three quarters of the floor:

```bash
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.protocol import analysis as A; print('%.9f' % (P.gap**2/8), '%.6f' % A.binary_kl_divergence(P.s_v,P.forger_floor), '%.4f' % A.binary_kl_divergence(P.s_v,0.5), '%.6f' % A._kl_repudiation_exponent(P.s_a,P.s_v))"
```

```
0.000274658 0.003088 0.4594 0.015630
```

`D(s_v || 1/12) = 0.003088` nats is what sizes `s_v`, and `gap^2/8 = 0.000274658` per matched
record is what sizes the key. The full ladder, one rung either side of the shipped point on
both knobs, is a committed table: [`docs/tables/repudiation-curve.md`](tables/repudiation-curve.md),
under *What the `s_a` / `s_v` gap buys and what it costs*, regenerated with
`python tools/sweep.py reduce repudiation-curve`. Its shape is worth reading before anyone
proposes widening the gap. Moving `s_v` one rung up to `0.078125` spends `96.91` decades of
forgery security (KL estimator, `1.124e-103` to `9.165e-07`) to buy `6.88` decades of repudiation
(`1.414e-09` to `1.851e-16`), and every way of widening the gap from the other end instead
shrinks the link noise an honest signature survives, which is `2 s_a`. That second figure reads
*eight* in the table's own generated footnote; recomputed from the two rows the footnote is
describing it is `6.88`, and the recomputed value is the one that stands here.

The in-model exponent kept as a yardstick, `min_q [D(s_a||q) + D(s_v||q)] = 0.015630` per
matched *position*, is about 28 times `gap^2/8` per matched *record* once the two counts are
put on the same footing. That ratio is the price of a statement that is true rather than
merely tight, and it is paid in key length.

---

## 11. The five inequalities

Every bound in the project traces to one of these, and the point of listing them together is
that each was chosen for a stated reason rather than reached for by habit.

| Inequality | Where it does the work | Why that one |
| --- | --- | --- |
| **Hoeffding** | the per-run repudiation bound (Section 7), over the recipients' coins | The summands are two-point variables of known range and unknown law. Nothing else is available, since the records were fixed by an adversary before the coins were drawn |
| **Multiplicative Chernoff, lower tail** | both matched-count floors (Section 9) | The statistic is a binomial count and the event is a shortfall. It is the loosest of three valid choices here, which Phase 4 raised as finding F1 and the command below reproduces: in critical counts at the same budget, the protocol's floor fires at `36554` where the exact binomial tail still certifies `36951`, and pooled at `74189` against `74749`. A looser floor is safe, it aborts honest runs less often, and every published bound stands; raising it would reach the margin argument of Section 9.2, so it is a protocol change with a security argument attached rather than a tightening |
| **Exact binomial tails** | the double-binomial forgery probabilities of Section 6, the honest-abort costs, and every rate threshold in the detector | Where the null really is binomial and the sum is affordable, no inequality is needed at all. These are the numbers labelled *exact*, and they are what the bounds are checked against |
| **Relative entropy (KL)** | the sharp form of both forgery bounds | Hoeffding charges the variance the range allows rather than the variance the null has. At `rho = 1/12` that costs `74.00` decades, which Section 6.3 shows side by side |
| **McDiarmid, bounded differences** | the CHSH threshold on a check-round sample | The statistic is a sum of four correlator estimates, not a single binomial count. McDiarmid asks for independence and not identical distribution, so the bound survives an honest channel that drifts. It costs `9.10` standard deviations at `eps = 1e-9` where a normal quantile asks `6.00`, a factor of `1.52` for a bound that holds at every sample size rather than asymptotically |

```bash
python -c "from sih141.protocol.params import DEFAULT_PARAMS as P; from sih141.detect.thresholds_rate import floor_comparison; print(floor_comparison(P))"
python -c "import math; from scipy.stats import norm; print('%.2f %.2f %.2f' % (2*math.sqrt(math.log(1e9)), norm.isf(1e-9), 2*math.sqrt(math.log(1e9))/norm.isf(1e-9)))"
```

```
{'signing_length': 115200, 'protocol_matched': 36554, 'protocol_pooled': 74189, 'exact_matched': 36951, 'exact_pooled': 74749, 'hoeffding_matched': 36801, 'hoeffding_pooled': 74539, 'chernoff_matched': 36554, 'chernoff_pooled': 74189}
9.10 6.00 1.52
```

A critical count is one below the floor it belongs to, so `protocol_matched = 36554` is the
same rule as `m_min = 36555` in Section 9 read in the other direction. That is worth saying
because the off-by-one between the two vocabularies is precisely the kind of thing that turns
a correct number into a wrong sentence.

Interval estimates are separate from all of the above and use **Wilson** score intervals
throughout, at 99% in the results tables. Almost every defended result in this project is `0`
successes out of `N`, where the normal interval degenerates to a point and would claim
certainty from a finite experiment:

```bash
python -c "from sih141.attacks.impersonation import wilson_interval as w; print([ (k, round(w(k,400,confidence=0.99).low,4), round(w(k,400,confidence=0.99).high,4)) for k in (0,120,400) ])"
```

```
[(0, 0.0, 0.0163), (120, 0.2446, 0.3619), (400, 0.9837, 1.0)]
```

The CHSH threshold carries **(AUTH)** as a second assumption and is easy to drop: it is not
device-independent, and it certifies only under the hypothesis that both endpoints measured at
the announced settings. A test fails if that sentence leaves its docstring.

---

## 12. Where the model runs out

Four things this document cannot claim, stated here rather than left for a reader to find.

**The proof and the measurement do not reach each other, and the honest claim lives where
neither goes.** At `L = 768` with 400 trials the measurement is `0/400`, whose 99% Wilson
upper limit is `0.0163`; the exact in-model probability for that adversary at its own tilt
`q = 0.041` is `5.845e-04`, a factor of `27.9` below what the sample can resolve; and the
proven bound is `0.9212`, a further factor of `56.5` above the measurement's limit. The region
the real claim lives in, `1.4139e-09` at `L = 115200`, is out of range for both. A measured
zero at demonstration scale
is evidence the mechanism works and is never confirmation of the bound, and the row is
committed with the rest of its curve in
[`docs/tables/repudiation-curve.md`](tables/repudiation-curve.md), regenerated with
`python tools/sweep.py run repudiation-curve --workers 20`. What closing either gap would cost,
in trials and in machine-years, is priced in [`SECURITY.md`](SECURITY.md) §7, which owns this
limitation.

**Full impersonation succeeds with probability 1** if the channel from Alice is not
authenticated. That is assumption (AUTH) of Section 5, it is inherent to this family of
schemes, and it appears in every results table as `undetectable-by-construction` rather than as
a blank or a miss, because a hypothesis silently missing from a table reads as one that was
ruled out.

**One ordering decision changes what an attack even is.** The recipients' count exchange can
happen before or after Bob forwards, and the identical recipient forgery at `L = 96` over 400
runs gives `0/400` accepted under the before-forwarding ordering, where Bob accepts and
Charlie alone reaches no verdict
and the attack is a denial of transfer, against `120/400 = 0.3000 [0.2446, 0.3619]` under
after-forwarding, where Charlie scores it and the closed form of Section 6.3 says `0.29663`.
Pooling the two publishes `15%` and describes neither. Both rows are in
[`docs/tables/forgery-curve.md`](tables/forgery-curve.md), regenerated with
`python tools/sweep.py run forgery-curve --workers 20`; grouping by the ordering and never
averaging over it is a standing constraint, and `Detection.grouping_key` exists so it cannot
be done by accident. All five key lengths, with the refusal column that makes the two readings
of a `0/400` visible, are [`ATTACKS.md`](ATTACKS.md) §1.

**A recipient can force aborts** by under-reporting his matched count, which is availability
rather than integrity: under-reporting can only withhold an acceptance, never manufacture one,
since every acceptance still needs the accepting verifier's own rate to clear his own
threshold on his own log. It is a real fifth attack surface, free and deterministic, and it is
loud. Wherever both floors are live, the quietest declaration that still denies sits below
`-sqrt(3 ln(1/eps)) = -11.5362` standard deviations and approaches that limit from underneath as
`L` grows: `-11.6047` at `L = 600`, `-11.5375` at the production parameters ([PHASE3](PHASE3.md)
§6). `L = 192` reads `-9.798` instead, for the same reason it carries no security claim. Nothing
defends against the denial itself, any more than a threshold defends against Alice declining to
sign, and the surface is priced in [`ATTACKS.md`](ATTACKS.md) §5.

---

## References

1. D. Gottesman and I. Chuang, *Quantum Digital Signatures*, arXiv:quant-ph/0105032 (2001).
2. V. Dunjko, P. Wallden and E. Andersson, *Quantum Digital Signatures without Quantum
   Memory*, Phys. Rev. Lett. **112**, 040502 (2014).
3. R. Amiri, P. Wallden, A. Kent and E. Andersson, *Secure Quantum Signatures Using Insecure
   Quantum Channels*, Phys. Rev. A **93**, 032325 (2016).

*Derivations in full, with the seams and the measurement harness, are in
[`docs/PHASE2.md`](PHASE2.md) and [`docs/PHASE4.md`](PHASE4.md).*
