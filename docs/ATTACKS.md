# The attack record

Every adversary this project has run against its own protocol, with what each one was allowed to
know, where it attaches, what stops it, and what it measured. Five adversaries are measured:
outside forgery, recipient forgery, replay, channel manipulation and count starvation.
Impersonation is a sixth entry of a different kind, because one of its scopes is excluded by a
stated assumption rather than defeated by a mechanism, and this document never lets an exclusion
sit in a table looking like a defence.

No number below was written by hand. Each one comes from a committed table under
[`tables/`](tables), a doctest inside the package that `pytest` runs on every commit, a named test
in `tests/`, or a closed form evaluated from the parameter set, and the source is printed beside
it. That rule is **D9**, and §9 collects the commands into one table.

Two sibling documents complete the submission. The closed forms and bounds quoted here are derived
in [`MODELLING.md`](MODELLING.md), which owns the mathematics; what the whole record adds up to as
a set of security claims, with the assumptions each one rests on, is [`SECURITY.md`](SECURITY.md).

## Two distinctions that decide how to read every table

**An abort is not a rejection.** A verifier who reaches no verdict has not detected anything. He
has declined to judge on evidence he considers too thin, which is a refusal to transfer the
signature, and folding it into a rejection rate would publish a detection that never occurred.
Aborts are a separate transcript field with a separate type; every rate here prints its
denominator as `k/n`, and refusals get their own column and are added to neither side. The
distinction is load-bearing rather than pedantic: §1 is an attack that produces 400 refusals under
one configuration and 120 acceptances under another, and a reader who treats those refusals as
catches has the protocol exactly backwards.

**An exclusion is not a result.** Full impersonation succeeds with probability 1 against a channel
that is not authenticated, and the protocol contains nothing that would stop it. It is ruled out
by assumption **(AUTH)**, so it reads `undetectable-by-construction` wherever it appears, never as
a zero and never as a blank. §6 is the whole of that argument.

---

## 1. The strongest result: one integer's ordering decides what the attack is

Start here, because it is the sharpest thing this project measured and because it is the easiest
result in the whole record to destroy by paraphrasing it.

Phase C′ of the protocol has Bob and Charlie exchange a single number each: how many positions of
the declared key each of them can actually score. Either verifier holding suspiciously little
evidence makes both refuse rather than guess. That exchange has to happen at some point relative
to Bob's forwarding hop, and `count_exchange_timing` names the two choices:

| setting | who counts what | what it models |
| --- | --- | --- |
| `COUNTS_BEFORE_FORWARDING` (shipped) | both count the declaration Alice signed | the adversary owns the declaration channel and not the count channel |
| `COUNTS_AFTER_FORWARDING` | both count the declaration that reached Charlie | the adversary owns both, which in a deployment is one link |

Now run the binding forgery adversary against each. `RecipientForger` sits on the `forwarder`
seam: Bob accepts Alice's declaration honestly, then forwards his own measured log to Charlie as
if it were Alice's key. That is his optimal move and it is deterministic (§2.2). Same class, same
`__call__`, same code path, one configuration flag different. And the flag is not quietly a second
protocol: on an honest run the two orderings agree position for position, same records, same
verdicts, same pooled count, same spent rounds, which is asserted rather than assumed, because an
ordering that changed an honest run would be changing the protocol instead of naming an
experiment.

| `L` | ordering | engaged | Charlie accepted (**measured**, 99% Wilson) | rejected | **no verdict** | exact `P` (closed form) |
| --- | --- | --- | --- | --- | --- | --- |
| 96 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `2.9663e-01` |
| 96 | after | 400 | `120/400 = 0.3000 [0.2446, 0.3619]` | 280 | 0 | `2.9663e-01` |
| 192 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `2.0459e-01` |
| 192 | after | 400 | `63/400 = 0.1575 [0.1162, 0.2100]` | 337 | 0 | `2.0459e-01` |
| 384 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `1.1260e-01` |
| 384 | after | 400 | `49/400 = 0.1225 [0.0863, 0.1710]` | 351 | 0 | `1.1260e-01` |
| 768 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `4.0360e-02` |
| 768 | after | 400 | `11/400 = 0.0275 [0.0129, 0.0575]` | 389 | 0 | `4.0360e-02` |
| 1200 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `1.4002e-02` |
| 1200 | after | 400 | `6/400 = 0.0150 [0.0055, 0.0403]` | 394 | 0 | `1.4002e-02` |

> Source: [`tables/forgery-curve.md`](tables/forgery-curve.md).
> Regenerate: `python tools/sweep.py reduce forgery-curve`

**Before forwarding, the attack is a denial of transfer.** Charlie's own matched count was taken
against the declaration Alice signed while he is looking at the one Bob delivered, so the count he
holds names a different declaration from the one in front of him. He refuses on provenance, and he
refuses on all 400 runs at every length. Bob, meanwhile, accepted; Bob is the adversary. The
signature stops there and reaches nobody.

**After forwarding, the same attack is a forgery that lands.** Charlie returns a real verdict on
all 400 runs and accepts 120 of them at `L = 96`, a rate of `0.3000` against a closed form of
`0.29663`. All five `after` rows have the closed form inside the measured 99% interval.

Pooling the two orderings at `L = 96` publishes `120/800 = 15%`, and 15% describes neither run.
That is why `count_exchange_timing` is part of the grouping key of every table in the evaluation
and is never averaged over, and why **any sentence of the form "the recipient forgery rate is X"
is wrong unless it names the ordering.**

The closed form describes the `after` rows and not the `before` ones, and the table shows that
too. `recipient_forgery_probability` is the probability that Charlie *accepts*, which presupposes
he reaches a verdict at all; four of the five `before` rows have it outside their interval, which
is the model correctly declining to describe an experiment it is not about. The fifth, `L = 1200`,
falls inside only because `1.4002e-02` has already dropped below the `0.0163` that 400 trials can
resolve, so its agreement is arithmetic about the sample size and not a validation.

One more thing about those zeros, because §7 is about exactly this failure mode. The `before` rows
report `0/400` acceptances by an adversary that certainly acted: read off the forger's own log,
`bob96before` substituted 51 to 80 positions per run and `bob1200before` 758 to 847, on every one
of the 400 runs of each. A zero from an arm that never fired would look identical in the
acceptance column and mean nothing.

---

## 2. Forgery

Two forgers, because the threat model contains two and they are not the same adversary. Eve holds
nothing. Bob holds half the evidence Charlie will score against, which makes him the binding case
and the one a security claim has to quote.

### 2.1 The outside forger, on the `signer` seam

**What she assumes.** Nothing beyond the ability to substitute a declaration in transit. She
ignores Alice's keys and any recipient logs the seam offers her, which is pinned by a test: same
generator, different Alice keys, identical declaration out.

**Where she attaches.** The `signer` seam rather than the forwarding hop, deliberately. Her
declaration then reaches both verifiers, so one batch of runs measures her against `s_a` and `s_v`
at once, and unlike a recipient she is neither verifier, so nothing self-verifies.

**What stops her.** The Born rule. A declared eigenvalue she did not measure agrees with a
recipient's record on a matched position with probability exactly `1/2`, against a threshold of
`1/64` at Bob and `1/16` at Charlie, so her acceptance probability falls exponentially in the
matched count.

**What it measured.** Ladder at `check_fraction = 0`, 400 trials per rung, denominator `engaged`:

| `L` | Charlie accepted (**measured**, 99% Wilson) | rejected | no verdict | Bob accepted (**measured**) | exact `P` | **proven** (KL) |
| --- | --- | --- | --- | --- | --- | --- |
| 9 | `61/400 = 0.1525 [0.1119, 0.2044]` | 318 | 21 | `66/400 = 0.1650 [0.1227, 0.2182]` | `1.6779e-01` | `3.076e-01` |
| 15 | `26/400 = 0.0650 [0.0398, 0.1044]` | 372 | 2 | `22/400 = 0.0550 [0.0322, 0.0923]` | `6.2622e-02` | `1.402e-01` |
| 24 | `4/400 = 0.0100 [0.0030, 0.0330]` | 396 | 0 | `8/400 = 0.0200 [0.0083, 0.0474]` | `1.2520e-02` | `4.312e-02` |
| 30 | `1/400 = 0.0025 [0.0003, 0.0209]` | 399 | 0 | `2/400 = 0.0050 [0.0010, 0.0252]` | `4.2111e-03` | `1.965e-02` |
| 24 *(after-forwarding)* | `2/400 = 0.0050 [0.0010, 0.0252]` | 398 | 0 | `8/400 = 0.0200 [0.0083, 0.0474]` | `1.2520e-02` | `4.312e-02` |

> Source: [`tables/forgery-curve.md`](tables/forgery-curve.md).
> Regenerate: `python tools/sweep.py reduce forgery-curve`

The 21 no-verdicts at `L = 9` are honest aborts on an empty matched set, and they sit in the
refusal column where they belong; the acceptance denominator is unaffected because `engaged`
counts all 400 runs.

Her ladder stops at `L = 30` and the reason is worth stating, because a longer ladder would look
more impressive and would be worthless. At `L = 30`, 400 trials expect `400 × 4.2111e-03 = 1.7`
acceptances. At `L = 48` they expect `0.09`, and at `L = 96`, `0.0002`. A rung past 30 reports
`0/400` whatever the truth is, so it tests the sample size rather than the protocol. The
measurement anchors the closed form where a measurement is possible at all, and the closed form
carries the curve from there to `1.12e-12` at `L = 192` and beyond.

The rate that actually carries to full scale is not acceptance. It is the per-position mismatch
rate, which follows from the Born rule and a uniform basis draw and never mentions `L`. Measured
at `L = 30` over 800 sessions, pooled over positions rather than averaged over runs:

| quantity | Bob | Charlie | predicted |
| --- | --- | --- | --- |
| mismatch, per scored position | `3924/7917 = 0.4956 [0.4846, 0.5067]` | `3998/7967 = 0.5018 [0.4908, 0.5128]` | `1/2` |
| scored fraction | `7917/24000 = 0.3299` | `7967/24000 = 0.3320` | `1/3` |

> Source: [`PHASE3.md`](PHASE3.md) §2a, reproduced by
> `python -m pytest tests/test_phase3_integration.py`

That `1/2` is the exact assumption `forgery_probability` is built on, estimated over roughly 8000
positions per verifier. Acceptance at a demo length is a handful of successes; the mismatch rate
is where the evidence is.

### 2.2 The forging recipient, on the `forwarder` seam

**What he assumes.** He is Bob. He has accepted Alice's declaration, so he holds a full record of
his own measurements and knows Alice's declared bases and eigenvalues. He controls what reaches
Charlie.

**Where he attaches.** The hop between the two verifiers. He forwards `key_from_record` of his own
raw log, which strictly dominates every randomised alternative: a position the symmetrisation
exchange swapped to him matches with certainty, a retained one gives `P(match | scored) = 2/3`
against `1/2` for anything else, and flipping an eigenvalue is strictly worse.

**What stops him.** Charlie's threshold, and under the shipped ordering he never even reaches it.
His per-position mismatch rate is `1/12 = 0.0833` against Charlie's cut of `1/16 = 0.0625`, so
acceptance needs a downward fluctuation and its probability decays exponentially in Charlie's
matched count. The exact in-model probability is `4.0360e-02` at `L = 768` and `2.1726e-105` at
production parameters, where the KL bound over it is `1.1238e-103`; §8 says why the estimator has
to be named every time. Before any of that arithmetic is reached, the provenance half of the count
exchange refuses him outright (§1).

**What it measured.** The acceptance ladder is §1. The per-position statistics, at `L = 60` over
300 sessions under the deployment ordering:

| quantity | measured | 95% interval | predicted | `z` |
| --- | --- | --- | --- | --- |
| acceptance at Charlie | `96/300 = 0.3200` | `[0.2698, 0.3748]` | `0.345566` | `−0.93` |
| mismatch per scored position | `1026/11887 = 0.0863` | `[0.0814, 0.0915]` | `1/12 = 0.08333` | `+1.18` |
| scored fraction | `11887/18000 = 0.6604` | `[0.6534, 0.6673]` | `2/3` | `−1.79` |
| mismatch, **symmetrisation removed** | `810/2398 = 0.3378` | `[0.3191, 0.3570]` | `1/3` | `+0.46` |

> Source: [`PHASE3.md`](PHASE3.md) §2b, reproduced by
> `python -m pytest tests/test_phase3_integration.py`

**The last row runs the other way from what a reader expects, and it is worth slowing down for.**
Symmetrisation is not a defence against this adversary. It is what makes him the binding one
instead of an outsider. Without Phase A′
his mismatch rate is `1/3`, which already beats the outsider's `1/2` at the same scored fraction
(at `L = 192`, `3.17e-07` against her `1.12e-12`); with it, half of Charlie's
log is literally Bob's own record, so a swapped position matches with certainty, his scored
fraction rises from `1/3` to `2/3` and his mismatch floor drops to `1/12`. Same adversary, same
code path, one seam swapped, and the floor moves by a factor of four with the two 95% intervals
nowhere near touching.

Phase A′ exists for non-repudiation: it is what stops Alice aiming a declaration at one verifier,
because she cannot know who ends up holding what. The bill arrives as unforgeability against a
recipient, and it is what forces the production key length from 6,912 to 115,200 to hold the same
guarantee. That trade is the honest answer to a judge asking why the symmetrisation step is there,
and the two mismatch rows above are its price tag rather than its endorsement.

The scored fraction is the other thing to notice. A forging recipient matches `2/3` of the key
where an honest run matches `1/3`, and no channel attack can move a matched count, which depends
only on basis draws. So the pair `(matched fraction, rate)` tells the three
apart: `(2/3, 1/12)` is a forging recipient, `(1/3, 1/2)` an outside substitution, `(1/3, ~0)` a
noisy wire.

---

## 3. Replay

Four flavours. Three of them close cleanly, and the fourth turns out not to be closed by the
mechanism everyone assumed was closing it.

**What the adversary assumes.** He has seen a `(message, signature)` pair go past, or he sits on
the hop and can mint declarations of his own. Phase B publishes the round's opening on the
declaration, so anyone downstream of that reveal knows the live round identifier.

**Where it attaches.** The `forwarder` seam, plus direct drives of `verify_or_abort` for the
cross-round cases, which the seam cannot express (§3.3).

**What stops it.** Two independent pieces, each inert unless the caller supplies the state it
reads. The *round binding* stamps every record with the distribution round it came from and every
declaration with the round whose opening it reveals; the record is the anchor, so the comparison
is driven by the side an adversary cannot reach, and a verifier whose record names no round scores
as before. The *consumed-records ledger* is one `ConsumedRecords` per verifier keyed on
`(session_id, message_bit)`, spent only when a verdict is actually reached, held by the verifier
and never a module-level default. Bob's refuses a record belonging to anyone else and offers no
way to read Charlie's.

| attack | undefended | defended | mechanism |
| --- | --- | --- | --- |
| (a) straight re-verification | `100/100` accepted | `0/100`, `RECORD_ALREADY_VERIFIED` | the ledger |
| (b) cross-session pairing | `46/400 = 0.115 [0.0873, 0.1500]` at `L = 12` against `forgery_probability = 0.10445`, `z = +0.69` | `0/100`, `SESSION_MISMATCH` | the round binding |
| (c) burn a verifier's round | n/a | see §3.1 | **not the ledger** |
| (d) two rounds, one identifier | `14/1000 = 0.014` against `0.01252` | signer loses her own second round, `400/400` | the ledger keys on `(session_id, message_bit)` |

> Source: [`PHASE3.md`](PHASE3.md) §5, reproduced by
> `python -m pytest tests/test_phase3_integration.py tests/test_attack_replay.py`

Row (a) is asserted as counts and never compared against a probability, because the scoring rule
is a pure function of the declaration and the record: it cannot tell a second call from a first,
and the ledger that can is a rule with no sampling distribution behind it. Row (b) is the more
interesting one. Undefended, a cross-round pairing *is* exactly an outside forgery, and it measures
as one; the identifier does not make forging harder, it makes the pairing refuse to be scored.
`L = 12` was chosen so the prediction is `0.104` rather than `0.013`, which is a sharp comparison
in four hundred trials instead of a few thousand.

### 3.1 The denial of service that was priced at zero

`verify.py` used to reason: entries are spent only on a verdict, a refusal spends nothing,
therefore no outsider can poison a ledger, therefore the only party who can burn a round on a
declaration that will be rejected is the signer, who could simply decline to sign instead. The
first half is true and measured (`0/400` over three routes; 50 wrong-round presentations left the
ledger empty). **The inference is false.**

The identifier deliberately does not cover the declared key, because if it did, every forgery
would abort as `SESSION_MISMATCH` and the whole of §2 would empty into the no-verdict column. So
anyone downstream of Phase B can mint a *different* declaration naming the *same* round. The
Bob-to-Charlie hop is exactly where the threat model puts an adversary and is not covered by the
classical-authentication assumption. He hands Charlie a forged declaration carrying the correct
round name; Charlie scores it, rejects it, and a rejection is a verdict, so the round is spent.
Alice's genuine declaration is refused as `RECORD_ALREADY_VERIFIED` from then on. Measured
`300/300` at `L = 24` and `100/100` at `L = 96`.

What closes it is the provenance half of the count exchange, under one ordering only:

| Phase C′ configuration | round burned |
| --- | --- |
| `no_count_exchange` | 300/300 |
| counts taken as received (`COUNTS_AFTER_FORWARDING`) | 300/300 |
| counts taken as signed (`COUNTS_BEFORE_FORWARDING`, shipped) | **0/300** |

So §1's ordering is not only the difference between a denial and a forgery. It is also the
difference between a burnable round and a round nobody downstream can spend.

**What counts as a burned round**, because the audit found the looser reading and it mattered.
Success is the honest declaration being refused as `RECORD_ALREADY_VERIFIED`, the mechanism itself,
and not "the honest declaration was not accepted". The two agree on every healthy trial and come
apart on a degenerate one: below the `L = 137` crossover both matched-count floors read 1, a run
aborts only on an empty matched set, and at `L = 12` an honest run manages that by itself. Three
trials in a hundred and twenty end `empty-matched-set` with no ledger present, so under the loose
reading the *undefended* arm, where the attack provably achieves nothing that lasts, would have
reported `3/120`. Every figure above was re-measured under the strict definition and none of them
moved; what changed is that they are now rules rather than facts about a kind seed. A trial in
which the attack was not measured at all is refused outright rather than scored either way.

**Honest pricing.** The residual surface is one burned round per verifier per presentation channel
the adversary controls, and it closes only when every such channel is authenticated or the count
exchange runs ahead of the hop. Two repairs suggest themselves and both are worse. Spending a
ledger entry only on an acceptance gives an adaptive adversary unlimited tries at one round
(present, read the rejection, edit one position, present again), which converts a bounded forgery
probability into a search. Keying the ledger on the declaration as well as the round is the same
thing said more directly. One shot per round is the property worth keeping; where that shot gets
taken is what authentication buys.

### 3.2 What could not be broken

Poisoning a ledger from outside, `0/400` over three routes. One verifier writing the other's
ledger, refused with a reason. Forging a round identifier, `0/500000` preimage attempts against
the length-prefixed encoding, which bounds the per-attempt rate at `7.7e-06` at 95% and is all a
bounded search can say against `2**−128 = 2.9e-39`. And a signer giving two rounds one identifier,
which buys her exactly the outside forger's rate while costing her the second round outright.

### 3.3 One thing the seams cannot express

`QDSSession._bind_to_round()` overwrites the `session_opening` of whatever the `Signer` or
`Forwarder` seam returns with the live round's opening, so a stale declaration pushed through the
forwarder reaches Charlie carrying the live identifier and is scored as a forgery rather than
refused as a replay. That is deliberate, for the reason in §3.1, but it means the cross-round
measurements drive `verify_or_abort` directly, and anyone reading a `ReplayingForwarder`
transcript will see an altered forwarding and not a replay. Pinned by
`test_session_relabels_a_stale_declaration_as_fresh`.

---

## 4. Channel manipulation

**What the adversary assumes.** Access to one of the two lines the protocol runs over: the
entanglement line (`resource_factory`, where the Bell pairs come from) or the payload line
(`payload_map`, the state being teleported). Three attacks, each mountable on either line by a
bound method, each taking a `target` party, so a party-targeted attack is a parameter rather than
a fourth class.

**What catches it**, since nothing here prevents an attack on a wire. Check rounds. The recipients
reserve a fraction of positions, drawn from their own generator so the signer cannot know which,
and spend them measuring the link instead of carrying key. Two arms: QBER, where both halves are
measured in the same basis, and CHSH, where they are measured at independently drawn Bell-test
settings.

**One identity predicts all of it.** Every resource here is Bell-diagonal or a collapse of one, so
with the correlation tensor `T = (T_xx, T_yy, T_zz)`:

```
S    = sqrt(2) * (T_zz + T_xx)          the shipped CHSH settings lie in the x-z plane
QBER = mean_b (1 - s_b * T_bb) / 2,     s = (+1, -1, +1)
```

`chsh_from_tensor` and `qber_from_tensor` are those two lines. The QBER identity is pinned against
the protocol's own `analysis.depolarising_error_rate` to `1e-12` across `p`, and the CHSH identity
against `checkrounds.depolarising_chsh`, so the attack's prediction and the protocol's cannot drift
apart.

### 4.1 What the campaigns measured

Standalone campaigns, 8000 rounds each, 95% Wilson:

| resource | measured QBER | 95% interval | predicted |
| --- | --- | --- | --- |
| depolarising, `p = 0.2` | `795/8000 = 0.0994` | `[0.0930, 0.1061]` | `p/2 = 0.1000` |
| intercept-resend | `2645/8000 = 0.3306` | `[0.3204, 0.3410]` | `1/3` |
| kept GHZ share | `2668/8000 = 0.3335` | `[0.3233, 0.3439]` | `1/3` |

CHSH separates what QBER cannot:

| channel condition | `S` | how it is obtained |
| --- | --- | --- |
| ideal entanglement | `2.8284` | `2√2`, Tsirelson |
| depolarising, `p = 0.3` | `1.9799` | `(1−p)·2√2` |
| kept GHZ share, `Z` axis | `1.4142` | `√2`, measured 99% interval `[1.3202, 1.5198]` |
| intercept-resend | `0.9428` | collapse in a uniformly drawn axis |
| **classical bound** | `2.0000` | **`CLASSICAL_CHSH_BOUND`, what a separable resource may not exceed** |

> Source: [`PHASE3.md`](PHASE3.md) §4, reproduced by
> `python -m pytest tests/test_phase3_integration.py`

That last row is on the list because an earlier draft of this project published `2.0000` as the
kept share's own CHSH value, and it is nothing of the kind. The kept-share marginal of `(|000⟩ + |111⟩)/√2` is `(|00⟩⟨00| + |11⟩⟨11|)/2`, whose only surviving
correlator is `T_zz = 1`, giving `S = √2 = 1.4142`, and the measured 99% interval excludes 2.0
outright. The consequence is operational: a detector thresholding on "does this link still violate
the classical bound" holds `0.59` of margin against a kept share, not `0.00`. A kept share taken in
a uniformly drawn axis rather than `Z` falls to `0.9428`, the same value as intercept-resend, and
at that point the two attacks part company on purity (`0.50` against `1.00`) and not on any
correlator.

### 4.2 Attribution, and what it costs

The check logs are built inside `distribute()` before the symmetriser runs, and the `Symmetriser`
signature only ever sees `RecipientRecord`s, so no code path hands it a check log. The smearing
that symmetrisation applies to the records therefore leaves the check statistics alone, and a
one-link attack stays attributable. Depolariser at `p = 0.3` on Bob's link only, `L = 768`,
`check_fraction = 0.5`, session seed `433000`, pooled over both message bits:

| statistic | Bob | Charlie |
| --- | --- | --- |
| check-log QBER | `33/192 = 0.1719`, 99% `[0.1130, 0.2527]` | `0/192 = 0.0000`, 99% `[0.0000, 0.0334]` |
| post-exchange record mismatch | smeared to about `q/2` | smeared to about `q/2`, on a link nobody touched |

The two intervals are disjoint at 99%, so a detector can name the compromised link. Two conditions
ride on that, and both were measured rather than assumed. A detector must **not** pool the two
links, since pooling reports the average of two things and detects neither, and here it would
voluntarily discard the only signal symmetrisation leaves standing. And attribution is a
sample-size property: at `L = 96` the same attack is plainly detected on Bob's link while the two
99% intervals still overlap, so the party cannot be named.

The price went up during the audit and the increase is published rather than absorbed. Both links
must retain the same key, so the reserved set has to be shared; making the two links' check sets
disjoint therefore means *dealing* the reserved set between them, and each link then publishes
`check_count / 2` rounds instead of `check_count`. Every per-link interval is `√2` wider at a fixed
check fraction. Concretely, at `L = 384, cf = 0.5` the two links' 99% intervals are disjoint on six
session seeds in eight where they were disjoint on eight of eight before, so attribution at that
sizing is no longer reliable and is no longer claimed.

The CHSH arm cannot attribute at demo sizing at all, and the arithmetic is derived rather than
sampled. On an ideal link each of the four correlators has `|E| = 1/√2`, so
`Var(S) = Σ(1 − E²)/n = 8/N` and the 99% half-width is `2.5758·√(8/N)`, which is `0.4073` at 320
CHSH rounds and `0.5760` at 160. Against that, a depolariser at `p = 0.14` shifts `S` by
`2√2·p = 0.3960`. The shift sits *inside* the interval at both sizes.

### 4.3 The payload line is invisible, and totally

A check round teleports no payload. The `payload_map` seam is consulted there, as it is at every
position, and what it returns is discarded, so an adversary on the payload line wrecks the key
while the published channel statistics report a clean link. Same `InterceptResend` mounted on the
two seams under identical seeds:

| line | published QBER | published CHSH | mean matched mismatch (the key) |
| --- | --- | --- | --- |
| resource | `0.3104` | `0.9686` | `0.3535` |
| payload | **`0.0000`** | `2.7993` | `0.3535` |

> Source: doctest on `sih141.attacks.channel.payload_line_is_unwatched`, run by
> `python -m pytest sih141/attacks/channel.py`

Equal damage, and one of the two lines leaves no residual to threshold on. This is a limitation
asserted rather than described: `test_the_payload_line_is_invisible_to_the_check_round_arm` fails
if the published QBER stops reading zero or the key stops being wrecked. The signal that survives
is the verifiers' own mismatch rate, which reads the key rather than the sample.

### 4.4 One reported disagreement, and how it was settled

A channel batch measured QBER `0.2635` on 8000 rounds at `p = 0.5` against an exact prediction of
`0.2500`, with a 99% interval that excluded it. Either the sampler is biased or that batch was a
high draw, and the way to tell is sample size rather than a different seed, because a bias survives
a large increase in `n` and a fluctuation does not. Pooled over **200,000 rounds across 25
independent batches**: `49800/200000 = 0.249000` against `0.250000`, `z = −1.03`, with 25 of 25
per-batch 99% intervals covering the prediction. That pooled run was a one-off investigation and
is not in the committed sweep, so like the §4.5 timing precisions it carries no regenerating
command; what is pinned, and runs, is the 80,000-round check named below. The closed form is exact, the sampler is unbiased,
and the reported batch was a 2.8 sigma draw. Pinned at 80,000 rounds by
`test_the_depolarising_sampler_is_unbiased_at_p_equals_one_half` so it cannot rot back.

### 4.5 The assumption every check-round number here depends on

**(NO-TIMING).** A check round measures both wings of a pair; a key round teleports and measures
one. The two branches take different wall-clock times, and an adversary holding a seam and timing
its own consecutive calls classifies the branch with no instrumentation at all: measured at
`L = 192, cf = 0.25` over twelve session seeds, a rank rule over public parameters nominates check
rounds at precision `0.6667` to `0.8646`, mean `0.7665`, against a per-link base rate of `0.1250`.

Those precision figures are the only numbers in this document that **no command reproduces**, and
the exception is structural rather than an oversight. An assertion about a wall-clock gap is an
assertion about the machine the suite happens to be running on, so a test pinning it would be
flaky by construction, which is the same reason a constant-work rewrite could not be *shown* to
work either. Read them as a measurement of one afternoon on one laptop, and read everything else
here as a function of a seed.

Eight other routes to the same knowledge were found across four hardening rounds and all eight are
closed, each by making the seam's interaction trace constant over the positions of a link rather
than by patching the current spelling. Timing is left open, and the reason is that this simulator
models information flow and not physical execution: the signal is a two-hundred-microsecond gap
between two branches of a Python loop, on hardware where the physical operations being modelled
would be optical events six orders of magnitude faster. Closing it in code means every position
performing the union of both branches, which a little more than doubles every checked session, and
the honest description of the result would be "the gap is smaller" rather than "the route is
closed".

So every check-round statistic in §4 is conditioned on the adversary not inferring the check set
from timing. Two things bound what that assumption carries. It does not touch the strongest
detector signals, since the verifier's own mismatch rate, the matched counts and every abort
reason read the key rather than the sample, and a spare-the-watched adversary damages the key by
construction. And it is an assumption about the harness rather than about the protocol: a
deployment inherits a real engineering requirement here (constant-work receivers, or delaying the
correction bits, or delaying the announcement), and this document inherits the obligation to say
so. The full argument is [`PHASE3.md`](PHASE3.md) §12.

---

## 5. Count starvation

We found this one ourselves, by attacking our own Phase C′, and it is the reason the count
exchange has a threat model written against it at all.

**What the adversary assumes.** He is a recipient, and he answers the count exchange. He edits his
**own** `MatchedCountMessage` to a smaller number and delegates everything else to the shipped
`exchange_matched_counts`, so the attack arm and the control arm differ in exactly one integer. He
refuses to touch the counterpart's count, either floor, or the declaration digest, because a seam
that edited those would be a stronger party than any recipient, and the verifier re-derives the
floors anyway.

**Where it attaches.** The `count_exchange` seam, Phase C′.

**What it costs him.** One integer. No key material, no quantum resource, no computation, and the
seam sees the message bit and the declaration digest before it answers, so the denial can be
aimed.

**What stops it.** Nothing stops the denial, and pretending otherwise would be the dishonest move
here. What the protocol guarantees is that the denial cannot masquerade as an honest run, and that
it cannot manufacture an acceptance.

**What it measured.** Deterministic denial: 20/20 in the integration arm at `L = 192`, and 40/40,
60/60, 30/30 and 20/20 in the module's own arms at `L = 192`, `600` and `1200`. The rule is exact
arithmetic rather than a rate, and it is pinned against `verify()` itself at the boundary (denied
at `h`, a verdict at `h+1`) over six victim counts, not against a restatement of the formula:

```
denied  <=>  counterpart declares c <= max(m_min − 1, M_min − |M_R| − 1)
```

**He cannot look normal, and that is a theorem rather than a measurement.** Both floors are the
same Chernoff tail at `eps = 2⁻⁶⁴`, so the quietest *denying* declaration sits a fixed number of
honest standard deviations below the mean, independent of `L`:

| `L` | 192 | 600 | 1200 | 115200 (`DEFAULT_PARAMS`) |
| --- | --- | --- | --- | --- |
| `least_implausible_z` | `−9.798` | `−11.6047` | `−11.5738` | `−11.5375` |

converging on `−√(3 ln(1/eps)) = −11.5362`. The honest lower tail there is `4.1e-37` at `L = 600`
and `2.5e-31` at the production parameters, so a single-run threshold on the declared count as a
z-score catches every successful starvation at a false-alarm rate already inside the honest-abort
budget the floors were derived from. `L = 192` sits off the pattern because both floors are
degenerate there, which is the same reason no security claim is made below `L = 137`.

**The denial is one-sided, and one transcript holds the contradiction.** A starving Charlie still
reaches his own verdict, because his own count comes from his own record and only the
counterpart's arrives over the exchange. So a single transcript carries a declared count far below
`m_min` sitting beside a scored `matched_count` of roughly `L/3`, and he cannot suppress that from
inside this seam. It makes the attack a *transferability inversion*: the starver keeps an
acceptance that the party Alice signed to cannot get.

**Not a break, and the transcript type says so.** Every acceptance still needs the accepting
verifier's own rate on his own log to clear his own threshold, and no counterpart message touches
that. No arm produced an acceptance the honest arm did not, and no arm produced a rejection: the
denials are aborts, `COUNTERPART_BELOW_FLOOR` or `POOLED_BELOW_FLOOR`, a different transcript type,
never averaged into a rejection rate. It is availability, not forgery, and this document calls it
the fifth attack surface rather than the fifth break.

Detection, from the ROC sweep at `L = 384`, 40 trials, budget `eps = 1e-9`, intervals at 99%:

| arm | attacked | detected (**measured**) | clean | false alarms (**measured**) | refusals |
| --- | --- | --- | --- | --- | --- |
| `starvation` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 40 |
| `starvation-selective` | 22 | `22/22 = 1.000 [0.768, 1.000]` | 18 | `0/18 = 0.000 [0.000, 0.269]` | 22 |

> Source: [`tables/roc.md`](tables/roc.md).
> Regenerate: `python tools/sweep.py reduce roc`

The selective row is where the denominator earns its keep. That adversary engaged on 22 of its 40
runs and left the other 18 byte-identical to honest runs; scoring the whole cell as attacked would
have published `22/40 = 0.550` against the true `22/22 = 1.000`, and the untouched 18 belong in
the clean denominator where they measure `0/18`. Forty-five percentage points, on the choice of
what to divide by.

---

## 6. Impersonation, in scopes

Mallory draws her own key pair from her own generator and serves whichever Alice-side seams she
holds from one shared cache keyed on `(message_bit, key_length)`, so the key she teleports is the
key she declares. Four scopes: she takes neither seam, the signing seam, the distribution seam, or
both.

At `L = 192` over 200 trials per arm:

| scope | accepted | Bob's mismatch rate | Charlie's |
| --- | --- | --- | --- |
| `none` (honest control) | `200/200` | `0.0000` | `0.0000` |
| `full` | `200/200` | `0.0000` | `0.0000` |
| `signing` | `0/200` | `0.4988` | `0.5038` |
| `distribution` | `0/200` | `0.5031` | `0.4997` |

> Source: doctest on `sih141.attacks.impersonation.shipped_summary`, run by
> `python -m pytest sih141/attacks/impersonation.py`

**The contrast is the result.** Seizing one seam is caught cold at a coin flip, because the key
being declared and the key that was distributed are then different objects and every matched
position is a fresh 50/50. Seizing both is accepted every time, at zero mismatches, and is
identical to the honest control in every transcript number. Mallory is running the protocol
correctly with a key of her own, and no counting rule over the recipients' logs can object to a
key they measured faithfully.

**So the `full` row is not a measurement of a defence, and this document will not let it read as
one.** It is what assumption **(AUTH)** excludes. Nothing in `Signature`, `RecipientRecord`,
`VerificationResult` or `SessionTranscript` names or binds a signer; the round identifier binds a
declaration to a *distribution*, not to a party. Full impersonation succeeds with probability 1
against an unauthenticated channel from Alice. Every detector row for that scope reads
`undetectable-by-construction`, and the ROC table prints exactly that word rather than a zero,
because a zero in a detection column is a claim that the detector looked and found nothing. It did
not look, and it cannot. The exclusion is inherent to measurement-based QDS rather than to this
implementation, and (AUTH) has to be stated wherever the exclusion is used.

Two supporting measurements, because the argument above is easy to state and easy to make vacuous.
Under `DISTRIBUTION` the matched sets are identical *position for position* to the control at the
same session seed, 200 trials of 200, so QBER really is the only signal and the evidence floors are
a liveness control rather than an impersonation detector. Under `SIGNING` that identity holds 0
times in 200, which is the control that stops the first claim from being a comparison that always
succeeds.

**A correction rode along with this table.** `analysis.py` used to quote `0/60` accepted at
`QBER = 0.4987` (Bob) and `0.4806` (Charlie). The acceptance count reproduces. `0.4806` does not,
and could not have: with no key length, no `n`, and no statement of whether the rate was pooled
over positions or averaged over runs, there was nothing to reproduce. At any plausible `L` the
pooled standard deviation over 60 runs is at most `0.0144`, which puts `0.4806` about 1.3 standard
deviations low while quoting it to four figures. The four rows above replace it, and they carry
their own counts and re-check their own arithmetic at import.

---

## 7. Every zero in this document, checked against the adversary's own log

An arm that reports a clean zero because the adversary never engaged is not a defended attack. It
is a broken experiment that looks like a triumph, and this project has shipped one.

**The one that got caught.** Phase 4's replay arm first measured `0/40`, which would have been a
striking result. `ReplayingForwarder(captures=None)` mints its default capture at `key_length = 24`,
and `__call__` declines a capture whose shape does not match the live declaration, so at `L = 384`
the adversary forwarded **honestly on every call** and the arm measured nothing whatsoever. The
`0/40` was correct about the runs it produced and said nothing about the detector. It only
announced itself because every other arm in the same sweep read `40/40`. Re-measured with the
capture minted at the run's own length, which is also the more faithful adversary, the arm reads
`40/40 = 1.000 [0.858, 1.000]`.

Since then, every zero gets read against the adversary's own bookkeeping before it is published:

| zero | what the adversary's log says it did |
| --- | --- |
| `bob96before`, `0/400` accepted | substituted 51 to 80 positions per run, on all 400 |
| `bob1200before`, `0/400` accepted | substituted 758 to 847 positions per run, on all 400 |
| `l768` repudiation, `0/400` | the tilt replaced 42 to 88 states per run, 63.5 on average, on all 400 |
| `tol-p05` / `tol-p20` / `tol-p35`, `0/40` detected | touched 27 to 50, 128 to 180 and 241 to 301 hops per run |
| impersonation `full`, `0` detections | **not a zero**: `undetectable-by-construction` under (AUTH) |

The `tol-` rows are the uncomfortable ones and they stay in. Those cells score a depolariser
against the link's own true error rate rather than a noiseless null, and at or near the tolerated
level the detector does not fire on an attack that certainly happened. A lower detection rate from
a derived threshold is a better result than a higher one from a threshold tuned on the runs in
front of it, and D7 forbids moving a cut to improve a number.

Positive controls do the other half of the job, because a zero is only readable against an arm
that is known to fire. The repudiation ladder's `0/400` at `L = 768` sits beside three
unsymmetrised control cells measuring `400/400 = 1.0000 [0.9837, 1.0000]` against the same
adversary with the symmetrisation exchange removed, so the zero is a protocol result rather than a
silent arm.

---

## 8. What these measurements cannot reach

Stated here rather than left for a judge to find, because each one is worse discovered than
declared.

**No acceptance rate can be measured at production parameters.** One `L = 115200` session costs
about four minutes, and the recipient forger's acceptance probability there is `2.1726e-105`. What
carries to that
length is the per-position statistic, the scored fraction and the mismatch rate, which follow from
the Born rule and a uniform basis draw and never mention `L` at all. The acceptance rates at demo lengths
are the check that the harness composes those per-position statistics the way the analysis says.

**The proof and the measurement do not meet, and the gap is wide.** At `L = 768` the repudiation
measurement is `0/400`, whose 99% upper limit is `0.0163`; the exact in-model probability is
`5.845e-04`, twenty-eight times below what a sample of 400 can resolve; and the proven enforced
bound is `9.212e-01`, fifty-six times looser than the measurement. Neither reaches the other. The
region the real claim lives in, `1.4139e-09` at `L = 115200`, is out of range for both. A measured
zero there is evidence that the mechanism works and is never confirmation of the bound, and
[`SECURITY.md`](SECURITY.md) §7 prices what closing either gap would take.

**Below `L = 137` there is no security claim to test.** That is where
`minimum_pooled_matched_count` first exceeds 1, and it is `137` rather than the `140` an earlier
draft used, which is merely where the floor moves from 2 to 3. The per-verifier floor does not bite
until `L = 273`. Below the crossover both floors read 1, meaning "abort only on an empty matched
set", and every number in a run still computes cheerfully, which is why the security-claim column
exists in the tables. At `check_fraction = 0.25` the first nominal length carrying a claim is
`182`, whose signing length is `137`.

**Ground truth is the adversary's own bookkeeping and a detector may not read it.** Which link Eve
touched, and which runs a selective starver targeted, live on `attack.decisions()` and
`CountStarver.log`. Any false-positive rate has to be scored against a labelled harness with the
labels supplied by the experiment, never by the transcript. An untargeted run is byte-identical to
an honest one, and that is correct behaviour rather than a gap.

**Who minted a declaration cannot be read from one party's holdings.** The round identifier does
not cover the declared key, so at the moment Charlie decides, nothing he holds distinguishes
"Alice forged" from "the hop forged". The harness can tell, because it holds both declarations, so
`forwarding_altered_signature` is a harness view and not a passive detector. In a deployment that
question costs a dispute in which Bob's and Charlie's copies are compared.

**The bound estimator has to be named every time.** At `DEFAULT_PARAMS` recipient forgery has an
exact in-model probability of `2.1726e-105`, and two valid bounds sit above it decades apart:
`1.1238e-103` by the KL form and `1.1252e-29` by the Hoeffding default. Both are correct. A figure
published without saying which one it is is not, and the audit caught exactly that. Why the two
part company by 74 decades over the same quantity is [`MODELLING.md`](MODELLING.md) §6.3.

---

## 9. Reproducing every figure in this document

| figure | command |
| --- | --- |
| the count-ordering ladder, both forgery ladders, the floors table | `python tools/sweep.py reduce forgery-curve` |
| the ROC rows for starvation, replay, impersonation and the `tol-` cells | `python tools/sweep.py reduce roc` |
| the repudiation `0/400` at `L = 768` and its unsymmetrised controls | `python tools/sweep.py reduce repudiation-curve` |
| the Phase 3 per-position arms: outside forgery, recipient forgery, symmetrisation contrast, replay, channel campaigns, starvation | `python -m pytest tests/test_phase3_integration.py` |
| the impersonation scope table | `python -m pytest sih141/attacks/impersonation.py` |
| the payload-line invisibility figures | `python -m pytest sih141/attacks/channel.py` |
| the replay ledger and identifier arms | `python -m pytest tests/test_attack_replay.py` |
| the starvation boundary rule and selective policy | `python -m pytest tests/test_attack_starvation.py` |
| every closed form, bound and floor quoted above | `python -m pytest sih141/protocol/analysis.py sih141/protocol/verify.py` |
| all of it at once | `python -m pytest` |

Two standing rules sit underneath that table. **D3**: every adversary draws from its own injected
generator, and `tests/test_phase3_isolation_suite.py` holds one row per adversary-and-seam pair
that fails if an attack's decisions move with the session's randomness, or fail to move with its
own. All fourteen rows pass, and since the audit the check is separately shown to be *capable* of
failing thirteen of them one row at a time, which is a different claim from a green suite. The
fourteenth is the deterministic recipient forger, whose second half is waived in writing because
he draws nothing at all, and whose randomised sibling carries the row instead. **D9**: every
number above is regenerable from the command beside it, with the timing precision figures of §4.5
named as the exception and the reason given there. A number that cannot be regenerated does not
get published, because a figure nobody can reproduce is worth less than no figure at all. It looks
like evidence.

---

*Protocol and parameters: [`QDS.md`](QDS.md). The mathematics behind every closed form above:
[`MODELLING.md`](MODELLING.md). What the record adds up to as claims: [`SECURITY.md`](SECURITY.md).
Per-adversary engineering detail: [`PHASE3.md`](PHASE3.md). The detector that consumes these
signals: [`PHASE4.md`](PHASE4.md). The sweep that produced the committed tables:
[`PHASE5.md`](PHASE5.md).*
