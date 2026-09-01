# Phase 3 — The Adversaries

Engineering note for `sih141.attacks`. Covers the five adversaries and what each one is
measured at, the isolation convention that makes those measurements mean anything, the
detector signals Phase 4 will consume, the replay defence and its real price, the
check-round sampling design, and every limitation the phase found.

Status: complete. **Not one adversary needed a protocol edit to be mounted**, which is what
the Phase 2 seams were for. Mounting and *measuring* are not the same thing, though, and one
gap turned up between them — §2b. Five things did change in `sih141/protocol/`, and none of them is
a new mechanism:

* one new configuration, `count_exchange_timing`, with the public `forward()` it needs;
* one capability the seams were missing, `tally.counterpart_count`;
* two transcript fields closing named Phase 4 blockers, `spent_rounds` and `replay_refusals`;
* two helpers promoted from private to public, `session.forwarder_wants_view` and
  `distribute.accepts_context`, because two modules had reached for the private spellings;
* three prose corrections where a Phase 3 measurement contradicted a shipped claim.

**The three headline results, in the order they matter.**

1. **The shipped protocol's recipient-forgery rate is now measurable, and it agrees.**
   Under the ordering `QDSSession` shipped with, a forging hop is refused on provenance and
   Charlie never scores — 12/12 runs reach no verdict. That is a *denial of transfer*, not a
   detection, and it made the rate of the shipped scheme unmeasurable; every published figure
   came from the pre-pooled arm. Under the deployment ordering the same adversary is scored
   and accepted `96/300 = 0.320` against `recipient_forgery_probability(L=60) = 0.345566`,
   `z = −0.93`. §2.
2. **Symmetrisation is worth a factor of four, measured through the shipped seams.** Same
   adversary, same code path, one seam swapped: mismatch rate `0.0863` on the `1/12` floor
   with Phase A′, `0.3378` on the `1/3` floor without. The two 95% intervals,
   `[0.0814, 0.0915]` and `[0.3191, 0.3570]`, do not come close to touching. §2.
3. **The ledger's denial-of-service surface was priced at zero and is not zero.** `verify.py`
   claimed the only party who could burn a round on a declaration that will be rejected is
   the signer herself. The Bob-to-Charlie hop can do it too, using an opening Phase B
   publishes — 300/300 at `L = 24`, 100/100 at `L = 96`. What closes it is the *ordering* of
   Phase C′, not the ledger and not the round binding. §5.

**What every adversary passed before its number was believed.** All fourteen
adversary-and-seam pairs pass the D6 isolation check in `tests/test_phase3_isolation_suite.py`,
and — since the audit — the check is separately shown to be *capable* of failing thirteen of
them, one row at a time. Every deliberately-defective control is still caught. **No adversary
failed, so no published rate changed on that account.** §7.

---

## 1. Module layout

| Module | Adversary | Seams it mounts on | Public surface |
| --- | --- | --- | --- |
| `isolation.py` | — (the check) | — | `check_attack_isolation`, `assert_attack_isolated`, `IsolationReport`, `AttackIsolationError`, `AttackBuilder`, `DecisionProbe`, `SignerScenario`, `signer_scenario`, `signer_probe`, `forwarder_probe`, `canonical`, `SessionEnvironment`, `active_session`, `session_environment`, `same_stream`, `stream_fingerprint`, `derived_from_seed`, `require_distinct_streams`, `MIN_JUSTIFICATION`, `DEFAULT_*_SEEDS`, `SCENARIO_*`, `SESSION_MATERIAL_BYTES` |
| `statistics.py` | — (the arithmetic) | — | `wilson_bounds`, `agrees_within`, `AgreementVerdict`, `sigma_tolerance`, `binomial_standard_error`, `two_sided_z`, `Z_90`/`Z_95`/`Z_99` |
| `forgery.py` | `OutsideForger`, `RecipientForger` | `signer`, `forwarder` | `measure_outside_forgery`, `measure_recipient_forgery`, `ForgeryMeasurement`, `wilson_interval`, `forwarder_probe`, three floor constants |
| `impersonation.py` | `Impersonator` | `distributor`, `signer` | `ImpersonationScope`, `impersonation_seams`, `measure_impersonation`, `run_impersonation`, `matched_sets_identical`, `MEASURED`, `shipped_summary`, `detector_signals`, `signing_probe`, `distributor_probe` |
| `replay.py` | `ReplayingForwarder` | `forwarder`, plus direct drives of `verify_or_abort` | seven `measure_*` functions, `ReplayCapture`, `replay_capture`, `replay_probe`, `AttackOutcome`, the three `COUNTS_*` modes |
| `channel.py` | `DepolarisingChannel`, `InterceptResend`, `KeptShareSwap` | `resource_factory`, `payload_map` | `chsh_from_tensor`, `qber_from_tensor`, `depolarising_tensor`, `collapse_tensor`, `measure_qber`, `measure_chsh`, `attribution_survives_symmetrisation`, `payload_line_is_unwatched`, `AttackDecision` |
| `starvation.py` | `CountStarver` | `count_exchange` | `StarvationMode`, `measure_starvation`, `denial_headroom`, `declaration_z_score`, `least_implausible_z`, `pooled_branch_requirement`, `declared_versus_scored`, `starvation_probe`, `probe_messages` |

`sih141/attacks/__init__.py` re-exports all of it with an explicit `__all__` and no wildcard
imports, and `sih141/__init__.py` exposes the three subpackages. Dependencies run one way:
`statistics` → `isolation` → the five attack modules, with every attack module depending on
`sih141.protocol` and nothing in `sih141.protocol` depending on `sih141.attacks`.

---

## 2. Forgery

Two flavours, because the threat model has two forgers and they are not the same adversary.

### 2a. The outside forger — `signer` seam

Eve substitutes Alice's declaration outright. She ignores the keys and any recipient logs
the seam offers her (pinned by test: same generator, different Alice keys, identical
declaration). Mounted on the *signer* seam rather than the hop, deliberately: her
declaration then reaches both verifiers, so one batch measures her against `s_a` and `s_v` at
once, and unlike a recipient she is neither verifier, so there is no self-verification
problem.

`L = 30`, 800 sessions, session seeds `400000…`, attack seeds `900000…` (disjoint ranges,
which is convention D6 as an arithmetic fact about the harness rather than a promise about it):

| Quantity | Bob | Charlie | Predicted | Source |
| --- | --- | --- | --- | --- |
| acceptance | `5/800 = 0.00625`, 95% `[0.0027, 0.0145]` | `3/800 = 0.00375`, `[0.0013, 0.0110]` | `0.0042075` / `0.0042111` | `analysis.forgery_probability` |
| mismatch, per scored position | `3924/7917 = 0.4956`, `[0.4846, 0.5067]` | `3998/7967 = 0.5018`, `[0.4908, 0.5128]` | `1/2` | `FORGER_MATCHED_MISMATCH_PROBABILITY` |
| scored fraction | `7917/24000 = 0.3299` | `7967/24000 = 0.3320` | `1/3` | `analysis.matched_statistics` |

The mismatch rate is the number that carries. Acceptance is an exponential in the matched
count and is a handful of successes at any length a test can run; the mismatch rate is a
per-position Bernoulli parameter estimated over ~8000 positions, and it is the exact
assumption `forgery_probability` is built on.

### 2b. The forging recipient — `forwarder` seam

Bob accepts Alice's declaration and forwards `key_from_record(view.raw_record)`: his own
measured log, which is the optimal move (§7). `L = 60`, 300 sessions.

| Quantity | Measured | 95% interval | Predicted | z |
| --- | --- | --- | --- | --- |
| acceptance at Charlie | `96/300 = 0.3200` | `[0.2698, 0.3748]` | `0.345566` | `−0.93` |
| mismatch per scored position | `1026/11887 = 0.0863` | `[0.0814, 0.0915]` | `1/12 = 0.08333` | `+1.18` |
| scored fraction | `11887/18000 = 0.6604` | `[0.6534, 0.6673]` | `2/3` | `−1.79` |
| mismatch, **no symmetrisation** | `810/2398 = 0.3378` | `[0.3191, 0.3570]` | `1/3` | `+0.46` |

**This arm did not exist before Phase 3 integration.** `QDSSession` ran `exchange_counts()`
lazily inside `verify(Party.BOB)`, so both matched counts were taken against the declaration
Alice *signed*, before the hop existed. Charlie's own count therefore named one declaration
while he was looking at another, and he refused on provenance rather than scoring — 12/12
runs, and 50/50 in the original attack report. That refusal is a denial of transfer, not a
detection, and it has no acceptance probability attached to it because the prediction
describes a Charlie who scores.

`count_exchange_timing` names the two experiments:

| Setting | Who counts what | What it models | Forging hop |
| --- | --- | --- | --- |
| `COUNTS_BEFORE_FORWARDING` (default, shipped) | both count Alice's declaration | adversary owns the declaration channel, not the count channel | refused on provenance, **no verdict** |
| `COUNTS_AFTER_FORWARDING` | both count the declaration that reached Charlie | adversary owns both, which in a deployment is one link | **scored**, `0.320` accepted |

On an honest run the two are identical position for position — same records, same signature,
same verdicts, same pooled count, same spent rounds — which is asserted, because an ordering
that changed an honest run would be changing the protocol rather than naming an experiment.

---

## 3. Impersonation

Mallory draws her own key pair from her own generator and serves both Alice-side seams from
one shared cache keyed on `(message_bit, key_length)`, so the key she teleports is the key she
declares. Four scopes: `NONE`, `DISTRIBUTION`, `SIGNING`, `FULL`.

At `L = 96`, 40 sessions per arm (the shipped table in `impersonation.MEASURED` is at
`L = 192` over 200):

| Scope | Accepted | Bob QBER | Charlie QBER | Matched fraction |
| --- | --- | --- | --- | --- |
| `none` (control) | 40/40 | `0/1295 = 0.0000` | `0/1224 = 0.0000` | 0.337 / 0.319 |
| `signing` | 0/40 | `628/1252 = 0.5016` | `610/1295 = 0.4710` | 0.326 / 0.337 |
| `distribution` | 0/40 | `657/1295 = 0.5073` | `609/1224 = 0.4975` | 0.337 / 0.319 |
| `full` (`L = 192`, n = 200) | 200/200 | `0.0000` | `0.0000` | `1/3` |

**The contrast is the result.** Seizing both seams is accepted every time at zero mismatches
and is *identical to the honest control in every transcript number* — because Mallory is
running the protocol correctly with a key of her own, and no counting rule over the
recipients' logs can object to a key they measured faithfully. That is assumption **(AUTH)**
in `analysis.py`, and Phase 3 is what makes it load-bearing rather than decorative.

**The matched counts' *law* never moves; under `DISTRIBUTION` the counts themselves do not
either.** The distinction matters and an earlier revision of this line lost it: under `SIGNING`
the matched set and its realised counts *do* move (`MATCHED_IDENTICAL_TRIALS[SIGNING] == 0`),
and what survives is that the count is still `Binomial(L, 1/3)` -- which is all the surrounding
argument needs. Under `DISTRIBUTION` the stronger statement holds and was checked in its
sharpest form: the matched sets are identical *position for position* to the control at the
same session seed, 200/200 trials, with `SIGNING` as the control that stops the claim being
vacuous (0/200 identical there, counts still `Binomial(L, 1/3)`). So QBER is the only signal
there is, and the two evidence floors are an evidence-liveness control rather than an
impersonation detector.

**A correction landed in `analysis.py`.** It used to quote `0/60` accepted at
`QBER = 0.4987 (Bob)` and `0.4806 (Charlie)`. The acceptance count reproduces; `0.4806` does
not, and could not have — with no key length, no `n`, and no statement of whether the rate was
pooled over positions or averaged over runs, there was nothing to reproduce. At any plausible
`L` the pooled standard deviation over 60 runs is at most `0.0144`, putting `0.4806` about
`1.3` sd low while quoting it to four figures. It is replaced by the four-row table above,
whose rows carry their own counts and re-check their own arithmetic at import.

---

## 4. Channel manipulation

Three attacks, each mountable on **both** lines by a bound method — `attack.resource` for
`resource_factory`, `attack.payload` for `payload_map` — and each taking `target: Party | None`,
so the party-targeted attack is a parameter rather than a fourth class.

**One identity predicts everything.** Every resource here is Bell-diagonal or a collapse of
one, so with `T = (T_xx, T_yy, T_zz)`:

```
S    = sqrt(2) * (T_zz + T_xx)              [the shipped CHSH settings lie in the x-z plane]
QBER = mean_b (1 - s_b * T_bb) / 2,   s = (+1, -1, +1)
```

`chsh_from_tensor` and `qber_from_tensor` are those two lines. The QBER identity is pinned
against `analysis.depolarising_error_rate` to `1e−12` across `p`, and the CHSH identity
against `checkrounds.depolarising_chsh`, so the attack's prediction and the protocol's cannot
drift apart.

### The sampling design, and the intervals it produces

A run reserves a `check_fraction` of its positions for measurement instead of key. The
recipients draw the check plan from the session's own generator, so *which* positions are
check rounds is theirs and not the signer's; the reserved positions are spent on a QBER arm
(`CheckRole.QBER` — both halves measured in the same basis from `params.bases`) and a CHSH
arm (`CheckRole.CHSH` — the two halves measured at independently drawn Bell-test settings,
which for the shipped choice lie in the x-z plane), and
`params.sifted()` reduces the signing length accordingly, so the floors and bounds of Phase 2
apply to what is left rather than to the nominal `L`.

The reserved *set* is shared by the two links, because both records must index the same key,
but the rounds are **dealt between them**: Bob measures half the reserved positions and
Charlie the other half, and the half a link does not measure it runs as an ordinary key round
and then drops. A run distributes to Bob and then to Charlie, so a check set both links shared
would mean one recovery bought the second link outright. The price is exact and worth stating:
each link publishes `check_count / 2` rounds, so a deployment that wants `n` rounds per link
reserves `2n` positions — `CheckRoundBudget.reserved_fraction` is that number, and
`draw_check_plan(..., parties=None)` restores the shared plan at full sample size and
re-couples the links.

**Intervals.** QBER is reported as a Wilson score interval at **99%** — Wilson because a clean
link measures exactly `0/n`, where the Wald interval collapses to the single point `0` and
claims certainty from a finite experiment; 99% rather than 95% because a channel campaign
makes a dozen comparisons in one run and would otherwise expect a miss every twenty. CHSH is
reported as a normal interval on four correlators, clipped only at the *algebraic* range `[-4, 4]`
and deliberately not at Tsirelson's `2√2`, so a clean link at demo sample sizes routinely
reads above `2.83` (§9.5). Every published interval is recomputed from the *raw observations*
carried in the transcript — `estimate_qber(check_log_for(party, bit).qber)` returns the same
numbers the run reported, which is what makes the estimate auditable rather than asserted.

**Sizing.** `required_check_rounds` sizes the arm to resolve a shift of `2·s_a` at
`L = 115200`. Below that, what a campaign can resolve has to be stated rather than assumed:
at 192 pooled rounds a `p = 0.3` one-link attack is detected *and* attributed on the QBER arm
(intervals disjoint at 99%); at 8000 rounds the 99% half-width is about `0.014` at a rate of
`1/3` and `0.009` at `0.1`; and the CHSH arm needs the full-scale sample before it can
attribute anything at all.

Standalone check-round campaigns, 8000 rounds each. Intervals here are the attack suite's
own 95% Wilson bounds (`attacks.statistics.wilson_bounds`, the default a measurement table
quotes); the *protocol's* published interval on the same observations is the 99% one
`estimate_qber` returns, which is what a detector reads:

| Resource | Measured QBER | 95% interval | Predicted |
| --- | --- | --- | --- |
| depolarising `p = 0.2` | `795/8000 = 0.0994` | `[0.0930, 0.1061]` | `p/2 = 0.1000` |
| intercept-resend | `2645/8000 = 0.3306` | `[0.3204, 0.3410]` | `1/3` |
| kept GHZ share | `2668/8000 = 0.3335` | `[0.3233, 0.3439]` | `1/3` |

**A reference value was wrong and is corrected.** A Phase 2 audit quoted `S = 2.0000` for an
eavesdropper keeping a share of a GHZ state. The kept-share marginal of
`(|000> + |111>)/sqrt(2)` is `(|00><00| + |11><11|)/2`, whose only surviving correlator is
`T_zz = 1`, so `S = sqrt(2) = 1.4142`. The measured 99% interval `[1.3202, 1.5198]` **excludes**
2.0. `2.0000` is `CLASSICAL_CHSH_BOUND` — what a separable resource may not exceed — and is
also exactly `depolarising_chsh(1 − 1/sqrt(2))`, which is the likely transposition. The
correction is operational: a detector thresholding on "does this link still violate the
classical bound" has `0.59` of margin against a kept share, not `0.00`.

### Attribution survives symmetrisation, on the QBER arm only

`QDSSession` builds one `CheckLog` per `(party, message_bit)` inside `distribute()`, from the
`_ChannelTap` wrapper, and only then calls the symmetriser — the `Symmetriser` signature only
ever sees `RecipientRecord`s, so no code path hands a `CheckLog` to Phase A′. The smearing is
confined to the records. One-link depolariser at `p = 0.3` on Bob, `L = 384`,
`check_fraction = 0.5`, pooled over both bits:

| Statistic | Bob | Charlie |
| --- | --- | --- |
| check-log QBER | `18/192 = 0.0938`, 99% `[0.0523, 0.1623]` | `0/192 = 0.0000`, 99% `[0.0000, 0.0334]` |
| post-exchange record mismatch | smeared to ≈ `q/2` | smeared to ≈ `q/2`, on a link never touched |

The two check-log intervals are disjoint at 99%, so **Phase 4 can name the compromised link**
— via the QBER arm, per party. Two conditions on that, both measured:

* **Phase 4 must not pool the two links.** `estimate_qber`'s own docstring warns that pooling
  reports the average of two things and detects neither; here that pooling would voluntarily
  discard the only signal symmetrisation leaves standing. Per-party estimation should be the
  default and pooling the deliberate opt-in.
* **Attribution is a sample-size property, not a free one.** At `L = 96` the same attack is
  plainly detected on Bob's link and the two 99% intervals still *overlap*, so a detector
  could not name the party. The CHSH arm cannot attribute at demo sizing at all — at
  `p = 0.14` the shift in `S` is about `0.4` against a 99% half-width of about `0.37`.
  `required_check_rounds` sizes the arm to resolve `2·s_a` at `L = 115200`; anything smaller
  has to say what it can resolve.

---

## 5. Replay, and the ledger's real price

Four flavours. Three are closed and the fourth is not closed by what everyone assumed.

| Attack | Undefended | Defended | Mechanism |
| --- | --- | --- | --- |
| (a) straight re-verification | `100/100` accepted | `0/100`, `RECORD_ALREADY_VERIFIED` | the ledger |
| (b) cross-session pairing | `46/400 = 0.115` at `L = 12`, 95% `[0.0873, 0.1500]` vs `forgery_probability = 0.10445`, `z = +0.69` | `0/100`, `SESSION_MISMATCH` | the round binding |
| (c) burn a verifier's round | — | see below | **not the ledger** |
| (d) two rounds, one identifier | `14/1000 = 0.014` vs `0.01252` | signer loses her own second round, `400/400` | the ledger keys on `(session_id, message_bit)` |

Undefended, a cross-round pairing is *exactly* an outside forgery, which is the point: the
identifier does not make it harder to forge, it makes it refuse to be scored at all.

**The design, and what it costs.** Two independent pieces, and each is inert unless the
caller supplies the state it reads. (i) *The round binding*: every record carries the
distribution round it came from, every declaration names the round whose opening Phase B
reveals, and a verifier holding a stamped record refuses a declaration naming another round.
The **record** is the anchor, not the signature — the comparison is driven by the side an
adversary cannot reach, and a verifier whose record names no round simply scores as before,
which is what keeps every log written before the binding existed working unchanged. The
identifier deliberately does **not** cover the declared key, so a forgery is *scored and
rejected* rather than refused; without that, the whole forgery table of §2 would empty into
the no-verdict column. (ii) *The consumed-records ledger*: one `ConsumedRecords` per verifier,
keyed on `(session_id, message_bit)`, spent only when a verdict is actually reached. It is an
object the verifier holds and passes, never a module-level default — Bob's refuses a record
belonging to anyone else and offers no way to read Charlie's, so one verifier's history cannot
leak into the other's decision, and two runs made from the same seed (which produce the same
identifier by design) do not refuse each other as replays.

Cost: one 32-character identifier per round per verifier, roughly `10²` bytes, prunable by
round because that is exactly what it is keyed on. No randomness (D3), no extra message, and
no change to the accept rule. The *ordering* cost is separate and belongs to Phase C′, not
here: Bob's acceptance is no longer local. The real price is the denial of service below.

### (c) The denial of service that was priced at zero

`verify.py` used to reason: entries are spent only on a verdict, a refusal spends nothing,
therefore an adversary cannot poison a ledger from outside — *therefore* the only party who
can spend a round on a declaration that will be rejected is the signer herself, who could
anyway decline to sign. The first half is true and measured (`0/400` over three routes; 50
wrong-round presentations left the ledger empty). **The inference is false.**

Phase B reveals the round's opening *on the declaration*, and the identifier deliberately does
not cover the declared key. So anyone downstream of that reveal can mint a *different*
declaration naming the *same* round. The Bob-to-Charlie hop is exactly where the threat model
puts an adversary and is not covered by the classical-authentication assumption. He hands
Charlie a forged-but-correctly-named declaration; Charlie scores it, rejects it, and a
rejection is a verdict, so the round is spent. Alice's genuine declaration is then refused as
`RECORD_ALREADY_VERIFIED` for ever. Measured `300/300` at `L = 24` and `100/100` at `L = 96`.

What closes it is the **provenance half of the count exchange, under one ordering only**:

| Phase C′ configuration | Round burned? |
| --- | --- |
| `no_count_exchange` | 300/300 |
| counts taken as received (`COUNTS_AFTER_FORWARDING`) | 300/300 |
| counts taken as signed (`COUNTS_BEFORE_FORWARDING`, the shipped default) | 0/300 |

**What counts as a burned round.** Success here is the honest declaration being refused as
`RECORD_ALREADY_VERIFIED` — the mechanism — and not the looser "the honest declaration was not
accepted", which is what `measure_ledger_denial_of_service` scored until the audit. The two
agree on every healthy trial and come apart on a degenerate one: below `L = 140` both
matched-count floors degenerate and an honest run can fail entirely on its own, and the loose
reading counted that as the adversary burning a round he never touched. At `L = 12` it does:
three trials in a hundred and twenty end `empty-matched-set` with no ledger present, so the
*undefended* arm — where the attack provably achieves nothing that lasts — would have reported
`3/120`. Every figure in the table above was re-measured under the corrected definition and is
unchanged; what changed is that they are now rules rather than facts about a kind seed. A trial
in which the attack was not measured at all is refused outright rather than scored either way.

**Honest pricing.** The residual denial-of-service surface is one burned round per verifier
per presentation channel the adversary controls, and it is closed only when every such channel
is authenticated *or* the count exchange runs ahead of the hop. The two obvious repairs are
both worse and neither was made:

* *Spend only on an acceptance.* An adaptive adversary then gets unlimited tries at one round
  — present, see the rejection, edit one position, present again — which turns a bounded
  forgery probability into a search.
* *Key the ledger on the declaration as well as the round.* The same thing, more directly.

One shot per round is the property worth keeping; **where** the shot is taken is what
authentication buys. `verify.py`'s `:ref:`ledger-denial`` now says so.

### What could not be broken

Poisoning a ledger from outside (`0/400` over three routes); one verifier writing the other's
ledger (refused with a reason); forging an identifier (`0/500000` preimage attempts against
the length-prefixed encoding, bounding the per-attempt rate at `7.7e−06` at 95%, which is all
a bounded search can say against `2**−128 = 2.9e−39`); and a signer giving two rounds one
identifier, which buys her exactly the outside forger's rate and costs her the second round
outright.

### One thing the seams still cannot express

`QDSSession._bind_to_round()` overwrites the `session_opening` of whatever the `Signer` or
`Forwarder` seam returns with the live round's opening. A *stale* declaration pushed through
the forwarder therefore reaches Charlie carrying the live identifier and is scored as a
forgery, not refused as a replay. That is deliberate — otherwise every forgery would abort as
`SESSION_MISMATCH` and the forgery table would empty into the no-verdict column — but it means
cross-round measurements drive `verify_or_abort` directly, and an integrator reading a
transcript of `ReplayingForwarder` will see an *altered forwarding*, not a replay. Pinned by
`test_session_relabels_a_stale_declaration_as_fresh`.

---

## 6. Count starvation

One recipient replaces his **own** `MatchedCountMessage` with a smaller count and delegates to
the shipped `exchange_matched_counts`, so the attack arm and the control arm differ in exactly
one integer. It refuses to touch the counterpart's count, either floor, or the declaration
digest — a seam that edited those would be a stronger party than any recipient, and the floors
are re-derived by the verifier anyway.

**How cheap: one integer.** No key material, no quantum resource, no computation, and the
denial is deterministic — 20/20 in the integration arm, 40/40, 60/60, 30/30 and 20/20 in the
module's own arms at `L = 192`, `600` and `1200`. The rule is exact arithmetic:

```
denied  <=>  counterpart declares c <= max(m_min − 1, M_min − |M_R| − 1)
```

pinned against `verify()` itself at the boundary (denied at `h`, verdict at `h+1`) over six
victim counts, not against a restatement of the formula.

**It is selective and free.** The seam sees the message bit and the declaration digest before
answering. Bit-selective denial hits 20/40 with every bit-0 run completing and transferable;
probabilistic `p = 0.5` hits 27/60. No aggregate over run *outcomes* separates a selective
starver from an honest pair, so the per-run count signal below is load-bearing.

**He cannot look normal, and that is a theorem.** Both floors are the same Chernoff tail at
`eps = 2**−64`, so the quietest *denying* declaration sits a fixed number of honest standard
deviations below the mean, **independent of L**:

| `L` | 192 | 600 | 1200 | 115200 (`DEFAULT_PARAMS`) |
| --- | --- | --- | --- | --- |
| `least_implausible_z` | `−9.798` | `−11.6047` | `−11.5738` | `−11.5375` |

converging on `−sqrt(3 ln(1/eps)) = −11.5362`. The honest lower tail there is `4.1e−37` at
`L = 600` and `2.5e−31` at the defaults, so a single-run z-threshold on the declared count
catches **every** successful starvation at a false-alarm rate already inside the honest-abort
budget the floors were calibrated to. (`L = 192` is off the pattern because both floors are
degenerate there, which is the same reason no security claim is made below `L = 140`.)

**The denial is one-sided, and the transcript holds the contradiction.** A starving Charlie
still reaches his own verdict — his own count comes from his own record, only the
counterpart's comes over the exchange — so one transcript holds a declared count far below
`m_min` beside a scored `matched_count` of roughly `L/3`. He cannot suppress it from inside
this seam. That makes it a *transferability inversion*: the starver keeps an acceptance the
party Alice signed to cannot get.

**Not a break: pure availability.** Every acceptance still needs the accepting verifier's own
rate on his own log to clear his own threshold, and no counterpart message touches that. No
arm produced an acceptance the honest arm did not, and no arm produced a rejection — the
denials are aborts (`COUNTERPART_BELOW_FLOOR` / `POOLED_BELOW_FLOOR`), a different transcript
type, never averaged into a rejection rate.

---

## 7. Convention D6, and the check that enforces it

**The rule.** An adversary's behaviour is a function of its *own* generator and of what the
threat model says it can observe — never of the session's randomness.

**Why it is a check and not a paragraph.** `QDSSession` derives two labelled streams, so no
Alice-side seam is ever handed the symmetrisation coins. That closes the leak *through the
seam* and does nothing about the leak through the *harness*, which is what writing a
reproducible experiment looks like:

```python
seed = 20260141
attack = MyForger(seed)                                    # <-- the defect
session = QDSSession(params, signer=attack, rng=np.random.default_rng(seed))
```

An adversary holding that integer rebuilds the run and predicts every private symmetrisation
coin — `120/120` on both message bits, in about ten lines, using nothing but the public API.
The mathematics is untouched; the *experiment* is fiction, and it looks entirely legitimate.

**The check has two halves and needs both.** (a) hold the attack's generator fixed and vary
the session seed — decisions must not move. (b) hold the session seed fixed and vary the
attack's generator — decisions must move, because a constant is independent of everything and
without (b) half (a) passes vacuously.

`tests/test_phase3_isolation_suite.py` is one table with one row per adversary-and-seam pair.
A sixth adversary is one row.

| Row | Builder | Probe | (b) |
| --- | --- | --- | --- |
| outside-forger/signer | `OutsideForger` | `signer_probe()` | passes |
| recipient-forger/forwarder | `RecipientForger` | `forwarder_probe()` | **waived** |
| recipient-forger/randomised | `partial(RecipientForger, guess_probability=0.25)` | `forwarder_probe()` | passes |
| impersonator/signer, /distributor | `Impersonator` | `signing_probe()`, `distributor_probe()` | passes |
| replaying-forwarder/forwarder | `ReplayingForwarder` | `replay_probe()` | passes |
| depolarising-channel × {resource, payload, targeted} | `partial(DepolarisingChannel, 0.14)` | resource / payload probes | passes |
| intercept-resend × {resource, payload} | `InterceptResend` | resource / payload probes | passes |
| kept-share-swap × {resource, payload} | `KeptShareSwap` | resource / payload probes | passes |
| count-starver/count-exchange | `CountStarver` | `starvation_probe()` | passes |

**Result: 14/14 pass check (a), and the pass is now evidenced.** No adversary failed, so no
published rate changed.

That sentence used to be the whole of the result, and it carried nothing. The audit found
check (a) **inert on all fourteen rows**: every ready-made probe opened with `del
session_seed`, no shipped adversary declares a `session_seed` constructor argument, so nothing
varied between the five calls check (a) compares and no row *could* fail. The two negative
controls kept working throughout — they read the seed through the builder, the one channel that
was live — which is exactly why it went unnoticed for the whole phase.

`check_attack_isolation` now installs a `SessionEnvironment` around every build and every probe
call and varies it with the session seed, opening the three routes a real experiment leaks
through: the harness's module-level seed constant (`active_session()`), ambient global
randomness (`numpy.random` and stdlib `random`, which D3 forbids drawing from and which a
reproducible harness seeds), and an adversary generator the harness derived from the session's
own seed. The routes are open on purpose: a check that offers no leak detects no theft.

`test_the_session_channel_is_live_on_every_row` is the evidence. Per row it rebuilds *that*
adversary with the session's seed folded into its generator — one line of defect, same class,
same `__call__`, same probe — and requires check (a) to catch it. Thirteen of fourteen rows are
covered directly. The fourteenth is the deterministic recipient forger, whose decisions move
with nothing at all and so cannot be moved by a defect in whose randomness he was handed; that
is the same fact the waiver rests on, and his randomised sibling is covered.

### The one waiver, and why it is not a loophole

The optimal recipient forger is a **deterministic function of his view**. Declaring his own
raw log strictly dominates every randomised alternative at every position: a swapped position
matches with certainty, a retained one gives `P(match | scored) = 2/3` against `1/2` for any
other declaration, and flipping the eigenvalue is strictly worse. He has nothing to draw, so
check (b) cannot pass for the adversary whose rate we publish.

`isolation.py` gained a documented deterministic mode (`:ref:`deterministic-mode``) with three
responses in order of preference:

1. **Realise the adversary as a sampled process** where the physics allows it. A per-round
   Pauli twirl has exactly the depolarising ensemble and *is* a function of the adversary's
   own stream — which is why `DepolarisingChannel` is a twirl rather than the averaged Werner
   state, and note the two are not observationally equivalent to a channel monitor: the twirl
   leaves purity and concurrence at `1.0` with fidelity flipping `1`/`0`, where the averaged
   state would report a constant fidelity of `1 − 3p/4`.
2. **Check a randomised sibling sharing the call path** — `guess_probability` on the forger,
   `jitter` on the starver. Strictly suboptimal, so no published rate is measured with it, but
   it exercises the identical `__call__`.
3. **Waive (b) in writing.** `deterministic="..."` requires at least `MIN_JUSTIFICATION = 40`
   characters of actual argument (a bool is refused with a message saying why), check (a) still
   runs and still raises, the reason is carried in the report, and `summary()` prints
   `ISOLATED (check (b) waived)` so nobody reads the verdict without it.

The waiver is only sound **alongside** response 2, and the suite enforces that:
`test_every_waiver_has_a_randomised_sibling` fails if a waived adversary has no randomised row.

### The negative controls

A check that has never failed is not known to work. The defective toys in
`tests/test_attack_isolation.py` are re-run here and must still be caught: `SessionSeedForger`
by check (a) (`reads the session's randomness`), `DeafForger` by check (b) (`ignored the
generator it was handed`). The (b) failure message now also names the deterministic escape
hatch and warns when it is *not* the right answer, so the next author does not reach for the
waiver to paper over a broken probe.

A third control came out of the audit, and it is the one that would have caught the vacuous
check: `AmbientSessionForger` takes only `rng` in its constructor — so `session_seed_offered`
is `False` for it, exactly as for every shipped adversary — and reads the session while it is
being *called*, the way an attack defined in the same module as the harness's `SEED` constant
does without declaring anything. Under the check as shipped it passed. `GlobalRandomnessForger`
covers the ambient route and `build_from_the_session_stream` the one-seed-used-twice route.

A shared control is not by itself enough, and that is the lesson of the finding: a control run
through `signer_probe()` establishes that *that* probe's channel is live and says nothing about
`starvation_probe()`, the two channel probes, or a probe added next year. Hence the per-row
test above.

### Two ways to write a probe that blames the adversary for your bug

Both were found the hard way, by different agents, and both report a flawless attack as a
cheat. They are now documented in `isolation.py` under `:ref:`probe-traps``.

* **A distributor probe must return the adversary's own decision, never the seam's output.**
  The obvious probe returns the records — which are a function of the session's Alice-side
  stream *by construction*, for every honest implementation. Return the key the impersonator
  substituted instead.
* **A `payload_map` probe used to need `check_fraction = 0`, and the reason was a defect.**
  `payload_map` was called on key rounds only, so the *set of occasions the adversary is
  consulted* moved with the seed even for a perfect adversary — and the same fact let any
  adversary holding the seam read the check set off the gaps in its own call sequence. The
  seam is now called on every position and its result discarded on a check round, so the probe
  no longer needs the workaround and the leak is gone with it. `resource_factory` never had
  the problem; `channel_monitor` had the mirror image of it and is fixed the same way.

The rule both are instances of: everything the adversary legitimately observes, *including the
set of occasions on which it is consulted*, must be identical across probe calls.

---

## 8. Detector signals for Phase 4

Everything here is reachable from `SessionTranscript` unless the last column says otherwise.

| Statistic | Honest | Under attack | Reachable |
| --- | --- | --- | --- |
| `VerificationResult.rate` per verifier | `0.0` on an ideal channel | `1/2` outside forgery and partial impersonation; `1/12` forging recipient; `0.0` under **full** impersonation | yes |
| `VerificationResult.matched_count` per verifier | `Binomial(L, 1/3)` | **unchanged** by every forgery and every impersonation scope; `2L/3` under recipient forgery | yes |
| the **pair** `(matched fraction, rate)` | `(1/3, ~0)` | `(2/3, 1/12)` recipient forgery; `(1/3, 1/2)` outside forgery; `(1/3, ~0)` depolarising channel | yes |
| per-link check QBER, `estimate_qber(check_log_for(party, bit).qber)` | `0.0000`, 99% `[0, 0.033]` at 192 rounds | `p/2` on the attacked link, `0.0000` on the other — **disjoint at 99%**, and this is the only statistic that both detects and attributes | yes |
| per-link CHSH, `estimate_chsh` | `2.8284` | `(1−p)·2.8284` twirl; `0.9428` intercept-resend; `1.4142` Z-axis kept share | yes |
| `ChannelSample.purity` | `1.00` | `0.50` for a kept share **only** — the one statistic separating it from intercept-resend, which no correlator can do at any sample size | yes |
| `ChannelSample.concurrence` | `1.00` | `0.00` for both collapse attacks; blind to the twirl | yes |
| `ChannelSample.wings_agree` | `True` | **`True` for all three channel attacks** — reported as a non-signal, see §9 | yes |
| `SessionTranscript.forwarding_altered_signature` | `False` | `True` on every hop attack | yes (harness view — see §9) |
| `AbortReason.RECORD_ALREADY_VERIFIED` in `aborts_by_party` | absent | present on a burned round or a re-presentation | yes |
| `AbortReason.SESSION_MISMATCH` | absent | every cross-session pairing against a stamped log | yes |
| `AbortReason.COUNTS_FROM_TWO_DECLARATIONS` | absent | an altering hop **under `COUNTS_BEFORE_FORWARDING` only** — it vanishes under the other ordering, where the attack succeeds silently | yes |
| declared count as a z-score, `declaration_z_score` | `|z| < ~4` | `z <= −11.54` for the quietest successful starvation at any live `L` | yes |
| declared vs scored count in one transcript, `declared_versus_scored` | equal | declared far below `m_min` beside a scored `~L/3` | yes |
| `SessionTranscript.spent_rounds` | one entry per verifier per round decided | an entry for a round the verifier never accepted; two rounds collapsing to one entry | **yes — new in Phase 3** |
| `SessionTranscript.replay_refusals` | `()` — an honest run asks each verifier once | `(('Bob', 3),)` after three re-presentations, *beside* the standing verdict rather than in place of it | **yes — new in Phase 3** |
| `VerificationAbort.counterpart_matched` on a starved run | absent | the count the counterpart declared, on the abort it caused | yes |
| `SessionTranscript.count_exchange_timing` | `before-forwarding` | says which of the two experiments the run was | **yes — new in Phase 3** |
| `SessionTranscript.repudiated` | `False` | `False` under hop forgery, **correctly** — a detector reading "Bob accepted, Charlie rejected" as repudiation would misattribute every forgery to Alice | yes |

Two requests that could not be answered before are now answered. `spent_rounds` exposes
each verifier's ledger — "this round was spent by this verifier" was previously readable only
off an object the verifier holds, which made every replay statistic unanswerable after the
fact. `replay_refusals` counts the presentations that were *refused*; those used to leave no
trace at all, because filing the refusal as the verifier's outcome would let a replayed
presentation **delete** the acceptance that spent the round — a larger hole than the ledger
closes — so it is counted beside the verdict instead of in place of it.

### What Phase 4 asked for and cannot have

Three requests could not be made reachable, and each is a design fact rather than an omission.

1. **Ground truth — which link Eve touched, which runs a selective starver targeted.**
   `attack.decisions()` and `CountStarver.log` hold it, and a detector may not read them: they
   are the adversary's own bookkeeping. Phase 4 must score its false-positive rate against a
   *labelled harness*, with the labels supplied by the experiment and never by the transcript.
   An untargeted run is byte-identical to an honest one, and that is the correct behaviour.
2. **Cross-run history — "this verifier keeps starving the pair".** `SessionTranscript` is one
   run and nothing in the package accumulates per-party behaviour. Phase 4 must keep its own
   ledger keyed by party. Not a blocker: the per-run z-score is already decisive at a
   false-alarm rate of `2.5e−31`.
3. **Who minted a declaration naming the live round.** The identifier deliberately does not
   cover the declared key, so at the moment Charlie decides, nothing in *his own holdings*
   distinguishes "Alice forged" from "the hop forged". The transcript can tell, because the
   harness holds both declarations — but in a deployment that costs a dispute in which Bob's
   and Charlie's copies are compared. `forwarding_altered_signature` is therefore a harness
   view, not a passive detector, and Phase 4 must not present it as one. The same caveat
   applies to `SessionTranscript.records`, which carries all four post-exchange logs: no single
   party in a deployment holds both verifiers' logs.

---

## 9. Limitations found

**Every one of these is measured or derived, not suspected.**

1. **Full impersonation is undetectable, by construction.** Nothing in `Signature`,
   `RecipientRecord`, `VerificationResult` or `SessionTranscript` names or binds a signer; the
   round identifier binds a declaration to a *distribution*, not to a party. Assumption (AUTH)
   is what excludes her, and only (AUTH). This is a Phase 4 blocker for that scope and is
   inherent to measurement-based QDS, not to this implementation.
2. **The payload line is invisible to both check arms, and totally.** Same `InterceptResend`
   on the two seams under identical seeds: resource line QBER `0.3104` / CHSH `0.9686`; payload
   line QBER **exactly `0.0000`** / CHSH `2.7993`, with equal key damage (mean matched mismatch
   `0.3535` on both). A check round teleports no payload — the seam is consulted there, as it
   is everywhere, and what it returns is discarded — so the arm is blind by construction: no
   partial visibility and no residual to threshold on. The signal that survives is the
   verifiers' own mismatch rate.
3. **`ChannelSample.wings_agree` detects none of these attacks.** No trace-preserving map on
   one half of a maximally entangled pair can change only that half's marginal, so all three
   channel adversaries act on one leg and leave it `True` on every round. It is a detector for
   damping or replacement — its docstring's worked example is a split product state — and its
   docstring now says so.
4. **CHSH cannot attribute at demo check sizing.** `dS` is only about `0.4` at `p = 0.14`
   against a 99% half-width of about `0.37`. A sample-size fact, but any Phase 4 attribution
   built on CHSH needs the full-scale sample and must say so.
5. **Measured CHSH routinely lands above Tsirelson at demo sample sizes** — `3.0425` on a clean
   link over 480 rounds, `2.8410` over 8000. `estimate_chsh` clips only at the algebraic bound,
   which is right, but a Phase 6 dashboard rendering `S = 3.04` next to `ideal 2.83` will read
   as a bug to anyone who has not read that docstring.
6. **No acceptance rate can be measured at `DEFAULT_PARAMS`.** One `L = 115200` session costs
   minutes and the sharpest predicted acceptance is about `1e−103`. What carries to that length
   is the *per-position* statistic — scored fraction and mismatch rate — which follows from the
   Born rule and a uniform basis draw and does not mention `L` at all. The acceptance rates
   measured at demo lengths are the check that the harness composes those per-position
   statistics the way the analysis says.
7. **Below `L = 140` both matched-count floors degenerate and carry no security claim.** Every
   arm below that length is labelled as demonstrating mechanism only, in the test module and in
   the parameter constants themselves. `least_implausible_z` at `L = 192` is `−9.80` rather
   than `−11.54` for exactly this reason.
8. **The `count_exchange` seam is shared but the threat model is not.** `QDSSession` builds one
   `PooledMatchedCounts` and hands it to both verifiers, but a *recipient* controls only his own
   message. An unconstrained seam could edit the counterpart's count, both floors and the
   digest. `CountStarver` restricts itself in code and the tests pin that; anyone writing
   another `count_exchange` adversary must do the same or they will publish a rate for a party
   that does not exist.
9. **The starver has last-mover advantage, deliberately kept.** `CountExchange` is called with
   both messages already computed, so an adversarial seam sees the victim's count before
   choosing. A deployment running Phase C′ simultaneously would force a blind commit. The
   advantage only ever helps the adversary, so the measured attack is the conservative one —
   but the simultaneous variant is a different experiment and is not measured here.

### One reported disagreement, resolved

A channel batch measured QBER `0.2635` on 8000 rounds at `p = 0.5` against an exact prediction
of `0.2500`, with a 99% interval that excluded it — one miss in twelve comparisons at 99%.
Either the sampler is biased or that batch was a high draw, and that is settled by sample size,
not by choosing a different seed: a bias survives a large increase in `n` and a fluctuation
does not.

Pooled over **200,000 rounds across 25 independent batches**: `49800/200000 = 0.249000` against
`0.250000`, `z = −1.03`, and **25/25** per-batch 99% intervals cover the prediction. The
closed form is exact (`qber_from_tensor(depolarising_tensor(p)) == p/2` identically), the
sampler is unbiased, and the reported batch was a `2.8` sigma draw. Pinned by
`test_the_depolarising_sampler_is_unbiased_at_p_equals_one_half` at 80,000 rounds so it cannot
rot.

The other flagged disagreement — the forging recipient under the shipped pooled rule, reported
as `agrees: false` with no prediction available — was not a numerical disagreement at all. It
was the protocol gap of §2b, and it is now measured and agrees.

---

## 10. Mutation checks

A defence with no test that fails when it is removed is not tested. Each mutation switches one
defence off surgically, runs its tests, and restores the file from a scratchpad copy.

| Defence disabled | Mutation | Result |
| --- | --- | --- |
| the consumed-records ledger | `verify()` no longer consults `ledger.is_spent(record)` | **RED** — 12 failures across `test_protocol_replay.py` (5) and `test_attack_replay.py` (7), including `test_after_a_captured_signature_is_refused_every_time_it_is_re_presented` and `test_a_rejection_spends_the_round_and_this_is_the_denial_of_service_price` |
| the declaration binding | `_evidence_refusal` no longer compares the counterpart's digest with the scored declaration's | **RED** — 4 failures, and *only* those four: `test_a_count_against_another_declaration_is_refused_not_pooled`, `test_a_hop_that_alters_the_declaration_stops_the_pooled_floor_passing`, `test_a_seam_that_drops_the_binding_reaches_no_verdict`, and `test_the_shipped_ordering_denies_the_transfer_instead_of_detecting_it`. Honest runs are untouched, which is what a fail-*open* mutation should look like |
| check (a) of the isolation check | `IsolationReport.reads_the_session` returns `False` | **RED** — 24 failures, including every negative control and all thirteen rows of `test_the_session_channel_is_live_on_every_row`. The same mutation applied to a clean checkout of the pre-audit code costs **7** (this document previously said 6, which was wrong; the 7 are all controls) |
| the channel check (a) reaches the candidate by | `observe()` no longer installs the `SessionEnvironment` | **RED** — 18 failures, and this is the shape of the original defect reproduced on demand: every shipped negative control still passes, because each reads the seed through the builder, and only the per-row channel evidence goes red |

All four sites verified byte-identical to their originals afterwards.

---

## 11. Conventions

**D1 — `DensityMatrix` canonical.** Every channel attack accepts and returns density
matrices; `KeptShareSwap` returns the reduced two-qubit state of a three-qubit GHZ, which has
no state-vector representation, so the convention is load-bearing rather than stylistic here.

**D2 — little-endian, pinned by asymmetric states.** The kept-share marginal
`(|00><00| + |11><11|)/2` is symmetric and cannot pin an ordering; the tests that do use the
asymmetric collapse tensors.

**D3 — injected generators throughout.** Every adversary takes its own
`numpy.random.Generator`; no module reaches for global `numpy.random` or stdlib `random`, and
an adversary that does is now caught by check (a) rather than merely asked not to. The
`measure_*` functions take the world's generator and the adversary's separately and **refuse
the same *stream* for both** — the same object, the same position in one stream, or two
generators built from one seed, which is one stream byte for byte and is the form the mistake
actually takes. `run_impersonation`, `measure_impersonation` and `measure_starvation` take a
session *seed* and an adversary *generator*, and now refuse the seed-shaped version of the same
collision; before the audit those three had no guard at all.

**D4 — no AI/ML.** Correlation tensors, binomial sums, Wilson intervals, one Chernoff tail and
one bisection on `math.erf`. Nothing is learned, fitted or thresholded from data; every cut
comes from `ProtocolParams` and was fixed before any run started.

**D5 — load-bearing numbers in doctests.** `pyproject` runs `--doctest-modules` over `sih141`,
so every numeric claim written as an executable example is a live test. The numbers in *this*
document are prose and are therefore **not** checked by the suite — every one of them is
reproduced by `tests/test_phase3_integration.py`, which is, and which is where a reader should
check them.

**D6 — attacks own their randomness.** §7. This is the convention Phase 3 added, and it is the
one the whole phase's arithmetic rests on.

---

## 12. Cost

| Arm | Cost |
| --- | --- |
| one `L = 30` session | ~0.06 s |
| one `L = 60` session with a forwarding attack | ~0.12 s |
| one `L = 192` session | ~0.36 s |
| one standalone check round | ~0.3 ms |
| `tests/test_phase3_integration.py` | 40 tests, **~3 min 40 s** |
| `tests/test_phase3_isolation_suite.py` | 50 tests, **16 s** |
| `tests/test_attack_isolation.py` | 48 tests, **3 s** |
| one `DEFAULT_PARAMS` session | minutes — out of reach for any repeated-trials measurement |
| the **whole suite** (`python -m pytest`) | **2166 passed in 765.56s (0:12:45)** |

The heavy shipped tables (800 impersonation sessions at `L = 192`, 8 minutes; 2000 outside
forgeries at `L = 30`) are **not** in the unit suite. What is in the suite is a smaller live
arm plus a prefix of each documented reproduction recipe, so a recipe cannot rot silently.
