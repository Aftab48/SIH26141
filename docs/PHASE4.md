# Phase 4: Detection, and the difference between a derivation and a fit

Engineering note for `sih141.detect`. Covers the statistics a detector may legitimately read,
the twenty-two thresholds derived over them, the composite rule that combines three families
under one false-positive budget, the measured detection rates against all five adversaries,
and every conditioning caveat those numbers carry, including the one inherited from Phase 3.

**Before quoting any check-round number from here, read §8.** Every channel statistic in this
phase is conditioned on **(NO-TIMING)**, stated in `docs/PHASE3.md` §12. The statistics that
read the *key* rather than the check sample are not.

Status: complete. The phase ships the `sih141/detect/` package, holding the statistics layer,
three threshold families and the composite rule. Integrating them also reached outside the
package four times, and each is recorded rather than folded in silently: **two check-round side
channels closed** in `sih141/protocol/distribute.py` (§9), **one bug fixed** in
`sih141/protocol/checkrounds.py` (§9), and **one unproven constant replaced** in
`sih141/detect/statistics.py` (§9). Nothing under `sih141/attacks/` was touched.

## 0. The one thing this phase is for

A machine-learning detector reports **"97% accurate on our data."** This one reports:

> the probability of a false alarm is at most `3.3964e-10`, and here is the derivation.

That difference is the submission's whole argument, and it is fragile in one specific way: the
moment a threshold is chosen because it separates the attack runs in front of you, the scheme's
information-theoretic security is silently capped at whatever your test set happened to
contain. Convention **D7** forbids it:

> Every threshold this phase ships comes from (i) a stated null distribution, written down,
> and (ii) a concentration inequality applied to it, with the algebra shown, and carries a
> **provable** false-positive bound, a sentence of the form *"under the null, this fires with
> probability at most X, and here is why"*, never an observed rate.
>
> **Corollary.** You may look at honest-run data to *check* that a derived threshold behaves
> as derived. You may not look at attack data to *choose* one.

### The audit, one threshold at a time

Every shipped threshold was audited against three questions. A threshold that cannot answer
all three is fitted whatever its docstring says.

1. **Is the null actually stated?** Checked as data, not as prose: every carrier type has a
   mandatory non-empty `null` field, and `ThresholdView` reads all three families through it.
2. **Is the inequality actually applied?** Checked two ways, neither of which trusts the
   module's own arithmetic. The tail at each shipped critical value is recomputed in
   `fractions.Fraction` **rational arithmetic** and required to sit at or below the reported
   bound, which is required to sit at or below the budget. And, in the sharper test, each
   threshold is swept across **ten decades of budget** and required to move with it. A number
   somebody chose does not.
3. **Does the proven bound hold against the measured honest-run rate?** Measured on honest
   corpora at four configurations and scored against the bound by an exact binomial surprise,
   never against a tolerance picked by eye.

**What "22 thresholds" counts, so the number is checkable rather than asserted:**

```
len(RATE_COUNT_ROSTER)     12   the twelve budgeted rate-and-count names
len(RATE_COUNT_FREE_TESTS)  1   declaration_gap, charged nothing
len(CHANNEL_STATISTICS)     5   qber, chsh, fidelity, purity, concurrence
len(STRUCTURAL_CHECKS)      4   structural / evidence / replay / run-shape
                           --
                           22
```

Two more derived objects ship beside them and are audited with them, but are deliberately not
roster members: the **CHSH certificate**, which is not an alarm, and the **abort-shortfall**
magnitude, which is not a check. So 24 were audited. Several of the 22 ship **two nulls**: a
noiseless point mass and a noise-tolerant law. Both were audited separately.

**Result: 22 of 22 pass, individually, and so do the two non-roster members.** The
per-threshold verdicts are the table in §2, whose `proven bound` and `measured` columns are
questions 2 and 3. Two members needed judgement rather than a mechanical pass and are recorded
here so the count is not hiding them:

* **`evidence-abort`** fails a naive reading of question 2: its critical value is `1` at
  every budget. It is not a constant. Its statistic is a count in `{0, 1, 2}` and *any* abort
  is already the event, so the budget decides **admissibility** rather than the critical value:
  below `3 · 2⁻⁶⁴` no key length reaches the budget and the check is **withheld** (`fires_at`
  becomes `None`) rather than fired at a bar the derivation does not reach. What is a function
  of `n` is the *bound*: `1.1881e-04` at `n = 24`, `2.4904e-17` at `n = 96`, settling on
  `1.6263e-19` above `n = 273`. It is independently reproduced against the exact union of
  three binomial lower tails wherever that is computable.
* **`abort-shortfall`** returns `1` at every budget at or above `2⁻⁶⁴`, and the collapse *is*
  the result. The protocol's floors were already calibrated at that budget and spend all of
  it, so the abort itself is the threshold and its magnitude adds no detection power. The knob
  only turns below `2⁻⁶⁴` (`83` records at `1e-21`, `341` at `1e-27`). Reported as a collapse
  rather than dressed up, because claiming it separates anything at a usable budget would be
  exactly the fitting D7 forbids.

### Ten thresholds cost exactly nothing, and the cost of that is stated

**Ten** of the twenty-two have **point-mass nulls**: nine budgeted members
(`mismatch_rate` at both verifiers, `qber_errors`, `fidelity`, `purity`,
`concurrence`, `structural-abort`, `replay-refusal`, `run-shape`) plus the free
`declaration_gap`. On a noiseless honest run the event they fire on is outside the outcome
space rather than merely improbable, so the false-positive probability is **exactly `0`** at
every budget, at every key length. That is the strongest bound in the phase and it is free.

The cost is stated with the claim rather than left for a reader to find: *it is a claim about
a noiseless link*. On an honest run over a genuinely noisy channel those same members fire on
every link, correctly, because the null was the wrong one for that deployment. Hand the
family the run's own noise level and the same links go quiet at a budget of `0.05`.
`tolerated_depolarising` and `channel_error_rate` default to `0` and must come from outside;
the transcript carries no independent estimate of what an honest channel should look like
(finding F2, §9).

## 1. The boundary, and why it is the code rather than a convention

The detector reads a `SessionTranscript` **that has been round-tripped through JSON**, and
nothing else. Not the session object, not the adversary, not any harness state.

This is not a style preference. A detection rate measured by something that can see the
adversary's log is not a detection rate; it is a restatement of the ground truth, and Phase 3
paid for that lesson twice. So the boundary is enforced structurally:

* `TranscriptStatistics.from_transcript(t)` is **defined** as `from_json(t.to_json())`. It
  serialises and re-reads even when handed a live object, so anything that does not survive a
  transcript file is gone by construction rather than by discipline.
* A test reads the package's own source and asserts it imports nothing from `sih141.attacks`.
  A static edge from the detector to the adversary suite would mean the shipped detector could
  not be built without the adversaries it is measured against.
* `detect()` takes a transcript and a budget. Its parameter list is asserted by a test, and
  there is no `rng` and no seam for a harness.

Anything a detector wants that is not reachable this way is a **finding to report**, not a
reason to reach further. Ten of them are in §9.

## 2. Every threshold, with its null, its inequality, its bound and its measured rate

Operating point: `L = 384`, sifted `n = 384` for the count members (the `check_fraction = 0`
arm) and `24` QBER / `24` CHSH rounds per link for the channel members (the
`check_fraction = 0.25` arm).

**How the `measured` column was obtained.** From the honest corpus of §5: 120 honest runs
across three configurations for the rate and structural members, and the 40 runs of the
`check_fraction = 0.25` arm for the channel members, which are the only ones on which a channel
member is evaluable at all. Not one honest run produced a signal of **any** kind, run-shape
signals included (they are counted here even though they are excluded from the detection
column), so `0/120` and `0/40` are per-member figures rather than a composite silence.

**Each table is at its family's own budget of `eps = 1e-9`, standalone.** A family's budget is
then divided over its own roster before it reaches a member (`eps/12` for a rate member,
`eps/4` per link and `eps/5` per member for a channel one), so the `proven bound` column is
what that member proves at **its own share**, never at `eps`. Inside the composite of §4 each
family gets less than `1e-9` (the rate and channel families get `5e-10` each), so the members'
critical values there are a little further out and their bounds a little smaller. The composite
figures in §4 are the ones to publish; these are the ones to read a derivation against.

### 2a. The rate-and-count family: twelve budgeted members plus one free

Twelve roster names at `eps/12` each. `R` ranges over the two verifiers.

| member | null | inequality | critical | proven bound | measured (honest) |
| --- | --- | --- | --- | --- | --- |
| `mismatch_rate:R` (noiseless) | point mass at `0`: on a noiseless link every matched position reproduces the declared eigenvalue with probability one | none needed, the point mass is answered exactly | `1` | **exactly `0`** | `0/120` |
| `mismatch_rate:R` (`p_e = 0.01`) | `Binomial(m, p_e)` conditionally on the observed matched count `m`, carried through by the tower rule | exact binomial upper tail | `17` | `3.2406e-11` | see §5 |
| `matched_count_low:R` | `Binomial(384, 1/3)`, unconditionally over the symmetrisation coins | exact binomial lower tail | `71` | `6.6380e-11` | `0/120` |
| `matched_count_high:R` | as above | exact binomial upper tail | `190` | `4.8376e-11` | `0/120` |
| `declared_count_low:R` | `Binomial(384, 1/3)`: on an honest run the Phase C′ wire integer *is* the count he then scores | exact binomial lower tail | `71` | `6.6380e-11` | `0/120` |
| `declared_count_high:R` | as above | exact binomial upper tail | `190` | `4.8376e-11` | `0/120` |
| `pooled_count_low` | `Binomial(768, 1/3)`, exact by **conservation** under the coins, never by convolving the two marginals | exact binomial lower tail | `174` | `5.8530e-11` | `0/120` |
| `pooled_count_high` | as above | exact binomial upper tail | `342` | `7.5676e-11` | `0/120` |
| `declaration_gap` *(free)* | point mass at `0`, and not a probabilistic statement at all: each recipient declares the count he then scores, so the two integers are the same integer by construction | none required | `≠ 0` | **exactly `0`** | `0/120` |

`declaration_gap` is charged **nothing** from the family budget, because the union bound
divides `eps` over the twelve budgeted names and this thirteenth test contributes a zero term.
It is the strongest member and the cheapest.

**The pooled members are weaker than the per-verifier ones against a one-party deviation, by
exactly `√2`**, and this is derived rather than observed: the shift is unchanged while the
null's spread grows like `√(2n)`. At `DEFAULT_PARAMS` the per-verifier separation is `240.0`
standard deviations and the pooled one `169.7056`. The pooled members are kept for a shortfall
in the *total* evidence base, not for this.

### 2b. The channel family: per link, per message bit, never pooled

Five members at `eps/4` per link-and-bit, then `eps/20` per member. Constraint 3 of Phase 3:
symmetrisation smears the *records* but never the *check logs*, so per-link QBER is the only
statistic that both detects a party-targeted channel attack **and attributes it**. There is no
pooling export in the module and a test asserts its absence.

| member | null | inequality | critical | proven bound | measured (honest) |
| --- | --- | --- | --- | --- | --- |
| `qber_errors` (noiseless) | point mass at `0`: `E ~ Binomial(n, p₀/2)` at `p₀ = 0` is a non-negative variable with zero mean | none, a point mass | `1` | **exactly `0`** | `0/40` |
| `qber_errors` (`p₀ = 1/32`) | `Binomial(24, 0.015625)` conditional on the check plan | exact binomial upper tail | `10` | `1.3926e-12` | see §8 |
| `chsh` (detection) | `E[S] = (1 − p₀)·2√2`, over `24` independent rounds in cells `(6,6,6,6)` | **McDiarmid** bounded differences, one-sided | `−2.7952` | `5.0000e-11` | `0/40` |
| `fidelity` (ideal) | point mass at `1`: a bounded variable whose mean sits on its own supremum is degenerate | none, a point mass | `1.0000` | **exactly `0`** | `0/40` |
| `purity` (ideal) | as above | none, a point mass | `1.0000` | **exactly `0`** | `0/40` |
| `concurrence` (ideal) | as above | none, a point mass | `1.0000` | **exactly `0`** | `0/40` |
| `chsh` **certificate**, *not an alarm* | `S_true ≤ 2`, the classical bound: a statement about the **resource**, not the channel | McDiarmid, upper tail | `7.6236` | `5.0000e-11` | n/a |

Two things about this table that a Phase 5 author must carry forward.

**A missing certificate is not a detection.** `chsh_certificate_threshold` carries
`is_alarm=False` and `screen_link` refuses to evaluate a non-alarm. A short sample cannot
certify anything, so *"CHSH failed to certify on N runs"* is a statement about the sample size,
not about the runs. It also carries a **second** assumption that is easy to drop: it is *not*
device-independent, it certifies under **(AUTH)** that both endpoints measured at the announced
settings, and a test fails if that sentence leaves its docstring.

**An unavailable statistic is never a cleared one.** `ChannelScreen` keeps `unavailable`
(a mapping of name to reason) separate from `cleared`, and `ChannelThreshold.fires(None)`
raises rather than returning `False`. Three things land in `unavailable`: a link with no QBER
rounds, a CHSH statistic with an empty cell (McDiarmid's bounded-difference constant `2/n_c`
is then infinite), and an **unmonitored** link, where an adversary who substitutes his own
states consumes no entanglement and leaves the sample empty. Summing `cleared` and
`unavailable` into one column is how a table reports a clean bill of health that never happened.

**At a toy length the family has four working members, not five.** Measured *after* the
derivations were frozen: at `L = 384` with `eps = 1e-9` and the noiseless null, the CHSH member
fires on nothing at all, because at 24 CHSH rounds and a share of `5e-11` the critical value is
about `−2.80`, below the classical bound, so that sample can only see a resource whose
correlations were *inverted*. Any ROC curve drawn from this family at a toy length is measuring
four members and should say so.

### 2c. The structural family: aborts, refusals, run shape

Four checks plus one magnitude threshold. **Three of the four cost exactly zero**, and that is
the shape of the family rather than an accident: their events are decided by equality tests on
data the honest protocol fixes, not by any random draw.

| member | null | inequality | critical | proven bound | measured (honest) |
| --- | --- | --- | --- | --- | --- |
| `structural-abort` | point mass at `0`: each of the four structural reasons is an equality test on data the honest protocol fixes | none, a point mass | `1` | **exactly `0`** | `0/120` |
| `evidence-abort` | union of three binomial lower tails: `m_B, m_C ~ Binomial(n, 1/3)` and `M ~ Binomial(2n, 1/3)` | multiplicative Chernoff lower tail at `eps₀ = 2⁻⁶⁴`, exact point mass where a floor degenerates, union bound over the three floor events | `1` | `1.6263e-19` | `0/120` |
| `replay-refusal` | point mass at `0`: an honest run asks each verifier once per `(session, bit)` and the ledger check is set membership | none, a point mass | `1` | **exactly `0`** | `0/120` |
| `run-shape` | point mass at `0`: six equalities the shipped session satisfies by construction | none, a point mass | `1` | **exactly `0`** | `0/120` |
| `abort-shortfall` | the count behind the shortfall is `Binomial(n, 1/3)` (or `Binomial(2n, 1/3)` for the pooled floor) | multiplicative Chernoff lower tail, **inverted** | `1` (collapsed) | `3.7774e-20` | `0/120` |

**"Was the evidence thin, or did somebody make it thin?" resolves rather than needing a second
statistic.** An honest evidence abort has probability at most `1.6263e-19`, so at that cost an
abort *is* somebody's doing. What remains is attribution (whose count was short), and
`attribute_aborts` reads that off the reason and the shortfall.

**The two abort groups carry different bounds and must never be summed.**
`STRUCTURAL_ABORT_REASONS` cannot occur on an honest run at any key length, so firing on
`structural > 0` costs exactly zero. `EVIDENCE_ABORT_REASONS` are bounded by the floors' own
Chernoff derivation. A test asserts the two frozensets are disjoint and their union is exactly
`set(AbortReason)`, so a reason added upstream fails here rather than quietly joining the group
with the weaker bound.

**Run-shape violations are excluded from the detection column** (`Detection.detected` and
`StructuralReport.detection_alarms` both drop them). A run-shape violation is a statement about
the transcript **file**, not about an adversary: `from_dict` defaults `spent_rounds` to `()`,
so a file written before the replay ledger existed is byte-indistinguishable from one whose
verifiers reached verdicts without spending a round. Counting it would inflate a detection
column with a plumbing fact. It is still on `Detection.signals` with `is_detection=False`.

## 3. Constraint 4, enforced by type rather than by prose

> **No verdict is not a rejection.** Aborts are a separate transcript field with a separate
> type precisely so that no statistic can average a refusal into a rejection. Folding them
> together reports a detection that never happened, the single most likely way for a Phase 5
> table to be wrong.

Three guards, none of them a comment:

* `RunOutcome` raises `TypeError` on `bool()`, so `if outcome:` stops rather than silently
  treating a refusal as falsy.
* `NoVerdictCount` is an `int` that refuses `+` with anything but another `NoVerdictCount`, so
  `tally.rejected + tally.refused` **and** `sum(...)` both raise. Totalling refusals on purpose
  is `NoVerdictCount.total`, which cannot be reached by accident.
* `TranscriptStatistics.verifier(party)` raises `KeyError` for a party who reached no verdict,
  with a message distinguishing *"asked and refused to score"* from *"never asked"*,
  deliberately not `None` and not `False`, either of which a caller eventually reads as a
  rejection.

`OutcomeTally` has no field that sums two of the four counts, and its `merge()` refuses two
tallies from different `count_exchange_timing` values.

## 4. The composite rule, and the family-wise bound

Firing when **any** threshold fires has a false-positive rate far worse than any single
threshold's, and nothing inside a component would ever say so. Three decisions, all made before
any run existed.

**C-1, the correction: a union bound, and no independence assumed.** None is available: the
rate and structural families both read the matched counts, and every channel screen shares the
symmetrisation coins with every rate member. Šidák is rejected because it needs independence
and buys a factor of about `1 + eps/2`. Holm and Simes are rejected for a deeper reason: a
derived threshold carries a **bound on a tail**, not a p-value, and ten members are point
masses whose only attainable p-value is `0` or `1`. Dropping quiet members is rejected as
fitting. The slack is stated, not absorbed.

**C-2, the allocation.** The structural family's proven bound is `B_evid(n)` whatever share it
is given (its share decides only *admissibility*), so it is charged exactly
`min(B_evid(n), eps/3)` and the rest splits in half. The cap makes the split provably never
worse than an even third. At `L = 384, f = 0.25` (sifted `n = 288`) and `eps = 1e-9`:

```
eps_struct = min(B_evid, eps/3) = min(1.6263e-19, 3.3333e-10) = 1.6263e-19
eps_rate   = eps_chan = (eps - eps_struct)/2 = 5.0000e-10
sum        = eps      = 1.0000e-09
```

The channel share divides again over a `LINK_ROSTER` **fixed at four**, not sized to the run:
the run's configuration is a constant under the null but not under an adversary.

**What it proves, and what an uncorrected OR would have proved.** At `L = 384`,
`check_fraction = 0.25`, `eps = 1e-9`:

| | proven |
| --- | --- |
| rate family | `2.3964e-10` |
| structural family | `1.6263e-19` |
| channel family | `1.0000e-10` |
| **composite (union bound)** | **`3.3964e-10`** |
| slack factor against the budget | `2.944` |
| *the same members OR'd naively* | `1.3442e-09`, which **overspends the budget by a third** |

Every one of those figures is a doctest.

### Three numbers that are not each other

* **`Detection.false_positive_bound`** is the number to publish. At the operating point above
  it differs from `eps` by a factor of `2.944`; quoting the budget would overstate the
  detector's own false-alarm rate by exactly that.
* **`Detection.slack_factor`** is that ratio.
* **`Detection.evidence_bound`** is a **third** number and a different statement (post hoc,
  over the set of signals that actually fired), and must never be plotted as the detector's
  error rate.

### Two things to check before plotting a point

* **`Detection.bound_is_unconditional`.** At a positive `channel_error_rate` the rate family's
  mismatch members are conditioned on the run's observed matched counts; the summed bound is
  then a bound on `P(fire | matched counts)`, and `eps` is what remains unconditionally true.
  It is `True` at the default noiseless null.
* **`Detection.withheld` is not `cleared`.** On a run with no check rounds it carries an
  explicit line saying the whole channel family was unevaluable. Half the budget is unspendable
  there; the composite proves `2.6499e-10` at `L = 192` with slack `3.77`, and the roster is
  deliberately **not** resized to reclaim it.

## 5. Detection rates, per adversary

`L = 384`, `eps = 1e-9`, 40 runs per arm, `detect()` reading a JSON round-tripped transcript
and nothing else. Every threshold was frozen before any of this ran. Intervals are **Wilson**
score intervals at 99%, because almost every rate here is `0/40` or `40/40`, where the normal
interval is a degenerate point and would claim certainty from a finite experiment.

**Grouped by `count_exchange_timing`, never averaged over it** (Phase 3 constraint 6).

| arm | ordering | detected | 99% Wilson | signals | hypotheses named |
| --- | --- | --- | --- | --- | --- |
| *honest -- the false-alarm denominator* | | | | | |
| honest (no check rounds) | `before-forwarding` | 0/40 | `[0.0000, 0.1423]` | *none* | `honest` |
| honest (check_fraction=0.25) | `before-forwarding` | 0/40 | `[0.0000, 0.1423]` | *none* | `honest` |
| honest (after-forwarding) | `after-forwarding` | 0/40 | `[0.0000, 0.1423]` | *none* | `honest` |
| **1. Forgery, outside** | | | | | |
| forgery: outside | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| forgery: outside | `after-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| **2. Forgery, forging recipient** | | | | | |
| forgery: recipient | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `forwarding-tamper` | `recipient-forgery` + `replay` |
| forgery: recipient | `after-forwarding` | 40/40 | `[0.8577, 1.0000]` | `count-high`, `forwarding-tamper`, `mismatch` | `recipient-forgery` |
| **3. Impersonation** | | | | | |
| impersonation: signing | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| impersonation: distribution | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| impersonation: full | `before-forwarding` | 0/40 | `[0.0000, 0.1423]` | *none* | `honest` |
| **4. Replay** | | | | | |
| replay: replaying forwarder (capture at run length) | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `forwarding-tamper` | `recipient-forgery` + `replay` |
| replay: replaying forwarder (capture at run length) | `after-forwarding` | 40/40 | `[0.8577, 1.0000]` | `forwarding-tamper`, `mismatch` | `recipient-forgery` + `replay` |
| **5. Channel manipulation** | | | | | |
| channel: depolariser p=0.60 (Bob) [check=0.0] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| channel: depolariser p=0.60 (Bob) [check=0.25] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `channel`, `mismatch` | **the substitution group** (5) |
| channel: depolariser p=0.10 (Bob) [check=0.0] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| channel: depolariser p=0.10 (Bob) [check=0.25] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `channel`, `mismatch` | **the substitution group** (5) x39; `channel-manipulation` x1 |
| channel: intercept-resend (Bob) [check=0.0] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| channel: intercept-resend (Bob) [check=0.25] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `channel`, `mismatch` | **the substitution group** (5) |
| channel: kept-share swap (Bob) [check=0.0] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `mismatch` | **the substitution group** (5) |
| channel: kept-share swap (Bob) [check=0.25] | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `channel`, `mismatch` | **the substitution group** (5) |
| **6. Count starvation** | | | | | |
| count starvation | `before-forwarding` | 40/40 | `[0.8577, 1.0000]` | `count-low`, `evidence-shortfall` | `count-starvation` |
| count starvation | `after-forwarding` | 40/40 | `[0.8577, 1.0000]` | `count-low`, `evidence-shortfall` | `count-starvation` |

***the substitution group** is the five hypotheses a substituted or corrupted declaration leaves standing: `outside-forgery`, `impersonation-signing-seam`, `impersonation-distribution-seam`, `replay` and `channel-manipulation`. Naming the group rather than picking one of them is the honest output of a transcript-only detector; see below.*


### What the numbers say

**All five adversary families are detected at `40/40`, on every arm and every ordering, with
one stated exception inside the impersonation family, and `0/120` false alarms.** Of the 19
attack arms, **18 are at `40/40`**, each with a 99% Wilson interval of `[0.8577, 1.0000]`; the
nineteenth is `impersonation: full` at `0/40`, which is assumption **(AUTH)** rather than a
miss.

**Against the Phase 3 prototype**, which separated *four of five adversaries at 100% with
`0/80` false alarms* on a threshold-only detector reading a round-tripped transcript: the
derived detector is at least as sensitive on every family it was compared on, and it replaces
an *observed* false-alarm rate with a *proven* one.

Two cautions on that comparison, because it is the one a reader will want to quote. The two
experiments do not share a parameter set, a seed set or an arm list, so the sensible reading is
"the derivation did not cost detection", not "the derived detector is better". And the honest
comparison is not really rate against rate at all: `0/80` and `0/120` are both consistent with
a true false-alarm rate of a few percent, whereas `3.3964e-10` is a statement about every run
that will ever be scored. The sample size is what the derivation makes irrelevant.

**The false-alarm side is the load-bearing half, and it is now a proof rather than an
observation.** `0/120` honest runs across three configurations, at a composite bound of
`2.7818e-10` on the unchecked arm and `3.1464e-10` or `3.3964e-10` on the checked one. The
Phase 3 prototype reported `0/80`, a comparable *observation*. What changed is not the number
of false alarms but what can be said about the next hundred thousand runs.

*The checked arm shows two different bounds because the bound is computed per run, not fixed:
a run whose own check plan leaves one channel member unevaluable (a CHSH cell that came up
empty, say) spends less of the budget and proves a smaller number. Reporting the larger one
for every run would be safe but would overstate what the quiet runs actually cost.*

**The detection rate did not go down, and that deserves saying plainly.** A derived threshold
is normally *less* sensitive than one tuned to the data in front of you, and a lower rate here
would have been a legitimate and more honest result. It did not happen, for a reason that is
visible in the `kinds` column rather than lucky. The separations these five adversaries produce
are enormous: a substituted declaration puts the mismatch rate at `1/2` against a null that is
a **point mass at 0**, so the derived cut sits nowhere near the boundary. The derivation cost
nothing in power here **and it would still be the right choice if it had**, because the
alternative is a detector whose false-positive rate is only known on the runs it was built
from.

**Detection is carried by the mismatch signal, which is Phase 3 constraint 1 restated as a
measurement.** Every channel arm is detected at `check_fraction = 0.0` (where the entire
channel family is unevaluable and contributes nothing) on the verifier's own mismatch rate
alone. The verifier rate really is the strongest and cheapest signal, and it needs no check
rounds at all.

**Where the composite is coarse, it says so instead of guessing.** Outside forgery,
signing-seam impersonation, distribution-seam impersonation and all four channel attacks are
each detected `40/40` and each named as the **same five-way group**. That is the honest output
of a transcript-only detector: a substituted or corrupted declaration is visible, and *which*
position produced it is not. A detector that picked one would be inventing an attribution.

**The channel family earns its place exactly once in this sweep, and the table shows it.** On
`1` of the `40` runs of the `p = 0.10` depolariser at `check_fraction = 0.25`, the channel
screen fired hard enough on Bob's link to exclude the rest of the substitution group and name
`channel-manipulation` **alone**; the other `39` name the group. That is a per-link attribution
the mismatch rate cannot make at all (§8, last bullet), and it is worth one row rather than a
headline: at this length the channel family has four working members and a `24`-round CHSH
sample that can fire on nothing (§2b). A longer check budget is what would turn that `1/40` into
a rate worth quoting.

**Constraint 5, working in the direction that matters.** No channel arm is ever named a
recipient forgery (`recipient-forgery` does not appear in any channel arm's named set), because
that hypothesis *requires* an inflated matched count and a channel adversary moves no basis.
Phase 3 measured plain depolarising noise producing `repudiated == True` with a completely
honest Alice; the composite does not repeat that mistake, and it does not repeat it as a
property of the deduction table rather than as a coincidence of these seeds.

**Two arms are named uniquely, and both are count-driven.** Count starvation is named alone on
both orderings (`count-low` plus `evidence-shortfall`). Recipient forgery is named alone under
`COUNTS_AFTER_FORWARDING`, on `count-high`, which is exactly the discriminator Phase 3
constraint 5 identified, Charlie's matched count, and *not* `transcript.repudiated`, which
cannot separate signer misbehaviour from noise.

**The two orderings give different answers to the same attack, as predicted.** Under
`COUNTS_AFTER_FORWARDING` recipient forgery is a forgery Charlie scores and is named alone;
under `COUNTS_BEFORE_FORWARDING` it is a denial of service Charlie refuses, detected on the
structural forwarding-tamper signal (which the rate family alone would have missed) and named
as the pair that holds the forwarding hop. Averaging the two would publish one number for two
different experiments.

**Full impersonation: `0/40`, and it is reported rather than missing.** Mallory on both of
Alice's seams produces a run drawn from the honest law; no derived threshold can fire and a
detector that reported anything here would be reporting its own noise. It appears on every
`Detection` as `undetectable-by-construction` citing **(AUTH)**. See §7.

### One arm was measured twice, and the first measurement was wrong

The replay arm first came out `0/40`, which would have been a striking result. It was a
**wiring** artefact and not a detector result, and it is recorded here rather than quietly
fixed. `ReplayingForwarder(captures=None)` mints its default capture at `key_length = 24`
(`CAPTURE_PARAMS`), and `__call__` declines a capture whose shape does not match the live
declaration, so at `L = 384` the adversary forwarded **honestly** on every call and the arm
was measuring nothing at all. The `0/40` was correct about the runs it produced and said
nothing about the detector.

Re-measured with the capture minted at the run's own length (which is also the more faithful
adversary, a genuine cross-session replay of a full-length declaration), the arm is the row
above. The lesson generalises: **an adversary arm that reports zero should be checked for
whether it ran** before it is published, and this one only announced itself because every other
arm in the same sweep was `40/40`.

## 6. Mutation checks

A green suite proves nothing about a test that cannot fail. Seven one-idea reversions, each
applied to its **own copy** of the tree in the system temp directory, and each copy's relevant
tests then run. The working tree is never touched, because other agents work in it
concurrently. **All seven go RED**, and the assertion that caught each one is recorded, because
*which* test fires says whether the defence is guarded where it was meant to be.

| | mutation | caught by | verdict |
| --- | --- | --- | --- |
| **M1** | a threshold's derivation replaced by a **constant** that separates this project's own honest and attacked data | `test_a_lower_threshold_is_certified_at_its_own_budget`: the exact binomial tail at the returned count is `0.9976` against a budget of `0.01` | **RED** |
| **M2** | the family-wise correction removed: every family handed the **whole** budget (the naive OR, over-spending) | `test_the_three_shares_sum_to_the_budget`: `FamilyBudget` refuses a split whose shares do not sum to `eps`, so the naive OR is *unrepresentable* rather than merely wrong | **RED** |
| **M2b** | the union bound dropped while the allocation is kept: the three families combined by `max` instead of `sum` (the naive OR, **under-reporting**) | `test_the_composite_bound_is_the_sum_of_the_three_families`: reports `2.3963e-10` where the sum is `3.3964e-10` | **RED** |
| **M3** | **an abort folded into the rejection column**: the `NoVerdictCount.__add__` guard removed | `test_a_no_verdict_count_refuses_to_be_added_to_a_verdict_count`: DID NOT RAISE | **RED** |
| **M4** | the route-H payload validation reverted | `test_a_malformed_payload_no_longer_says_which_branch_a_position_took`: the terminal event takes **2** values over one link's positions, and the message prints the surviving positions, i.e. the check set | **RED** |
| **M5** | the route-I resource validation reverted | `test_the_resource_seam_refuses_a_malformed_pair_from_one_place`: two raise sites, `checkrounds.py:_as_resource` and `teleport.py:_resource_density` | **RED** |
| **M6** | the float dust put back in the protocol's Wilson interval | `test_the_two_wilson_intervals_agree_to_the_bit_at_both_endpoints` | **RED** |

**M3 is constraint 4 and it matters most**, so it is worth saying exactly what stops it. The
mutation removed only the *arithmetic* guard, and the suite still caught it immediately,
because the guard is a type, not a convention, and the test asserts the `TypeError` rather than
asserting a number that happens to come out right.

**M2 is worth reading twice for a different reason.** The naive OR was caught not by a bound
comparison but by an **invariant inside the module**: `FamilyBudget` refuses to construct a
split whose shares do not sum to the budget, because the union bound of C-1 is only a bound on
`eps` when they do. That is a stronger position than catching it downstream: the mistake
cannot be represented. M2b was added precisely because M2 alone would have left the *other*
half of "ORs naively" untested: dropping the union bound while keeping the allocation
under-reports rather than over-spends, and a detector that under-reports its own error rate is
the more dangerous of the two.

## 7. What is undetectable, and why

**Full impersonation.** Mallory on *both* of Alice's seams produces a run that is internally
consistent in every respect: the declaration matches the records because she made both. There
is no statistic to build. This is assumption **(AUTH)**, stated openly rather than patched
around, and Phase 3 measured it at `200/200` accepted.

It must appear in any results table as **`undetectable-by-construction`**, never as a blank or
a miss. The attribution is present on every `Detection` with `false_positive_bound=None` and
`(AUTH)` in its rationale, and `summary()` always prints the line; a hypothesis silently
missing from a table reads as one that was ruled out.

**`wings_agree` is a non-signal, and no detector is built on it.** No trace-preserving map on
one half of a maximally entangled pair can change only that half's marginal, so every channel
adversary leaves it `True` on every round. Measured again this phase: under intercept-resend on
Bob's link, concurrence collapses to `0` and fidelity to `0.5` while **both** wing purities move
to `1.0` together, so the boolean that compares them reports nothing. It is excluded from the
package with an importable `why_wings_agree_is_absent()` and a test that scans the source for
`.wings_agree`.

**Three signals are unreachable and should stay so.** Which link Eve touched, and which runs a
selective starver targeted, live on the **adversary's log**, and a detector may not read one.
An untargeted run is byte-identical to an honest one, and correctly so. False-positive rates are
scored against a labelled harness instead.

**There is no false-negative bound anywhere in this layer, and there cannot be one from a
transcript.** Every bound in this phase is under the honest null. The per-arm detection rates
in §5 are measurements with a sample size, not guarantees. In particular, **a clear channel
screen does not exclude a channel adversary.**

## 8. Conditioning caveats: read before quoting anything

### (NO-TIMING), inherited from Phase 3

> Every claim this project makes about **check-round statistics** (the per-link QBER and CHSH,
> the `ChannelSample` rows behind them, and everything Phase 4 or Phase 5 builds on them) is
> conditioned on the adversary not inferring the check set from timing.

Cite it the way §3 of `docs/PHASE3.md` cites **(AUTH)**: as a stated assumption with a named
boundary, not as an oversight. Two things bound how much it carries.

1. **It does not touch the strongest detector signal**, and §5 measures how much that is worth.
   The verifier's own mismatch rate, the matched counts, the declared-count tails and every
   abort reason read the **key**, not the sample, and a spare-the-watched adversary damages the
   key by construction. So everything in §2a and §2c is unaffected; it is the check-round
   *attribution* (which link Eve touched) that leans on the assumption. Concretely: all four
   channel attacks are detected `40/40` at `check_fraction = 0.0`, where the entire channel
   family is unevaluable and every one of these caveats is vacuous. **(NO-TIMING) is carrying
   the attribution, not the detection.**
2. **It is an assumption about the harness, not about the protocol.** Routes A–F, H and I were
   closed because they were bugs in how the simulator hands objects around. Route G cannot be
   closed here because there is no clock here to close it against.

**Timing is now the only route the assumption is carrying.** Phase 3 left routes G *and* H
open; H is closed in this phase, along with a ninth route, I, found by the test written to
close H. See `docs/PHASE3.md` §12, corrected accordingly.

### The other five, each with the reason it exists

* **Group by `count_exchange_timing`; never average over it** (Phase 3 constraint 6). Measured:
  a recipient forgery under `COUNTS_AFTER_FORWARDING` is a forgery Charlie *scores*, and the
  composite names it alone; under `COUNTS_BEFORE_FORWARDING` it is a denial of service Charlie
  *refuses*, and the composite names the pair that holds the forwarding hop. A table mixing the
  two averages a forgery rate with a denial-of-service rate. `Detection.grouping_key` exists so
  this cannot be done by accident.
* **`TranscriptStatistics.params` is the SIFTED set.** `params.key_length` is `n`, the positions
  that carried key; the run's nominal `L` is a separate field, `nominal_key_length`. Every null
  in the layer is stated over `n`. At `check_fraction = 0.25` a null stated over `L` would claim
  64 expected matched positions where the truth is 48: a third more evidence than the run has,
  and every bound in the scheme is exponential in that count.
* **`eps` is per screen, and a run has up to four screens.** `screen_link` divides the budget it
  is *given* over the members it evaluates; the caller must divide the run-level budget over the
  `(party, message_bit)` links first. `divide_budget` exists so that arithmetic is written down
  once instead of guessed four times.
* **Publish `dominance_noise_level()` beside every mismatch-rate detection.** `s_a` and `s_v`
  are noise and forgery budgets, not false-positive budgets. At `DEFAULT_PARAMS` and
  `eps = 1e-9` the crossover against `s_a` is `0.012119`, **below** the design noise level
  `2 s_a = 0.03125`, so on a link running as noisy as the scheme tolerates, the mismatch
  detector is dominated by Bob's own cut and adds nothing. Against Charlie's looser `s_v` the
  crossover is `0.055355`, above it. All of the detector's power at the noiseless default comes
  from assuming the link is quieter than the protocol assumes; a table quoting the rate without
  the crossover is quoting a detection rate whose denominator is an assumption.
* **For the mismatch member, a roster name's party is the verifier who *scored*, not the link
  that was touched.** Phase A′ swaps records between recipients, so `mismatch_rate:Bob` carries
  no information about which link Eve was on. Measured with a strength-`0.30` depolariser aimed
  at Bob's link alone: the check-round QBER names the link on every one of eight runs while the
  mismatch counts are scrambled, and Charlie's is the *larger* on three of the eight. For the
  matched count the party **is** a real attribution. Same shape of name, two different meanings.

## 9. Findings

### What the transcript does not expose: reported, not reached around

1. Which link Eve touched, and which runs a selective starver targeted. Adversary's log.
2. **The channel's true error rate on a run with `check_fraction = 0`.** So the mismatch member
   there has only the noiseless null, and a noise-tolerant threshold must be handed the noise
   level from outside.
3. The raw pre-symmetrisation records and the coins, so only the **unconditional** matched-count
   law is usable. Conditionally on the records, `m_C = M − m_B` exactly.
4. Any timing or ordering information. There are no timestamps anywhere, which is why
   (NO-TIMING) is an assumption and not a check.
5. The resource at **key** positions. `transcript.channel` holds check positions only, and
   `from_dict` refuses a file claiming otherwise, so every channel number is an estimate over a
   sample and never a census.
6. A replay **rate**. Refusals are counted but attempts are not, so no denominator exists.
7. Alice's behaviour directly. She reaches no verdict, and full impersonation is inseparable by
   (AUTH).
8. Anything inside a channel monitor's `extra` blob, free-form JSON written by a seam. Only its
   keys are surfaced.
9. **A matched set for the unsigned message bit.** Both distributions' records are carried but
   only one declaration, so half the run's evidence is frequency-only, worth knowing before a
   Phase 5 table tries to double its sample.
10. Which recipient sent which Phase C′ message, and in what order.

### Protocol findings this phase raised but did not act on

**F1: both matched-count floors invert the loosest of three valid inequalities.** At `q = 1/3`
the multiplicative Chernoff lower tail is dominated by the exact binomial tail at every length.
Critical counts at the same `2⁻⁶⁴` budget. At `L = 192`: protocol `0`, exact `11`; `L = 600`: `66`
vs `100`; `L = 115200`: `36554` vs `36951` (pooled `74189` vs `74749`). A looser floor is
**safe**, with fewer honest aborts and every published bound standing, but the margin
`M_min − 2 m_min` that closes the split-coin route is bought at the loosest available exchange
rate, and at `L = 192` the shipped per-verifier floor degenerates to "abort only on an empty
matched set" where the exact tail still certifies `12`. Raising it reaches
`enforced_repudiation_bound` and the `(2 − √2) A` margin argument, so it is a **protocol change
with a security argument attached**, not a tightening. `floor_comparison()` computes the table
and a test pins it whole.

### Fixed this phase

**Two check-round side channels closed, and a ninth route found while closing the eighth.**
Phase 3 left route H (the raise oracle) open with a proposed one-line shape check. Reproducing
it first showed the proposal would have closed **one of seven** spellings: the asymmetry was
never about shape, it was that validation happened on one branch only, so every malformation
`teleport` refuses recovered the check set at precision `1.0000`. The shipped fix validates the
seam's answer above the branch, against the precondition both branches share, by calling the
very function `teleport` calls. The test written to close it (which asserts the general
invariant rather than the instance) then found **route I** on its first run: a malformed
*resource* raises on both branches, but from two different functions, so the traceback named the
branch even though the exception class did not. Same fix, same place. Honest runs are
bit-identical either side of both changes, shown by SHA-256 over ten transcripts against a clean
snapshot of `HEAD`. Full account, with the measurements and the invariant's stated limits, in
`docs/PHASE3.md` §12, corrected by this phase.

**The protocol's Wilson interval carried floating-point dust.** `estimate_qber` over a clean
50-round sample returned `interval.low == 6.938893903907228e-18` rather than `0.0`, because
`_wilson_interval` clamped with `max(0.0, centre − spread)` where the two terms are equal in
exact arithmetic. Every defended result in this project is `0` successes out of `N`, so the dust
landed on exactly the numbers a reader most needs to read plainly. The same bug was removed from
`sih141/attacks/statistics.py` in Phase 3; this copy was not part of that consolidation. Both
copies now clamp **by case**, and `tests/test_detect_reconciliation.py` pins them against each
other to the bit at both endpoints over a grid of sample sizes.

**`AbortStatistics.honest_bound` was an unproven constant.** It was `2 · 2⁻⁶⁴`, documented as
the run-level bound on `evidence > 0`. The run-level union is over **three** events, namely both
per-verifier floors *and* the pooled floor, and `verify.py` derives `3 eps` itself. So the field
was smaller than the union bound its own derivation supports. Worse, it was a *constant*
where the truth is a function of `n`: at `n = 96` the honest probability is `2.4904e-17` and at
`n = 24` it is `1.1881e-04`, both far **above** `2 eps₀`, so it was optimistic at the short end
as well. It is now computed from the run's own sifted parameters, and the structural family's
copy of the derivation **delegates** to it, so a run cannot be handed two different bounds for
one event.

### Reconciliation: what three parallel families cost

The three families were derived by three hands and each reported the same two integration
problems that none of them could fix from inside one family.

* **62 names were missing from the package surface.** All three families' exports were absent
  from `sih141/detect/__init__.py`. There were no collisions; they are all exported now.
* **Three copies of the Chernoff lower-tail inversion** (in the rate family, the structural
  family and `protocol/verify.py`) had each been pinned against the protocol's, but never
  against **each other**. They agree exactly wherever the form applies. They also spell
  "vacuous" two different ways, which the pinning test found: the rate family returns `-1` and
  the structural family returns `None`. A caller reading `-1` as a count would refuse every run,
  so the test requires them to agree on *when* the form has power as well as on the value.
* **Two exact binomial tail implementations**, one summing through `lgamma` with a rigorous
  geometric remainder and one accumulating, now agree with each other and with
  `fractions.Fraction` rational arithmetic to a relative `1e-12` on both tails.
* **The one genuinely dangerous convention clash: `vacuous` and `reaches_its_statistic` are the
  same fact with opposite senses.** `vacuous=True` and `reaches_its_statistic=False` both mean
  *this threshold cannot fire*. A combiner reading one where it meant the other would flip
  "this sample can detect nothing" into "this sample is fine", silently, in the direction that
  manufactures a clean bill of health. `ThresholdView` gives all three carriers one vocabulary
  with `can_fire` in **one** sense, and refuses to duck-type: guessing from the attributes
  present is precisely how the pair gets misread.

## 10. Cost, and the suite

| Arm | Cost |
| --- | --- |
| one `L = 384` session, no check rounds | `~0.76 s` |
| one `L = 384` session, `check_fraction = 0.25` | `~0.78 s` |
| `detect()` on one transcript | well under the session that produced it |
| the 22-arm adversary sweep of §5, 40 runs per arm | `1148 s` |
| `tests/test_detect_reconciliation.py` | 34 tests, `~30 s` |
| the **whole suite** (`python -m pytest`) | **`3036 passed, 0 failed, 0 skipped`, exit code `0`** |

Up from `2174` at the end of Phase 3 and `1421` at the end of Phase 2. The wall clock for that
run was `2274 s`, measured while other verification scripts were running on the same machine, so
it is an upper bound rather than a benchmark; the load-bearing figure is `3036 / 3036`.

The route-closure work costs nothing an honest run can see. `payload_map=None` returns before
the payload check, so an honest run never reaches it; the resource check is one `_coerce_state`
per position, `3.5 µs` against a position that costs about `486 µs`. Ten honest transcripts
hash identically under SHA-256 either side of both changes.

## 11. What Phase 5 needs to know

* Build **one** family per `(parameter set, eps)` with `RateCountThresholds.for_params` and call
  `evaluate()` once per run. That is both the cheap pattern and the honest one: it makes visible
  that no threshold moved with the data. At a positive noise level the two mismatch members are
  conditioned on a particular run and `evaluate()` refuses to score any other, so the sweep must
  build per run there.
* `family_budget(params, eps=..., counts_exchanged=...)` gives the allocation without running
  anything, and `FamilyBudget.derivation` prints the algebra with that budget's numbers
  substituted.
* **The cross-family union bound is nobody's job inside a single family.** A detector that fires
  when any of the three families fires has a false-positive bound equal to the **sum** of the
  three, so a target budget `E` must be split before it reaches each family. `detect()` does
  this; a caller assembling families by hand must.
* `Detection.to_dict()` is JSON-clean and carries `budget`, all `attributions`, `named`,
  `kinds`, `withheld`, `grouping_key` and the rendered `summary`.
* **The family's ROC is degenerate above `eps = 3·2⁻⁶⁴` for the structural family, and that is
  derived rather than a bug.** Three checks have a bound of exactly `0`, so no budget can move
  them, and the fourth is either admissible at `1.6263e-19` or withheld outright. The curve has
  exactly two regimes. A smoother curve would have to be manufactured.
* **Use `threshold_view()` in anything that walks thresholds from more than one family.** The
  raw carriers spell the budget, the critical value and the direction three different ways, and
  they spell *"can this fire"* in two **opposite** senses. One vocabulary, one sense, and a
  `TypeError` rather than a guess.
* **Do not add the CHSH certificate to an alarm table**, and do not sum `cleared` with
  `unavailable`. Both mistakes manufacture a result out of a sample-size problem.
* **Check that an arm ran before publishing a zero.** This phase measured `0/40` for the replay
  arm and it was a wiring artefact: the adversary had nothing replayable and forwarded honestly
  (§5). It only announced itself because every other arm in the same sweep was `40/40`.

## 12. The independent audit

Three auditors ran against `2e75d91` after integration, each in its own clone, each given the
integrator's claims and told to assume they were wrong. All three returned **sound**. Between
them they re-executed roughly 90,000 detector evaluations and several thousand exact-rational
comparisons. Six defects were confirmed; none invalidates a shipped bound.

The audit is worth reading for what it could NOT break, because that is the phase's actual
claim:

* **No fitted threshold.** Auditor 1 re-derived `critical_count` from scratch in
  `fractions.Fraction` over 288 inversions and checked each shipped threshold is *extremal*
  (that the next count out exceeds the budget), not merely admissible. 0 anomalies. It also
  re-derived the channel family from McDiarmid by hand and confirmed the published `k=118` at
  `n=4114` with 40-digit `mpmath`.
* **The union bound is over the tests actually run.** Auditor 2 wrote an independent enumerator
  that rebuilds every threshold `detect()` constructs and `fsum`s the bounds itself: 1536
  `detect` calls across 12 key lengths, 6 check fractions, both count-exchange orderings and 4
  budgets. Recomputation mismatches: **0**. An orphan check in the other direction over 1125
  further calls found no signal source outside the three reporters.
* **No special-cased operating point.** Auditor 3 swept ~88,800 evaluations across three budget
  ladders and found zero violations of monotonicity in `detected`, in `false_positive_bound`, or
  in any individual signal. An AST walk for unexplained float literals turned up only real
  mathematical constants.
* **Ten point masses, independently confirmed.** Both auditor 2 and auditor 3 arrived at ten
  frozen instances by different routes, confirming the integrator's late correction from nine.

### Confirmed defects

| # | Severity | Where | What | Status |
|---|---|---|---|---|
| A1-1 | minor | `thresholds_rate.py` | Docstring quoted `1.4e-13` agreement "across the range"; that was the maximum over the nine counts the pinning test parametrises. True worst case over the swept range is `2.624e-13`. | **fixed**: figure corrected to `3e-13`, sweep stated, underflow region documented |
| A1-2 | minor | `detect/__init__.py` | Claimed as a general property that every `ThresholdView` proves a bound inside its own budget. Five counterexamples exist, all with `can_fire=False`. | **fixed**: invariant restated with its `can_fire` precondition and the counterexample pinned as a doctest |
| A1-3 | minor | `statistics.py` | `floor_shortfall_bound` ignored its `floor` argument on the Chernoff branch, so outside its documented precondition it certified `2**-64` for an event of probability ~1. | **fixed**: the containment the derivation relies on is now checked rather than assumed: the term is offered only where `floor - 1 <= (1 - d0)·mu`. Both protocol floors keep their bound (tightly: `36554` against `36554.2`); a floor above the derivation gets `1.0` |
| A2-1 | minor | `detector.py` | At the smallest representable budget the family split underflowed and the refusal named an internal field (`rate`) rather than the caller's argument (`eps`). | **fixed**: the refusal now names `eps`, states the share that underflowed, and says where the usable floor is so a sweep can stop there |
| A3-1 | **major** | `detector.py` | The noiseless null was absent from the machine-readable output. See below. | **fixed**: `Detection.channel_error_rate` and the derived `null_is_noiseless` now ship on the verdict and in `to_dict()` (21 keys). Additive; no call site changed |
| A3-2 | minor | `detector.py` | `detect()` raises below roughly `1e-314`, far outside any usable budget. | **fixed**: behaviour kept, since refusing is the safe direction; the message now says the subnormal region is a floating-point limit rather than a detector defect |

### A3-1, the major, in full

`detect()` defaults to `channel_error_rate=0.0`. That null is correct and it is disclosed in
the `detect()` docstring, in finding F6, and in `dominance_noise_level()`. The defect is that the
disclosure lives entirely in **prose**, while the machine-readable headline fields carry nothing
about it. `Detection.to_dict()` has 19 keys and `channel_error_rate` is not one of them.

Reproduced independently at `2e75d91`, honest parties, depolarising noise on the wire only:

| link error rate | false alarms (n=30) |
|---|---|
| 0.00000 | 0/30 |
| 0.00250 | 13/30 |
| 0.00500 | 17/30 |
| 0.01000 | 27/30 |
| 0.01500 | 30/30 |
| 0.03125 (= `2*s_a`, the design noise level) | 30/30 |

Every one of those runs reports `false_positive_bound = 2.7818e-10` and
`bound_is_unconditional = True`, on runs where **both verifiers accepted**. Passing the true rate
gives `0/30` at every level, so the mechanism is right and only the default is the trap.

`bound_is_unconditional` is the field whose name most suggests it would flag this. It does not:
it concerns conditioning on `|M_R|`, and it is `True` in exactly the dangerous case and `False`
in the safe one.

**Fixed after the audit closed.** `Detection` now carries `channel_error_rate`, and the derived
`null_is_noiseless` is `True` exactly when it is `0.0`. Both reach `to_dict()`, so a results table
has one field to filter on instead of a paragraph to remember. The alternative, making
`channel_error_rate` required, is the only change that would *force* a caller to confront the
null, and it was rejected because it breaks every existing call site including this document's
worked examples. What was **not** done: inferring the noise level inside `detect()`. At
`check_fraction = 0` the transcript does not carry it (§9, finding 2), so guessing it would be
inventing a null, the thing D7 exists to prevent. `tests/test_detect_audit_fixes.py` pins all
four fixes, including the auditor's single-run reproduction.

**Consequence for Phase 5, which the fix reduces but does not remove.** A pipeline that tabulates `detected` and
`false_positive_bound` will record honest noisy links as detections carrying a proven `2.8e-10`
bound. Any table drawn from this detector must either pass the link's true error rate, or state
in the table that the null is noiseless and that the run's link was not. This is the same species
as constraint 1: a number that is arithmetically correct and still a false claim once its
denominator or its null goes unstated.
