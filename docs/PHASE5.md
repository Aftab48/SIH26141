# Phase 5: The evaluation harness, and what this machine actually costs

Engineering note and results for `sih141/eval` and `tools/sweep.py`: the harness every
experiment runs on, the seed rule that makes a parallel sweep publishable, the production sweep's
numbers, and the measured performance of the machine it ran on.

**Status: complete.** 12,494 trials across seven experiments in 23.3 minutes at twenty workers,
zero failures. §§1–4 are the plumbing and the determinism proof, §5 is the sweep itself, §6 is how
to read a table here, §§7–10 are the results, §§11–12 are the machine, §13 is every limitation,
§14 is what the reduction refuses to do and §15 is how to add an experiment.

Every figure below was produced by a command printed next to it, run against seeds on disk. Two
figures in the performance sections did **not** survive being re-run and say so on the row; that is
what D9 is for.

---

## 0. The rule this phase is built around

> **D9. Every published number is reproducible from a recorded seed and a committed command.**

An evaluation phase's only product is numbers, and a number nobody can regenerate is worth less
than no number at all, because it looks like evidence. Concretely: every figure that reaches
this document, `README.md` or a chart must be derivable by running one committed command
against recorded seeds, and that command must be printed next to the table it produced.

The corollary is the reason D3 (randomness only through an injected, keyword-only `rng`) has
been enforced since Phase 1. Because randomness is injected rather than global, **a trial's
result depends on its seed and on nothing else**: not on worker count, not on scheduling order,
not on which core it landed. That is what makes a parallel sweep publishable, and §4 proves it
rather than asserting it.

---

## 1. The two commands

They are separable on purpose. The sweep happens once, whenever the human likes; the tables are
redrawn as often as anyone wants, from whatever is on disk, without re-running a trial.

```
python tools/sweep.py run honest --trials 30 --workers 20
python tools/sweep.py reduce honest
```

The practical reason is that a full-scale sweep is measured in hours. The methodological reason
matters more: a reduction that can only run inside the sweep cannot be re-run by a reviewer
against the same files, and a table that costs two hours to regenerate is a table nobody will
check.

`run` is **resumable**. One file per trial, written atomically by the worker that finished it,
named from the trial's identity: `<root>/<experiment>/<cell>/trial-000042.json`. On startup it
skips what is already there. Re-running the identical command after a hibernation costs the
trials that were in flight and nothing else. This is not hypothetical: a hibernation has already
destroyed one long run in this project and baked `"<no summary line>"` into `docs/METRICS.md`.

Results default to `~/.sih141/results`, **outside the repository**. Raw per-trial files are never
committed; only reduced tables are. Committing them would be a mistake of a familiar shape: a
reviewer seeing 200 JSON files in the tree would take them for the evidence, when the evidence is
the seed plus the command and the files are a cache of a computation anyone can redo.

There is a third subcommand, `perf`, which measures the machine rather than the protocol. It
produced everything in §§11–12.

---

## 2. Where a trial's randomness comes from

For an experiment name `e`, a cell name `c`, a role `r` and a zero-based trial index `i`:

```
material = b"sih141/eval/seed/v1" || 0x00
        || utf8(e) || 0x00 || utf8(c) || 0x00 || utf8(r) || 0x00 || ascii(decimal(i))
seed     = int.from_bytes(blake2b(material, digest_size=8, person=b"sih141-eval"), "big")
```

Three properties, each tested rather than stated.

**Pure.** `trial_seed` reads no clock, no environment and no global state. Worker count, chunk
size and completion order cannot reach it. It is not `hash((e, c, r, i))` precisely because
Python's `hash` is randomised per process by `PYTHONHASHSEED`, which is the "depends on which
process ran it" failure this rule exists to rule out, and there is a test that computes a seed
in a separate interpreter with a different hash seed and compares.

**Unambiguous.** `0x00` separates the fields, and legal names are `[a-z0-9][a-z0-9._-]{0,63}`,
so no two identities can build the same material. Without the separator `("ab", "c")` and
`("a", "bc")` would collide and two cells would silently share a stream; the same pattern keeps
path separators and drive letters out of names that become directory components.

**Independent across roles.** The session's generator and an adversary's come from different
`r`, so D6 (every adversary owns its randomness and never reads the session's) is a property
of the derivation rather than a convention a scenario author has to remember. The test compares
*realised draws* through `sih141.attacks.isolation.same_stream`, not seeds.

The rule, not the seeds, goes into every run manifest: there may be thousands of seeds, and each
individual one is on its own trial's record anyway.

---

## 3. What a trial leaves behind

A full-scale transcript is 25.4 MiB unchecked and 37.2 MiB at `check_fraction = 0.25`, so 200
trials in full would be five to seven gigabytes and a sweep across several cells would be tens.
The harness stores a **reduced record**: `Detection.to_dict()`
(all twenty-one keys), the transcript fields the tables need, the seeds, the parameters and the
wall clock. Full transcripts only behind `--retain-transcripts`, for a named handful of worked
examples.

### Ground truth is not evidence

Phase 3 constraint 4: which link Eve touched, and which runs a selective starver targeted, live
on the **adversary's** log, and a detector may not read them. `GroundTruth` is the harness's
label; `Detection` is what the detector concluded from the transcript alone. They are built at
different times: the detector has already returned before the label is attached.

The property that matters is not "the label is in a different field" but "the label could not
have reached the detector", and the test is an observation that would differ if it had: score one
transcript once, build two records with contradictory labels, and compare the `detection` blocks
byte for byte.

Two labelling rules ride on the record itself, because a table gets them wrong otherwise:

- **`engaged` is read off the adversary's own log**, never assumed from the cell. A channel
  attack aimed at Bob's link engages on no Charlie hop; an untargeted run is byte-identical to an
  honest one and must be scored as one. `GroundTruth` **refuses** `engaged=True` with
  `engaged_count=0`, because Phase 4's replay arm reported a clean 0/40 while having forwarded
  honestly throughout, and an arm reporting zero has to be able to prove it acted.
- **`detectable=False` is a label**, so a row for full impersonation prints
  `undetectable-by-construction` rather than a blank, a dash or a zero. A hypothesis missing from
  a table reads as one that was ruled out; a zero reads as one we tried and failed to catch.

### What the fingerprint leaves out

`TrialRecord.fingerprint()` is a SHA-256 over the canonical JSON of everything except
`wall_clock`. Timings depend on the machine, on thermal state and on how many workers were
competing, so they are on the record (Phase 5 needs a performance section) and out of the
comparison. The excluded set is exactly one field and is pinned by a test, because an exclusion
list is the natural hiding place for a field that genuinely moved between one worker and twenty.

---

## 4. Determinism, proven rather than asserted

This is the claim D9 rests on and the one a judge is most entitled to challenge about a parallel
result. Four tests, each written so that it could fail:

| What is claimed | What is actually run |
| --- | --- |
| Same seeds, same results at any width | Two whole sweeps, one in-process and one across four spawned workers, compared by fingerprint. The test also asserts more than one PID appeared, so a pool that silently ran everything in one worker would not pass by accident. |
| Results do not depend on completion order | Trial 2 produced twice, once alone in its own directory and once as the third of four, and the fingerprints compared. |
| The *tables* match, not just the records | The rendered markdown of the outcome and detection tables compared across the two topologies. Records could match while a reduction sorted by directory order. |
| No worker touches a global RNG (D3) | Both global states snapshotted around a sweep and compared, in the parent and inside every worker. A separate test draws from both globals and asserts the probe notices, so the probe cannot be decorative. |

The BLAS thread limits are set in the **parent before the pool exists**. Windows uses spawn and a
spawned child copies the parent's environment at interpreter start, before any import, so the
limit is in place by construction rather than by an initializer racing numpy's own pool
initialisation. And it is then measured: `tools/sweep.py perf --probe` asks a real worker what
its own environment says, because setting the variables after numpy is imported is a silent
no-op that looks identical from the outside.

---

---

## 5. The production sweep

One run per experiment, seven experiments, **12,494 trials in 23.3 minutes** at twenty workers,
zero failures and zero retries. Every table below this line was reduced from that store and
nothing else. The 23.3 minutes is the sum of the seven manifests' own wall clocks, 1398.5 s; a
human running the seven lines back to back pays a little more for seven interpreter starts.

```
python tools/sweep.py run smoke             --workers 20
python tools/sweep.py run honest            --workers 20
python tools/sweep.py run noise             --workers 20
python tools/sweep.py run scaling           --workers 20
python tools/sweep.py run roc               --workers 20
python tools/sweep.py run repudiation-curve --workers 20
python tools/sweep.py run forgery-curve     --workers 20
```

No `--trials`: each experiment's production count is its registry default. No `--results`: the
default `~/.sih141/results` is outside the repository, and every `reduce` below assumes it.

| experiment | cells | trials/cell | records | wall clock | question it answers |
| --- | --- | --- | --- | --- | --- |
| `smoke` | 1 | 4 | 4 | 1.2 s | does the harness work |
| `honest` | 3 | 30 | 90 | 15.0 s | the false-alarm arm, at three key lengths |
| `noise` | 4 | 30 | 120 | 15.6 s | what a noiseless null costs on a noisy link |
| `scaling` | 4 | 20 | 80 | 113.4 s | cost against key length, through the real runner |
| `roc` | 15 | 40 | 600 | 84.5 s | detection against a swept false-positive budget |
| `repudiation-curve` | 14 | 400 | 5600 | 507.4 s | can a signer repudiate, against key length |
| `forgery-curve` | 15 | 400 | 6000 | 619.7 s | can a declaration be forged, against key length |

Every manifest records commit `f94d9fe`, twenty workers, all five BLAS thread limits reading `1`
in a worker's own environment, and an empty `global_rng_touched` list. Every cell holds exactly
the trial count its manifest asked for; the reduction checks that against the manifest rather
than against the highest index present, so a run cut short by its last trials is caught.

The whole store is **239 MiB**: 90 MiB of it the 600 ROC records, which are the only ones that
retain their transcripts, because the ROC reduction re-scores them at fifteen budgets and cannot
work from a summary. The two 400-trial families keep reduced records only; retaining their
transcripts would have cost tens of gigabytes for tables that need a verdict and a handful of
counts.

**Reducing is cheap and re-runs nothing.** All seven reductions plus both charts take about a
minute on this machine, and 52 s of that is ROC re-scoring its 600 retained transcripts at fifteen
budgets each. So the tables can be redrawn as often as anyone wants to check them, which is the
point of `run` and `reduce` being separate commands.

### Provenance, and what re-running the whole sweep proved

An earlier store recorded `dirty: true` on every manifest: eight files were modified or
untracked when that sweep ran, so its commit did not describe the code that produced it. The
numbers were right and no reviewer could have pinned them to a commit, which under D9 is one
step short of publishable. So the store was deleted and the seven lines above were run again
against a committed tree.

**Every manifest now records `f94d9fe` with `dirty: false`**, and the re-run answered a question
the first one could not. This was not a resume or a re-reduce: 12,494 trials were computed from
scratch, in fresh worker processes, on a machine in a different state. Across the 51 cells
both runs share, per-cell wall clock moved by a median of 6.1% and by as much as 20.5%
(`l384`, 1041.64 s against 827.84 s). Against the committed tables, what changed:

| quantity | change |
| --- | --- |
| every measured rate, every confidence interval, every proven bound | **none** |
| both charts, `roc.svg` and `repudiation-curve.svg` | **byte-identical** |
| wall-clock and per-trial timing columns | moved, as they must |

The charts are the check worth reading, because they plot the rates and the bounds and nothing
else: a single moved result would have moved a coordinate. So the determinism argument in §4
is no longer only an assertion about seeds and a test at four workers: the entire production
sweep has now been computed twice, hours apart, and agrees everywhere it claims to.

### What the integration audit re-ran, and what it found

D9 has three tests, not one: **is there a recorded seed**, **is there a committed command**, and
**does that command, run now, actually reproduce the number**. The third is the one that catches
things, and it caught four.

| what was re-run | how it went |
| --- | --- |
| All seven `reduce` commands, exactly as printed under their own tables, including the quoted `--results` path | **byte-identical**, all seven, exit 0 |
| Both charts, re-rendered | identical coordinate for coordinate; only the embedded output path differs |
| `perf --session-scaling` timings | within 1% on all three lengths |
| `perf --session-scaling` **sizes** | **wrong by up to 21%**, §11.1 |
| `perf --memory` | within 1% on peak RSS, identical on transcript size |
| `perf --speedup` | **7.04× → 10.27×**, §11.2 |
| the degenerate small-end table | **had no command at all**; one exists now, and three of its cells were one draw published as a property, §12 |
| "26.7 MB" beside "0.226 KiB/position" | **a unit mismatch inside one sentence**, 25.4 MiB, §11.1 |
| one cell of every results table, recomputed by a different route | all agree; see the notes under each section |

Nothing in §§7–10 failed. Everything that failed was in the performance sections, which is where
the numbers are measurements of a machine rather than functions of a seed, and the one that
was simply *wrong* rather than unstable, the transcript size, had a green doctest sitting beside
it that read the constant back out of its own dict.

---

## 6. How to read any table in this phase

Six rules, each of which came out of an audit at real cost, and each of which is a way a results
table can be arithmetically right and still a false claim.

**A no-verdict is not a rejection.** Aborts are a separate transcript field with a separate type.
Every rate prints its denominator as `k/n`, and refusals get their own column and are added to
nothing. A row reading "detection 92%" with 8% silently aborted is a false claim, and the shared
detection table carries `refusals (any party)` for exactly that reason.

**The two count orderings are never pooled.** `count_exchange_timing` is part of the grouping key
of every table, so one cell can become two rows. At `L = 96` the same recipient forgery gives all
refusals before forwarding and a 30% acceptance rate after it; pooling them publishes 15%, which
describes neither run.

**Measured is not proven, and the columns say which.** A detection rate is a measurement with a
sample size and a 99% Wilson interval. A false-positive bound is a proof under the honest null.
There is no false-negative bound and there cannot be one from a transcript, so no table here
prints one. An empty denominator reads `no trials`, never `0.000`.

**A withheld family is `not evaluated`, never `passed`.** With no check rounds the whole channel
family is unevaluable and `Detection.withheld` says so.

**A hypothesis excluded by assumption is named.** Full impersonation reads
`undetectable-by-construction`, never a blank, a dash or a zero.

**The null is a column.** `null_is_noiseless` rides on every detection row, because a mismatch
detection under a noiseless null on a genuinely noisy link is arithmetically correct and a false
claim once the null goes unstated.

### The two charts, and how they were checked

D9 applies to a figure exactly as it does to a table, so each chart prints its own regenerating
command in the corner of the SVG. Both were re-rendered during the integration pass and came back
identical coordinate for coordinate, the embedded output path being the only difference.

They were also checked by **inverting their own geometry**, which is a different thing from
grepping the markup for a number. `repudiation-curve.svg` puts the measured rate on a log axis with
`1e0` at `y = 56.0` and `1e-1` at `y = 120.3`; reading each point's `cy` back through that scale
recovers 0.2716, 0.1651, 0.0873, 0.0450, 0.0200, 0.0349, 0.0150, 0.0050 and 0.0025, the nine
non-zero rungs of §7's table, every one within 1%. The tenth rung is `0/400`: it is drawn as an
interval bar reaching the axis floor with its `0/400` label attached, because a zero has no place
on a log axis and a point silently dropped would read as a rung that was never run.

`roc.svg` carries 165 circles, which is eleven arms at fifteen budgets; the three cells with no
attacked runs are correctly absent, and `impersonation-full` is listed as
`undetectable-by-construction` rather than drawn as a line along zero. Its x axis is the **proven**
bound and its y axis the **measured** rate with the 99% interval as a bar, and both words are in
the axis labels.

---

## 7. Repudiation against key length

> Regenerate: `python tools/sweep.py reduce repudiation-curve --results ~/.sih141/results`
> Chart: add `--charts docs/figures`
> Full tables: [`docs/tables/repudiation-curve.md`](tables/repudiation-curve.md) ·
> [`docs/figures/repudiation-curve.svg`](figures/repudiation-curve.svg)

**The question.** As the key length grows, how often does a signer who is genuinely trying to
repudiate succeed against the shipped protocol, and how does the enforced a-priori bound track
that measured rate?

**The cells.** Fourteen, all at `check_fraction = 0`, 400 trials each. Ten symmetrised rungs from
`L = 24` to `L = 768`, each at the tilt `q` that maximises `analysis.repudiation_probability` for
that length on a 0.001 grid. The ladder straddles the security-claim crossover on purpose: `l24`,
`l48`, `l96` and `l132` carry **no** claim and `l138` upward do. One ordering control, `l192after`,
runs the `l192` rung under the after-forwarding ordering. Three positive controls, `unsym192`,
`unsym384` and `unsym768`, aim a tilt of 0.30 at Charlie with the symmetrisation exchange removed,
where repudiation succeeds at every key length.

**The denominator** is `engaged`: runs whose tilt actually replaced at least one delivered state,
read off `TiltingPreparation.flips` and never off the cell's intent. A run the tilt happened to
leave alone is byte-identical to an honest run, is counted in its own `not engaged` column, and is
not scored as a missed repudiation. That column is not decorative: at `L = 24`, 6 of the 400 runs
came out untouched, so the row reads `107/394` and not `107/400`.

**The numerator** is the runs where Bob accepted, Charlie rejected, the forwarding hop left the
declaration alone and the session is coherent. It is recomputed by two routes: the transcript's
own `repudiated` property, and a rebuild from the recorded verdict strings. A test asserts they
agree on every record *and* that both answers actually occur in the sample, so a route that
always said `False` could not pass.

**Aborts** are inside the denominator and are not repudiations (a verifier who reached no verdict
did not accept, so the event did not occur), and they get their own `no verdict` column. That is
also the denominator the proven bound is stated over, which is what lets the measured and proven
columns be read against each other. On this sweep the column is zero on every row.

| `L` | tilt `q` | engaged | repudiated (**measured**, 99% Wilson) | no verdict | exact in-model `P` (closed form) | enforced bound (**proven**) | claim |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 24 | 0.085 | 394 | `107/394 = 0.2716 [0.2180, 0.3327]` | 0 | `2.498e-01` | `9.995e-01` | no |
| 48 | 0.059 | 399 | `66/399 = 0.1654 [0.1231, 0.2187]` | 0 | `1.569e-01` | `9.995e-01` | no |
| 96 | 0.047 | 400 | `35/400 = 0.0875 [0.0575, 0.1309]` | 0 | `6.602e-02` | `9.995e-01` | no |
| 132 | 0.043 | 400 | `18/400 = 0.0450 [0.0249, 0.0799]` | 0 | `3.639e-02` | `9.995e-01` | no |
| 138 | 0.043 | 400 | `8/400 = 0.0200 [0.0083, 0.0474]` | 0 | `3.270e-02` | `9.995e-01` | **yes** |
| 192 | 0.044 | 400 | `14/400 = 0.0350 [0.0179, 0.0673]` | 0 | `2.951e-02` | `9.940e-01` | yes |
| 300 | 0.042 | 400 | `6/400 = 0.0150 [0.0055, 0.0403]` | 0 | `1.158e-02` | `9.818e-01` | yes |
| 384 | 0.042 | 400 | `2/400 = 0.0050 [0.0010, 0.0252]` | 0 | `7.100e-03` | `9.713e-01` | yes |
| 600 | 0.041 | 400 | `1/400 = 0.0025 [0.0003, 0.0209]` | 0 | `1.936e-03` | `9.434e-01` | yes |
| 768 | 0.041 | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | `5.845e-04` | `9.212e-01` | yes |

Two rows that are not part of the ladder and must not be read as one:

| cell | what it is | repudiated (**measured**) |
| --- | --- | --- |
| `l192after` | the `L = 192` rung under the **after-forwarding** ordering | `7/400 = 0.0175 [0.0069, 0.0439]` |
| `unsym192` / `unsym384` / `unsym768` | positive controls, no symmetrisation exchange, tilt 0.30 | `400/400 = 1.0000 [0.9837, 1.0000]` |

**The ordering control answers its question rather than assuming it.** `l192` measures `0.0350
[0.0179, 0.0673]` and `l192after` measures `0.0175 [0.0069, 0.0439]`; the closed form `0.02951`
lies inside both. So the count ordering does not move *this* attack detectably at `n = 400`, which
is a measurement, not the assumption it would have been if the cell did not exist. §8 is where the
ordering does move an attack, by everything.

**The closed form lands inside the measured interval on all eleven rows that carry both**: the
ten ladder rungs and the ordering control. That is the check that the measurement and the model are
describing the same experiment, and it is an independent route rather than a restatement:
`analysis.repudiation_probability` is the exact acceptance probability for this adversary's family,
computed from the parameters with no simulation. The `exact in-model P` cell reads `n/a` on the
three unsymmetrised rows, because the closed form assumes the symmetrised, untargeted family and a
number there would look like a contradiction of the measurement rather than a column that does not
apply.

**The positive controls are what makes a zero readable.** `l768` measures `0/400`. The three
`unsym*` cells measure `400/400` against the same adversary with the symmetrisation exchange
removed, so the zero is a protocol result and not an arm that never fired. Phase 4's replay arm
reported a clean `0/40` while having forwarded honestly throughout, and that is the failure these
rows exist to rule out.

The adversary's own log says the same thing more directly. On `l768` the tilt replaced between
**42 and 88 states per run**, 63.5 on average, on all 400 runs; on `l600`, 29 to 71. The `0/400`
is 400 runs of an attack that certainly happened and did not succeed: the `mean states flipped`
column in the full table carries that figure on every row, so a row cannot report a zero without
also reporting how hard it tried.

### Where demo-scale runs cannot demonstrate non-repudiation

This is the strongest limitation in the phase and the table prints it from its own rows, so it
cannot go stale.

At `L = 768` the measurement is `0/400`, whose 99% upper limit is **0.0163**. The exact in-model
probability is **5.845e-04**, twenty-eight times below what a sample of 400 can resolve. The proven
enforced bound is **9.212e-01**, fifty-six times looser than the measurement. And the region the
security claim actually lives in (`1.4139e-09` at `L = 115200`) is unreachable by both.

So the proof is vacuous over exactly the range a measurement can reach, and the measurement is
blind over exactly the range the proof is about. **A measured zero here is evidence that the
mechanism works. It is never confirmation of the bound.**

### The floors, and the crossover that is not 140

> Regenerate: same command. Every column in this table is a closed form in the parameter set;
> none is a measurement and none is labelled one.

The security claim turns on at `L = 137`, where `M_min` (`minimum_pooled_matched_count`) first
exceeds 1. `M_min` **alone** is the quantity that crosses, which is what `security_claim_at` and
`detect/statistics.py` test: the "floor on `M`" column below is `max(2·m_min, M_min)`, and it
already reads 2 at `L = 132` and `L = 136`, on the wrong side of the crossover. The per-verifier
floor `m_min` does not bite until `L = 273`. Below the crossover `m_min` and `M_min` are both 1
("abort only on an empty matched set"), and every number in the run still computes cheerfully,
which is why the column exists.

| `L` | `m_min` | `M_min` | floor on `M` | claim | enforced repudiation (**proven**) | recipient forgery (**proven**) | outside forgery (**proven**) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 132 | 1 | 1 | 2 | no | `9.995e-01` | `7.621e-01` | `3.097e-08` |
| 136 | 1 | 1 | 2 | no | `9.995e-01` | `7.559e-01` | `1.834e-08` |
| **137** | 1 | **2** | 2 | **yes** | `9.995e-01` | `7.543e-01` | `1.609e-08` |
| 192 | 1 | 22 | 22 | yes | `9.940e-01` | `6.736e-01` | `1.196e-11` |
| 272 | 1 | 55 | 55 | yes | `9.850e-01` | `5.714e-01` | `3.364e-16` |
| **273** | **2** | 55 | 55 | yes | `9.850e-01` | `5.702e-01` | `2.951e-16` |
| 768 | 106 | 299 | 299 | yes | `9.212e-01` | `2.059e-01` | `2.048e-44` |
| 4800 | 1224 | 2668 | 2668 | yes | `4.806e-01` | `5.134e-05` | `8.814e-274` |
| 115200 | 36555 | 74190 | 74190 | yes | **`1.414e-09`** | `1.124e-103` | `10^-6553.3` |

The bounds are the KL form, which is never weaker than Hoeffding, and they are printed from
`log10` rather than from the library's float: `forgery_bound` underflows to `0.0` at
`L = 115200`, and a bound of exactly zero is a claim no proof supports.

**A prose figure this table corrects.** `docs/QDS.md` said "a real Alice genuinely repudiates
~3.5% of the time at `L = 600`". At `L = 600` the best symmetric tilt achieves `1.936e-03` in
model and measures `1/400 = 0.0025 [0.0003, 0.0209]`. 3.27% is the figure for `L ≈ 138`, and it
appears on the `l138` row above. That is the sixth wrong prose number this project has found, and
it is corrected from the table rather than from an argument.

---

## 8. Forgery against key length

> Regenerate: `python tools/sweep.py reduce forgery-curve --results ~/.sih141/results`
> Full tables: [`docs/tables/forgery-curve.md`](tables/forgery-curve.md)

**The question.** How often is a forged declaration accepted (for the outside forger who holds
nothing and for the binding one, a recipient who holds half the target's evidence), and does the
count ordering change the answer?

**The cells.** Fifteen, all at `check_fraction = 0`, 400 trials each. Four outside-forgery rungs
at `L = 9, 15, 24, 30`, the only lengths where Eve's exact acceptance probability is above what 400
trials can resolve: it is `4.67e-07` by `L = 96` and `1.12e-12` by `L = 192`, so a rung there
would measure `0/400` whatever happened and say nothing. Plus `eve24after` under the other
ordering. Then the recipient forger at `L = 96, 192, 384, 768, 1200`, each in a `before` and an
`after` variant.

**The denominator** is `engaged`: runs where the forger's declaration really differed from
Alice's, counted position by position on the adversary's own log. A forwarder who passed the
declaration through would be an honest Bob and the run is scored as one.
`Charlie accepted + Charlie rejected + Charlie no verdict = engaged`, exactly, on every row.

**Aborts.** `Charlie no verdict` is a refusal, its own column, never folded into a rejection.

**And the rows reporting `0/400` acted.** Read off the forgers' own logs: `bob96before` substituted
51 to 80 positions per run and `bob1200before` 758 to 847, on all 400 runs of each. Their zero
acceptance is a refusal to transfer, not an arm that forwarded honestly.

### The outside forger, and the closed form she anchors

| `L` | engaged | Charlie accepted (**measured**) | rejected | no verdict | exact `P` (closed form) | **proven** bound |
| --- | --- | --- | --- | --- | --- | --- |
| 9 | 400 | `61/400 = 0.1525 [0.1119, 0.2044]` | 318 | 21 | `1.6779e-01` | `3.076e-01` |
| 15 | 400 | `26/400 = 0.0650 [0.0398, 0.1044]` | 372 | 2 | `6.2622e-02` | `1.402e-01` |
| 24 | 400 | `4/400 = 0.0100 [0.0030, 0.0330]` | 396 | 0 | `1.2520e-02` | `4.312e-02` |
| 30 | 400 | `1/400 = 0.0025 [0.0003, 0.0209]` | 399 | 0 | `4.2111e-03` | `1.965e-02` |
| 24 *(after-forwarding)* | 400 | `2/400 = 0.0050 [0.0010, 0.0252]` | 398 | 0 | `1.2520e-02` | `4.312e-02` |

Five rows, five times the closed form inside the interval. Eve's declaration reaches both
verifiers, so one run measures her against `s_a` and `s_v` at once, and Bob's acceptance is its
own measured column: `66/400`, `22/400`, `8/400`, `2/400`. Her ladder stops at `L = 30` because
that is the last length where 400 trials expect to *see* anything: `400 × 4.2111e-03 = 1.7`
acceptances, against `0.09` at `L = 48` and `0.0002` at `L = 96`. A rung past 30 would report
`0/400` whatever the truth was, so it would be testing the sample size rather than the protocol.
The measurement anchors the closed form where a measurement is possible; the closed form carries
the curve from there.

The 21 no-verdicts at `L = 9` are honest aborts on an empty matched set. They are in the refusal
column, not the rejection column, and the acceptance rate's denominator is unaffected because
`engaged` counts all 400.

**A proven bound of exactly zero, and why it is not an empty sum.** The `eve9` row's
`max proven FP bound` reads `0.000e+00`. That is the real answer, not a missing one: the mismatch
member's null on a noiseless link is a *point mass* at zero, because a matched position never disagrees,
so `P(e_R ≥ 1 | honest)` is zero exactly, at every budget and every key length. Phase 4 requires
those ten members to prove exactly zero rather than something small, and the test suite enforces
it. It is also the sharpest possible illustration of why `null_is_noiseless` is a column: a bound
of zero is a claim about a *noiseless* link, and on a genuinely noisy honest channel the same
member fires, correctly, because the null was the wrong one for that deployment.

### The recipient forger, and why the ordering is a column

**This is the strongest result in the sweep and the easiest to destroy in prose.**

| `L` | ordering | engaged | Charlie accepted (**measured**) | rejected | **no verdict** | exact `P` | **proven** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 96 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `2.9663e-01` | `8.207e-01` |
| 96 | after | 400 | `120/400 = 0.3000 [0.2446, 0.3619]` | 280 | 0 | `2.9663e-01` | `8.207e-01` |
| 192 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `2.0459e-01` | `6.736e-01` |
| 192 | after | 400 | `63/400 = 0.1575 [0.1162, 0.2100]` | 337 | 0 | `2.0459e-01` | `6.736e-01` |
| 384 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `1.1260e-01` | `4.538e-01` |
| 384 | after | 400 | `49/400 = 0.1225 [0.0863, 0.1710]` | 351 | 0 | `1.1260e-01` | `4.538e-01` |
| 768 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `4.0360e-02` | `2.059e-01` |
| 768 | after | 400 | `11/400 = 0.0275 [0.0129, 0.0575]` | 389 | 0 | `4.0360e-02` | `2.059e-01` |
| 1200 | before | 400 | `0/400 = 0.0000 [0.0000, 0.0163]` | 0 | **400** | `1.4002e-02` | `8.465e-02` |
| 1200 | after | 400 | `6/400 = 0.0150 [0.0055, 0.0403]` | 394 | 0 | `1.4002e-02` | `8.465e-02` |

**The `before` rows measure a denial of transfer, not a caught forgery.** A substituted declaration
leaves Charlie's pooled matched count undefined, so Bob accepts and Charlie alone reaches no
verdict, on every one of the 400 runs. Their `0/400` acceptance is the acceptance rate of an attack that
denies rather than forges.

**The `after` rows measure a forgery rate.** Charlie returns a real verdict on all 400 and accepts
120 of them at `L = 96`, against a closed form of 0.29663.

Pooling the two orderings at `L = 96` would publish `120/800 = 15%`, a figure describing neither
run. **Any sentence saying "the recipient forgery rate is X" without naming the ordering is
wrong**, and that is why timing is a column in every table in this phase and never a thing
averaged over.

`Bob accepted` reads `forger` on all ten recipient rows. Bob *is* the adversary there; it is not
a hypothesis that was ruled out and it is not a zero.

**The closed form describes the `after` rows and not the `before` ones, and the table shows it.**
`recipient_forgery_probability` is the probability that Charlie *accepts*, which presupposes he
reaches a verdict. All five `after` rows have their closed form inside the measured interval. Four
of the five `before` rows have it outside, because those runs measure `0/400` acceptances out of
400 refusals; the model is not describing that experiment. The fifth, `L = 1200`, falls inside
only because `1.4002e-02` has already dropped below the `0.0163` that 400 trials can resolve, so
its agreement is a coincidence of sample size and not a validation. Across the two families, every
row where the closed form's event can occur has it inside the interval: **21 for 21**.

The ladder stops at `L = 1200` for the same reason Eve's stops at 30: 400 trials expect
`400 × 1.4002e-02 = 5.6` acceptances there, against `0.36` at `L = 2400`.

The recipient forger is the binding adversary and the one a security claim should quote; at
`L = 115200` the proven bound is `1.124e-103`, and no sample this project can afford will ever
see it.

---

## 9. ROC: detection against a swept false-positive budget

> Regenerate: `python tools/sweep.py reduce roc --results ~/.sih141/results`
> Chart: add `--charts docs/figures`
> Full tables: [`docs/tables/roc.md`](tables/roc.md) · [`docs/figures/roc.svg`](figures/roc.svg)

**The question.** As the detector's false-positive budget `eps` is swept over a committed
fifteen-rung ladder, what detection rate does the Phase 4 detector achieve against each adversary
, with every operating point obtained by passing that `eps` to the shipped `detect()`, and no
threshold moved by hand?

**`eps` is a reduce-time axis, not a cell dimension.** A trial's seed is a pure function of
`(experiment, cell, index)`, so making `eps` a cell would give every operating point a different
sample and a five-percent wobble at `n = 40` would be sampling noise. Instead the cells retain
their transcripts and the reduction hands each one to `detect()` once per budget. That is cheap
against the session it re-scores: the production run's own timing table gives 29.4 ms per
`detect()` against 2.14 s per session at `L = 384`, so the whole fifteen-rung ladder costs about a
fifth of one session. And the ladder is not frozen: a reviewer who wants a point between two of
ours re-reduces, and nobody re-runs.

**The cells.** Fifteen at `L = 384`, 40 trials each. Fourteen run at `check_fraction = 0.25`, the
only arrangement where the channel family is evaluable at all, and the configuration Phase 4 §5
published, so the `eps=1e-9` column is directly comparable. The fifteenth, `honest-unchecked`, runs
at `check_fraction = 0` precisely so the table has a row where the channel family is withheld and
reads `not evaluated`. Eleven are scored against the noiseless null; four `tol-` cells are scored
against the link's true error rate (`channel_error_rate = 0.025`,
`tolerated_depolarising = 0.05`).

**Two rates, two denominators, both printed on the row.** `detected` is over `attacked`: runs
whose adversary engaged, counted off the adversary's own log. `false alarms` is over `clean`:
runs on which no adversary acted, *including the untargeted runs of a selective cell*, because
such a run is byte-identical to an honest one. `attacked + clean == runs`, always.

That distinction is worth 45 percentage points on one row: `starvation-selective` engaged on 22 of
its 40 runs, and scoring the whole cell as attacked would have published `22/40 = 0.550` against
the true `22/22 = 1.000`.

**Aborts are neither.** `refusals` is its own column and is added to nothing. The detector returned
a verdict on every run in both denominators, refusal or not, so no run has been dropped.

### At `eps = 1e-9`, the budget Phase 4 published

| arm | attacked | detected (**measured**) | clean | false alarms (**measured**) | refusals | **proven** FP bound | null noiseless |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `honest` | 0 | *no trials* | 40 | `0/40 = 0.000 [0.000, 0.142]` | 0 | `3.3964e-10` | yes |
| `honest-unchecked` | 0 | *no trials* | 40 | `0/40 = 0.000 [0.000, 0.142]` | 0 | `2.7818e-10` | yes |
| `outside-forgery` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 0 | `3.3964e-10` | yes |
| `recipient-forgery` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 40 | `3.3964e-10` | yes |
| `recipient-forgery-after` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 40 | `3.3964e-10` | yes |
| `replay` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 40 | `3.3964e-10` | yes |
| `starvation` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 40 | `3.3964e-10` | yes |
| `starvation-selective` | 22 | `22/22 = 1.000 [0.768, 1.000]` | 18 | `0/18 = 0.000 [0.000, 0.269]` | 22 | `3.3964e-10` | yes |
| `impersonation-signing` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 0 | `3.3964e-10` | yes |
| `impersonation-full` | 40 | **`undetectable-by-construction`** | 0 | *no trials* | 0 | `3.3964e-10` | yes |
| `channel-bob` | 40 | `40/40 = 1.000 [0.858, 1.000]` | 0 | *no trials* | 0 | `3.3964e-10` | yes |
| `tol-honest` | 0 | *no trials* | 40 | `0/40 = 0.000 [0.000, 0.142]` | 0 | `7.3122e-10` | **no** |
| `tol-p05` | 40 | `0/40 = 0.000 [0.000, 0.142]` | 0 | *no trials* | 0 | `7.3101e-10` | **no** |
| `tol-p20` | 40 | `0/40 = 0.000 [0.000, 0.142]` | 0 | *no trials* | 0 | `7.2267e-10` | **no** |
| `tol-p35` | 40 | `0/40 = 0.000 [0.000, 0.142]` | 0 | *no trials* | 0 | `7.1991e-10` | **no** |

`impersonation-full` is assumption **(AUTH)**: the attack is excluded by hypothesis, so the cell
reads `undetectable-by-construction` and not a zero. Its *clean* column stays a measurement,
because the assumption is about the attack and not about the runs it left alone.

**The anchor reproduces Phase 4 exactly, from a different seed set through different code.** 39 of
40 honest checked runs prove `3.3964e-10` and one proves `3.1464e-10` with `channel:Bob/1:chsh`
withheld; both figures, including the footnote about an empty CHSH cell, are what
`docs/PHASE4.md` prints. The unchecked cell proves `2.7818e-10`.

### Where the curve has a shape, and where it does not

Every cell is a **measured** rate with its sample size and a 99% Wilson interval; there is no
proven quantity in this table.

| arm | at `eps=5e-01` | at `eps=1e-09` | at `eps=1e-30` | first falls below 1.0 at |
| --- | --- | --- | --- | --- |
| each of the eight noiseless-null attack arms | `40/40 = 1.000 [0.858, 1.000]` † | `40/40 = 1.000 [0.858, 1.000]` † | `40/40 = 1.000 [0.858, 1.000]` † | never |
| `tol-p35` (depolariser at 7× tolerated) | `40/40 = 1.000 [0.858, 1.000]` | `0/40 = 0.000 [0.000, 0.142]` | `0/40 = 0.000 [0.000, 0.142]` | `1e-02` |
| `tol-p20` | `26/40 = 0.650 [0.447, 0.810]` | `0/40 = 0.000 [0.000, 0.142]` | `0/40 = 0.000 [0.000, 0.142]` | below 1.0 at every budget |
| `tol-p05` (exactly the tolerated level) | `4/40 = 0.100 [0.030, 0.284]` | `0/40 = 0.000 [0.000, 0.142]` | `0/40 = 0.000 [0.000, 0.142]` | below 1.0 at every budget |

† `starvation-selective` is the exception in the denominator only: 22 of its 40 runs were attacked,
so its cell reads `22/22 = 1.000 [0.768, 1.000]` at every budget, over a smaller sample and a wider
interval. Its other 18 runs are in the *clean* denominator, where they measure `0/18`.

**Under a noiseless null the ROC is flat at 1.0 across thirty decades of budget.** That is not a
detector without discrimination; it is a separation so large that the derived cut is nowhere near
the boundary, and `eps` is simply not the binding constraint for those adversaries.

**Under the true-rate null the curve has a shape**, and `tol-p35` walks down it: 40, 40, 39, 30,
18, 11, 3, 1, 0 as the budget tightens from `5e-1` to `1e-8`.

**Every arm that reports a zero is checked for whether it acted at all**, on the adversary's own
log and not on the cell's intent, because Phase 4's replay arm once reported a clean `0/40` while
having forwarded honestly throughout. Read straight off the production records: `tol-p05` touched
27 to 50 hops per run, `tol-p20` 128 to 180 and `tol-p35` 241 to 301. Their `0/40` at `eps = 1e-9`
is a detector that did not fire on an attack that certainly happened. That is the result. And
`attacked + clean == runs == 40` on all fifteen cells, so no run is missing from either
denominator.

**Monotonicity is checked per run, not per rate.** Because every budget scores the same transcript,
a run that fires at a tighter `eps` must fire at every looser one, so the check is an up-set test
over each of the 600 records' own fifteen verdicts, not a comparison of rates. `up-set holds`
reads `yes` on all fifteen arms, and a test feeds the checker a crafted non-monotone ladder to
prove it can say `no`.

**No proven bound exceeds its own budget, anywhere on the grid.** Zero of 225 rows, checked by
reading the published table back and dividing: the slack runs **1.13×–2.82×** at `eps = 5e-1` and
**2.38×–6.82×** at `eps = 1e-30`. Publishing `eps` instead of `Detection.false_positive_bound`
would overstate the detector's own false-alarm rate by those factors.

**One member loses its admissible operating point above the tightest budget anyone asks for.**
`structural:evidence-abort` has no admissible cut below `eps = 4.879e-19`, bisected on a retained
transcript from this sweep. That is *above* `2**-64` (`5.421e-20`), the smallest budget this
project quotes, so at the tightest budget anyone would ask for the member is withheld and the
table reads `not evaluated`, never `passed`. It bisects to the same crossover on every run, so
it is a property of the parameters and not of a sample.

### Against the Phase 3 prototype

| detector | attacked arms separated | false alarms (**measured**) | false-alarm bound (**proven**) | how the threshold was chosen |
| --- | --- | --- | --- | --- |
| Phase 3 prototype | 4 of 5 adversaries at 100% | `0/80` observed | none, there is no null to invert | tuned on the runs in front of it |
| Phase 4 at `eps=1e-9`, noiseless null | 8 of 8 attacked arms at 100%; 1 `undetectable-by-construction` | `0/98 = 0.000 [0.000, 0.063]` | `3.3964e-10` per run, under the honest null | derived (D7) |
| Phase 4 at `eps=1e-9`, true rate as null | **0 of 3** attacked arms at 100% | `0/40 = 0.000 [0.000, 0.142]` | `7.3122e-10` per run, under the honest null | derived (D7) |

The two false-alarm columns are not the same kind of statement. `0/80` and `0/98` are both
*observations*, and both are consistent with a true false-alarm rate of a few percent; the proven
column is a statement about every run that will ever be scored. The sample size is what the
derivation makes irrelevant.

**A lower detection rate from a derived threshold is a better result than a higher rate from a
tuned one.** The `0 of 3` row is where the derived detector gives ground, and the reason is stated
rather than tuned away: once the link's own error rate is admitted into the null, an adversary at
or near that level is inside the noise the protocol already tolerates. That is a result about the
protocol's observability, and D7 forbids moving a threshold to improve it.

---

## 10. The honest baseline, and what a noiseless null costs

> Regenerate: `python tools/sweep.py reduce honest --results ~/.sih141/results` and
> `python tools/sweep.py reduce noise --results ~/.sih141/results`
> Full tables: [`docs/tables/honest.md`](tables/honest.md) ·
> [`docs/tables/noise.md`](tables/noise.md)

**`honest`** is the false-alarm arm: 30 honest runs on a noiseless link at each of `L = 192, 384,
768`, `check_fraction = 0.25`. Every one measures `0/30 = 0.000 [0.000, 0.181]` flagged, against a
proven per-run bound of `3.865e-10`, `3.396e-10` and `4.177e-10`. The measurement is not the
result, since the sample is far too small to see `1e-10`; the *proof* is, and the measurement is the check
that nothing in the pipeline contradicts it.

**`noise`** is the arm where the null is not the truth. Honest parties, a depolarising wire at four
strengths, all scored against the noiseless null:

| depolarising strength | attacked | flagged (**measured**) | refusals | **proven** FP bound | null noiseless |
| --- | --- | --- | --- | --- | --- |
| 0.0 | 0 | *no trials*, clean column reads `0/30 = 0.000 [0.000, 0.181]` | 0 | `3.396e-10` | yes |
| 0.0025 | 30 | `14/30 = 0.467 [0.260, 0.685]` | 0 | `3.396e-10` | yes |
| 0.005 | 30 | `23/30 = 0.767 [0.532, 0.905]` | 0 | `3.396e-10` | yes |
| 0.010 | 30 | `28/30 = 0.933 [0.723, 0.987]` | 0 | `3.396e-10` | yes |

Read this row by row and it says "the detector catches channel noise". Read the last column and it
says something more useful and much less comfortable: **an honest run over a noisy link departs
from a noiseless null, and the detector reports it as a detection with a proven bound, correctly.**
The behaviour is right. The claim is only right with `null_is_noiseless` attached, which is Phase 4
audit finding A3-1, and it is why that field is a column and not a paragraph.

**Passing the link's true rate turns the whole column off, and §9's `tol-` cells are the evidence
in this sweep.** `tol-honest` runs a noiseless link scored against `channel_error_rate = 0.025` and
measures `0/40` false alarms; `tol-p05` runs a depolariser at exactly the tolerated level, whose
mismatch rate *is* 0.025, and measures `0/40` detections at `eps = 1e-9`. A null at or above the
link's truth is a null honest runs do not depart from, which is the whole point, and also why the
`tol-` arms are the only place in this phase where the detector gives ground.

Do not try to infer the noise level inside the detector: at `check_fraction = 0` the transcript
does not carry it, and guessing it would be inventing a null.

**Dominance.** `dominance_noise_level()` is published beside every mismatch-rate detection rate. At
`DEFAULT_PARAMS` and `eps = 1e-9` the crossover is `0.012119`, *below* the design noise level
`2·s_a = 0.03125`. So on a link as noisy as the scheme tolerates, the mismatch detector adds
nothing over the verifier's own cut. Over the matched counts the repudiation sweep produced
(`|M_R|` from 2 to 299) it runs `0.000000` to `0.009459` at Charlie's cut, which is lower still.
At demo scale that detector is dominated on any link that is noisy at all. It is not dominated in
those tables only because those runs are on a genuinely noiseless link, where the null is the truth
and the mismatches come from Alice.

---

## 11. Throughput, and the two figures that did not survive a reproduction

Everything in §§11–12 is a measurement of **this machine**, not of the protocol, and it is the
only part of this document that is not bit-reproducible. That distinction is doing real work
here: the integration pass re-ran every command printed in this section and two of them came back
with different numbers, one because the published figure was simply wrong and one because the
quantity is not stable enough to publish as a number.

### 11.1 Session cost against key length

> Regenerate: `python tools/sweep.py perf --session-scaling --key-lengths 96,192,768`
> The full-scale row is one end-to-end run at `seed 20260905`, timed with nothing attached.

| `L` | check fraction | seconds | ms/position | positions/s | KiB/position |
| --- | --- | --- | --- | --- | --- |
| 96 | 0.25 | 0.211 | 2.198 | 455 | 0.337 |
| 192 | 0.25 | 0.420 | 2.188 | 457 | 0.330 |
| 768 | 0.25 | 1.650 | 2.148 | 465 | 0.325 |
| **115200** | **0.0** | **235.09** | **2.041** | **490** | **0.226** |
| 115200 | 0.25 | n/a | n/a | n/a | 0.330 |

**Where each column comes from.** The three small rows are one `perf --session-scaling` run,
which seeds length `L` at `5 + L`. The `115200` timing is a separate end-to-end run at seed
20260905; its size column and the `check_fraction = 0.25` row underneath were measured through the
same `time_session` at seed `5 + L`. Sizes are deterministic in the seed, so mixing the two is safe
for that column and would not be for the timings.

The timings **reproduce**: re-running the command during the integration pass gave 0.209, 0.419 and
1.636 seconds, within 1% of the row above on all three, and a third reading at `L = 96` once the
machine was quiet again gave 0.211 s, the published value to the millisecond. Which is itself the
§11.2 finding in miniature: the same command on the same machine reads 2.195 ms/position when
nothing else is running and about 3.2 when a browser is. The full-scale row confirms the 230.2 s
already in `docs/QDS.md` to within 2.1%, so the 6.7 ms/position figure, a `tracemalloc` artefact
that inflated every timing by very close to three times, stays dead.
`REFERENCE_MS_PER_POSITION = 2.041` is the one number the run plan rests on, and every total derived
from it is a doctest over that constant.

**But the rate itself is a best case, not a constant.** §11.2 has the evidence: on a machine with a
browser open, sustained single-threaded throughput at `L = 768` is about 3.2 ms/position rather
than 2.15, because a lone core stops boosting as soon as anything else is awake. Quote 2.041 as
what this machine does when nothing else is running, which is the condition the run plan should be
built under, and not as a property of the code.

**The size column was wrong for a whole release, and the doctest beside it could not have caught
it.** The three small rows read `0.408`, `0.371` and `0.339`. Running the command above now gives
`0.337`, `0.330` and `0.325`: 21%, 12% and 4% high. Transcript size is deterministic in the seed
(four seeds at `L = 96` spread by under 0.001 KiB/position), so this was not measurement noise:
`0.408` is roughly what `L = 96` gives at a check fraction near **0.42**, and the figures had come
from a different configuration. They survived because the only test on them looked the constant up
in its own dict. A doctest that reads a dict literal proves the literal is still there.

`MEASURED_TRANSCRIPT_KB` now **re-measures** two lengths at both check fractions, which costs about
a second and fails if a figure is copied from the wrong configuration. Restoring `0.408` turns the
suite red, which is the property the previous test did not have.

Two corrections ride along with it.

**The curve is not monotone.** The earlier text said the size "falls with `L` towards 0.33 as the
fixed header is amortised". It falls to a minimum of `0.325` around `L = 768` and then comes back
to `0.330` at full scale, because a second effect runs the other way: the per-position integers
grow a digit as the indices they name get larger. The unchecked series does the same, dipping to
`0.220` at `L = 768` and returning to `0.226`.

**Kibibytes and kilobytes were mixed in one sentence.** `kb_per_position` is `len(json) / 1024`, so
a full-scale unchecked transcript is `0.226 × 115200 / 1024 = ` **25.4 MiB**, not the "26.7 MB" the
earlier text printed; that was the same byte count in decimal megabytes, sitting next to a figure
derived in binary ones. The checked run is **37.2 MiB** (38,971,467 bytes). Both are now stated in
MiB, which is what the constant divides by.

**Detector latency is not a constant few milliseconds.** It is 1.54 s on a full-scale unchecked
transcript against 2.9 ms on a 96-position one, because it is dominated by parsing the JSON, so it
scales with `L` like everything else. Still under one percent of the session that produced it.
Like every other timing here it is a machine measurement and moves with the machine's state: a
contended reading during the integration pass gave 2.16 s for the same transcript. The *shape*
(three orders of magnitude across a 1200-fold range in `L`) is what the figure is for.

### 11.2 Parallel speedup: measured twice, and it did not reproduce

> Regenerate: `python tools/sweep.py perf --speedup --speedup-cell l768 --trials 120 --workers 1,4,8,14,20`
> 120 honest sessions at `L = 768` per point, each point into a fresh results directory so a
> resumed sweep could not time an empty run.

| workers | wall s (first run) | speedup | wall s (**re-run, integration pass**) | speedup |
| --- | --- | --- | --- | --- |
| 1 | 204.81 | 1.00 | **305.47** | 1.00 |
| 4 | 59.86 | 3.42 | 77.41 | 3.95 |
| 8 | 40.37 | 5.07 | 52.36 | 5.83 |
| 14 | 34.44 | 5.95 | 36.60 | 8.35 |
| 20 | 29.10 | **7.04** | 29.75 | **10.27** |

**The twenty-worker wall clock reproduces to 2.2%. The one-worker baseline moved by 49%, and the
speedup is a ratio with that baseline in the denominator.** So `7.04×` is not a number this
document can publish as a stable measurement, and neither is `10.27×`.

The diagnosis, measured rather than assumed. Eight consecutive single sessions at `L = 768` on the
re-run machine give `1.746` s for the first and about `2.48` s for every one after it, a 42% ramp
within seconds, which is the all-core turbo budget collapsing as soon as anything else is awake.
The machine during the re-run was carrying a browser, two chat applications and two game launchers
at 10% load, which is precisely the state the phase brief anticipates when it says to leave eight
logical threads free so the human can keep working. The first run's machine was quieter.

So what should be quoted:

- **The wall clock at twenty workers is reproducible.** 29.10 s and 29.75 s for 120 sessions at
  `L = 768`, on two different days, in two different machine states. Quote this.
- **The speedup ratio is not.** It says how much better twenty workers are *than this machine's
  single-core state at that moment*, and that state moves by half. Quote it with both measurements
  or not at all.
- **`docs/QDS.md`'s original "15× effective speedup" is still wrong**, and both measurements agree
  on that. At 7.04× two hundred trials at `DEFAULT_PARAMS` is 1.9 hours; at 10.27× it is 1.3 hours;
  at 15× it would be 52 minutes, and neither run supports that.

Two things that are *not* the cause, checked rather than assumed. **Not idle workers:** occupancy
(in-worker seconds over the sweep's own wall clock) is 17.74 of 20 on the first run and 17.61 on
the second, so the pool is busy; it is the cores that are slow. The production sweep gives the same
answer independently: the `scaling` experiment's in-worker session seconds total 2225.21 against a
manifest wall clock of 117.0 s, an occupancy of **19.02 of 20**. **Not BLAS oversubscription:**
every worker is asked what it sees, in its own process, and all five thread-limit variables read
`1`.

What it is, is the per-trial cost rising with worker count, and the two runs' per-trial columns
make the mechanism visible:

| workers | s/trial, first run | s/trial, **re-run** |
| --- | --- | --- |
| 1 | 1.700 | 2.538 |
| 4 | 1.943 | 2.533 |
| 8 | 2.546 | 3.374 |
| 14 | 3.634 | 3.839 |
| 20 | 4.302 | 4.366 |

**On the re-run, one worker and four workers cost exactly the same per trial**: 2.538 s against
2.533 s, where on the first run four workers already cost 14% more. A lone worker that is no
faster than four of them is a lone worker that was never getting a single-core boost. That is the
whole diagnosis: the baseline had already collapsed to all-core clocks before the sweep started,
and the twenty-worker column, where every core is pinned anyway, barely moved between the two runs
(4.302 against 4.366).

So the contention is real and it starts **before the E-cores are reached**: eight workers on an
eight-P-core part cost 1.50× per trial on a quiet machine. But it is the all-core turbo budget
plus shared L3 and memory bandwidth, not the pool. The further growth from 14 to 20 is the twelve
E-cores, slower per clock for scalar Python.

**Use 20 workers anyway** (29.75 s beats 36.60 s at fourteen), but the marginal return past eight
is poor, so if the laptop must stay usable during a sweep, eight workers cost about 40% more wall
clock and leave twelve logical threads free.

**Do not quote any of this at `L = 115200`.** It was measured at `L = 768`, where a trial is under
three seconds and pool startup is a visible share of the parallel points. At full scale startup
vanishes but each worker holds a far larger transcript.

### 11.3 What the timing column in a results table is not

Every experiment's timing table prints `ms/position`, and **it is not the protocol's cost.** It
carries the contention of whatever worker count produced those records, and it also carries
whatever the adversary in that cell costs on top of the session.

Across the production sweep at twenty workers the column runs from **2.415** (`smoke`, four trials,
so the pool barely fills) to **10.407** (`roc`'s `replay` cell, which runs one extra
capture session per worker process, cached but amortised over only the two trials that worker
gets), against a single-threaded reference of **2.041**. The honest cells at the same
key length sit at 5.0–7.5. Multiplying any of those by a key length to project a production run
overstates it by two to five times. The tables say so in a footnote of their own, because this is
the same species as `null_is_noiseless`: arithmetically right, misleading without its condition.

---

## 12. Memory, and the edges

> Regenerate: `python tools/sweep.py perf --memory --key-lengths 96,768,3072,12288,49152,115200`
> Every row is at `check_fraction = 0.25`, the expensive case. Peak RSS is read from
> `GetProcessMemoryInfo`, **not** `tracemalloc`.

| `L` | peak RSS MiB (first run) | peak RSS MiB (**re-run**) | transcript MiB |
| --- | --- | --- | --- |
| 96 | 78.5 | 79.1 | 0.03 |
| 768 | 80.4 | 80.8 | 0.24 |
| 3072 | 86.2 | 87.3 | 0.98 |
| 12288 | 107.3 | 107.7 | 3.92 |
| 49152 | 197.0 | 198.1 | 15.82 |
| **115200** | **348.7** | **352.0** | **37.17** |

**This one reproduces.** Peak RSS agrees within 1% on every row and the transcript column is
identical to the byte, because it is deterministic. Where the timing measurements are hostage to
the machine's clock state, memory is not.

The floor is a little under 80 MiB (numpy and qiskit imported, before any session), which both
runs agree on: 78.5 MiB minus a 0.9 MiB rise on the first, 79.1 minus 0.9 on the second. At full
scale one worker peaks at 350 MiB, so twenty are about **7 GiB** against this machine's 24. That fits, but it is not
the "20 workers is under 2 GB" the phase brief records: that figure is twenty import floors and
does not count the transcripts. The production set is unchecked and therefore cheaper than the last
row. Memory is not the binding constraint here, but it is the one that would bind first on a
smaller machine.

That probe shipped a real defect worth recording: ctypes defaults every argument to a 32-bit int,
so the pseudo-handle `-1` from `GetCurrentProcess` arrived as `0xFFFFFFFF` rather than a 64-bit
`HANDLE`, the call failed, and **every row read `0.0 MB`**, which looks exactly like a process
that used no memory. There is a test that fails if it breaks again.

### The degenerate small end

> Regenerate: `python tools/sweep.py perf --small-end`
> Five honest sessions per length at `check_fraction = 0.25`.

**This table had no committed command until the integration pass, and under D9 that is the same as
having no figures.** Its numbers came from an ad-hoc probe. `measure_small_end` and the
`--small-end` flag now produce it, and regenerating it changed three cells.

| `L` | signing length | `m_min` | `M_min` | aborts / 5 | security claim | families withheld |
| --- | --- | --- | --- | --- | --- | --- |
| 3 | parameter set **refused** | n/a | n/a | n/a | n/a | n/a |
| 6 | 5 | 1 | 1 | 1 | no | 3 |
| 12 | 9 | 1 | 1 | 1 | no | 5 |
| 24 | 18 | 1 | 1 | 0 | no | 5 |
| 96 | 72 | 1 | 1 | 0 | no | **1–4** |
| 180 | 135 | 1 | 1 | 0 | no | **0–2** |
| **182** | **137** | 1 | **2** | 0 | **yes** | **0–4** |
| 384 | 288 | 4 | 62 | 0 | yes | 0 |

**The withheld column is a range now, and it should always have been one.** The earlier table
printed `4`, `2` and `1` for those three rows: one draw each, published as a property. Below about
`L = 216` whether a detector family is evaluable depends on how the check rounds happened to split
between the QBER and CHSH cells, so a single run's answer is a sample and not a fact about the
length. The section's own prose already said that; the table now measures it.

Three more things worth carrying forward:

- **The claim boundary is `L = 182`, not 140.** The number to hold onto is the *signing* length,
  137. A quarter of the positions go to check rounds, so a caller who sets `key_length = 140`
  because "below 140 the floors degenerate" gets a signing length of 105 and no claim at all. Below
  the boundary runs still complete and the detector still returns a verdict; what it does not return
  is a claim.
- **Aborts appear on honest runs at the very small end** (one in five at `L = 6` and `L = 12`)
  because a verifier's matched set falls under the floor. Those are no-verdicts, not rejections, and
  any table drawn there has a 20% denominator problem.
- **`ProtocolParams(key_length=3, check_fraction=0.25)` refuses to exist.** `floor(0.25 × 3)` is
  zero check rounds, so the set would claim estimation while estimating nothing. It is a **row**
  here, not a gap: a length missing from a table reads as one nobody tried.

The large end is bounded by time, not memory. `L = 115200` is 235 s per session single-threaded on
a quiet machine, and linear scaling means the largest `L` that finishes in a sane time is whatever
the human's patience divided by 2.041 ms allows.

---

## 13. Limitations, stated plainly

Each of these is worse if a judge finds it first.

**1. Demo-scale runs cannot demonstrate non-repudiation.** §7 has the arithmetic. At `L = 768`,
400 trials measure `0/400` with a 99% upper limit of `0.0163`; the exact in-model probability is
`5.845e-04`, twenty-eight times finer than the sample can resolve; the proven bound is `9.212e-01`,
fifty-six times looser than the measurement. The region the claim lives in (`1.4139e-09` at
`L = 115200`) is unreachable by both. The proof is vacuous where a measurement can reach and the
measurement is blind where the proof bites.

**2. Full impersonation is undetectable by construction.** Assumption (AUTH). It appears in every
table as `undetectable-by-construction`, because a hypothesis missing from a table reads as one that
was ruled out and a zero reads as one we tried and failed to catch.

**3. There is no false-negative bound and there cannot be one from a transcript.** Every proven
bound in `detect/` is under the honest null. Every detection rate in this document is a measurement
with a sample size and an interval, and it is labelled `measured` wherever it appears.

**4. The detector at or near the tolerated noise level catches nothing, once the null is honest.**
`tol-p05` sits exactly at the tolerated level and measures `0/40` at `eps = 1e-9`. That is a result
about the protocol's observability, not a detector defect, and it was not tuned away (D7).

**5. `dominance_noise_level` is below the design noise level.** At `DEFAULT_PARAMS` and
`eps = 1e-9` the crossover is `0.012119` against a tolerated `2·s_a = 0.03125`, so on a link as
noisy as the scheme tolerates the mismatch detector adds nothing over the verifier's own cut.

**6. The whole channel family is unevaluable without check rounds.** Every `check_fraction = 0`
run in §§7–8 has it withheld, and the tables read `not evaluated`, never `passed`. An unmonitored
link is not a clean one.

**7. Two performance figures are machine-state measurements and one of them does not reproduce.**
§11.2. The parallel speedup moved from 7.04× to 10.27× between two runs of the same command,
because the single-worker baseline moved by half. Nothing derived from a speedup ratio in this
project should be quoted without both numbers.

**8. This store's provenance was dirty, and no longer is.** *(Closed, kept as history.)* The first
production store recorded `dirty: true` on every manifest, so its commit stamp did not describe
the code that produced it. It was deleted and the seven lines were run again from a committed
tree: all seven manifests in the shipped store record `f94d9fe` with `dirty: false` (§5). Nothing
in this limitation applies to the numbers published here.

**9. The samples are small where the effects are small.** 400 trials resolve about `0.016` at the
99% level and 40 trials resolve about `0.14`. Every rate in this document that reads `0.000` is a
statement about what a sample of that size could see, and the interval beside it says how little
that is.

**10. "Flat at 1.0" is a 40-trial statement, and it cuts both ways.** §9's headline (every attacked
arm at 100% across thirty decades of budget) has a 99% Wilson interval of `[0.858, 1.000]`. The
measurement is equally consistent with a true detection rate of 90%, and 40 trials cannot tell the
two apart. What the flat curve does establish, and it is the useful part, is that the *budget* is
not what limits those arms: moving `eps` by thirty orders of magnitude does not move a single run's
verdict. A larger `n` would narrow the rate; it would not change that conclusion.

---

## 14. What the reduction refuses to do

These come out of the Phase 3 and Phase 4 audits and are constraints on the **table**, not only
on the code that fills it. Each is enforced in a type or a test rather than documented and hoped
for.

**A no-verdict is not a rejection.** Counting goes through
`sih141.detect.thresholds_structural.OutcomeTally`, which has no field summing a rejection with a
refusal and whose two no-verdict counts raise a `TypeError` if added to an `int`. Every rate
prints its denominator, and the aborts get their own column. A row reading "detection 92%" with
8% silently aborted is a false claim.

That was the enforcement, and the integration pass found it insufficient in the one place it
mattered most. `outcome_table` converts the tally's no-verdict counts to plain `int`s to print
them, and once they are `int`s nothing stops one being added to another. Adding `refused` into
`rejected` and printing a zero left **328 tests and doctests green**, because every fixture that
reached the shared tables was an honest cell with no refusals to fold: the check existed and
could not fail. The two experiment families' own tables were protected; the two *shared* tables,
which appear in all seven experiment files, were not.

What closes it is a fixture that actually refuses (a recipient forger at `L = 96` under the
shipped ordering, Bob accepted and Charlie refused, in a fifth of a second), with the four verdict
columns recomputed from the record's own verdicts and compared against the table's. Re-applying
the fold now fails. `detection_table` also grew a `refusals (any party)` column, because it was
printing `flagged on attacked 400/400 = 1.000` on rows where all 400 runs were a Charlie
no-verdict.

**The two count orderings are never pooled.** `count_exchange_timing` is part of the grouping key
of every table, so one cell can become two rows. `OutcomeTally.merge` refuses two tallies that
disagree on it.

**Measured is not proven.** A detection rate is a measurement with a sample size and a 99% Wilson
interval, and the column header says `measured`. A false-positive bound is proven under the
honest null and its header says `proven`. There is no false-negative bound and there cannot be
one from a transcript, so nothing here prints one. An empty denominator reads `no trials`, never
`0.000`; a zero reads as a measurement that found nothing, which is a different claim from an
absent measurement.

**An unevaluated family is not a passed one.** `Detection.withheld` names families that could not
be scored, and those cells read `not evaluated`.

**A null that was not the truth is a column.** `null_is_noiseless` rides on every detection row.
A mismatch-rate detection under a noiseless null on a genuinely noisy link is arithmetically
correct and still a false claim once the null goes unstated. That is Phase 4 audit finding A3-1.

**Every table carries the command that regenerates it.** It is a field of the `Table` type rather
than something a writer is trusted to remember, and a table built without one prints
"**no command recorded -- this table is not reproducible and must not be published (D9)**", which
is louder than silence.

**Provenance is printed above the tables**: the commit, whether the tree was dirty, the worker
counts, and every command that produced the records being reduced. Results spanning two commits
say so, because a table drawn across a code change has two meanings.

---

## 15. Adding an experiment

A scenario is one function:

```python
def scenario(cell: Cell, seeds: TrialSeeds) -> tuple[SessionTranscript, GroundTruth]
```

registered in `sih141.eval.experiments.SCENARIOS`. Its three obligations are in that module's
docstring: take randomness only from `seeds`, report `engaged` off the adversary's own log, and
do not call the detector. Nothing in the runner, the store, the manifest or the reduction changes
when one is added.

A family that needs tables of its own registers a callable taking
`(records, *, command, cell_order, expected)` in `reduce.EXTRA_REDUCTIONS`, and a chart renderer
in `EXTRA_CHARTS`. `expected` is the per-cell trial count the store's manifests asked for: a
family that builds its own completeness footnote without it can check only for interior gaps, and
for one release the ROC grid printed "No manifest recorded a trial count for this store" while the
outcome table three sections above it, in the same file, said "Complete: every cell has all the
trials its manifest asked for". Both cannot be true of one store, and a reader has no way to tell
which.

Every registry write goes through `sih141.eval.experiments.claim`, which refuses to displace a key
another family owns (in both directions), because yielding leaves a family registered nowhere,
which from outside looks exactly like a family nobody wrote.

Seven experiments ship:

| name | what it is for |
| --- | --- |
| `repudiation-curve` | Can a signer repudiate, against key length, with the exact closed form and the proven bound beside the measurement. §7. |
| `forgery-curve` | Can a declaration be forged, outside and by a recipient, under both count orderings. §8. |
| `roc` | Detection against a swept false-positive budget, per adversary. §9. |
| `honest` | Honest runs on a noiseless link at three key lengths. The false-positive arm. |
| `noise` | Honest parties over a depolarising wire at six strengths, scored against the noiseless null. The arm where `null_is_noiseless` decides whether a row is a false claim. |
| `scaling` | Throughput against key length, run through the real runner so the timing table can be checked against the manifest. |
| `smoke` | Four trials at `L = 96`, for exercising the harness. |
