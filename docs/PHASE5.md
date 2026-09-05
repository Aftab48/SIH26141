# Phase 5 — The evaluation harness, and what this machine actually costs

Engineering note for `sih141/eval` and `tools/sweep.py`. Covers the harness every downstream
experiment runs on, the seed rule that makes a parallel sweep publishable, and the measured
performance of the machine it runs on — including the estimate in the run plan that turned
out to be wrong by a factor of two, and the correction this document had to make to itself.

**Status: the harness is complete; the experiments are not.** §§1–4 are the plumbing, §§5–7
are the machine, §8 is what the reduction refuses to do and §9 is how to add an experiment.
There are no results tables here yet, and when there are, every one of them will have been
produced by `tools/sweep.py reduce` against seeds on disk, because that is what D9 requires.

---

## 0. The rule this phase is built around

> **D9. Every published number is reproducible from a recorded seed and a committed command.**

An evaluation phase's only product is numbers, and a number nobody can regenerate is worth less
than no number at all, because it looks like evidence. Concretely: every figure that reaches
this document, `README.md` or a chart must be derivable by running one committed command
against recorded seeds, and that command must be printed next to the table it produced.

The corollary is the reason D3 — randomness only through an injected, keyword-only `rng` — has
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
named from the trial's identity — `<root>/<experiment>/<cell>/trial-000042.json`. On startup it
skips what is already there. Re-running the identical command after a hibernation costs the
trials that were in flight and nothing else. This is not hypothetical: a hibernation has already
destroyed one long run in this project and baked `"<no summary line>"` into `docs/METRICS.md`.

Results default to `~/.sih141/results`, **outside the repository**. Raw per-trial files are never
committed; only reduced tables are. Committing them would be a mistake of a familiar shape — a
reviewer seeing 200 JSON files in the tree would take them for the evidence, when the evidence is
the seed plus the command and the files are a cache of a computation anyone can redo.

There is a third subcommand, `perf`, which measures the machine rather than the protocol. It
produced everything in §5–§7.

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
process ran it" failure this rule exists to rule out — and there is a test that computes a seed
in a separate interpreter with a different hash seed and compares.

**Unambiguous.** `0x00` separates the fields, and legal names are `[a-z0-9][a-z0-9._-]{0,63}`,
so no two identities can build the same material. Without the separator `("ab", "c")` and
`("a", "bc")` would collide and two cells would silently share a stream. The same pattern keeps
path separators and drive letters out of names that become directory components.

**Independent across roles.** The session's generator and an adversary's come from different
`r`, so D6 — every adversary owns its randomness and never reads the session's — is a property
of the derivation rather than a convention a scenario author has to remember. The test compares
*realised draws* through `sih141.attacks.isolation.same_stream`, not seeds.

The rule, not the seeds, goes into every run manifest: there may be thousands of seeds, and each
individual one is on its own trial's record anyway.

---

## 3. What a trial leaves behind

A full-scale transcript is 26.7 MB unchecked and 37.2 MB at `check_fraction = 0.25`, so 200
trials in full would be five to seven gigabytes and a sweep across several cells would be tens. The harness stores a **reduced record**: `Detection.to_dict()`
(all twenty-one keys), the transcript fields the tables need, the seeds, the parameters and the
wall clock. Full transcripts only behind `--retain-transcripts`, for a named handful of worked
examples.

### Ground truth is not evidence

Phase 3 constraint 4: which link Eve touched, and which runs a selective starver targeted, live
on the **adversary's** log, and a detector may not read them. `GroundTruth` is the harness's
label; `Detection` is what the detector concluded from the transcript alone. They are built at
different times — the detector has already returned before the label is attached.

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
competing, so they are on the record — Phase 5 needs a performance section — and out of the
comparison. The excluded set is exactly one field and is pinned by a test, because an exclusion
list is the natural hiding place for a field that genuinely moved between one worker and twenty.

---

## 4. Determinism, proven rather than asserted

This is the claim D9 rests on and the one a judge is most entitled to challenge about a parallel
result. Four tests, each written so that it could fail:

| What is claimed | What is actually run |
| --- | --- |
| Same seeds, same results at any width | Two whole sweeps, one in-process and one across four spawned workers, compared by fingerprint. The test also asserts more than one PID appeared, so a pool that silently ran everything in one worker would not pass by accident. |
| Results do not depend on completion order | Trial 2 produced twice — once alone in its own directory, once as the third of four — and the fingerprints compared. |
| The *tables* match, not just the records | The rendered markdown of the outcome and detection tables compared across the two topologies. Records could match while a reduction sorted by directory order. |
| No worker touches a global RNG (D3) | Both global states snapshotted around a sweep and compared, in the parent and inside every worker. A separate test draws from both globals and asserts the probe notices, so the probe cannot be decorative. |

The BLAS thread limits are set in the **parent before the pool exists**. Windows uses spawn and a
spawned child copies the parent's environment at interpreter start, before any import, so the
limit is in place by construction rather than by an initializer racing numpy's own pool
initialisation. And it is then measured: `tools/sweep.py perf --probe` asks a real worker what
its own environment says, because setting the variables after numpy is imported is a silent
no-op that looks identical from the outside.

---

## 5. Throughput

> Regenerate: `python tools/sweep.py perf --session-scaling --key-lengths 96,192,768`
> The full-scale row is one end-to-end run; see below.

| `L` | check fraction | seconds | ms/position | positions/s | KB/position |
| --- | --- | --- | --- | --- | --- |
| 96 | 0.25 | 0.211 | 2.198 | 455 | 0.408 |
| 192 | 0.25 | 0.420 | 2.188 | 457 | 0.371 |
| 768 | 0.25 | 1.650 | 2.148 | 465 | 0.339 |
| **115200** | **0.0** | **235.09** | **2.041** | **490** | **0.226** |

The last row is one honest session at `DEFAULT_PARAMS`, timed end to end with nothing attached,
seed `20260905`. It confirms the 230.2 s already in `docs/QDS.md` to within 2.1%, so the
6.7 ms/position figure — a `tracemalloc` artefact that inflated every timing by very close to
three times — stays dead. Scaling is linear across a 1200-fold range in `L`.

Two things about the other columns, one of which cost this document a correction.

**Transcript size depends on the check fraction as much as on `L`, and a figure quoted without
both is not a figure.** A full-scale run at `check_fraction = 0` — which is what
`DEFAULT_PARAMS` uses — is 0.226 KB per position, 26.7 MB. The same length at `0.25` is
**0.330 KB per position, 37.2 MB**, because every check round publishes a channel sample:
fidelity, purity, concurrence and both wing purities. A first draft of this section recorded
0.226 as *the* full-scale figure and stated that the phase brief's 0.33 was an error. The brief
was right; it had measured a checked run. Both numbers were correct measurements of two
different configurations and the mistake was reporting one without its second coordinate — the
same species of error as the `tracemalloc` timing, caught this time by measuring the other
configuration rather than by arguing about it.

**Detector latency is not a constant few milliseconds.** It is 1.54 s on a full-scale transcript
against 2.9 ms on a 96-position one, because it is dominated by parsing the JSON, so it scales
with `L` like everything else. Still under one percent of the session that produced it.

Every row here is a doctested constant in `sih141.eval.perf`, so the totals derived from them —
12.8 hours for 200 trials single-threaded — cannot drift away from the rate they came from.

---

## 6. Parallel speedup, and the number the plan had wrong

> Regenerate: `python tools/sweep.py perf --speedup --speedup-cell l768 --trials 120 --workers 1,4,8,14,20`
> 120 honest sessions at `L = 768` per point, each point into a fresh results directory so a
> resumed sweep could not time an empty run.

| workers | wall s | speedup | efficiency | sum of in-worker trial s | occupancy | mean s/trial |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 204.81 | 1.00 | 1.00 | 203.98 | 1.00 | 1.700 |
| 4 | 59.86 | 3.42 | 0.86 | 233.17 | 3.90 | 1.943 |
| 8 | 40.37 | 5.07 | 0.63 | 305.56 | 7.57 | 2.546 |
| 14 | 34.44 | 5.95 | 0.42 | 436.13 | 12.66 | 3.634 |
| 20 | 29.10 | **7.04** | 0.35 | 516.26 | **17.74** | 4.302 |

`docs/QDS.md` said "about 51 minutes at 20 workers on this CPU's realistic 15× effective
speedup". **The 15× was an estimate and it is wrong.** At 7.04×, 200 trials at
`DEFAULT_PARAMS` is **1.9 hours**, not 51 minutes. That correction is now in `QDS.md`.

### What is not the cause, checked rather than assumed

**Not idle workers.** Occupancy — the sum of in-worker trial seconds over the sweep's own wall
clock — is 17.74 at 20 workers, so on average 17.7 of the 20 were busy for the whole run,
startup included. The pool is working. What is not working is the cores. This is also the
sanity check the phase brief asks for: aggregate throughput and the manifest's wall clock are
being compared, and they agree.

**Not BLAS oversubscription.** Every worker was asked what it sees, in its own process, and all
five thread-limit variables read `1`.

**Not a cold baseline.** The one-worker point was re-measured immediately after the twenty-worker
run, on a hot machine: 1.702 s/trial against 1.700 s cold, a 0.1% difference. The ratio is a real
measurement.

### What it is

Per-trial time rises monotonically with worker count, and it starts rising **before the E-cores
are reached**: eight workers on an eight-P-core part already cost 1.50× per trial. That is the
all-core turbo budget — one active core boosts far higher than eight — plus shared L3 and memory
bandwidth. The further growth from 14 to 20 workers is the twelve E-cores, which are slower per
clock than a P-core for scalar Python.

**Use 20 workers anyway**: 29.10 s beats 34.44 s at fourteen. But the marginal return past eight
is poor — eight workers buy 5.07× for 40% of the machine, and the last six buy 18% — so if the
laptop needs to stay usable during a sweep, eight is the sweet spot at 39% more wall clock.

**Do not quote 7.04× at `L = 115200` as established.** It was measured at `L = 768`, where a
trial is 1.7 s and pool startup is a visible share of the parallel points. At full scale startup
vanishes but each worker holds a far larger transcript, so memory pressure could be worse rather
than better. Treat it as a plausible ceiling there.

---

## 7. Memory, and the edges

> Regenerate: `python tools/sweep.py perf --memory --key-lengths 96,768,3072,12288,49152,115200`
> Every row is at `check_fraction = 0.25`, the expensive case.

| `L` | peak RSS MB | rise MB | transcript MB |
| --- | --- | --- | --- |
| 96 | 78.5 | +0.9 | 0.03 |
| 768 | 80.4 | +2.0 | 0.24 |
| 3072 | 86.2 | +5.8 | 0.98 |
| 12288 | 107.5 | +30.0 | 3.92 |
| 49152 | 196.4 | +88.9 | 15.82 |
| **115200** | **348.7** | +152.3 | 37.17 |

The floor is about 76 MB — numpy and qiskit imported, before any session — which matches the
75 MB per worker the brief records. Above it the rise tracks `L`. At full scale one worker peaks
at **349 MB**, so twenty are about **7 GB** against this machine's 24 GB. That fits, but it is
not the "20 workers is under 2 GB" the brief records: that figure is twenty import floors and
does not count the transcripts. The production set is unchecked and therefore cheaper than the
last row. Memory is not the binding constraint here, but it is the one that would bind first on
a smaller machine, and it is no longer a non-issue.

Peak RSS is read from `GetProcessMemoryInfo`, **not** `tracemalloc`. Leaving a profiler attached
is exactly how this project's earlier throughput figure came out three times too large, and a
memory measurement that distorts the timing beside it is worth less than no measurement. That
probe also shipped a real defect worth recording: ctypes defaults every argument to a 32-bit int,
so the pseudo-handle `-1` from `GetCurrentProcess` arrived as `0xFFFFFFFF` rather than a 64-bit
`HANDLE`, the call failed, and **every row of the table read `0.0 MB`** — which looks exactly
like a process that used no memory. There is now a test that fails if it breaks again.

### The degenerate small end

Five trials per length at `check_fraction = 0.25`:

| `L` | signing length | `m_min` | `M_min` | aborts / 5 | security claim | families withheld |
| --- | --- | --- | --- | --- | --- | --- |
| 3 | — | — | — | — | — | parameter set **refused** |
| 6 | 5 | 1 | 1 | 1 | no | 3 |
| 12 | 9 | 1 | 1 | 1 | no | 5 |
| 24 | 18 | 1 | 1 | 0 | no | 5 |
| 96 | 72 | 1 | 1 | 0 | no | 4 |
| 180 | 135 | 1 | 1 | 0 | no | 2 |
| **183** | **138** | 1 | **2** | 0 | **yes** | 1 |
| 384 | 288 | 4 | 62 | 0 | yes | 0 |

Four things worth carrying forward:

- **The claim boundary is `L = 183`, not 140.** The number to hold onto is the *signing* length,
  138. A quarter of the positions go to check rounds, so a caller who sets `key_length = 140`
  because "below 140 the floors degenerate" gets a signing length of 105 and no claim at all.
  Below the boundary runs still complete and the detector still returns a verdict; what it does
  not return is a claim.
- **Aborts appear on honest runs at the very small end** — one in five at `L = 6` and `L = 12` —
  because a verifier's matched set falls under the floor. Those are no-verdicts, not rejections,
  and any table drawn there has a 20% denominator problem.
- **`ProtocolParams(key_length=3, check_fraction=0.25)` refuses to exist.** `floor(0.25 × 3)` is
  zero check rounds, so the set would claim estimation while estimating nothing, and the refusal
  names the three ways out. That is the right behaviour and it is the reason the smallest usable
  cell in the registry is `L = 96`.
- **Whether a detector family is evaluable is not a clean function of `L`.** Below about
  `L = 216` the channel family is withheld on some runs and not others, because it depends on how
  the check rounds happened to split between QBER and CHSH cells. A cell near the boundary will
  produce rows whose `withheld families` column is not constant, and that is a property of the
  runs rather than a bug.

The large end is bounded by time, not memory: `L = 115200` is 235 s per session, and linear
scaling means the largest `L` that completes in a sane time is whatever the human's patience
divided by 2.041 ms allows.

---

## 8. What the reduction refuses to do

These come out of the Phase 3 and Phase 4 audits and are constraints on the **table**, not just
on the code that fills it. Each is enforced in a type or a test rather than documented and hoped
for.

**A no-verdict is not a rejection.** Counting goes through
`sih141.detect.thresholds_structural.OutcomeTally`, which has no field summing a rejection with a
refusal and whose two no-verdict counts raise a `TypeError` if added to an `int`. Every rate
prints its denominator, and the aborts get their own column. A row reading "detection 92%" with
8% silently aborted is a false claim.

**The two count orderings are never pooled.** `count_exchange_timing` is part of the grouping key
of every table, so one cell can become two rows. `OutcomeTally.merge` refuses two tallies that
disagree on it.

**Measured is not proven.** A detection rate is a measurement with a sample size and a 99% Wilson
interval, and the column header says `measured`. A false-positive bound is proven under the
honest null and its header says `proven`. There is no false-negative bound and there cannot be
one from a transcript, so nothing here prints one. An empty denominator reads `no trials`, never
`0.000` — a zero reads as a measurement that found nothing, which is a different claim from an
absent measurement.

**An unevaluated family is not a passed one.** `Detection.withheld` names families that could not
be scored, and those cells read `not evaluated`.

**A null that was not the truth is a column.** `null_is_noiseless` rides on every detection row.
A mismatch-rate detection under a noiseless null on a genuinely noisy link is arithmetically
correct and still a false claim once the null goes unstated — Phase 4 audit finding A3-1.

**Every table carries the command that regenerates it.** It is a field of the `Table` type rather
than something a writer is trusted to remember, and a table built without one prints
"**no command recorded — this table is not reproducible and must not be published (D9)**", which
is louder than silence.

**Provenance is printed above the tables**: the commit, whether the tree was dirty, the worker
counts, and every command that produced the records being reduced. Results spanning two commits
say so, because a table drawn across a code change has two meanings.

---

## 9. Adding an experiment

A scenario is one function:

```python
def scenario(cell: Cell, seeds: TrialSeeds) -> tuple[SessionTranscript, GroundTruth]
```

registered in `sih141.eval.experiments.SCENARIOS`. Its three obligations are in that module's
docstring: take randomness only from `seeds`, report `engaged` off the adversary's own log, and
do not call the detector. Nothing in the runner, the store, the manifest or the reduction changes
when one is added.

Four experiments ship, deliberately few — the harness is the deliverable of this pass:

| name | what it is for |
| --- | --- |
| `honest` | Honest runs on a noiseless link at three key lengths. The false-positive arm. |
| `noise` | Honest parties over a depolarising wire at four strengths, scored against the noiseless null. The arm where `null_is_noiseless` decides whether a row is a false claim. |
| `scaling` | Throughput against key length, run through the real runner so the timing table can be checked against the manifest. |
| `smoke` | Four trials at `L = 96`, for exercising the harness. |
