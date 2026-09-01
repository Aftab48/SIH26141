# Working Journal

**SIH26141** — decisions, issues, dead ends and findings, phase to phase.

> **Temporary file.** Append-only: entries are never edited or removed, only
> added. Rendered from `journal/entries/` by `tools/journal.py render` — edit
> the entries, not this file. Scheduled for deletion at the end of Phase 7,
> on the maintainer's explicit instruction. The permanent record is
> `docs/METRICS.md` and the `docs/PHASE*.md` notes.

**113 entries** — 29 finding · 28 issue · 26 decision · 16 fix · 12 note · 2 deadend


## Phase 0 — Scaffold

### `[D]` Stack: Python + Qiskit, served from one process

*decision · claude · 2026-08-29T19:50:00Z*

Chose Python 3.14 + Qiskit 2.5.2 over (a) a hand-rolled statevector simulator in browser
TypeScript and (b) a CLI-only Python core.

Qiskit is recognised by judges and gives realistic noise models for free, which Phase 3
needs. To avoid a two-process dev setup on Windows, the plan is for FastAPI to serve both
the API and the static frontend later -- one command, no Node build step.

### `[*]` qiskit-aer ships a Python 3.14 wheel

*finding · claude · 2026-08-29T19:52:00Z*

Python 3.14.4 is very new, so the risk was that `qiskit-aer` (compiled C++) had no cp314
wheel and would try to build from source. Checked with a `pip install --dry-run` before
committing to the stack: `qiskit_aer-0.17.2-cp314-cp314-win_amd64.whl` exists. Installed
clean, and the `quantum_info` API was verified working before any code was written.

### `[D]` D1 -- DensityMatrix is the canonical state type

*decision · claude · 2026-08-29T19:55:00Z*

Any function returning a post-measurement or post-channel state returns a DensityMatrix;
inputs accept Statevector or DensityMatrix.

Rationale: Phase 3 introduces noisy channels, and pure-state-only code would need
rewriting at exactly the busiest moment. Systems here are 1-3 qubits, so an 8x8 matrix
costs nothing. Paying a small cost now to avoid a rewrite later.

### `[D]` D2 -- little-endian ordering, pinned by asymmetric states

*decision · claude · 2026-08-29T19:56:00Z*

Qiskit convention: qubit 0 is the rightmost bit. Every module states it; every test pins
it using an ASYMMETRIC state such as |01>.

The subtle part: symmetric states like |00>+|11> look identical under both conventions, so
a test built on them cannot catch an endianness bug. This is the classic silent failure in
quantum simulation code.

### `[D]` D3 -- all randomness through an injected Generator

*decision · claude · 2026-08-29T19:57:00Z*

Every function consuming randomness takes keyword-only `rng: np.random.Generator | None`
resolved through `resolve_rng`. No global `numpy.random`, no stdlib `random`, anywhere.

Reason: the Phase 5 forgery-probability curves are only credible if they are exactly
reproducible. A single global random call anywhere would quietly break that.


## Phase 1 — Quantum core

### `[!]` Two tests were vacuous

*issue · verify:contract/foundation · 2026-08-29T20:22:00Z*

`test_verify_eigenstate_agrees` asserted the implementation against itself -- it would have
passed against broken physics. A second test in `test_states.py` had two of three assertion
blocks that could not fail.

Found by mutation testing (inject a fault, confirm the suite goes red). This is the reason
verification agents are told to mutate rather than read: a green suite proves nothing about
tests that cannot fail.

### `[!]` _coerce_state accepted non-physical states

*issue · verify:physics/foundation · 2026-08-29T20:25:00Z*

The shared state normaliser validated shape, finiteness, trace-1 and Hermiticity but NEVER
positive semidefiniteness. A matrix with negative eigenvalues -- not a physical state -- would
have passed straight through into the Phase 3 noise channels and produced fidelity numbers
that were meaningless but never crashed.

Fixed. Flagged independently by two verifiers, which is a good sign the finding was real.

### `[!]` My workflow script crashed the final phase

*issue · claude · 2026-08-29T21:28:00Z*

Passed a nested array to `parallel()` -- `parallel([xs.map(...)])` instead of
`parallel(xs.map(...))` -- so the Phase 1 audit phase never launched. All 11 substantive
agents had completed; only the auditors were lost.

My bug, not the code's. Fixed and resumed from cache.

### `[*]` Independent numpy reference matched Qiskit to 5.6e-16

*finding · audit:2 · 2026-08-29T21:30:00Z*

An auditor rebuilt the 3-qubit teleportation register from scratch in raw numpy -- its own
little-endian index arithmetic, own Bell vectors, own 8x8 projectors, own partial trace --
reusing no `sih141` code path, then compared against the implementation across 13 resource
families x 12 payloads x 40 seeds.

Max deviation 5.55e-16. Werner-resource fidelity matched the closed form 1 - p/2 exactly to
12 decimals. Also cross-checked against Qiskit Aer with 400000 shots.

This is the strongest correctness evidence in the project so far, because it is independent
rather than confirmatory.

### `[!]` qiskit state_fidelity returns values above 1

*issue · audit:2 · 2026-08-29T21:32:00Z*

`TeleportationResult.fidelity` used Qiskit's raw `state_fidelity`, while `__post_init__`
hard-raises if the value falls outside [0, 1]. Measured: raw `state_fidelity` returned
1.000000000000001 in 6906 of 20000 pure-vs-pure trials.

The code survived only by luck of an unrelated PSD-repair step. Now routed through the
clipped `states.fidelity` helper so the invariant holds by construction rather than by
accident.

### `[!]` teleport() rejected mixed payloads -- blocks Phase 3

*issue · audit:3 · 2026-08-29T21:35:00Z*

`_payload_statevector` raised on Tr(rho^2) != 1. The teleportation algebra works fine for
mixed states; the restriction was artificial.

It blocked two real attack scenarios: intercept-resend or noise on the FORWARD PAYLOAD line
(as opposed to the entanglement resource), and relaying a key qubit over more than one hop.
The docstring's advice to 'degrade the resource instead' is only an equivalent model for
some attacks, not for payload-line interception.

### `[!]` teleport() could not move an entangled qubit

*issue · audit:3 · 2026-08-29T21:36:00Z*

The payload had to be a standalone pure single-qubit state, so the teleported qubit could
not stay correlated with anything else. Entanglement-swapping flows were impossible and
Phase 2 would have had to reimplement correction bookkeeping on top of `bell_measure`.

The underlying machinery was fine -- the auditor ran a full 4-qubit entanglement swap through
`bell_measure` and it was exact on all 400 trials -- so this was purely a missing abstraction.
Caught by the forward-looking 'will Phase 3 be buildable on this?' audit lens, which turned
out to be the highest-value lens of the three.


## Phase 2 — QDS protocol

### `[*]` The induced teleportation channel is always a Pauli channel

*finding · harden:teleport · 2026-08-30T05:40:00Z*

A planned test asserting that two teleportation channels do NOT commute turned out to be
false, and finding out why produced a stronger result: the Pauli corrections twirl the
resource, so the induced channel is ALWAYS a Pauli channel with weights q_B = <B|rho|B>.
It is therefore always unital, and any two teleportation channels commute -- even when the
noise processes that produced the resources do not.

A wrong hypothesis that produced a better theorem than the one intended.

### `[+]` Core widened for real attack modelling

*fix · harden:teleport · 2026-08-30T05:45:00Z*

Added `teleport_in_register` (teleports one qubit of a larger register, preserving its
correlations), `teleport_channel` (the exact induced single-qubit channel, so Phase 4 can
predict QBER analytically instead of only sampling it), and mixed-payload support.

Verified: teleporting half of a Bell pair leaves concurrence 1.0; a purity-0.82 mixed
payload teleports at fidelity 1.0 through a clean |Phi+>.

### `[!]` states.fidelity was ~1e-8 wrong for mixed payloads

*issue · verify:harden · 2026-08-30T06:30:00Z*

Qiskit's `state_fidelity` uses the exact <psi|rho|psi> shortcut when one argument is a
Statevector, but the sqrtm-based Uhlmann formula when both are DensityMatrix -- and the
sqrtm route carries ~1e-8 absolute error, against a module contract of 1e-9.

Unreachable before the hardening (mixed payloads were rejected), and reachable by every
mixed payload after it. Fixed to take the exact Tr(rho sigma) whenever either argument is
pure; max error now 6.7e-16.

### `[!]` CRITICAL -- symmetrisation was missing entirely

*issue · verify:crypto · 2026-08-30T08:00:00Z*

My Phase 2 spec had Alice distribute one copy of the key states to Bob and one to Charlie,
independently. That is broken: Alice sends Bob states matching the key she will declare and
sends Charlie states that do not. Measured r_B = 0.0000 (accept), r_C = 0.4032 (reject).

40/40 successful repudiations at L=192. Non-repudiation -- one of the three properties a
signature scheme exists to provide -- was absent.

Fix: the recipients' symmetrisation exchange (Dunjko-Wallden-Andersson / Amiri), a
per-position fair-coin swap of Bob's and Charlie's records, so Alice cannot know which
evidence each holds. After: 20/20 unsymmetrised, 0/20 symmetrised.

MY SPEC ERROR. I wrote the design brief and omitted a known, required step.

### `[D]` Parameter cascade forced by symmetrisation

*decision · integrate:phase2 · 2026-08-30T08:10:00Z*

Symmetrisation makes a RECIPIENT forger the binding adversary -- after the exchange Bob holds
half of Charlie's evidence -- rather than an outsider. The forger floor drops from 1/3 to
1/12 (derived, and shown optimal over all POVMs).

Consequences: s_v 1/6 -> 1/16, s_a 1/32 -> 1/64, and key length 6912 -> 115200 to hold the
same ~6.9e-10 repudiation bound. A 16.7x increase in L: the honest price of a guarantee that
holds against an adversary rather than against a model of one.

### `[!]` Network drop killed the readiness auditor

*issue · claude · 2026-08-30T09:55:00Z*

`API Error: The response stopped arriving`, server_error, truncated after output. Died 59
entries in, just before writing its first probe. Traced to the maintainer's connection
dropping. A second auditor was hit and auto-retried; this one was not.

### `[!]` Parallel auditors corrupted each other's measurements

*issue · claude · 2026-08-30T10:05:00Z*

Three auditors ran concurrently against ONE shared tree, all permitted to inject faults and
revert them. They contradicted each other about whether the teleportation step was
test-enforced, and one reported that two of its early measurements had been invalidated by
another's mid-run edits.

MY ORCHESTRATION ERROR. Mutation-testing agents must be isolated -- own worktree, or run
strictly sequentially. Settled afterwards with git: the second auditor was right.

### `[!]` CRITICAL -- adaptive-declaration repudiation

*issue · audit:phase2:1 · 2026-08-30T10:30:00Z*

`repudiation_bound()` was documented as valid for EVERY Alice strategy with no model of
Alice. It was not: its M-averaging silently assumes the declared bases are independent of
the recipients' logged bases. But `QDSSession.sign` hands the Signer seam BOTH RAW LOGS.

An Alice who reads them pins the matched count M at 13 for any L and repudiates at 0.46-0.58
measured, reproduced at L=115200 where the published bound is 6.9173e-10. Nine orders of
magnitude of overclaim.

Crucially the MATHEMATICS was fine -- the conditional form returns 0.9964, correctly
predicting the attack succeeds. The error was publishing the averaged number as
unconditional.

### `[*]` No unconditional repudiation bound below 1/2 exists without an abort rule

*finding · repair:bound-honesty · 2026-08-30T12:20:00Z*

Worst-casing over the matched count gives exp(-gap^2/8) = 0.99973, which is useless -- and it
is NOT slack in the analysis: an explicit strategy achieves exactly 1/2 at every L.

So the uselessness is a theorem, not a weak bound. Stated as a result in PHASE2.md. With an
abort rule the guarantee returns: exp(-m_min gap^2/8), genuinely unconditional.

The original bug turned into a real result about the protocol.

### `[D]` Chernoff-derived matched-count abort rule

*decision · repair:abort-rule · 2026-08-30T12:25:00Z*

|M_R| ~ Binomial(L, 1/3), mu = L/3. Multiplicative Chernoff lower tail with honest-abort
budget eps = 2^-64 gives d = sqrt(2 ln(1/eps)/mu) and floor m_min = ceil((1-d)mu) = 36555 at
DEFAULT_PARAMS -- 95.2% of the mean. Verification aborts rather than scores below it.

Honest-abort probability <= 2eps = 1.1e-19 per run, ten orders of magnitude below the ~1e-9
forgery and repudiation bounds, so the abort rule can never become the dominant honest
failure mode. Degenerates continuously to the old 'a rate needs a denominator' rule at short
key lengths, which is why no existing test broke.

Derived, not picked. The attack pins M at ~13 against a mean of 76800 -- roughly 275 standard
deviations low -- so a verifier that accepts it is ignoring evidence it already holds.

### `[D]` Aborts are stored separately from verdicts

*decision · repair:abort-rule · 2026-08-30T12:28:00Z*

`VerificationAbort` lives in its own transcript field with its own type, distinct from
accept/reject results.

Reason: a plumbing failure or a refusal must never be silently averaged into a rejection by
a Phase 4 or Phase 5 statistic. That class of bug corrupts an evaluation quietly and is
found six weeks later, if at all.

### `[!]` OPEN -- per-verifier floors do not close the split-coin attack

*issue · repair:bound-honesty · 2026-08-30T12:30:00Z*

Disclosed by the repair agent itself rather than left to be found: with only per-verifier
floors, an Alice reading both logs aims the TOTAL matched count at 2*m_min = 73110 and
splits it evenly, so neither verifier trips its own floor, no mismatch rate looks anomalous,
and she still repudiates at ~1/2.

Closing it needs a POOLED floor at 75000 -- one extra classical message between Bob and
Charlie. Priced at 4.6e-11. Implementation in progress.

### `[!]` Worktree isolation failed on a stale git check

*issue · claude · 2026-08-30T12:40:00Z*

Both re-audit agents died with 'Cannot create agent worktree: not in a git repository'. The
runtime had cached the repo's git status from session start -- before `git init` ran.

Workaround: run the audits strictly sequentially instead. That achieves the isolation goal
(no concurrent mutation) without depending on worktree support.

### `[D]` Root cause of the whole attack class: the Signer seam sees both raw logs

*decision · claude · 2026-08-30T12:50:00Z*

Every repudiation attack in rounds 2 and 3 exists because `QDSSession.sign` hands Alice BOTH
recipients' raw measurement logs. A real Alice has no such access -- those records are
private by construction.

The seam was introduced deliberately so a recipient forger could express its optimal
strategy, but it means we have been hardening against an adversary strictly stronger than
the threat model requires. That is why the rounds felt endless.

PLAN: keep the over-powered seam for attack simulation (Phase 3 needs it), make the DEFAULT
protocol not expose both logs to the signer, and state the threat model explicitly. To be
folded into the opening of Phase 3, not another Phase 2 round.

Should have been spotted two rounds earlier.

### `[D]` Stopping rule for Phase 2

*decision · claude · 2026-08-30T12:56:00Z*

Phase 2 has consumed three workflows because each round found a genuine security break. The
attacks are converging -- round 1 needed no special access, round 2 needed both raw logs,
round 3 needs both logs plus precise aiming -- but that could still run indefinitely.

COMMITTED: when the pooled-floor workflow finishes, move to Phase 3. Any residual finding is
documented as a stated limitation rather than triggering round 4. Sole exception: a critical
break that would make Phase 4's detection thresholds wrong, since that would poison the
evaluation rather than merely being a caveat.

### `[+]` Honest-abort cost stays far inside budget

*fix · impl:pooled-floor · 2026-08-30T14:33:13Z*

Exact binomial lower tails by integer arithmetic: P[m < m_min] = 2.5e-31, P[M < M_min] = 2.9e-31,
union over the three checks 8.0e-31 at DEFAULT_PARAMS -- against a per-check budget of 5.42e-20
and a union budget of 1.63e-19. Inside budget at every L from 150 to 115200.

Seeded simulation: 120 honest sessions, zero aborts, smallest M/M_min = 1.71. No honest test
regressed.

Also: DEMO_PARAMS (L=192) gained protection it never had -- the pooled floor of 22 now refuses
the M=13 starving attack that used to succeed about half the time there.

### `[D]` The pooled rule costs an ordering change: Bob's verdict is no longer local

*decision · impl:pooled-floor · 2026-08-30T14:33:13Z*

Charlie must hold the declaration in order to count against it, so Bob now forwards BEFORE he
decides. His verdict stops being a local computation.

QDSSession models this by having verify() trigger exchange_counts() lazily, so the older
distribute/sign/verify/transfer sequence still gets the pooled rule; run() calls it explicitly
in phase order.

Stated in PHASE2.md as part of the price rather than hidden -- it is a genuine change to the
protocol's communication pattern, not an implementation detail.

### `[+]` Pooled matched-count floor closes the split-coin attack

*fix · impl:pooled-floor · 2026-08-30T14:33:13Z*

Implemented as an explicit new protocol phase C' (`sih141/protocol/tally.py`), i.e. the extra
classical message between Bob and Charlie is modelled as a real step rather than smuggled
through a shared Python object.

Measured, not asserted:
  - BEFORE (at HEAD ab56cf8): 78/200 = 0.390 at L=360, 85/200 = 0.425 at L=600
  - AFTER: 0/200 at both key lengths; all 400 runs end in a joint no-verdict
  - Closed form (1 - C(2m,m)2^-2m)/2 predicts 0.432 and 0.466, and 0.4985 at L=115200 --
    the attack gets STRONGER with L, so the small-L demonstration carries upward

Suite 1319 -> 1389.

### `[*]` No floor choice ALONE can close the split-coin attack

*finding · impl:pooled-floor · 2026-08-30T14:33:13Z*

Contrary to my brief's assumption, the pooled floor by itself is not sufficient. The agent
derived the L-independent asymptote eps^(3-2*sqrt2) = 4.9e-04 showing WHY: the residual route
survives any choice of floor.

Closed properly with a SECOND rule riding on the same classical message -- the joint consequence
of the per-verifier floor. Both rules implemented, both measured, and PHASE2.md section 6b-iv
separates what each one buys.

Margin: M_min - 2*m_min = (2-sqrt2)*sqrt(2 mu ln(1/eps)) ~ 0.586*A, which is 1080 records at
DEFAULT_PARAMS and 78 at L=600 -- positive at every L >= 140 and growing like sqrt(L).

### `[*]` M is exactly Binomial(2L,1/3) -- but not for the obvious reason

*finding · impl:pooled-floor · 2026-08-30T14:33:13Z*

The naive derivation (convolve the two post-exchange marginals) lands on the right answer for
the WRONG reason. After symmetrisation m_B and m_C are perfectly dependent: given the records,
m_C = M - m_B, with measured sample correlation -1.0 across 120 coin seeds.

What actually makes the law exact is CONSERVATION: the coins merely re-assign a fixed multiset
of 2L entries whose bases were drawn i.i.d. uniform, so M is a sum of 2L independent indicators
that the coins cannot move.

Verified both ways: on one fixed pair of logs, M took exactly ONE value across 120 coin seeds
while m_B took 21. Over 20000 simulated runs the empirical CDF sits 0.0064 from the exact
Binomial(2L,1/3) CDF, against a Kolmogorov 95% critical value of 0.0096.

### `[!]` My task brief mispriced the pooled floor -- 75000 is not derivable

*issue · impl:pooled-floor · 2026-08-30T14:33:13Z*

I briefed the agent with M_min = 75000 and a residual abort route of 4.6e-11, both taken from
the previous round's analysis agent. Both were wrong.

At the stated budget eps = 2^-64 the derived floor is M_min = 74190. The honest cost of 75000
is 7.8e-16 -- four orders of magnitude ABOVE the budget, so it is not a legitimate choice at
all. And the 4.6e-11 figure was computed at 75000; at the correctly derived 74190 that route
is 3.7e-04, seven orders of magnitude worse.

Lesson: a number quoted by one agent and carried into the next agent's brief is not evidence.
I propagated it without checking. Future briefs should state where a number came from and ask
the receiving agent to re-derive it rather than trust it.

### `[*]` VERDICT SOUND -- pooled floor verified by exhaustive enumeration

*finding · verify:pooled-floor · 2026-08-30T15:37:50Z*

STATUS: closed (no action needed).

The verifier attacked the implementation five ways and it held.

  - Floors re-derived from scratch, EXACT match at all 11 key lengths tested
    (120 through 115200). m_min=36555, M_min=74190, 2*m_min=73110,
    M_min-2*m_min=1080 vs predicted (2-sqrt2)*A = 1081.2.
  - THE DECISIVE TEST was exhaustive, not sampled: it enumerated the ENTIRE (m_B,m_C)
    space through the shipped _evidence_refusal at five key lengths, ~1.4M pairs.
    ZERO asymmetric outcomes. Bob reaching a verdict implies Charlie does, always.
  - min(m_B+m_C) over all survivors = max(2*m_min, M_min) EXACTLY, so
    guaranteed_pooled_matched_count is TIGHT, not merely safe.
  - Positive control: split-coin at 2*m_min gives 80/200 and 83/200 third outcomes
    with the pooled rule OFF, 0/200 with it ON. The defence was verified by removing
    it and watching the attack return.
  - corr(m_B, m_C | records) = -1.000000 exactly, confirming the convolution trap the
    implementer avoided.

One scoping point the verifier singled out as what actually matters: the binomial law is
used ONLY for honest completeness. For SOUNDNESS the floor is an enforced check, so
conditioning on 'no abort' gives M >= M_min with no distributional assumption -- which is
precisely why a log-reading Alice steering M cannot break it.

### `[!]` MAJOR -- my checkpoint script committed an auditor's mutation to origin

*issue · claude · 2026-08-30T15:37:50Z*

STATUS: closed (corrected and root-caused).

WHAT HAPPENED. tools/checkpoint.py runs the test suite (~5 min) and then `git add -A`.
The verify agent, doing legitimate mutation testing, installed a fault INSIDE that window.
The suite had already passed on clean code; the commit captured the mutated code. Classic
time-of-check/time-of-use race.

IMPACT. Commit da72efe carried `_chernoff_floor(1.0 * checked.expected_matched)` instead
of `2.0 *` -- the broken pooled floor that collapses M_min to m_min and REOPENS the
split-coin attack. I pushed it to origin/main. For a period, the public repository
contained security code that did not work, inside a commit labelled as fixing it.

DETECTION. Not by me -- the verify agent noticed, repaired it with `git commit --amend`
preserving subject/author/author-date, and reported it as a MAJOR concern. Verified
byte-identical to its own snapshot before amending.

RESOLUTION. Local HEAD 64185f9 has the correct `2.0 *`; force-pushed with
--force-with-lease; origin and local now match and line 592 is correct.

ROOT-CAUSE FIX. checkpoint.py now fingerprints (md5) every file git would commit BEFORE
the suite runs, re-checks after the suite, and re-checks again immediately before staging.
Any drift aborts the checkpoint with the drifted paths listed. The suite must have
validated exactly what gets committed.

The verifier's wider warning stands and is worth repeating: an unattended process that
commits whatever transient state exists will eventually capture a mutation. Automation
that writes to history must be race-aware, not merely test-aware.

### `[*]` MINOR -- both floors are inert at demo-scale key lengths

*finding · verify:pooled-floor · 2026-08-30T15:37:50Z*

STATUS: OPEN (documentation constraint, not a code defect).

M_min <= 2*m_min for every L <= 139, and the enforced bound stays vacuous well beyond that:
0.974 at L=360, 0.943 at L=600, still 0.48 at L=4800. Only at DEFAULT_PARAMS (L=115200)
does it reach 1.41e-09.

Correctly reported by enforced_repudiation_bound (0.994 at DEMO_PARAMS) rather than hidden.

CONSEQUENCE FOR PHASE 6: the dashboard will run at demo-scale L for speed. No demonstration
run at L <= 1200 may be presented as exhibiting non-repudiation -- it exhibits the MECHANISM,
not the guarantee. The UI must say so, or a judge will reasonably call it misleading.

### `[!]` MINOR -- verify.py:230 quotes a figure that matches no computation

*issue · verify:pooled-floor · 2026-08-30T15:37:50Z*

STATUS: OPEN. To be fixed in the Phase 2 closing pass.

The line states the residual abort route has '(exact tail 4.8e-05)'. The verifier computes
3.611e-05 one-sided and 7.223e-05 two-sided; no natural variant -- with or without
continuity correction, normal approximation, <= vs < -- yields 4.8e-05.

Does not affect the argument: the route is ~1e-4 either way, vastly above the 1.41e-9
bound, so the joint rule remains necessary. Should read 3.6e-05.

WHY IT SURVIVED, which matters more than the digits: it is prose inside a code block, not
a doctest. This project runs --doctest-modules, so a number written as an executable
example is checked on every run; a number written as prose is unverifiable by construction.
The fix is to convert it into a doctest that computes the tail, so the NEXT wrong number of
this kind fails the suite instead of waiting for an auditor.

### `[!]` MINOR -- SessionTranscript.repudiated under-reports on pooled-OFF runs

*issue · verify:pooled-floor · 2026-08-30T15:37:50Z*

STATUS: OPEN (accept or fix -- decide at the closing pass).

`.repudiated` returns False for the THIRD OUTCOME (Bob accepts, Charlie reaches no verdict)
because it requires both parties to hold a VerificationResult. On pooled-ON runs that
outcome is provably unreachable -- the verifier's exhaustive sweep confirms it -- so the
property is exactly correct there.

The hazard is Phase 5: a harness aggregating `.repudiated` across no_count_exchange runs
would score the split-coin attack as ZERO successes despite ~50% third outcomes. The
transcript does flag such runs loudly, and the seam is opt-in with a deliberately alarming
name, so this is a documented sharp edge rather than a defect.

ACTION FOR PHASE 5: any aggregator must key on the ABORT CHANNEL, not on `.repudiated`.

### `[!]` Second bug in checkpoint.py: porcelain parsing dropped a leading character

*issue · claude · 2026-08-30T15:37:50Z*

STATUS: closed.

The git() helper strips its combined output, which removes the LEADING SPACE from the
first line of `git status --porcelain`. A fixed line[3:] slice then dropped the first
character of that path -- '.gitignore' displayed as 'gitignore'.

Not cosmetic: paths are matched against IGNORABLE to decide whether a change set is
substantive. Had JOURNAL.md sorted first, it would have parsed as 'OURNAL.md', missed the
match, and triggered a commit the rule exists to prevent.

Fixed by splitting on the two-character status field (line[:2], line[2:].strip()), which
is correct whether or not the leading space survived. Verified both cases.

### `[!]` OPEN for Phase 3 -- seed sharing silently restores full coin prediction

*issue · verify:close · 2026-08-30T21:28:15Z*

STATUS: OPEN. Must become a hard convention before any Phase 3 attack is written.

The two-stream fix closes the leak through the seam. It does NOT close the case where an
attack closes over the same seed the harness passes to the session: rebuild the material
with default_rng(seed).bytes(32), derive the recipient stream, and predict every coin. The
verifier confirmed this rather than taking it on trust -- 120/120 coins on both message bits,
exact array equality, in roughly ten lines.

WHY IT MATTERS: any Phase 3 or Phase 5 attack written the natural way -- reusing the harness
seed so the run is reproducible -- silently regains full coin prediction and would publish
bogus repudiation rates that look entirely legitimate.

This needs to be a structural rule (attacks take their own generator as a constructor
argument, enforced by a test), not a paragraph in a docstring that an author may not read.

### `[!]` Closing verifier returned UNSOUND -- repairs 1 and 2 sound, documentation incomplete

*issue · verify:close · 2026-08-30T21:28:15Z*

STATUS: partly closed (see the two OPEN entries that follow).

The rng-leak repair and the untested-wire repair were both verified SOUND by independent
execution. The verifier wrote its own coin-reading Distributor from scratch and measured
pre-fix 3/3 repudiations at DEFAULT_PARAMS against post-fix 0/3, then hunted siblings
exhaustively: an object-graph walk of all six seams (depth 5, cycle-safe), 0/4001 generator
rewind steps in both directions, 0/19 seed-reconstruction routes, and independently
recomputed the pinned SHA-256 digests.

What it found still open was documentation, and I closed those by hand rather than spawning
another round:
  - verify.py:230 still quoted 4.8e-05. Fixed to 3.6e-05 AND converted the two derivable
    figures into doctests, since prose is exactly what --doctest-modules cannot check.
  - The transcript's closing NO VERDICT line hardcoded one abort reason, so it read 'the
    matched set was below the floor' two lines under 'Every floor met.' Now names the
    reason each verifier actually gave.
  - PHASE2.md rule D3 still described one threaded generator; there are now two derived
    streams. Rewritten, with the security rationale.
  - PHASE2.md's verifier pseudo-code listed three checks; there are four. The provenance
    check was missing entirely.
  - Two test docstrings explained a mechanism that no longer exists.

I verified the corrected tail figures myself with scipy before writing them
(3.611637e-05 one-sided, 3.855276e-04 Chernoff, 4.948696e-04 asymptote) rather than
copying an auditor's number -- propagating an unchecked figure is how the wrong one got
there in the first place.

### `[*]` Full-scale validation at L = 115,200 passes

*finding · claude · 2026-08-30T21:28:15Z*

STATUS: closed.

Everything measured at production parameters rather than extrapolated from demo runs.

  ARITHMETIC (the actual guarantee, instant)
    m_min 36,555   M_min 74,190   2*m_min 73,110   margin 1,080
    guaranteed pooled count 74,190;  enforced bound 1.4139e-09
    M_min > 2*m_min  ->  PASS

  HONEST SESSION (241.8 s)
    Bob      38,421 matched, 0 mismatches, rate 0.000000, accepted
    Charlie  38,395 matched, 0 mismatches, rate 0.000000, accepted
    no abort; transferable; not repudiated
    Matched counts sit 21 and 5 away from the theoretical mean L/3 = 38,400.

  STARVED DECLARATION (244.5 s)
    A signer declaring a basis absent from BOTH raw logs at every position.
    Both verifiers aborted with 'empty-matched-set'. No crash, not transferable,
    not repudiated.

What this rules out: scale-dependent bugs. The floors compute correctly at full L,
an honest run does not trip them, and an attacker cannot crash a verifier.

### `[D]` Provenance repaired on the 78/200 split-coin figure

*decision · claude · 2026-08-30T21:28:15Z*

STATUS: closed.

The figure was cited in six source files as 'measured through the shipped seams', and it does
not reproduce from this tree: the verifier measured 86/200 pre-fix and 99/200 post-fix on the
repo's canonical seed set, and agent 1's two-stream change moved every seeded transcript.

All the values -- 78, 85, 86, 87, 99 -- agree with the closed form (0.432 at L=360) to within
sampling error, so nothing is substantively wrong. What was wrong was presenting an
irreproducible count as the authoritative number.

All six sites now lead with the closed form and cross-reference a single provenance note in
verify.py that states plainly which tree the counts came from and that they are not
reproducible from this one. The counts are kept rather than deleted, because a measured
attack is worth more than a formula alone -- but dropped provenance is how a figure becomes
folklore.

### `[!]` OPEN for Phase 3 -- the declaration-binding check can be stripped by the adversary it targets

*issue · verify:close · 2026-08-30T21:28:15Z*

STATUS: OPEN. Carried into Phase 3.

The binding check is advisory rather than enforced: a count_exchange seam that performs the
honest arithmetic but returns PooledMatchedCounts(..., declaration_digest=None) restores
exactly the behaviour the check was added to stop. Verified by execution -- with the shipped
exchange Charlie aborts 'counts-from-two-declarations'; with the digest dropped he reaches a
verdict again on a count whose real evidence base is zero, pooled with Bob's count from a
different declaration.

Consequence is bounded in the measured instance (Charlie rejects rather than accepts), but
'a count of unrecorded provenance is taken at its word' is a bypass, and Phase C' is the
recipients' own step -- the adversary here IS a recipient.

Not fixed in Phase 2 because the fix belongs with the Phase 3 seam-restriction work, and
because I committed to reporting rather than starting another repair round.


## Phase 3 — Attack suite

### `[-]` Journal and metrics tooling added

*note · claude · 2026-08-30T13:15:00Z*

Two logs, different jobs.

`docs/METRICS.md` -- permanent, generated by `tools/metrics.py`. Test counts, source volume,
test-to-code ratio, and the LIVE security parameters read out of the package at generation
time, so documented numbers are whatever the code actually computes.

`JOURNAL.md` -- this file. Temporary, append-only, deleted at the end of Phase 7 on the
maintainer's word. Entries are individual immutable files under `journal/entries/` and are
rendered into JOURNAL.md, because concurrent agents appending to one file would clobber each
other.

Seeded retrospectively from the Phase 0-2 session history; from Phase 3 onward every
subagent is instructed to log its own decisions and issues as it goes.

### `[D]` RecipientView: the threat model as a type, checked by reachability

*decision · impl:records+isolation · 2026-08-31T15:42:44Z*

The Phase 2 audit's complaint was that a "Bob" adversary had to reach into
QDSSession.raw_records and was handed Charlie's log with it. RecipientView
(sih141/protocol/records.py) fixes that: party, message_bit, raw_record, record,
matched_count, and nothing else.

THREE DESIGN CALLS WORTH REMEMBERING.

1. matched_count is Optional and NOT computed. A view built at the end of Phase A
cannot know |M_R| -- the key is not revealed until Phase B -- and a type that
computed it would need a declaration it does not have. None means "no declaration
yet", which is deliberately distinct from 0 ("a declaration this recipient can
score nowhere"). with_matched_count() fills it in later; the view is frozen.

2. The counterpart's count is NOT a field. Phase C' does deliver it, so a view
eventually coexists with a number that came from the other verifier. Putting it on
the view would blur exactly the line the type draws, so it is passed alongside,
the way verify() already takes it alongside a record.

3. raw_record.symmetrised must be False, checked. Passing the post-exchange log in
as the raw one is a silent downgrade, not a type error: a forging recipient who
declares his post-exchange log declares precisely the half the counterpart does
NOT hold, so his forgery quietly fails at chance instead of reaching the 1/12
floor. That is a wrong number, not a crash, so it is refused at construction.

HOW "IMPOSSIBLE TO REACH THE OTHER RECIPIENT" IS TESTED. Not by reading the class.
tests/test_protocol_keys.py walks the object graph out of a view (dataclass
fields, __dict__, containers; classes and modules recorded but not descended) and
asserts no RecipientRecord of the counterpart, no PrivateKey, no Signature, no
QDSSession and no Generator is reachable. The crawl has a POSITIVE CONTROL first:
the same crawl pointed at session.raw_records/records/keys must find all 8 records
and both keys. Without it, a crawler that silently found nothing would pass the
leak test for every possible defect.

THE NON-INVARIANT, stated so a later reader does not "fix" it: after Phase A'
roughly half of Bob's post-exchange entries ARE, by object identity, entries off
Charlie's raw log. That is what symmetrisation means and those entries are now
Bob's evidence. The invariant is about whole logs, never about shared entries. A
test asserts 0 < shared < L so the fact stays visible.

### `[+]` CLOSED: D6 is now a behavioural check, and the seed leak needs no private API

*fix · impl:records+isolation · 2026-08-31T15:43:07Z*

The OPEN issue from Phase 2 ("seed sharing silently restores full coin prediction")
is now closed by sih141/attacks/isolation.py + tests/test_attack_isolation.py.

CONFIRMED, AND SIMPLER THAN THE ORIGINAL REPORT. The auditor's ten-line version
rebuilt the material with default_rng(seed).bytes(32) and derived the recipient
stream. That needs the private _derive_stream and the stream label. It is not
required. An attack holding the harness seed just rebuilds the session:

    rebuilt = QDSSession(params, rng=np.random.default_rng(seed)); rebuilt.distribute()
    assert rebuilt.records == honest.records          # True

Four lines, public API only, and every symmetrisation coin falls out: measured
120/120 across both message bits at L=60, exact array equality. That is now a
doctest in the module and a test in tests/test_attack_isolation.py, so the claim
is executable rather than prose. It also means no amount of hiding private names
would have helped -- determinism itself is the channel, which is exactly why the
fix has to be a rule about the attack and not about the session.

THE CHECK IS TWO-SIDED, AND THE SECOND SIDE IS THE LOAD-BEARING ONE.
(a) fix the attack's rng, vary the session seed -> decisions must not move.
(b) fix the session seed, vary the attack's rng  -> decisions MUST move.
Without (b), an adversary passes (a) by being constant. DeafForger in the test
file is the permanent negative control for exactly that, and it is kept forever:
a test that has never failed is not known to work. SessionSeedForger is the
control for (a), and its coin prediction is separately pinned as exact so the
control stands for the real leak rather than for "something that differs".

THE TRAP I ALMOST WALKED INTO, and the single most important thing for whoever
adds the five real adversaries. Check (a) is only a statement about the ADVERSARY
if everything it legitimately OBSERVES is identical across the two runs. The
natural probe -- build a fresh QDSSession per session seed and call the attack --
hands a recipient-forger a different measurement log each time, so his declaration
moves for an entirely honest reason and a perfectly isolated attack is reported as
a cheat. signer_probe() therefore replays ONE frozen honest run (signer_scenario(),
under SCENARIO_SEED, disjoint from both varied seed lists) on every call, and the
session seed is a quantity the adversary can only know if it went and took it.
The false-failure mode is pinned by a test, and the failure message names the
probe as the other possible culprit.

INTERFACE, so a sixth adversary is one line. build is an AttackBuilder called as
build(rng=..., session_seed=...) -- the seed only if the signature accepts it. D6
already requires an adversary's constructor to take rng, so THE CLASS IS THE
BUILDER: parametrize over [ForgingBob, RepudiatingAlice, ...] and call
assert_attack_isolated(attack, signer_probe()). A builder that refuses rng is
rejected up front with D6 quoted at it, rather than dying as a TypeError inside
the first probe. Adversaries needing injected observations (a RecipientView) get a
three-line builder closure; ViewForger/build_view_forger in the test file is the
worked example.

### `[x]` Rejected: a syntactic scan for session-seed use

*deadend · impl:records+isolation · 2026-08-31T15:43:26Z*

DEAD END, recorded so nobody repeats it: a *syntactic* isolation check.

The obvious first idea is to scan an adversary's source (or its closure cells,
or __init__ defaults) for np.random.default_rng, for a name called "seed", for a
reference to the session object. I did not build it, and it should not be built
later, for two reasons.

1. It is evaded by one indirection and by nothing more sophisticated than
   `factory = np.random.default_rng` at module level, or a seed arriving through
   a config dict, or a helper in another module. Every one of those is what a
   real experiment script looks like anyway.
2. It gives FALSE CONFIDENCE, which is strictly worse than no check. The whole
   reason this exists is that a leaking attack looks entirely legitimate --
   same seams, same transcript, same printed bound. A green syntactic scan adds
   one more legitimate-looking thing to that list.

The behavioural check demonstrates the property instead of looking for its
absence. That is also why the two failure messages are long: each one names the
defect, the seeds to reproduce with, AND the alternative explanation (a probe
that varied the observations), because the same symptom has two causes and
guessing wrong costs an afternoon.

SMALL THINGS FOUND ALONG THE WAY.

canonical() is not decoration. Decision traces arrive as numpy arrays (unhashable,
elementwise ==), nested mappings (order), floats (nan != nan), and dataclasses. All
four break either the equality or the set-cardinality the check runs on. It refuses
an object with the default repr outright, with an explanation, because an address
in the trace would make EVERY candidate fail check (a) -- a false-failure mode
that would be blamed on the adversaries.

A fresh adversary is built per probe, never reused. A reused instance carries its
generator state forward between session seeds, so an isolated candidate that draws
at call time would be reported as reading the session. DrawsAtCallTime in the test
file exists solely to pin that.

Five attack seeds is the default for check (b). An adversary whose own randomness
is a single fair coin would fail by chance about once in sixteen runs; that is
documented on DEFAULT_ATTACK_SEEDS and the list is a parameter. Real adversaries
make L choices, so it is not a practical risk -- but a future one-bit adversary
should widen the list rather than trust the default.

### `[-]` Files touched outside the brief's ownership list

*note · impl:records+isolation · 2026-08-31T15:43:41Z*

Two files outside my stated ownership (records.py, keys.py,
tests/test_protocol_keys.py) were touched. Flagging both so the integrator can
re-apply them if a concurrent agent's write lands on top.

1. sih141/attacks/__init__.py -- CREATED. The brief said "nothing else in
   sih141/attacks/ exists yet", but the package needs an __init__.py to match
   sih141/core and sih141/protocol (both have one) and to be collected by
   --doctest-modules the same way. It is a docstring plus a re-export of
   isolation's __all__; no logic.

2. sih141/protocol/__init__.py -- THREE ADDITIVE EDITS. key_from_record,
   RecipientView and recipient_views added to the imports and to __all__. That
   file's stated purpose is that "Phase 3 onwards never needs to reach into a
   submodule", and new public API that is not re-exported there defeats it --
   an attack author would go back to importing from sih141.protocol.records
   directly, which is the habit the view is trying to break. Purely additive:
   no existing line changed.

Nothing in session.py, verify.py or tally.py was touched. Those three plus
tests/test_protocol_tally.py and tests/test_protocol_verify_abort.py showed as
modified in git status throughout, by other agents working concurrently; the full
suite was run against whatever state they were in and passed.

WHERE THE NEW SURFACE LIVES, for whoever wires the five real adversaries:
  sih141/protocol/records.py   RecipientView, recipient_views
  sih141/protocol/keys.py      key_from_record
  sih141/attacks/isolation.py  assert_attack_isolated, check_attack_isolation,
                               signer_probe, signer_scenario, canonical,
                               IsolationReport, AttackIsolationError

### `[+]` Declaration binding made unforgeable by omission

*fix · phase3-tally-provenance · 2026-08-31T15:50:10Z*

THE HOLE (carried over from Phase 2, logged OPEN)

The declaration-binding check was advisory. `MatchedCountMessage.declaration_digest`
and `PooledMatchedCounts.declaration_digest` defaulted to None, `verify` skipped the
binding check whenever the counterpart count named no declaration, and
`exchange_matched_counts` compared the two digests only when both were present.

Reproduced before touching anything, L = 1200, seed 20260845, forwarder = the
Bob-log-avoiding hop:

    shipped exchange | charlie verdict: None  | abort: Charlie counts-from-two-declarations
    digest dropped   | charlie verdict: False | abort: {}
    (real m_B under the delivered declaration: 0; pooled floor: 534)

A `count_exchange` seam doing the honest arithmetic and returning
`PooledMatchedCounts(..., declaration_digest=None)` got Charlie back to a verdict on
a count whose real evidence base under the declaration he scored was zero, pooled
with Bob's count against a different declaration.

WHY "THE SEAM IS TRUSTED" IS NOT A DEFENCE

Phase C' is the recipients' own step and the adversary in :ref:`one-declaration` IS a
recipient -- the party holding the Bob-to-Charlie hop is the party running half the
exchange. An optional provenance field is therefore not a record of ignorance, it is
a lever: a check the adversary can switch off by declining to answer.

DECISION: BOTH, AT THREE LEVELS, AND WHY NOT A FOURTH

1. Mandatory at construction. `declaration_digest` is a required field on both types,
   `_as_declaration_digest` refuses None with its own ValueError (separate from the
   TypeError for non-strings, because omission is the security case), and `from_dict`
   requires the key. A PooledMatchedCounts is the only thing a count_exchange seam
   can hand QDSSession, so a seam that cannot express "I decline to say" cannot.
2. Neither type may be subclassed (`_final`, via `__init_subclass__`). Without this,
   (1) is routed around in one line: `counterpart_of` is the single point where a
   count crosses into a verdict and the only thing that attaches the declaration to
   the number, so a subclass overriding it returns a bare int and declines the
   provenance one level further out, still passing session's isinstance gate.
3. `verify` refuses a count that arrives carrying the exchange's provenance slot with
   nothing in it -- new `AbortReason.COUNT_OF_UNRECORDED_PROVENANCE`, a no-verdict
   like the rest. After (1) and (2) nothing in the package produces such a count,
   which is the point: it holds for a carrier arriving from outside their reach.

NOT done: refusing a plain `int` for `counterpart_matched`. Considered and rejected.
The discriminator is `hasattr(value, "declaration_digest")` (`_claims_provenance`):
a plain int has no slot to leave empty, so it cannot be an exchange declining to fill
one -- it can only come from the verifier's own call site, which is not a channel any
adversary in this threat model holds, and closing it would have meant rewriting ~15
call sites in tests/test_protocol_verify_abort.py to pass a private carrier type,
making a public keyword argument's only valid value an instance of a private class.
The seam's channel is closed at (1)+(2) instead. If a future change lets an adversary
reach `verify` directly, this reasoning is what has to be revisited.

ALSO NOT closed, deliberately: a seam may still return None. That is
`no_count_exchange` -- refusal to exchange, not omission of provenance. It is louder
(counts_exchanged=False, printed in the transcript summary, no pooled claim) and
Phase 3 needs it to measure the split-coin attack.

A SECOND HOLE FOUND ON THE WAY

`exchange_matched_counts` did `declaration_digest=bob.declaration_digest or
charlie.declaration_digest`. A malicious recipient sending a message with no digest
therefore had the honest counterpart's digest adopted as its own -- not a missing
binding but a fabricated one, and it would have passed the honest verifier's check.
That is why the digest is mandatory on `MatchedCountMessage` too and not only on the
pooled view; the fallback is now a plain inequality.

RED/GREEN, both directions, reported as required

* Against pre-fix code, the four new tally tests: 4 failed (DID NOT RAISE ValueError
  / TypeError / ValueError / MatchedSetTooSmall).
* After the fix: full suite 1475 passed.
* Bypass re-installed (digest optional again, `__init_subclass__` removed, from_dict
  back to `.get`, exchange back to the `is not None and` guard + `or` fallback,
  `binding_missing` forced False): 6 failed, 76 passed across the two test files.
* Bypass reverted from a temp-dir snapshot: 82 passed, then full suite 1508 passed
  (the count moves because other agents are adding tests concurrently).

COST, stated so nobody rediscovers it as a bug

A MatchedCountMessage or PooledMatchedCounts serialised before the field existed no
longer restores -- KeyError on "declaration_digest". That is the honest outcome: such
a record's counts cannot be shown to belong to one declaration, so the pooled floor
cannot be applied to them, and restoring it into an object that *looks* enforceable
is the omission route reopened at the persistence boundary. SessionTranscript.pooled
is itself still optional, so a transcript from before Phase C' restores as what it
is: a run whose recipients did not compare counts.

NOTE FOR WHOEVER OWNS session.py

The comment at session.py:1292 says "three of the five AbortReason members". There
are six now. Prose only, no logic depends on it; I did not touch the file because
another agent owns it this round.

### `[D]` The session identifier must not depend on the declared key

*decision · replay-defence agent · 2026-08-31T17:01:32Z*

The obvious design for a session identifier is a digest of the round's key
material -- it makes the identifier a *fact about the round* rather than a name
the signer picks, and it is what I set out to build. It is wrong, and the reason
is worth writing down because it is not visible until you trace a forgery
through it.

The verifier can only recompute the identifier from the key he was *declared*.
A forgery is precisely a declaration whose key is not the one distributed. So
with the key in the digest, every forgery recomputes to an identifier that does
not match the record's, and verify() refuses to score instead of rejecting.
Phase 3's entire forgery table would have emptied into the no-verdict column,
and the scheme's headline detection would have been reported as a plumbing
error. The abort machinery exists exactly so that plumbing failures and
signature failures never share a channel; folding the key into the binding puts
them back in one.

So: the identifier names the ROUND, the mismatch rate judges the KEY, and the
two must not be computed from overlapping inputs. What is hashed is a 128-bit
opening the signer draws per (round, message bit) and reveals in Phase B, plus
the message bit, the key length and the application context. Nothing about the
key, and in particular nothing about k_{1-b}: a digest of key material would
have been a computational handle on the *unsigned* key, which this scheme does
not have anywhere else and should not acquire for a replay defence.

What that costs, stated rather than hidden: the identifier is a label the
verifier compares, not a proof he can check against the key. A signer who wants
two rounds to carry one identifier can reuse her own opening. She gains nothing
-- the two rounds' keys differ, so a declaration replayed across them is
rejected on the rate, and each verifier's ConsumedRecords grants one verdict per
identifier, so two rounds sharing an identifier are ONE round to every verifier.
The opening is also the commitment an auditor makes her open in a dispute; a
fabricated identifier has no opening, and QDSSession.opening_for exposes the
unsigned round's so that the check is executable rather than rhetorical.
tests/test_protocol_replay.py::test_the_identifier_does_not_depend_on_the_declared_key
pins the property this entry is about.

### `[D]` Why the consumed-records ledger is passed, not a module default

*decision · replay-defence agent · 2026-08-31T17:01:51Z*

The brief said "the ledger must be per-verifier state, not global". I first
reached for the usual shape -- a module-level default keyed by party, so that
verify() is stateful by default and nobody has to remember to pass anything.
That is unbuildable here, and the reason is specific to this project rather than
general good taste.

Round identifiers are derived from a seed-derived opening. Two runs made with
the same seed produce the SAME identifier, by design: seeded reproducibility is
what Phase 5 rests on and what tests/test_protocol_session.py pins. A
process-wide ledger would therefore refuse the second of two identically seeded
experiments as a replay of the first -- and the suite is full of tests that use
one base seed. Content-addressing the record instead is worse: two structurally
identical hand-built logs in two different doctests are two different rounds,
and a content hash cannot tell a coincidence from a replay. That is the same
trap the module docstring already documents for run_id, one level down.

So the ledger is an object the verifier holds and passes: verify(..., ledger=).
ConsumedRecords is constructed for one party and raises on another party's
record, so there is no object anywhere from which Bob's history reaches
Charlie's decision -- which is the security half of "per-verifier". QDSSession
owns one per verifier and passes each verifier his own, so the integrated path
is stateful by default and only the hand-built pairs in the test suite stay
pure. That is why exactly two existing tests had to move rather than dozens.

Two consequences that took a real bug to find:

(1) A round is spent on a VERDICT, never on a refusal. If a refusal spent it,
anything that can make a verifier abort -- a starved matched set, a counterpart
count of unrecorded provenance, a mismatched round -- would destroy an honest
signature's one chance to be scored. It is also what makes transfer() work: it
re-verifies Charlie after an abort on the unforwarded declaration.

(2) QDSSession.verify records the abort and pops the verdict before re-raising.
With the ledger in place, the second ask for a party who had already accepted
DELETED his acceptance and replaced it with the replay refusal -- so the replay
defence became a way of erasing the very decision it protects, which is a bigger
hole than the one it closes. Fixed by leaving the standing verdict alone when
the reason is RECORD_ALREADY_VERIFIED and a result already exists for that
party. Caught by an assertion in the moved test, not by the type checker; if
anyone adds a third stateful refusal, check this branch again.

### `[*]` Pricing the ledger's denial-of-service surface

*finding · replay-defence agent · 2026-08-31T17:02:09Z*

The brief asked whether the ledger can be exhausted or poisoned to deny service
to an honest signature. It can, once, by one route, and the honest answer is
that the route costs nothing to whoever already holds a cheaper denial.

A verdict spends a round, and a REJECTION is a verdict. So a party who can put
a declaration in front of a verifier before the honest one arrives burns the
round: the verifier rejects the bad declaration, spends, and the honest
declaration is then refused. Measured in
tests/test_protocol_replay.py::test_a_rejection_spends_the_round_and_this_is_the_denial_of_service_price.

The price:
  - Bob. Phase B runs over an authenticated channel (assumption (AUTH), stated
    in sih141.protocol.signature). The only party who can put a declaration in
    front of Bob is the signer, and a signer who wants to deny service can
    simply not sign. No new capability.
  - Charlie. The only party who can put one in front of Charlie is whoever holds
    the Bob-to-Charlie hop, i.e. Bob. Bob withholding the forward is the same
    denial for less work. No new capability.

The alternative -- spend only on ACCEPTANCE -- removes even this, and I decided
against it: it lets a verifier be asked the same rejected question without
limit, and "one round, one verdict" is the rule the whole mechanism is named
after. A rejection is a verdict.

Exhaustion is linear and prunable: one (32-char identifier, message bit) pair
per round decided, of order 1e2 bytes, so 1e7 rounds is about a gigabyte. The
key IS the round, which is what makes a retention policy expressible at all --
this is the thing the old run_id note said a ledger needed and could not get
from content.

One more residual, noted and not defended: the classical channel is
authenticated but NOT secret, so an eavesdropper reads (b, k_b) off it and can
rush the true declaration to Charlie ahead of Bob. Charlie accepts it -- it is
valid -- and spends; Bob's forward then aborts. Transferability was achieved,
just by a different courier, and Charlie cannot tell. Anyone building the
Phase 5 tables should know that a RECORD_ALREADY_VERIFIED at Charlie is not
necessarily an attack on Charlie.

### `[D]` Three small replay-defence decisions that are easy to undo by accident

*decision · replay-defence agent · 2026-08-31T17:02:28Z*

Three smaller decisions from the replay work, each of which would be easy to
undo by accident.

1. A THIRD derived stream for the openings.
Openings have to come from somewhere. Drawing them from the Alice stream shifts
every later variate and changes every seeded transcript in the project for a
value none of them depend on -- keys, records, coins, the lot. So
_BINDING_STREAM_LABEL joins the two in :ref:`two-streams`; deriving a third
stream from the same 32 bytes costs one SHA-256 and leaves the other two
byte-identical. tests/test_protocol_replay.py::test_the_binding_stream_does_not_perturb_the_other_two
rebuilds a session's keys and all four records from the two documented streams
alone and asserts equality, so this cannot silently regress. It is also the one
stream no seam is handed, which means a distributor cannot read the opening of
the OTHER message bit -- the round that stays sealed.

2. QDSSession OVERRIDES whatever session fields a seam put on a declaration.
sign() and transfer() both rebuild the returned Signature with this run's
opening and context (_bind_to_round). A seam may declare any key it likes --
that is what the Signer and Forwarder seams are for -- but it does not get to
say which round the declaration belongs to. If it could, a forging signer that
simply left the round unnamed would turn every forgery into a SESSION_MISMATCH
abort, which is the failure mode of journal entry "The session identifier must
not depend on the declared key" arriving by a different door. The consequence is
that the binding never fires through the shipped seams, and it is not supposed
to: it fires where the pairing is done by hand, which is where replay lives.

3. The RECORD is the anchor, not the signature.
The comparison is driven by the side an adversary cannot reach. A verifier
holding a stamped log demands the declaration name that round and refuses one
naming another OR naming none; a verifier whose log names no round has nothing
to compare and scores exactly as before. That asymmetry is what keeps every
hand-built pair in the suite working, and it is NOT the omission route that
tally.py had to close: there the party who could omit the binding was the
adversary the check was aimed at, whereas here the only party who can omit it is
the verifier himself, and a verifier who blinds himself loses only his own
protection. QDSSession re-stamps the post-symmetrisation logs for the same
reason -- a symmetriser seam is the recipients' step, and it must not be able to
strip the recipients' own binding on the way through.

### `[*]` CHSH needs two measurements, so Alice must know the check set

*finding · check-rounds agent · 2026-08-31T17:56:23Z*

A genuine two-wing CHSH test cannot be hidden from Alice in this architecture,
and pretending otherwise would have produced a fake number.

The brief says the check set is drawn from the recipient stream because "she
must not know which positions are checked". I tried to honour that literally and
could not, for a structural reason worth writing down so nobody spends another
afternoon on it.

A CHSH violation needs TWO measurements on one shared pair, with two settings
per wing. In this protocol Alice's half of the pair is consumed by the Bell
measurement that teleports the payload. So on a check round she must measure her
half at an announced angle INSTEAD of Bell-measuring it against a payload, and
one qubit cannot do both. She therefore has to know, at measurement time, that
the round is a check round.

Three dead ends I tried first:

1. Use Alice's Bell-measurement outcome as her CHSH wing. It does carry
   correlation: for an ideal pair, her outcome plus her known (basis,
   eigenvalue) determines the recipient's uncorrected outcome exactly on matched
   bases. But that makes her wing a PREPARATION, not a measurement -- the
   accessible correlation matrix is diagonal in {X,Y,Z} with entries 1, and the
   CHSH combination over any settings from that set is 0. Prepare-and-measure
   admits no Bell violation, by construction. This is a theorem, not a coding
   problem.
2. Extra decoy rounds interleaved with the key rounds, so the check set hides
   inside a longer stream. Same wall: Alice still has to do something different
   with her half on a decoy round.
3. Infer CHSH from the teleportation fidelity via the singlet fraction
   (F_tel = (2 F_s + 1)/3, S <= 2*sqrt(2)*(4 F_s - 1)/3). This works arithmetically
   but is an INFERRED number under a Werner assumption, not a measured Bell
   violation, and publishing it as "CHSH" would be exactly the kind of quiet
   overclaim this project keeps finding in its own older docstrings.

What is actually true, and what the module now says: the property the estimate
rests on is that the CHANNEL ADVERSARY does not know the check set WHILE
ATTACKING. That is bought by timing, not by secrecy from Alice -- the same
argument sifting rests on in every QKD protocol. Alice learns the set only after
the pairs are through the channel, and her honesty at that point is assumption
(AUTH), which is already load-bearing everywhere else in this package (a signer
who owns both seams is accepted with probability 1 at QBER 0, per params.py).

The enforceable half is testable and is tested: distribute.py calls the
resource_factory identically on both branches (same call, same ResourceContext,
same order) and consumes exactly three variates per position either way, so
nothing on the wire or in the stream distinguishes a watched round from an
unwatched one. test_the_factory_cannot_tell_a_check_round_from_a_key_round is
the load-bearing test of the whole feature; if it ever goes red, every number
checkrounds.py produces describes a channel nobody used.

The module docstring states all of this under :ref:`check-timing`, including the
sentence that matters most: this is NOT a device-independent test.

### `[D]` Why the check fraction is 1/8, and why CHECKED_PARAMS is longer not weaker

*decision · check-rounds agent · 2026-08-31T17:56:46Z*

DEFAULT_CHECK_FRACTION = 1/8, and every step of the arithmetic is a doctest in
checkrounds.py. The point of writing it down here is the SHAPE of the
derivation, which surprised me twice.

Setup: confidence 0.99 two-sided, z = 2.5758 (obtained by bisecting math.erfc,
not from a table of fitted coefficients -- no magic constants to mistype).

R1, the QBER arm. s_a = 1/64 is a DECISION threshold, so the ask is a half-width
of s_a/4: then a channel at the budget and a noiseless one have intervals
separated by s_a/2 with no overlap. n_q >= 16 z^2 (1 - s_a)/s_a = 6688.

R2, the CHSH arm. s_a is a budget on p = 2 s_a = 1/32, and dS/dp = -2*sqrt(2),
so resolving p_a needs a half-width of 2*sqrt(2)*p_a in S. Each cell is a mean of
+-1 products, 1 - E^2 = 1/2 at the ideal point, so Var(S) = 8/n for balanced
cells: n_S >= z^2/p_a^2 = 6795.

SURPRISE 1: the weight is derived, not chosen. 6795/(6688+6795) = 0.5040, so
CHECK_CHSH_WEIGHT = 1/2 falls out of the two requirements being almost exactly
equal. I had assumed I would have to defend a split by taste. I did not.

SURPRISE 2: CHSH is a much coarser instrument than QBER for small p, and the two
requirements only look comparable because R2 was stated at the budget scale
rather than at s_a/4. The weaker ask -- merely CERTIFY a violation of the
classical bound on an honest channel -- needs 8 z^2/(2sqrt2 - 2)^2 = 78 rounds.
Seventy-eight. If I had sized the sample on that, the CHSH arm would have been
free and useless: it could say "entangled" but never "entangled at p = 0.03
rather than 0.06", which is the question Phase 4 actually asks. The reason is
structural: QBER's per-round variance is O(p) near a small p, CHSH's is O(1)
always. Anyone tempted to shrink the check fraction should shrink the CHSH arm
knowingly, not by accident.

Total 13483, which is 0.1170 of L = 115200, rounded UP to the next binary
fraction: 1/8. Rounding down would have failed the requirement it was derived
from.

WHAT IT COSTS, and the decision that follows. Spending 1/8 out of L = 115200
leaves 100800 signing positions, 33600 expected matched, and moves
enforced_repudiation_bound from 1.4139e-09 to 1.8853e-08 -- thirteen times
weaker. I did NOT ship that. CHECKED_PARAMS runs at L = 131664 (the smallest
multiple of 24 above 115200 * 8/7), whose signing length 115206 is at least the
old whole key, so the bound comes back to 1.4124e-09 -- no weaker than the
unchecked set. Check rounds are bought with key length, not with security. Both
numbers are doctests, printed side by side, precisely so the cheap one cannot be
quoted by mistake later.

DEFAULT_PARAMS keeps check_fraction = 0.0. That is deliberate: it is the audited
set whose 1.4139e-09 appears in docstrings across five modules I do not own, and
silently moving it would have invalidated all of them. Turning estimation on is
a deployment decision and now looks like one.

Finally: what binds is the COUNT, not the fraction. required_check_rounds()
exists so a deployment at another L derives its own; DEFAULT_CHECK_FRACTION is
documented as "the fraction that meets the counts at DEFAULT_PARAMS's length",
never as a universal constant. At 10x the key length the same sample is 1/80.

### `[!]` The effective length propagates through verify.py but NOT through analysis.py

*issue · check-rounds agent · 2026-08-31T17:57:05Z*

The propagation of the shortened key length is DONE for verify.py and NOT DONE
for analysis.py, and the gap is real. Anyone touching either module should read
this before assuming the feature is closed.

The mechanism: ProtocolParams gained check_fraction, and

    check_count     = floor(check_fraction * key_length)
    signing_length  = key_length - check_count
    expected_matched = signing_length / |B|        <- the change that matters

verify.py's minimum_matched_count and minimum_pooled_matched_count read
params.expected_matched and NOTHING else, so both floors and hence
enforced_repudiation_bound follow the signing length automatically, without
verify.py knowing check rounds exist. I did not have to touch it (and was not
allowed to). That is the whole trick and it is pinned by
test_every_derived_quantity_follows_the_signing_length, which asserts that a
checked set and a plain set of its signing length agree term for term -- so a
future edit that points expected_matched back at L fails immediately.

analysis.py is DIFFERENT and is not fixed. It counts Bernoulli trials against
checked.key_length directly -- Binomial(L, 1/|B|), Binomial(2L, 1/|B|), about
twenty call sites -- because when it was written every round was a key position.
Handed a set with check_fraction > 0 it counts the diverted positions as key and
returns a bound that is TOO GOOD. matched_statistics(checked).expected is 38400
where the truth is 33600; averaged_repudiation_bound(checked) is strictly
smaller than the honest one.

I do not own analysis.py, so I closed it the only two ways available:

1. ProtocolParams.sifted() is documented as MANDATORY before any analytic call,
   naming the affected functions, with the reason.
2. test_the_analytic_bounds_must_be_given_the_sifted_parameters ASSERTS the
   discrepancy, including the direction -- the unsifted call must be the
   better-looking number, which is what makes forgetting sifted() a silent
   weakening rather than a loud one. If someone later fixes analysis.py to read
   signing_length, that test goes red and should be replaced by an equality.
   That is intentional: it is a tripwire, not a blessing.

FOR WHOEVER OWNS analysis.py: the fix is to introduce a "trials" notion that
reads params.signing_length rather than params.key_length at those ~20 sites.
It is mechanical but it touches every published bound in the module, so it wants
its own change and its own review, not a drive-by.

Related sharp edge, already handled: distribute.py now REFUSES a params with
check_fraction > 0 and no check_plan. Without that refusal QDSSession (which is
not check-aware and which I must not touch) would happily distribute a
full-length record and then score it against floors sized for a shorter key --
every bound weakened, nothing in the transcript to show it. The refusal is at
the only boundary that can see both facts.

### `[-]` Five check-round decisions that are easy to undo by accident

*note · check-rounds agent · 2026-08-31T17:57:30Z*

Four smaller decisions that are easy to undo by accident, and one derivation
that turned out sharper than expected.

1. THE CHECK-ROUND QBER EQUALS THE KEY MISMATCH RATE EXACTLY, BASIS BY BASIS,
   FOR EVERY BELL-DIAGONAL RESOURCE. I expected to have to argue this only for
   Werner and hand-wave the rest. It is exact. Write the resource as
   sum_B lam_B |B><B|. The check-round error rates are

       q_Z = lam(Psi+) + lam(Psi-)
       q_X = lam(Phi-) + lam(Psi-)
       q_Y = lam(Phi-) + lam(Psi+)

   and teleportation through the same resource is the Pauli channel applying
   I, X, Z, XZ with probabilities lam(Phi+), lam(Psi+), lam(Phi-), lam(Psi-);
   a matched position in basis a errs iff the applied Pauli anticommutes with
   sigma_a, which gives the same three expressions. Werner collapses both to
   p/2, which is analysis.depolarising_error_rate -- the function s_a was sized
   against -- so the chain from a measured check statistic to Bob's threshold
   closes without a modelling assumption beyond Bell-diagonality.

   The test uses lam = (0.70, 0.10, 0.15, 0.05), giving 0.15 / 0.20 / 0.25 in
   Z / X / Y. DO NOT "simplify" it to a Werner resource: Werner gives the same
   rate in all three bases and cannot tell the per-basis identity from the
   weaker averaged one.

2. THE DISCARDED BASIS DRAW ON A CHECK ROUND IS LOAD-BEARING. distribute.py
   draws the recipient's key basis on EVERY position, including check rounds,
   and throws it away there. It looks like waste. It is what makes the variate
   budget constant at three per position on both branches, which makes the
   generator state identical at the start of every position, which makes a
   retained position of a checked run BIT-IDENTICAL to the same position of an
   unchecked run under one seed. test_retained_positions_are_bit_identical_to_
   an_unchecked_run asserts that as equality, not as a statistic -- it is a far
   stronger form of "excluding check positions does not bias the key" than any
   uniformity test, and deleting the draw would silently destroy it.

3. THE PLAN IS SHARED BY BOTH RECIPIENTS, AND MUST BE. Symmetrisation exchanges
   Bob's and Charlie's entries position by position and verification scores one
   declaration against both records, so if the two retained different positions
   the logs would stop indexing the same key. The SETTINGS are shared too, which
   is harmless (two independent links, and nothing reveals a setting until the
   pairs are through) but is a choice; a deployment wanting per-party settings
   would need a per-party plan sharing the position set.

4. NO SYNTHETIC-SAMPLE HELPER IN THE MODULE. The coverage tests need hundreds of
   samples and build them from a Bernoulli model, but those helpers live in the
   TEST file, private, not in checkrounds.py. A module that can fabricate a
   CheckLog is a module from which a fabricated estimate can reach a report. The
   cost is that Phase 5 will have to write its own if it wants calibration
   curves; that is the right trade.

5. Intervals are CLIPPED AT THE ALGEBRAIC BOUND +-4, NOT AT TSIRELSON. Quantum
   mechanics bounds the true S by 2*sqrt(2), but the ESTIMATE can exceed it by
   sampling noise, and clipping there would assume the conclusion the test
   exists to check. Same reasoning as the Wilson interval at zero errors: it
   returns [0, z^2/(n+z^2)], not [0, 0], because absence of evidence is not
   certainty.

NOT ATTEMPTED, deliberately: the brief quotes 2.0000 for a kept GHZ share and
1.0020 for intercept-resend as Phase 4 figures. I derived and pinned only what I
could derive -- 2*sqrt(2) ideal, (1-p)*2*sqrt(2) Werner, the classical bound 2,
and a classically correlated pair sitting below it -- and made no claim about
those two. Phase 4 owns them; if they disagree with this module's settings, the
settings are in CHSH_ALICE_ANGLES / CHSH_RECIPIENT_ANGLES and the prediction is
depolarising_chsh().

### `[D]` The signer seam no longer sees the recipients' logs by default

*decision · attack-surface agent · 2026-08-31T19:40:02Z*

The signer seam used to be handed BOTH recipients' raw logs on every run. That
is strictly more than any single adversary in the threat model holds -- a
repudiating Alice holds neither log, a forging recipient holds one -- and it is
where the whole Phase 2 repudiation attack family started. The default now
passes NO_RECIPIENT_LOGS and the old behaviour is
QDSSession(..., signer_sees_recipient_logs=True).

Three decisions inside that, each easy to undo by accident:

1. It is a CAPABILITY flag, not a "this run cheated" flag. What the transcript
   records is "the seam was shown both logs", not "the signer read both logs" --
   nothing can check the second. The summary line says exactly that, and the
   wording matters: "Any bound quoted for this run holds only if the signer in
   fact read no more than its adversary is entitled to, and nothing here checks
   that." An attack that legitimately reads only its own log (a recipient
   forger mounted on the signer seam) still trips the flag, because the flag is
   about the harness, not the attack.

2. The default is a WithheldRecords instance, not {}. A signer reaching for
   records[b][Party.BOB] against a plain {} gets `KeyError: 0`, which is
   indistinguishable from a mis-wired attack; against this it gets a KeyError
   naming the constructor flag and pointing a recipient forger at the forwarder
   seam. It is otherwise an exact empty Mapping, so `.get(b, {})` and len() and
   iteration behave, and honest_signer is unaffected.

3. The opt-in still hands over the RAW logs, never the post-exchange ones. That
   was already the rule and it stays: the raw log is what a forging recipient
   needs (half of the counterpart's evidence IS his raw record after Phase A'),
   and the post-exchange logs would hand a repudiating Alice the coins'
   outcome, which is the only randomness the non-repudiation bound uses.

Six existing attack call sites in four test files had to add the flag
(test_phase2_integration, test_protocol_reconciliation, test_protocol_verify,
test_protocol_verify_abort). Every one of them reads a recipient log, so every
one of them was already outside the model in the harness's sense; they now say
so. tests/test_attack_isolation.py needed nothing -- signer_probe calls the seam
directly and never goes through QDSSession.sign.

### `[*]` The recipient forger belongs on the forwarder seam, and what that route actually returns

*finding · attack-surface agent · 2026-08-31T19:40:03Z*

session.py used to send a Phase 3 author to mount a forging Bob on the SIGNER
seam. That is the wrong adversary: the signer's declaration goes to BOTH
verifiers, so Bob is handed his own forgery and rejects it. Measured at L=600
on one seed, and now asserted in tests/test_protocol_session.py
(test_the_signer_route_records_a_successful_forgery_as_a_rejection):

  * signer route: Bob's rate leaves 0.0 and lands at the 1/12 forger floor with
    Charlie's, and Bob's matched count inflates from ~L/3 to ~2L/3 because the
    declaration was built from a recipient's log rather than drawn independently
    of it. transferable=False, repudiated=False -- a working forgery recorded as
    a run in which nothing happened.
  * forwarder route: Charlie's VerificationResult is IDENTICAL (same record,
    same forged key, same verdict object) and Bob keeps his honest verdict.

So the forwarder route buys nothing at Charlie and costs nothing but Bob's
corruption. It is now the documented route, and Forwarder.__call__ takes an
optional keyword-only `view` so the attack can be written against Bob's own
RecipientView with no back-patching and no access to Charlie's log.

TWO THINGS THE NEXT AGENT MUST KNOW.

(1) Under the SHIPPED (pooled) rule the forwarder route does not produce a
rejection at Charlie -- it produces a NO VERDICT,
AbortReason.COUNTS_FROM_TWO_DECLARATIONS. Phase C' runs before either verdict,
so the counts Charlie holds were computed against Alice's declaration while he
is scoring Bob's, and m_C(forwarded) + m_B(original) is no run's pooled count.
verify.py's `one-declaration` section already reasons this through and is
right. The consequence for Phase 3/5: to measure the forger's RATE against s_v
(the 1/12 floor) the run must be pre-pooled, count_exchange=no_count_exchange,
which is the same arm the split-coin experiments already use.

(2) That refusal is NOT evidence that recipient forgery is caught. It is
guaranteed by this harness's ordering: the forwarder seam has no way to supply a
matching matched-count message, so a substituted declaration always arrives with
a stale digest. A real forging Bob announces his own count against his own
declaration and does not trip it. Closing that would mean letting the forwarding
party re-run Phase C' -- a change to tally.py's message flow, which is audited
and which I did not touch. Flagged here so it is a known gap rather than a
result.

`view` is detected the same way the resource factory's context is: a forwarder
that CAN be called with two arguments IS called with two, so only `*, view` with
no default receives one. honest_forwarder declares `view=None` precisely in
order to decline it, which keeps the honest path from building a RecipientView
at all.

### `[+]` repudiated is gated on the forwarding hop, and summary() had two false closing lines

*fix · attack-surface agent · 2026-08-31T19:40:03Z*

SessionTranscript.repudiated is now

    bob.accepted and not charlie.accepted
    and not forwarding_altered_signature      <-- new
    and session_coherent

Repudiation is Alice disavowing ONE declaration, so it needs both verifiers to
have scored one. When Bob himself supplied Charlie's -- which is now the
documented recipient-forgery route -- "Bob accepted and Charlie rejected" is the
expected outcome of a FORGERY experiment, and counting it would add one to a
Phase 5 repudiation rate for every forgery attempt. Same argument the property
next door already makes: pooled_matched_count returns None on an altered run
because it is two experiments and not one.

This is a BREAKING SEMANTIC CHANGE for anything that classifies runs. Nothing in
the repository relied on it -- every other .repudiated call site runs an honest
forwarding hop -- but a Phase 4/5 table that switches on outcomes needs the new
cases.

summary()'s closing line had the same hole and is fixed with it. It used to fall
through to "REJECTED: Bob did not accept the signature" whenever transferable
and repudiated were both False, which was a FALSE STATEMENT on exactly two kinds
of run: one where the hop altered the declaration and Bob accepted, and one
where session_coherent was False. There are now five closing lines:

    NO VERDICT / INCOMPLETE / TRANSFERABLE / REPUDIATION
    REJECTED         -- only when Bob genuinely did not accept
    INCOHERENT       -- verdicts and declaration from different rounds
    NOT TRANSFERRED  -- Bob accepted, Charlie scored a different declaration

The order of the elif chain is load-bearing: REJECTED is now guarded by
`not self.verdict_for(Party.BOB).accepted`, which is only safe because the
aborted and not-is_complete branches come first and guarantee both verdicts
exist.

### `[D]` Making QDSSession check-aware: the plan's stream, two identity tricks, empty logs

*decision · attack-surface agent · 2026-08-31T19:40:04Z*

QDSSession accepts a params with check_fraction > 0 now. The checkrounds agent
left the recipe and it was right; what follows is the part that is not obvious
from the recipe.

THE PLAN COMES FROM self._recipient_rng, one per message bit, drawn BEFORE that
bit's distribution and therefore before that bit's symmetrisation coins. Never
from the Alice stream: the whole value of a sampled estimate is that the
estimated party cannot choose the sample, and a distributor seam holding Alice's
generator must not be able to predict which positions are watched. Pinned by
test_the_check_plan_is_drawn_from_the_recipients_stream, which rebuilds the
stream from the seed material and draws the plans out of it.

TWO IDENTITY TRICKS, both deliberate, both worth keeping:

  * self._scored_params is `params.sifted() if params.has_check_rounds else
    params` -- the params object ITSELF on the common branch, not an equal copy.
    params.sifted() returns replace(self, check_fraction=0.0), which is equal
    but not identical, and a seam handed it would stop receiving the very object
    the caller passed. test_the_signer_seam_receives_exactly_what_a_repudiating
    _alice_holds asserts `captured["params"] is params`.
  * self._signing_keys is the SAME TUPLE as self._keys when no plan is in force,
    so `signature.declared_key is session.keys[b]` stays true. With a plan it is
    plan.sift_key(keys[b]) per bit, which shares the elements.

The record stamp uses self._scored_params.key_length, not params.key_length,
because Signature.session_id derives from len(declared_key) and the declared key
is the sifted one. Getting that wrong makes every checked run abort as
SESSION_MISMATCH.

The transcript keeps the UNSIFTED params -- it still has to record that the run
reserved a check fraction -- and _check_result_against / _check_abort_against /
_check_pooled_against re-derive params.sifted() themselves. repudiation_guarantee
likewise: analysis.py counts Bernoulli trials against key_length directly, so
handing it a checked set would count the diverted positions as key and return a
bound that is too good.

EMPTY CHECK LOGS ARE DROPPED, not filed. The default distributor is now
distribute_public_key_with_checks (identical records -- the other function is a
wrapper over it -- plus the logs), and on an unchecked run it returns four
CheckLogs with no rounds in them. Carrying those would put "this run published
no statistics" into every honest transcript as four objects rather than as an
absence, and would change the serialised form of every seeded run in the
project. _check_distribution files a log only when round_count > 0.

### `[D]` The channel monitor: a tap on the factory, check positions only, no Bell outcome

*decision · attack-surface agent · 2026-08-31T19:40:04Z*

Phase 4 needs per-check-round channel diagnostics in the transcript. Three
design choices, in decreasing order of how easy they are to get wrong.

1. THE MONITOR IS A TAP ON THE RESOURCE FACTORY, NOT A HOOK IN distribute.py.
   QDSSession wraps whatever resource_factory it was given in a _ChannelTap that
   calls it identically at every position and then, only at a position the plan
   designates a check round, records a ChannelSample. Two reasons for the
   wrapper over a hook. It keeps distribute.py's load-bearing invariant intact
   by construction -- the factory is the whole of the adversary's access to the
   loop, and the tap is strictly downstream of it, so
   test_the_factory_cannot_tell_a_check_round_from_a_key_round is untouched and
   still means what it says. And the session already knows the plan, so the
   filter "check positions only" lives in the one object that can enforce it.

2. NO BELL OUTCOME AND NO CORRECTION BITS, and this is not an oversight. The
   brief asked for them. A check round runs NO teleportation -- it spends its
   pair on measuring both wings -- so neither quantity exists on the rounds that
   may be published. They exist only on key rounds, and publishing a key round's
   channel per position is precisely what the sampling exists to prevent: an
   estimate whose sample is every position is not a sample. What is published
   instead is the pair itself, summarised: fidelity to |Phi+>, purity,
   concurrence, and the two single-qubit marginal purities. A detector that
   wants more writes a channel_monitor and gets it into ChannelSample.extra;
   that is what the seam is for.

3. THE TWO WING MARGINALS ARE WHY THE SUMMARY IS NOT THREE NUMBERS. Fidelity,
   purity and concurrence are all invariant under swapping the two qubits, so
   an attack on the leg in flight and an equally strong fault in Alice's own
   apparatus produce IDENTICAL triples -- asserted in
   test_the_two_wings_say_which_end_of_the_pair_was_disturbed. alice_purity and
   recipient_purity separate them. The qubit indices are imported from
   checkrounds (_ALICE_QUBIT, _RECIPIENT_QUBIT) rather than written as 0 and 1,
   so the two modules cannot come to disagree about which half is whose; reading
   the pair the wrong way round would attribute a one-sided attack to the wrong
   party with nothing failing (D2).

ENFORCED, NOT JUST INTENDED: SessionTranscript.__post_init__ checks every
ChannelSample against the run's own published CheckLog and refuses one sitting
at a position the log did not record, or tagged with the other arm. The live
path cannot produce such a sample; a transcript is a file and can say anything.
A run whose distributor returned bare records publishes no log, and then the
sample is only range-checked -- the honest reading of "tapped but not
published".

SURPRISE WORTH KNOWING: a one-sided attack on the CHANNEL is not one-sided in
the EVIDENCE. Aiming a payload substitution at Charlie's link raises BOB's
mismatch rate too, because Phase A' then re-assigns half the corrupted entries
to Bob (test_the_payload_seam_can_target_one_recipients_link measures both
arms; with no_symmetrisation the aim is exact, 0.0 and 1.0). The check rounds
are what localise it, because they happen per link and BEFORE the exchange --
which is also why Bob's and Charlie's CheckLogs must never be pooled into one
rate.

### `[-]` Files touched outside the ownership list, and why each one had to be

*note · attack-surface agent · 2026-08-31T19:58:37Z*

The brief gave me sih141/protocol/session.py and tests/test_protocol_session.py.
Seven other files had to change, and each one is here so the next reviewer does
not have to reconstruct why.

sih141/protocol/distribute.py -- the payload_map seam LIVES here; there is
nowhere else to apply a map to the state between preparation and teleport().
Additive only: a new PayloadMap alias, identity_payload, _map_payload, one
keyword on the four public functions defaulting to None, and one call site
inside the key-round branch. With payload_map=None nothing is called and the
variate stream is untouched, so every seeded run in the project is unmoved.

sih141/protocol/__init__.py -- exports for the new public names (PayloadMap,
identity_payload, ChannelMonitor, ChannelSample, WithheldRecords,
NO_RECIPIENT_LOGS). The checkrounds agent left a note that whoever owns this
file should add theirs; I did not add theirs, only mine, so that note still
stands.

tests/test_phase2_integration.py, tests/test_protocol_reconciliation.py,
tests/test_protocol_verify.py, tests/test_protocol_verify_abort.py -- six
QDSSession constructions whose signer reads a recipient log. They now pass
signer_sees_recipient_logs=True. Nothing else about them changed: same seeds,
same assertions, same numbers, because the flag is a capability and not a mode.

docs/PHASE2.md -- the seam table said the signer seam receives both raw logs
and that the forwarder takes two arguments. Both are now false. I did not
rewrite the Phase 2 narrative -- it is a record of Phase 2 and should stay one
-- and added a "Changed in Phase 3" block under the table instead, pointing at
the three session.py sections that carry the current story. A stale claim in a
doc is the failure mode this project has already had three times.

Not touched, deliberately: tally.py and verify.py. The forwarder route's
COUNTS_FROM_TWO_DECLARATIONS behaviour is theirs to change if anyone decides it
should change, and the reasoning in verify.py's one-declaration section is
sound as written. See the finding entry for the gap.

### `[*]` Impersonation measured: full accepted 200/200, partial 0/200 at QBER 1/2; shipped 0.4806 unreproducible

*finding · attack-impersonation · 2026-08-31T21:20:20Z*

Phase 3 adversary: IMPERSONATION (sih141/attacks/impersonation.py).

WHAT WAS MEASURED
200 sessions per scope at L = 192, message bit 0, one shared seed sequence
(900000..900199) across all four arms, Mallory's generator seeded 4242 and
never the session's. Pooled over positions, not averaged over runs:

  scope         accepted(both)   r_Bob     r_Charlie   matched sets vs control
  none          200/200          0.0000    0.0000      identical (200/200)
  full          200/200          0.0000    0.0000      moved (0/200)
  signing         0/200          0.4988    0.5038      moved (0/200)
  distribution    0/200          0.5031    0.4997      IDENTICAL (200/200)

Wilson 95% on the partial rates covers 1/2 in all four cells. Acceptance
intervals do not overlap: full [0.9812, 1.0], partial [0.0, 0.0188].

THE SHIPPED (AUTH) FIGURES DO NOT STAND AS WRITTEN
analysis.py lines 92-99 quote "0/60 accepted, at QBER = 0.4987 (Bob) and 0.4806
(Charlie)" with no key length and no scope split. The 0/60 acceptance is
correct and reproduces. 0.4987 is unremarkable. 0.4806 is the problem: at any
plausible L the pooled matched count over 60 runs is >= 1200 positions, so the
sd of a pooled rate is <= 0.0144 and 0.4806 is 1.3 sd low -- possible, but it
is quoted to four figures with no n, no L and no statement of whether it is
pooled over positions or averaged over runs, and those two estimators differ.
I could not reproduce it either. RECOMMENDATION for whoever owns analysis.py
(I did not edit it, per the rules): replace both numbers with the four-row
table above, which records L, n and the counts behind every rate, and note
that the two partial scopes are separate experiments rather than one.

WHY 1/2 AND NOT SOMETHING ELSE, ON BOTH ROUTES
Signing seam only: Mallory's declared eigenvalue is a fair coin independent of
everything the recipient measured, so P(mismatch | scored) = 1/2 outright.
Distribution seam only: Alice declares her true (a_i, u_i) and the recipient
measured Mallory's eigenstate in a_i. With prob 1/n Mallory's basis matched and
the outcome is her own independent fair coin; otherwise the Born rule makes it
a fair coin. Either way 1/2. Both are per-POSITION statements and never mention
L, which is the whole scaling argument: the L = 192 measurement carries to
L = 115200 unchanged, and the thresholds (1/64, 1/16) only get further away.

THE SURPRISE WORTH LOGGING
Under the DISTRIBUTION scope the matched set is identical POSITION FOR POSITION
to the control at the same session seed -- not merely the same in distribution.
Reason: my distributor forwards the session's Alice-side rng to
distribute_public_key_with_checks and consumes exactly the same number of
variates (the key it sends is a different key, not a different length), so the
recipients' measurement bases are bit-identical; and Alice still declares her
own key, so {i : c_i == d_i} cannot move. matched_sets_identical() checks it
and MATCHED_IDENTICAL_TRIALS records 200/200. This is the sharpest available
statement that the evidence floors are an evidence-liveness control and not an
impersonation detector.

FOR PHASE 4
Only ONE transcript statistic moves under partial impersonation:
VerificationResult.rate. matched_count, pooled_matched_count and the check-round
QBER are all unchanged, and all are reachable from the transcript. Under FULL
impersonation NOTHING moves -- and the impersonating distributor teleports
faithfully over an ideal resource, so the channel monitor reports a perfect
channel while the key is somebody else's. A Phase 4 detector that keys off
channel quality will see nothing here. detector_signals() ships this as data.

DESIGN DECISION: ONE Impersonator OBJECT, TWO SEAMS
The distributor and the signer are bound methods of the same object sharing one
key cache keyed on (message_bit, key_length). Two independent adversaries, one
per seam, would draw two different keys and FULL would silently degrade into a
signing-only impersonation -- 0/200 accepted, presented as a security result.
The check-round case is the trap: distribution happens at the full length and
signing at the sifted one, so Impersonator.distribute sifts its key with the
plan it is given and files the result under the sifted length. There is a test
(test_full_impersonation_survives_check_rounds) whose only job is to fail if
that line is deleted.

D6
Both seams pass assert_attack_isolated separately. The distribution seam needed
its own probe: the honest probe shape would return the records, which ARE a
function of the session's Alice-side stream by construction, so check (a) would
fail for an entirely honest reason. distributor_probe() returns the KEY Mallory
substituted instead, which is the decision D6 is actually about. Worth knowing
before writing any other adversary that sits on the distribution seam.

### `[*]` Count starvation is free but cannot hide: z = -11.54 at every L

*finding · phase3-starvation-agent · 2026-08-31T21:20:46Z*

Count starvation is free to mount and impossible to hide, and the second half of
that is a theorem rather than a measurement.

The attack: a recipient replaces his own MatchedCountMessage with a smaller
count and delegates to the shipped exchange_matched_counts. Cost: one integer.
No key material, no quantum resource, no computation. Denial is deterministic,
not probabilistic - measured 40/40 at L=600 in every starving arm.

What makes it interesting is the price in plausibility. Both floors are the same
Chernoff tail at the same budget eps = 2^-64, so the largest count that still
denies sits a FIXED number of honest standard deviations below the mean,
independent of L:

    mu - m_min = sqrt(2 mu ln(1/eps)),  sd = sqrt(2 mu/3)
    z -> -sqrt(3 ln(1/eps)) = -11.5362

Measured: -11.6047 at L=600, -11.5738 at L=1200, -11.5375 at DEFAULT_PARAMS.
It converges from below, so the attack does not get quieter at deployment scale.
A Phase 4 detector thresholding the declared count at m_min has a false-alarm
rate of matched_shortfall_probability(params, minimum_matched=m_min) - 4.1e-37
at L=600, 2.5e-31 at DEFAULT - and catches every successful starvation with
certainty, because every successful starvation is by definition below m_min or
below M_min - m_B. One z-score against a binomial whose parameters are L and
|B|. No history, no ML (D4).

The one route to a denying declaration ABOVE m_min is the pooled branch,
c < M_min - m_B. It requires the VICTIM's own honest count to be below
M_min - m_min, which is (sqrt2 - 1) * 11.5362 = 4.78 sd low and which the
starver does not control: probability 8.3e-07 at DEFAULT_PARAMS. Even inside it
the usable window is a few counts wide just above m_min.

Second finding, and the one I did not expect: the naive starvation leaves a
within-ONE-RUN contradiction. A starving Charlie still reaches his own verdict -
his own count comes from his own record and only the counterpart's count comes
from the exchange - so one transcript holds pooled.charlie_count = 0 beside
results[Charlie].matched_count = 208. He cannot suppress it from inside the
count_exchange seam. Measured accepted_by_starver = 40/40. The denial is
strictly one-sided: he denies the other verifier and keeps his own acceptance,
which is a transferability inversion worth naming even though it is not a
forgery.

Third: selectivity is free and is the worse variant. The seam sees the message
bit and the declaration digest before it answers, so denying only bit 1, or only
a chosen digest, costs nothing and leaves every untargeted run completing
normally. No aggregate over OUTCOMES separates a selective starver from an
honest pair on a noisy channel. The separation has to come from the declared
counts, which is the z-score above - so the per-run signal is load-bearing, not
a convenience.

Not a break: every acceptance still needs the accepting verifier's own rate on
his own log to clear his own threshold, and no message from the counterpart
touches that. Under-reporting can only withhold an acceptance. tally.py already
said this in prose; it is now an experiment.

Files: sih141/attacks/starvation.py, tests/test_attack_starvation.py.

### `[-]` count_exchange seam: last-mover advantage, and why an adversary must restrict itself

*note · phase3-starvation-agent · 2026-08-31T21:21:06Z*

Two seam observations from writing the count-starvation adversary. Neither is a
defect and I changed nothing under sih141/protocol/, but both change what a
measured number means and should be stated rather than discovered later.

1. The count_exchange seam makes the starver a LAST MOVER.

   CountExchange is called as (messages, params) with BOTH verifiers' messages
   already computed. So an adversarial seam sees the victim's count m_B before
   choosing what to declare, and can compute denial_headroom exactly rather than
   guessing. Phase C' is described as an exchange, and a real deployment may run
   it simultaneously, in which case the starver would have to commit blind.

   I kept the advantage rather than modelling it away: it only ever helps the
   adversary, so the measured attack is the conservative one. But it means the
   pooled branch of the headroom (c < M_min - m_B) is exactly available in this
   model and would be only guessable in a simultaneous one. If Phase 4 or a
   reviewer wants the simultaneous variant, it is a different experiment and
   should say so - not a parameter of this class.

2. The seam is SHARED, and the threat model is not.

   QDSSession builds one PooledMatchedCounts from the seam and hands it to both
   verifiers, but a recipient controls only his own message. An unconstrained
   seam could edit the counterpart's count, both floors and the declaration
   digest; a recipient cannot. CountStarver therefore restricts itself in code -
   it replaces its own message and delegates to exchange_matched_counts - and
   the test suite pins that. Anyone writing another count_exchange adversary
   should do the same, or they will publish a rate for a party that does not
   exist.

   Note this restriction is not costly. The floors are re-derived by
   _check_pooled_against at the transcript boundary and by verify() at the
   verdict, so editing them is inert and merely visible. A doctored digest is
   refused as COUNTS_FROM_TWO_DECLARATIONS - which is also a denial, but a
   two-sided and loud one, and it would deny the starver himself.

   The consequence worth keeping: the ONLY channel from this seam into a verdict
   is one integer plus its declaration binding, via
   PooledMatchedCounts.counterpart_of. That is a genuinely narrow surface and it
   is why the attack is a pure availability attack with no integrity component.

3. What the transcript does not retain: history. SessionTranscript is one run.
   A Phase 4 detector that wants "this verifier keeps starving the pair" has to
   keep its own ledger keyed by party across transcripts; nothing in the package
   accumulates one. Not a blocker, because the per-run z-score is already
   decisive at a false-alarm rate of 2.5e-31, but the pattern-level detector is
   Phase 4's own work and needs stating.

### `[*]` One correlation tensor predicts both check-round statistics

*finding · attack-agent:channel · 2026-08-31T21:29:37Z*

Every resource the channel adversary produces is Bell-diagonal or a collapse of one, so
its correlation tensor is diagonal and BOTH published statistics fall out of three numbers:

    S    = sqrt(2) * (T_zz + T_xx)                (the shipped CHSH settings lie in x-z)
    QBER = mean_b (1 - s_b T_bb) / 2,  s = (+1, -1, +1)

WHY THIS IS WORTH KEEPING. It replaced a per-attack derivation with one identity, and it
immediately explained two things that were otherwise going to be measured and shrugged at:

1. T_yy cannot reach S at all. The CHSH settings are 0, pi/2 for Alice and +-pi/4 for the
   recipient, all in the x-z plane, so a resource whose ONLY defect is on the y axis
   passes the Bell test with a perfect 2.8284 and is caught only by the QBER arm. That is
   a real blind spot in the check-round design, not a rounding of one, and Phase 4 must
   not treat "S is at Tsirelson" as "the link is clean".
2. Intercept-resend and a kept GHZ share have the SAME tensor when Eve draws her axis the
   same way, so no correlator separates them at any sample size. They are separated only
   by ChannelSample.purity (1.0 for a pure resent product, 0.5 for the rank-2 kept-share
   marginal). The identity said so before any rounds were spent looking.

It also fixed the auditor's reference value: a kept GHZ share has T = (0,0,1), so
S = sqrt(2) = 1.4142, NOT 2.0000. 2.0000 is CLASSICAL_CHSH_BOUND and is also
depolarising_chsh(1 - 1/sqrt(2)); the two are easy to transpose. Measured 1.3950
[1.2951, 1.4949] at 8000 rounds, which excludes 2.0.

### `[*]` Check logs are not symmetrised, so per-link attribution survives

*finding · attack-agent:channel · 2026-08-31T21:29:54Z*

THE QUESTION: symmetrisation smears a party-targeted attack across both post-exchange
logs, so a one-link attack at strength q looks like a two-link attack at q/2. Do the
check rounds recover per-link attribution?

THEY DO, and the reason is structural rather than statistical: QDSSession builds one
CheckLog per (party, message_bit) INSIDE distribute(), from the _ChannelTap wrapper, and
then calls the symmetriser. The symmetriser's signature only ever sees RecipientRecords.
No code path hands a CheckLog to Phase A'. So the smearing is confined to the records.

MEASURED, depolarising p=0.14 aimed at Bob's link, L=960, check_fraction=0.5, pooled over
both message bits (attribution_survives_symmetrisation() in sih141/attacks/channel.py):

  post-exchange record rate   Bob 0.0204   Charlie 0.0292   <- smeared, not attributable
  unsymmetrised companion     Bob 0.0567   Charlie 0.0000   <- what was smeared
  check-log QBER              Bob 0.0708 [0.0462, 0.1072]
                              Charlie 0.0000 [0.0000, 0.0136]   <- DISJOINT at 99%
  check-log CHSH              Bob 2.4734 [2.1035, 2.8434]
                              Charlie 3.0425 [2.7363, 3.3486]

Bob's check QBER lands on the predicted p/2 = 0.07 and Charlie's is exactly zero. The
QBER arm attributes cleanly; the CHSH arm at this sample size does NOT (the intervals
overlap heavily, and Charlie's point estimate is 3.04, above Tsirelson, which is ordinary
sampling noise on 480 CHSH rounds). At p = 0.14, dS = 0.4 while the CHSH half-width at
DEFAULT check sizing is ~0.2, so CHSH attribution needs the full-scale sample; QBER
attribution does not.

CONSEQUENCE FOR PHASE 4: the detector must read per-party CheckLogs and must NOT pool
Bob's and Charlie's logs into one channel estimate. estimate_qber's own docstring already
warns that pooling two different links "reports the average of two things and detects
neither" -- that warning is exactly the attribution loss, and pooling would voluntarily
throw away the only signal that survives symmetrisation.

### `[*]` Ledger DoS: the hop can burn Charlie's round, and only Phase C' ordering stops it

*finding · phase3-replay-adversary · 2026-08-31T21:30:04Z*

The replay defence holds against every replay I could mount. The thing that does
NOT hold is a denial of service built out of the ledger, and what closes it is
not the replay defence at all.

Mechanism. Phase B reveals the round's opening ON the declaration. The
identifier deliberately does not cover the declared key (so that a forgery is
scored rather than refused). Therefore anyone who has seen the declaration can
mint a different declaration naming the SAME round. The Bob-to-Charlie hop is
exactly where the threat model puts an adversary and is not covered by the
classical authentication assumption. He hands Charlie a forged-but-correctly-
named declaration; Charlie scores it, REJECTS it, and a rejection is a verdict,
so the round is SPENT. The genuine declaration, arriving afterwards by any
route, is then refused as RECORD_ALREADY_VERIFIED. Charlie can never accept it.
Without the ledger the same adversary gets a denial that the next presentation
undoes.

What saves it, and why that is uncomfortable. A Phase C' count names the
declaration it counted. If Charlie's counterpart count names the declaration
ALICE SIGNED while Charlie is looking at the forged one, he refuses on
COUNTS_FROM_TWO_DECLARATIONS -- a refusal, so nothing is spent, so the genuine
declaration still lands. That is what the shipped QDSSession does, because it
runs exchange_counts() lazily inside verify(Party.BOB), i.e. BEFORE the
forwarding hop. It is not what a deployment does: each recipient counts against
the declaration he actually received, and the adversary holding the hop is also
the recipient who computes one of the two counts, so he counts against what he
forwards and the provenance check sees one consistent declaration.

Measured at L=24, defended arm, 300 trials each ordering (successes = the honest
declaration failed to be accepted):
  counts="none"        300/300   (the pre-pooled variant, no_count_exchange)
  counts="as-received" 300/300   (the deployment reading)
  counts="as-signed"     0/300   (the shipped session's ordering)
Undefended (no ledger, unstamped record): 0/300 in every ordering.

So the ledger's denial-of-service surface is currently closed by an ORDERING
ACCIDENT in a component built for something else entirely (the pooled floor's
one-declaration rule), and it is wide open in the two configurations the package
itself ships as legitimate. I did not change any protocol file -- that is a
finding, not an edit -- but Phase 4/5 should not repeat the claim in
sih141/protocol/verify.py's :ref:`replay` section that "an adversary therefore
cannot poison a verifier's ledger from outside ... the residual denial-of-service
surface prices out at zero". Poisoning from outside is indeed impossible (I
measured 0/400 over three routes). Making the verifier spend a round he was
entitled to spend, on a declaration the adversary chose, is not.

### `[D]` Isolation probes: payload seam needs check_fraction 0, and D6 forces sampled noise

*decision · attack-agent:channel · 2026-08-31T21:30:11Z*

Two things an isolation probe over a channel attack has to get right, both learned the
hard way while wiring sih141/attacks/channel.py to assert_attack_isolated.

1. A PAYLOAD-SEAM PROBE MUST RUN WITH check_fraction = 0.
   payload_map is called on key rounds only, and WHICH positions are key rounds is decided
   by the recipients' check plan, drawn from the session's own generator. So the set of
   contexts a payload attack is offered legitimately MOVES with the session seed even for a
   perfectly isolated adversary. A probe that returns the attack's log including positions
   therefore fails an honest attack -- check (a) fires, reads_the_session comes back True,
   and the diagnosis points at the adversary instead of at the probe. With no check rounds
   every position is a key round, the call set is fixed, and only Eve's own choices vary.
   The resource seam has no such problem: it is called identically at every position on
   both branches (check-round lockstep), so a resource probe can keep check rounds on.

2. A DETERMINISTIC ADVERSARY CANNOT PASS, AND THAT SHAPED THE PHYSICS.
   check_attack_isolation's half (b) requires the adversary's decisions to MOVE when its own
   generator moves. A depolarising channel written the obvious way -- return the Werner
   density matrix (1-p)|Phi+><Phi+| + p I/4 -- draws nothing and is caught as "does not use
   its own generator", the same verdict as the DeafForger control. The fix is not to weaken
   the check; it is to realise the channel as a per-round Pauli twirl on the travelling
   wing, which is what a physical channel does, has exactly the Werner ensemble, and makes
   the adversary's behaviour a function of its own stream.
   The realisation is NOT observationally equivalent everywhere, and the difference is a
   Phase 4 signal: a twirled Bell pair is still a Bell pair, so ChannelSample.purity and
   .concurrence stay pinned at 1.0 every round and the wings stay symmetric; only .fidelity
   moves, and it moves to 0.0 on engaged rounds rather than drifting to 1 - 3p/4. Returning
   the averaged Werner state instead would put fidelity at a constant 1 - 3p/4 on every
   round -- a far louder signal, and a fictional one.

### `[D]` The seams cannot express a cross-round replay; _bind_to_round relabels it as fresh

*decision · phase3-replay-adversary · 2026-08-31T21:30:19Z*

Wrote sih141/attacks/replay.py as a REPLAYING FORWARDER (the Bob-to-Charlie hop)
rather than as a replaying signer, and then measured the cross-round attacks
OUTSIDE that seam. The reason is worth recording so the next agent does not
spend an afternoon on it.

QDSSession._bind_to_round() overwrites the session_opening of whatever the
forwarder returns with the LIVE round's opening. A stale declaration pushed
through the forwarder seam therefore arrives at Charlie carrying the live
identifier: the replay binding cannot see it, and Charlie scores it as a
forgery. That is deliberate and correct -- if the seam could leave the round
unnamed, every forgery would abort as SESSION_MISMATCH and the whole Phase 3
forgery table would empty into the no-verdict column -- but the consequence is
that the forwarder seam CANNOT EXPRESS a cross-round replay at all. Nor can the
signer seam, for the same reason.

So a faithful cross-session experiment has to assemble the (signature, record)
pair itself and call verify_or_abort directly. That is what
measure_cross_session_pairing and friends do. It is not a shortcut: verify() is
the whole of Phase C, and the pair handed to it is exactly the pair the
adversary would present.

Consequence for the integrator: do NOT try to measure replay by wiring
ReplayingForwarder into QDSSession and reading the transcript. The adversary is
written faithfully (it really does substitute and relabel) and is D6-isolated,
but what the transcript will show is an altered forwarding, not a replay.
tests/test_attack_replay.py::test_session_relabels_a_stale_declaration_as_fresh
pins that so a change to the rebinding cannot silently turn these numbers into
something else.

### `[*]` The payload line is invisible to both check arms, measured

*finding · attack-agent:channel · 2026-08-31T21:30:30Z*

Measured, not asserted. sih141/attacks/channel.py mounts InterceptResend twice under
identical seeds, once on resource_factory and once on payload_map, L=960, check_fraction=0.5
(payload_line_is_unwatched()):

                     key mismatch rate   published QBER   published CHSH
  resource line            0.3535            0.3177           0.8813
  payload line             0.3613            0.0000           2.7561

Comparable destruction of the key. On the resource line both statistics collapse; on the
payload line the QBER arm reports a PERFECT channel -- literally zero errors, not a small
one -- and the Bell test still violates the classical bound at close to Tsirelson.

This is a documented consequence of the seam design (sih141.protocol.distribute,
:ref:`payload-seam`: "a check round prepares no payload ... neither the QBER nor the CHSH
estimate will move because of one"), so the mechanism is not news. The SIZE of it is what
Phase 4 needs and what had not been measured: there is no partial visibility to exploit and
no residual signal to threshold on. The channel-statistics detector has exactly zero power
against anything mounted on the payload line, and the ONLY reachable signal is
VerificationResult.rate.

That is not a hole in the protocol -- the payload seam is inside Alice's preparation, on
her side of the Bell measurement, so an eavesdropper on the wire cannot reach it and an
Alice who can reach it is the repudiating-signer threat model, not the channel threat
model. But a Phase 4 detector that reports "channel clean" must say WHICH channel it
means, or a reader will hear "key clean" and be wrong by a factor of infinity.

### `[*]` wings_agree detects none of the channel attacks; fidelity and purity do

*finding · attack-agent:channel · 2026-08-31T21:34:12Z*

ChannelSample.wings_agree is documented as "the signature of something that acted on ONE
leg, which is the shape of an eavesdropper on the wire rather than a noisy source". Every
attack in sih141/attacks/channel.py acts on one leg -- the travelling qubit, resource
qubit 1 -- and NONE of them moves wings_agree. All three leave
alice_purity == recipient_purity on every check round.

The reason is that the leg is one half of a MAXIMALLY ENTANGLED pair. Measuring the
travelling half of |Phi+> collapses Alice's half too; dephasing it into Eve's ancilla mixes
Alice's half by the same amount; a Pauli on it leaves both halves at 0.5 as before. There
is no local operation on one half of a maximally entangled state that changes only that
half's marginal purity, because both marginals are already maximally mixed and the reduced
state of the untouched wing is invariant under any trace-preserving map on the other.

So wings_agree is a detector for a channel that DAMPS or REPLACES the travelling qubit
with something less than maximally mixed (the docstring's own worked example is a split
product state, alice 0.5 / recipient 1.0), and it is not a detector for eavesdropping on a
Bell-pair distribution link. Phase 4 should not lean on it for the channel-manipulation
family.

What does work, measured over one link's check rounds at L=256, check_fraction=0.25:

  resource            fidelity   purity   concurrence
  clean pair          1.00       1.00     1.00
  depolarising p      1 - 3p/4   1.00     1.00
  intercept-resend    0.50       1.00     0.00
  kept share          0.50       0.50     0.00

Fidelity alone ranks all four. Purity and concurrence are blind to the depolariser (a
Pauli-twirled Bell pair is still a Bell pair) but are the ONLY thing separating
intercept-resend from a kept share, which the two correlators cannot do at any sample size.

### `[D]` The optimal recipient forger is deterministic, so D6 check (b) needs a knob

*decision · phase3-forgery · 2026-08-31T21:34:22Z*

The optimal recipient forger declares his own raw log and nothing else, and that
declaration is a DETERMINISTIC function of his RecipientView. Checked position by
position: on a swapped position Charlie holds Bob's own raw entry, so declaring it
is right by construction; on a retained position, declaring his measured basis b_i
gives P(match | scored) = 2/3, while declaring any other basis gives 1/2, and
flipping the eigenvalue is strictly worse than not. So there is no randomised
strategy that ties, let alone beats, the pure one - which matches the POVM argument
in analysis.py section 3b and the earlier scratch exploration of the 1/3 bound.

Consequence for the D6 machinery: check (b) of check_attack_isolation ("vary the
attack's own rng, decisions must move") CANNOT pass for the adversary whose rate we
actually want to publish. That is not a defect in him and not a defect in the check;
isolation.py already says a deterministic-by-construction candidate needs a different
argument. What I did rather than fake it:

  * RecipientForger takes guess_probability (default 0.0). A positive value replaces
    that fraction of positions with independent draws from his own generator. It is
    strictly suboptimal - it walks the mismatch rate from 1/12 towards 1/2 - and it
    exists only so the candidate is visible to check (b) through the same __call__.
  * tests/test_attack_forgery.py runs assert_attack_isolated on
    partial(RecipientForger, guess_probability=0.25), and separately asserts the
    STRONGER property for the default forger: check_attack_isolation reports
    reads_the_session False, offending_session_seeds (), distinct_decisions 1.

The integrator must NOT wire the bare class through assert_attack_isolated - it will
fail check (b), correctly and unhelpfully. Wire the partial, or give isolation.py a
documented "deterministic candidate" mode that asserts (a) alone and requires the
caller to state why (b) is inapplicable. I did not add that mode: isolation.py is
another agent's file and the workaround is one functools.partial.

### `[+]` Kept GHZ share CHSH is 1.4142, not 2.0000; other three references confirmed

*fix · attack-agent:channel · 2026-08-31T21:34:40Z*

The four CHSH figures a previous auditor recorded, checked at 8000 check rounds per arm
with 99% intervals (measure_chsh in sih141/attacks/channel.py):

  ideal                      2.8410 [2.7599, 2.9221]  pred 2.8284  CONFIRMED
  depolarising p=0.3         1.9510 [1.8504, 2.0516]  pred 1.9799  CONFIRMED
  intercept-resend (X/Y/Z)   0.9120 [0.7998, 1.0242]  pred 0.9428  CONFIRMED as noise
                                                                   around 0.9428; the
                                                                   auditor's 1.0020 also
                                                                   sits inside this
                                                                   interval, so it was a
                                                                   fluctuation, not a
                                                                   different quantity.
  kept GHZ share (Z axis)    1.3950 [1.2951, 1.4949]  pred 1.4142  CORRECTED from 2.0000

The kept-share correction. The marginal of (|000> + |111>)/sqrt(2) on Alice's and the
recipient's qubits is (|00><00| + |11><11|)/2, whose only surviving correlator is T_zz = 1,
so S = sqrt(2) * (T_zz + T_xx) = sqrt(2) = 1.4142. 2.0000 is CLASSICAL_CHSH_BOUND -- what a
separable resource cannot EXCEED -- and is also exactly depolarising_chsh(1 - 1/sqrt(2)),
so the two are easy to transpose. The measured interval excludes 2.0.

This matters operationally, not just for tidiness. A Phase 4 detector thresholding at "does
this link still violate the classical bound" has 0.59 of margin against a kept share, not
0.00. Recording it as 2.0000 would have made the attack look like the single hardest case
for the Bell arm when it is comfortably inside its reach.

Also recorded: the QBER a kept GHZ share produces is 1/3, IDENTICAL to intercept-resend's,
and identical whether Eve fixes her axis or draws it. Measured 0.33325 [0.31982, 0.34696]
for the Z-only kept share and 0.33013 [0.31673, 0.34380] for the random-axis one.

### `[*]` Recipient forgery doubles Charlie's matched count - the cheapest Phase 4 signal

*finding · phase3-forgery · 2026-08-31T21:43:59Z*

Measured, and this is the signal Phase 4 should build on first.

A recipient forgery does not only raise Charlie's mismatch rate - it DOUBLES his
matched count, and the matched count is cheaper, tighter and available without
comparing two declarations.

  arm                          |M_C|/L        r_C
  honest                       1/3            ~0 (ideal channel)
  outside forger (L=30, 2000)  0.33192        0.49676  CI [0.48982, 0.50371]
  recipient forger (L=60, 800) 0.66779        0.08239  CI [0.07943, 0.08545]

Why the inflation happens: the forger declares his own raw log, so on the ~half
of positions the exchange swapped, the basis he declares is exactly the basis
Charlie now holds - those positions are matched with certainty. Scored fraction
goes 1/3 -> (n+1)/2n = 2/3, which is params.forger_scored_fraction, and it is
per-position, so it holds at every L including 115200.

Both quantities are reachable from SessionTranscript with no extra plumbing:
VerificationResult carries matched_count and rate for each verifier. The matched
count is the better detector because it separates a forgery from CHANNEL NOISE:
a depolarising channel raises r_C but cannot move |M_C|, which depends only on
the basis draws. A detector thresholding on r_C alone would confuse a forging
recipient with a noisy link; one that also reads |M_C|/L would not.

What is NOT cheaply reachable: "Bob forwarded something different" is visible in
the transcript only because the harness holds BOTH declarations
(forwarded_signature vs signature). In deployment no single party holds both, so
that signal costs a dispute in which Bob's copy and Charlie's copy are compared.
Do not build a Phase 4 detector on it and call it passive.

Also measured: with the shipped Phase C' in force, the forwarded forgery produces
no verdict at all (COUNTS_FROM_TWO_DECLARATIONS) on 50/50 runs. That is a denial
of transfer, not a detection - Charlie learns two numbers disagree about their
provenance and nothing about the signature - and measure_recipient_forgery
reports it in no_verdict, never in the rejection count, for exactly that reason.

### `[*]` Replay measurements: (a),(b),(d) hold; forgery_probability predicts the undefended cross-session rate

*finding · phase3-replay-adversary · 2026-08-31T21:57:19Z*

All four replay attacks measured, defence enabled and disabled. Numbers first,
then the two that matter.

(a) Straight re-verification, L=24, 400 trials per arm.
    undefended 400/400 accepted a second time; defended 0/400, all 400 refused
    as RECORD_ALREADY_VERIFIED. The defence is total, and the refusal is a
    no-verdict rather than a rejection, which is the right shape.

(b) Cross-session pairing (run A's declaration, run B's records).
    defended: 0/400 at Bob and 0/400 at Charlie, every trial SESSION_MISMATCH,
    refused before a single position is counted.
    undefended: refused by nothing, decided by arithmetic alone, and the
    arithmetic is EXACTLY the outside forger's -- an unrelated key agrees at 1/2
    per matched position, so analysis.forgery_probability is the prediction:
      L=12 Bob    1307/12000 = 0.1089   predicted 0.10445   z = +1.60
      L=24 Bob      41/3000  = 0.01367  predicted 0.012520  CI [0.0101,0.0185]
      L=24 Charlie  40/3000  = 0.01333  predicted 0.012520  CI [0.0098,0.0181]
    Agreement at three points, two key lengths and both thresholds. The refusal
    rate at L=12 was 0.7%, which is (2/3)^12 = 0.77%, i.e. P(|M|=0) -- an
    independent check that the matched-count law is Bin(L,1/3) as assumed.
    Scaling: the closed form carries to L=115200 where forgery_bound underflows
    to 0.0, so the undefended acceptance is astronomically small there anyway --
    but the DEFENDED result is a rule, not a rate, and 0/400 at L=24 is the same
    0 at any L.

    A caution for whoever writes this up: the first L=12 batch alone came in at
    353/3000 = 0.1177, which is +2.4 sigma and OUTSIDE its own Wilson interval
    relative to the prediction. Three further independent batches pooled to
    z = +0.48. It was a high draw, not a disagreement. Do not publish a single
    3000-trial batch at L=12 as evidence either way.

(c) Ledger. Poisoning from outside is impossible: 0/400 over three routes
    (declaration naming another round, counterpart count below the floor, and
    the other verifier's record handed to this ledger), and a 50-presentation
    stream of wrong-round declarations left len(ledger) == 0. Storage is bounded
    by verdicts, so exhaustion is bounded by rounds the signer actually ran.
    The DENIAL OF SERVICE is the finding and has its own journal entry.

(d) Identifier. A signer reusing an opening gets two rounds under one
    identifier; the migration she buys is worth exactly the outside forger's
    rate (14/1000 = 0.0140 at L=24 against a prediction of 0.01252) and it costs
    her the second round outright: 400/400 of the honest second declarations
    were refused as RECORD_ALREADY_VERIFIED. Forging an identifier is a 128-bit
    preimage; 0/500000 attempts, which bounds the per-attempt rate at 7.4e-6 by
    Wilson against an analytic 2**-128 = 2.9e-39. The encoding resisted every
    delimiter-shifting pair I could build (test_identifier_encoding_resists_
    delimiter_shifting), which is what the length prefixes are for.

Two things Phase 4 should know it CANNOT see. First, at the moment Charlie
decides, nothing in his own holdings distinguishes "Alice forged" from "the hop
forged": both give him a rejection at rate ~1/2. The distinguishing signal is
the PAIR of rates -- Bob accepted at ~0 while Charlie rejected at ~1/2 -- and
that needs the two verifiers to compare, which is a protocol step that does not
exist. Second, a replay is invisible in a single transcript by construction: the
ledger refuses it, so the transcript of the replayed presentation is a refusal
with no record of what was presented. A Phase 4 detector wanting replay
statistics has to read ConsumedRecords.spent_rounds() across rounds, not the
transcript of one.

### `[D]` Phase C' ordering is a parameter now, and the shipped forgery rate is measurable

*decision · phase3-integrator · 2026-08-31T23:13:33Z*

The shipped QDSSession ran exchange_counts() lazily inside verify(Party.BOB), so both
matched counts were taken against the declaration Alice SIGNED, before the Bob-to-Charlie
hop existed. Two agents hit the same wall from opposite directions and neither could get
past it:

- the forgery agent could not measure the recipient-forgery rate of the shipped protocol at
  all. Charlie's own count named one declaration while he was scoring another, so he
  aborted on COUNTS_FROM_TWO_DECLARATIONS instead of scoring: 50/50 runs, no verdict. Every
  published recipient-forgery figure therefore came from the pre-pooled arm
  (no_count_exchange), and the module said so honestly.
- the replay agent found that the same ordering is the ONLY thing closing the ledger's
  denial-of-service surface, and that it closes it by accident: a component built for the
  pooled floor happens to run before the hop.

WHY THAT IS AN API DEFECT AND NOT A PROTOCOL BUG. The seams could not express the
deployment reading of Phase C' -- each recipient counting against the declaration he
actually holds -- and the natural reading is the only one available when the hop and the
count exchange are separated in time or share a link. So the package could measure one
experiment and had no way to name, let alone measure, the other.

FIX: count_exchange_timing, a keyword on QDSSession, values COUNTS_BEFORE_FORWARDING
(default, shipped, unchanged) and COUNTS_AFTER_FORWARDING. Plus a public forward() that
performs the hop without verifying at the far end -- transfer() now delegates to it and it
is idempotent, because an adversary offered the forwarder seam twice would get two chances
to substitute.

THE MODELLING DECISION, which took three attempts to get right. Under after-forwarding BOTH
recipients count against the declaration that reached Charlie, not one each against what
each received. Reasoning: the provenance check is defeated exactly when the adversary
controls both the declaration delivered to the victim and the count message delivered to
the victim, and on the Bob-to-Charlie hop in a deployment those are one link. So the
adversary announces a count against what he is passing on, provenance agrees, and Charlie
scores the forgery on its merits.

The asymmetry that produces is deliberate: Bob is then counting a declaration he is not
scoring, so his own provenance check refuses. That is correct. A party cannot both announce
a count against D' and reach a verdict on D, and a real forging Bob does not try -- he has
nothing to gain from his own verdict and everything to gain from Charlie's. His refusal is
recorded as a refusal, never as a rejection.

Two earlier attempts, both rejected:
1. Bob counts what he received, Charlie counts what he received. Models a third party on
   the wire, not a forging Bob; digests differ, exchange_matched_counts raises, and the run
   crashes instead of producing a refusal. I added split-count machinery to handle that and
   then deleted it -- see below.
2. Each verifier's counterpart count re-bound to the declaration HE scores. Makes the
   provenance check unconditionally vacuous under that timing, which overstates the
   adversary.

DEAD END WORTH RECORDING: I built a _split_counts path on the session so that two
recipients holding two declarations would each be handed the counterpart's message as sent
and refuse it themselves rather than crashing. Once the modelling above settled, the
session can never construct that state (both messages are built against one declaration),
so the path was dead code and was removed. The public capability it needed survives as
tally.counterpart_count(message), which is genuinely useful to anyone driving verify()
directly -- the replay agent's harness needed exactly it -- and is documented as the way to
turn "the recipients could not pool" from a ValueError into the verdict-free refusal the
protocol specifies.

MEASURED, and this is the point of the whole change. L=60, 300 sessions, RecipientForger on
the forwarder seam, shipped pooled rule in force:
  after-forwarding:  Charlie scores 300/300, accepts 105/300 = 0.350
                     against recipient_forgery_probability(L=60) = 0.345566, z = +0.16
                     mismatch 1008/12004 = 0.08397 against the 1/12 floor, z = +0.25
                     scored fraction 0.6669 against 2/3
  before-forwarding: Charlie scores 0/300. No verdict, every run.
On an honest run the two orderings are identical position for position -- records,
signature, verdicts, pooled count, spent rounds -- which is asserted, because an ordering
that changed an honest run would be changing the protocol rather than naming an experiment.

### `[D]` Deterministic adversaries: a written waiver, and the sibling row that makes it sound

*decision · phase3-integrator · 2026-08-31T23:13:57Z*

Three of the five attack agents hit the same wall: check (b) of the isolation contract --
"vary the adversary's own generator and its decisions must move" -- cannot be satisfied by
an adversary that is deterministic BY CONSTRUCTION.

The cases, and they are not the same shape:
- the optimal recipient forger declares his own raw log, which strictly dominates every
  randomised alternative at every position (a swapped position matches with certainty; a
  retained one gives P(match|scored) = 2/3 against 1/2 for anything else; flipping the
  eigenvalue is worse). He has nothing to draw. This is the adversary whose rate we publish.
- the obvious depolarising channel returns the Werner state and consumes no randomness.
- a count starver whose declaration is a fixed function of the counterpart's count.

check (b) is NOT optional -- without it, check (a) passes vacuously, because a constant is
independent of everything. So the answer cannot be "skip it".

DECISION: a documented three-response ladder in isolation.py (:ref:`deterministic-mode`),
in order of preference.

1. Realise the adversary as a SAMPLED PROCESS where the physics allows. A per-round Pauli
   twirl has exactly the depolarising ensemble and is a function of the adversary's own
   stream, so (b) applies unchanged. The channel agent had already found this independently
   and it is now written down centrally. Worth knowing: the two realisations are NOT
   observationally equivalent to a channel monitor -- the sampled twirl leaves purity and
   concurrence pinned at 1.0 with fidelity flipping 1/0, where the averaged Werner state
   would report a constant fidelity of 1-3p/4 on every round, which is a louder and
   fictional signal.
2. Check a RANDOMISED SIBLING sharing the call path: guess_probability on the forger,
   jitter on the starver. Strictly suboptimal, so no published rate may be measured with
   it, but it exercises the identical __call__ and therefore demonstrates that THAT code
   draws from the generator it was handed.
3. WAIVE (b) IN WRITING: deterministic="..." on check_attack_isolation and
   assert_attack_isolated.

WHY THE WAIVER IS A STRING AND NOT A BOOL, and why 40 characters. A bool would switch off
half the check and leave no reason in the report. MIN_JUSTIFICATION = 40 is about one
clause, and is deliberately not satisfiable by "n/a" or "deterministic": the caller has to
write down why the adversary has no randomness, and that sentence is what the next reader
audits, because it is the argument REPLACING the check. Passing True raises TypeError with
"it is not a flag" in the message.

WHAT THE WAIVER DOES NOT DO. Check (a) still runs and still raises. Both halves still run
and both are still reported; the only thing that changes is that IsolationReport.isolated
stops requiring (b). summary() prints "ISOLATED (check (b) waived)" plus the justification
on its own line, so nobody can read the verdict without the caveat. Pinned by a test that
feeds SessionSeedForger a waiver and asserts it is still caught.

THE STRUCTURAL GUARD, which matters more than the mode itself. A waiver on its own says
"this candidate made the same choice five times", which is EQUALLY CONSISTENT with a
candidate that quietly derived that one choice from the session -- exactly the defect the
check exists for. So the waiver is only sound alongside response 2, and
tests/test_phase3_isolation_suite.py::test_every_waiver_has_a_randomised_sibling fails if a
waived adversary has no randomised row in the table. That is enforcement, not documentation.

Also added: the (b) failure message now names the escape hatch AND warns when it is not the
right answer ("if the candidate HAS randomness and (b) fails, that is a broken probe"), so
the next author does not reach for the waiver to paper over a probe bug.

RESULT: 14 adversary-and-seam pairs, one waiver, and it is the one the theory says must be
there. No adversary failed check (a), so no published rate changed on this account.

### `[*]` The ledger's DoS surface is not zero, and the two obvious repairs are worse

*finding · phase3-integrator · 2026-08-31T23:14:23Z*

verify.py's :ref:`replay` section priced the ledger's residual denial-of-service surface at
zero, by this reasoning:

  "Entries are spent only when a verdict is actually reached; a refusal spends nothing, so
   an adversary cannot poison a verifier's ledger from outside: the only way to add an entry
   is to make that verifier reach the verdict he was entitled to reach. Under the standing
   authentication assumption the one party who can spend a round on a declaration that will
   be REJECTED is the signer herself, and a signer who wants to deny service can simply
   decline to sign."

The first sentence is true and the replay agent measured it: 0/400 poisoning attempts over
three routes, and 50 wrong-round presentations left len(ledger) == 0.

THE INFERENCE IS FALSE. Making a verifier reach a verdict is not the same as being the
signer. Phase B reveals the round's opening ON the declaration, and the identifier
deliberately does not cover the declared key (so that a forgery is scored rather than
refused -- that part is right and must stay). So anyone downstream of that reveal can mint a
DIFFERENT declaration naming the SAME round. The Bob-to-Charlie hop is exactly where the
threat model puts an adversary and is not covered by the classical-authentication
assumption. He hands Charlie a forged-but-correctly-named declaration; Charlie scores it,
REJECTS it, and a rejection is a verdict, so the round is spent. Alice's genuine declaration
is then refused as RECORD_ALREADY_VERIFIED, permanently. Measured 300/300 at L=24 and
100/100 at L=96.

WHAT ACTUALLY CLOSES IT is neither the ledger nor the round binding. It is the provenance
half of the count exchange, and only under one ordering. Measured across all three:
  no_count_exchange                       300/300 burned
  counts as received (after-forwarding)   300/300 burned
  counts as signed (before-forwarding)      0/300 burned
So the shipped default closes it -- as a side effect of when the step runs.

TWO REPAIRS CONSIDERED AND REJECTED, and I want the reasoning on record because both look
obviously right for about ten seconds.

1. SPEND ONLY ON AN ACCEPTANCE. Then a rejected declaration can be re-presented, and
   re-presenting the same pair is harmless because verify() is deterministic in
   (declaration, record). But it is not the same pair that gets re-presented. An ADAPTIVE
   adversary presents a declaration, sees the rejection, edits one position, and presents
   again -- unlimited tries against one round, and he can walk the matched set. That turns a
   bounded forgery probability into a search. Strictly worse than the DoS it fixes.
2. KEY THE LEDGER ON (session_id, message_bit, declaration_digest). Same thing, more
   directly: every distinct declaration gets its own shot at the round.

One shot per round is the property worth keeping. WHERE the shot is taken is what
authentication buys, and that is the honest pricing:

  the residual denial-of-service surface is one burned round per verifier per presentation
  channel the adversary controls, and it is closed only when every channel that can present
  a declaration to a verifier is authenticated, OR the count exchange runs ahead of the hop.

verify.py now says that, under a new :ref:`ledger-denial` anchor, with the measurements and
both rejected repairs. No code changed: the spend rule is right.

Two smaller prose corrections landed in the same pass, both for the same reason -- a Phase 3
measurement contradicted a shipped claim:

- session.py ChannelSample.wings_agree was documented as "the signature of something that
  acted on ONE leg, which is the shape of an eavesdropper on the wire". True for a damping
  or replacement channel (its own worked example is a split product state), MISLEADING for
  eavesdropping on a Bell-pair link: no trace-preserving map on one half of a maximally
  entangled pair can change only that half's marginal, so all three channel adversaries act
  on one leg and leave wings_agree True on every round. Zero detection power against that
  family. The docstring now says so and names what does see them (fidelity, concurrence,
  purity for a kept share, and above all the per-link check QBER).

- analysis.py's (AUTH) section quoted "0/60 accepted, at QBER = 0.4987 (Bob) and 0.4806
  (Charlie)". The acceptance count reproduces; 0.4806 does not, and could not have -- no key
  length, no n, and no statement of whether the rate was pooled over positions or averaged
  over runs. At any plausible L the pooled sd over 60 runs is at most 0.0144, putting 0.4806
  about 1.3 sd low while quoted to four figures. Replaced with the four-row L=192 / n=200
  table from impersonation.MEASURED, whose rows carry their own counts and re-check their
  own arithmetic at import. Replaced rather than corrected: the defect was the missing
  conditions, not the digits.

### `[*]` The p=0.5 QBER disagreement was a high draw, settled by n and not by seeds

*finding · phase3-integrator · 2026-08-31T23:14:49Z*

One measurement in the Phase 3 attack tables was flagged agrees=false: the channel agent's
depolarising QBER at p = 0.5 came in at 0.2635 on 8000 rounds against an exact prediction of
0.2500, with a 99% Wilson interval of [0.25101, 0.27638] that EXCLUDES the prediction. The
agent re-ran at four further seeds, all covering, and read it as a 2.8 sigma fluctuation.

That reasoning is right but the evidence was the wrong shape, because "I ran it again with
other seeds and it was fine" is indistinguishable from seed-shopping to a reader who was not
there. The question is whether the SAMPLER is biased, and that is settled by sample size, not
by a different seed: a bias survives a large increase in n and a fluctuation does not.

WHAT I DID. Pooled 25 independent batches of 8000 rounds each -- 200,000 rounds, 25x the
batch that missed -- and looked at both the pooled z-score and the per-batch coverage rate.

  pooled:      49800/200000 = 0.249000 against 0.250000, z = -1.03
  per-batch:   25/25 of the 99% intervals cover the prediction (expected ~24.75)
  batch rates: 0.247 0.25462 0.24225 0.25675 0.25775 0.245 0.25438 0.24413 0.25588 0.2505
               0.251 0.25562 0.24225 0.24388 0.25012 0.25688 0.24525 0.253 0.24088 0.2405
               0.25212 0.243 0.24763 0.24638 0.24825

VERDICT: the formula is right and the measurement was a high draw. Note the closed form is
not an approximation to be checked -- qber_from_tensor(depolarising_tensor(p)) == p/2 holds
identically, and the identity is separately pinned against the protocol's own
analysis.depolarising_error_rate to 1e-12 across p. There was never a formula to be wrong;
the only live question was the sampler, and it is unbiased.

CONTEXT that makes the original miss unsurprising rather than alarming: the channel module
makes twelve comparisons at 99% in one run, so the expected number of misses is 0.12 and
seeing one has probability about 11%. Nothing was wrong.

PINNED: tests/test_phase3_integration.py::test_the_depolarising_sampler_is_unbiased_at_p_
equals_one_half runs 10 batches (80,000 rounds) at a 3-sigma band and asserts |z| < 3. Ten
batches rather than 25 for runtime; 80,000 rounds still gives a standard error of 0.00153,
so a bias of the size the original batch would have implied (+0.0135) would show at nearly
9 sigma.

I did NOT loosen any tolerance and did NOT change any seed to make this pass, because either
would have hidden the question rather than answered it. The tolerance mechanism used
throughout the integration suite is derived instead: agrees_within() computes its band as
4 * sqrt(p(1-p)/n) at the PREDICTED p, so the band shrinks as the sample grows and cannot be
widened by an author who dislikes a result.

The other flagged disagreement in the tables -- the forging recipient under the shipped
pooled rule, reported as agrees=false with "none available" as its prediction -- was never a
numerical disagreement. It was the Phase C' ordering gap, and it is now measured and agrees
(see the separate entry on count_exchange_timing).

### `[-]` Seam friction: what was fixed, and what was declined and why

*note · phase3-integrator · 2026-08-31T23:17:13Z*

Every seam-friction item the five attack agents reported, and what happened to it.

FIXED
1. isolation.py had no mode for a deterministic-by-construction adversary; three agents hit
   it. Fixed with a documented waiver requiring a written justification plus a randomised
   sibling row. Separate entry.
2. No Forwarder-seam probe existed, so two agents wrote one privately. isolation.py now
   ships forwarder_probe(scenario, *, party, matched_count), which calls the candidate the
   way transfer() does -- reading the arity off its signature with the same helper the
   session uses, so a probe pass and a session run exercise one code path.
3. Four private copies of the Wilson interval, two carrying the same float-dust bug (the
   closed form returns ~1.7e-18 rather than 0.0 at zero successes, and EVERY defended
   result in this suite is 0/N). New sih141/attacks/statistics.py holds the arithmetic once,
   clamped exactly by case at both ends; the four public wilson_interval functions keep
   their own signatures and delegate. Also there: agrees_within(), whose band is
   4*sqrt(p(1-p)/n) at the PREDICTED p -- the tolerance mechanism the integration suite uses
   so that no Phase 3 tolerance is a number somebody liked the look of.
4. Two private helpers reached for from outside their modules -- session._forwarder_wants_
   view (imported by a test) and distribute._accepts_context (imported by a test and by an
   attack). Both promoted to public names, both privates kept as aliases so nothing that
   already imports them breaks. Which shape a seam has is part of the seam's contract.
5. The Phase C' ordering gap. Separate entry.
6. Three prose claims contradicted by measurement (verify.py's DoS pricing, session.py's
   wings_agree, analysis.py's (AUTH) figures). Separate entry.
7. Two Phase 4 blockers closed by new transcript fields: spent_rounds (each verifier's
   ledger, previously readable only off an object the verifier holds) and replay_refusals
   (a refused re-presentation previously left NO trace, because filing it as the verifier's
   outcome would let a replay delete the acceptance that spent the round -- so it is counted
   beside the verdict instead of in place of it).
8. The two probe traps that report a flawless attack as a cheat -- a distributor probe
   returning the seam's output rather than the adversary's decision, and a payload_map probe
   run with check_fraction > 0 -- are now documented centrally in isolation.py under
   :ref:`probe-traps`, with the rule both are instances of: everything the adversary
   legitimately observes, INCLUDING the set of occasions on which it is consulted, must be
   identical across probe calls.

DECLINED, with reasons.
9. "A suite-wide probe registry beside signer_probe." Declined beyond forwarder_probe. The
   distributor, count_exchange and payload probes are not generic: distributor_probe must
   return the KEY the adversary substituted (a generic one returning the records fails check
   (a) honestly), starvation_probe freezes two synthetic MatchedCountMessages rather than
   running a session, and a payload probe needs check_fraction pinned to zero. Each is a
   statement about its own adversary, and hoisting them would produce four functions with
   one caller each and a false suggestion that any of them is reusable. The rule that IS
   general is now documented instead.
10. "Widen the Signer seam's keys annotation to accept an empty tuple." Declined. The
    impersonation agent widened its own annotation, which is the right place: the seam's
    contract is that Alice's committed pair is offered, and an adversary ignoring it is not
    a reason to weaken what the session promises to pass.
11. "Change the ledger's spend rule so a rejection does not burn a round." Declined, and
    this one matters: it would give an adaptive adversary unlimited tries at one round --
    present, see the rejection, edit one position, present again -- turning a bounded
    forgery probability into a search. Keying the ledger on the declaration digest as well
    does the same thing more directly. One shot per round is the property worth keeping;
    where the shot is taken is what authentication buys, and that is now the documented
    pricing.
12. "The seams cannot express a cross-round replay, because _bind_to_round overwrites the
    opening." Declined as a change. It is deliberate and load-bearing: without it every
    forgery would abort as SESSION_MISMATCH and the forgery table would empty into the
    no-verdict column. The consequence an integrator must know -- that a transcript of
    ReplayingForwarder shows an ALTERED FORWARDING, not a replay -- is documented in
    docs/PHASE3.md and pinned by the replay module's own test.
13. "Drop the arity assertion that imports a protocol private." Superseded by fix 4; the
    import is now of a public name and the assertion can stay.
14. Cross-run per-party history (starvation) and adversary ground truth (channel,
    starvation). Not reachable and should not be: a transcript is one run, and an
    adversary's own log is not evidence a detector may read. Stated in docs/PHASE3.md with
    what Phase 4 must do instead -- keep its own ledger keyed by party, and score its
    false-positive rate against a labelled harness.

### `[*]` Check-round estimate is steerable: payload_map and channel_monitor leak the check set to the channel adversary

*finding · phase3-auditor-replay-and-checkrounds · 2026-09-01T00:00:21Z*

The load-bearing invariant of sih141/protocol/checkrounds.py is stated in
sih141/protocol/distribute.py as "The factory is the whole of the adversary's
access to this loop, so it sees one undifferentiated stream of requests", and
pinned by test_the_factory_cannot_tell_a_check_round_from_a_key_round. The test
exercises resource_factory ALONE. The declared adversary is not alone.

session.py's own threat model says: "A channel adversary owns the quantum links
and the payload line: any entanglement resource he likes per hop
(resource_factory), and any substitution he likes on the state Alice sends
(payload_map)." payload_map is called on KEY ROUNDS ONLY. So the positions on
which the same adversary is *not* consulted are exactly the check positions, and
context.position is handed to him, so the gaps are legible. Measured: the check
set is recovered exactly (24/24, 120/120) from the payload-map call pattern
alone, for both message bits.

Two things make it exploitable rather than merely observable:
  1. distribute_public_key_with_checks runs Bob's whole pass before Charlie's
     first hop (verified: Bob's last factory call index 95, Charlie's first 96),
     and both links execute the SAME plan.
  2. channel_monitor is invoked on check rounds only, which recovers the same
     set with no Alice-side seam involved at all (120/120).

Exploit, at L=480, check_fraction=1/4, Werner p=0.9 on Charlie's link, with the
key hops treated bit-identically in both arms (real key mismatch 0.223140 in
both, exact equality):
    naive             published QBER 0.4667  [0.2565, 0.6768]  S = 0.439
    spare the watched published QBER 0.0000  [0.0000, 0.2101]  S = 2.673
Same delivered channel, same wrecked key, and the published estimate is entirely
under the adversary's control.

As a subclass of the SHIPPED sih141.attacks.channel.DepolarisingChannel (which
already exposes attack.resource and attack.payload on one object, exactly as
docs/PHASE3.md section 4 prescribes), six lines, L=1200, p=0.4 on Charlie:
    shipped attack    published QBER 0.2400  S = 1.237
    selective         published QBER 0.0000  S = 2.007

The facts were half-known: docs/PHASE3.md section 7 records "a payload_map probe
must run with check_fraction = 0" because the set of occasions the adversary is
consulted moves with the seed, and it even states the general rule -- "everything
the adversary legitimately observes, INCLUDING the set of occasions on which it
is consulted, must be identical across probe calls". That rule was applied to
probe hygiene and never to the adversary. Nobody turned it around.

Every channel number Phase 4 will key a detector off is a number a channel
adversary can set to whatever he likes.

### `[*]` Ledger DoS survives the shipped count ordering when the adversary owns the count link too

*finding · phase3-auditor-replay-and-checkrounds · 2026-09-01T00:00:38Z*

verify.py's :ref:`ledger-denial` prices the residual DoS as "closed only when
every channel that can present a declaration to a verifier is authenticated, OR
the count exchange runs ahead of the hop", and reports before-forwarding at
0/300. I reproduce 0/40 for a hop-only adversary -- the "or" clause is true only
against an adversary restricted to the declaration link.

The threat model's classical-link adversary "sees and may alter the classical
messages", and session.py's own COUNTS_AFTER_FORWARDING docstring argues that
"in a deployment they are the same link". Give him both, under the SHIPPED
before-forwarding default: he picks his substitute declaration before Phase C'
and returns a PooledMatchedCounts whose declaration_digest is the substitute's.
Charlie's provenance check then compares like with like, passes, Charlie scores
the substitute, rejects it, and a rejection is a verdict, so the round burns.
Measured 40/40 at L=96. Alice's genuine declaration re-presented to Charlie
afterwards: records-already-verified, permanently.

Residual detectability: Bob still refuses with counts-from-two-declarations, so
the run is not silent. But Charlie's transcript records a REJECTION (rate 1.0)
of a round Alice signed honestly, which is exactly the transferability failure
signature a repudiating Alice would produce -- the adversary frames Alice.

Separately, and inconsistent with the same file: session.py's
COUNTS_AFTER_FORWARDING bullet 1 claims a third party on the hop means "Neither
verifier reaches a verdict, and a refusal spends no round." Measured over 20
runs: 20 verdicts (Charlie rejects every time), Charlie's round burned 20/20,
Bob refusing on counts-from-two-declarations. The mechanism in that bullet is
inverted -- _declaration_counted() returns the FORWARDED declaration for BOTH
recipients under this timing, so it is Bob's count that names the substitute and
Charlie's that matches what he scores. The ledger-denial section's own
"after-forwarding 300/300" is the correct number; the two passages contradict
each other and a reader who stops at the first is misled.

Everything else in the replay defence stood up: forged/relabelled identifiers
refuse (session-identifier-mismatch), cross-run pairing refuses, the record is
the anchor, refusals spend nothing, and the identically-seeded-collision caveat
is real and correctly documented.

### `[-]` Audited and sound: effective-length propagation, retained-key uniformity; plus sift_record drops the symmetrised bit

*note · phase3-auditor-replay-and-checkrounds · 2026-09-01T00:00:56Z*

Audited as an adversary and could not break these; recording so the next agent
does not re-derive them.

EFFECTIVE KEY LENGTH. Every floor and bound on the shipped path is computed from
signing_length, not L. At L=960, check_fraction=1/8 (signing 840):
  m_min      123 (would be 152 from nominal L)
  M_min      338 (would be 402)
  guaranteed_pooled 338 (would be 402)
and all three agree term for term with ProtocolParams(key_length=840).
session._scored_params is params.sifted(); every VerificationResult carries
key_length=840; PooledMatchedCounts.key_length=840; SessionTranscript keeps the
UNSIFTED set but re-derives sifted() before _check_result_against /
_check_abort_against / _check_pooled_against; repudiation_guarantee goes through
params.sifted(). session_identifier is derived at the effective length too.
The documented figures reproduce exactly: DEFAULT 1.4139e-09, CHECKED_PARAMS
(L=131664, signing 115206) 1.4124e-09, and DEFAULT+1/8-checks-without-lengthening
1.8853e-08. The analysis module really is the unsafe one and really is optimistic
unsifted (forgery_bound 1.88e-47 vs 1.30e-41 at this length) -- the warning in
ProtocolParams.sifted is not overstated.

RETAINED KEY IS UNBIASED. plan.sift_key returns the same element OBJECTS
(identity, not equality) in order; the plan is a function of the recipient stream
alone and reproduces identically for two different keys; over 400 keys x 480
positions the retained (basis, eigenvalue) histogram gives chi-square 4.08 on 5
dof against uniform (0.1% critical 20.5); per-position retention over 4000 plans
has sd 0.0051 against a binomial 0.0052, min 0.8600 max 0.8905 around 0.8750.

MINOR BUG, fail-safe. CheckRoundPlan.sift_record rebuilds through
RecipientRecord.from_measurements and therefore silently drops the `symmetrised`
provenance bit: a symmetrised record in, symmetrised=False out. Its docstring
says it exists "for a caller who distributed without a plan and wants to apply
one after the fact", which is precisely the ordering that hits this. Consequence
is a refusal (verify_all declines a raw pair), not a false accept, so it costs an
honest verdict rather than granting a dishonest one -- but it costs it silently.

### `[!]` CRITICAL and OPEN -- the check rounds are steerable by the channel adversary

*issue · audit:phase3:2 · 2026-09-01T00:35:24Z*

STATUS: OPEN. Not fixed in Phase 3. Decision pending with the maintainer.

The check set leaks two independent ways, both measured:
  - payload_map is invoked on KEY ROUNDS ONLY and receives context.position, so the GAPS in
    its call sequence are exactly the check set. Recovered 24/24 at L=96.
  - channel_monitor is invoked on CHECK ROUNDS ONLY, so being called is itself the signal.
    Recovered 120/120 at L=480, with no Alice-side seam involved at all.

Exploitable because distribute_public_key_with_checks finishes Bob's entire pass before
Charlie's first hop, and both links run the SAME plan. The adversary learns the plan on link
one and cheats on link two.

Measured, key hops held bit-identical between arms (L=480, check_fraction=1/4, Werner p=0.9
on Charlie's link):

                        published QBER   published CHSH   REAL key mismatch
    naive                  0.4667            0.439            0.2231
    spare the watched      0.0000            2.673            0.2231

It is a six-line subclass of our own shipped DepolarisingChannel. The invariant asserted in
distribute.py -- that the factory is the whole of the adversary access to the loop -- is
false, and its test drives resource_factory ALONE while the declared adversary also holds
payload_map.

WHY IT IS SERIOUS BUT NOT FATAL: auditor 1 independently established that the VERIFIER RATE
is the strongest and cheapest channel signal and needs no check rounds at all. Channel
attacks are still DETECTED. What is compromised is the published QBER/CHSH FIGURE, which
must not be quoted as a security statistic until this is closed.

FIX DIRECTION: make the check set uninferable -- invoke payload_map and channel_monitor on
EVERY position and discard the irrelevant results, and give the two links independent plans
instead of one shared plan run back to back.

### `[+]` Corrected four published numbers that did not reproduce

*fix · claude · 2026-09-01T00:35:24Z*

STATUS: closed. Each verified by computation before changing it rather than by trusting the
auditor, because propagating an unchecked figure is how the wrong ones got there.

  session.py   105/300 -> 96/300. The stale value came from a working-note draft; the
               shipped code measures 96/300 = 0.3200 at z = -0.93, which docs/PHASE3.md and
               README.md already carried and an independent re-measurement reproduced count
               for count.

  PHASE3.md    7.4e-06 -> 7.7e-06 for the 0/500000 preimage bound. 7.4e-06 is the
               Clopper-Pearson 97.5% one-sided value, -ln(0.025)/n = 7.3778e-06; the suite
               standardised on Wilson, which gives 7.6829e-06. It was quoted TIGHTER than
               the code computes, the unsafe direction for a security bound.

  PHASE3.md    0.0146 -> 0.0145. wilson_bounds(5, 800) returns 0.014547.

  PHASE3.md    The bold claim that the matched counts never move contradicted its own table
               four rows above and the constant MATCHED_IDENTICAL_TRIALS[SIGNING] == 0.
               What is invariant is the count's LAW, which is all the argument needs.

### `[*]` Phase 4 IS buildable -- 4 of 5 adversaries separate at 100%, zero false alarms

*finding · audit:phase3:1 · 2026-09-01T00:35:24Z*

STATUS: closed, no action needed. The most important positive result of the phase.

A threshold-only detector -- no ML, every cut a constant fixed before any attack run --
reading a SessionTranscript ROUND-TRIPPED THROUGH JSON, so it provably cannot touch
attack.decisions(), CountStarver.log, or any harness state.

    honest control                   0/80 flagged  (false-alarm rate zero)
    outside forger                  40/40   via rate
    recipient forger, both orderings 40/40
    impersonation, partial          40/40   via rate
    impersonation, FULL              0/40   NOT SEPARABLE -- the stated (AUTH) assumption
    channel, 3 attacks x 2 links   120/120
    count starver                   40/40   via abort reason
    replay                          40/40 and 60/60

Two design inputs for Phase 4 fell out of it. The verifier RATE is the strongest and
cheapest channel signal and needs no check rounds. And wings_agree is a NON-SIGNAL: no
trace-preserving map on one half of a maximally entangled pair can change only that half's
marginal, so every channel adversary leaves it True on every round. Do not build a detector
on it.

### `[!]` MAJOR and OPEN -- the D6 stream guards compare generator objects, not seeds

*issue · audit:phase3:3 · 2026-09-01T00:35:24Z*

STATUS: OPEN.

forgery._check_streams and replay._distinct_generators both refuse only the identical
generator OBJECT. Two generators built from ONE SEED pass -- precisely the leak isolation.py
exists to prevent, because QDSSession consumes its caller's generator as a single
rng.bytes(32) and derives every stream from that material with a public helper.

impersonation.py and starvation.py carry no guard at all.

Together with the previous entry: the D6 machinery does not enforce what it claims. The
convention held in practice; it is not held by construction.

### `[!]` MAJOR and OPEN -- check (a) of the D6 isolation test is inert on all 14 rows

*issue · audit:phase3:3 · 2026-09-01T00:35:24Z*

STATUS: OPEN.

The PHASE3.md headline result of 14/14 passing check (a) is true and carries NO EVIDENCE,
because no row can fail it. Six probes -- isolation.signer_probe, isolation.forwarder_probe,
forgery.forwarder_probe, impersonation.signing_probe, replay.replay_probe and
starvation.starvation_probe -- execute a del of session_seed, so observing at a varied
session seed changes nothing.

This is the vacuous-test failure mode, in the one test I called the single most important in
Phase 3. The negative controls still work, which is why it looked healthy: SessionSeedForger
is caught by (a) and DeafForger by (b).

MITIGATING FACT, established independently: auditor 3 re-measured 16 published tables with
its own harness written from the docs rather than by importing our tests, and every one
reproduced count for count. So no adversary was in fact reading the session -- the guard
simply would not have caught one that did.

### `[+]` Closed the check-round accounting hole in analysis.py

*fix · claude · 2026-09-01T00:35:24Z*

STATUS: closed.

Confirmed by my own measurement before fixing. Handed a parameter set that reserves check
rounds, analysis.py counted the diverted positions as key: matched_statistics gave 38400
expected matched positions where the truth is 34560, an 11% overcount, and the bounds are
exponential in that count. recipient_forgery_bound read 1.13e-29 where the honest figure is
8.83e-27.

Erring in the FLATTERING direction is the failure mode this project has already shipped
three times, so it is closed at the choke point rather than at twenty call sites where the
twenty-first would be missed: _as_params -- which every public entry point routes through,
verified by AST that none bypasses it -- now returns params.sifted() when check rounds are
reserved. sifted() is idempotent and the identity on an unchecked set, so nothing published
from DEFAULT_PARAMS moves. Pinned by a doctest.

Nothing in the workflow was assigned to this. The check-round agent flagged it in its
integrator notes, but the repair agent receives only the five ATTACK reports -- a gap in my
workflow design, not in any agent's work.

### `[-]` Phase 3 complete -- 14/14 agents, audit verdicts unsound/sound/unsound

*note · claude · 2026-09-01T00:35:24Z*

Suite 1421 -> 2098. Commits 5983c00, ea5ba71, 658f2ff, e36e7b1.

Built: declaration-binding enforcement, attack randomness isolation, RecipientView, replay
defence (session binding + consumed-records ledger), sampled check rounds, channel-monitor
seam, restricted signer seam, payload_map, widened forwarder, and all five adversaries with
measurements.

Two auditors returned unsound; their findings are the next four entries. The third returned
sound and established that Phase 4 is buildable.

### `[+]` Check (a) was inert on all 14 rows; the session now reaches the candidate

*fix · impl:d6-isolation · 2026-09-01T14:35:39Z*

FINDING (audit, confirmed and fixed). Check (a) of the D6 isolation check was
INERT ON ALL FOURTEEN ROWS of tests/test_phase3_isolation_suite.py. The headline
"Result: 14/14 pass check (a)" was true and carried no evidence whatsoever,
because no row could fail.

Mechanism. check_attack_isolation.observe(attack_seed, session_seed) reaches the
candidate by exactly two routes: the builder's optional session_seed= keyword,
and the probe's session_seed argument. Six ready-made probes -- isolation.
signer_probe, isolation.forwarder_probe, forgery.forwarder_probe, impersonation.
signing_probe, replay.replay_probe, starvation.starvation_probe -- opened with
`del session_seed`. No shipped adversary declares session_seed in its
constructor, so _builder_offers_session_seed returned False for every one of
them. The five "different" calls check (a) compares were therefore five runs of
a byte-identical experiment. The channel probes ran a live session per seed, but
ResourceContext carries only (party, message_bit, position) and check-round
lockstep calls the seam identically at every position, so nothing the adversary
could see moved there either.

Why it survived. The two negative controls both read the seed through the
BUILDER, which was the one channel that stayed live. They kept passing, and a
green control on a dead channel reads exactly like a green control on a live one.

FIX. check_attack_isolation.observe now wraps both the build and the probe call
in a SessionEnvironment (sih141/attacks/isolation.py), varied with the session
seed. It opens the three routes a real experiment leaks through:

  1. active_session() -- the check's stand-in for the module-level SEED constant
     every attack script keeps in scope. Published deliberately: a check that
     offers no leak detects no theft.
  2. ambient global randomness -- numpy.random's legacy global stream and
     stdlib random's, seeded from the session seed for the duration of the call
     and restored exactly afterwards (states compared before/after in a test).
     D3 forbids drawing there; an adversary that does is now caught by check (a)
     instead of the rule sitting unenforced in a docstring.
  3. SessionEnvironment.stream_material() -- the session's own rng.bytes(32)
     draw, so a control can rebuild the run precisely as QDSSession does.

Note the routes are open to everyone and cost the honest candidate nothing: an
isolated adversary draws from the generator it was handed, which is what check
(b) varies.

EVIDENCE, per row, which is the part a shared control cannot give. A control
passing through signer_probe() says that probe's channel is live and says
nothing about starvation_probe(), the two channel probes, or a probe added next
year. test_the_session_channel_is_live_on_every_row rebuilds each shipped
adversary with the session's seed folded into its generator -- same class, same
__call__, same probe, one line of defect -- and requires check (a) to catch it.
13/14 caught. The fourteenth is the deterministic recipient forger, whose
decisions move with nothing at all; his randomised sibling is caught, which is
the same argument the (b) waiver already rests on.

NO CASCADE. All fourteen shipped rows still pass with the channel live, on every
seam. No published rate moved on this account.

Two mutation runs, snapshot-and-restore, isolation.py verified byte-identical
afterwards:
  reads_the_session -> False              25 failures (was 6 before this work)
  observe() installs no SessionEnvironment 17 failures -- and BOTH shipped
      negative controls still pass under it, which is the shape of the original
      defect reproduced on demand.

Also fixed in passing: signer_probe's docstring claimed it calls the candidate
"exactly as QDSSession.sign would ... holding the raw pre-exchange logs". The
shipped default is signer_sees_recipient_logs=False, so a live session hands the
seam NO_RECIPIENT_LOGS. The probe is strictly more generous than the protocol,
which is sound for an isolation check (an adversary shown more and still not
moving is isolated a fortiori) but is not the equivalence that was claimed. The
docstring now says which it is and why.

### `[+]` Stream guards compared objects, not seeds; two rngs from one seed now refused

*fix · impl:d6-isolation · 2026-09-01T14:35:40Z*

FINDING (audit, confirmed and fixed). The D6 stream guards compared Python
OBJECTS, not streams, and therefore refused only the form of the mistake nobody
makes.

forgery._check_streams tested `rng is session_rng`. replay._distinct_generators
tested `checked_world is checked_attack`. Both waved through

    SEED = 20260141
    measure_outside_forgery(params, trials=N,
                            rng=np.random.default_rng(SEED),
                            session_rng=np.random.default_rng(SEED))

which is two objects and ONE STREAM: identical bytes for ever. QDSSession
consumes its caller's generator as a single rng.bytes(32) and derives Alice's
stream, the recipients' stream and the binding stream from that material, so an
adversary holding that stream rebuilds the run and predicts every private
symmetrisation coin (120/120, pinned in isolation.py's own docstring). That is
precisely the leak isolation.py exists to prevent, arriving by the shortest
possible route -- and it is the route a real harness takes, because nobody
passes one object twice but everybody writes one SEED constant.

impersonation.py and starvation.py had no guard at all.

FIX. sih141/attacks/isolation.py gained the stream-identity layer:

  stream_fingerprint(rng)  -> (derivation, state). derivation is
      (bit-generator type, seed-sequence entropy, spawn key); state is the bit
      generator's current position.
  same_stream(a, b)        -> same object, OR same position in one stream, OR
      same derivation at any offset. Advancing one does not make it independent.
      parent.spawn(2) children are correctly NOT refused -- that is the one
      right way to split a generator and refusing it would push callers back to
      two default_rng calls on one seed.
  derived_from_seed(rng, seed) -> the seed-shaped half, for the entry points
      that take a session seed for one role and a generator for the other.
  require_distinct_streams(...) -> raises with the mechanism and a named repair.

Rewired: forgery._check_streams, replay._distinct_generators. Added where there
was nothing: impersonation.run_impersonation (against its one session_seed),
impersonation.measure_impersonation (against the WHOLE seed list up front, so a
collision at trial 137 of 200 is reported before any run is spent), and
starvation.measure_starvation (against session_seed_start .. start+trials-1).

No shipped call site was refused by the new guards -- FIRST_SESSION_SEED is
900_000 and session_seed_start defaults to 500_000, both chosen to be far from
any adversary seed in the package, and every doctest and test already used
unrelated seeds. So no measured number moved. What moved is that the property is
now enforced rather than assumed.

CONNECTION TO THE OTHER FINDING. These two are the same leak from opposite ends.
Check (a) asks whether the adversary went and TOOK the session's randomness; the
stream guards ask whether the harness HANDED it over. Neither implies the other,
and until now the first was inert and the second was looking at the wrong thing.

### `[x]` Four wrong ways to make check (a) vary the session seed

*deadend · impl:d6-isolation · 2026-09-01T14:35:45Z*

DEAD ENDS from making check (a) non-vacuous. Recorded because each one looks
right for about ten minutes and the next person will try them in this order.

1. "Run a live QDSSession seeded with session_seed inside signer_probe /
   forwarder_probe." This is the obvious reading of "depend on session_seed the
   way a real run does", and it is the documented probe trap (:ref:`probe-traps`
   in isolation.py) wearing a different hat. A recipient-forger's declaration is
   a function of HIS OWN LOG, which is drawn from the session's stream; give him
   a fresh session per seed and his declaration moves for an entirely honest
   reason, check (a) fails, and the report blames a flawless adversary. The
   frozen scenario is not an accident to be removed -- it is what makes check
   (a) a statement about the adversary instead of about the harness. Freezing
   the OBSERVATIONS and varying the SESSION are two different jobs and a probe
   has to do both; `del session_seed` did neither.

2. "Wrap the candidate in an adapter so a live session CALLS it while it is
   handed the frozen arguments." Costs a full distribution per probe call and
   buys nothing: the candidate's inputs are still constant, so a pure function
   of them is still constant. The only adversary it would catch is one doing
   frame introspection, which is not a threat model anybody has.

3. "Offer session_seed at call time to any seam whose signature declares it,
   mirroring _builder_offers_session_seed." Implemented in spirit and then
   dropped as the PRIMARY route: Signer, Forwarder and CountExchange take no
   such argument in the protocol, no shipped adversary declares one, so it can
   never fire on a shipped row and would have left the check exactly as
   vacuous as it was for the rows that matter. It catches only an adversary
   polite enough to ask for the seed by name.

4. "Just record in IsolationReport that check (a) had no live channel and let
   the reader judge." Honest, and not a fix -- the brief is that the check must
   CHECK, not that it must confess. Kept the honest half: the
   session_seed_offered docstring no longer claims a call-time channel that did
   not exist, because that sentence is what made the vacuity invisible in code
   review.

WHAT ACTUALLY WORKED, and why it is not artificial. The environment publishes
the harness's seed constant. Nothing in the protocol publishes it; the CHECK
publishes it, on purpose, because a check that offers no leak detects no theft
and an adversary that reaches for it has done precisely what D6 forbids. Add the
ambient global streams (which a reproducible harness really does seed from the
same constant, and which D3 already bans drawing from) and the session's own
32-byte material, and every candidate has a route whether or not it declares
one.

The composition is the point and is worth stating separately: check (b) already
proves, per row, that the probe can see the candidate's own stream. So an
adversary whose stream was derived from the session's MUST be visible to check
(a) through that same probe. That turns two assertions into a proof, and it is
what test_the_session_channel_is_live_on_every_row runs. The one row it cannot
cover is the one whose decisions move with nothing at all -- the deterministic
recipient forger -- which is the same fact the (b) waiver rests on, and is why
the waiver is only ever sound beside a randomised sibling.

### `[+]` Ledger DoS now scores its mechanism; every published figure re-measured, none moved

*fix · impl:d6-isolation · 2026-09-01T14:35:45Z*

FINDING (audit, confirmed and fixed). measure_ledger_denial_of_service scored
itself on `not _accepted(honest)` -- the adversary's GOAL, but not his
MECHANISM. The two agree on every healthy trial and come apart on a degenerate
one, which makes a published 0/N a fact about the seed rather than a rule.

The attack burns Charlie's round: the hop mints a declaration naming the live
round, Charlie scores it, rejects it, and a rejection is a verdict, so the round
is spent and the genuine declaration is afterwards refused as
RECORD_ALREADY_VERIFIED. That refusal is the mechanism. "Not accepted" also
covers an honest declaration that was never going to be accepted anyway -- below
L = 140 both matched-count floors degenerate and an honest run can fail on its
own -- and scoring those as burned rounds credits the adversary with something
he did not do.

REPRODUCED, not merely argued. At L = 12, rng=default_rng(1),
attack_rng=default_rng(2), 120 trials, defended=False (no ledger present, so
nothing can be spent and the attack provably achieves nothing that lasts):
three trials end with the honest declaration refused as `empty-matched-set`.
Under the old definition that arm reports 3/120 for an attack that cannot
succeed in it at all. Under the new one it raises, naming trial 47.

FIX. successes now counts _round_already_spent(honest), i.e. exactly
AbortReason.RECORD_ALREADY_VERIFIED. A trial whose honest declaration is neither
accepted nor denied by the ledger is refused outright with a ValueError naming
the trial, the reason and the L: it is neither a success nor a clean failure,
because the attack was not measured in it, and folding it into either column is
how a rate acquires a denominator it does not deserve. refusals still counts
every no-verdict, so successes == refusals exactly when the ledger was the only
thing refusing, and a gap is visible rather than absorbed.

RE-MEASURED. Every published figure re-run under both definitions, L = 24 with
300 trials and L = 96 with 100, rng=default_rng(20260141),
attack_rng=default_rng(4242), all three count orderings x defended/undefended:

  L=24  defended  counts=none         old 300/300  new 300/300
  L=24  defended  counts=as-received  old 300/300  new 300/300
  L=24  defended  counts=as-signed    old   0/300  new   0/300
  L=24  undefended, all three orderings old 0/300  new   0/300
  L=96  defended  counts=none         old 100/100  new 100/100
  L=96  defended  counts=as-received  old 100/100  new 100/100
  L=96  defended  counts=as-signed    old   0/100  new   0/100
  L=96  undefended, all three orderings old 0/100  new   0/100

No degenerate trial occurred at either length ("other={}" on every arm), so
NOTHING MOVED. docs/PHASE3.md's 300/300 and 0/300 stand as published. What
changed is that they are now rules: the 0/300 at counts-as-signed is zero
because nothing was spent, and a trial that could have made it non-zero for an
unrelated reason now stops the measurement instead of contributing to it.

### `[+]` Close the check-set inference channel: seams called everywhere, links dealt apart

*fix · impl:uninferable-check-set · 2026-09-01T14:45:36Z*

MEASURED, BEFORE THE FIX. The channel-side adversary recovered the check set
exactly, by two independent routes, on the shipped code:

  * payload_map was invoked on key rounds only and handed context.position, so
    the GAPS in its call sequence were the check set. Recovered 24/24 at L=96,
    check_fraction=1/4, for both recipients and both message bits.
  * channel_monitor was invoked on check rounds only, so being called was the
    whole signal. Recovered 120/120 at L=480, with no Alice-side seam involved.

Exploitable, not merely observable, because distribute_public_key_with_checks
finishes Bob's entire pass before Charlie's first hop and both links executed
the SAME plan. Measured at L=480, check_fraction=1/4, Werner p=0.9 on Charlie's
link, with the key hops held bit-identical between the two arms:

                    published QBER              published CHSH   REAL mismatch
  naive             0.4667 [0.2565, 0.6768]     0.439            0.223140
  spare the watched 0.0000 [0.0000, 0.2101]     2.673            0.223140

Reproduced here as 0.4333 vs 0.0000 under this agent's own seeds and twirl
schedule; the shape is the finding, not the digits.

The module docstring of distribute.py asserted "the factory is the whole of the
adversary's access to this loop", and
test_the_factory_cannot_tell_a_check_round_from_a_key_round drove resource_factory
ALONE. session.py's own declared threat model hands the same party payload_map
and channel_monitor as well. The invariant was false and its test could not see
it: a test that drives one third of the declared adversary measures one third of
the property.

THE FIX, three parts, all landed.

A. payload_map is invoked on EVERY position and its result discarded on a check
   round -- the same shape the recipient's basis draw already had, and for the
   same reason. distribute.py.
B. channel_monitor is invoked on EVERY position and its result discarded on a
   key round. _ChannelTap in session.py. The other half of the original
   argument is untouched: nothing is RECORDED at a key position, and
   _check_sample_against still re-checks that at the JSON boundary.
C. The reserved positions are dealt between the two links instead of both links
   running the same set. QberRound/ChshRound carry a `party` tag,
   CheckRoundPlan.rounds_by_position(party) and positions_for(party) read it,
   and draw_check_plan deals each arm round-robin. The reserved SET is still
   shared -- it has to be, or the two records stop indexing the same key -- so
   what changes is which link spends which reserved position on a check.

MEASURED, AFTER. The three seams' call sequences are a CONSTANT function of the
plan: over six runs whose only difference is the session seed, six distinct
plans produce one distinct seam view (1440 calls each). Zero bits. So the
posterior over check sets is the prior, and an adversary who must nominate
check_count positions expects check_count^2 / L hits -- at L=120, cf=1/4 that is
7.5 of 30, a precision of 0.25, the base rate, measured over 200 plans. The
payload seam's nomination is now empty; the monitor's is all L positions, whose
precision is exactly the base rate 0.125 at L=480.

The spare-the-watched exploit no longer separates its two arms: published QBER
0.2667 and CHSH -0.487 in BOTH, against a real matched-basis key mismatch of
0.4793 in both. The published statistic tracks the damage instead of the
watched subset.

Determinism held: one seed still reproduces the transcript JSON, the plans and
every seam's call order byte for byte, with three seams attached and called
3 * 2 * 2 * L times.

And the honest run is unmoved. The sifted records are BIT-IDENTICAL to before --
test_retained_positions_are_bit_identical_to_an_unchecked_run passes unchanged,
because a reserved position dealt to the other link runs as a key round that
consumes the same integers/random/random pattern a check round did, so the
generator is in the same state at the start of every position and only the
discarded entry differs. Verdicts, matched counts and record contents are
untouched; the demo functions in attacks/channel.py still report record_rate
['0.0204', '0.0292'] and unsymmetrised_rate ['0.0000', '0.0567'] to the digit.

### `[D]` Per-link check sets cost half the sample, and that is forced, not chosen

*decision · impl:uninferable-check-set · 2026-09-01T14:46:04Z*

Writing down the constraint that decided the shape of part C, because three
designs were tried against it and two are dead ends worth not re-walking.

THE CONSTRAINT. A recipient who spends position p on a check round has no key
entry at p. Symmetrisation exchanges the two records position by position and
verification scores one declaration against both, so both records must cover
the SAME positions. Therefore the signing positions are the complement of the
UNION of the two links' check sets, and

    |S_Bob  U  S_Charlie|  =  params.check_count

is forced, because params.signing_length = L - check_count is what every
matched-count floor and the repudiation bound are derived from, and params.py
is not a file this change can move.

Given |union| = check_count, there are exactly two ways to place two check sets
of equal size m:

  * S_Bob = S_Charlie, m = check_count. Today's design. Full sample on both
    links, and the two links coupled: one recovery buys both.
  * S_Bob disjoint from S_Charlie, m = check_count / 2. Independent halves, and
    half the published sample per link.

There is no middle: a partial overlap makes the union size random, and a random
union size makes signing_length random. So the choice is a straight trade, and
it is worth stating in exactly those terms -- you cannot have a shared signing
key, per-link check sets AND the full sample. The shipped answer is the disjoint
split, with CheckRoundBudget.reserved_fraction (= 2 * fraction) as the number a
deployment sizes with, and draw_check_plan(..., parties=None) as the documented
way back to the coupled full-sample plan.

DEAD END 1: two independently drawn full-size plans, union sifted. This is the
literal reading of "give the two links independent check plans" and it cannot be
built: |union| is then hypergeometric, so signing_length varies run to run and
every floor in Phase 2 is computed against a length the run does not have.

DEAD END 2: give the distributor a per-link plan, e.g. check_plan as a mapping
of party to plan. It breaks sih141/attacks/impersonation.py, whose distributor
seam has an explicit `check_plan: CheckRoundPlan | None` parameter and calls
check_plan.sift_key(mine). That is why the split is carried INSIDE one
CheckRoundPlan as a per-round `party` tag rather than as a second object: every
existing signature, that one included, is untouched, and a plan whose rounds are
untagged still means "every link measures every reserved position".

DEAD END 3 (considered, not built): interleave Bob's and Charlie's passes so
neither finishes before the other starts. It closes exploitability at zero cost
in sample size, but it changes the variate ORDER, so every seeded outcome in the
project moves, and it does not give the two links different check sets -- it
only makes the shared set useless to an adversary who has to act before he can
learn it. Worth revisiting if the halved sample ever becomes the binding
constraint; the two are not mutually exclusive.

WHAT THE SPLIT COSTS, exactly. Each link publishes check_count/2 rounds instead
of check_count, so every published interval half-width grows by sqrt(2) at a
fixed check_fraction. The reserved positions dealt to the other link are not
wasted quantum resource in any physical sense -- they are teleported and
measured like any key round -- but they yield neither key nor a published
observation, which is the price of the two sets differing.

WHAT IT BUYS, exactly. An adversary who learns S_Bob learns a set of positions
that carry no key on either link. The reserved positions he does NOT know are
precisely S_Charlie, every one of which Charlie is watching. So "attack
everything except what I learned on link one" now attacks Charlie's entire check
sample, and the published QBER reports the attack in full. Measured: the two
arms of the spare-the-watched experiment are now identical to the digit.

### `[!]` Five stale literals in attacks/channel.py need the owning agent's pen

*issue · impl:uninferable-check-set · 2026-09-01T14:46:26Z*

HAND-OFF, for whoever owns sih141/attacks/channel.py.

Five doctest literals in that file move as a direct consequence of the
check-set fix. I did not edit the file -- it is owned by another agent working
concurrently -- so the suite is red at exactly two doctests until someone with
the pen applies this. Every qualitative claim in both docstrings still holds;
only the digits move, and each moved for a stated reason.

sih141/attacks/channel.py :: attribution_survives_symmetrisation

    >>> f"{outcome.check_qber[outcome.target]:.4f}"
    '0.0708'      ->    '0.0542'

  Reason: the check sample per link halved, because the reserved positions are
  now dealt between Bob's link and Charlie's. Unchanged and still asserted:
  min(check_qber) '0.0000'; attributable(margin=0.02) and intervals_disjoint()
  both True; records_attributable(margin=0.02) False; record_rate
  ['0.0204', '0.0292']; unsymmetrised_rate ['0.0000', '0.0567']. The records
  are bit-identical -- only the published check statistics moved.

sih141/attacks/channel.py :: payload_line_is_unwatched

    >>> f"{seen['resource_qber']:.4f}", f"{seen['resource_chsh']:.4f}"
    ('0.3177', '0.8813')    ->    ('0.3104', '0.9686')

    >>> f"{seen['payload_qber']:.4f}", f"{seen['payload_chsh']:.4f}"
    ('0.0000', '2.7561')    ->    ('0.0000', '2.7993')

    >>> f"{seen['payload_record_rate']:.4f}"
    '0.3613'      ->    '0.3535'

  Reasons: the first two pairs move with the halved check sample. The last one
  moves because payload_map is now consulted on every position rather than on
  key rounds only, so a randomised payload adversary advances its OWN generator
  at every position -- which is the point, since a seam whose own stream
  advanced only on key rounds carried the check set out with it. It now equals
  resource_record_rate ('0.3535') exactly, because the two seams are offered the
  same hops in the same order and the same adversary seed therefore draws the
  same sequence. resource_record_rate is unchanged at '0.3535'.

Two prose statements in that file are now false and are not caught by any test:

  * ChannelAttack.payload's docstring: "Called once per **key round** and never
    on a check round". It is now called on every position; what it returns on a
    check round is discarded, so the second half of the sentence -- that an
    attack mounted here is invisible to both published statistics -- is still
    true and is still the point.
  * The module docstring's channel-detector table says a ChannelSample is
    "Recorded on every **checked** run" -- still true; but note that samples are
    now one per check round per LINK's own half, so a run publishes check_count
    samples per message bit, not 2 * check_count.

docs/PHASE3.md has already been updated to the new figures, so it is briefly
ahead of attacks/channel.py until this lands.

### `[+]` Re-pinned channel.py's five demo figures after the per-link check-set split

*fix · impl:d6-isolation · 2026-09-01T14:50:46Z*

HAND-OFF ACCEPTED, and independently re-measured. The agent who landed the
per-link check-round split left a note naming five doctest literals in
sih141/attacks/channel.py that its change moves. channel.py is owned here, so
this entry is the re-pin -- and every figure below was produced by running the
two demo functions in this working tree, not copied from the note.

  attribution_survives_symmetrisation
    check_qber[target]              '0.0708'  ->  '0.0542'
    (unchanged and still asserted: min check_qber '0.0000'; attributable and
     intervals_disjoint both True; records_attributable False; record_rate
     ['0.0204','0.0292']; unsymmetrised_rate ['0.0000','0.0567'] -- the records
     are untouched, only the published check statistics moved)

  payload_line_is_unwatched
    resource_qber, resource_chsh    ('0.3177','0.8813') -> ('0.3104','0.9686')
    payload_qber,  payload_chsh     ('0.0000','2.7561') -> ('0.0000','2.7993')
    payload_record_rate             '0.3613'  ->  '0.3535'
    resource_record_rate            '0.3535'  ->  unchanged

Causes, as stated by the change's author and checked here. The first four move
with the halved per-link check sample. payload_record_rate moves because
payload_map is now consulted at every position, so the payload adversary
advances its own generator at every position and is offered exactly the hops the
resource adversary is; under one seed it therefore draws the same sequence and
the two rates coincide at 0.3535. That coincidence is now stated in the docstring
as a consequence rather than left as two numbers that happen to match.

The qualitative claim of both demos is intact: the payload line is still
unwatched (0.0000 QBER, 2.7993 CHSH against 0.3104 and 0.9686 on the resource
line at comparable key damage), and check logs still separate the attacked link
from the clean one with disjoint intervals where the records do not.

PROSE THAT WAS FALSE, verified before rewriting rather than after. Three places
said the payload seam is "never called on a check round". Measured at L=24,
check_fraction=0.25: payload_map is invoked 24/24 positions for both parties and
both message bits. What changed is that its RESULT is discarded on a check
round, not that it is not called -- and the distinction is the point of the
change, because a seam whose own generator advanced only on key rounds carried
the check set out in the gaps. The invisibility claim survives unchanged and is
still what the doctest measures. Also corrected: a run publishes check_count
ChannelSamples per message bit, each link watching its own half, not one per
link per reserved position.

### `[-]` Hand-off taken up: attacks/channel.py literals landed, two prose lines still stale

*note · impl:uninferable-check-set · 2026-09-01T14:56:43Z*

The hand-off in the entry above has landed: sih141/attacks/channel.py now
carries all five updated literals, applied by the agent who owns that file, and
both doctests pass. Recorded here rather than by editing that entry because
this journal is append-only, and because a reader who finds the hand-off should
not have to guess whether it was ever taken up.

Still open in that file, and not caught by any test because it is prose:

  * ChannelAttack.payload's docstring still says "Called once per **key round**
    and never on a check round". It is now called on every position; what it
    returns on a check round is discarded, so the sentence that follows -- that
    an attack mounted here is invisible to both published statistics -- is
    still true and is still the point.
  * The module docstring's detector table says a ChannelSample is "Recorded on
    every **checked** run", which remains true, but a run now publishes
    check_count samples per message bit rather than 2 * check_count: the
    reserved positions are dealt between the links, so each link's samples are
    its own half.

### `[-]` Stale probe rationale left in the isolation suite for its owner

*note · impl:uninferable-check-set · 2026-09-01T14:58:00Z*

One more stale rationale, left alone because its file is being edited
concurrently and the edit is prose only.

tests/test_phase3_isolation_suite.py :: _channel_payload_probe

Its docstring says ``check_fraction`` is zero because "``payload_map`` is
called on key rounds only and which positions are key rounds comes out of the
session's own generator, so the set of contexts a payload adversary is
legitimately offered moves with the session seed even when the adversary is
flawless". That was true and is not any more: the seam is offered every
position whether or not a plan is in force, which is precisely the fix that
closed the check-set channel. The zero is now a harmless simplification rather
than a requirement, and the probe passes either way.

The twin of this docstring in tests/test_attack_channel.py :: _payload_probe
has been updated in place, so the two now disagree; whoever owns the isolation
suite should bring it into line. The same rationale is quoted a third time in
docs/PHASE3.md section 7, which has been updated already.

Neither is a test failure. All three are prose, which is exactly the category
this project has shipped four wrong numbers in.

### `[*]` A fifth wrong prose number: the check-(a) mutation cost 7 failures, not 6

*finding · impl:d6-isolation · 2026-09-01T15:09:44Z*

docs/PHASE3.md's falsification table said the mutation "IsolationReport.
reads_the_session returns False" turned the suite RED with "6 failures". It is 7.

Measured, not inferred: `git archive HEAD` into a scratch directory, the one
line mutated there, and

    python -m pytest tests/test_attack_isolation.py \
        tests/test_phase3_isolation_suite.py sih141/attacks/isolation.py -q

run against that untouched pre-audit tree. Seven FAILED lines. The working tree
is not involved, so this is not a consequence of anything landed in this task --
the number was wrong when it was written.

Small, and it is the fifth wrong prose figure this project has shipped, which is
the point of recording it. The document's own D5 note says the numbers in it are
prose and therefore unchecked; that is exactly why each one has to be measured
when it is written rather than counted from a failure list scrolled past once.

The row now reads 24 (the same mutation on the current tree, measured) against 7
(pre-audit, measured), and the second mutation row -- observe() installing no
SessionEnvironment -- reads 18, likewise measured. Both mutation sites were
restored from a scratchpad snapshot and verified byte-identical afterwards.

### `[D]` Reconciled the two Phase 3 fixes: the isolation rows now ride on the seam lockstep

*decision · reconcile:phase3 · 2026-09-01T16:24:32Z*

STATUS: closed. The two Phase 3 repairs landed in parallel and they meet in
tests/test_phase3_isolation_suite.py. Reconciled there, and the reconciliation
turned out to be worth more than bookkeeping: the isolation suite is now a live
detector for the check-set leak.

WHAT INTERACTED. Check (a) varies the session seed with the attack's own
generator fixed and requires the adversary's decisions not to move. The check
plan is drawn from the recipients' stream, so it moves with that seed. Before
the seam fix, payload_map was invoked on key rounds only, so the set of
positions a payload adversary was offered moved with the plan all by itself --
which is why _channel_payload_probe ran at check_fraction = 0 and its docstring
called the zero load-bearing. Correct at the time, and dead now: the seam is
offered every position.

WHAT I CHANGED.
  - One home for the probe session, _channel_session(), used by both channel
    probes, so the liveness the rows depend on can be asserted against the
    object the rows actually call rather than a copy that can drift.
  - CHANNEL_PROBE_PARAMS: both channel probes now run key_length=24,
    check_fraction=0.25. The payload rows run WITH check rounds.
  - test_the_channel_probes_vary_the_session_they_run: the five session seeds
    check (a) varies must produce five different check plans.
  - test_the_channel_rows_ride_on_the_seam_lockstep: all three channel-side
    seams are offered every position of a checked run, asserted here, with a
    failure message that names the protocol rather than the attack.

WHAT A GREEN ROW MEANS NOW. Before: "this adversary does not read the session
seed". Now, for the two channel rows: "this adversary does not read the session
seed AND its decisions do not move with the check plan". The second half is a
property of the seam wiring, which is why it is also asserted directly.

MEASURED, against mutations of the current tree:
  - revert payload_map to key rounds only -> the isolation suite goes RED, 4
    failures: the three */payload rows fail check (a), and the lockstep test
    fails beside them saying whose fault it is. Before this change the isolation
    suite did not notice that mutation at all.
  - revert channel_monitor to check rounds only -> RED, 1 failure, the lockstep
    test. No row mounts an adversary on the monitor, so the direct assertion is
    the only thing that can catch it, which is why it exists.

A DEAD END THAT IS ALSO A FINDING. The task asked me to restore a `del
session_seed` in one probe and confirm the suite goes red. It does not, and it
should not: the six ready-made probes already contain that `del`, and it is
correct now. What made check (a) inert was never the `del` -- it was that
nothing else offered the candidate a route to the session. observe() installs a
SessionEnvironment around every build and probe call, so the routes are open
whatever a probe does with its argument.

The equivalent mutation is removing that installation: 18 failures, and every
shipped negative control still passes under it, which is exactly why the vacuity
survived a whole phase.

But there IS a live version of the original mistake, and it is the one worth
recording: a probe that FREEZES its session. It does not fail; it passes for
less. Check (a) still catches a session-reading adversary, but the plan stops
moving and the row silently drops half its claim. I measured it: freezing the
session inside _channel_session left the whole isolation suite green. It now
turns test_the_channel_probes_vary_the_session_they_run red. That is the third
probe trap, and it is documented in isolation.py under :ref:`probe-traps`
alongside the two that were already there.

### `[*]` The per-link check deal moved a published number: one-link attribution needs twice the key length

*finding · reconcile:phase3 · 2026-09-01T16:24:33Z*

STATUS: closed, by correcting the document and doubling the length of the test
that pins it. This is the one published number the two fixes moved, and it moved
because of the per-link deal rather than the every-position seams.

WHAT MOVED. docs/PHASE3.md section 4 claimed a one-link depolariser at p = 0.3
on Bob, L = 384, check_fraction = 0.5, is not only DETECTED but ATTRIBUTED: the
two links' 99% QBER intervals disjoint, so Phase 4 can name the compromised
party. Each link used to measure all check_count reserved positions. It now
measures half of them, so that run puts 96 QBER rounds on each link where it
used to put 192, and every per-link interval is sqrt(2) wider.

MEASURED, same experiment, session seeds 2026..2033, attack seed 999:

  L = 384, cf = 0.5   before the deal   192 rounds/link   disjoint 8 of 8 seeds
  L = 384, cf = 0.5   after             96  rounds/link   disjoint 6 of 8 seeds
  L = 768, cf = 0.5   after             192 rounds/link   disjoint 8 of 8 seeds

At seed 2026 specifically: before, Bob 29/192 = 0.1510 99% [0.0962, 0.2292]
against Charlie 0/192 [0.0000, 0.0334]; after, Bob 9/96 = 0.0938 [0.0414,
0.1986] against Charlie 0/96 [0.0000, 0.0646] -- overlapping.

So the claim as written was true before and is not reliably true now. It is not
softened, it is re-sized: the doc now states it as a property of ROUNDS PER LINK
(192 of them), which is what it always was statistically, and names the run that
delivers them.

WHAT I CHANGED.
  - docs/PHASE3.md section 4: the sizing paragraph, the attribution table and
    the two conditions. The table's figures are now the ones the test asserts,
    at the test's own seed, so the two cannot disagree.
  - tests/test_phase3_integration.py ::
    test_a_one_link_channel_attack_is_attributable_from_the_check_logs moved
    from L = 384 to L = 768 and now pins the figures to the digit: Bob 33/192 =
    0.1719 99% [0.1130, 0.2527], Charlie 0/192 [0.0000, 0.0334]. It also asserts
    the two links get equal-sized samples and that Bob's QBER plus CHSH
    observations account for exactly half the reserved positions, so a future
    change to the deal fails on the arithmetic and not two paragraphs of prose
    away.
  - The old test passed on its own seed after the deal. That is the failure mode
    worth naming: an assertion that survives because of the seed it was written
    with is not evidence, and 6-of-8 is what a reader deserves to be told.

ALSO CORRECTED, same cause. Section 9.4's CHSH sentence quoted a 99% half-width
of 0.37 with no sample size attached. Measured: 0.3607 at 320 CHSH rounds and
0.5111 at 160, and 160 is what a run that used to deliver 320 delivers now. The
sentence now carries both numbers and their round counts. dS = 2 sqrt(2) p is
analytic and did not move.

NOT MOVED, checked rather than assumed. Every standalone campaign figure --
the 8000-round QBER table, the kept-share CHSH interval, the p = 0.5 unbiasedness
pooling -- goes through measure_qber / measure_chsh, which build resources
directly and never run a session. The deal cannot reach them.

### `[+]` Honest path is byte-identical across both fixes, and is now pinned by a digest

*fix · reconcile:phase3 · 2026-09-01T16:24:33Z*

STATUS: closed. Asserted rather than assumed, and asserted ACROSS revisions,
which no test written inside one revision can do for itself.

THE PROBLEM WITH THE INVARIANCE TESTS WE HAD. Every one of them compares two
runs of the same tree: a checked run against an unchecked one, a seeded run
against itself. All of them are satisfied by "the honest path changed and both
sides of the comparison moved with it". They are necessary and they are not
sufficient.

WHAT I MEASURED. A clean `git archive HEAD` copy at 885f342 and the working tree,
same script, same seed (20260141), L = 96.

  check_fraction = 0   records, signing keys, verdicts, verdict summaries,
                       check plans, channel samples AND the whole transcript
                       JSON: IDENTICAL, byte for byte.
                       sha256 = 43ea5ceafda99b83d41dd78b8ef7b6968300a7b005040cbd346a7c0ca726660b

  check_fraction = 1/4 records, signing keys, verdicts, verdict summaries and
                       the check PLANS: IDENTICAL. The transcript differs, and
                       only in the published check logs: each link's log went
                       from 24 observations per message bit to 12, the two
                       links' position sets are disjoint, their union is exactly
                       the old set, and -- the part worth checking rather than
                       assuming -- every observation that survived has the SAME
                       VALUE it had before, position by position, all 48 of
                       them across both links and both bits.

That last point is what makes the variate-budget argument concrete: a reserved
position that becomes a key round on this link spends integers, random, random
exactly as a check round did, so the generator is in the same state at the start
of every position and the surviving check rounds see the same draws they always
saw.

WHAT I ADDED. tests/test_protocol_checkrounds.py ::
test_an_unchecked_honest_run_is_byte_identical_to_the_pre_fix_code, pinning that
sha256 as a module constant with the commit it was measured at. The checked
run's records are covered by composition rather than by a second digest -- a
checked transcript legitimately differs now, so pinning one would pin the wrong
thing: test_retained_positions_are_bit_identical_to_an_unchecked_run says a
checked record is the unchecked record sifted, and the unchecked record is now
pinned byte for byte.

WHAT DID CHANGE, and is supposed to: the seam call COUNTS. payload_map and
channel_monitor are called key_length times per link per message bit instead of
signing_length and check_count respectively, and each link's published check log
is half the size. Neither reaches the record, the verdict or the key.

### `[-]` All three audit ledger items are closed, and the ledger has a home in PHASE3.md

*note · reconcile:phase3 · 2026-09-01T16:24:33Z*

STATUS: note. All three items the Phase 3 audit opened are now closed, and the
ledger has a home a reader will find: docs/PHASE3.md section 0, immediately under
the header, rather than only in this journal.

  1  CRITICAL  the check rounds are steerable by the channel adversary
     CLOSED by calling payload_map and channel_monitor at every position and
     discarding their answers where they have no use, and by dealing a plan's
     reserved rounds between the two links. Recovery is back to the base rate.

  2  MAJOR     the D6 stream guards compare generator objects, not seeds
     CLOSED by stream_fingerprint / same_stream / derived_from_seed /
     require_distinct_streams, wired into forgery, replay, run_impersonation,
     measure_impersonation and measure_starvation.

  3  MAJOR     check (a) of the D6 isolation test is inert on all 14 rows
     CLOSED by installing a SessionEnvironment around every build and probe
     call, and by evidencing the pass per row rather than through a shared
     control.

Each closure has a mutation that turns it red (PHASE3.md section 10), which is
the only form of "closed" this project accepts.

WHAT CLOSING ITEM 1 COST, recorded here because it is the one published number
that moved. Both recipients must retain the same key, so the reserved set stays
shared and the ROUNDS are dealt; each link therefore publishes check_count / 2
rounds and every per-link interval is sqrt(2) wider. The one-link attribution
claim of section 4 needed its key length doubled to survive. That is written into
section 0 and section 9 limitation 10 rather than absorbed quietly, and
draw_check_plan(..., parties=None) is a documented, tested way back to the
coupled full-sample plan for a deployment that would rather not pay it.

### `[!]` CRITICAL and OPEN -- the check set is still recoverable: being USED is the new signal

*issue · verify:harden · 2026-09-01T17:37:21Z*

STATUS: OPEN. The hardening round closed the call-sequence leak and did NOT close the finding.

The fix equalised how often each seam is CALLED. It did not equalise what the protocol then
DOES with what the seam returned. The object resource_factory hands over is read ONCE on a key
round (teleport) and TWICE on a check round (ChannelSample.of -> _as_pair -> as_density, then
observe_qber_round / observe_chsh_round). An adversary returning an instrumented object counts
the reads.

FOUR ROUTES REMAIN, all held by the declared channel-side adversary:
  D  resource read-count      precision 1.0000, recall 1.0000 (resource_factory alone)
  E  payload read-count       precision 1.0000, recall 1.0000 (payload_map alone)
  F  extra-mapping consumed   precision 1.0000, recall 1.0000 (channel_monitor alone)
  G  TIMING                   precision 0.70-1.00, and NO instrumentation of any kind

Route G is the one the brief named and the fix does not touch at all: a check round performs
two projective measurements of an entangled pair while a key round performs a teleportation
plus one measurement, so the wall-clock gap between consecutive factory calls classifies the
branch.

Spare-the-watched still works in-run. At the parameters PHASE3.md section 8 itself publishes,
per-link check QBER goes from 23/192 = 0.1198 (detected AND attributed) to 0/192 = 0.0000
(neither), with BIT-IDENTICAL key damage.

So the answer to the question the brief asked -- do published QBER and CHSH now track the real
key mismatch? -- is NO.

WHAT DID CLOSE, and it is not nothing: routes A (payload call gaps), B (monitor invocation) and
C (factory call gaps) are all shut, verified from scratch at two key lengths, both bits, both
recipients. The per-link deal is genuine -- the two links' sets are disjoint, their union is the
reserved set, and knowing one link's set moves the posterior on the other only from 0.1250 to
0.1429.

FRAMING THAT MATTERS FOR THE DECISION. Routes D, E and F are artefacts of the SIMULATION
HARNESS: they count how many times Python reads an object. A real adversary on a fibre observes
no such thing. Route G is more nearly real but is also dominated, in a deployment, by physical
processes rather than by our loop structure. That does NOT make them harmless -- every attack
number this project publishes comes from this harness, so a harness a simulated adversary can
steer produces published figures that are wrong even where a real adversary could not steer.
It is the same category as the Phase 3 finding that the harness leaked the symmetrisation
coins: not a break of the protocol, a break of our ability to measure it.

FIX DIRECTION: equalise the WORK, not just the calls -- read every seam's return value the same
number of times on both branches, and consume the monitor's mapping identically. Route G needs
either constant-work rounds or an explicit statement that timing is out of the simulated threat
model, argued rather than assumed.

### `[-]` Phase 3 hardening: what closed, what did not, and why I stopped here

*note · claude · 2026-09-01T17:37:21Z*

Two findings went into this round. One closed, one did not.

CLOSED: the D6 isolation check. It was vacuous; it now bites, with per-row evidence and two
mutations proving the tests can fail.

NOT CLOSED: the steerable check set. The fix shut three of seven leak routes and the adversary
still recovers the check set at precision 1.0. The published channel statistic still does not
track the real key damage.

I am stopping rather than starting a second hardening round, because that is what the
maintainer asked for and because the remaining routes raise a design question that is his to
answer, not mine to assume: whether to equalise the protocol's WORK on both branches (real
cost, and route G may need constant-work rounds), or to state explicitly that read-counting and
timing are outside the simulated threat model and argue why.

The second option is defensible -- a real Eve does not count Python attribute reads -- but it
must be argued in the documentation rather than left implicit, and it changes what Phase 4's
channel detector may claim. Either way the code is committed, green at 2169 tests, and the
limitation is recorded here rather than discovered by a judge.

### `[+]` CLOSED -- the D6 isolation check now genuinely bites

*fix · fix:isolation-that-isolates · 2026-09-01T17:37:21Z*

STATUS: closed, verified independently.

Root cause was deeper than the audit reported. observe(attack_seed, session_seed) reached the
candidate by only TWO routes -- the builder's optional session_seed= keyword and the probe's
argument. Six probes deleted the second and NO shipped adversary declared the first, so the
five calls check (a) compared were five byte-identical experiments.

The fix went into observe(), not the six probes, so a probe author cannot forget it. It now
installs a SessionEnvironment and deliberately opens three leak routes -- an in-scope session
handle, the ambient global numpy/stdlib random streams, and the session's own rng.bytes(32)
material -- on the principle that a check offering no leak detects no theft. A D3 violation is
now caught rather than merely forbidden.

Evidence is PER ROW, because a shared control cannot give it: each of the 14 adversaries is
rebuilt with the session seed folded into its generator -- same class, same probe, one line of
defect -- and check (a) must catch it. 13/14 caught; the 14th is the deterministic recipient
forger, whose decisions move with nothing at all, and whose randomised sibling is caught.

  mutation 'reads_the_session always False':  7 failures before -> 24 after
  new mutation 'remove the environment':      18 failures, AND every negative control still
                                              passes under it -- which is exactly why the old
                                              controls never caught the vacuity.

Independent verification caught six distinct reading routes (session handle, stream material,
global numpy, stdlib random, declared keyword, and a late reader in __call__). Stream guards
now refuse same-seed generators in EVERY attack module, including the two that had no guard.
No shipped attack rate moved -- now a measured statement rather than an untested one.

### `[*]` MINOR and OPEN -- one D6 route the isolation check still cannot see

*finding · verify:harden · 2026-09-01T17:37:21Z*

STATUS: OPEN, and worth knowing before Phase 5 publishes anything.

An adversary that closes over the harness's real, fixed SEED constant -- rather than the check's
varying stand-in -- passes BOTH halves. Its stream is byte-for-byte the session's in the real
experiment, yet its decisions do not move across the check's varied session seeds.

The derived_from_seed guards do not close it either: they inspect the generator HANDED to the
entry point, and such an adversary builds default_rng(SEED) internally.

This is the one route D6 names explicitly that remains uncovered.

### `[!]` MINOR and OPEN -- three docstrings still assert the invariant that WAS the vulnerability

*issue · verify:harden · 2026-09-01T17:37:21Z*

STATUS: OPEN.

distribute.py:372 (the PayloadMap type-alias contract itself), session.py:183 (the phase3-seams
section a Phase 4 author reads) and session.py:3158 (QDSSession.__init__) all still say
payload_map is 'called once per key round'. It is now called at every position.

The parallel channel_monitor text WAS updated, so the repository now contradicts itself about
the exact invariant the critical fix established.

Also open: the re-stated CHSH half-widths at PHASE3.md:317 and :740 do not reproduce -- both sit
at the low tail of their sampling distributions, and both are prose pinned by no doctest, in a
repository whose own D5 rule puts load-bearing figures in doctests and whose README already
records five wrong prose numbers.
