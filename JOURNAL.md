# Working Journal

**SIH26141** — decisions, issues, dead ends and findings, phase to phase.

> **Temporary file.** Append-only: entries are never edited or removed, only
> added. Rendered from `journal/entries/` by `tools/journal.py render` — edit
> the entries, not this file. Scheduled for deletion at the end of Phase 7,
> on the maintainer's explicit instruction. The permanent record is
> `docs/METRICS.md` and the `docs/PHASE*.md` notes.

**54 entries** — 21 issue · 15 decision · 10 finding · 5 fix · 2 note · 1 deadend


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
