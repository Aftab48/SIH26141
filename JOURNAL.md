# Working Journal

**SIH26141** — decisions, issues, dead ends and findings, phase to phase.

> **Temporary file.** Append-only: entries are never edited or removed, only
> added. Rendered from `journal/entries/` by `tools/journal.py render` — edit
> the entries, not this file. Scheduled for deletion at the end of Phase 7,
> on the maintainer's explicit instruction. The permanent record is
> `docs/METRICS.md` and the `docs/PHASE*.md` notes.

**40 entries** — 18 issue · 10 decision · 8 finding · 3 fix · 1 note


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
