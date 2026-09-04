# Phase 6 — The dashboard, and the eight things a screen can lie about

Engineering note for `sih141.web`. Covers the one command that runs the deliverable, the API
as it actually shipped, how each of the eight demonstration constraints is rendered and why,
what a demo-scale run does and does not establish, the vendoring inventory and how the
no-network claim was verified, the measured latencies an operator should know before a judge
is watching, and every deviation from the brief.

Status: complete. The phase ships `sih141/web/` — a FastAPI application serving both the JSON
API and the static frontend from one process, with no Node, no bundler, no build step and
nothing fetched from a network at runtime. Integration found and fixed **four defects that each
had a passing test**; they are in §9, and the pattern that produced all four is the most
transferable thing in this document.

Full suite on the shipped tree: **3338 passed, 0 failed, 0 skipped**, exit `0`, about 21:50 wall
clock. (`pytest -q` does not print its summary line when stdout is not a TTY in this
environment, so the counts are read off the progress output — 3338 `.` and no `F`, `E` or `s` —
and cross-checked against `pytest --collect-only -q`, which also reports 3338.)

> **Phase 6 runs before Phase 5.** Nothing on this screen is an evaluation result. Phase 5 has
> produced no numbers, and the dashboard demonstrates a live run rather than reporting a study.
> The one table of measured rates on the page is a **Phase 4 calibration**, labelled as such,
> and it is about the noiseless null rather than about any adversary.

## 0. The one command

```
pip install -r requirements.txt
python -m sih141.web
```

Then open the address it prints. That is the whole of it.

```
SIH26141 0.1.0 -- http://127.0.0.1:8141
  frontend        present (.../sih141/web/static)
  live key length up to L = 1024; longer runs are refused, never clamped
  concurrent runs at most 2
  network         nothing is fetched; /docs is off because Swagger UI loads from a CDN
```

`--host` and `--port` are the only options that matter. The default host is `127.0.0.1` and
**not** `0.0.0.0`: this server runs unauthenticated quantum simulation on request, so exposing
it on a venue network is a thing an operator may deliberately want and is not a thing that
should happen because nobody chose.

One process serves both halves. There is no second server, no proxy and no build artefact —
the repo is the deliverable, and `git clone` plus the two lines above is the entire path from
nothing to a running screen.

**If you edit a static asset while the server is up**, hard-reload the page. `StaticFiles`
sends `ETag` and `Last-Modified` and no explicit `Cache-Control`, so a warm navigation can
reuse a cached script. This cost twenty minutes during integration: a CSS fix was live on the
server and invisible in the browser, and the page was verified against a stale copy of itself.

## 1. The API as shipped

Six endpoints. `/docs` is deliberately **off** — Swagger UI loads its own assets from a CDN,
which would put a network fetch on the one page that must never make one.

| Method | Path            | Returns |
|--------|-----------------|---------|
| `GET`  | `/api/health`   | `{"ok": true, "version": "0.1.0"}` |
| `GET`  | `/api/attacks`  | 11 rows: `key`, `label`, `summary`, `detectable`, `assumption` |
| `GET`  | `/api/defaults` | `params`, `bounds`, `limits`, `eps_default`, `live_key_length_max`, and the caps |
| `POST` | `/api/run`      | `{detection, run, ground_truth, timings}` |
| `GET`  | `/`             | the frontend |
| `GET`  | `/static/…`     | its assets |

`GET /openapi.json` also answers, because FastAPI generates it and it is harmless; only the
HTML documentation UI is disabled.

The run body is nine optional fields — the brief's eight plus `tolerated_depolarising` (§8.7):

```jsonc
{ "attack": "honest", "key_length": 192, "check_fraction": 0.25, "noise": 0.0,
  "eps": 1e-9, "channel_error_rate": 0.0, "tolerated_depolarising": 0.0,
  "count_exchange_timing": "before-forwarding", "seed": 20260141 }
```

Unknown fields are rejected (`422 extra_forbidden`) rather than ignored, so a typo in a control
name is an error rather than a silently defaulted run.

### The four top-level keys of a run, and why `ground_truth` is one of them

```jsonc
{
  "detection":    { /* Detection.to_dict(), 21 keys, verbatim */ },
  "run":          { /* transcript facts the screen needs */ },
  "ground_truth": { /* what the HARNESS knows and the detector cannot read */ },
  "timings":      { "session_ms": 410.7, "detect_ms": 5.1 },

  "request":      { /* the VALIDATED request, defaults filled in  — §8.7 */ },
  "error":        null   /* non-null on a run-level failure       — §8.7 */
}
```

`request` and `error` are two additive keys beyond the brief's four. `request` echoes what was
actually run *including the defaults the caller did not send*, so the screen can state the
parameters a result belongs to rather than trusting the control panel to still hold them.
`error` is what makes the `NO RUN` state possible at all: a run-level failure is answered
**`200` with all the keys present**, `detection` and `run` null, and `error` saying what
happened — because a 500 page in the middle of a demonstration tells the room nothing, and a
null detection rendered as "nothing fired" would be a failed run shown as a clean one. The
`503` at capacity carries the same shape plus `Retry-After: 3`, so even a refusal is
renderable.

Which link Eve touched, and which runs a selective starver targeted, live on the **adversary's**
log. The detector may not read them, and keeping them in a separate object means the screen can
show *what actually happened* beside *what the detector could tell* with no chance of one
leaking into the other. A test asserts the separation directly, and the recorded fixture set
includes an adversary mounted at strength zero whose transcript is byte-identical to an honest
one — correctly, and shown as one.

`detection` is `Detection.to_dict()` unmodified. Nothing in this phase recomputes any part of
it, and nothing reaches past `detect()` and `family_budget()`.

### Caps, and refusal rather than clamping

Every parameter the UI can send is bounded, the bounds are published under `/api/defaults`, and
the UI shows them beside the control that sets them — as the input's own `min`/`max` and as a
sentence reading, e.g., **`24 to 1024, refused outside — never clamped`**. The figures are read
from the API rather than written into the page, and a test asserts the UI shows every cap the
API declares.

| field | range | refused with |
|---|---|---|
| `key_length` | 24 … 1024 | `400`, naming the ceiling and the cost |
| `check_fraction` | 0.0 … 0.5 | `400` |
| `noise` | 0.0 … 0.5 | `400` |
| `channel_error_rate` | 0.0 … 0.5 | `400` |
| `tolerated_depolarising` | 0.0 … 0.5 | `400` |
| `eps` | 1e-19 … 0.1 | `400` |
| `seed` | 0 … 2³²−1 | `400` |
| `attack`, `count_exchange_timing` | enumerated | `400`, listing the members |
| concurrent runs | at most 2 | `503`, immediately |

An over-cap `key_length` is **refused, never clamped**, and the refusal says why:

> The request is refused rather than quietly run at 1024: a screen reporting a clamped run
> under the label of the one that was asked for is the single easiest way for this dashboard
> to lie.

`MAX_CONCURRENT_RUNS = 2` is enforced by a non-blocking `BoundedSemaphore`, so the third
simultaneous run is **refused at once** rather than queued. Queuing would be worse: it turns a
button press into an unbounded wait with a spinner and no explanation.

## 2. The live range, and the four minutes that are not offered

`DEFAULT_PARAMS` is `L = 115200`. One session at that length is about four minutes and roughly
37 MB of transcript, and it cannot be produced by a button click. The dashboard's answer is
stated rather than hidden:

* **Live**, up to `L = 1024`. Above that the request is refused.
* **The headline set is published as the closed forms it is** and never as a run. `m_min`,
  `M_min`, the family budget and the enforced repudiation bound at `L = 115200` are all derived
  without running a session, which is exactly why they can be shown when a run cannot. The
  panel says `runnable from this screen? ⊘ NO — ABOUT FOUR MINUTES PER SESSION`.

There are **no pre-generated headline transcripts**. The brief offered that as the obvious
answer; the build stage chose the closed forms instead, on the grounds that a 37 MB transcript
in the repo is a generated artefact and the repo is the deliverable. The decision is recorded
in the journal.

The 13 **recorded runs** in the left rail are a different thing and serve a different purpose:
they are the demonstration walk-through, they load from the repo, and they keep working if the
service dies mid-demonstration — at which point the masthead flips to `RECORDED ONLY — API NOT
REACHABLE` by itself. They are produced by `tools/phase6_fixtures.py`, which drives
`create_app()` through `TestClient` and writes the response **verbatim**, so recorded mode and
live mode render the same objects through the same code and a divergence between them is
impossible rather than merely unlikely.

## 3. The eight constraints, one at a time

Each was walked against the running screen at `http://localhost:8141`, not against a fixture.

### 1. No verdict is a third state

Rendered per **verifier**, not per run, and this is the one place the obvious design is wrong.
The intuitive reading of "an abort is a third state, distinct from detected and clean" is a
three-way headline chip. The recorded runs refute it: **recipient forgery is DETECTED *and*
denies a verifier a verdict**, and so is count starvation. A three-way chip has to discard one
of those facts. So the headline is two panels — `DETECTOR` (did a derived threshold fire) and
`VERIFIERS` (what each party did) — and the third state lives on the verifiers panel, where it
is actually well defined.

Verified live on `count-starvation`:

* Bob's chip is `◇ NO VERDICT`, **violet, dashed**, against Charlie's teal solid `● ACCEPTED`.
* A dedicated violet banner: *"This is a THIRD STATE. It is not an acceptance and it is not a
  rejection… It must not be counted as a detection, must not be counted as a miss, and must not
  appear in the denominator of any rate."*
* The floors chart shows Bob as **"denied the evidence — nothing to plot"**, not a zero bar,
  and the pooled count as `⊘ NO POOLED COUNT — that is an absent number, not a zero`.
* The detector's own Python summary carries `structural:evidence-abort:Bob:…` verbatim.

A **fourth** state exists that the brief did not ask for: `NO RUN`, for a request that errored
or was refused — "not a clean run, not a detection and not a no-verdict, and it belongs in no
rate". That generalisation was right, and §9.3 is the story of it being incomplete.

### 2. Proven and measured are different kinds of number

Two different **shapes**, not two shades:

* `⊢ PROVEN` — a solid blue chip with a turnstile, from a stated null and a named inequality.
* `MEASURED` — a **dashed amber** chip carrying its sample size: `0 / 30 runs`, `203 ms, 1 run`.

Both appear in the page's own legend, above the fold. There is **no false-negative bound**
anywhere on the screen, because none exists and none can be had from a transcript; a test
asserts nothing on the page implies one.

**One correction to the record.** The build-stage journal says the measured chip "cannot be
rendered without a sample size, because the sample size is a required argument of the function
that draws it". It is not: `measured(value, sample)` renders the qualifier as
`sample ? … : null`, so a caller passing none gets a chip without one. In practice every chip on
the page carries its sample — all five call sites pass one, and it was checked on screen — so
the claim is true of the *output* and false of the *mechanism*. Nothing is wrong on the screen;
what is wrong is a guarantee that was asserted and never enforced. Making `sample` mandatory,
with a test, is a small change left for whoever picks this up (§10 note).

That gap is D8 from the inside. A claim about JavaScript behaviour sits outside the suite and
outside `--doctest-modules`, which is exactly why the rule pushes every load-bearing quantity
into Python — and why the JS that remains is checked by a scanner over its source text rather
than trusted.

### 3. The null is noiseless by default, and the screen says so

**This is the dashboard's worst failure mode and the one to show a judge first, unprompted.**

`detect()` defaults to `channel_error_rate = 0.0`. An honest run over a noisy link departs from
that null and is correctly reported as **detected** — the honest baseline, the run that is
supposed to show what "no attack" looks like, lighting up red in front of an audience.

Verified live. `attack = honest`, `noise = 0.03125` (the design level `2·s_a`),
`channel_error_rate = 0.0`:

* The detector fires: `▲ DETECTED — 2 signal(s)`.
* Immediately beneath it, a red-ruled banner: **THE NULL IS NOISELESS — THIS RUN FIRED, AND IT
  WAS SCORED AGAINST THE NOISELESS NULL. Read the ground-truth box before reading this as an
  adversary.** The banner is adaptive: on a clean run it says the nulls *do* match the link; on
  this one it says *"the harness confirms the nulls do NOT match the link, and that no adversary
  is mounted. What fired is the null being wrong about the wire."*
* The ground-truth box: `adversary: none mounted`, and `do the nulls match the link? NO — the
  wire departs from the law the detector was given`.
* The Phase 4 calibration table sits beside it, every row `MEASURED` with its sample size:
  `0.0 → 0/30`, `0.0025 → 13/30`, `0.005 → 17/30`, `0.01 → 27/30`, `0.015 → 30/30`,
  `0.03125 → 30/30`, and the line *"0/30 at every level when the link's true rate is passed to
  detect()"*.

Run again with `channel_error_rate = 0.015625` and `tolerated_depolarising = 0.03125`: nothing
fires, and the banner changes to the informational `ℹ THE NULL CARRIES THE LINK'S ERROR RATE`.

There are **two** nulls, not one, and the controls name them as such: `noise — the LINK` versus
`channel_error_rate — the NULL (rate family)` and `tolerated_depolarising — the NULL (channel
family)`. The operator sets them. They are **never inferred** — at `check_fraction = 0` the
transcript carries no estimate of the link's rate, and guessing would be inventing a null (D7).

### 4. Full impersonation is undetectable by construction

`impersonation-full` appears in the attribution table on **every** run, with `⊘ UNDETECTABLE BY
CONSTRUCTION` and `⊘ OUT OF MODEL — (AUTH)` where a bound would be, plus a banner carrying the
assumption text from `/api/attacks` verbatim. Its radio button in the control rail carries the
same token, so the screen says so *before* you run it.

Never a blank, never a dash, never a zero. The page states the reason in as many words: a zero
reads as "we tried and failed"; the claim is "we proved you cannot, and here is the assumption".

Verified live: `impersonation-full` gives `● NOTHING FIRED`, both verifiers accepting, and
ground truth `detectability: undetectable-by-construction`. The contrast with
`impersonation-partial` — same run, one seam, `▲ DETECTED` — is the point of (AUTH). And the
attribution table is honest about what a detection does *not* name: `outside-forgery`,
`impersonation-signing-seam` and `impersonation-distribution-seam` each carry
**not separable from** the other two, in the row itself, because they fire the same two
mismatch signals.

### 5. An unmonitored link is not a clean one

At `check_fraction = 0` the channel panel draws **no chart at all**. Not a chart of zeros: a
dotted, hatched `⊘ NOT EVALUATED` block carrying the detector's own `withheld` sentence, plus
the note that the channel family's share of the budget is simply unspendable on such a run and
is *reported rather than reclaimed*.

Verified live: the SVG count on the page drops from 4 to 2 — the QBER and CHSH charts are
genuinely absent rather than drawn empty — and the panel reads *"NO CHART IS DRAWN: a chart of
zeros would read as a flat healthy line, and an unmonitored link is not a clean one."* A
separate `WITHHELD` panel is headed **"not evaluated — which is not the same as passed"**.

### 6. Never pool across the timing

`count_exchange_timing` is a control in the rail carrying the sentence *"a control and a label,
never a thing to average over"*, and a `GROUPING KEY` panel renders `detection.grouping_key` on
every run beside *"group by this; never average over it"*.

Nothing on the screen sums or averages anything at all, so there is no total that could cross
the two orderings — which is the same fact as D8 from another direction.

**The brief lists this as the one known gap with no test. It is not a gap.** Two tests pin it,
and they were part of the frontend's final edits before it was stopped:
`test_the_timing_is_a_label_and_never_a_thing_summed_over` asserts the panel exists, renders
both fields and carries its three sentences; a second test,
`…_two_orderings_are_two_experiments_and_the_recorded_set_says_so`, asserts every recorded run's
ordering appears inside its `grouping_key`. The first's docstring divides the labour exactly:
the D8 scanner guarantees the browser *cannot* pool, and the test guarantees the screen *says*
so, because "a panel can be deleted without a scanner noticing".

### 7. Demo scale demonstrates no non-repudiation

The trap is that a demo run reports `transferable: true` cheerfully. The transferability panel
prints that and, immediately beside it, everything that makes it meaningless:

* `transferable (this run)` — a plain **grey** chip, deliberately not a green tick, reading *"an
  outcome of THIS run, not a guarantee"*.
* this run's enforced repudiation bound — `9.9890e-01` at `L = 192` — against `1.4139e-09` at
  `DEFAULT_PARAMS`, both labelled `⊢ PROVEN`.
* `are this run's floors live?` and `floors collapse below 140 sifted positions`.
* the sentence **NON-REPUDIATION IS NOT DEMONSTRATED HERE**, with the reason: *"the enforced
  bound at this run's parameters is a number close to one — which is not a bound on anything."*

Verified live at `L = 48`: a red banner leads the panel — **THIS RUN CARRIES NO SECURITY CLAIM
AT ALL** — the run's own floors print as `m_min = 1, M_min = 1`, and the enforced bound is
`9.9945e-01`. Both verifiers accept and `transferable` says yes, and the panel says in the run's
own numbers why that establishes nothing.

### 8. Publish `false_positive_bound`

The `BOUNDS` panel puts it first, labelled **THE NUMBER TO QUOTE**:

```
false_positive_bound   ⊢ PROVEN  3.8649e-10   P(any signal | honest) — THE NUMBER TO QUOTE
eps (the budget asked for)        1.0000e-09   an input, not a result
slack                             2.59         how far inside its budget the composite proved
evidence_bound                    nothing fired, so there is no post-hoc set to bound
```

`eps` is present and marked *an input, not a result*. `evidence_bound` is a `⊢ PROVEN` chip
marked **POST HOC**, with the sentence that it is a different statement and is never the
detector's error rate — the headline panel notes that at `L = 384, eps = 1e-9` the two differ by
a factor of **2.944**. A test asserts every recorded run has `false_positive_bound < eps`.

## 4. What the demo can and cannot establish

**Can.** That the machinery runs end to end. That the detector fires on eight of the mounted
adversaries and stays quiet on the two that are out of model or inactive. That the derived
thresholds behave as derived, and that the composite publishes a proven bound well inside its
budget. That an abort, a withheld family and an out-of-model attack are three different things
and are rendered as three different things.

**Cannot.** Anything about non-repudiation (§3.7). Any false-negative statement whatsoever —
there is no such bound in this project and none can be had from a transcript. Any detection
*rate* for any adversary: the screen shows one run at a time, and Phase 5 has not run. The
single table of measured rates is a Phase 4 calibration about the noiseless null, labelled
`not a Phase 5 result — a Phase 4 calibration`, and it is about honest runs.

The decision rule is the **same** at both sizes. Only `L` differs, and with it whether the
floors mean anything at all.

## 5. Vendoring, and how the no-network claim was verified

**26 files, 486 KB, four extensions.**

| kind | count | size |
|---|---:|---:|
| `.json` (contract, constants, 13 recorded runs + index) | 19 | 341.2 KB |
| `.js`  (`app`, `render`, `charts`, `contract`, `format`) | 5 | 119.7 KB |
| `.css` (`app.css`) | 1 | 21.2 KB |
| `.html` (`index.html`) | 1 | 3.7 KB |
| **total** | **26** | **485.9 KB** |

No chart library, no web font, no icon font, no image, no analytics, no bundle, no minified
vendor blob, nothing that needs a toolchain to rebuild. **The charts are hand-rolled SVG** —
real `<text>` nodes, so they stay sharp at any projector scale, a screen reader can reach them,
and a test can read them. Type is the operating system's own stack. Even the favicon is
`<link rel="icon" href="data:,">`, an empty inline document, so the browser does not make the
one request nobody writes down — `GET /favicon.ico`.

Verified four ways. The second is the one that matters most, and the reason is at the end of
this section.

1. **Independent content scan.** Every served byte was scanned for `http:`/`https:`,
   protocol-relative `//`, `@import`, `url(`, `srcset`, `integrity`, `crossorigin`,
   `preconnect`/`preload`, `@font-face`, `WebSocket`, `EventSource`, `sendBeacon`, `importmap`,
   dynamic `import(`, and `XMLHttpRequest`. Contents, not the tags anybody wrote, because a
   vendored file with a remote `@import` inside it still fails at the venue and fails in the way
   that is hardest to notice first.

   Three hits, all benign and all checked by hand: **one** `http:` — the SVG namespace URI
   `http://www.w3.org/2000/svg`, which the DOM requires as a string and never fetches; **one**
   `@import`, inside a prose comment in `index.html` saying there is no `@import`; and **three**
   `url(`, two in comments and one real — `url(#hatchId)`, a same-document SVG fragment
   reference for the hatch pattern. Everything else: zero.

2. **Structural closure.** There is exactly **one** `fetch()` call site in 3,526 lines of
   JavaScript (`app.js:77`), and every path handed to it is root-relative: `/api/run`,
   `/api/attacks`, `/api/defaults`, `/static/…`. A root-relative URL **cannot** leave the
   origin. There is no other network API anywhere in the frontend. This is stronger than any
   empirical check: it is not that no request happened to leave, it is that none can.

3. **Empirical, against the real service.** The page was hard-reloaded and driven — a recorded
   run, a live run, projector mode toggled — and `performance.getEntriesByType('resource')`
   reports **11 resources from exactly one origin**, `http://localhost:8141`, totalling 30.9 KB
   — the five scripts, `app.css`, `api-contract.json`, `constants.json`,
   `recorded/index.json`, and the two start-up calls `/api/attacks` and `/api/defaults` (the
   document itself is the navigation entry, not a resource). Not one request left the origin.
   Driving all 13 recorded runs and further live runs adds only `/api/run` and the recorded
   fixtures, under the same origin.

4. **Enforced by the suite.** `test_no_asset_references_a_remote_origin` scans the contents of
   every served file, `test_every_local_reference_resolves_on_disk` checks the other direction,
   `test_every_fetch_target_is_same_origin` covers the JavaScript, and
   `test_every_served_asset_is_a_known_kind` asserts the only extensions under the static root
   are `.html`, `.css`, `.js` and `.json`.

**What was not done, stated plainly:** the machine's network adapter was **not** disabled and no
firewall rule was added — both are system/security settings, and this agent does not change
those. The claim rests on (2) instead, which is a proof by exhaustion of the request set rather
than a single observation: with one fetch site and only root-relative paths, there is no code
path that *could* reach a network, so there is nothing for a disabled adapter to reveal. (1) and
(3) confirm it from the bytes and from the browser.

The one seam that would have 404'd the demonstration is worth repeating here because it is
invisible under a stand-in server: the service serves `index.html` at `/` and mounts the assets
at `/static`, so **relative** asset paths resolve to `/css/app.css` and 404 — every stylesheet
and every script at once, on the one page anybody looks at — while `python -m http.server` over
the static directory serves them perfectly. The paths are root-absolute, and a test asserts both
halves of the seam. Confirmed in this phase against the real service: every asset the page asks
for answered `200`, and the MIME types are right (`text/css`, `text/javascript`), which is the
other thing that differs between the stand-in and the real mount.

## 6. Measured latency — what a click costs

Target machine, i7-14700HX (20 physical / 28 logical cores), 24 GB, `check_fraction = 0.25`,
honest arm, no profiler, **machine otherwise idle**. Server-side figures are the median of three
runs.

That last condition is not boilerplate. Session generation is CPU-bound, and re-running the
sweep while the test suite was saturating the cores put the same `L = 192` run at **640–970 ms**
instead of 433 ms. Do not start a build, a suite or a sweep on the demo machine while a judge is
watching.

**Page load.** `DOMContentLoaded` and `load` at **318 ms** cold, 11 resources, **30.9 KB**
transferred, slowest single resource 4 ms. There is nothing to block on: no font, no library,
no CDN.

**Click to verdict**, measured in the browser from the `click` to the verdict painted:

| `key_length` | click → verdict | server: session | server: detect | response | transcript |
|---:|---:|---:|---:|---:|---:|
| 24   | **72 ms**   | 52.8 ms   | 1.3 ms  | 16.8 KB | 9.4 KB |
| 96   | **229 ms**  | 203.4 ms  | 2.9 ms  | 17.0 KB | 32.4 KB |
| 192  | **433 ms**  | 410.7 ms  | 5.1 ms  | 17.3 KB | 63.2 KB |
| 384  | **1,188 ms**| 823.8 ms  | 8.8 ms  | 17.4 KB | 125.3 KB |
| 768  | **1,813 ms**| 1,638.9 ms| 16.5 ms | 17.5 KB | 249.3 KB |
| 1024 | **2,341 ms**| 2,236.2 ms| 22.1 ms | 17.6 KB | 332.0 KB |

The server columns are medians of three; the click-to-verdict column is **one** measurement each
and includes rendering, so read it as a size rather than a precise figure. Its overhead over the
server's own time is about 20 ms on most rows and a few hundred on two of them — render and GC
noise, not a trend, since the largest run has less overhead than the middle ones.

Three things an operator should take from this table.

* **Detection is free and session generation is the entire cost** — 22 ms against 2.2 s at the
  ceiling, about 1%. Scaling is linear at roughly 2.2 ms per position.
* **The response is flat at ~17 KB** however long the run, because the transcript stays on the
  server and only the facts the screen needs cross the wire. The 332 KB transcript at `L = 1024`
  is never shipped to the browser.
* **`L = 384` is the largest length that stays comfortably interactive** — under half a second
  of server time, about a second end to end. `L = 192` is the default for a reason. `L = 1024`
  is offered, is honest about costing 2.3 s, and is the right choice only when somebody has
  asked to see the length change.

**Recorded runs are effectively instant** — all 13 render in about **175 ms** each, including
the fetch of their own JSON. They are the right thing to click when the point being made is
about the *result* rather than about the run happening live.

**Nothing starts without saying so.** The status line fills in the instant the button is
pressed, echoing the exact parameters — `running: honest, key_length 1024, check_fraction 0.25,
noise 0, timing before-forwarding. Generating the session is the slow part; detection is
milliseconds.` — and the Run button is **disabled** for the duration, so a click cannot start a
second run or be lost.

**If the service dies mid-demonstration**, the masthead flips to `RECORDED ONLY — API NOT
REACHABLE`, all 13 recorded runs keep working from the browser's cache, and an attempted live
run says `NO RUN` rather than leaving a stale verdict on screen. Verified by killing the
process with the page open (§9.3, §9.4). What does *not* work is a **cold** load against a dead
service: the page itself is served by that process, so there is nothing to fall back to. Start
the server before the room fills.

## 7. Abusing the running service

The previous integration round found two `500`s on non-finite input and fixed them; that ground
is covered and is not repeated here. This round pushed at concurrency, body size, content types,
methods, paths, headers and mid-run disconnects. **76 hostile requests, zero `500`s, zero
tracebacks on the wire**, plus two afterwards — a health check and a normal run — to confirm the
service still worked. Status histogram over the single-request sections: 23 × `400`, 16 × `422`,
8 × `404`, 5 × `405`, 6 × `200`, 1 × `503`.

* **Bounds.** Every out-of-range value returns `400` naming the field, the value and the cap:
  `key_length` at 0, −192, 1025, 2⁷⁰ and 1,048,576; `check_fraction` at 1.0, 1.5, −0.5; `noise`
  at 2.0 and −1; `eps` at 0, −1e−9 and 1e300; `seed` at −1 and 2⁶⁴. Wrong types return `422`
  with a structured detail. Unknown fields return `422 extra_forbidden`. An `attack` of
  `'; DROP TABLE runs;--` returns `400` listing the eleven valid keys.
* **Malformed bodies.** Truncated JSON, HTML, NUL bytes, invalid UTF-8, an empty body, a bare
  `null`, an array, and 1 MB and 8 MB of junk — all `400`/`422`, the 8 MB case in 89 ms.
* **Content types.** `text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`,
  `application/octet-stream` and a missing `Content-Type` are all handled; only the last is
  accepted, which is correct, since the body is valid JSON either way.
* **Methods and paths.** `GET`/`PUT`/`DELETE` on `/api/run` → `405`. Directory traversal via
  `../`, `..%2f`, `..\` and `C:/Windows/win.ini` → `404`. An 8 KB path → `404`. `/docs` → `404`.
  One cosmetic oddity, left alone: `HEAD /` answers `405` rather than `200`, because FastAPI's
  route decorator registers `GET` only where Starlette's plain `Route` would add `HEAD`. It
  affects a naive uptime probe and nothing on the page; `GET /api/health` is the liveness check
  and answers in ~6 ms.
* **Concurrency.** Twelve simultaneous runs at `L = 1024`: **exactly two `200`s and ten
  `503`s**, the refusals arriving in 195–308 ms rather than being queued, whole thing done in
  4.7 s. A third run started while two are in flight is refused in **34 ms**. No traceback in
  any response.
* **Mid-run disconnects.** Three connections aborted with `RST` a quarter-second into an
  `L = 1024` run. The server survived and answered health and a normal run immediately after.
  Worth knowing: the abandoned run **continues to completion server-side and holds its slot
  until it finishes**. That is bounded — at most 2 slots, at most ~2.3 s each at the ceiling,
  and it self-heals — but a hostile client can keep both slots busy with disconnecting requests.
* **Headers.** A 64 KB header is refused by `h11` with `400`. Three hundred headers are handled.

**One known limitation, not a defect and not fixed.** A request declaring a large
`Content-Length` and then sending nothing holds its connection open until the client gives up:
uvicorn applies no request-read timeout. It ties up one connection, **not** a run slot — the
concurrency gate is acquired after the body is read — and the service stayed responsive
throughout. Behind any real deployment this is the reverse proxy's job; for a demo on loopback
it is not worth a bespoke timeout, and it is recorded here rather than discovered later.

## 8. Deviations from the brief

1. **No pre-generated headline transcripts.** The brief offered "a bounded live range plus
   pre-generated transcripts for the headline parameters" as the obvious answer and left the
   choice open. The choice made is a bounded live range (`L ≤ 1024`) plus the headline set
   published as **closed forms**, never as a run. A 37 MB transcript is a generated artefact and
   the repo is the deliverable.
2. **Constraint 6 was already pinned.** The brief names it as the one known gap. Two tests cover
   it (§3.6); they were part of the frontend's final edits and post-date the test-name reading
   the brief was written from. Nothing was added.
3. **The page commits to one light theme** and has no dark-mode block, which departs from the
   usual theme-aware guidance. It is shown on a projector in a lit room: a washed-out beamer
   lifts blacks, so a dark theme becomes grey mush while a light one keeps its white bright and
   its near-black text the darkest thing on the screen.
4. **The network adapter was not disabled** for the no-network check. §5 states what was done
   instead and why the structural argument is the stronger one.
5. **Eleven rows on `/api/attacks`, not six.** `honest`; the two forgeries (`outside-forgery`,
   `recipient-forgery`); three impersonation variants, because the seams are separable and the
   contrast between them *is* the (AUTH) argument (`impersonation-partial`,
   `impersonation-distribution`, `impersonation-full`); `replay`; `count-starvation`; and three
   channel arms (`channel-manipulation`, `channel-intercept-resend`, `channel-kept-share`).
   This is the Phase 3 driver's roster surfaced, not an addition by this phase.
6. **Four defects were fixed during integration**, in `app.css`, `app.js`, `render.js`,
   `limits.py` and `api.py`, with four new tests, two strengthened, and one new doctest on
   `json_safe`. They are §9.
7. **`POST /api/run` extends the contract in three additive ways**, all of them needed and none
   of them removing anything the brief specified.

   *Two extra response keys*, `request` and `error` (§1). `error` is load-bearing: it is what
   lets a run-level failure be a `200` carrying the fourth `NO RUN` state instead of a 500 page,
   which is constraint 1 generalised. `request` echoes the validated parameters with defaults
   filled in, so a panel can name the run it belongs to.

   *One extra request field*:
   `tolerated_depolarising`, the channel family's null. The extension is **strictly additive** —
   every field the brief lists is present, all are optional, and a body containing only the
   brief's eight fields is accepted and was exercised as such throughout §7. It is also
   *necessary*: constraint 3 requires the operator to be able to score a noisy run against its
   true null, and there are **two** nulls, not one — `channel_error_rate` for the rate family
   and `tolerated_depolarising` for the channel family. Without the second field the honest
   noisy run could be corrected for the mismatch members and not for the channel members, and
   constraint 3 would be half-satisfiable. `/api/defaults` publishes its cap alongside the
   others.
8. **One labelling ambiguity was fixed** that was not a defect. The headline panel compares a
   demo column against a headline column, and the demo column is `/api/defaults.bounds.demo` —
   a fixed parameter set that does not track the controls. So at `L = 192` the screen carried
   `enforced repudiation bound 9.9890e-01` on the run's own panel and `9.9398e-01` in the demo
   column, both under the same name and apparently at the same length. Both are correct and
   they are different quantities: the run's is computed at its own **sifted** length after
   check rounds are deducted, the column's at the default set's full key length. Nothing was
   derived in the browser and D8 was never in question — it was two API numbers sharing a name.
   The caption now says **BOTH COLUMNS ARE PARAMETER SETS AND NEITHER IS THIS RUN** and the
   headers read `demo default set` and `headline set`.

## 9. Four defects that each had a passing test

The transferable lesson of this phase. All of them shipped green, because each test asserted
that a **string was present in a file** — the right check for "did someone delete this" and no
check at all for "does this work". None could have been found by reading the code, and each
took minutes to find by driving the running service.

### 9.1 Projector mode was completely inert

```css
body.projector { --scale: 1.28; }                 /* setter, on <body>  */
html { font-size: calc(16px * var(--scale)); }    /* reader, on <html>  */
```

A custom property inherits *downwards*. The rule matching `html` resolves `--scale` on the
`html` element, where it is always the `:root` value of `1`; the value set on `<body>` is
invisible to its own parent. Every size on the page is a `rem` — the root font-size — so the one
variable that was supposed to move the whole page moved nothing.

Measured before the fix: document height **5563 px with projector mode on and 5563 px with it
off**. The class landed and `aria-pressed` flipped; the page did not move a pixel. The control
for a big room did nothing.

Fixed by putting the class on the root element (`:root.projector`,
`document.documentElement.classList.toggle`) so the element that sets the variable is the one
that spends it. After: `16px → 20.48px`, exactly 16 × 1.28, and the page 5607 → 7983 px,
returning cleanly to 5607 on the second toggle. (5607 rather than 5563 because the two
measurements were taken over different rendered runs; the load-bearing figure is that the before
pair were *identical* and the after pair are not.) **And it changes no number**: all 185 rendered numbers on a live run are byte-identical
with the toggle on and off, which was the property the original test was really protecting and
is now checked against the rendered page rather than the stylesheet.

### 9.2 A deeply nested body was a `500`

`POST /api/run` with `"[" * 2000 + "]" * 2000` → **`500` in 170 ms**. The same shape as the
non-finite bug this phase already fixed, one layer further out: pydantic refuses the body
correctly, FastAPI echoes the offending value back inside `input`, and `jsonable_encoder` walks
it one stack frame per level. `RecursionError` landed inside the app's own validation handler,
so a properly refused request came back as a `500` with a thousand-frame traceback.

Fixed by bounding depth in `json_safe` (`MAX_ERROR_BODY_DEPTH = 32`) **and by the ordering**:
`jsonable_encoder(json_safe(errors))`, so the depth is bounded before anything else walks the
value. The first attempt kept the existing "probe with `json.dumps` first and return untouched
if it encodes" shape and was wrong — a 200-deep list encodes fine, so the probe succeeds and
hands the value back at full depth. A depth bound only means anything applied on the way *down*;
containers are now always walked and only scalars are probed.

After: depth 200 and 2000 → `422` (232 bytes, with `<nested beyond 32 levels>` in place of the
tail), depth 20,000 and 100,000 → `400` from the JSON parser itself. The existing sweep already
carried a **200**-deep body, which is exactly why it passed: 200 frames fit inside Python's
limit and 2000 do not. The depth was the whole test.

### 9.3 A refused request left the previous run's verdict on screen

The worst of the three, because it is a false statement rather than a dead control.

Type `key_length = 5000` and press Run. The service refuses with the right sentence and the
status line says so — and the result area goes on showing the **previous** run: `NOTHING FIRED`,
`|M| = 265 / 768`, a proven bound, a green verdict. Numbers from a run at `L = 1024`, displayed
under a control panel reading 5000.

That is exactly what the cap exists to prevent, arriving by another door. `limits.py` refuses
rather than clamping *because* "a screen reporting a clamped run under the label of the one that
was asked for is the single easiest way for this dashboard to lie" — and the screen was doing it
anyway, with numbers from a run whose parameters the operator could no longer see.

The cause is a seam between two failure modes that arrive by different doors. A run that
**starts** and does not finish is answered `200` with null bodies and reaches `failurePanel`,
which renders the `NO RUN` state — built, tested, working. A request refused by a cap or the
schema never gets there: it is a `400`/`422`, `fetch` rejects, and the `catch` only wrote the
status line. `Render.refused` now clears the stage and renders the same fourth state, carrying
the server's own sentence and the parameters that were refused.

**The same bug was in the recorded-run loader** — found by fixing the first one and reading the
other `catch`. A fixture that fails to load also left the previous run standing, and that is the
path that runs when the *service has died*, i.e. exactly when nobody in the room can check the
screen against anything else. Both are fixed, and the test asserts there are exactly two
stage-rendering failure paths and that both clear the stage, so a third added later must be
handled too.

### 9.4 The masthead went on claiming a live API after the process died

Found while testing 9.3 under the real failure. The mode chip is painted **once**, at start-up,
when `/api/attacks` cannot be reached — so it is right when the page loads against a dead
service and wrong when the service dies *during* a demonstration, which is the case it exists
for. Verified by killing the server with the page open: the run failed with `Failed to fetch`,
the stage correctly showed `NO RUN`, and the masthead still read **LIVE API**.

The two failures must stay distinguishable, which is why the repaint is guarded rather than
unconditional. `getJson` raises `HTTP <status> …` when the server **answered** — a `400` from a
cap or a `503` from the run gate is the service working exactly as designed — and anything else
means the fetch itself failed. Repainting on an HTTP error would announce a dead API every time
somebody typed a `key_length` over the ceiling.

Verified in all three states: service alive → `LIVE API`; cap refusal → still `LIVE API`, with
`NO RUN` on the stage; process killed → **`RECORDED ONLY — API NOT REACHABLE`**. Fixing it also
made an existing feature reachable: `startLiveRun` already carried the message *"the API is not
reachable, so no live run can be started. The recorded runs below still work"*, and it could
never fire, because nothing ever moved the mode after start-up.

**The demo genuinely survives the service dying.** With the process killed and the page open,
all 13 recorded runs still render from the browser's cache in ~175 ms each, and a live run
attempt says `NO RUN` rather than showing a stale verdict.

## 10. Where the code is

| path | what |
|---|---|
| `sih141/web/__main__.py` | the one command; `--host`, `--port`, `--log-level` |
| `sih141/web/api.py` | `create_app()`, the six endpoints, the concurrency gate |
| `sih141/web/limits.py` | every cap, `RequestRefused`, `json_safe` |
| `sih141/web/driver.py` | mounts an adversary, runs a session, splits ground truth out |
| `sih141/web/catalogue.py` | the attack roster and its `detectable`/`assumption` fields |
| `sih141/web/payload.py` | the `run` object the screen reads |
| `sih141/web/static/` | the frontend: 26 files, nothing fetched |
| `tools/phase6_fixtures.py` | records the 13 walk-through runs through `TestClient`, verbatim |
| `tests/test_web_api.py` | the API, the caps, the abuse sweep |
| `tests/test_web_contract.py` | the four top-level keys, and ground truth staying separate |
| `tests/test_web_driver.py` | the harness under the API |
| `tests/test_web_frontend.py` | the D8 scanner, the eight constraints, the no-network scan |

### Left for whoever picks this up

Three things found late, none of them wrong on the screen today, none changed because the tree
was already under a green full-suite run and a late untested edit is the exact failure this
phase spent its time documenting.

1. **Make `measured(value, sample)` require its sample** (`render.js:179`) and pin it with a
   test. Today every call site passes one and the guarantee is a convention (§3.2).
2. **Add a `<noscript>` block to `index.html`.** With scripting disabled the page renders the
   masthead and an empty stage with no explanation. Not misleading — just unhelpful, and one
   paragraph fixes it.
3. **`docs/METRICS.md` is stale**, generated 2026-09-03 before the web module existed. It is
   generated, not hand-written: `python tools/metrics.py` refreshes it, and it already lists
   `sih141/web` in its module set. It re-runs the full suite, so budget about half an hour.
