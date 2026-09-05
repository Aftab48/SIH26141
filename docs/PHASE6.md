# Phase 6: The dashboard, and the eight things a screen can lie about

Engineering note for `sih141.web`. Covers the one command that runs the deliverable, the API
as it actually shipped, how each of the eight demonstration constraints is rendered and why,
what a demo-scale run does and does not establish, the vendoring inventory and how the
no-network claim was verified, the measured latencies an operator should know before a judge
is watching, and every deviation from the brief.

Status: complete. The phase ships `sih141/web/`, a FastAPI application serving both the JSON
API and the static frontend from one process, with no Node, no bundler, no build step and
nothing fetched from a network at runtime. Integration found and fixed **four defects that each
had a passing test**; they are in §9, and the pattern that produced all four is the most
transferable thing in this document.

Three independent audits then ran against that tree and **all three returned UNSOUND**: twelve
defects, six of them major, two of which falsified claims this document makes. They are in
§11 with the measurement that closed each one. Two of the twelve deserve to be read before
anything else here, because both are this project's own stated failure mode arriving on a
screen: the screen instructed an operator to state ONE of `detect()`'s two nulls and asserted
that doing so clears an honest noisy run (it does not: 12/12 detected, `honest` ruled out, an
adversary named), and a refusal path crashed while formatting its own refusal for the third
time in one phase. Writing the test for the first of those turned up a **thirteenth**: a
sentence this API publishes claimed both verifiers accept on every honest noisy run, and Bob
rejects on 5 of 12.

Full suite on the shipped tree, after the audit round: **3460 passed in 1327.97s (0:22:07)**,
exit `0`, no failures, no errors, no skips. `python -m pytest` printed that summary line
verbatim, and `pytest --collect-only -q` sums to the same 3460. The round before it reported
3338; the 122 new tests are §11's.

> **Phase 6 runs before Phase 5.** Nothing on this screen is an evaluation result. Phase 5 has
> produced no numbers, and the dashboard demonstrates a live run rather than reporting a study.
> The one table of measured rates on the page is a **Phase 4 calibration**, labelled as such,
> and it is about the noiseless null rather than about any adversary.

## 0. The one command

```
pip install -r requirements.txt
python -m sih141.web
```

Then open the address it prints. That's the whole of it.

```
SIH26141 0.1.0 -- listening, bound before this line was printed:
                  http://127.0.0.1:8141
                  http://[::1]:8141
  frontend        present (.../sih141/web/static)
  live key length up to L = 1024; longer runs are refused, never clamped
  concurrent runs at most 2
  request body    at most 65536 bytes; larger is 413 before the app sees it
  network         nothing is fetched; /docs is off because Swagger UI loads from a CDN
```

Two things in that banner are load-bearing and both were defects (§11).

**The sockets are open before the address is printed.** The banner used to come first and the
bind second, inside `uvicorn.run`, so a second instance on a busy port printed an address it
never bound, then uvicorn's startup lines, then the bind error, and *ended* on `Application
shutdown complete`, which reads like a clean stop. The exit status was `1`, so scripts were
fine; the presenter who left an instance running an hour ago, restarts, reads the address line
and demonstrates against the **old process** was not. A busy port now prints `COULD NOT START`,
names the port, prints no address at all, and exits `1`. On Windows the new listener also sets
`SO_EXCLUSIVEADDRUSE`, which closes a second hazard the audit's repro walked past: a second
instance on `127.0.0.1:8141` used to bind *successfully* while another held `0.0.0.0:8141`, and
both then answered.

**Both loopback addresses are bound.** `127.0.0.1` and `0.0.0.0` are IPv4 wildcards and nothing
listens on `::1`; on Windows `--host ::` is the mirror image, since an IPv6 socket is `V6ONLY`
there. Measured before the fix, server on `--host 0.0.0.0`: `http://127.0.0.1:PORT/api/health`
answered, `http://[::1]:PORT/api/health` returned nothing. A browser that resolves `localhost`
to `::1` without falling back cannot open the demo at the address an operator is most likely to
type. Loopback and the wildcards now open one socket per family and the banner lists every
address that was actually bound; a machine with no IPv6 stack gets one socket and a
`not bound` line saying so.

`--host` and `--port` are the only options that matter. The default host is `127.0.0.1` and
**not** `0.0.0.0`: this server runs unauthenticated quantum simulation on request, so exposing
it on a venue network is a thing an operator may deliberately want and is not a thing that
should happen because nobody chose.

One process serves both halves. There is no second server, no proxy and no build artefact: the
repo is the deliverable, and `git clone` plus the two lines above is the entire path from
nothing to a running screen.

**If you edit a static asset while the server is up**, hard-reload the page. `StaticFiles`
sends `ETag` and `Last-Modified` and no explicit `Cache-Control`, so a warm navigation can
reuse a cached script. This cost twenty minutes during integration: a CSS fix was live on the
server and invisible in the browser, and the page was verified against a stale copy of itself.

## 1. The API as shipped

Six endpoints. `/docs` is deliberately **off**, because Swagger UI loads its own assets from a
CDN, which would put a network fetch on the one page that must never make one.

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

The run body is nine optional fields, the brief's eight plus `tolerated_depolarising` (§8.7):

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

  "request":      { /* the VALIDATED request, defaults filled in, §8.7 */ },
  "error":        null   /* non-null on a run-level failure,       §8.7 */
}
```

`request` and `error` are two additive keys beyond the brief's four. `request` echoes what was
actually run *including the defaults the caller did not send*, so the screen can state the
parameters a result belongs to rather than trusting the control panel to still hold them.
`error` is what makes the `NO RUN` state possible at all: a run-level failure is answered
**`200` with all the keys present**, `detection` and `run` null, and `error` saying what
happened, because a 500 page in the middle of a demonstration tells the room nothing, and a
null detection rendered as "nothing fired" would be a failed run shown as a clean one. The
`503` at capacity carries the same shape plus `Retry-After: 3`, so even a refusal is
renderable.

Which link Eve touched, and which runs a selective starver targeted, live on the **adversary's**
log. The detector may not read them, and keeping them in a separate object means the screen can
show *what actually happened* beside *what the detector could tell* with no chance of one
leaking into the other. A test asserts the separation directly, and the recorded fixture set
includes an adversary mounted at strength zero whose transcript is byte-identical to an honest
one. That is correct, and it is shown as one.

`detection` is `Detection.to_dict()` unmodified. Nothing in this phase recomputes any part of
it, and nothing reaches past `detect()` and `family_budget()`.

### Caps, and refusal rather than clamping

Every parameter the UI can send is bounded, the bounds are published under `/api/defaults`, and
the UI shows them beside the control that sets them, both as the input's own `min`/`max` and as
a sentence reading, e.g., **`24 to 1024, refused outside, never clamped`**. The figures are read
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
  panel says `runnable from this screen? ⊘ NO: ABOUT FOUR MINUTES PER SESSION`.

There are **no pre-generated headline transcripts**. The brief offered that as the obvious
answer; the build stage chose the closed forms instead, on the grounds that a 37 MB transcript
in the repo is a generated artefact and the repo is the deliverable. The decision is recorded
in the journal.

The 13 **recorded runs** in the left rail are a different thing and serve a different purpose:
they are the demonstration walk-through, they load from the repo, and they keep working if the
service dies mid-demonstration, at which point the masthead flips to `RECORDED ONLY: API NOT
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
of those facts. So the headline is two panels: `DETECTOR` (did a derived threshold fire) and
`VERIFIERS` (what each party did). The third state lives on the verifiers panel, where it
is actually well defined.

Verified live on `count-starvation`:

* Bob's chip is `◇ NO VERDICT`, **violet, dashed**, against Charlie's teal solid `● ACCEPTED`.
* A dedicated violet banner: *"This is a THIRD STATE. It is not an acceptance and it is not a
  rejection… It must not be counted as a detection, must not be counted as a miss, and must not
  appear in the denominator of any rate."*
* The floors chart shows Bob as **"denied the evidence, nothing to plot"**, not a zero bar,
  and the pooled count as `⊘ NO POOLED COUNT: that is an absent number, not a zero`.
* The detector's own Python summary carries `structural:evidence-abort:Bob:…` verbatim.

A **fourth** state exists that the brief did not ask for: `NO RUN`, for a request that errored
or was refused ("not a clean run, not a detection and not a no-verdict, and it belongs in no
rate"). That generalisation was right, and §9.3 is the story of it being incomplete.

### 2. Proven and measured are different kinds of number

Two different **shapes**, not two shades:

* `⊢ PROVEN` is a solid blue chip with a turnstile, from a stated null and a named inequality.
* `MEASURED` is a **dashed amber** chip carrying its sample size: `0 / 30 runs`, `203 ms, 1 run`.

Both appear in the page's own legend, above the fold. There is **no false-negative bound**
anywhere on the screen, because none exists and none can be had from a transcript; a test
asserts nothing on the page implies one.

**One correction to the record.** The build-stage journal says the measured chip "cannot be
rendered without a sample size, because the sample size is a required argument of the function
that draws it". It is not: `measured(value, sample)` renders the qualifier as
`sample ? … : null`, so a caller passing none gets a chip without one. In practice every chip on
the page carries its sample (all five call sites pass one, and it was checked on screen), so
the claim is true of the *output* and false of the *mechanism*. Nothing is wrong on the screen;
what is wrong is a guarantee that was asserted and never enforced. Making `sample` mandatory,
with a test, is a small change left for whoever picks this up (§10 note).

That gap is D8 from the inside. A claim about JavaScript behaviour sits outside the suite and
outside `--doctest-modules`, which is exactly why the rule pushes every load-bearing quantity
into Python, and why the JS that remains is checked by a scanner over its source text rather
than trusted.

### 3. The null is noiseless by default, and the screen says so

**This is the dashboard's worst failure mode and the one to show a judge first, unprompted.**

`detect()` defaults to `channel_error_rate = 0.0`. An honest run over a noisy link departs from
that null and is correctly reported as **detected**: the honest baseline, the run that is
supposed to show what "no attack" looks like, lighting up red in front of an audience.

Verified live. `attack = honest`, `noise = 0.03125` (the design level `2·s_a`),
`channel_error_rate = 0.0`:

* The detector fires: `▲ DETECTED: 2 signal(s)`.
* Immediately beneath it, a red-ruled banner: **THE NULL IS NOISELESS: THIS RUN FIRED, AND IT
  WAS SCORED AGAINST THE NOISELESS NULL. Read the ground-truth box before reading this as an
  adversary.** The banner is adaptive: on a clean run it says the nulls *do* match the link; on
  this one it says *"the harness confirms the nulls do NOT match the link, and that no adversary
  is mounted. What fired is the null being wrong about the wire."*
* The ground-truth box: `adversary: none mounted`, and `do the nulls match the link? NO: the
  wire departs from the law the detector was given`.
* The Phase 4 calibration table sits beside it, every row `MEASURED` with its sample size:
  `0.0 → 0/30`, `0.0025 → 13/30`, `0.005 → 17/30`, `0.01 → 27/30`, `0.015 → 30/30`,
  `0.03125 → 30/30`, and the line *"0/30 at every level when the link's true rate is passed to
  detect()"*.

Run again with `channel_error_rate = 0.015625` and `tolerated_depolarising = 0.03125`: nothing
fires, and the banner changes to the informational `ℹ THE NULL CARRIES THE LINK'S ERROR RATE`.

There are **two** nulls, not one, and the controls name them as such: `noise: the LINK` versus
`channel_error_rate, the NULL (rate family)` and `tolerated_depolarising, the NULL (channel
family)`. The operator sets them. They are **never inferred**: at `check_fraction = 0` the
transcript carries no estimate of the link's rate, and guessing would be inventing a null (D7).

### 4. Full impersonation is undetectable by construction

`impersonation-full` appears in the attribution table on **every** run, with `⊘ UNDETECTABLE BY
CONSTRUCTION` and `⊘ OUT OF MODEL (AUTH)` where a bound would be, plus a banner carrying the
assumption text from `/api/attacks` verbatim. Its radio button in the control rail carries the
same token, so the screen says so *before* you run it.

Never a blank, never a dash, never a zero. The page states the reason in as many words: a zero
reads as "we tried and failed"; the claim is "we proved you cannot, and here is the assumption".

Verified live: `impersonation-full` gives `● NOTHING FIRED`, both verifiers accepting, and
ground truth `detectability: undetectable-by-construction`. The contrast with
`impersonation-partial` (same run, one seam, `▲ DETECTED`) is the point of (AUTH). And the
attribution table is honest about what a detection does *not* name: `outside-forgery`,
`impersonation-signing-seam` and `impersonation-distribution-seam` each carry
**not separable from** the other two, in the row itself, because they fire the same two
mismatch signals.

### 5. An unmonitored link is not a clean one

At `check_fraction = 0` the channel panel draws **no chart at all**. Not a chart of zeros: a
dotted, hatched `⊘ NOT EVALUATED` block carrying the detector's own `withheld` sentence, plus
the note that the channel family's share of the budget is simply unspendable on such a run and
is *reported rather than reclaimed*.

Verified live: the SVG count on the page drops from 4 to 2 (the QBER and CHSH charts are
genuinely absent rather than drawn empty), and the panel reads *"NO CHART IS DRAWN: a chart of
zeros would read as a flat healthy line, and an unmonitored link is not a clean one."* A
separate `WITHHELD` panel is headed **"not evaluated, which is not the same as passed"**.

### 6. Never pool across the timing

`count_exchange_timing` is a control in the rail carrying the sentence *"a control and a label,
never a thing to average over"*, and a `GROUPING KEY` panel renders `detection.grouping_key` on
every run beside *"group by this; never average over it"*.

Nothing on the screen sums or averages anything at all, so there is no total that could cross
the two orderings, which is the same fact as D8 from another direction.

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

* `transferable (this run)`, a plain **grey** chip, deliberately not a green tick, reading *"an
  outcome of THIS run, not a guarantee"*.
* this run's enforced repudiation bound (`9.9890e-01` at `L = 192`) against `1.4139e-09` at
  `DEFAULT_PARAMS`, both labelled `⊢ PROVEN`.
* `are this run's floors live?` and `floors collapse below 140 sifted positions`.
* the sentence **NON-REPUDIATION IS NOT DEMONSTRATED HERE**, with the reason: *"the enforced
  bound at this run's parameters is a number close to one, which is not a bound on anything."*

Verified live at `L = 48`. A red banner leads the panel: **THIS RUN CARRIES NO SECURITY CLAIM
AT ALL**. The run's own floors print as `m_min = 1, M_min = 1`, and the enforced bound is
`9.9945e-01`. Both verifiers accept and `transferable` says yes, and the panel says in the run's
own numbers why that establishes nothing.

### 8. Publish `false_positive_bound`

The `BOUNDS` panel puts it first, labelled **THE NUMBER TO QUOTE**:

```
false_positive_bound   ⊢ PROVEN  3.8649e-10   P(any signal | honest): THE NUMBER TO QUOTE
eps (the budget asked for)        1.0000e-09   an input, not a result
slack                             2.59         how far inside its budget the composite proved
evidence_bound                    nothing fired, so there is no post-hoc set to bound
```

`eps` is present and marked *an input, not a result*. `evidence_bound` is a `⊢ PROVEN` chip
marked **POST HOC**, with the sentence that it is a different statement and is never the
detector's error rate; the headline panel notes that at `L = 384, eps = 1e-9` the two differ by
a factor of **2.944**. A test asserts every recorded run has `false_positive_bound < eps`.

## 4. What the demo can and cannot establish

**Can.** That the machinery runs end to end. That the detector fires on eight of the mounted
adversaries and stays quiet on the two that are out of model or inactive. That the derived
thresholds behave as derived, and that the composite publishes a proven bound well inside its
budget. That an abort, a withheld family and an out-of-model attack are three different things
and are rendered as three different things.

**Cannot.** Anything about non-repudiation (§3.7). Any false-negative statement whatsoever,
since there is no such bound in this project and none can be had from a transcript. Any detection
*rate* for any adversary: the screen shows one run at a time, and Phase 5 has not run. The
single table of measured rates is a Phase 4 calibration about the noiseless null, labelled
`not a Phase 5 result, a Phase 4 calibration`, and it is about honest runs.

The decision rule is the **same** at both sizes. Only `L` differs, and with it whether the
floors mean anything at all.

## 5. Vendoring, and how the no-network claim was verified

**26 files, 520 KB, four extensions.**

| kind | count | size |
|---|---:|---:|
| `.json` (contract, constants, 13 recorded runs + index) | 19 | 356.2 KB |
| `.js`  (`app`, `render`, `charts`, `contract`, `format`) | 5 | 137.0 KB |
| `.css` (`app.css`) | 1 | 22.6 KB |
| `.html` (`index.html`) | 1 | 3.7 KB |
| **total** | **26** | **519.5 KB** |

No file was added by the audit round; the growth is the fixes and the words that explain them.

No chart library, no web font, no icon font, no image, no analytics, no bundle, no minified
vendor blob, nothing that needs a toolchain to rebuild. **The charts are hand-rolled SVG**:
real `<text>` nodes, so they stay sharp at any projector scale, a screen reader can reach them,
and a test can read them. Type is the operating system's own stack. Even the favicon is
`<link rel="icon" href="data:,">`, an empty inline document, so the browser never makes
`GET /favicon.ico`, the one request nobody writes down.

Verified four ways. The second is the one that matters most, and the reason is at the end of
this section.

1. **Independent content scan.** Every served byte was scanned for `http:`/`https:`,
   protocol-relative `//`, `@import`, `url(`, `srcset`, `integrity`, `crossorigin`,
   `preconnect`/`preload`, `@font-face`, `WebSocket`, `EventSource`, `sendBeacon`, `importmap`,
   dynamic `import(`, and `XMLHttpRequest`. Contents, not the tags anybody wrote, because a
   vendored file with a remote `@import` inside it still fails at the venue and fails in the way
   that is hardest to notice first.

   Three hits, all benign and all checked by hand: **one** `http:`, the SVG namespace URI
   `http://www.w3.org/2000/svg`, which the DOM requires as a string and never fetches; **one**
   `@import`, inside a prose comment in `index.html` saying there is no `@import`; and **three**
   `url(`, two in comments and one real (`url(#hatchId)`, a same-document SVG fragment
   reference for the hatch pattern). Everything else: zero.

2. **Structural closure.** There is exactly **one** `fetch()` call site in the frontend's
   JavaScript (`app.js`, inside `getJson`), and every path handed to it is root-relative:
   `/api/run`, `/api/health`, `/api/attacks`, `/api/defaults`, `/static/…`. A root-relative URL
   **cannot** leave the origin. There is no other network API anywhere in the frontend. This is
   stronger than any empirical check: it is not that no request happened to leave, it is that
   none can.

3. **Empirical, against the real service.** The page was hard-reloaded and driven (a recorded
   run, a live run, projector mode toggled), and `performance.getEntriesByType('resource')`
   reports resources from exactly one origin. The audit round added two new request kinds, the
   13-file recorded preload at boot (§11.4) and the five-second `/api/health` poll (§11.5), so
   the measurement was taken again: **37 resources, 11 of them health polls, and zero from a
   foreign origin.** Not one request left the origin, and the two new kinds are the reason to say so
   again rather than to assume the earlier count still stands.

4. **Enforced by the suite.** `test_no_asset_references_a_remote_origin` scans the contents of
   every served file, `test_every_local_reference_resolves_on_disk` checks the other direction,
   `test_every_fetch_target_is_same_origin` covers the JavaScript, and
   `test_every_served_asset_is_a_known_kind` asserts the only extensions under the static root
   are `.html`, `.css`, `.js` and `.json`.

**What was not done, stated plainly:** the machine's network adapter was **not** disabled and no
firewall rule was added; both are system/security settings, and this agent does not change
those. The claim rests on (2) instead, which is a proof by exhaustion of the request set rather
than a single observation: with one fetch site and only root-relative paths, there is no code
path that *could* reach a network, so there is nothing for a disabled adapter to reveal. (1) and
(3) confirm it from the bytes and from the browser.

The one seam that would have 404'd the demonstration is worth repeating here because it is
invisible under a stand-in server: the service serves `index.html` at `/` and mounts the assets
at `/static`, so **relative** asset paths resolve to `/css/app.css` and 404. Every stylesheet
and every script fails at once, on the one page anybody looks at, while `python -m http.server`
over the static directory serves them perfectly. The paths are root-absolute, and a test asserts
both halves of the seam. Confirmed in this phase against the real service: every asset the page asks
for answered `200`, and the MIME types are right (`text/css`, `text/javascript`), which is the
other thing that differs between the stand-in and the real mount.

## 6. Measured latency: what a click costs

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
server's own time is about 20 ms on most rows and a few hundred on two of them. That is render
and GC noise, not a trend, since the largest run has less overhead than the middle ones.

Three things an operator should take from this table.

* **Detection is free and session generation is the entire cost**: 22 ms against 2.2 s at the
  ceiling, about 1%. Scaling is linear at roughly 2.2 ms per position.
* **The response is flat at ~17 KB** however long the run, because the transcript stays on the
  server and only the facts the screen needs cross the wire. The 332 KB transcript at `L = 1024`
  is never shipped to the browser.
* **`L = 384` is the largest length that stays comfortably interactive**, at under half a second
  of server time and about a second end to end. `L = 192` is the default for a reason. `L = 1024`
  is offered, is honest about costing 2.3 s, and is the right choice only when somebody has
  asked to see the length change.

**Recorded runs are effectively instant.** All 13 render in about **175 ms** each, including
the fetch of their own JSON. They are the right thing to click when the point being made is
about the *result* rather than about the run happening live.

**Nothing starts without saying so.** The status line fills in the instant the button is
pressed, echoing the exact parameters: `running: honest, key_length 1024, check_fraction 0.25,
noise 0, timing before-forwarding. Generating the session is the slow part; detection is
milliseconds.` The Run button is **disabled** for the duration, so a click cannot start a
second run or be lost.

**If the service dies mid-demonstration**, the masthead flips to
`RECORDED ONLY (13): API NOT REACHABLE` within five seconds, all 13 recorded runs keep working
**from this page's memory**, and an attempted live run says `NO RUN` rather than leaving a stale
verdict on screen.

That paragraph used to say the recorded runs kept working "from the browser's cache", and the
audit showed they did not. `showRecorded` re-fetched `data/recorded/<file>.json` on every click
and the server sent no `Cache-Control`, so survival was decided by Chrome's *heuristic*
freshness, roughly a tenth of the file's age, which on a tree cloned that morning is a couple
of minutes. On a fresh clone: page loaded, process killed, three recorded runs clicked, three
`Failed to fetch` and three `NO RUN` panels. The whole set is 365 KB, so it is now fetched once
at boot while the service is alive and every click reads memory; the rail says
`13 of 13 held in this page's memory`, so a partial preload is visible before the click that
needs it rather than after.

**A cold load against a dead service does not load at all, and that is now deliberate.** This
document used to say the page "is served by that process, so there is nothing to fall back to",
which was not what happened either: it rendered from cache with the masthead asserting
`RECORDED ONLY: API NOT REACHABLE` above a rail holding **zero** recorded runs, a chip
promising a fallback mode that was empty. Nothing numeric was wrong on that screen (every
control read `range not supplied by the API`, the headline panel read `THE API DID NOT SUPPLY
THIS`), but the chip was, and the chip is what a presenter points at. On a tree whose files had
just been edited the same reload produced a *third* outcome: a blank page, because the scripts
had to revalidate and could not.

A failure mode that is a coin flip cannot be documented, so the frontend is served with
`Cache-Control: no-cache` (revalidate before reuse, not do-not-store). A live server answers
`304` over loopback in well under a millisecond; a dead one produces the browser's own error
page. There is one behaviour, and it is the honest one. It also removes the stale-asset hazard
this document warns about elsewhere. The masthead's third state (`NOTHING LIVE: NO API AND NO
RECORDED RUNS`) stays as defence in depth for a browser or proxy that serves a stale shell
anyway.

Start the server before the room fills.

## 7. Abusing the running service

The previous integration round found two `500`s on non-finite input and fixed them; that ground
is covered and is not repeated here. This round pushed at concurrency, body size, content types,
methods, paths, headers and mid-run disconnects. **76 hostile requests, zero `500`s, zero
tracebacks on the wire**, plus two afterwards, a health check and a normal run, to confirm the
service still worked. Status histogram over the single-request sections: 23 × `400`, 16 × `422`,
8 × `404`, 5 × `405`, 6 × `200`, 1 × `503`.

> **That "zero `500`s" was false, and the way it was false is the point.** An audit sent a
> `key_length` with 309 digits and got a `500`. The battery above stopped at ten digits. The
> defect was a *third* instance of the shape the two earlier ones had: a request refused
> **correctly**, then the code reporting the refusal falling over while quoting the input back.
> This section's own framing ("that ground is covered") is what made the third instance easy
> to miss. Covering an instance is not covering a shape. §11.1 has the fix and the sweep that
> replaces this battery: every field on the request surface crossed with every value that is
> hard to *render*, which contains all three instances and did not have to know about any of
> them.

* **Bounds.** Every out-of-range value returns `400` naming the field, the value and the cap:
  `key_length` at 0, −192, 1025, 2⁷⁰ and 1,048,576; `check_fraction` at 1.0, 1.5, −0.5; `noise`
  at 2.0 and −1; `eps` at 0, −1e−9 and 1e300; `seed` at −1 and 2⁶⁴. Wrong types return `422`
  with a structured detail. Unknown fields return `422 extra_forbidden`. An `attack` of
  `'; DROP TABLE runs;--` returns `400` listing the eleven valid keys.
* **Malformed bodies.** Truncated JSON, HTML, NUL bytes, invalid UTF-8, an empty body, a bare
  `null` and an array, all `400`/`422`. The 1 MB and 8 MB junk bodies in this battery were
  handled *and were the wrong measurement*: they were refused, and the refusal echoed the
  offending field back twice, once inside its message and once as `value`, for a measured **2.00×**
  on the wire and about **9×** in resident memory that was never released. 256 MB took the process
  to 2.4 GB and it stayed there. Bodies are now capped at **65536 bytes** and answered `413`
  before the application sees them (§11.2).
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
  until it finishes**. That is bounded (at most 2 slots, at most ~2.3 s each at the ceiling) and
  it self-heals, but a hostile client can keep both slots busy with disconnecting requests.
* **Headers.** A 64 KB header is refused by `h11` with `400`. Three hundred headers are handled.

**One known limitation, not a defect and not fixed.** A request declaring a large
`Content-Length` and then sending nothing holds its connection open until the client gives up:
uvicorn applies no request-read timeout. It ties up one connection, **not** a run slot, since the
concurrency gate is acquired after the body is read, and the service stayed responsive
throughout. Behind any real deployment this is the reverse proxy's job; for a demo on loopback
it isn't worth a bespoke timeout, and it is recorded here rather than discovered later.

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
   `tolerated_depolarising`, the channel family's null. The extension is **strictly additive**:
   every field the brief lists is present, all are optional, and a body containing only the
   brief's eight fields is accepted and was exercised as such throughout §7. It is also
   *necessary*: constraint 3 requires the operator to be able to score a noisy run against its
   true null, and there are **two** nulls, not one. `channel_error_rate` belongs to the rate
   family and `tolerated_depolarising` to the channel family. Without the second field the honest
   noisy run could be corrected for the mismatch members and not for the channel members, and
   constraint 3 would be half-satisfiable. `/api/defaults` publishes its cap alongside the
   others.
8. **One labelling ambiguity was fixed** that was not a defect. The headline panel compares a
   demo column against a headline column, and the demo column is `/api/defaults.bounds.demo`,
   a fixed parameter set that does not track the controls. So at `L = 192` the screen carried
   `enforced repudiation bound 9.9890e-01` on the run's own panel and `9.9398e-01` in the demo
   column, both under the same name and apparently at the same length. Both are correct and
   they are different quantities: the run's is computed at its own **sifted** length after
   check rounds are deducted, the column's at the default set's full key length. Nothing was
   derived in the browser and D8 was never in question; it was two API numbers sharing a name.
   The caption now says **BOTH COLUMNS ARE PARAMETER SETS AND NEITHER IS THIS RUN** and the
   headers read `demo default set` and `headline set`.
9. **The audit round adds two more additive extensions and one new status code**, all in §11 and
   none of them removing anything.

   *One more response field*: `run.nulls`, from `sih141.web.payload.nulls_stated()`. It reports
   which of `detect()`'s two nulls the operator actually stated (three states, not two), and it
   exists because the alternative was the browser comparing a null to zero to decide what the
   screen says, which is a decision made outside every test this project has (**D8**).
   `Detection.null_is_noiseless` is untouched: it is the rate family's flag and remains exactly
   that.

   *One more status code*: `413`, for a request body over `MAX_REQUEST_BYTES` (65536). The brief
   requires that a request cannot exhaust the server, and nothing bounded the body: `413` is the
   correct answer and is refused before the application sees the bytes.

   *Two more response headers*: `Cache-Control: no-cache` on the frontend, so a cold load against
   a dead service has one behaviour instead of three (§11.6), and `Cache-Control: no-store` on
   every `/api/` answer, because `/api/health` is polled so the masthead's `LIVE API` claim is
   verified rather than inferred, and a cached `{"ok": true}` would put that claim back over a
   dead process.
10. **The dashboard always sends both nulls**, so the eight-field body of the fixed contract is
   still exactly what the server accepts and is no longer what the screen sends. The contract
   manifest records this: `tolerated_depolarising` stays under `request_optional`, optional on
   the wire and mandatory on the screen, because an operator who can set one of two nulls is
   being told to do something that leaves an honest run reported as an attack (§11.1).

## 9. Four defects that each had a passing test

The transferable lesson of this phase. All of them shipped green, because each test asserted
that a **string was present in a file**: the right check for "did someone delete this" and no
check at all for "does this work". None could have been found by reading the code, and each
took minutes to find by driving the running service.

### 9.1 Projector mode was completely inert

```css
body.projector { --scale: 1.28; }                 /* setter, on <body>  */
html { font-size: calc(16px * var(--scale)); }    /* reader, on <html>  */
```

A custom property inherits *downwards*. The rule matching `html` resolves `--scale` on the
`html` element, where it is always the `:root` value of `1`; the value set on `<body>` is
invisible to its own parent. Every size on the page is a `rem`, the root font-size, so the one
variable that was supposed to move the whole page moved nothing.

Measured before the fix: document height **5563 px with projector mode on and 5563 px with it
off**. The class landed and `aria-pressed` flipped; the page did not move a pixel. The control
for a big room did nothing.

Fixed by putting the class on the root element (`:root.projector`,
`document.documentElement.classList.toggle`) so the element that sets the variable is the one
that spends it. After: `16px → 20.48px`, exactly 16 × 1.28, and the page 5607 → 7983 px,
returning cleanly to 5607 on the second toggle. (5607 rather than 5563 because the two
measurements were taken over different rendered runs; the load-bearing figure is that the before
pair were *identical* and the after pair are not.) **And it changes no number**: all 185
rendered numbers on a live run are byte-identical with the toggle on and off, which was the
property the original test was really protecting and is now checked against the rendered page
rather than the stylesheet.

### 9.2 A deeply nested body was a `500`

`POST /api/run` with `"[" * 2000 + "]" * 2000` → **`500` in 170 ms**. The same shape as the
non-finite bug this phase already fixed, one layer further out: pydantic refuses the body
correctly, FastAPI echoes the offending value back inside `input`, and `jsonable_encoder` walks
it one stack frame per level. `RecursionError` landed inside the app's own validation handler,
so a properly refused request came back as a `500` with a thousand-frame traceback.

Fixed by bounding depth in `json_safe` (`MAX_ERROR_BODY_DEPTH = 32`) **and by the ordering**:
`jsonable_encoder(json_safe(errors))`, so the depth is bounded before anything else walks the
value. The first attempt kept the existing "probe with `json.dumps` first and return untouched
if it encodes" shape, and it was wrong because a 200-deep list encodes fine, so the probe
succeeds and hands the value back at full depth. A depth bound only means anything applied on the way *down*;
containers are now always walked and only scalars are probed.

After: depth 200 and 2000 → `422` (232 bytes, with `<nested beyond 32 levels>` in place of the
tail), depth 20,000 and 100,000 → `400` from the JSON parser itself. The existing sweep already
carried a **200**-deep body, which is exactly why it passed: 200 frames fit inside Python's
limit and 2000 do not. The depth was the whole test.

### 9.3 A refused request left the previous run's verdict on screen

The worst of the three, because it is a false statement rather than a dead control.

Type `key_length = 5000` and press Run. The service refuses with the right sentence and the
status line says so, yet the result area goes on showing the **previous** run: `NOTHING FIRED`,
`|M| = 265 / 768`, a proven bound, a green verdict. Numbers from a run at `L = 1024`, displayed
under a control panel reading 5000.

That is exactly what the cap exists to prevent, arriving by another door. `limits.py` refuses
rather than clamping *because* "a screen reporting a clamped run under the label of the one that
was asked for is the single easiest way for this dashboard to lie", and the screen was doing it
anyway, with numbers from a run whose parameters the operator could no longer see.

The cause is a seam between two failure modes that arrive by different doors. A run that
**starts** and does not finish is answered `200` with null bodies and reaches `failurePanel`,
which renders the `NO RUN` state (built, tested, working). A request refused by a cap or the
schema never gets there: it is a `400`/`422`, `fetch` rejects, and the `catch` only wrote the
status line. `Render.refused` now clears the stage and renders the same fourth state, carrying
the server's own sentence and the parameters that were refused.

**The same bug was in the recorded-run loader**, found by fixing the first one and reading the
other `catch`. A fixture that fails to load also left the previous run standing, and that is the
path that runs when the *service has died*, i.e. exactly when nobody in the room can check the
screen against anything else. Both are fixed, and the test asserts there are exactly two
stage-rendering failure paths and that both clear the stage, so a third added later must be
handled too.

### 9.4 The masthead went on claiming a live API after the process died

Found while testing 9.3 under the real failure. The mode chip is painted **once**, at start-up,
when `/api/attacks` cannot be reached, so it is right when the page loads against a dead
service and wrong when the service dies *during* a demonstration, which is the case it exists
for. Verified by killing the server with the page open: the run failed with `Failed to fetch`,
the stage correctly showed `NO RUN`, and the masthead still read **LIVE API**.

The two failures must stay distinguishable, which is why the repaint is guarded rather than
unconditional. `getJson` raises `HTTP <status> …` when the server **answered** (a `400` from a
cap or a `503` from the run gate is the service working exactly as designed), and anything else
means the fetch itself failed. Repainting on an HTTP error would announce a dead API every time
somebody typed a `key_length` over the ceiling.

Verified in all three states: service alive → `LIVE API`; cap refusal → still `LIVE API`, with
`NO RUN` on the stage; process killed → **`RECORDED ONLY: API NOT REACHABLE`**. Fixing it also
made an existing feature reachable: `startLiveRun` already carried the message *"the API is not
reachable, so no live run can be started. The recorded runs below still work"*, and it could
never fire, because nothing ever moved the mode after start-up.

> **This fix covered one of the two paths, and the audit found the other.** The repaint lived
> inside `startLiveRun`'s catch. `showRecorded`'s catch called `Render.refused` and `setStatus`
> and never touched `state.mode`, so clicking three recorded runs against a dead process gave
> three `Failed to fetch` panels under a masthead still reading `LIVE API`, and the recorded
> path is the one a presenter falls back to. §11.4 and §11.5 close it: one shared handler that
> every failing path calls, and a five-second `/api/health` poll, because with recorded runs now
> served from memory there is no longer any failure on that path to learn from.

**The demo genuinely survives the service dying**, but not for the reason this section
originally gave, and the difference is §11.4. With the process killed and the page open, all 13
recorded runs render **from memory**, because they are fetched once at boot rather than on each
click; a live run attempt says `NO RUN`; and the masthead flips within five seconds whether or
not anything has been clicked, because `/api/health` is polled rather than waited on. The
earlier claim, "from the browser's cache", was measured false on a fresh clone.

## 11. Three audits, thirteen defects

Three independent auditors ran against the tree §9 closed and **all three returned UNSOUND**:
twelve defects, six major. A thirteenth turned up while writing the test for the first of them.
Each entry below carries the measurement before the fix and the measurement after, because a
summary count hides the one that did not work.

Two of them are the reason this round happened at all rather than the phase being declared done:
both are this project's own stated failure mode arriving on a screen a judge reads.

### 11.1 The screen instructed an operator to produce a false accusation: MAJOR

`detect()` takes **two** null parameters. `channel_error_rate` (`p_e`) is what the *rate* family
reads the verifiers' mismatch counts against; `tolerated_depolarising` (`p0`) is what the
*channel* family reads the published check rounds against. Both default to a perfect link, and
neither is converted into the other, because doing that silently would state a null the operator
did not ask for.

`Detection.null_is_noiseless` is defined over the first alone, correctly; it is the rate
family's flag. The banner keyed off it, so there were two states on screen where there are three,
and the calibration panel asserted *"0/30 at every level when the link's true rate is passed to
`detect()`"* while the warning above it said *"Set the link's true rate in the controls"*,
singular.

An operator who follows that instruction, on an **honest** run over a noisy link:

| nulls stated | banner before | verdict | attribution |
|---|---|---|---|
| neither | red `The null is noiseless` | `DETECTED` | `honest` RULED OUT, 5 adversaries named |
| **rate only: what the screen said to do** | **blue INFO `The null carries the link's error rate`** | `DETECTED` | `honest` RULED OUT, `channel-manipulation` **SUPPORTED** |
| both | *unreachable by following the instruction* | n/a | n/a |

Measured over twelve seeds at `L = 192`, `check_fraction = 0.25`, link strength `0.03125` (the
design noise level `2 s_a`): **12/12** detected with neither null stated, **12/12** with only
`channel_error_rate` corrected, **0/12** with both. `0.015625` is exactly the figure the same
screen's ground-truth box prints as the link's true error rate.

The mechanism was right. `tolerated_depolarising` was already a request field, already a
control, and the API already shipped the correcting sentence as
`noise_null_calibration.second_null_note`. What was wrong was everything the operator reads:
`render.js`'s `noiseCalibration()` rendered `with_true_rate_passed` and **dropped**
`second_null_note`, and no JavaScript or test referenced it. A sentence the API ships and the
screen drops is worse than one nobody wrote: it reads as though the question was answered.

**Fixed** in four places, and the shape of the fix matters more than any one of them.

* `sih141/web/payload.py` gains `nulls_stated()`, which returns the three-way state as flags
  **computed in Python**: both default, one stated, both stated. The browser branches on a
  boolean the API sent; it does not compare a null to zero (**D8**).
* `render.js`'s `nullBanners()` has three branches, and the middle one, the state the old
  instruction led into, is an `alarm`/`caution` banner headed **"Only one of the two nulls is
  stated"**, never the calm blue INFO. The info banner is now reachable only when both are.
* The calibration panel renders `second_null_note` in a `.warn-note` block, visually distinct
  from the line it corrects.
* The two controls are labelled `NULL 1 of 2` and `NULL 2 of 2` under a standing note reading
  *"TWO NULLS, AND BOTH DEFAULT TO A PERFECT LINK … setting either alone leaves the other family
  scoring against a link nobody has, and the run still fires."* `with_true_rate_passed` itself
  now names both request fields, so it is true read alone.

**Verified end to end in the browser**, which is what constraint 3 demands: run the honest arm
over a noisy link and follow the screen's own instruction exactly as written.

| nulls | banner after | verdict | `honest` row |
|---|---|---|---|
| `0, 0` | red alarm: *Both nulls are noiseless* | `DETECTED` | RULED OUT |
| `0.015625, 0` | **red alarm: *Only one of the two nulls is stated*** | `DETECTED` | RULED OUT |
| `0.015625, 0.03125` | blue info: *Both nulls were stated by the operator* | **`NOTHING FIRED`** | **SUPPORTED** |

That last heading is deliberately weaker than it could be. It says both nulls were **stated**,
not that they are the right ones: an operator can state two nulls describing a link nobody has.
Type an honest link's numbers on a run with Eve on the resource seam, and a heading reading "both
nulls carry the link" would assert she is not there. Whether the nulls *match* the wire is the
harness's sentence, printed in the same banner, because only the harness knows it.

Nothing about the detector changed. The thresholds are derived and were never touched (**D7**);
what changed is that the screen now asks for the two nulls it actually has.

### 11.2 `key_length` with 309 digits was a `500`: MAJOR, and the third of its shape

`check_key_length`'s over-ceiling message estimated the run's cost as
`f"{length * 2.2 / 1000.0:.0f} s"`. `int → float` overflows above `sys.float_info.max`, so any
`key_length` of 309 or more digits raised `OverflowError` **while its own refusal was being
formatted**. Measured before: 10 digits → `400`, 100 → `400`, 308 → `400`, **309 → `500`**,
400 → `500`, 1000 → `500`, with `Internal Server Error` on the wire and a traceback in the log.
The existing test used `key_length = 10**9` (ten digits) and passed.

This is the **third instance of one shape** in this phase: a request refused *correctly*, and
then the code reporting the refusal falling over while quoting the input back. §9.2 was the
second (a body nested 2000 deep, `RecursionError` inside the `422` handler); a bare `NaN` in the
error body was the first. Each was fixed where it was found, which is why there was a third.

**Fixed as a rule rather than as an instance**, in `sih141/web/limits.py`:

> Nothing that renders a refusal may compute on caller input, and every caller-supplied value
> reaches a message or a body through `safe_text()` or `json_safe()`, both of which are total.

`safe_text()` catches whatever `repr` throws (an integer beyond `sys.get_int_max_str_digits()`
is the one this API meets; it reports the digit count instead) and truncates what it returns.
`json_safe()` already bounded depth and encodability and now bounds length too. No message
anywhere multiplies a caller's number: the over-ceiling refusal quotes the **measured**
`COST_TABLE` row at the ceiling instead, which is a figure the suite already pins.

Measured after: 10, 100, 308, 309, 400, 1000 and 4300 digits are **all `400`**, all naming the
cap, all under 1100 bytes.

**The test is written against the shape, not the instance.**
`test_no_field_can_be_made_to_crash_its_own_refusal` crosses all nine request fields with nine
values that are hard to *render* (`NaN`, `±Infinity`, 309- and 4300-digit integers, a 20 KB
string, 400-deep lists and objects), 81 cases in all, and asserts every one comes back
`400`/`413`/`422` carrying JSON with no traceback. It contains all three instances and had to
know about none of them. Run against the pre-fix tree it fails on exactly the two cases that
were broken.

### 11.3 No request body size cap, ~9× memory amplification: MAJOR

`RequestRefused.to_dict()` echoed the offending value twice with no bound on either, once inside
`message` via `{!r}` and once as `value`, and there was no cap on the body itself. Measured
by the auditor: a 1,000,014-byte request produced a 2,000,707-byte response (**×2.00**); 64 MB in
→ 134 MB out; 128 MB in → 268 MB out, RSS 347 MB; 256 MB in → 537 MB out, RSS **2,363 MB**,
still 2,365 MB after 20 s idle and 2,375 MB after a subsequent normal run. Three concurrent
200 MB bodies: three 419 MB responses and a settled RSS of 5,520 MB.

`MAX_CONCURRENT_RUNS` offered nothing, and that is worth stating plainly: the gate is taken
**after** validation, so a request refused by a cap never reaches it. The gate protects the CPU
and only the CPU.

**Fixed** with `_BodyLimit`, a pure-ASGI middleware installed outermost. It is pure ASGI because
the point is that the bytes are never accumulated, and a middleware handed a `Request` has
already lost that argument. A declared `Content-Length` over `MAX_REQUEST_BYTES` (65536) is
refused with nothing read; a body without one is counted as it arrives and abandoned the moment
the count passes the ceiling. Everything under the ceiling is replayed unchanged.

Measured after, same request sizes: 100 KB → `413` in 295 bytes (**×0.0029**), 1 MB → `413` in
296 bytes (**×0.0003**), 8 MB → `413` in 296 bytes. A 1 KB body still gets its `400` with the
offending value quoted, truncated at 200 characters with a count of what was dropped. The
ceiling is published under `/api/defaults` → `limits.max_request_bytes` and printed in the
start-up banner.

Measured against the **running server**, which is where the auditor's numbers were taken. A
64 MB body: `413`, **297 bytes** of response, **1.3 ms**, and `curl` reports `size_upload: 0`.
The declared `Content-Length` is refused before the body is sent at all. A 256 MB body: `413` in
816 ms, and the process's `WorkingSet64` is **111 MB before and 111 MB after**, unchanged, with
`GET /api/health` answering immediately afterwards. The auditor measured 2,363 MB, still held
20 s later and after a subsequent normal run.

### 11.4 The dead-service fallback did not exist on a fresh clone: MAJOR

`showRecorded` re-fetched `/static/data/recorded/<file>.json` on **every click** with no
in-memory copy, and the server sent no `Cache-Control`, so whether the fallback worked was
decided by Chrome's heuristic freshness, about a tenth of the file's age. Reproduced on a fresh
clone: page loaded, process killed, three recorded runs clicked → `could not load
run_outside_forgery.json: Failed to fetch`, same for `run_impersonation_full.json` and
`run_replay.json`, `NO RUN` on the stage each time, three `net::ERR_CONNECTION_REFUSED` in the
console. This document claimed all 13 kept working.

**Fixed** by loading the whole set (365 KB) once at boot, in parallel, into
`state.recordedPayloads`. `showRecorded` now contains no `fetch` at all, which is the property
the test asserts: *"showRecorded reaches the network; with the service dead that is the click
that fails, in front of the room."* The rail prints `13 of 13 held in this page's memory`, so a
partial preload is visible before the click that needs it.

Measured after, process killed with the page open. Three recorded runs clicked, and all three
render fully with the status line reading `(from memory)`: `Outside forgery` → `DETECTED`,
`Impersonation, both seams` → `NOTHING FIRED`, `Replay` → `DETECTED`.

### 11.5 The masthead never flipped when a *recorded* run failed: MAJOR

§9.4's fix put the mode repaint inside `startLiveRun`'s catch only. `showRecorded`'s catch called
`Render.refused` and `setStatus` and never touched `state.mode`, so three failed recorded clicks
against a dead process left `mode-chip` reading `LIVE API` (measured verbatim by the auditor),
and the recorded path is the one a presenter falls back to.

**Fixed** two ways, because with 11.4 in place the recorded path can no longer fail and so can no
longer *tell* anyone.

* One `noteTransportFailure()` that every failing path calls: the live run's catch, the live
  run's not-reachable guard, and the recorded loader's not-held branch. The test asserts the
  count of call sites rather than the presence of a string, because a fix that lives in one
  branch of one function is a fix for one branch of one function.
* A five-second `/api/health` poll, so the chip is **checked** rather than waiting to be
  surprised, and so it comes *back* to `LIVE API` by itself when the server is restarted, which
  is what an operator who has just fixed something needs to see.

Measured after: server killed with the page open, the chip reads
`RECORDED ONLY (13): API NOT REACHABLE` before the first recorded click completes; a cap refusal
with the service alive leaves it on `LIVE API`.

### 11.6 A cold load against a dead service behaved three different ways: MAJOR (docs)

Documented as *"the page itself is served by that process, so there is nothing to fall back to"*.
What actually happened: it rendered from cache, with the masthead asserting `RECORDED ONLY: API
NOT REACHABLE` above a rail containing **zero** recorded runs. The numeric honesty held. Every
control read `range not supplied by the API`, and the headline panel read `THE API DID NOT SUPPLY
THIS. Nothing is shown in its place.` But the chip promised a fallback mode that was empty. On
a tree whose files had just been edited, the same reload produced a third outcome: a blank page.

**Fixed** at the root by serving the frontend with `Cache-Control: no-cache` (revalidate before
reuse, not do-not-store). One behaviour now: a live server answers `304` over loopback in
microseconds; a dead one produces the browser's own error page (measured:
`chrome-error://chromewebdata/`). It also removes the stale-asset hazard §5 warns about. The
masthead gains a third state, `NOTHING LIVE: NO API AND NO RECORDED RUNS`, as defence in depth
for a browser or proxy that serves a stale shell anyway. The paragraph in §6 is rewritten.

### 11.7 The `NO RUN` panel blamed the server for a transport failure: MINOR

`Failed to fetch` against a process that is not running was rendered under *"The service refused
this request, so no session was generated and nothing was scored"*, followed by the `key_length`
cap's rationale, for a request nobody refused. The same copy appeared for a failed recorded-run
load, which is a static JSON file no cap has an opinion about. The **state** was right (fourth
state, stage cleared, raw reason shown); the attribution was invented.

**Fixed**: `refusalPanel(message, request, kind)` has two headings and two explanations.
Measured after. Cap refusal with the service alive: *"This run was refused / The service refused
this request …"* plus the cap paragraph, chip stays `LIVE API`. Transport failure: *"Nothing
answered this request / The request never reached a service. Nothing refused it and nothing
scored it …"*, no cap paragraph anywhere on the page, chip flips.

### 11.8 The banner advertised an address it had not bound: MINOR

Covered in §0. Measured before: banner with `http://127.0.0.1:8141`, then `Started server
process`, `Application startup complete`, then the bind error, ending on `Application shutdown
complete`. Measured after: `COULD NOT START`, the port named, **no address line at all**,
exit `1`.

### 11.9 Nothing listened on `::1`, MINOR (audited as *suspected*, confirmed at the socket)

Covered in §0. Confirmed here at the socket level in both directions: `--host 0.0.0.0` answered
on `127.0.0.1` and not on `[::1]`; `--host ::` answered on `[::1]` and not on `127.0.0.1`,
because Windows sets `IPV6_V6ONLY` by default.

The auditor could not demonstrate a *browser* failing this way and said so, so the browser half
was measured here rather than assumed. Chrome on this machine **does** fall back, and the cost is
latency: an IPv4-only server opened as `http://localhost:PORT` gave a time to first byte of
**319 ms**, against **7 ms** with a connect time of **0 ms** on the same page served by a
dual-bound server. So on this browser the defect is a third of a second on every navigation
rather than a failure, and on a browser that does not fall back it is a demo that will not
open at the address an operator types. Both families are bound now; both numbers go away.

### 11.10 Projector mode overflowed at 1024×768: MINOR

The classic projector resolution. `white-space: nowrap` on `.num` and `.state` put **307 px** of
the page off-screen with projector mode on: `documentElement.clientWidth` 1009,
`scrollWidth` **1316**, 28 elements past the viewport with no scrolling ancestor, including the
`⊢ PROVEN` and `MEASURED` chips that carry constraint 2 and the
`⊘ NO: ABOUT FOUR MINUTES PER SESSION` chip. Page-level overflow, not contained by the
`.table-wrap` scrollers, so reading them needed a horizontal page scroll.

**Fixed**: chips may wrap (`flex-wrap: wrap`, `max-width: 100%`) and the two definition-list
grids use `fit-content(16rem)` instead of `max-content`. A **number** still never breaks, because
`.num .value` sets `overflow-wrap: normal`, which overrides the `anywhere` it inherits, while
the prose and the comma-separated lists around it wrap at their spaces.

One more overflow surfaced while measuring: `Charts.bars` draws `row.unavailable` as SVG text
centred in the hatched cell, and the API's reason for an unevaluable CHSH statistic is a whole
sentence, which ran 66 px past the window edge. The chart now carries `NOT EVALUATED: see
below` and the sentence is rendered under it as text that wraps. It is moved, never dropped.

Measured after, all 13 recorded runs at 1024×768 with projector mode **on**:
`scrollWidth == clientWidth == 1009` on every one, zero uncontained overflowing elements.

### 11.11 `2.944` was attached to the wrong pair: MINOR (audited as *suspected*)

The headline panel's note, rendered verbatim on screen, read *"…is
`Detection.false_positive_bound`, never `eps` and never `evidence_bound`, which is a post hoc
statement about the signals that fired and a different claim: at `L = 384`, `eps = 1e-9` the two
differ by a factor of `2.944`."* The nearest antecedent for *"the two"* is the
`false_positive_bound`/`evidence_bound` pair the clause has just contrasted.

Measured at `L = 384`, `eps = 1e-9`, honest, seed 7: `false_positive_bound = 3.3964e-10`,
`eps = 1e-9`, ratio **2.944** exactly (it is `slack_factor`), `evidence_bound = null`. On a run
where something fires (count-starvation, `L = 192`), `false_positive_bound = 3.8649e-10` and
`evidence_bound = 5.4210e-20`, a ratio of about **7×10⁹**. So the sentence, read the way its
grammar invites, states a factor of 2.944 for a pair nine orders of magnitude apart, on the one
constraint that exists to stop those three numbers being confused. Every other statement of
2.944 in this repository binds it to the budget-versus-bound pair.

**Confirmed as a real defect** and fixed by naming the pair in the same clause as the number, and
by giving `evidence_bound` its own scale. `test_the_published_bound_note_names_the_pair_the_factor_belongs_to`
measures both ratios and asserts the sentence's structure, so the prose and the arithmetic cannot
drift apart again.

### 11.12 README pointed at "the three defects": MINOR

§9 describes four. Fixed, and the line now points at this section too.

### 11.13 "Both verifiers accept in every one of them" was false: found while writing the test

Not from the audit. `noise_null_calibration.second_null_note`, published by the API and rendered
on screen, and the same sentence in `driver.py`'s module docstring, claimed that both verifiers
accept in every one of the twelve honest noisy runs 11.1 rests on. Writing the test that asserts
it produced `{'accepted', 'rejected'}`.

Measured over those twelve seeds: the pair of outcomes is **identical under all three null
settings on every seed**, which it must be, since the verifiers' outcomes belong to the protocol
and the nulls belong to the detector. And it is **7 seeds where both accept and 5 where Bob
rejects** the honest signature. A link at the design noise level costs the signature something,
and that is a separate fact from anything the detector said.

The claim is corrected in all three places it appeared and the corrected version is now the
stronger statement: the nulls move the *detector* and do not move the *verifiers* at all. This is
the clearest illustration in the phase of why constraint 1 keeps the two questions apart.

### What the round is worth reading for

Every one of §9's four defects had a passing test. Every one of those tests asserted that a
**string was present in a file**: the right check for "has someone deleted this" and no check at
all for "does this work". The tests added here measure the thing that would differ if the fix
were absent: the status code, the response size, the number of sockets that accept a connection,
the ratio of two bounds, the count of call sites that route through the shared handler, the
absence of `fetch` inside one named function. Verified by running the new test files against a
clean checkout of the pre-fix commit rather than by believing they would: **34 test IDs across 25
test functions fail** there, 23 IDs in `test_web_api.py` and 11 in `test_web_frontend.py`.

Eleven of those are frontend tests and they are still static analysis, because this repository
has no JavaScript runtime and must not grow one. What changed is *scope*: they extract a single
function body by brace matching and assert about **that**, so "`showRecorded` reaches the
network" is a property of the recorded path, where "the file contains the word `fetch`" was a
property of nothing.

Where a check genuinely cannot run in Python (a browser laying out a page), the measurement was
taken by driving the running screen and is recorded above with its numbers, and the test pins the
CSS property that produced it.

## 10. Where the code is

| path | what |
|---|---|
| `sih141/web/__main__.py` | the one command; `--host`, `--port`, `--log-level` |
| `sih141/web/api.py` | `create_app()`, the six endpoints, the concurrency gate |
| `sih141/web/limits.py` | every cap, `RequestRefused`, `json_safe`, `safe_text` |
| `sih141/web/driver.py` | mounts an adversary, runs a session, splits ground truth out |
| `sih141/web/catalogue.py` | the attack roster and its `detectable`/`assumption` fields |
| `sih141/web/payload.py` | the `run` object the screen reads, and `nulls_stated()` |
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
   masthead and an empty stage with no explanation. Not misleading, just unhelpful, and one
   paragraph fixes it.
3. **`docs/METRICS.md` is stale**, generated 2026-09-03 before the web module existed. It is
   generated, not hand-written: `python tools/metrics.py` refreshes it, and it already lists
   `sih141/web` in its module set. It re-runs the full suite, so budget about half an hour.
