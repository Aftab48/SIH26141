## roc

**Provenance.**

- commit: `f94d9feb73be`
- worker counts: [20]
- produced by: `python tools/sweep.py run roc --workers 20`

### Run outcomes, by cell and count ordering

| cell | count_exchange_timing | runs | parties | accepted | rejected | refused | not_asked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honest | before-forwarding | 40 | 80 | 80 | 0 | 0 | 0 |
| honest-unchecked | before-forwarding | 40 | 80 | 80 | 0 | 0 | 0 |
| outside-forgery | before-forwarding | 40 | 80 | 0 | 80 | 0 | 0 |
| recipient-forgery | before-forwarding | 40 | 80 | 40 | 0 | 40 | 0 |
| recipient-forgery-after | after-forwarding | 40 | 80 | 5 | 35 | 40 | 0 |
| replay | before-forwarding | 40 | 80 | 40 | 0 | 40 | 0 |
| starvation | before-forwarding | 40 | 80 | 40 | 0 | 40 | 0 |
| starvation-selective | before-forwarding | 40 | 80 | 58 | 0 | 22 | 0 |
| impersonation-signing | before-forwarding | 40 | 80 | 0 | 80 | 0 | 0 |
| impersonation-full | before-forwarding | 40 | 80 | 80 | 0 | 0 | 0 |
| channel-bob | before-forwarding | 40 | 80 | 55 | 25 | 0 | 0 |
| tol-honest | before-forwarding | 40 | 80 | 80 | 0 | 0 | 0 |
| tol-p05 | before-forwarding | 40 | 80 | 67 | 13 | 0 | 0 |
| tol-p20 | before-forwarding | 40 | 80 | 32 | 48 | 0 | 0 |
| tol-p35 | before-forwarding | 40 | 80 | 5 | 75 | 0 | 0 |

Regenerate: `python tools/sweep.py reduce roc --results 'C:\Users\Aftab\.sih141\results'`

- Complete: every cell has all the trials its manifest asked for, and no trial index is missing below the highest present. A trial whose scenario raised would leave no file, so this is checked rather than assumed.
- `parties` is the denominator, and it is two verifiers per run -- every run has a Bob and a Charlie whatever became of them. accepted + rejected + refused + not_asked = parties, exactly. `not_asked` is a party the protocol never put the question to, which is a third thing again from a refusal.
- `refused` is a no-verdict, not a rejection. A run where a verifier could not score the declaration is neither an acceptance nor a detection, and it is never folded into either.
- `count_exchange_timing` is a column, never averaged over: the two orderings give different answers to the same attack.

### Detector signals, measured rates apart from proven bounds

| cell | count_exchange_timing | hypothesis | runs | attacked | flagged on attacked (measured) | flagged on clean (measured) | refusals (any party) | max proven FP bound | null_is_noiseless | withheld families |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| honest | before-forwarding | honest | 40 | 0 | no trials | 0/40 = 0.000 [0.000, 0.142] | 0 | 3.396e-10 | yes | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 40 | 0 | no trials | 0/40 = 0.000 [0.000, 0.142] | 0 | 2.782e-10 | yes | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 0 | 3.396e-10 | yes | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 40 | 3.396e-10 | yes | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 40 | 3.396e-10 | yes | not evaluated (1) |
| replay | before-forwarding | replay | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 40 | 3.396e-10 | yes | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 40 | 3.396e-10 | yes | not evaluated (1) |
| starvation-selective | before-forwarding | count-starvation | 40 | 22 | 22/22 = 1.000 [0.768, 1.000] | 0/18 = 0.000 [0.000, 0.269] | 22 | 3.396e-10 | yes | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 0 | 3.396e-10 | yes | not evaluated (2) |
| impersonation-full | before-forwarding | impersonation-full | 40 | 40 | undetectable-by-construction | no trials | 0 | 3.396e-10 | yes | - |
| channel-bob | before-forwarding | channel-manipulation | 40 | 40 | 40/40 = 1.000 [0.858, 1.000] | no trials | 0 | 3.396e-10 | yes | not evaluated (1) |
| tol-honest | before-forwarding | channel-manipulation | 40 | 0 | no trials | 0/40 = 0.000 [0.000, 0.142] | 0 | 7.312e-10 | no | - |
| tol-p05 | before-forwarding | channel-manipulation | 40 | 40 | 0/40 = 0.000 [0.000, 0.142] | no trials | 0 | 7.310e-10 | no | - |
| tol-p20 | before-forwarding | channel-manipulation | 40 | 40 | 0/40 = 0.000 [0.000, 0.142] | no trials | 0 | 7.227e-10 | no | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 40 | 40 | 0/40 = 0.000 [0.000, 0.142] | no trials | 0 | 7.199e-10 | no | not evaluated (1) |

Regenerate: `python tools/sweep.py reduce roc --results 'C:\Users\Aftab\.sih141\results'`

- `flagged on attacked (measured)` and `flagged on clean (measured)` are MEASUREMENTS with a sample size, shown as k/n with a 99% Wilson interval. There is no false-negative bound and there cannot be one from a transcript.
- `max proven FP bound` is PROVEN under the honest null -- the largest Detection.false_positive_bound in the group. It shares no column with a measured rate.
- `attacked` counts runs whose adversary engaged, read off the adversary's own log. An untargeted run is byte-identical to an honest one and is scored as one.
- `refusals (any party)` counts runs where AT LEAST ONE verifier reached no verdict. It is shown beside the rates and added to neither denominator: a refusal is not a rejection, and it is not a miss either -- the detector scored every run in both denominators, refusal or not. A row whose count equals its `runs` did not necessarily deny transfer, and this is where an experiment's own per-party table earns its place: at L = 96 the recipient forger refuses on all 400 runs under either ordering, but before forwarding it is CHARLIE who reaches no verdict (a denial of transfer) and after forwarding it is BOB, while Charlie returns a real 120/400 acceptance. Same count, opposite reading, which is why the column is named for what it actually counts.
- `null_is_noiseless` says whether the detector was given a noiseless null. On a genuinely noisy link that null is not the truth, honest runs depart from it, and the mismatch members fire correctly -- so a `yes` here is a caveat on the row, not a detail.
- `undetectable-by-construction` means an assumption rules detection out for that hypothesis -- full impersonation under (AUTH). It is never a blank, a dash or a zero.
- Families withheld on at least one run in this table, reported as `not evaluated` and never as passed: channel: this run published no check rounds, so the whole channel family is unevaluable -- an unmonitored link is not a clean one, channel:Bob/0:chsh, channel:Bob/1:chsh, channel:Charlie/0:chsh, channel:Charlie/1:chsh.

### Per-trial cost, by cell

| cell | key_length | trials | session s (total) | session s (mean) | detect s (mean) | ms/position |
| --- | --- | --- | --- | --- | --- | --- |
| honest | 384 | 40 | 84.18 | 2.104 | 0.0300 | 5.480 |
| honest-unchecked | 384 | 40 | 95.91 | 2.398 | 0.0267 | 6.244 |
| outside-forgery | 384 | 40 | 104.27 | 2.607 | 0.0309 | 6.789 |
| recipient-forgery | 384 | 40 | 103.65 | 2.591 | 0.0314 | 6.748 |
| recipient-forgery-after | 384 | 40 | 108.41 | 2.710 | 0.0330 | 7.058 |
| replay | 384 | 40 | 160.48 | 4.012 | 0.0317 | 10.448 |
| starvation | 384 | 40 | 111.31 | 2.783 | 0.0295 | 7.247 |
| starvation-selective | 384 | 40 | 103.50 | 2.588 | 0.0314 | 6.738 |
| impersonation-signing | 384 | 40 | 104.18 | 2.604 | 0.0293 | 6.782 |
| impersonation-full | 384 | 40 | 108.62 | 2.716 | 0.0319 | 7.072 |
| channel-bob | 384 | 40 | 103.08 | 2.577 | 0.0292 | 6.711 |
| tol-honest | 384 | 40 | 108.17 | 2.704 | 0.0324 | 7.042 |
| tol-p05 | 384 | 40 | 105.06 | 2.627 | 0.0310 | 6.840 |
| tol-p20 | 384 | 40 | 98.03 | 2.451 | 0.0270 | 6.382 |
| tol-p35 | 384 | 40 | 93.91 | 2.348 | 0.0245 | 6.114 |

Regenerate: `python tools/sweep.py reduce roc --results 'C:\Users\Aftab\.sih141\results'`

- Timings are wall clock inside the worker, so at N workers the sum of `session s (total)` exceeds the sweep's own wall clock by roughly the achieved speedup. That comparison is the check on the runner: if it does not, one of the two numbers is wrong.
- **`ms/position` HERE IS NOT THE PROTOCOL'S COST.** It carries the contention of whatever worker count produced these records -- see `worker counts` in the provenance above. Measured on this machine, a trial takes 1.61x longer at twenty workers than at one at L = 384, and 2.53x at L = 768, because the cores share an all-core turbo budget and an L3. The single-threaded reference is `sih141.eval.perf.REFERENCE_MS_PER_POSITION`; regenerate it with `python tools/sweep.py perf`. Multiplying the figure below by a key length to project a production run overstates it by that factor.
- Timings are excluded from a record's fingerprint, so they cannot affect the reproducibility claim -- and every other table here is byte-identical at one worker and at twenty.

### ROC grid: measured detection against a proven false-positive bound, per adversary, per derived operating point

| cell | count_exchange_timing | hypothesis | eps | proven FP bound | attacked | detected (measured) | clean | false alarms (measured) | refusals | null_is_noiseless | bound unconditional | dominance p_e | withheld |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| honest | before-forwarding | honest | 5e-01 | 2.4341e-01 | 0 | no trials | 40 | 3/40 = 0.075 [0.019, 0.252] | 0 | yes | yes | 0.007194 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-01 | 4.6368e-02 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.001097 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-02 | 4.5959e-03 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000105 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-03 | 4.0167e-04 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000010 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-04 | 4.9585e-05 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000001 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-05 | 4.3035e-06 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-06 | 3.9249e-07 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-07 | 4.1039e-08 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-08 | 4.0873e-09 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-09 | 3.3964e-10 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-12 | 2.9010e-13 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-15 | 3.8361e-16 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-18 | 4.5664e-19 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest | before-forwarding | honest | 1e-24 | 1.7197e-25 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (2) |
| honest | before-forwarding | honest | 1e-30 | 1.6604e-31 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (2) |
| honest-unchecked | before-forwarding | honest | 5e-01 | 1.7723e-01 | 0 | no trials | 40 | 3/40 = 0.075 [0.019, 0.252] | 0 | yes | yes | 0.013077 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-01 | 3.4288e-02 | 0 | no trials | 40 | 1/40 = 0.025 [0.003, 0.182] | 0 | yes | yes | 0.004162 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-02 | 3.8130e-03 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.001164 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-03 | 3.6222e-04 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000356 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-04 | 3.2646e-05 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000111 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-05 | 2.9525e-06 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000035 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-06 | 2.7681e-07 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000011 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-07 | 2.7991e-08 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000004 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-08 | 3.3038e-09 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000001 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-09 | 2.7818e-10 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-12 | 2.8227e-13 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-15 | 2.0124e-16 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-18 | 4.0365e-19 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (1) |
| honest-unchecked | before-forwarding | honest | 1e-24 | 1.9562e-25 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (2) |
| honest-unchecked | before-forwarding | honest | 1e-30 | 1.4660e-31 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | yes | yes | 0.000000 | not evaluated (2) |
| outside-forgery | before-forwarding | outside-forgery | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.007270 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.001108 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000106 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000011 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000001 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| outside-forgery | before-forwarding | outside-forgery | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| outside-forgery | before-forwarding | outside-forgery | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| recipient-forgery | before-forwarding | recipient-forgery | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.007194 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.001097 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000105 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000010 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000001 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| recipient-forgery | before-forwarding | recipient-forgery | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.008818 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.002802 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000784 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000240 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000075 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000024 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000007 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000002 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000001 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| recipient-forgery-after | after-forwarding | recipient-forgery | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| replay | before-forwarding | replay | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.007048 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.001075 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000103 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000010 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000001 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| replay | before-forwarding | replay | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| replay | before-forwarding | replay | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| starvation | before-forwarding | count-starvation | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.007048 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.001075 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000103 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000010 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000001 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (1) |
| starvation | before-forwarding | count-starvation | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| starvation | before-forwarding | count-starvation | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 40 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 5e-01 | 2.4341e-01 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 1/18 = 0.056 [0.007, 0.344] | 22 | yes | yes | 0.007194 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-01 | 4.6368e-02 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.001097 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-02 | 4.5959e-03 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000105 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-03 | 4.0167e-04 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000010 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-04 | 4.9585e-05 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000001 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-05 | 4.3035e-06 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-06 | 3.9249e-07 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-07 | 4.1039e-08 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-08 | 4.0873e-09 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-09 | 3.3964e-10 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-12 | 2.9010e-13 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-15 | 3.8361e-16 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-18 | 4.5664e-19 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (2) |
| starvation-selective | before-forwarding | count-starvation | 1e-24 | 1.7197e-25 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (3) |
| starvation-selective | before-forwarding | count-starvation | 1e-30 | 1.6604e-31 | 22 | 22/22 = 1.000 [0.768, 1.000] | 18 | 0/18 = 0.000 [0.000, 0.269] | 22 | yes | yes | 0.000000 | not evaluated (3) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.007120 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.001086 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000104 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000010 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000001 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (3) |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (3) |
| impersonation-full | before-forwarding | impersonation-full | 5e-01 | 2.4341e-01 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.007194 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-01 | 4.6368e-02 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.001097 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-02 | 4.5959e-03 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000105 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-03 | 4.0167e-04 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000010 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-04 | 4.9585e-05 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000001 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-05 | 4.3035e-06 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-06 | 3.9249e-07 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-07 | 4.1039e-08 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-08 | 4.0873e-09 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-09 | 3.3964e-10 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-12 | 2.9010e-13 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-15 | 3.8361e-16 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-18 | 4.5664e-19 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | - |
| impersonation-full | before-forwarding | impersonation-full | 1e-24 | 1.7197e-25 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| impersonation-full | before-forwarding | impersonation-full | 1e-30 | 1.6604e-31 | 40 | undetectable-by-construction | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 5e-01 | 2.4341e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.007120 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-01 | 4.6368e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.001086 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-02 | 4.5959e-03 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000104 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-03 | 4.0167e-04 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000010 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-04 | 4.9585e-05 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000001 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-05 | 4.3035e-06 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-06 | 3.9249e-07 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-07 | 4.1039e-08 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-08 | 4.0873e-09 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-09 | 3.3964e-10 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-12 | 2.9010e-13 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-15 | 3.8361e-16 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-18 | 4.5664e-19 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (1) |
| channel-bob | before-forwarding | channel-manipulation | 1e-24 | 1.7197e-25 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| channel-bob | before-forwarding | channel-manipulation | 1e-30 | 1.6604e-31 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | yes | yes | 0.000000 | not evaluated (2) |
| tol-honest | before-forwarding | channel-manipulation | 5e-01 | 4.3935e-01 | 0 | no trials | 40 | 4/40 = 0.100 [0.030, 0.284] | 0 | no | no | 0.007120 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-01 | 8.4898e-02 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.001086 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-02 | 8.4270e-03 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000104 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-03 | 8.7023e-04 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000010 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-04 | 9.1824e-05 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000001 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-05 | 8.4253e-06 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-06 | 7.7926e-07 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-07 | 7.8931e-08 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-08 | 8.3920e-09 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-09 | 7.3122e-10 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-12 | 6.7430e-13 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-15 | 7.5735e-16 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-18 | 8.2258e-19 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | - |
| tol-honest | before-forwarding | channel-manipulation | 1e-24 | 4.6895e-25 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-honest | before-forwarding | channel-manipulation | 1e-30 | 4.2010e-31 | 0 | no trials | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p05 | before-forwarding | channel-manipulation | 5e-01 | 4.4143e-01 | 40 | 4/40 = 0.100 [0.030, 0.284] | 0 | no trials | 0 | no | no | 0.007425 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-01 | 8.4700e-02 | 40 | 1/40 = 0.025 [0.003, 0.182] | 0 | no trials | 0 | no | no | 0.001132 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-02 | 8.4527e-03 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000108 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-03 | 8.5870e-04 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000011 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-04 | 9.1281e-05 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000001 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-05 | 8.3325e-06 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-06 | 7.6777e-07 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-07 | 7.7712e-08 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-08 | 8.3131e-09 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-09 | 7.3101e-10 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-12 | 6.6469e-13 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-15 | 7.6337e-16 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-18 | 8.3127e-19 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | - |
| tol-p05 | before-forwarding | channel-manipulation | 1e-24 | 4.6623e-25 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p05 | before-forwarding | channel-manipulation | 1e-30 | 4.1692e-31 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 5e-01 | 4.4087e-01 | 40 | 26/40 = 0.650 [0.447, 0.810] | 0 | no trials | 0 | no | no | 0.007270 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-01 | 8.4727e-02 | 40 | 13/40 = 0.325 [0.171, 0.528] | 0 | no trials | 0 | no | no | 0.001108 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-02 | 8.4527e-03 | 40 | 7/40 = 0.175 [0.071, 0.372] | 0 | no trials | 0 | no | no | 0.000106 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-03 | 8.6332e-04 | 40 | 4/40 = 0.100 [0.030, 0.284] | 0 | no trials | 0 | no | no | 0.000011 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-04 | 9.0929e-05 | 40 | 1/40 = 0.025 [0.003, 0.182] | 0 | no trials | 0 | no | no | 0.000001 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-05 | 8.2817e-06 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-06 | 7.7910e-07 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-07 | 7.7959e-08 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-08 | 8.1930e-09 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-09 | 7.2267e-10 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-12 | 6.7259e-13 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-15 | 7.4804e-16 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-18 | 8.3041e-19 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-24 | 4.6725e-25 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (2) |
| tol-p20 | before-forwarding | channel-manipulation | 1e-30 | 4.1333e-31 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (2) |
| tol-p35 | before-forwarding | channel-manipulation | 5e-01 | 4.4170e-01 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | no | no | 0.007120 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-01 | 8.5351e-02 | 40 | 40/40 = 1.000 [0.858, 1.000] | 0 | no trials | 0 | no | no | 0.001086 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-02 | 8.4199e-03 | 40 | 39/40 = 0.975 [0.818, 0.997] | 0 | no trials | 0 | no | no | 0.000104 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-03 | 8.5905e-04 | 40 | 30/40 = 0.750 [0.547, 0.882] | 0 | no trials | 0 | no | no | 0.000010 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-04 | 9.2193e-05 | 40 | 18/40 = 0.450 [0.269, 0.645] | 0 | no trials | 0 | no | no | 0.000001 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-05 | 8.2678e-06 | 40 | 11/40 = 0.275 [0.136, 0.478] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-06 | 7.8003e-07 | 40 | 3/40 = 0.075 [0.019, 0.252] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-07 | 7.7544e-08 | 40 | 1/40 = 0.025 [0.003, 0.182] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-08 | 8.2927e-09 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-09 | 7.1991e-10 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-12 | 6.6129e-13 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-15 | 7.5683e-16 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-18 | 8.1419e-19 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (1) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-24 | 4.7352e-25 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (2) |
| tol-p35 | before-forwarding | channel-manipulation | 1e-30 | 4.2044e-31 | 40 | 0/40 = 0.000 [0.000, 0.142] | 0 | no trials | 0 | no | no | 0.000000 | not evaluated (2) |

Regenerate: `python tools/sweep.py reduce roc --results 'C:\Users\Aftab\.sih141\results'`

- **The two axes are different kinds of number.** `proven FP bound` is Detection.false_positive_bound: a union bound under the honest null, true of every run that will ever be scored. `detected (measured)` and `false alarms (measured)` are MEASUREMENTS with a sample size, shown as k/n with a 99% Wilson interval. There is no false-negative bound and there cannot be one from a transcript, so the two never share a column.
- **Denominators.** `detected` is over `attacked`: runs whose adversary engaged, counted off the adversary's own log and never off the cell's intent. `false alarms` is over `clean`: runs on which no adversary acted, which includes the untargeted runs of a selective cell -- such a run is byte-identical to an honest one and is scored as one.
- **Aborts are neither.** `refusals` counts runs where a verifier reached no verdict. They are shown in their own column and are added to nothing: a refusal is not a rejection, and it is not a miss either. The detector returned a verdict on every run in the denominators above, refusal or not, so no run has been dropped.
- **`count_exchange_timing` is a column, never averaged over.** The two orderings give different answers to the same attack; the recipient-forgery rows are the case in point, where one ordering produces a rejection and the other a denial of transfer.
- **`undetectable-by-construction`** means an assumption rules detection out for that hypothesis -- full impersonation under (AUTH). It is never a blank, a dash or a zero. The clean column on such a row is still a measurement, because the assumption is about the attack and not about the runs it left alone.
- **`null_is_noiseless`** says whether the mismatch members were scored against a link on which a matched position never disagrees. On a genuinely noisy link that null is not the truth, honest runs depart from it, and the mismatch members fire correctly -- so `yes` on an attacked row is a caveat on the row, not a detail. The `tol-` cells are the same physics scored against the link's true error rate (0.025), and they are the only cells here whose curve has a shape.
- **`dominance p_e`** is dominance_noise_level() at this budget and this group's median matched count, against the party cut s_a. Above that link error rate every run the mismatch member flags is a run the verifier has already rejected, and its marginal information is zero. Published beside the rate rather than in a footnote because the design noise level 2*s_a is larger than it at the default parameters.
- **Every point is derived.** The only argument that moves between rows of one cell is `eps`, handed to the shipped detect(). No threshold was fitted, chosen or nudged on attack data (D7).
- Withheld somewhere in this table, reported as `not evaluated` and never as passed: channel: this run published no check rounds, so the whole channel family is unevaluable -- an unmonitored link is not a clean one, channel:Bob/0:chsh, channel:Bob/1:chsh, channel:Charlie/0:chsh, channel:Charlie/1:chsh, structural:evidence-abort.
- Complete: every cell has all the trials its manifest asked for, and no trial index is missing below the highest present. A trial whose scenario raised would leave no file, so this is checked rather than assumed.

### Where each adversary's curve moves, and whether it is monotone

| cell | count_exchange_timing | hypothesis | attacked | clean | at eps=5e-01 (measured) | at eps=1e-09 (measured) | at eps=1e-30 (measured) | breaks at | up-set holds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| honest | before-forwarding | honest | 0 | 40 | no trials | no trials | no trials | no attacked runs | yes |
| honest-unchecked | before-forwarding | honest | 0 | 40 | no trials | no trials | no trials | no attacked runs | yes |
| outside-forgery | before-forwarding | outside-forgery | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| recipient-forgery | before-forwarding | recipient-forgery | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| recipient-forgery-after | after-forwarding | recipient-forgery | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| replay | before-forwarding | replay | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| starvation | before-forwarding | count-starvation | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| starvation-selective | before-forwarding | count-starvation | 22 | 18 | 22/22 = 1.000 [0.768, 1.000] | 22/22 = 1.000 [0.768, 1.000] | 22/22 = 1.000 [0.768, 1.000] | never below 1.0 | yes |
| impersonation-signing | before-forwarding | impersonation-signing-seam | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| impersonation-full | before-forwarding | impersonation-full | 40 | 0 | undetectable-by-construction | undetectable-by-construction | undetectable-by-construction | undetectable-by-construction | yes |
| channel-bob | before-forwarding | channel-manipulation | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | 40/40 = 1.000 [0.858, 1.000] | never below 1.0 | yes |
| tol-honest | before-forwarding | channel-manipulation | 0 | 40 | no trials | no trials | no trials | no attacked runs | yes |
| tol-p05 | before-forwarding | channel-manipulation | 40 | 0 | 4/40 = 0.100 [0.030, 0.284] | 0/40 = 0.000 [0.000, 0.142] | 0/40 = 0.000 [0.000, 0.142] | below 1.0 at every budget on the ladder | yes |
| tol-p20 | before-forwarding | channel-manipulation | 40 | 0 | 26/40 = 0.650 [0.447, 0.810] | 0/40 = 0.000 [0.000, 0.142] | 0/40 = 0.000 [0.000, 0.142] | below 1.0 at every budget on the ladder | yes |
| tol-p35 | before-forwarding | channel-manipulation | 40 | 0 | 40/40 = 1.000 [0.858, 1.000] | 0/40 = 0.000 [0.000, 0.142] | 0/40 = 0.000 [0.000, 0.142] | 1e-02 | yes |

Regenerate: `python tools/sweep.py reduce roc --results 'C:\Users\Aftab\.sih141\results'`

- `breaks at` is the loosest budget at which the measured detection rate first falls below 1.0. `never below 1.0` means the curve is flat at the ceiling across the whole ladder -- a result about how large the separation is, not a measurement that failed. `below 1.0 at every budget` means it never reached the ceiling, which is a different fact and is not abbreviated to a budget value.
- `up-set holds` is checked per RUN, not per rate: because every budget scores the same transcripts, a run that fires at a tighter eps must fire at every looser one. A `no` here is a finding about a threshold and is not smoothed over.
- The `at eps=1e-09` column is the one Phase 4 section 5 published, at the same n = 40 and the same key length, so the two are directly comparable.
- ABORTS: every rate here is over `attacked` or `clean`, and a run where a verifier reached no verdict stays in whichever of the two it belongs to -- a refusal is not a rejection and it is not a miss. The grid above carries the per-cell `refusals` count, and the recipient-forgery rows are the case worth reading there: one ordering is a denial of transfer and the other a forgery rate.

### Against the Phase 3 prototype: what the derivation cost

| detector | attacked arms separated | false alarms (measured) | false-alarm bound (proven) | how the threshold was chosen |
| --- | --- | --- | --- | --- |
| Phase 3 prototype (thresholds not derived) | 4 of 5 adversaries at 100% | 0/80 observed | none -- there is no null to invert | tuned on the runs in front of it |
| Phase 4 detector at eps=1e-09, noiseless null | 8 of 8 attacked arms at 100%; 1 arm undetectable-by-construction | 0/98 = 0.000 [0.000, 0.063] observed | 3.3964e-10 proven, per run, under the honest null | derived from a stated null and a concentration inequality (D7) |
| Phase 4 detector at eps=1e-09, true rate as null | 0 of 3 attacked arms at 100% | 0/40 = 0.000 [0.000, 0.142] observed | 7.3122e-10 proven, per run, under the honest null | derived from a stated null and a concentration inequality (D7) |

Regenerate: `python tools/sweep.py reduce roc --results 'C:\Users\Aftab\.sih141\results'`

- The two false-alarm columns are not the same kind of statement and must not be read as a like-for-like improvement. `0/80` and the observed column here are both OBSERVATIONS, and both are consistent with a true false-alarm rate of a few percent. The proven column is a statement about every run that will ever be scored. The sample size is what the derivation makes irrelevant.
- The two experiments share no parameter set, seed set or arm list, so the sensible reading is `the derivation did not cost detection`, not `the derived detector is better`.
- **A lower detection rate from a derived threshold is a better result than a higher rate from a tuned one.** Where a rate here is below the prototype's, that is the correct trade and not a regression: a tuned cut buys power on the runs it was tuned on and says nothing about the next hundred thousand. This family reports the rate it measures and does not move a threshold to improve it (D7).
- The `tol-` cells are where the derived detector does give ground, and the reason is stated rather than tuned away: once the link's own error rate is admitted into the null, an adversary at or near that level is inside the noise the protocol already tolerates. That is a result about the protocol's observability.
- DENOMINATORS AND ABORTS: `false alarms (measured)` is over the clean runs of the arms in that row's null -- the untargeted runs of a selective cell included, since such a run is byte-identical to an honest one -- and the count is printed rather than implied. None of those runs reached a no-verdict; where an arm does refuse it is counted in the grid's own `refusals` column and is added to neither denominator.
