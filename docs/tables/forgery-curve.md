## forgery-curve

**Provenance.**

- commit: `f94d9feb73be`
- worker counts: [20]
- produced by: `python tools/sweep.py run forgery-curve --workers 20`

### Run outcomes, by cell and count ordering

| cell | count_exchange_timing | runs | parties | accepted | rejected | refused | not_asked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| eve9 | before-forwarding | 400 | 800 | 127 | 631 | 42 | 0 |
| eve15 | before-forwarding | 400 | 800 | 48 | 748 | 4 | 0 |
| eve24 | before-forwarding | 400 | 800 | 12 | 788 | 0 | 0 |
| eve30 | before-forwarding | 400 | 800 | 3 | 797 | 0 | 0 |
| eve24after | after-forwarding | 400 | 800 | 10 | 790 | 0 | 0 |
| bob96before | before-forwarding | 400 | 800 | 400 | 0 | 400 | 0 |
| bob96after | after-forwarding | 400 | 800 | 120 | 280 | 400 | 0 |
| bob192before | before-forwarding | 400 | 800 | 400 | 0 | 400 | 0 |
| bob192after | after-forwarding | 400 | 800 | 63 | 337 | 400 | 0 |
| bob384before | before-forwarding | 400 | 800 | 400 | 0 | 400 | 0 |
| bob384after | after-forwarding | 400 | 800 | 49 | 351 | 400 | 0 |
| bob768before | before-forwarding | 400 | 800 | 400 | 0 | 400 | 0 |
| bob768after | after-forwarding | 400 | 800 | 11 | 389 | 400 | 0 |
| bob1200before | before-forwarding | 400 | 800 | 400 | 0 | 400 | 0 |
| bob1200after | after-forwarding | 400 | 800 | 6 | 394 | 400 | 0 |

Regenerate: `python tools/sweep.py reduce forgery-curve --results 'C:\Users\Aftab\.sih141\results'`

- Complete: every cell has all the trials its manifest asked for, and no trial index is missing below the highest present. A trial whose scenario raised would leave no file, so this is checked rather than assumed.
- `parties` is the denominator, and it is two verifiers per run -- every run has a Bob and a Charlie whatever became of them. accepted + rejected + refused + not_asked = parties, exactly. `not_asked` is a party the protocol never put the question to, which is a third thing again from a refusal.
- `refused` is a no-verdict, not a rejection. A run where a verifier could not score the declaration is neither an acceptance nor a detection, and it is never folded into either.
- `count_exchange_timing` is a column, never averaged over: the two orderings give different answers to the same attack.

### Detector signals, measured rates apart from proven bounds

| cell | count_exchange_timing | hypothesis | runs | attacked | flagged on attacked (measured) | flagged on clean (measured) | refusals (any party) | max proven FP bound | null_is_noiseless | withheld families |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| eve9 | before-forwarding | outside-forgery | 400 | 400 | 367/400 = 0.917 [0.875, 0.946] | no trials | 21 | 0.000e+00 | yes | not evaluated (2) |
| eve15 | before-forwarding | outside-forgery | 400 | 400 | 396/400 = 0.990 [0.967, 0.997] | no trials | 2 | 8.747e-12 | yes | not evaluated (2) |
| eve24 | before-forwarding | outside-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.627e-11 | yes | not evaluated (2) |
| eve30 | before-forwarding | outside-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 7.004e-11 | yes | not evaluated (2) |
| eve24after | after-forwarding | outside-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.627e-11 | yes | not evaluated (2) |
| bob96before | before-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 2.651e-10 | yes | not evaluated (1) |
| bob96after | after-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 2.651e-10 | yes | not evaluated (1) |
| bob192before | before-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 2.650e-10 | yes | not evaluated (1) |
| bob192after | after-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 2.650e-10 | yes | not evaluated (1) |
| bob384before | before-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 2.782e-10 | yes | not evaluated (1) |
| bob384after | after-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 2.782e-10 | yes | not evaluated (1) |
| bob768before | before-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 3.248e-10 | yes | not evaluated (1) |
| bob768after | after-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 3.248e-10 | yes | not evaluated (1) |
| bob1200before | before-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 3.770e-10 | yes | not evaluated (1) |
| bob1200after | after-forwarding | recipient-forgery | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 400 | 3.770e-10 | yes | not evaluated (1) |

Regenerate: `python tools/sweep.py reduce forgery-curve --results 'C:\Users\Aftab\.sih141\results'`

- `flagged on attacked (measured)` and `flagged on clean (measured)` are MEASUREMENTS with a sample size, shown as k/n with a 99% Wilson interval. There is no false-negative bound and there cannot be one from a transcript.
- `max proven FP bound` is PROVEN under the honest null -- the largest Detection.false_positive_bound in the group. It shares no column with a measured rate.
- `attacked` counts runs whose adversary engaged, read off the adversary's own log. An untargeted run is byte-identical to an honest one and is scored as one.
- `refusals (any party)` counts runs where AT LEAST ONE verifier reached no verdict. It is shown beside the rates and added to neither denominator: a refusal is not a rejection, and it is not a miss either -- the detector scored every run in both denominators, refusal or not. A row whose count equals its `runs` did not necessarily deny transfer, and this is where an experiment's own per-party table earns its place: at L = 96 the recipient forger refuses on all 400 runs under either ordering, but before forwarding it is CHARLIE who reaches no verdict (a denial of transfer) and after forwarding it is BOB, while Charlie returns a real 120/400 acceptance. Same count, opposite reading, which is why the column is named for what it actually counts.
- `null_is_noiseless` says whether the detector was given a noiseless null. On a genuinely noisy link that null is not the truth, honest runs depart from it, and the mismatch members fire correctly -- so a `yes` here is a caveat on the row, not a detail.
- `undetectable-by-construction` means an assumption rules detection out for that hypothesis -- full impersonation under (AUTH). It is never a blank, a dash or a zero.
- Families withheld on at least one run in this table, reported as `not evaluated` and never as passed: channel: this run published no check rounds, so the whole channel family is unevaluable -- an unmonitored link is not a clean one, structural:evidence-abort.

### Per-trial cost, by cell

| cell | key_length | trials | session s (total) | session s (mean) | detect s (mean) | ms/position |
| --- | --- | --- | --- | --- | --- | --- |
| eve9 | 9 | 400 | 21.55 | 0.054 | 0.0017 | 5.986 |
| eve15 | 15 | 400 | 35.85 | 0.090 | 0.0020 | 5.974 |
| eve24 | 24 | 400 | 56.15 | 0.140 | 0.0024 | 5.849 |
| eve30 | 30 | 400 | 69.94 | 0.175 | 0.0029 | 5.829 |
| eve24after | 24 | 400 | 55.21 | 0.138 | 0.0024 | 5.751 |
| bob96before | 96 | 400 | 244.10 | 0.610 | 0.0084 | 6.357 |
| bob96after | 96 | 400 | 223.20 | 0.558 | 0.0073 | 5.813 |
| bob192before | 192 | 400 | 435.32 | 1.088 | 0.0125 | 5.668 |
| bob192after | 192 | 400 | 431.79 | 1.079 | 0.0129 | 5.622 |
| bob384before | 384 | 400 | 814.55 | 2.036 | 0.0219 | 5.303 |
| bob384after | 384 | 400 | 846.06 | 2.115 | 0.0225 | 5.508 |
| bob768before | 768 | 400 | 1664.32 | 4.161 | 0.0405 | 5.418 |
| bob768after | 768 | 400 | 1695.59 | 4.239 | 0.0410 | 5.520 |
| bob1200before | 1200 | 400 | 2788.36 | 6.971 | 0.0629 | 5.809 |
| bob1200after | 1200 | 400 | 2743.68 | 6.859 | 0.0612 | 5.716 |

Regenerate: `python tools/sweep.py reduce forgery-curve --results 'C:\Users\Aftab\.sih141\results'`

- Timings are wall clock inside the worker, so at N workers the sum of `session s (total)` exceeds the sweep's own wall clock by roughly the achieved speedup. That comparison is the check on the runner: if it does not, one of the two numbers is wrong.
- **`ms/position` HERE IS NOT THE PROTOCOL'S COST.** It carries the contention of whatever worker count produced these records -- see `worker counts` in the provenance above. Measured on this machine, a trial takes 1.61x longer at twenty workers than at one at L = 384, and 2.53x at L = 768, because the cores share an all-core turbo budget and an L3. The single-threaded reference is `sih141.eval.perf.REFERENCE_MS_PER_POSITION`; regenerate it with `python tools/sweep.py perf`. Multiplying the figure below by a key length to project a production run overstates it by that factor.
- Timings are excluded from a record's fingerprint, so they cannot affect the reproducibility claim -- and every other table here is byte-identical at one worker and at twenty.

### Forgery against key length: measured, exact and proven

| cell | adversary | key_length | count ordering | runs | engaged | Charlie accepted (measured) | Charlie rejected | Charlie no verdict | not engaged | Bob accepted (measured) | exact P (closed form) | proven bound | security claim |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| eve9 | outside-forgery | 9 | before-forwarding | 400 | 400 | 61/400 = 0.1525 [0.1119, 0.2044] | 318 | 21 | 0 | 66/400 = 0.1650 [0.1227, 0.2182] | 1.6779e-01 | 3.076e-01 | no |
| eve15 | outside-forgery | 15 | before-forwarding | 400 | 400 | 26/400 = 0.0650 [0.0398, 0.1044] | 372 | 2 | 0 | 22/400 = 0.0550 [0.0322, 0.0923] | 6.2622e-02 | 1.402e-01 | no |
| eve24 | outside-forgery | 24 | before-forwarding | 400 | 400 | 4/400 = 0.0100 [0.0030, 0.0330] | 396 | 0 | 0 | 8/400 = 0.0200 [0.0083, 0.0474] | 1.2520e-02 | 4.312e-02 | no |
| eve30 | outside-forgery | 30 | before-forwarding | 400 | 400 | 1/400 = 0.0025 [0.0003, 0.0209] | 399 | 0 | 0 | 2/400 = 0.0050 [0.0010, 0.0252] | 4.2111e-03 | 1.965e-02 | no |
| eve24after | outside-forgery | 24 | after-forwarding | 400 | 400 | 2/400 = 0.0050 [0.0010, 0.0252] | 398 | 0 | 0 | 8/400 = 0.0200 [0.0083, 0.0474] | 1.2520e-02 | 4.312e-02 | no |
| bob96before | recipient-forgery | 96 | before-forwarding | 400 | 400 | 0/400 = 0.0000 [0.0000, 0.0163] | 0 | 400 | 0 | forger | 2.9663e-01 | 8.207e-01 | no |
| bob96after | recipient-forgery | 96 | after-forwarding | 400 | 400 | 120/400 = 0.3000 [0.2446, 0.3619] | 280 | 0 | 0 | forger | 2.9663e-01 | 8.207e-01 | no |
| bob192before | recipient-forgery | 192 | before-forwarding | 400 | 400 | 0/400 = 0.0000 [0.0000, 0.0163] | 0 | 400 | 0 | forger | 2.0459e-01 | 6.736e-01 | yes |
| bob192after | recipient-forgery | 192 | after-forwarding | 400 | 400 | 63/400 = 0.1575 [0.1162, 0.2100] | 337 | 0 | 0 | forger | 2.0459e-01 | 6.736e-01 | yes |
| bob384before | recipient-forgery | 384 | before-forwarding | 400 | 400 | 0/400 = 0.0000 [0.0000, 0.0163] | 0 | 400 | 0 | forger | 1.1260e-01 | 4.538e-01 | yes |
| bob384after | recipient-forgery | 384 | after-forwarding | 400 | 400 | 49/400 = 0.1225 [0.0863, 0.1710] | 351 | 0 | 0 | forger | 1.1260e-01 | 4.538e-01 | yes |
| bob768before | recipient-forgery | 768 | before-forwarding | 400 | 400 | 0/400 = 0.0000 [0.0000, 0.0163] | 0 | 400 | 0 | forger | 4.0360e-02 | 2.059e-01 | yes |
| bob768after | recipient-forgery | 768 | after-forwarding | 400 | 400 | 11/400 = 0.0275 [0.0129, 0.0575] | 389 | 0 | 0 | forger | 4.0360e-02 | 2.059e-01 | yes |
| bob1200before | recipient-forgery | 1200 | before-forwarding | 400 | 400 | 0/400 = 0.0000 [0.0000, 0.0163] | 0 | 400 | 0 | forger | 1.4002e-02 | 8.465e-02 | yes |
| bob1200after | recipient-forgery | 1200 | after-forwarding | 400 | 400 | 6/400 = 0.0150 [0.0055, 0.0403] | 394 | 0 | 0 | forger | 1.4002e-02 | 8.465e-02 | yes |

Regenerate: `python tools/sweep.py reduce forgery-curve --results 'C:\Users\Aftab\.sih141\results'`

- DENOMINATOR: `engaged` -- runs where the forger's declaration really differed from Alice's, counted position by position on the adversary's own log. `Charlie accepted` + `Charlie rejected` + `Charlie no verdict` = `engaged`, exactly.
- ABORTS: `Charlie no verdict` is a REFUSAL, not a rejection, and it is never folded into one. Under the before-forwarding ordering the recipient-forgery rows are ALL refusals: a substituted declaration leaves CHARLIE'S pooled matched count undefined, so Bob accepts the genuine declaration he was sent and Charlie alone reaches no verdict. The attack is a denial of transfer rather than a detected forgery.
- COUNT ORDERING IS A COLUMN AND HERE IS WHY (Phase 3 constraint 2): the same attack against the same code gives all refusals before forwarding and a real acceptance rate after it. Pooling the two would publish a figure describing neither.
- `Charlie accepted (measured)` carries a 99% Wilson interval and the word `measured`. `proven bound` holds against the stated adversary model. They never share a column.
- `exact P (closed form)` is forgery_probability for Eve and recipient_forgery_probability for Bob -- the exact acceptance probability under each one's stated adversary model, and the independent route the measurement is checked against.
- `Bob accepted` reads `forger` on the recipient rows because Bob IS the adversary there; it is not a hypothesis that was ruled out and not a zero.
- Eve's rungs stop at L = 30 because her acceptance probability is 1.1e-12 by L = 192: they anchor the closed form to a measurement where one is possible at all, and the closed form carries the curve from there. The recipient forger is the binding adversary and the one a security claim should quote.

### Matched-count floors and the bounds they buy, by key length

| key_length | m_min | M_min | floor on M | security claim | gap s_v - s_a | enforced repudiation bound (proven) | recipient-forgery bound (proven) | outside-forgery bound (proven) | measured here |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 9 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.817e-01 | 3.076e-01 | yes |
| 15 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.696e-01 | 1.402e-01 | yes |
| 24 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.518e-01 | 4.312e-02 | yes |
| 30 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.401e-01 | 1.965e-02 | yes |
| 48 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.060e-01 | 1.860e-03 | - |
| 96 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 8.207e-01 | 3.459e-06 | yes |
| 132 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 7.621e-01 | 3.097e-08 | - |
| 136 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 7.559e-01 | 1.834e-08 | - |
| 137 | 1 | 2 | 2 | yes | 0.046875 | 9.995e-01 | 7.543e-01 | 1.609e-08 | - |
| 138 | 1 | 2 | 2 | yes | 0.046875 | 9.995e-01 | 7.528e-01 | 1.411e-08 | - |
| 140 | 1 | 3 | 3 | yes | 0.046875 | 9.992e-01 | 7.497e-01 | 1.086e-08 | - |
| 192 | 1 | 22 | 22 | yes | 0.046875 | 9.940e-01 | 6.736e-01 | 1.196e-11 | yes |
| 272 | 1 | 55 | 55 | yes | 0.046875 | 9.850e-01 | 5.714e-01 | 3.364e-16 | - |
| 273 | 2 | 55 | 55 | yes | 0.046875 | 9.850e-01 | 5.702e-01 | 2.951e-16 | - |
| 300 | 6 | 67 | 67 | yes | 0.046875 | 9.818e-01 | 5.394e-01 | 8.592e-18 | - |
| 384 | 22 | 106 | 106 | yes | 0.046875 | 9.713e-01 | 4.538e-01 | 1.431e-22 | yes |
| 600 | 67 | 212 | 212 | yes | 0.046875 | 9.434e-01 | 2.909e-01 | 7.382e-35 | - |
| 768 | 106 | 299 | 299 | yes | 0.046875 | 9.212e-01 | 2.059e-01 | 2.048e-44 | yes |
| 1200 | 212 | 534 | 534 | yes | 0.046875 | 8.636e-01 | 8.465e-02 | 5.449e-69 | yes |
| 2400 | 534 | 1224 | 1224 | yes | 0.046875 | 7.145e-01 | 7.165e-03 | 2.969e-137 | - |
| 4800 | 1224 | 2668 | 2668 | yes | 0.046875 | 4.806e-01 | 5.134e-05 | 8.814e-274 | - |
| 9600 | 2668 | 5647 | 5647 | yes | 0.046875 | 2.120e-01 | 2.636e-09 | 10^-546.1 | - |
| 19200 | 5647 | 11735 | 11735 | yes | 0.046875 | 3.983e-02 | 6.947e-18 | 10^-1092.2 | - |
| 115200 | 36555 | 74190 | 74190 | yes | 0.046875 | 1.414e-09 | 1.124e-103 | 10^-6553.3 | - |

Regenerate: `python tools/sweep.py reduce forgery-curve --results 'C:\Users\Aftab\.sih141\results'`

- EVERY column here is a closed form in the parameter set. None is a measurement and none is labelled one; `measured here` says only which key lengths this sweep also ran trials at.
- `security claim` turns on at L = 137, where the POOLED floor first exceeds 1. The per-verifier floor does not bite until L = 273. Below the crossover both floors are 1 -- 'abort only on an empty matched set' -- and every number in the run still computes cheerfully, which is why the column exists.
- The bounds are the KL form, which is never weaker than the Hoeffding one. They are printed from log10 rather than from the library's float: forgery_bound underflows to 0.0 at L = 115200, and a bound of exactly zero is a claim no proof supports.
- `floor on M` is max(2 m_min, M_min), the pooled evidence base the shipped rules guarantee on any run that reaches a verdict. It is what the enforced repudiation bound is evaluated at.
- The enforced bound is a-priori and holds for every signer strategy. The per-run bound a completed run should quote is repudiation_bound at its OWN observed M, which every transcript carries as repudiation_guarantee.
