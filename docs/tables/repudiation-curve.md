## repudiation-curve

**Provenance.**

- commit: `6cb0f57750c0`
- **the working tree was dirty for at least one run**, so the commit above does not fully describe the code that ran
- worker counts: [20]
- produced by: `python 'C:\Users\Aftab\Desktop\local websites\sih-141\tools\sweep.py' run repudiation-curve --workers 20`

### Run outcomes, by cell and count ordering

| cell | count_exchange_timing | runs | parties | accepted | rejected | refused | not_asked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| l24 | before-forwarding | 400 | 800 | 389 | 411 | 0 | 0 |
| l48 | before-forwarding | 400 | 800 | 390 | 410 | 0 | 0 |
| l96 | before-forwarding | 400 | 800 | 367 | 433 | 0 | 0 |
| l132 | before-forwarding | 400 | 800 | 376 | 424 | 0 | 0 |
| l138 | before-forwarding | 400 | 800 | 353 | 447 | 0 | 0 |
| l192 | before-forwarding | 400 | 800 | 374 | 426 | 0 | 0 |
| l300 | before-forwarding | 400 | 800 | 371 | 429 | 0 | 0 |
| l384 | before-forwarding | 400 | 800 | 369 | 431 | 0 | 0 |
| l600 | before-forwarding | 400 | 800 | 383 | 417 | 0 | 0 |
| l768 | before-forwarding | 400 | 800 | 384 | 416 | 0 | 0 |
| l192after | after-forwarding | 400 | 800 | 380 | 420 | 0 | 0 |
| unsym192 | before-forwarding | 400 | 800 | 400 | 400 | 0 | 0 |
| unsym384 | before-forwarding | 400 | 800 | 400 | 400 | 0 | 0 |
| unsym768 | before-forwarding | 400 | 800 | 400 | 400 | 0 | 0 |

Regenerate: `python tools/sweep.py reduce repudiation-curve --results 'C:\Users\Aftab\.sih141\results'`

- Complete: every cell has all the trials its manifest asked for, and no trial index is missing below the highest present. A trial whose scenario raised would leave no file, so this is checked rather than assumed.
- `parties` is the denominator, and it is two verifiers per run -- every run has a Bob and a Charlie whatever became of them. accepted + rejected + refused + not_asked = parties, exactly. `not_asked` is a party the protocol never put the question to, which is a third thing again from a refusal.
- `refused` is a no-verdict, not a rejection. A run where a verifier could not score the declaration is neither an acceptance nor a detection, and it is never folded into either.
- `count_exchange_timing` is a column, never averaged over: the two orderings give different answers to the same attack.

### Detector signals, measured rates apart from proven bounds

| cell | count_exchange_timing | hypothesis | runs | attacked | flagged on attacked (measured) | flagged on clean (measured) | refusals (any party) | max proven FP bound | null_is_noiseless | withheld families |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| l24 | before-forwarding | repudiation | 400 | 394 | 308/394 = 0.782 [0.724, 0.830] | 0/6 = 0.000 [0.000, 0.525] | 0 | 2.627e-11 | yes | not evaluated (2) |
| l48 | before-forwarding | repudiation | 400 | 399 | 346/399 = 0.867 [0.817, 0.905] | 0/1 = 0.000 [0.000, 0.869] | 0 | 1.015e-10 | yes | not evaluated (2) |
| l96 | before-forwarding | repudiation | 400 | 400 | 385/400 = 0.963 [0.930, 0.980] | no trials | 0 | 2.651e-10 | yes | not evaluated (1) |
| l132 | before-forwarding | repudiation | 400 | 400 | 394/400 = 0.985 [0.960, 0.995] | no trials | 0 | 1.538e-10 | yes | not evaluated (1) |
| l138 | before-forwarding | repudiation | 400 | 400 | 396/400 = 0.990 [0.967, 0.997] | no trials | 0 | 2.354e-10 | yes | not evaluated (1) |
| l192 | before-forwarding | repudiation | 400 | 400 | 398/400 = 0.995 [0.975, 0.999] | no trials | 0 | 2.650e-10 | yes | not evaluated (1) |
| l300 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.578e-10 | yes | not evaluated (1) |
| l384 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.782e-10 | yes | not evaluated (1) |
| l600 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 3.287e-10 | yes | not evaluated (1) |
| l768 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 3.248e-10 | yes | not evaluated (1) |
| l192after | after-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.650e-10 | yes | not evaluated (1) |
| unsym192 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.650e-10 | yes | not evaluated (1) |
| unsym384 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 2.782e-10 | yes | not evaluated (1) |
| unsym768 | before-forwarding | repudiation | 400 | 400 | 400/400 = 1.000 [0.984, 1.000] | no trials | 0 | 3.248e-10 | yes | not evaluated (1) |

Regenerate: `python tools/sweep.py reduce repudiation-curve --results 'C:\Users\Aftab\.sih141\results'`

- `flagged on attacked (measured)` and `flagged on clean (measured)` are MEASUREMENTS with a sample size, shown as k/n with a 99% Wilson interval. There is no false-negative bound and there cannot be one from a transcript.
- `max proven FP bound` is PROVEN under the honest null -- the largest Detection.false_positive_bound in the group. It shares no column with a measured rate.
- `attacked` counts runs whose adversary engaged, read off the adversary's own log. An untargeted run is byte-identical to an honest one and is scored as one.
- `refusals (any party)` counts runs where AT LEAST ONE verifier reached no verdict. It is shown beside the rates and added to neither denominator: a refusal is not a rejection, and it is not a miss either -- the detector scored every run in both denominators, refusal or not. A row whose count equals its `runs` did not necessarily deny transfer, and this is where an experiment's own per-party table earns its place: at L = 96 the recipient forger refuses on all 400 runs under either ordering, but before forwarding it is CHARLIE who reaches no verdict (a denial of transfer) and after forwarding it is BOB, while Charlie returns a real 120/400 acceptance. Same count, opposite reading, which is why the column is named for what it actually counts.
- `null_is_noiseless` says whether the detector was given a noiseless null. On a genuinely noisy link that null is not the truth, honest runs depart from it, and the mismatch members fire correctly -- so a `yes` here is a caveat on the row, not a detail.
- `undetectable-by-construction` means an assumption rules detection out for that hypothesis. It is never a blank, a dash or a zero.
- Families withheld on at least one run in this table, reported as `not evaluated` and never as passed: channel: this run published no check rounds, so the whole channel family is unevaluable -- an unmonitored link is not a clean one, structural:evidence-abort.

### Per-trial cost, by cell

| cell | key_length | trials | session s (total) | session s (mean) | detect s (mean) | ms/position |
| --- | --- | --- | --- | --- | --- | --- |
| l24 | 24 | 400 | 57.84 | 0.145 | 0.0026 | 6.025 |
| l48 | 48 | 400 | 134.76 | 0.337 | 0.0047 | 7.019 |
| l96 | 96 | 400 | 276.37 | 0.691 | 0.0086 | 7.197 |
| l132 | 132 | 400 | 366.38 | 0.916 | 0.0110 | 6.939 |
| l138 | 138 | 400 | 379.55 | 0.949 | 0.0109 | 6.876 |
| l192 | 192 | 400 | 526.97 | 1.317 | 0.0142 | 6.862 |
| l300 | 300 | 400 | 836.45 | 2.091 | 0.0208 | 6.970 |
| l384 | 384 | 400 | 1041.64 | 2.604 | 0.0259 | 6.782 |
| l600 | 600 | 400 | 1608.17 | 4.020 | 0.0368 | 6.701 |
| l768 | 768 | 400 | 1967.82 | 4.920 | 0.0451 | 6.406 |
| l192after | 192 | 400 | 501.01 | 1.253 | 0.0134 | 6.524 |
| unsym192 | 192 | 400 | 494.69 | 1.237 | 0.0132 | 6.441 |
| unsym384 | 384 | 400 | 945.59 | 2.364 | 0.0236 | 6.156 |
| unsym768 | 768 | 400 | 1756.69 | 4.392 | 0.0389 | 5.718 |

Regenerate: `python tools/sweep.py reduce repudiation-curve --results 'C:\Users\Aftab\.sih141\results'`

- Timings are wall clock inside the worker, so at N workers the sum of `session s (total)` exceeds the sweep's own wall clock by roughly the achieved speedup. That comparison is the check on the runner: if it does not, one of the two numbers is wrong.
- **`ms/position` HERE IS NOT THE PROTOCOL'S COST.** It carries the contention of whatever worker count produced these records -- see `worker counts` in the provenance above. Measured on this machine, a trial takes 1.61x longer at twenty workers than at one at L = 384, and 2.53x at L = 768, because the cores share an all-core turbo budget and an L3. The single-threaded reference is `sih141.eval.perf.REFERENCE_MS_PER_POSITION`; regenerate it with `python tools/sweep.py perf`. Multiplying the figure below by a key length to project a production run overstates it by that factor.
- Timings are excluded from a record's fingerprint, so they cannot affect the reproducibility claim -- and every other table here is byte-identical at one worker and at twenty.

### Repudiation against key length: measured, exact and proven

| cell | key_length | count ordering | symmetrised | tilt q | runs | engaged | not engaged | repudiated (measured) | no verdict | Bob accepted | mean states flipped | exact in-model P (closed form) | enforced bound (proven) | security claim |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| l24 | 24 | before-forwarding | yes | 0.085 | 400 | 394 | 6 | 107/394 = 0.2716 [0.2180, 0.3327] | 0 | 193 | 4.2 | 2.498e-01 | 9.995e-01 | no |
| l48 | 48 | before-forwarding | yes | 0.059 | 400 | 399 | 1 | 66/399 = 0.1654 [0.1231, 0.2187] | 0 | 148 | 5.8 | 1.569e-01 | 9.995e-01 | no |
| l96 | 96 | before-forwarding | yes | 0.047 | 400 | 400 | 0 | 35/400 = 0.0875 [0.0575, 0.1309] | 0 | 90 | 9.1 | 6.602e-02 | 9.995e-01 | no |
| l132 | 132 | before-forwarding | yes | 0.043 | 400 | 400 | 0 | 18/400 = 0.0450 [0.0249, 0.0799] | 0 | 59 | 11.2 | 3.639e-02 | 9.995e-01 | no |
| l138 | 138 | before-forwarding | yes | 0.043 | 400 | 400 | 0 | 8/400 = 0.0200 [0.0083, 0.0474] | 0 | 47 | 12.0 | 3.270e-02 | 9.995e-01 | yes |
| l192 | 192 | before-forwarding | yes | 0.044 | 400 | 400 | 0 | 14/400 = 0.0350 [0.0179, 0.0673] | 0 | 57 | 16.4 | 2.951e-02 | 9.940e-01 | yes |
| l300 | 300 | before-forwarding | yes | 0.042 | 400 | 400 | 0 | 6/400 = 0.0150 [0.0055, 0.0403] | 0 | 28 | 25.4 | 1.158e-02 | 9.818e-01 | yes |
| l384 | 384 | before-forwarding | yes | 0.042 | 400 | 400 | 0 | 2/400 = 0.0050 [0.0010, 0.0252] | 0 | 18 | 32.8 | 7.100e-03 | 9.713e-01 | yes |
| l600 | 600 | before-forwarding | yes | 0.041 | 400 | 400 | 0 | 1/400 = 0.0025 [0.0003, 0.0209] | 0 | 13 | 48.7 | 1.936e-03 | 9.434e-01 | yes |
| l768 | 768 | before-forwarding | yes | 0.041 | 400 | 400 | 0 | 0/400 = 0.0000 [0.0000, 0.0163] | 0 | 6 | 63.5 | 5.845e-04 | 9.212e-01 | yes |
| l192after | 192 | after-forwarding | yes | 0.044 | 400 | 400 | 0 | 7/400 = 0.0175 [0.0069, 0.0439] | 0 | 56 | 17.0 | 2.951e-02 | 9.940e-01 | yes |
| unsym192 | 192 | before-forwarding | no | 0.300 | 400 | 400 | 0 | 400/400 = 1.0000 [0.9837, 1.0000] | 0 | 400 | 57.3 | n/a: closed form assumes the symmetrised, untargeted family | 9.940e-01 | yes |
| unsym384 | 384 | before-forwarding | no | 0.300 | 400 | 400 | 0 | 400/400 = 1.0000 [0.9837, 1.0000] | 0 | 400 | 115.4 | n/a: closed form assumes the symmetrised, untargeted family | 9.713e-01 | yes |
| unsym768 | 768 | before-forwarding | no | 0.300 | 400 | 400 | 0 | 400/400 = 1.0000 [0.9837, 1.0000] | 0 | 400 | 230.8 | n/a: closed form assumes the symmetrised, untargeted family | 9.212e-01 | yes |

Regenerate: `python tools/sweep.py reduce repudiation-curve --results 'C:\Users\Aftab\.sih141\results'`

- DENOMINATOR: `engaged` -- runs whose tilt actually replaced at least one delivered state, read off the adversary's own counter. `not engaged` runs are byte-identical to honest runs and are scored as honest runs, not as missed repudiations.
- ABORTS: the `no verdict` runs are INSIDE the denominator and are NOT repudiations. A verifier who reached no verdict did not accept, so the repudiation event did not occur; and that is the same denominator the proven bound is stated over, which is what lets the two columns be compared at all. No column here sums a refusal with a rejection.
- `repudiated (measured)` is a MEASUREMENT with a sample size, shown as k/n with a 99% Wilson interval. There is no false-negative bound and there cannot be one from a transcript.
- `exact in-model P` is repudiation_probability(params, q): the exact closed form for THIS adversary's family -- a signer who tilts both deliveries independently at rate q -- and an independent route to the same number. It is not a bound over all strategies.
- `enforced bound (proven)` is exp(-max(2 m_min, M_min) gap^2 / 8), which holds for EVERY signer strategy with no independence assumption. Measured and proven never share a column.
- `security claim` is False where both matched-count floors degenerate to 1. Those rows are still real measurements of a real protocol; what they carry no claim about is the bound.
- `count ordering` is a column, never averaged over (Phase 3 constraint 2). The l192after row is the control that says so for this attack rather than assuming it.
- `exact in-model P` reads `n/a` on any row that did not run the family it describes -- an aimed tilt, or the variant with no symmetrisation exchange. A number there would look like a contradiction of the measurement rather than a column that does not apply.
- The `unsym*` rows are a POSITIVE CONTROL, not a result: the same adversary against the variant with no symmetrisation exchange, where repudiation succeeds at every key length. They are what tells a rung reporting zero apart from a rung whose attack was never mounted.
- transcript.repudiated is used here as the OUTCOME of a labelled experiment, never as a detector signal: it cannot tell signer misbehaviour from channel noise from recipient forgery (Phase 3 constraint 7), which is exactly why the harness knows the truth and the detector does not.
- The link is noiseless and the detector was given the noiseless null, so the null here IS the truth; the mismatches these runs show come from Alice's preparation and not from the wire.
- DOMINANCE (Phase 3 constraint 9), for the detection table printed above these: the mismatch-rate detector stops adding anything over a verifier's own cut once the link error rate exceeds dominance_noise_level, which over the matched counts these runs produced (|M_R| from 2 to 299) is 0.000000 to 0.009459 at Charlie's cut -- far below the design noise level 2 s_a = 0.03125, and at the short end essentially zero. At demo scale that detector is dominated on any link that is noisy at all. It is not dominated here only because these runs are on a genuinely noiseless link, so the noiseless null is the truth and the mismatches come from Alice.
- WHERE DEMO-SCALE RUNS CANNOT DEMONSTRATE NON-REPUDIATION: the l768 row measures 0/400 = 0.0000 [0.0000, 0.0163], whose upper limit is still far above the exact probability 5.845e-04 and far below the proven bound 9.212e-01. The proof is loose over exactly the range a measurement can reach, and the region the security claim lives in (1.4e-09 at L=115200) is unreachable by both. A measured zero here is evidence the mechanism works, never confirmation of the bound.

### Matched-count floors and the bounds they buy, by key length

| key_length | m_min | M_min | floor on M | security claim | gap s_v - s_a | enforced repudiation bound (proven) | recipient-forgery bound (proven) | outside-forgery bound (proven) | measured here |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 24 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.518e-01 | 4.312e-02 | yes |
| 48 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 9.060e-01 | 1.860e-03 | yes |
| 96 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 8.207e-01 | 3.459e-06 | yes |
| 132 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 7.621e-01 | 3.097e-08 | yes |
| 136 | 1 | 1 | 2 | no | 0.046875 | 9.995e-01 | 7.559e-01 | 1.834e-08 | - |
| 137 | 1 | 2 | 2 | yes | 0.046875 | 9.995e-01 | 7.543e-01 | 1.609e-08 | - |
| 138 | 1 | 2 | 2 | yes | 0.046875 | 9.995e-01 | 7.528e-01 | 1.411e-08 | yes |
| 140 | 1 | 3 | 3 | yes | 0.046875 | 9.992e-01 | 7.497e-01 | 1.086e-08 | - |
| 192 | 1 | 22 | 22 | yes | 0.046875 | 9.940e-01 | 6.736e-01 | 1.196e-11 | yes |
| 272 | 1 | 55 | 55 | yes | 0.046875 | 9.850e-01 | 5.714e-01 | 3.364e-16 | - |
| 273 | 2 | 55 | 55 | yes | 0.046875 | 9.850e-01 | 5.702e-01 | 2.951e-16 | - |
| 300 | 6 | 67 | 67 | yes | 0.046875 | 9.818e-01 | 5.394e-01 | 8.592e-18 | yes |
| 384 | 22 | 106 | 106 | yes | 0.046875 | 9.713e-01 | 4.538e-01 | 1.431e-22 | yes |
| 600 | 67 | 212 | 212 | yes | 0.046875 | 9.434e-01 | 2.909e-01 | 7.382e-35 | yes |
| 768 | 106 | 299 | 299 | yes | 0.046875 | 9.212e-01 | 2.059e-01 | 2.048e-44 | yes |
| 1200 | 212 | 534 | 534 | yes | 0.046875 | 8.636e-01 | 8.465e-02 | 5.449e-69 | - |
| 2400 | 534 | 1224 | 1224 | yes | 0.046875 | 7.145e-01 | 7.165e-03 | 2.969e-137 | - |
| 4800 | 1224 | 2668 | 2668 | yes | 0.046875 | 4.806e-01 | 5.134e-05 | 8.814e-274 | - |
| 9600 | 2668 | 5647 | 5647 | yes | 0.046875 | 2.120e-01 | 2.636e-09 | 10^-546.1 | - |
| 19200 | 5647 | 11735 | 11735 | yes | 0.046875 | 3.983e-02 | 6.947e-18 | 10^-1092.2 | - |
| 115200 | 36555 | 74190 | 74190 | yes | 0.046875 | 1.414e-09 | 1.124e-103 | 10^-6553.3 | - |

Regenerate: `python tools/sweep.py reduce repudiation-curve --results 'C:\Users\Aftab\.sih141\results'`

- EVERY column here is a closed form in the parameter set. None is a measurement and none is labelled one; `measured here` says only which key lengths this sweep also ran trials at.
- `security claim` turns on at L = 137, where the POOLED floor first exceeds 1. The per-verifier floor does not bite until L = 273. Below the crossover both floors are 1 -- 'abort only on an empty matched set' -- and every number in the run still computes cheerfully, which is why the column exists.
- The bounds are the KL form, which is never weaker than the Hoeffding one. They are printed from log10 rather than from the library's float: forgery_bound underflows to 0.0 at L = 115200, and a bound of exactly zero is a claim no proof supports.
- `floor on M` is max(2 m_min, M_min), the pooled evidence base the shipped rules guarantee on any run that reaches a verdict. It is what the enforced repudiation bound is evaluated at.
- The enforced bound is a-priori and holds for every signer strategy. The per-run bound a completed run should quote is repudiation_bound at its OWN observed M, which every transcript carries as repudiation_guarantee.

### What the s_a / s_v gap buys and what it costs, at L = 115200

| knob | s_a | s_v | gap s_v - s_a | enforced repudiation bound (proven) | recipient-forgery bound (proven) | link noise tolerated 2 s_a |  |
| --- | --- | --- | --- | --- | --- | --- | --- |
| s_v | 0.015625 | 0.031250 | 0.015625 | 1.039e-01 | 10^-760.4 | 0.03125 | - |
| s_v | 0.015625 | 0.046875 | 0.031250 | 1.166e-04 | 10^-339.8 | 0.03125 | - |
| s_v | 0.015625 | 0.062500 | 0.046875 | 1.414e-09 | 1.124e-103 | 0.03125 | SHIPPED |
| s_v | 0.015625 | 0.078125 | 0.062500 | 1.851e-16 | 9.165e-07 | 0.03125 | - |
| s_v | 0.015625 | 0.080000 | 0.064375 | 2.039e-17 | 3.502e-03 | 0.03125 | - |
| s_a | 0.000000 | 0.062500 | 0.062500 | 1.851e-16 | 1.124e-103 | 0.00000 | - |
| s_a | 0.007812 | 0.062500 | 0.054688 | 9.011e-13 | 1.124e-103 | 0.01562 | - |
| s_a | 0.015625 | 0.062500 | 0.046875 | 1.414e-09 | 1.124e-103 | 0.03125 | SHIPPED |
| s_a | 0.031250 | 0.062500 | 0.031250 | 1.166e-04 | 1.124e-103 | 0.06250 | - |
| s_a | 0.046875 | 0.062500 | 0.015625 | 1.039e-01 | 1.124e-103 | 0.09375 | - |

Regenerate: `python tools/sweep.py reduce repudiation-curve --results 'C:\Users\Aftab\.sih141\results'`

- EVERY column is a closed form at the shipped key length. None is a measurement.
- Both bounds are exponential in the gap, and every way of widening it costs something: raising s_v walks the acceptance threshold towards the recipient forger's floor of 0.083333, where the forgery bound reaches 1 and there is no guarantee left; lowering s_a shrinks the link noise an honest signature survives, which is 2 s_a.
- ProtocolParams REFUSES an s_v at or above the forger floor unless allow_forgeable is set, so the ladder stops at 0.08 -- 96% of the way there, and the row that shows what the last few percent cost.
- The shipped s_v = 1/16 is three quarters of the floor. That is the choice this table exists to make checkable rather than assert: it buys 1.41e-09 repudiation and 1.12e-103 recipient forgery at once, and neither neighbour on this ladder does. The next rung up spends about a hundred orders of magnitude of forgery security to buy eight of repudiation, which is what 'three quarters of the floor' is protecting.
