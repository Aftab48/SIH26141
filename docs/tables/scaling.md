## scaling

**Provenance.**

- commit: `6cb0f57750c0`
- **the working tree was dirty for at least one run**, so the commit above does not fully describe the code that ran
- worker counts: [20]
- produced by: `python 'C:\Users\Aftab\Desktop\local websites\sih-141\tools\sweep.py' run scaling --workers 20`

### Run outcomes, by cell and count ordering

| cell | count_exchange_timing | runs | parties | accepted | rejected | refused | not_asked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| l192 | before-forwarding | 20 | 40 | 40 | 0 | 0 | 0 |
| l768 | before-forwarding | 20 | 40 | 40 | 0 | 0 | 0 |
| l3072 | before-forwarding | 20 | 40 | 40 | 0 | 0 | 0 |
| l12288 | before-forwarding | 20 | 40 | 40 | 0 | 0 | 0 |

Regenerate: `python tools/sweep.py reduce scaling --results 'C:\Users\Aftab\.sih141\results'`

- Complete: every cell has all the trials its manifest asked for, and no trial index is missing below the highest present. A trial whose scenario raised would leave no file, so this is checked rather than assumed.
- `parties` is the denominator, and it is two verifiers per run -- every run has a Bob and a Charlie whatever became of them. accepted + rejected + refused + not_asked = parties, exactly. `not_asked` is a party the protocol never put the question to, which is a third thing again from a refusal.
- `refused` is a no-verdict, not a rejection. A run where a verifier could not score the declaration is neither an acceptance nor a detection, and it is never folded into either.
- `count_exchange_timing` is a column, never averaged over: the two orderings give different answers to the same attack.

### Detector signals, measured rates apart from proven bounds

| cell | count_exchange_timing | hypothesis | runs | attacked | flagged on attacked (measured) | flagged on clean (measured) | refusals (any party) | max proven FP bound | null_is_noiseless | withheld families |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| l192 | before-forwarding | honest | 20 | 0 | no trials | 0/20 = 0.000 [0.000, 0.249] | 0 | 3.865e-10 | yes | not evaluated (4) |
| l768 | before-forwarding | honest | 20 | 0 | no trials | 0/20 = 0.000 [0.000, 0.249] | 0 | 4.177e-10 | yes | - |
| l3072 | before-forwarding | honest | 20 | 0 | no trials | 0/20 = 0.000 [0.000, 0.249] | 0 | 4.851e-10 | yes | - |
| l12288 | before-forwarding | honest | 20 | 0 | no trials | 0/20 = 0.000 [0.000, 0.249] | 0 | 5.030e-10 | yes | - |

Regenerate: `python tools/sweep.py reduce scaling --results 'C:\Users\Aftab\.sih141\results'`

- `flagged on attacked (measured)` and `flagged on clean (measured)` are MEASUREMENTS with a sample size, shown as k/n with a 99% Wilson interval. There is no false-negative bound and there cannot be one from a transcript.
- `max proven FP bound` is PROVEN under the honest null -- the largest Detection.false_positive_bound in the group. It shares no column with a measured rate.
- `attacked` counts runs whose adversary engaged, read off the adversary's own log. An untargeted run is byte-identical to an honest one and is scored as one.
- `refusals (any party)` counts runs where AT LEAST ONE verifier reached no verdict. It is shown beside the rates and added to neither denominator: a refusal is not a rejection, and it is not a miss either -- the detector scored every run in both denominators, refusal or not. A row whose count equals its `runs` did not necessarily deny transfer, and this is where an experiment's own per-party table earns its place: at L = 96 the recipient forger refuses on all 400 runs under either ordering, but before forwarding it is CHARLIE who reaches no verdict (a denial of transfer) and after forwarding it is BOB, while Charlie returns a real 120/400 acceptance. Same count, opposite reading, which is why the column is named for what it actually counts.
- `null_is_noiseless` says whether the detector was given a noiseless null. On a genuinely noisy link that null is not the truth, honest runs depart from it, and the mismatch members fire correctly -- so a `yes` here is a caveat on the row, not a detail.
- `undetectable-by-construction` means an assumption rules detection out for that hypothesis. It is never a blank, a dash or a zero.
- Families withheld on at least one run in this table, reported as `not evaluated` and never as passed: channel:Bob/0:chsh, channel:Bob/1:chsh, channel:Charlie/0:chsh, channel:Charlie/1:chsh.

### Per-trial cost, by cell

| cell | key_length | trials | session s (total) | session s (mean) | detect s (mean) | ms/position |
| --- | --- | --- | --- | --- | --- | --- |
| l192 | 192 | 20 | 19.24 | 0.962 | 0.0143 | 5.010 |
| l768 | 768 | 20 | 83.14 | 4.157 | 0.0452 | 5.413 |
| l3072 | 3072 | 20 | 342.64 | 17.132 | 0.1961 | 5.577 |
| l12288 | 12288 | 20 | 1780.19 | 89.010 | 1.1789 | 7.244 |

Regenerate: `python tools/sweep.py reduce scaling --results 'C:\Users\Aftab\.sih141\results'`

- Timings are wall clock inside the worker, so at N workers the sum of `session s (total)` exceeds the sweep's own wall clock by roughly the achieved speedup. That comparison is the check on the runner: if it does not, one of the two numbers is wrong.
- **`ms/position` HERE IS NOT THE PROTOCOL'S COST.** It carries the contention of whatever worker count produced these records -- see `worker counts` in the provenance above. Measured on this machine, a trial takes 1.61x longer at twenty workers than at one at L = 384, and 2.53x at L = 768, because the cores share an all-core turbo budget and an L3. The single-threaded reference is `sih141.eval.perf.REFERENCE_MS_PER_POSITION`; regenerate it with `python tools/sweep.py perf`. Multiplying the figure below by a key length to project a production run overstates it by that factor.
- Timings are excluded from a record's fingerprint, so they cannot affect the reproducibility claim -- and every other table here is byte-identical at one worker and at twenty.
