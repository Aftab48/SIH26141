# Project Metrics

**SIH26141**: Quantum-Inspired Cyber Threat Detection for Digital Signature Security

Generated `2026-09-05 16:45 UTC` by `tools/metrics.py`. Every figure is computed from the
repository, so do not edit by hand, re-run the script.

## Test suite

```
3800 passed in 1990.62s (0:33:10)
```

- Doctests collected from package modules: **481**
- `--doctest-modules` is enabled over `testpaths = ["tests", "sih141"]`, so every
  numeric claim written in a docstring is an executable test. Documentation that
  lies fails the suite.

## Source volume

| Module | Lines | Code | Docstrings | Comments | Functions | Classes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `sih141/core/__init__.py` | 160 | 78 | 64 | 5 | 0 | 0 |
| `sih141/core/measure.py` | 1357 | 285 | 838 | 61 | 17 | 1 |
| `sih141/core/paulis.py` | 578 | 95 | 377 | 4 | 10 | 1 |
| `sih141/core/rng.py` | 219 | 33 | 153 | 0 | 2 | 0 |
| `sih141/core/states.py` | 877 | 153 | 514 | 76 | 18 | 1 |
| `sih141/core/teleport.py` | 1183 | 171 | 785 | 52 | 15 | 2 |
| `sih141/protocol/__init__.py` | 353 | 206 | 123 | 12 | 0 | 0 |
| `sih141/protocol/analysis.py` | 3514 | 201 | 2750 | 29 | 39 | 2 |
| `sih141/protocol/checkrounds.py` | 3431 | 975 | 1978 | 33 | 81 | 11 |
| `sih141/protocol/distribute.py` | 1805 | 306 | 1249 | 78 | 13 | 2 |
| `sih141/protocol/keys.py` | 773 | 117 | 537 | 3 | 24 | 2 |
| `sih141/protocol/params.py` | 1606 | 483 | 916 | 2 | 26 | 2 |
| `sih141/protocol/records.py` | 1413 | 335 | 901 | 7 | 31 | 3 |
| `sih141/protocol/session.py` | 5327 | 1554 | 3032 | 227 | 92 | 9 |
| `sih141/protocol/signature.py` | 955 | 179 | 646 | 4 | 16 | 1 |
| `sih141/protocol/symmetrise.py` | 554 | 79 | 407 | 2 | 4 | 1 |
| `sih141/protocol/tally.py` | 1344 | 293 | 885 | 12 | 24 | 3 |
| `sih141/protocol/verify.py` | 3703 | 796 | 2397 | 90 | 49 | 6 |
| `sih141/attacks/__init__.py` | 329 | 196 | 108 | 9 | 0 | 0 |
| `sih141/attacks/channel.py` | 2056 | 443 | 1299 | 21 | 50 | 6 |
| `sih141/attacks/forgery.py` | 1679 | 474 | 985 | 26 | 29 | 3 |
| `sih141/attacks/impersonation.py` | 2019 | 560 | 1149 | 48 | 55 | 5 |
| `sih141/attacks/isolation.py` | 2145 | 462 | 1355 | 34 | 33 | 6 |
| `sih141/attacks/replay.py` | 2328 | 682 | 1317 | 51 | 36 | 3 |
| `sih141/attacks/starvation.py` | 1678 | 333 | 1115 | 21 | 27 | 4 |
| `sih141/attacks/statistics.py` | 570 | 158 | 323 | 3 | 14 | 1 |
| `sih141/detect/__init__.py` | 572 | 263 | 259 | 8 | 2 | 1 |
| `sih141/detect/detector.py` | 2652 | 927 | 1388 | 85 | 27 | 8 |
| `sih141/detect/statistics.py` | 3326 | 963 | 1939 | 61 | 56 | 10 |
| `sih141/detect/thresholds_channel.py` | 2905 | 591 | 1865 | 81 | 34 | 3 |
| `sih141/detect/thresholds_rate.py` | 3216 | 753 | 2003 | 73 | 43 | 4 |
| `sih141/detect/thresholds_structural.py` | 3138 | 668 | 2024 | 51 | 43 | 8 |
| `sih141/eval/__init__.py` | 286 | 200 | 76 | 0 | 0 | 0 |
| `sih141/eval/experiments.py` | 888 | 277 | 492 | 3 | 16 | 2 |
| `sih141/eval/manifest.py` | 516 | 191 | 269 | 0 | 11 | 1 |
| `sih141/eval/perf.py` | 1113 | 425 | 527 | 10 | 11 | 1 |
| `sih141/eval/records.py` | 781 | 219 | 473 | 0 | 16 | 2 |
| `sih141/eval/reduce.py` | 1131 | 406 | 584 | 24 | 13 | 1 |
| `sih141/eval/roc.py` | 2526 | 1140 | 1070 | 59 | 33 | 2 |
| `sih141/eval/runner.py` | 675 | 193 | 393 | 0 | 12 | 2 |
| `sih141/eval/security.py` | 3137 | 1227 | 1512 | 42 | 46 | 3 |
| `sih141/eval/seeds.py` | 363 | 58 | 246 | 0 | 6 | 1 |
| `sih141/eval/store.py` | 448 | 82 | 299 | 0 | 16 | 1 |
| `sih141/web/__init__.py` | 145 | 34 | 96 | 0 | 0 | 0 |
| `sih141/web/__main__.py` | 329 | 97 | 175 | 10 | 4 | 0 |
| `sih141/web/api.py` | 887 | 316 | 432 | 35 | 16 | 3 |
| `sih141/web/catalogue.py` | 583 | 317 | 207 | 7 | 5 | 1 |
| `sih141/web/driver.py` | 1250 | 512 | 562 | 40 | 12 | 3 |
| `sih141/web/limits.py` | 1070 | 277 | 578 | 78 | 14 | 2 |
| `sih141/web/payload.py` | 696 | 277 | 341 | 10 | 9 | 0 |
| **total** | **74589** | **20060** | **44013** | **1587** | **1150** | **134** |

Tests: **47933 lines** across **42 files**, **2318 test functions** defined.
Test-lines to code-lines ratio: **2.39 : 1**

## Live security parameters

Read out of `sih141.protocol` at generation time, so these are whatever the code
actually computes today, not what a document once claimed.

| Quantity | Value |
| --- | --- |
| `key_length` | 115200 |
| `s_a` | 0.015625 |
| `s_v` | 0.0625 |
| `bases` | 3 |
| `recipient_forgery_bound` | 1.12518e-29 |
| `recipient_forgery_probability` | 2.17257e-105 |
| `forgery_probability` | 0 |
| `forgery_bound` | 0 |
| `repudiation_bound` | (requires an explicit argument by design) |
| `averaged_repudiation_bound` | (requires an explicit argument by design) |
| `repudiation_bound_with_abort` | (requires an explicit argument by design) |
| `matched_shortfall_probability` | (requires an explicit argument by design) |

## Documentation

| File | Words |
| --- | ---: |
| `README.md` | 6224 |
| `JOURNAL.md` | 92394 |
| `docs/METRICS.md` | 1446 |
| `docs/PHASE1.md` | 4038 |
| `docs/PHASE2.md` | 9968 |
| `docs/PHASE3.md` | 14827 |
| `docs/PHASE4.md` | 9547 |
| `docs/PHASE5.md` | 12552 |
| `docs/PHASE6.md` | 12185 |
| `docs/QDS.md` | 5285 |
| **total** | **168466** |

Working-journal entries: **239** (temporary; deleted at the end of Phase 7).

## Repository

- Commits: **30**

| Commit | Subject |
| --- | --- |
| `4ad12d0` | Rewrite the documentation prose: 673 em dashes down to 75, substance untouched |
| `98d55cb` | Re-run the Phase 5 sweep from a clean tree: same results, provable provenance |
| `f94d9fe` | Close the Phase 5 audit: nine defects fixed, the sweep run end to end |
| `6cb0f57` | Add the Phase 5 experiment families: security curves and ROC |
| `98db568` | Add the Phase 5 evaluation harness: a resumable parallel sweep, determinism proven |
| `d09878f` | Configure pyright so its output is short enough to read: 519 errors to six |
| `95799b4` | Close the Phase 6 audit: twelve defects fixed, a thirteenth found |
| `abea2e8` | Close Phase 6: the dashboard runs, four defects found by driving it |
| `328b8ca` | Refuse non-finite input without crashing the refusal |
| `57a91ed` | Add the Phase 6 dashboard: API, frontend and their test suites |
| `efc2f22` | Fix the four open audit findings; correct a profiler-inflated timing |
| `505b71f` | Close Phase 4: three sound audits, two prose defects fixed |
| `2e75d91` | Close routes H and I; audit 22 thresholds; reconcile the families |
| `c61ee52` | Derive 22 thresholds and compose them with a family-wise bound |
| `99efdf7` | Add the detection statistics layer with its honest-run nulls |
| `cec3cc6` | Close the read-count inference routes; argue the timing boundary |
| `adee91b` | Record the hardening round: one finding closed, one still open |
| `f4544fc` | Reconcile the two hardening fixes and re-measure what moved |
| `9c00d5f` | Make the check set uninferable and the isolation check bite |
| `885f342` | Close Phase 3: propagate check-round sifting, fix stale figures |
| `e36e7b1` | Add channel monitor, restrict signer seam, build and verify five attacks |
| `658f2ff` | Add sampled check rounds for channel parameter estimation |
| `ea5ba71` | Add replay defence: session binding and consumed-records ledger |
| `5983c00` | Enforce declaration binding and add attack randomness isolation |
| `cf35087` | Close Phase 2: fix stale claims and verify at full scale |
