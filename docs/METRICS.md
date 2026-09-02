# Project Metrics

**SIH26141** — Quantum-Inspired Cyber Threat Detection for Digital Signature Security

Generated `2026-09-02 22:31 UTC` by `tools/metrics.py`. Every figure is computed from the
repository — do not edit by hand, re-run the script.

## Test suite

```
3036 passed in 1507.37s (0:25:07)
```

- Doctests collected from package modules: **355**
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
| `sih141/attacks/replay.py` | 2324 | 682 | 1313 | 51 | 36 | 3 |
| `sih141/attacks/starvation.py` | 1678 | 333 | 1115 | 21 | 27 | 4 |
| `sih141/attacks/statistics.py` | 570 | 158 | 323 | 3 | 14 | 1 |
| `sih141/detect/__init__.py` | 572 | 263 | 259 | 8 | 2 | 1 |
| `sih141/detect/detector.py` | 2583 | 906 | 1349 | 80 | 26 | 8 |
| `sih141/detect/statistics.py` | 3301 | 962 | 1921 | 57 | 56 | 10 |
| `sih141/detect/thresholds_channel.py` | 2905 | 591 | 1865 | 81 | 34 | 3 |
| `sih141/detect/thresholds_rate.py` | 3216 | 753 | 2003 | 73 | 43 | 4 |
| `sih141/detect/thresholds_structural.py` | 3138 | 668 | 2024 | 51 | 43 | 8 |
| **total** | **57667** | **13790** | **35620** | **1260** | **909** | **109** |

Tests: **37974 lines** across **32 files**, **1861 test functions** defined.
Test-lines to code-lines ratio: **2.75 : 1**

## Live security parameters

Read out of `sih141.protocol` at generation time, so these are whatever the code
actually computes today — not what a document once claimed.

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
| `README.md` | 4415 |
| `JOURNAL.md` | 55779 |
| `docs/METRICS.md` | 888 |
| `docs/PHASE1.md` | 4078 |
| `docs/PHASE2.md` | 10056 |
| `docs/PHASE3.md` | 15026 |
| `docs/PHASE4.md` | 9443 |
| `docs/QDS.md` | 4624 |
| **total** | **104309** |

Working-journal entries: **151** (temporary; deleted at the end of Phase 7).

## Repository

- Commits: **18**

| Commit | Subject |
| --- | --- |
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
| `8182fc4` | runway doc update |
| `cf32fc0` | Harden checkpoint against concurrent-agent races |
| `64185f9` | Add pooled matched-count floor and close split-coin repudiation |
| `e17328b` | Fix non-repudiation bound and add matched-count floor |
| `34aebea` | Add Phase 1 quantum core and Phase 2 QDS protocol |
