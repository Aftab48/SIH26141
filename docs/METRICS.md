# Project Metrics

**SIH26141** — Quantum-Inspired Cyber Threat Detection for Digital Signature Security

Generated `2026-08-30 21:28 UTC` by `tools/metrics.py`. Every figure is computed from the
repository — do not edit by hand, re-run the script.

## Test suite

```
1421 passed in 318.16s (0:05:18)
```

- Doctests collected from package modules: **112**
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
| `sih141/protocol/__init__.py` | 308 | 162 | 123 | 11 | 0 | 0 |
| `sih141/protocol/analysis.py` | 3447 | 210 | 2683 | 29 | 39 | 2 |
| `sih141/protocol/distribute.py` | 728 | 153 | 477 | 14 | 7 | 1 |
| `sih141/protocol/keys.py` | 620 | 108 | 411 | 3 | 23 | 2 |
| `sih141/protocol/params.py` | 1205 | 348 | 694 | 2 | 20 | 2 |
| `sih141/protocol/records.py` | 668 | 145 | 428 | 4 | 18 | 2 |
| `sih141/protocol/session.py` | 2713 | 767 | 1582 | 77 | 55 | 5 |
| `sih141/protocol/signature.py` | 426 | 82 | 283 | 2 | 11 | 1 |
| `sih141/protocol/symmetrise.py` | 554 | 79 | 407 | 2 | 4 | 1 |
| `sih141/protocol/tally.py` | 1125 | 286 | 706 | 7 | 20 | 3 |
| `sih141/protocol/verify.py` | 2921 | 644 | 1875 | 53 | 39 | 5 |
| **total** | **19089** | **3799** | **12400** | **402** | **298** | **29** |

Tests: **17423 lines** across **16 files**, **939 test functions** defined.
Test-lines to code-lines ratio: **4.59 : 1**

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
| `README.md` | 1759 |
| `JOURNAL.md` | 5148 |
| `docs/METRICS.md` | 609 |
| `docs/PHASE1.md` | 4078 |
| `docs/PHASE2.md` | 9835 |
| `docs/QDS.md` | 4377 |
| **total** | **25806** |

Working-journal entries: **45** (temporary; deleted at the end of Phase 7).

## Repository

- Commits: **5**

| Commit | Subject |
| --- | --- |
| `8182fc4` | runway doc update |
| `cf32fc0` | Harden checkpoint against concurrent-agent races |
| `64185f9` | Add pooled matched-count floor and close split-coin repudiation |
| `e17328b` | Fix non-repudiation bound and add matched-count floor |
| `34aebea` | Add Phase 1 quantum core and Phase 2 QDS protocol |
