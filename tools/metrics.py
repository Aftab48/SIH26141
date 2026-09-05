"""Generate ``docs/METRICS.md`` from the live repository.

Every figure is COMPUTED, never hand-written, so the file cannot drift out of sync
with the code. If a number here is wrong, this script is wrong.

    python tools/metrics.py              # full run, executes the test suite
    python tools/metrics.py --no-tests   # skip the suite (fast, for a quick refresh)

Deliberately dependency-free (stdlib plus a pytest subprocess) so it still works when
the package itself is mid-edit.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIRS = ("sih141/core", "sih141/protocol", "sih141/attacks",
                "sih141/detect", "sih141/eval", "sih141/web")


def run(cmd: list[str], timeout: int = 1800) -> str:
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr
    except Exception as exc:  # noqa: BLE001 - this is a reporting tool
        return f"<failed: {exc}>"


def source_stats(path: Path) -> dict[str, int]:
    """Split a module into code / docstring / comment / blank lines."""
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines()
    total = len(lines)
    comments = sum(1 for ln in lines if ln.strip().startswith("#"))
    blank = sum(1 for ln in lines if not ln.strip())
    doc = defs = classes = 0
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {"total": total, "code": max(0, total - comments - blank), "doc": 0,
                "comments": comments, "blank": blank, "defs": 0, "classes": 0}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            text = ast.get_docstring(node, clean=False)
            if text:
                doc += text.count("\n") + 1
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs += 1
        elif isinstance(node, ast.ClassDef):
            classes += 1
    return {"total": total, "code": max(0, total - doc - comments - blank), "doc": doc,
            "comments": comments, "blank": blank, "defs": defs, "classes": classes}


PROBE = r'''
import json
out = {}
try:
    import sih141.protocol as P
    params = getattr(P, "DEFAULT_PARAMS", None)
    if params is not None:
        for name in ("key_length", "s_a", "s_v", "bases"):
            if hasattr(params, name):
                v = getattr(params, name)
                out[name] = len(v) if name == "bases" and hasattr(v, "__len__") else v
    import sih141.protocol.analysis as A
    for fn in ("recipient_forgery_bound", "recipient_forgery_probability",
               "forgery_probability", "forgery_bound", "repudiation_bound",
               "averaged_repudiation_bound", "repudiation_bound_with_abort",
               "matched_shortfall_probability"):
        f = getattr(A, fn, None)
        if f is None:
            continue
        try:
            out[fn] = f(params)
        except TypeError:
            out[fn] = "(requires an explicit argument by design)"
        except Exception as exc:
            out[fn] = "<%s>" % type(exc).__name__
except Exception as exc:
    out["_error"] = "%s: %s" % (type(exc).__name__, exc)
print("@@METRICS@@" + json.dumps(out, default=str))
'''


def security_rows() -> list[str]:
    raw = run([sys.executable, "-c", PROBE], timeout=600)
    line = next((l for l in raw.splitlines() if l.startswith("@@METRICS@@")), None)
    if not line:
        return ["| _package not importable at generation time_ | n/a |"]
    data = json.loads(line[len("@@METRICS@@"):])
    rows = []
    for key, value in data.items():
        if isinstance(value, float):
            value = f"{value:.6g}"
        rows.append(f"| `{key}` | {value} |")
    return rows or ["| _no parameters found_ | n/a |"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-tests", action="store_true", help="skip running the suite")
    ns = ap.parse_args()

    out: list[str] = []
    add = out.append
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    add("# Project Metrics")
    add("")
    add("**SIH26141**: Quantum-Inspired Cyber Threat Detection for Digital Signature Security")
    add("")
    add(f"Generated `{stamp}` by `tools/metrics.py`. Every figure is computed from the")
    add("repository, so do not edit by hand, re-run the script.")
    add("")

    # ------------------------------------------------------------------ tests
    add("## Test suite")
    add("")
    if ns.no_tests:
        add("_Skipped (`--no-tests`)._")
    else:
        # Two hours, not the default thirty minutes. The suite is ~3,800 tests
        # and takes 25-40 minutes on an idle machine, but a busy one runs the
        # protocol at roughly half speed (docs/PHASE5.md 11.2 measures the
        # single-threaded rate moving by 49% between two runs of one command).
        # A timeout here does not fail loudly: it writes "<no summary line>"
        # into METRICS.md, which has already shipped once.
        res = run([sys.executable, "-m", "pytest", "--tb=no", "-p", "no:cacheprovider"],
                  timeout=7200)
        summary = next((l.strip() for l in reversed(res.splitlines())
                        if re.search(r"\d+ (passed|failed|error)", l)), "<no summary line>")
        add("```")
        add(summary)
        add("```")
        add("")
        collected = run([sys.executable, "-m", "pytest", "--collect-only",
                         "-p", "no:cacheprovider"], timeout=3600)
        doctests = len(re.findall(r"^sih141[/\\]", collected, re.M))
        add(f"- Doctests collected from package modules: **{doctests}**")
        add("- `--doctest-modules` is enabled over `testpaths = [\"tests\", \"sih141\"]`, so every")
        add("  numeric claim written in a docstring is an executable test. Documentation that")
        add("  lies fails the suite.")
    add("")

    # ---------------------------------------------------------- source volume
    add("## Source volume")
    add("")
    add("| Module | Lines | Code | Docstrings | Comments | Functions | Classes |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    grand = dict.fromkeys(("total", "code", "doc", "comments", "blank", "defs", "classes"), 0)
    for pkg in PACKAGE_DIRS:
        d = ROOT / pkg
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            s = source_stats(f)
            for k in grand:
                grand[k] += s[k]
            add(f"| `{pkg}/{f.name}` | {s['total']} | {s['code']} | {s['doc']} | "
                f"{s['comments']} | {s['defs']} | {s['classes']} |")
    add(f"| **total** | **{grand['total']}** | **{grand['code']}** | **{grand['doc']}** | "
        f"**{grand['comments']}** | **{grand['defs']}** | **{grand['classes']}** |")
    add("")

    tests_dir = ROOT / "tests"
    if tests_dir.is_dir():
        files = sorted(tests_dir.glob("*.py"))
        t = dict.fromkeys(("total", "defs"), 0)
        for f in files:
            s = source_stats(f)
            t["total"] += s["total"]
            t["defs"] += s["defs"]
        add(f"Tests: **{t['total']} lines** across **{len(files)} files**, "
            f"**{t['defs']} test functions** defined.")
        if grand["code"]:
            add(f"Test-lines to code-lines ratio: **{t['total'] / grand['code']:.2f} : 1**")
        add("")

    # ------------------------------------------------------ security numbers
    add("## Live security parameters")
    add("")
    add("Read out of `sih141.protocol` at generation time, so these are whatever the code")
    add("actually computes today, not what a document once claimed.")
    add("")
    add("| Quantity | Value |")
    add("| --- | --- |")
    out.extend(security_rows())
    add("")

    # --------------------------------------------------------------- writing
    add("## Documentation")
    add("")
    add("| File | Words |")
    add("| --- | ---: |")
    doc_total = 0
    candidates = [ROOT / "README.md", ROOT / "JOURNAL.md", *sorted((ROOT / "docs").glob("*.md"))]
    for f in candidates:
        if f.exists():
            words = len(f.read_text(encoding="utf-8").split())
            doc_total += words
            add(f"| `{f.relative_to(ROOT).as_posix()}` | {words} |")
    add(f"| **total** | **{doc_total}** |")
    add("")

    entries = ROOT / "journal" / "entries"
    if entries.is_dir():
        add(f"Working-journal entries: **{len(list(entries.glob('*.md')))}** "
            "(temporary; deleted at the end of Phase 7).")
        add("")

    # ------------------------------------------------------------------- git
    add("## Repository")
    add("")
    count = run(["git", "rev-list", "--count", "HEAD"]).strip()
    add(f"- Commits: **{count}**")
    add("")
    add("| Commit | Subject |")
    add("| --- | --- |")
    for line in run(["git", "log", "--pretty=%h|%s", "-25"]).splitlines():
        short, sep, subject = line.partition("|")
        if sep:
            add(f"| `{short.strip()}` | {subject.strip()} |")
    add("")

    target = ROOT / "docs" / "METRICS.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {target.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
