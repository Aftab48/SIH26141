"""Commit and push a phase's work -- but only if it is worth committing and it is green.

Called at the end of each workflow phase. It decides for itself whether anything
meaningful happened, so a phase that changed nothing (an audit that found nothing and
reverted its probes) leaves no empty commit behind.

    python tools/checkpoint.py --label "Add pooled matched-count floor"

Exit status is 0 in all normal outcomes, including "nothing to commit" -- a phase that
legitimately produced no edits is not a failure.

DECISION RULES
--------------
1. Nothing changed              -> do nothing, report, exit 0.
2. Only ignorable churn changed -> do nothing, report, exit 0.
   ("ignorable" = files the project regenerates or that carry no source meaning:
    JOURNAL.md and docs/METRICS.md on their own are not a reason to commit, though
    they ARE included once something else justifies the commit.)
3. Suite is red                 -> do NOT commit, report loudly, exit 0 unless
                                   --strict. Never push a broken tree.
4. Otherwise                    -> stage all, commit with the one-line label, push.

The commit subject is exactly --label, capped at 72 characters and never given a body.
Detail belongs in JOURNAL.md and docs/PHASE*.md, not in git history.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_SUBJECT = 72

# Changed on their own, these do not justify a commit; alongside real work they ride along.
IGNORABLE = {"JOURNAL.md", "docs/METRICS.md"}


def git(*args: str, check: bool = False) -> tuple[int, str]:
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{p.stdout}{p.stderr}")
    return p.returncode, (p.stdout + p.stderr).strip()


def changed_paths() -> list[tuple[str, str]]:
    """Parse ``git status --porcelain`` into (status, path) pairs.

    Careful with the offsets. Porcelain emits a two-character status field, so an
    unstaged modification starts with a LEADING SPACE (" M path"). ``git()`` strips
    the combined output, which removes that space from the first line only -- so a
    fixed ``line[3:]`` slice silently drops the first character of one path, turning
    ``.gitignore`` into ``gitignore``. That is not merely cosmetic: paths are matched
    against IGNORABLE, so a mangled name defeats the "do not commit for regenerated
    files alone" rule. Splitting on the status field instead is robust either way.
    """
    _, out = git("status", "--porcelain")
    entries = []
    for line in out.splitlines():
        if not line.strip():
            continue
        status, path = line[:2], line[2:].strip()
        entries.append((status.strip(), path.strip('"')))
    return entries


def tree_fingerprint() -> dict[str, str]:
    """Hash every file git would commit.

    Guards a real hazard: agents run concurrently in this repo, and mutation-testing
    agents deliberately edit source, run the suite, then revert. If one of them mutates
    a file *between* our test run and our ``git add``, we would commit code the suite
    never saw. That happened once -- a broken pooled floor (``1.0 *`` instead of
    ``2.0 *``) reached origin inside an otherwise-green commit. Never again: we
    fingerprint before testing and re-check immediately before staging.
    """
    _, listing = git("ls-files", "-co", "--exclude-standard")
    prints: dict[str, str] = {}
    for rel in listing.splitlines():
        rel = rel.strip().strip('"')
        if not rel:
            continue
        f = ROOT / rel
        try:
            prints[rel] = hashlib.md5(f.read_bytes()).hexdigest()
        except OSError:
            prints[rel] = "<unreadable>"
    return prints


def describe_drift(before: dict[str, str], after: dict[str, str]) -> list[str]:
    drift = []
    for path in sorted(set(before) | set(after)):
        b, a = before.get(path), after.get(path)
        if b != a:
            kind = "added" if b is None else "removed" if a is None else "modified"
            drift.append(f"{kind}: {path}")
    return drift


def suite_is_green() -> tuple[bool, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "--tb=no", "-p", "no:cacheprovider"],
                       cwd=ROOT, capture_output=True, text=True)
    text = p.stdout + p.stderr
    summary = next((l.strip() for l in reversed(text.splitlines())
                    if re.search(r"\d+ (passed|failed|error)", l)), "<no summary line>")
    green = p.returncode == 0 and "failed" not in summary and "error" not in summary
    return green, summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--label", required=True,
                    help="one-line commit subject; no body is ever added")
    ap.add_argument("--no-push", action="store_true", help="commit but do not push")
    ap.add_argument("--no-tests", action="store_true",
                    help="skip the suite (use only when a caller has just run it)")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if the suite is red or nothing was committed")
    ap.add_argument("--dry-run", action="store_true",
                    help="report the decision without staging, committing or pushing")
    ns = ap.parse_args()

    subject = ns.label.strip().rstrip(".")
    if len(subject) > MAX_SUBJECT:
        subject = subject[:MAX_SUBJECT].rstrip()
        print(f"note: label truncated to {MAX_SUBJECT} chars")

    entries = changed_paths()
    if not entries:
        print("checkpoint: nothing changed, no commit.")
        return 1 if ns.strict else 0

    substantive = [p for _, p in entries if p not in IGNORABLE]
    if not substantive:
        print("checkpoint: only regenerated files changed "
              f"({', '.join(p for _, p in entries)}), no commit.")
        return 1 if ns.strict else 0

    print(f"checkpoint: {len(entries)} path(s) changed, {len(substantive)} substantive:")
    for status, path in entries[:25]:
        print(f"   {status or '??':<3} {path}")
    if len(entries) > 25:
        print(f"   ... and {len(entries) - 25} more")

    before = tree_fingerprint()

    if not ns.no_tests:
        print(f"checkpoint: fingerprinted {len(before)} files; running the suite ...")
        green, summary = suite_is_green()
        print(f"checkpoint: {summary}")
        if not green:
            print("checkpoint: SUITE IS RED -- refusing to commit or push.")
            print("            Fix the failures, then re-run this checkpoint.")
            return 1 if ns.strict else 0

        drift = describe_drift(before, tree_fingerprint())
        if drift:
            print("checkpoint: TREE CHANGED WHILE THE SUITE WAS RUNNING -- refusing to commit.")
            print("            A concurrent agent edited files after the tests passed, so the")
            print("            suite did not validate what would be committed.")
            for line in drift[:20]:
                print(f"              {line}")
            print("            Re-run the checkpoint once no agent is mid-edit.")
            return 1 if ns.strict else 0

    if ns.dry_run:
        print(f"checkpoint: --dry-run, would commit {len(entries)} path(s) "
              f"as {subject!r} and push.")
        return 0

    drift = describe_drift(before, tree_fingerprint())
    if drift:
        print("checkpoint: tree changed just before staging -- refusing to commit.")
        for line in drift[:20]:
            print(f"              {line}")
        return 1 if ns.strict else 0

    git("add", "-A", check=True)
    rc, _ = git("diff", "--cached", "--quiet")
    if rc == 0:
        print("checkpoint: everything already committed, nothing staged.")
        return 1 if ns.strict else 0

    git("commit", "-q", "-m", subject, check=True)
    _, head = git("log", "-1", "--pretty=%h %s")
    print(f"checkpoint: committed {head}")

    if ns.no_push:
        print("checkpoint: --no-push, leaving it local.")
        return 0

    rc, out = git("push", "origin", "HEAD")
    if rc != 0:
        print(f"checkpoint: push FAILED (commit is safe locally):\n{out}")
        return 1 if ns.strict else 0
    print("checkpoint: pushed to origin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
