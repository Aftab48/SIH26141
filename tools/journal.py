"""Append-only working journal for the SIH26141 build.

WHY THIS EXISTS
---------------
Many subagents run concurrently. If they all appended to one Markdown file they
would clobber each other, so instead **every entry is its own immutable file**
under ``journal/entries/`` and ``JOURNAL.md`` is *rendered* from them. Nothing is
ever edited or deleted by a later writer -- additions only.

Filenames embed a UTC timestamp plus a random suffix, so two agents writing in the
same millisecond cannot collide and no shared counter has to be read-modify-written.

USAGE
-----
Add an entry (this is what subagents call)::

    python tools/journal.py add --phase 3 --kind issue \
        --author "impl:forgery" --title "Short title" --body "What happened and why."

``--body`` may also be piped on stdin, which avoids shell quoting pain::

    python tools/journal.py add --phase 3 --kind decision --author me \
        --title "Chose X over Y" --stdin < note.txt

Re-render the human-readable log::

    python tools/journal.py render

LIFECYCLE
---------
This journal is TEMPORARY. It is amended phase to phase and deleted at the end of
Phase 7, on the maintainer's explicit say-so. It is not part of the deliverable --
``docs/METRICS.md`` and the ``docs/PHASE*.md`` notes are.
"""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "journal" / "entries"
RENDERED = ROOT / "JOURNAL.md"

KINDS = ("decision", "issue", "fix", "finding", "deadend", "note")

PHASE_TITLES = {
    0: "Scaffold",
    1: "Quantum core",
    2: "QDS protocol",
    3: "Attack suite",
    4: "Detection engine",
    5: "Evaluation",
    6: "Dashboard",
    7: "Submission docs",
}

KIND_MARK = {
    "decision": "D",
    "issue": "!",
    "fix": "+",
    "finding": "*",
    "deadend": "x",
    "note": "-",
}


def _slug(text: str, limit: int = 48) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (s[:limit].rstrip("-")) or "entry"


def add(phase: int, kind: str, author: str, title: str, body: str,
        stamp: str | None = None) -> Path:
    """Write one immutable journal entry and return its path."""
    if kind not in KINDS:
        raise SystemExit(f"--kind must be one of {', '.join(KINDS)}; got {kind!r}")
    ENTRIES.mkdir(parents=True, exist_ok=True)
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    name = f"{stamp.replace(':', '')}-{uuid.uuid4().hex[:8]}-{_slug(title)}.md"
    path = ENTRIES / name
    path.write_text(
        "---\n"
        f"phase: {phase}\n"
        f"kind: {kind}\n"
        f"author: {author}\n"
        f"time: {stamp}\n"
        f"title: {title}\n"
        "---\n\n"
        f"{body.strip()}\n",
        encoding="utf-8",
    )
    return path


def _parse(path: Path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8")
    meta: dict[str, str] = {"body": "", "title": path.stem, "phase": "0",
                            "kind": "note", "author": "?", "time": ""}
    if raw.startswith("---"):
        _, _, rest = raw.partition("---\n")
        head, _, body = rest.partition("---\n")
        for line in head.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                meta[key.strip()] = value.strip()
        meta["body"] = body.strip()
    else:
        meta["body"] = raw.strip()
    return meta


def render() -> Path:
    entries = sorted(ENTRIES.glob("*.md")) if ENTRIES.is_dir() else []
    parsed = [_parse(p) for p in entries]
    parsed.sort(key=lambda m: (int(m.get("phase", 0)), m.get("time", "")))

    out: list[str] = []
    out.append("# Working Journal")
    out.append("")
    out.append("**SIH26141** — decisions, issues, dead ends and findings, phase to phase.")
    out.append("")
    out.append("> **Temporary file.** Append-only: entries are never edited or removed, only")
    out.append("> added. Rendered from `journal/entries/` by `tools/journal.py render` — edit")
    out.append("> the entries, not this file. Scheduled for deletion at the end of Phase 7,")
    out.append("> on the maintainer's explicit instruction. The permanent record is")
    out.append("> `docs/METRICS.md` and the `docs/PHASE*.md` notes.")
    out.append("")

    counts: dict[str, int] = {}
    for m in parsed:
        counts[m["kind"]] = counts.get(m["kind"], 0) + 1
    if parsed:
        tally = " · ".join(f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: -kv[1]))
        out.append(f"**{len(parsed)} entries** — {tally}")
        out.append("")

    current = None
    for m in parsed:
        phase = int(m.get("phase", 0))
        if phase != current:
            current = phase
            out.append("")
            out.append(f"## Phase {phase} — {PHASE_TITLES.get(phase, '')}")
            out.append("")
        mark = KIND_MARK.get(m["kind"], "-")
        out.append(f"### `[{mark}]` {m['title']}")
        out.append("")
        out.append(f"*{m['kind']} · {m['author']} · {m.get('time', '')}*")
        out.append("")
        out.append(m["body"])
        out.append("")

    if not parsed:
        out.append("_No entries yet._")
        out.append("")

    RENDERED.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    return RENDERED


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="append one immutable entry")
    a.add_argument("--phase", type=int, required=True)
    a.add_argument("--kind", required=True, choices=KINDS)
    a.add_argument("--author", required=True,
                   help="agent label, e.g. 'impl:forgery', or a person")
    a.add_argument("--title", required=True)
    a.add_argument("--body", default="")
    a.add_argument("--stdin", action="store_true", help="read the body from stdin")

    sub.add_parser("render", help="rebuild JOURNAL.md from journal/entries/")

    ns = ap.parse_args(argv)
    if ns.cmd == "add":
        body = sys.stdin.read() if ns.stdin else ns.body
        if not body.strip():
            raise SystemExit("empty body: pass --body or --stdin")
        path = add(ns.phase, ns.kind, ns.author, ns.title, body)
        render()
        print(f"added {path.relative_to(ROOT).as_posix()}")
    else:
        print(f"wrote {render().relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
