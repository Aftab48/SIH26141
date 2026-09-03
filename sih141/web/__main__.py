"""The one command: ``python -m sih141.web``.

One process serving both halves -- the JSON API and the static frontend -- with
no Node, no bundler and no build step. Clone, ``pip install -r
requirements.txt``, run this, open the printed address.

.. code-block:: text

    python -m sih141.web                    # http://127.0.0.1:8141
    python -m sih141.web --port 9000
    python -m sih141.web --host 0.0.0.0     # deliberate, and not the default

The default host is ``127.0.0.1`` and not ``0.0.0.0``. This server runs
unauthenticated quantum simulation on request; binding it to every interface is
a thing an operator may want at a venue and is not a thing that should happen
because nobody chose.

Nothing here reaches a network (:ref:`sih141.web.api <nothing-is-fetched>`),
and it prints the address rather than opening a browser, so nothing is
launched that the operator did not ask for.
"""

from __future__ import annotations

import argparse
from typing import Sequence

import uvicorn

from sih141 import __version__
from sih141.web.api import STATIC_DIR, create_app
from sih141.web.limits import LIVE_KEY_LENGTH_MAX, MAX_CONCURRENT_RUNS


__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser.

    Returns
    -------
    argparse.ArgumentParser

    Examples
    --------
    >>> from sih141.web.__main__ import build_parser
    >>> args = build_parser().parse_args([])
    >>> args.host, args.port
    ('127.0.0.1', 8141)
    >>> build_parser().parse_args(["--port", "9000"]).port
    9000
    """
    parser = argparse.ArgumentParser(
        prog="python -m sih141.web",
        description=(
            "Serve the SIH26141 detection dashboard: the JSON API and the "
            "static frontend, in one process, fetching nothing from a network."
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Interface to bind. Defaults to loopback; pass 0.0.0.0 "
            "deliberately to expose the demo on a venue network."
        ),
    )
    parser.add_argument("--port", type=int, default=8141, help="TCP port.")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        help="uvicorn log level.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Start the server.

    Parameters
    ----------
    argv : sequence of str or None, optional
        Command line, for testing. ``None`` reads :data:`sys.argv`.

    Returns
    -------
    int
        Process exit status.
    """
    args = build_parser().parse_args(argv)
    frontend = "present" if (STATIC_DIR / "index.html").is_file() else "MISSING"
    print(
        f"SIH26141 {__version__} -- http://{args.host}:{args.port}\n"
        f"  frontend        {frontend} ({STATIC_DIR})\n"
        f"  live key length up to L = {LIVE_KEY_LENGTH_MAX}; longer runs are "
        f"refused, never clamped\n"
        f"  concurrent runs at most {MAX_CONCURRENT_RUNS}\n"
        f"  network         nothing is fetched; /docs is off because Swagger "
        f"UI loads from a CDN",
        flush=True,
    )
    uvicorn.run(
        create_app(), host=args.host, port=args.port, log_level=args.log_level
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
