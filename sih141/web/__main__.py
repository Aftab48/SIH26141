"""The one command: ``python -m sih141.web``.

One process serving both halves -- the JSON API and the static frontend -- with
no Node, no bundler and no build step. Clone, ``pip install -r
requirements.txt``, run this, open the printed address.

.. code-block:: text

    python -m sih141.web                    # http://127.0.0.1:8141
    python -m sih141.web --port 9000
    python -m sih141.web --host 0.0.0.0     # deliberate, and not the default
    python -m sih141.web --audit-log run-events.jsonl

The last of those is the one thing this server can be asked to write. Without
it the security event log is kept in memory and dies with the process
(:ref:`sih141.web.api <the-server-now-keeps-something>`).

The default host is ``127.0.0.1`` and not ``0.0.0.0``. This server runs
unauthenticated quantum simulation on request; binding it to every interface is
a thing an operator may want at a venue and is not a thing that should happen
because nobody chose.

Nothing here reaches a network (:ref:`sih141.web.api <nothing-is-fetched>`),
and it prints the address rather than opening a browser, so nothing is
launched that the operator did not ask for.

.. _bind-before-you-announce:

The socket is opened BEFORE the address is printed
---------------------------------------------------
The banner used to be printed first and the bind attempted afterwards, inside
``uvicorn.run``. Start a second instance on a port that is already busy and the
output read: the address, ``Started server process``, ``Application startup
complete``, then the bind error, then ``Application shutdown complete`` -- which
is the last line and looks like a clean stop. The exit status was ``1``, so
scripts were fine; the human reading the top of the output was not, and the
failure mode is specific and bad. A presenter who left an instance running an
hour ago restarts, reads the address line, opens it, and demonstrates against
the OLD process -- serving whatever assets it was started with.

So :func:`open_listeners` binds first and hands the sockets to uvicorn. A busy
port fails before anything is announced, with a sentence naming the port, and
no address that was never bound is ever printed.

.. _both-address-families:

Both loopback families, because ``localhost`` is two addresses
---------------------------------------------------------------
``127.0.0.1`` and ``0.0.0.0`` are IPv4 wildcards and nothing more: a socket
bound to either accepts nothing on ``::1``. On Windows an IPv6 socket is
``IPV6_V6ONLY`` by default, so ``--host ::`` is the mirror image -- measured
here, ``--host ::`` answered ``http://[::1]:PORT`` and not
``http://127.0.0.1:PORT``. A browser resolving ``localhost`` to ``::1`` without
falling back therefore cannot open the demo at the address an operator is most
likely to type. Most browsers do fall back; "most" is not a thing to discover at
a venue.

So a loopback or wildcard host opens **one socket per family** and the banner
prints every address that was actually bound. A machine with no IPv6 stack
simply gets the one socket, and the banner says which -- it is never a silent
half-success.
"""

from __future__ import annotations

import argparse
import socket
from typing import Sequence

import uvicorn

from sih141 import __version__
from sih141.audit import DEFAULT_CAPACITY, AuditLog
from sih141.web.api import STATIC_DIR, create_app
from sih141.web.limits import (
    LIVE_KEY_LENGTH_MAX,
    MAX_CONCURRENT_RUNS,
    MAX_REQUEST_BYTES,
)


__all__ = ["bind_hosts", "build_parser", "main", "open_listeners"]


#: Hosts that mean "the local machine" and are therefore opened in both address
#: families. Anything else is taken literally and bound exactly once: an
#: operator who names an interface has named the one they mean.
_LOOPBACK_PAIRS: dict[str, tuple[str, ...]] = {
    "127.0.0.1": ("127.0.0.1", "::1"),
    "localhost": ("127.0.0.1", "::1"),
    "::1": ("::1", "127.0.0.1"),
    "0.0.0.0": ("0.0.0.0", "::"),
    "::": ("::", "0.0.0.0"),
}


def bind_hosts(host: str) -> tuple[str, ...]:
    """Return every address ``host`` should be bound on, in order.

    Parameters
    ----------
    host : str
        The ``--host`` argument.

    Returns
    -------
    tuple of str
        One entry for a named interface; two -- one per address family -- for
        loopback and for the wildcards (:ref:`both-address-families`).

    Examples
    --------
    >>> from sih141.web.__main__ import bind_hosts
    >>> bind_hosts("127.0.0.1")
    ('127.0.0.1', '::1')
    >>> bind_hosts("0.0.0.0")
    ('0.0.0.0', '::')

    A named interface is one socket, because the operator named it:

    >>> bind_hosts("192.168.1.40")
    ('192.168.1.40',)
    """
    return _LOOPBACK_PAIRS.get(host, (host,))


def open_listeners(
    host: str, port: int
) -> tuple[list[socket.socket], list[str], list[str]]:
    """Bind the listening sockets, before anything is printed.

    Parameters
    ----------
    host : str
        The ``--host`` argument.
    port : int
        The port.

    Returns
    -------
    sockets : list of socket.socket
        Bound and listening. Empty only if an exception was raised instead.
    bound : list of str
        The addresses that were bound, as URLs.
    skipped : list of str
        Addresses in the pair that could not be bound and why -- a machine with
        no IPv6 stack, typically. Reported rather than hidden: a half-success
        the operator does not know about is the thing this function exists to
        prevent.

    Raises
    ------
    OSError
        If the FIRST address -- the one the operator actually asked for --
        cannot be bound. That is the busy-port case, and it must fail here,
        loudly, before any address is announced
        (:ref:`bind-before-you-announce`).

    Examples
    --------
    A loopback bind opens both families and reports both:

    >>> import socket as _socket
    >>> from sih141.web.__main__ import open_listeners
    >>> probe = _socket.socket()
    >>> probe.bind(("127.0.0.1", 0))
    >>> free = probe.getsockname()[1]
    >>> probe.close()
    >>> sockets, bound, skipped = open_listeners("127.0.0.1", free)
    >>> "http://127.0.0.1:%d" % free in bound
    True
    >>> for listener in sockets:
    ...     listener.close()

    ``--port 0`` is a free port chosen by the kernel, and what is announced is
    the port that was handed out -- once, for the whole family, so the pair is
    one server on one port:

    >>> sockets, bound, skipped = open_listeners("127.0.0.1", 0)
    >>> ports = {listener.getsockname()[1] for listener in sockets}
    >>> len(ports) == 1 and 0 not in ports
    True
    >>> [url.rsplit(":", 1)[1] for url in bound] == [
    ...     str(listener.getsockname()[1]) for listener in sockets
    ... ]
    True
    >>> for listener in sockets:
    ...     listener.close()

    A busy port raises here rather than being announced and then failing:

    >>> held = _socket.socket()
    >>> held.setsockopt(_socket.SOL_SOCKET, _socket.SO_EXCLUSIVEADDRUSE
    ...                 if hasattr(_socket, "SO_EXCLUSIVEADDRUSE")
    ...                 else _socket.SO_REUSEADDR, 1)
    >>> held.bind(("127.0.0.1", 0))
    >>> held.listen(8)
    >>> busy = held.getsockname()[1]
    >>> try:
    ...     open_listeners("127.0.0.1", busy)
    ... except OSError:
    ...     print("refused, and nothing was printed")
    refused, and nothing was printed
    >>> held.close()
    """
    sockets: list[socket.socket] = []
    bound: list[str] = []
    skipped: list[str] = []
    # The port to bind, which is the REQUESTED port until an ephemeral one has
    # been handed out. `--port 0` means "any free port", and the kernel answers
    # it once per socket: bound naively, the loopback pair lands on two
    # different ports and is two servers, not one. So the first bind fixes the
    # port and the rest of the family follows it -- and if the second family
    # cannot have that port it is `skipped`, reported, like any other
    # half-success here.
    wanted = port
    for index, address in enumerate(bind_hosts(host)):
        family = (
            socket.AF_INET6 if ":" in address else socket.AF_INET
        )
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                # Windows lets a second process bind an address another one is
                # already listening on when both set SO_REUSEADDR, which is how
                # a forgotten instance goes on serving while a new one appears
                # to have started. Refusing is the whole point of binding here.
                listener.setsockopt(
                    socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1
                )
            else:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family is socket.AF_INET6:
                # Keep the two sockets independent rather than letting a
                # dual-stack v6 socket claim the v4 wildcard as well: with both
                # in the list that is a bind conflict on Linux.
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((address, wanted))
            listener.listen(128)
        except OSError as failure:
            listener.close()
            if index == 0:
                for opened in sockets:
                    opened.close()
                raise
            skipped.append(f"{address} ({failure.strerror or failure})")
            continue
        sockets.append(listener)
        # The port the socket ACTUALLY got, never the one that was asked for:
        # they differ under `--port 0`, and an announced address that was
        # never bound is the one thing this function exists to prevent
        # (:ref:`bind-before-you-announce`).
        wanted = listener.getsockname()[1]
        shown = f"[{address}]" if ":" in address else address
        bound.append(f"http://{shown}:{wanted}")
    return sockets, bound, skipped


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
            "deliberately to expose the demo on a venue network. Loopback and "
            "the wildcards are bound in BOTH address families, so a browser "
            "that resolves localhost to ::1 reaches the same server."
        ),
    )
    parser.add_argument("--port", type=int, default=8141, help="TCP port.")
    parser.add_argument(
        "--audit-log",
        default=None,
        metavar="PATH",
        help=(
            "Append the security event log to this file, as JSON Lines, one "
            "line per verification outcome. Without it the log is kept in "
            "memory only and dies with the process; either way it retains at "
            f"most {DEFAULT_CAPACITY} events and GET /api/events serves them."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        help="uvicorn log level.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Start the server.

    Binds first, announces second (:ref:`bind-before-you-announce`), and prints
    only the addresses that were actually bound.

    Parameters
    ----------
    argv : sequence of str or None, optional
        Command line, for testing. ``None`` reads :data:`sys.argv`.

    Returns
    -------
    int
        Process exit status. ``1`` when the port could not be bound or the
        ``--audit-log`` path could not be opened, with a message naming which
        of the two and **no address line at all**. The port is tried first, so
        a start that fails there leaves no log file behind.
    """
    args = build_parser().parse_args(argv)
    try:
        sockets, bound, skipped = open_listeners(args.host, args.port)
    except OSError as failure:
        print(
            f"SIH26141 {__version__} -- COULD NOT START.\n"
            f"  port {args.port} on {args.host} is not available: "
            f"{failure.strerror or failure}\n"
            f"  Nothing is serving and no address is printed above, "
            f"deliberately: an instance you started earlier may still be "
            f"holding this port and answering on it. Stop that one, or pass "
            f"--port with a free port.",
            flush=True,
        )
        return 1
    # AFTER the bind, and this order was chosen rather than fallen into.
    # `AuditLog` opens its file at construction, which creates it, so a log
    # built first left an empty JSON Lines file on the operator's disk every
    # time the port turned out to be busy -- a run that printed "Nothing is
    # serving" and had already written. Both failures still return before the
    # banner, so no address is announced for a server that is not up.
    try:
        audit = AuditLog(path=args.audit_log)
    except OSError as failure:
        for listener in sockets:
            listener.close()
        print(
            f"SIH26141 {__version__} -- COULD NOT START.\n"
            f"  the security event log cannot be written to "
            f"{args.audit_log}: {failure.strerror or failure}\n"
            f"  Nothing is serving. Pass a path in a directory that exists, "
            f"or drop --audit-log and the log is kept in memory.",
            flush=True,
        )
        return 1

    frontend = "present" if (STATIC_DIR / "index.html").is_file() else "MISSING"
    addresses = "\n".join(f"                  {url}" for url in bound)
    print(
        f"SIH26141 {__version__} -- listening, bound before this line was "
        f"printed:\n{addresses}\n"
        + (
            f"  not bound       {', '.join(skipped)}\n"
            if skipped
            else ""
        )
        + f"  frontend        {frontend} ({STATIC_DIR})\n"
        f"  live key length up to L = {LIVE_KEY_LENGTH_MAX}; longer runs are "
        f"refused, never clamped\n"
        f"  concurrent runs at most {MAX_CONCURRENT_RUNS}\n"
        f"  request body    at most {MAX_REQUEST_BYTES} bytes; larger is 413 "
        f"before the app sees it\n"
        f"  security log    "
        + (
            f"appended to {audit.path} and "
            if audit.path is not None
            else "in memory only, "
        )
        + f"at most {audit.capacity} events; GET /api/events\n"
        f"  network         nothing is fetched; /docs is off because Swagger "
        f"UI loads from a CDN",
        flush=True,
    )
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(audit_log=audit), log_level=args.log_level
        )
    )
    server.run(sockets=sockets)
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
