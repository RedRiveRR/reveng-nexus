"""POSIX process-tree guard for stdio MCP servers.

Usage: ``python -I _stdio_guard.py -- <executable> [args...]``

The MCP SDK (mcp 2.3, ``client/stdio.py`` ``_stop_server_process``) closes a stdio server's stdin
and kills the server's process group only if the server is still running two seconds later. A
server that exits promptly therefore leaves every worker it started running; the SDK documents
this as deliberate on POSIX (on Windows its Job Object reaps them). Nexus starts stdio servers on
POSIX through this guard:

* the server runs as the guard's child, in a new process group of its own, with the guard's
  stdin, stdout and stderr, argv and working directory, and no shell;
* its environment is the one Nexus built, passed byte for byte through ``GUARD_ENV_PREFIX``
  variables (see ``encode_environment``) and never the guard's own: the guard's interpreter
  changes its environment at start-up (PEP 538 locale coercion sets ``LC_CTYPE``);
* when the server exits, the guard empties that group: SIGTERM, then SIGKILL only if members are
  left after a bounded grace period, so the server's descendants do not outlive it;
* SIGTERM, SIGINT and SIGHUP sent to the guard (the SDK escalates with SIGTERM when the server
  does not exit) send SIGTERM to the server's group and arm a SIGKILL for the end of the grace
  period. A signal the guard inherited as ignored stays ignored, by the guard and the server,
  except SIGTERM: the server inherits it ignored, the guard still acts on it;
* the guard exits with the server's status, 128 + N when the server died of signal N.

The guard never signals its own process group, only the one it created. Not covered: descendants
that leave the server's group (``setsid``, daemonising double forks), and a guard killed outright
(SIGKILL) while its server ignores stdin EOF, since the server's group is then out of the SDK's
reach. Closing these needs OS-level containment (a Linux subreaper or parent-death signal,
cgroups), which this guard does not attempt.

Signal handlers only send signals, arm a timer and record diagnostics; output is written by the
main flow. Standard library only and never imports Nexus, so it runs isolated (``python -I``).
"""

from __future__ import annotations

import base64
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from typing import Any

# SIGTERM -> SIGKILL grace for the server's group. Shorter than the SDK's 2 s windows, so the
# guard finishes (and exits) before the SDK escalates further.
_TERM_GRACE = 1.0
_POLL = 0.02
# mcp.py imports this module on every platform (for encode_environment); Windows has no SIGHUP.
_FORWARDED = tuple(getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name))

# The server's environment travels in numbered chunks: Linux limits one environment string to
# 128 KiB (MAX_ARG_STRLEN).
GUARD_ENV_PREFIX = "REVENG_NEXUS_GUARD_ENV_"
_CHUNK = 64 * 1024


def encode_environment(env: Mapping[str, str]) -> dict[str, str]:
    """The ``GUARD_ENV_PREFIX`` variables that carry ``env`` exactly (keys and values as the OS
    sees them, ``os.fsencode``) to the server. Raises ValueError for what no OS environment can
    hold (a NUL byte, or "=" in a name), which would fail the launch anyway."""
    entries = []
    for key, value in env.items():
        raw_key, raw_value = os.fsencode(key), os.fsencode(value)
        if not raw_key or b"=" in raw_key or b"\0" in raw_key + raw_value:
            raise ValueError(f"environment variable {key!r} cannot be passed to a process")
        entries.append(raw_key + b"=" + raw_value)
    blob = base64.b64encode(b"\0".join(entries)).decode("ascii")
    chunks = [blob[i : i + _CHUNK] for i in range(0, len(blob), _CHUNK)] or [""]
    return {f"{GUARD_ENV_PREFIX}{index}": chunk for index, chunk in enumerate(chunks)}


def decode_environment(environ: Mapping[str, str]) -> dict[bytes, bytes] | None:
    """The environment carried by ``environ``'s ``GUARD_ENV_PREFIX`` variables; None if there are
    none. Raises ValueError for an incomplete or malformed set."""
    chunks = {k[len(GUARD_ENV_PREFIX) :]: v for k, v in environ.items() if k.startswith(GUARD_ENV_PREFIX)}
    if not chunks:
        return None
    if sorted(chunks) != sorted(str(i) for i in range(len(chunks))):
        raise ValueError("incomplete environment chunks")
    raw = base64.b64decode("".join(chunks[str(i)] for i in range(len(chunks))), validate=True)
    env: dict[bytes, bytes] = {}
    for entry in raw.split(b"\0") if raw else []:
        key, sep, value = entry.partition(b"=")
        if not key or not sep:
            raise ValueError("malformed environment entry")
        env[key] = value
    return env


def _note(message: str) -> None:
    """Report on stderr with one unbuffered write (never from a signal handler)."""
    try:
        os.write(2, f"reveng-nexus stdio guard: {message}\n".encode(errors="replace"))
    except OSError:
        pass


def _proc_has_live_member(pgid: int) -> bool | None:
    """Linux: whether a non-zombie process is in the group; None where /proc is unavailable.

    A killed descendant stays a group member as a zombie until its new parent reaps it, and a PID 1
    that does not reap (some containers) never does, so ``killpg(pgid, 0)`` alone cannot tell an
    emptied group from a running one.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as stat_file:
                stat = stat_file.read()
        except OSError:
            continue  # exited meanwhile
        fields = stat[stat.rindex(b")") + 2 :].split()
        if int(fields[2]) == pgid and fields[0] != b"Z":
            return True
    return False


class _Group:
    """The server's process group, addressed by the server's PID (its process-group id).

    POSIX does not reuse a PID while it is a process-group id, so the group stays addressable
    after the server itself has exited and been reaped.
    """

    def __init__(self) -> None:
        self.pgid: int | None = None
        self.stop_requested = False
        self.kill_at: float | None = None  # monotonic deadline of an armed SIGKILL
        self.problems: dict[str, str] = {}  # one entry per kind, written out by the main flow

    def send(self, sig: int) -> bool:
        """Signal the group; False once it no longer exists. Safe in a signal handler."""
        assert self.pgid is not None
        try:
            os.killpg(self.pgid, sig)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            # Some member is not ours to signal (or, on macOS, an unreaped zombie): EPERM does not
            # prove the group gone. Record it once; probes (signal 0) are expected to hit it.
            if sig:
                self.problems.setdefault(f"sig{sig}", f"cannot send signal {sig} to process group {self.pgid}: {exc}")
        return True

    def alive(self) -> bool:
        if not self.send(0):
            return False
        assert self.pgid is not None
        live = _proc_has_live_member(self.pgid)
        return True if live is None else live

    def request_stop(self, _signum: int = 0, _frame: Any = None) -> None:
        """Signal handler: SIGTERM the group now, SIGKILL it when the grace period ends."""
        self.stop_requested = True
        if self.pgid is None or self.kill_at is not None:
            return  # not started yet (applied right after start-up) or already stopping
        self.kill_at = time.monotonic() + _TERM_GRACE
        self.send(signal.SIGTERM)
        signal.setitimer(signal.ITIMER_REAL, _TERM_GRACE)

    def on_alarm(self, _signum: int, _frame: Any) -> None:
        self.send(signal.SIGKILL)

    def empty(self) -> None:
        """After the server exited: SIGTERM what is left, SIGKILL whatever outlives the grace."""
        if self.kill_at is None:
            if not self.send(signal.SIGTERM):
                return
            deadline = time.monotonic() + _TERM_GRACE
        else:
            deadline = self.kill_at  # SIGTERM already sent; keep the deadline it armed
        while time.monotonic() < deadline:
            if not self.alive():
                return
            time.sleep(_POLL)
        self.send(signal.SIGKILL)


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] != "--":
        _note("usage: _stdio_guard.py -- <executable> [args...]")
        return 2
    try:
        env = decode_environment(os.environ)
    except ValueError as exc:
        _note(f"refusing to start {argv[1]!r}: invalid {GUARD_ENV_PREFIX}* variables ({exc})")
        return 2
    group = _Group()
    inherited = {sig: signal.getsignal(sig) for sig in _FORWARDED}
    # Before start-up, so a termination request can never orphan a just-started server. exec()
    # resets caught signals to their defaults; ignored ones stay ignored, as without the guard.
    for sig in _FORWARDED:
        if inherited[sig] != signal.SIG_IGN:
            signal.signal(sig, group.request_stop)
    try:
        server = subprocess.Popen(argv[1:], env=env, process_group=0)
    except OSError as exc:
        _note(f"could not start {argv[1]!r}: {exc}")
        return 127
    group.pgid = server.pid
    signal.signal(signal.SIGALRM, group.on_alarm)
    if inherited[signal.SIGTERM] == signal.SIG_IGN:
        signal.signal(signal.SIGTERM, group.request_stop)  # the SDK's escalation must still work
    # Drop the guard's own copies of stdin and stdout: end-of-stream is decided by the server.
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    if devnull > 2:
        os.close(devnull)
    if group.stop_requested:
        group.request_stop()  # arrived during start-up
    status = server.wait()
    group.empty()
    signal.setitimer(signal.ITIMER_REAL, 0)
    for problem in group.problems.values():
        _note(problem)
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
