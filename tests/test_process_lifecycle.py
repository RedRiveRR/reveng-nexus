"""Process-lifecycle containment for MCP child servers (CLAUDE.md: launched children must be
contained; ``terminate()`` alone orphans grandchildren).

Every test checks that *descendants* are gone, not only the server: by recorded PID, and for the
guard tests also by process group (the guard's and the server's, which ``guard_harness.py``
records). A zombie counts as gone (it has terminated and only waits to be reaped by its new
parent). Waits poll a condition up to a deadline instead of sleeping a fixed time; the one
exception checks that an ignored signal does *not* end the guard within 0.5 s. Every PID and
group a test learns is killed in ``finally`` (``_Guarded.__exit__``), so a failing assertion never
leaves processes behind. POSIX tests are skipped on Windows, where the MCP SDK's Job Object
already reaps stdio trees; there, only the unchanged launch command is checked.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from reveng_nexus.providers._stdio_guard import GUARD_ENV_PREFIX, decode_environment
from reveng_nexus.providers.mcp import STDIO_GUARD, _ProcessTree, _stdio_launch
from reveng_nexus.registry import ProviderManager

MOCK_TREE = str(Path(__file__).parent / "mock_servers" / "mock_tree.py")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX process groups; Windows uses the SDK's Job Object")


# -- helpers ------------------------------------------------------------------------------------
def _gone(pid: int) -> bool:
    """True once ``pid`` has terminated (a zombie counts: it only awaits reaping)."""
    if sys.platform.startswith("linux"):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return True
        return stat[stat.rindex(")") + 2] == "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return state == "" or state.startswith("Z")


async def _survivors(pids, timeout: float = 10.0) -> list[int]:
    """PIDs still alive after polling up to ``timeout`` seconds for all of them to terminate."""
    deadline = time.monotonic() + timeout
    while True:
        alive = [pid for pid in pids if not _gone(pid)]
        if not alive or time.monotonic() >= deadline:
            return alive
        await asyncio.sleep(0.05)


def _kill_all(pids) -> None:
    for pid in pids:
        if not _gone(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


async def _read_pids(path: Path, timeout: float = 30.0) -> dict[str, int]:
    deadline = time.monotonic() + timeout
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise AssertionError(f"mock server never wrote {path}")
        await asyncio.sleep(0.05)
    return json.loads(path.read_text(encoding="utf-8"))


def _tree_provider(pid_file: Path, mode: str = "graceful", **extra) -> dict:
    return {
        "id": "tree",
        "enabled": True,
        "type": "mcp_stdio",
        "command": sys.executable,
        "args": [MOCK_TREE],
        "env": {"MOCK_TREE_PIDS": str(pid_file), "MOCK_TREE_MODE": mode},
        "tool_overrides": {"echo": "read", "initial_environ": "read"},
        "timeout_seconds": extra.pop("timeout_seconds", 20),
        "startup_timeout_seconds": extra.pop("startup_timeout_seconds", 60),
        **extra,
    }


# -- _ProcessTree (launched-HTTP servers) -------------------------------------------------------------
@posix_only
async def test_process_tree_terminate_reaps_a_group_whose_launcher_already_exited(tmp_path):
    """The launched path calls terminate() after the launcher exited ("reap anything it left
    behind"). os.getpgid() fails for a reaped leader, so the group must be addressed by its id."""
    gc_file = tmp_path / "gc.pid"
    code = (
        "import subprocess, sys\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        "open(sys.argv[1], 'w').write(str(gc.pid))\n"
    )  # the launcher exits right after starting its worker
    tree = _ProcessTree()
    proc = await asyncio.create_subprocess_exec(sys.executable, "-c", code, str(gc_file), **tree.popen_kwargs())
    tree.adopt(proc)
    grandchild = None
    try:
        assert await proc.wait() == 0
        grandchild = int(gc_file.read_text())
        assert not _gone(grandchild)
        tree.terminate(proc)
        assert await _survivors([grandchild]) == []
        assert tree.errors == []
    finally:
        tree.close()
        if grandchild is not None:
            _kill_all([grandchild])


@posix_only
async def test_process_tree_reports_signalling_failures_instead_of_hiding_them(monkeypatch):
    tree = _ProcessTree()
    proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "pass", **tree.popen_kwargs())
    tree.adopt(proc)
    await proc.wait()

    def denied(pgid, sig):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "killpg", denied)
    tree.terminate(proc)  # never raises from cleanup
    assert len(tree.errors) == 1 and "Operation not permitted" in tree.errors[0]


# -- stdio servers through Nexus -------------------------------------------------------------------
@posix_only
async def test_graceful_stdio_server_shutdown_reaps_child_and_grandchild(config_factory, workspace, tmp_path):
    pid_file = tmp_path / "tree.json"
    mgr = ProviderManager(config_factory(workspace, [_tree_provider(pid_file)]))
    pids: dict[str, int] = {}
    try:
        await mgr.start()
        assert mgr.provider_errors == {}
        pids = await _read_pids(pid_file)
        assert not any(_gone(pid) for pid in pids.values())
        await mgr.close()
        assert await _survivors(pids.values()) == [], pids
    finally:
        await mgr.close()
        _kill_all(pids.values())


@posix_only
async def test_stdio_server_ignoring_eof_and_sigterm_is_killed_with_its_descendants(
    config_factory, workspace, tmp_path
):
    pid_file = tmp_path / "tree.json"
    mgr = ProviderManager(config_factory(workspace, [_tree_provider(pid_file, "stubborn")]))
    pids: dict[str, int] = {}
    try:
        await mgr.start()
        pids = await _read_pids(pid_file)
        started = time.monotonic()
        await mgr.close()
        # SDK: 2 s grace after stdin EOF, SIGTERM, 2 s, SIGKILL; never unbounded
        assert time.monotonic() - started < 15
        assert await _survivors(pids.values()) == [], pids
    finally:
        await mgr.close()
        _kill_all(pids.values())


@posix_only
async def test_startup_timeout_and_repeated_close_leave_no_process(config_factory, workspace, tmp_path):
    pid_file = tmp_path / "tree.json"
    provider = _tree_provider(pid_file, "hang", startup_timeout_seconds=3)
    mgr = ProviderManager(config_factory(workspace, [provider]))
    pids: dict[str, int] = {}
    try:
        await mgr.start()  # the handshake never completes
        assert "tree" in mgr.provider_errors
        pids = await _read_pids(pid_file)
        await mgr.close()
        await mgr.close()  # idempotent
        assert await _survivors(pids.values()) == [], pids
    finally:
        await mgr.close()
        _kill_all(pids.values())


@posix_only
async def test_mcp_framing_round_trips_through_the_guard(config_factory, workspace, tmp_path):
    pid_file = tmp_path / "tree.json"
    mgr = ProviderManager(config_factory(workspace, [_tree_provider(pid_file)]))
    pids: dict[str, int] = {}
    try:
        await mgr.start()
        pids = await _read_pids(pid_file)
        text = 'line1\nline2\r\n"quoted" \\ ünïcödé   tab\t' + "x" * 300_000
        result = await mgr.call_provider_tool("tree", "echo", {"text": text})
        assert not result.is_error and result.content[0].text == text
    finally:
        await mgr.close()
        _kill_all(pids.values())


@posix_only
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/self/environ")
async def test_stdio_server_receives_exactly_the_environment_nexus_built(config_factory, workspace, tmp_path):
    """End to end: the server's start-up environment block equals the SDK's merge of its defaults
    with the environment Nexus built; nothing added (locale coercion, guard markers), nothing lost."""
    from mcp.client.stdio import get_default_environment

    pid_file = tmp_path / "tree.json"
    provider = _tree_provider(pid_file)
    provider["env"] |= {"NEXUS_PROBE": "a=b  c ü $HOME *", "EMPTY_VALUE": ""} | _PREFIX_COLLISIONS
    mgr = ProviderManager(config_factory(workspace, [provider]))
    pids: dict[str, int] = {}
    try:
        await mgr.start()
        pids = await _read_pids(pid_file)
        expected = get_default_environment() | mgr.providers["tree"]._env()
        result = await mgr.call_provider_tool("tree", "initial_environ", {})
        assert not result.is_error
        assert json.loads(result.content[0].text) == expected
    finally:
        await mgr.close()
        _kill_all(pids.values())


# -- the stdio guard itself ------------------------------------------------------------------------------
HARNESS = str(Path(__file__).parent / "mock_servers" / "guard_harness.py")
_IGNORE_THEN_EXEC = (
    "import os, signal, sys\n"
    "for name in filter(None, sys.argv[1].split(',')):\n"
    "    signal.signal(getattr(signal, name), signal.SIG_IGN)\n"
    "os.execv(sys.argv[2], sys.argv[2:])\n"
)  # stands in for a parent (nohup, a service manager) that starts Nexus with signals ignored
_SLEEPER = "import time; time.sleep(30)"


def _wait_until(condition, timeout: float = 10.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)
    return True


def _group_members(pgid: int) -> list[int]:
    """Live (non-zombie) members of process group ``pgid``."""
    if sys.platform.startswith("linux"):
        members = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                stat = Path(f"/proc/{entry}/stat").read_text()
            except OSError:
                continue
            state, _ppid, group = stat[stat.rindex(")") + 2 :].split()[:3]
            if int(group) == pgid and state != "Z":
                members.append(int(entry))
        return members
    listing = subprocess.run(["ps", "-A", "-o", "pid=,pgid=,stat="], capture_output=True, text=True).stdout
    rows = (line.split() for line in listing.splitlines())
    return [int(row[0]) for row in rows if len(row) >= 3 and int(row[1]) == pgid and not row[2].startswith("Z")]


def _groups_empty(*pgids: int | None, timeout: float = 10.0) -> bool:
    return _wait_until(lambda: not any(_group_members(g) for g in pgids if g), timeout)


def _kill_groups(*pgids: int | None) -> None:
    for pgid in pgids:
        if pgid:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


class _Guarded:
    """A guard (started like the SDK starts it: own session) whose server's group is recorded."""

    def __init__(self, tmp_path: Path, server: list[str], *, early: str = "", ignore: str = "", stdin=None, env=None):
        self.pid_file = tmp_path / "server.pid"
        self.stderr_path = tmp_path / "guard.err"
        argv = [sys.executable, "-I", HARNESS, str(STDIO_GUARD), "--", *server]
        if ignore:
            argv = [sys.executable, "-I", "-c", _IGNORE_THEN_EXEC, ignore, *argv]
        env = dict(os.environ if env is None else env)
        env["GUARD_HARNESS_SERVER_PID"] = str(self.pid_file)
        if early:
            env["GUARD_HARNESS_EARLY_SIGNAL"] = early
        with self.stderr_path.open("wb") as err:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL if stdin is None else stdin,
                stdout=subprocess.DEVNULL,
                stderr=err,
                env=env,
                start_new_session=True,
            )

    @property
    def server_pgid(self) -> int | None:
        try:
            return int(self.pid_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def wait_for_server(self) -> int:
        assert _wait_until(lambda: self.server_pgid is not None, 30), "guard never started its server"
        return self.server_pgid  # type: ignore[return-value]

    def __enter__(self) -> _Guarded:
        return self

    def __exit__(self, *exc) -> None:
        # Always runs, also after a failed assertion: kill both groups, release stdin, reap the guard.
        _kill_groups(self.proc.pid, self.server_pgid)
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(10)


def _guard(argv: list[str], env: dict[str, str] | None = None, **kwargs) -> subprocess.CompletedProcess:
    launch, launch_env = _stdio_launch(argv, dict(os.environ if env is None else env), posix=True)
    kwargs.setdefault("start_new_session", True)  # as the MCP SDK starts stdio servers
    return subprocess.run(launch, env=launch_env, capture_output=True, timeout=60, **kwargs)


def _env_executable() -> str:
    found = shutil.which("env") or next((p for p in ("/usr/bin/env", "/bin/env") if os.access(p, os.X_OK)), None)
    if found is None:
        pytest.skip("no env executable on this system")
    return found


# Provider variables that use the guard's transfer prefix: a non-numeric suffix, a chunk-shaped
# name and the bare prefix. They belong to the provider and must arrive unchanged.
_PREFIX_COLLISIONS = {
    f"{GUARD_ENV_PREFIX}x": "provider value",
    f"{GUARD_ENV_PREFIX}0": "not a chunk",
    GUARD_ENV_PREFIX: "",
}


@posix_only
@pytest.mark.parametrize("extra", [{}, {"LC_CTYPE": "C"}, {"LANG": "C", "LC_ALL": "C"}, _PREFIX_COLLISIONS], ids=str)
def test_guard_passes_exactly_the_built_environment_to_a_non_python_server(tmp_path, extra):
    """The guard's own interpreter coerces a C locale (PEP 538: it sets LC_CTYPE=C.UTF-8 in its
    environment). The server must still get the environment Nexus built: no added LC_CTYPE, an
    explicit LC_CTYPE=C kept, the provider's own variables that share the guard's transfer
    prefix kept, and no guard marker variables."""
    env_exe = _env_executable()
    env = {"PATH": os.path.dirname(env_exe), "HOME": str(tmp_path), "NEXUS_PROBE": "a=b  c ü $HOME *", "EMPTY": ""}
    env |= extra
    out = _guard([env_exe], env=env)
    assert out.returncode == 0, out.stderr
    observed = dict(line.partition("=")[::2] for line in out.stdout.decode().splitlines())
    assert observed == env


@posix_only
def test_guard_preserves_argv_cwd_and_stdio_bytes(tmp_path):
    script = (
        "import json, os, sys\n"
        "data = sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),"
        " 'env': os.environ.get('GUARD_PROBE')}).encode() + b'\\n' + data)\n"
    )
    args = ["", "a b", "--", "ünï", "mcp", "-c", "$HOME", "*"]
    payload = b'{"jsonrpc":"2.0"}\n\x00\xff\r\n' * 1000
    env = {**os.environ, "GUARD_PROBE": "value with spaces"}
    out = _guard([sys.executable, "-c", script, *args], env=env, input=payload, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    header, _, rest = out.stdout.partition(b"\n")
    meta = json.loads(header)
    assert meta == {"argv": args, "cwd": str(tmp_path), "env": "value with spaces"}
    assert rest == payload
    assert out.stderr == b""


@posix_only
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("raise SystemExit(0)", 0),
        ("raise SystemExit(7)", 7),
        ("import os, signal; os.kill(os.getpid(), signal.SIGTERM)", 128 + 15),
    ],
)
def test_guard_propagates_the_server_exit_status(code, expected):
    assert _guard([sys.executable, "-c", code]).returncode == expected


@posix_only
def test_guard_reports_a_missing_executable(tmp_path):
    out = _guard([str(tmp_path / "does-not-exist")])
    assert out.returncode == 127 and b"could not start" in out.stderr and b"Traceback" not in out.stderr


@posix_only
@pytest.mark.parametrize("new_session", [True, False])
async def test_guard_reaps_descendants_after_the_server_exits(tmp_path, new_session):
    """Also when the guard does not lead its own session: it only ever signals the group it created
    for the server, never its own (here: the test runner's) group."""
    gc_file = tmp_path / "gc.pid"
    code = (
        "import subprocess, sys\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        "open(sys.argv[1], 'w').write(str(gc.pid))\n"
    )
    grandchild = None
    try:
        out = _guard([sys.executable, "-c", code, str(gc_file)], start_new_session=new_session)
        assert out.returncode == 0, out.stderr
        grandchild = int(gc_file.read_text())
        assert await _survivors([grandchild]) == []
    finally:
        if grandchild is not None:
            _kill_all([grandchild])


# Descendant scripts for the escalation tests: start a worker, wait until it runs, then exit (0).
_SERVER_WITH_WORKER = (
    "import subprocess, sys, time\n"
    "worker = subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])\n"
    "while not __import__('os').path.exists(sys.argv[2]): time.sleep(0.01)\n"
    "open(sys.argv[3], 'w').write(repr(time.time()))\n"
)
_WORKER = "import signal, sys, time\n{setup}open(sys.argv[1], 'w').write('ready')\ntime.sleep(30)\n"


@posix_only
@pytest.mark.parametrize("worker_ignores_sigterm", [False, True])
def test_guard_escalates_to_sigkill_only_for_descendants_that_ignore_sigterm(tmp_path, worker_ignores_sigterm):
    setup = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" if worker_ignores_sigterm else ""
    ready, exited = tmp_path / "worker.ready", tmp_path / "server.exited"
    server = [sys.executable, "-c", _SERVER_WITH_WORKER, _WORKER.format(setup=setup), str(ready), str(exited)]
    with _Guarded(tmp_path, server) as run:
        pgid = run.wait_for_server()
        assert run.proc.wait(20) == 0
        cleanup = time.time() - float(exited.read_text())
        assert _groups_empty(pgid), _group_members(pgid)
        if worker_ignores_sigterm:
            assert 0.9 <= cleanup < 10, cleanup  # waited out the 1 s grace, then SIGKILL
        else:
            assert cleanup < 0.6, cleanup  # no grace period when SIGTERM suffices


@posix_only
def test_guard_applies_a_termination_request_that_arrives_before_the_server_starts(tmp_path):
    with _Guarded(tmp_path, [sys.executable, "-c", _SLEEPER], early="SIGTERM") as run:
        assert run.proc.wait(20) == 128 + signal.SIGTERM
        assert _groups_empty(run.wait_for_server(), run.proc.pid)


@posix_only
@pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT", "SIGHUP"])
def test_guard_stops_a_promptly_exiting_server_without_waiting_out_the_grace(tmp_path, signame):
    with _Guarded(tmp_path, [sys.executable, "-c", _SLEEPER]) as run:
        pgid = run.wait_for_server()
        started = time.monotonic()
        os.killpg(run.proc.pid, getattr(signal, signame))
        assert run.proc.wait(20) == 128 + signal.SIGTERM  # the server's group always gets SIGTERM
        assert time.monotonic() - started < 0.6
        assert _groups_empty(pgid, run.proc.pid)
        assert run.stderr_path.read_bytes() == b""


@posix_only
async def test_guard_forwards_termination_to_the_whole_server_tree(tmp_path):
    """The SDK escalates with SIGTERM to the guard's group: the guard must take the server tree
    down (even a server ignoring SIGTERM) and exit before the SDK's SIGKILL two seconds later."""
    pid_file = tmp_path / "tree.json"
    env = {**os.environ, "MOCK_TREE_PIDS": str(pid_file), "MOCK_TREE_MODE": "stubborn"}
    pids: dict[str, int] = {}
    with _Guarded(tmp_path, [sys.executable, MOCK_TREE], stdin=subprocess.PIPE, env=env) as run:
        try:
            pids = await _read_pids(pid_file)
            pgid = run.wait_for_server()
            assert pids["server"] == pgid
            started = time.monotonic()
            os.killpg(run.proc.pid, signal.SIGTERM)
            assert await asyncio.to_thread(run.proc.wait, 10) == 128 + signal.SIGKILL
            assert time.monotonic() - started < 2.0, "the guard must finish before the SDK's SIGKILL"
            assert await _survivors(pids.values()) == [], pids
            assert _groups_empty(pgid, run.proc.pid)
        finally:
            _kill_all(pids.values())


_REPORT_DISPOSITIONS = (
    "import json, signal, sys, time\n"
    "names = ('SIGTERM', 'SIGINT', 'SIGHUP')\n"
    "ignored = {n: signal.getsignal(getattr(signal, n)) == signal.SIG_IGN for n in names}\n"
    "open(sys.argv[1] + '.tmp', 'w').write(json.dumps(ignored))\n"
    "__import__('os').replace(sys.argv[1] + '.tmp', sys.argv[1])\n"
    "time.sleep(30)\n"
)


@posix_only
@pytest.mark.parametrize("signame", ["SIGHUP", "SIGINT"])
def test_inherited_ignored_signals_stay_ignored_for_guard_and_server(tmp_path, signame):
    report = tmp_path / "dispositions.json"
    with _Guarded(tmp_path, [sys.executable, "-c", _REPORT_DISPOSITIONS, str(report)], ignore=signame) as run:
        pgid = run.wait_for_server()
        assert _wait_until(report.is_file)
        assert json.loads(report.read_text()) == {"SIGTERM": False, "SIGINT": False, "SIGHUP": False} | {signame: True}
        os.killpg(run.proc.pid, getattr(signal, signame))
        with pytest.raises(subprocess.TimeoutExpired):
            run.proc.wait(0.5)  # ignored, as without the guard
        os.killpg(run.proc.pid, signal.SIGTERM)
        assert run.proc.wait(20) == 128 + signal.SIGTERM
        assert _groups_empty(pgid, run.proc.pid)


@posix_only
def test_inherited_ignored_sigterm_reaches_the_server_and_still_bounds_shutdown(tmp_path):
    """The server inherits SIGTERM ignored (as it would without the guard), yet the SDK's SIGTERM
    to the guard still empties the server's group, by SIGKILL after the grace period."""
    report = tmp_path / "dispositions.json"
    with _Guarded(tmp_path, [sys.executable, "-c", _REPORT_DISPOSITIONS, str(report)], ignore="SIGTERM") as run:
        pgid = run.wait_for_server()
        assert _wait_until(report.is_file)
        assert json.loads(report.read_text())["SIGTERM"] is True
        started = time.monotonic()
        os.killpg(run.proc.pid, signal.SIGTERM)
        assert run.proc.wait(20) == 128 + signal.SIGKILL
        assert time.monotonic() - started < 2.0
        assert _groups_empty(pgid, run.proc.pid)


# -- launch command, all platforms -------------------------------------------------------------------
def test_stdio_launch_is_only_wrapped_on_posix():
    command = ["/opt/node/bin/node", "/opt/rea/rea.mjs", "mcp"]
    env = {"PATH": "/usr/bin", "HOME": "/home/u"}
    assert _stdio_launch(command, env, posix=False) == (command, env)  # Windows: native launch, SDK Job Object
    wrapped, launch_env = _stdio_launch(command, env, posix=True)
    assert wrapped[: wrapped.index("--") + 1] == [sys.executable, "-I", str(STDIO_GUARD), "--"]
    assert wrapped[wrapped.index("--") + 1 :] == command  # REA's last argument stays exactly "mcp"
    assert STDIO_GUARD.is_file()
    # The guard gets only the transfer variables; the server's environment travels inside them.
    assert launch_env and all(k.startswith(GUARD_ENV_PREFIX) for k in launch_env)
    expected = {os.fsencode(k): os.fsencode(v) for k, v in env.items()}
    assert decode_environment(launch_env) == expected
    colliding = env | _PREFIX_COLLISIONS
    _argv, launch_env = _stdio_launch(command, colliding, posix=True)
    assert decode_environment(launch_env) == {os.fsencode(k): os.fsencode(v) for k, v in colliding.items()}


@posix_only
def test_stdio_launch_refuses_an_environment_the_system_cannot_pass(tmp_path):
    """The encoded copy is about 4/3 of the environment's size. A launch that would exceed the
    system's argument/environment limit fails with a clear message instead of an opaque E2BIG,
    and the guard is never started."""
    limit = os.sysconf("SC_ARG_MAX")
    huge = {"HOME": str(tmp_path), "BIG": "x" * limit}
    with pytest.raises(ValueError, match="argument/environment space"):
        _stdio_launch([sys.executable, "-c", "pass"], huge, posix=True)
    assert _stdio_launch(["x"], huge, posix=False) == (["x"], huge)  # Windows: unchanged


@posix_only
async def test_provider_with_an_oversized_environment_fails_with_a_clear_error(config_factory, workspace, tmp_path):
    pid_file = tmp_path / "tree.json"
    provider = _tree_provider(pid_file)
    provider["env"] |= {"BIG": "x" * os.sysconf("SC_ARG_MAX")}
    mgr = ProviderManager(config_factory(workspace, [provider]))
    try:
        await mgr.start()
        assert "argument/environment space" in str(mgr.provider_errors.get("tree", "")), mgr.provider_errors
        assert not pid_file.exists()  # nothing was started
    finally:
        await mgr.close()
