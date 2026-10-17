"""Child MCP providers: stdio, Streamable HTTP and launch-then-connect HTTP servers.

Each connection lives in a dedicated *owner task*: anyio cancel scopes created when a
transport is entered must be exited by the same task, and owning the connection in one
place also lets Nexus notice a crashed child and restart it a bounded number of times.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import anyio

from ..adapters import get_adapter
from ..config import expand_env
from ..errors import ConfigError, PolicyViolation, ProviderCallError, ProviderUnavailable
from ..netguard import format_host, is_loopback_host, parse_http_url
from ..redaction import redact_text
from ._stdio_guard import encode_environment
from .base import AnalysisProvider, OperationResult, ProviderHealth, TargetContext, ToolInfo

_MAX_RESTARTS = 2
# A restart requested this long after the end of the last restart attempt (successful or not) starts with a fresh budget: at
# most _MAX_RESTARTS within any such window (restarts only ever happen on a caller's request), so
# the limit bounds crash loops, not the number of unrelated crashes over a gateway's lifetime.
_RESTART_RESET_SECONDS = 600.0
_MAX_TOOL_PAGES = 100  # pagination guard; the whole listing also shares one deadline

_PASSTHROUGH_ENV = ("JAVA_HOME", "GHIDRA_INSTALL_DIR", "IDADIR", "ANDROID_HOME", "ANDROID_SDK_ROOT")


# Started in front of every stdio server on POSIX; see its module docstring.
STDIO_GUARD = Path(__file__).with_name("_stdio_guard.py")


def _stdio_launch(
    command: list[str], env: dict[str, str], *, posix: bool | None = None
) -> tuple[list[str], dict[str, str]]:
    """The argv and environment that launch a stdio server whose environment must be ``env``.

    POSIX: through ``_stdio_guard.py``, which reaps the server's descendants when the server exits
    (the MCP SDK only kills the process group of a server that fails to exit). The server's own
    argv follows ``--`` unchanged. ``env`` travels only encoded (``encode_environment``): the guard
    gets nothing but the transfer variables (plus the SDK's fixed defaults), so a provider variable
    that happens to use the transfer prefix cannot be mistaken for, or overwritten by, a transfer
    chunk, and the guard's interpreter, which alters its own environment at start-up, never
    passes it on. Raises ValueError when the encoded copy (about 4/3 of the environment's size)
    would not fit the system's argument/environment limit. Windows: unchanged; the SDK's Job
    Object reaps the tree.
    """
    if not (os.name != "nt" if posix is None else posix):
        return list(command), env
    argv = [sys.executable, "-I", str(STDIO_GUARD), "--", *command]
    launch_env = encode_environment(env)
    needed = _exec_space(argv, launch_env) + _SDK_DEFAULTS_ALLOWANCE
    limit = _arg_max()
    if limit is not None and needed > limit:
        raise ValueError(
            f"launching it through the stdio guard needs about {needed} bytes of argument/environment "
            f"space (the environment is passed encoded, about 4/3 of its size), over the system "
            f"limit of {limit}; reduce the provider's environment"
        )
    return argv, launch_env


# Room for the environment the SDK merges in (HOME, LOGNAME, PATH, SHELL, TERM, USER).
_SDK_DEFAULTS_ALLOWANCE = 8 * 1024


def _exec_space(argv: list[str], env: dict[str, str]) -> int:
    """Bytes execve() needs for ``argv`` and ``env``: each string, its NUL and its pointer."""
    strings = [os.fsencode(a) for a in argv] + [os.fsencode(k) + b"=" + os.fsencode(v) for k, v in env.items()]
    return sum(len(item) + 1 + 8 for item in strings)


def _arg_max() -> int | None:
    try:
        limit = os.sysconf("SC_ARG_MAX")
    except (AttributeError, ValueError, OSError):
        return None
    return limit if limit > 0 else None


def _resolve_command(command: str) -> list[str]:
    """Resolve an executable; wrap .cmd/.bat shims (npx, uvx shims) for CreateProcess."""
    resolved = shutil.which(command) or command
    if os.name == "nt" and resolved.lower().endswith((".cmd", ".bat")):
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", resolved]
    return [resolved]


def build_child_env(
    provider_env: dict[str, str], inherit: list[str] | tuple[str, ...]
) -> tuple[dict[str, str], list[str]]:
    """Safe default environment + explicitly inherited names + provider overrides."""
    from mcp.client.stdio import get_default_environment

    env = get_default_environment()
    for name in (*_PASSTHROUGH_ENV, *inherit):
        if name in os.environ:
            env[name] = os.environ[name]
    missing: list[str] = []
    for key, value in provider_env.items():
        expanded, unresolved = expand_env(value)
        missing.extend(unresolved)
        env[key] = expanded
    return env, missing


class _ConnectionOwner:
    """Owns one MCP client context (and optionally a launched server process)."""

    def __init__(self, label: str, connect, log_path: Path) -> None:
        self.label = label
        self._connect = connect  # async callable(owner) -> async context manager yielding Client
        self.log_path = log_path
        self.client: Any = None
        self.error: BaseException | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._scope: anyio.CancelScope | None = None
        self.started_at: float | None = None

    @property
    def alive(self) -> bool:
        return self._task is not None and not self._task.done() and self.client is not None

    async def start(self, timeout: float) -> Any:
        self._task = asyncio.create_task(self._run(), name=f"nexus-mcp-{self.label}")
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=timeout)
        except TimeoutError:
            await self.close()
            raise ProviderUnavailable(f"{self.label}: no MCP handshake within {timeout:.0f}s") from None
        if self.error is not None or self.client is None:
            err = self.error
            await self.close()
            raise ProviderUnavailable(f"{self.label}: failed to connect: {_describe(err)}") from err
        self.started_at = time.time()
        return self.client

    async def _run(self) -> None:
        try:
            # close() cancels this scope rather than the task: an anyio cancellation honours the
            # SDK's shielded transport shutdown (close stdin, kill the tree, drain stdout), whereas
            # a native task.cancel() defeats it and livelocks on a server that never answers.
            with anyio.CancelScope() as scope:
                self._scope = scope
                async with self._connect(self) as client:
                    self.client = client
                    self._ready.set()
                    await self._stop.wait()
        except BaseException as exc:  # noqa: BLE001 - recorded and surfaced as provider health
            self.error = exc
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            self.client = None
            self._ready.set()

    async def close(self, timeout: float = 20.0) -> None:
        self._stop.set()
        if self._task is None:
            return
        if not self._ready.is_set() and self._scope is not None:
            # Still in the handshake, where _stop is never observed: stop it cooperatively now.
            self._scope.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(self._task), timeout=timeout)
        except (TimeoutError, asyncio.CancelledError):
            if self._scope is not None:
                self._scope.cancel()
                await asyncio.wait({self._task}, timeout=timeout)
            if not self._task.done():  # last resort; may orphan the child (see _run)
                self._task.cancel()
                await asyncio.wait({self._task}, timeout=timeout)
            if not self._task.done():
                # Every wait above is bounded: a task that swallows cancellation is abandoned and
                # reported rather than hanging the gateway.
                self.error = self.error or ProviderUnavailable(
                    f"{self.label}: connection task did not stop after cancellation; abandoned"
                )
        except BaseException:  # noqa: BLE001 - the owner already recorded its error
            pass


class _ProcessTree:
    """Contain a launched server *and its descendants* (uvx → launcher → python → JVM).

    ``Process.terminate()`` only signals the direct child; on Windows that orphaned the
    grandchildren that actually serve MCP (observed with uvx + mcpyghidra-headless). On
    Windows the child is placed in a Job Object with KILL_ON_JOB_CLOSE — the same
    mechanism the MCP SDK uses for stdio servers — so terminating or closing the job reaps
    the whole tree, even if Nexus itself dies. On POSIX the child leads its own process
    group, which is signalled as a unit.

    Signalling failures other than "group already gone" are kept in ``errors`` (for the
    provider log) instead of raising out of cleanup.
    """

    def __init__(self) -> None:
        self.job: Any = None
        self.errors: list[str] = []

    @staticmethod
    def popen_kwargs() -> dict[str, Any]:
        return {} if os.name == "nt" else {"start_new_session": True}

    def adopt(self, proc: asyncio.subprocess.Process) -> None:
        if os.name != "nt":
            return
        try:
            import win32api
            import win32con
            import win32job

            job = win32job.CreateJobObject(None, "")
            info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
            handle = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, proc.pid)
            try:
                win32job.AssignProcessToJobObject(job, handle)
            finally:
                win32api.CloseHandle(handle)
            self.job = job
        except Exception:  # noqa: BLE001 - fall back to taskkill /T on terminate
            self.job = None

    def terminate(self, proc: asyncio.subprocess.Process) -> None:
        if sys.platform == "win32":
            if self.job is not None:
                try:
                    import win32job

                    win32job.TerminateJobObject(self.job, 1)
                    return
                except Exception:  # noqa: BLE001
                    pass
            import subprocess

            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            self._signal_group(proc, "SIGTERM")

    def kill(self, proc: asyncio.subprocess.Process) -> None:
        if sys.platform == "win32":
            self.terminate(proc)
        else:
            self._signal_group(proc, "SIGKILL")

    def _signal_group(self, proc: asyncio.subprocess.Process, name: str) -> None:
        if sys.platform == "win32":
            return
        import signal

        # popen_kwargs() started the child with start_new_session, so it leads a group whose id is
        # its PID. Address the group by that id: os.getpgid() fails once the leader has exited and
        # been reaped (the "launcher exited" path), while POSIX does not reuse a PID that is still
        # a process-group id, so the group's surviving members are reached either way.
        try:
            os.killpg(proc.pid, getattr(signal, name))
        except ProcessLookupError:
            pass  # the whole group has already exited
        except PermissionError as exc:
            self.errors.append(f"cannot send {name} to process group {proc.pid}: {exc}")

    def close(self) -> None:
        if self.job is not None:
            try:
                import win32api

                win32api.CloseHandle(self.job)
            except Exception:  # noqa: BLE001
                pass
            self.job = None


def _is_connection_lost(exc: BaseException) -> bool:
    try:
        from mcp.shared.exceptions import MCPError
        from mcp_types import CONNECTION_CLOSED
    except ImportError:  # pragma: no cover
        return False
    if isinstance(exc, MCPError) and exc.code == CONNECTION_CLOSED:
        return True
    return isinstance(
        exc,
        (
            anyio.ClosedResourceError,
            anyio.BrokenResourceError,
            anyio.EndOfStream,
            BrokenPipeError,
            ConnectionResetError,
        ),
    )


def _describe(exc: BaseException | None) -> str:
    if exc is None:
        return "unknown error"
    if isinstance(exc, BaseExceptionGroup):
        inner = [e for e in exc.exceptions]
        return "; ".join(_describe(e) for e in inner[:3])
    return redact_text(f"{type(exc).__name__}: {exc}")[:600]


class McpProvider(AnalysisProvider):
    """Proxy for an upstream MCP server, plus adapter-driven normalised operations."""

    def __init__(self, config, runtime) -> None:
        super().__init__(config, runtime)
        self.adapter = get_adapter(config.adapter)
        if self.adapter is not None:
            if not config.engine:
                self.engine = self.adapter.engine
            # Wrappers around the same engine (two Ghidra servers) share a family: their
            # agreement is consistency, not independent corroboration.
            self.engine_family = self.adapter.engine_family or self.engine
        self._owner: _ConnectionOwner | None = None
        self._target_owners: OrderedDict[str, _ConnectionOwner] = OrderedDict()
        self._active_target: str | None = None
        self._restarts = 0
        self._last_restart: float | None = None
        self._call_lock = asyncio.Lock()
        self.server_info: dict[str, Any] = {}
        self.adapter_state: dict[str, Any] = {}
        self.log_path = runtime.log_dir / f"{config.id}.log"
        self._missing_env: list[str] = []

    # -- connection factories -----------------------------------------------
    def _client_kwargs(self) -> dict[str, Any]:
        from mcp.types import Implementation

        from .. import __version__

        mode = self.config.protocol_mode
        if mode == "auto" and self.adapter is not None:
            mode = self.adapter.protocol_mode
        # The client-wide default bounds only requests sent without their own budget, in practice
        # the ``initialize`` handshake. Tool calls pass ``timeout_seconds`` explicitly and a whole
        # ``tools/list`` pagination runs under one deadline (refresh_tools). Startup is already
        # bounded by the owner's startup timeout, so the handshake must not be cut short by the
        # (often much smaller) per-call timeout.
        return {
            "mode": mode,
            "read_timeout_seconds": float(max(self.config.timeout_seconds, self._startup_budget())),
            "client_info": Implementation(name="reveng-nexus", version=__version__),
        }

    def _startup_budget(self) -> float:
        if self.config.type == "mcp_launched_http":
            return float(self.config.launch.startup_timeout_seconds)
        return float(self.config.startup_timeout_seconds)

    def _env(self) -> dict[str, str]:
        inherit = self.config.settings.get("inherit_env", [])
        if not isinstance(inherit, list):
            raise ConfigError(f"Provider {self.id!r}: settings.inherit_env must be a list")
        env, missing = build_child_env(self.config.env, inherit)
        self._missing_env = missing
        if missing:
            raise ProviderUnavailable(
                f"{self.id}: environment variables referenced in config are unset: {sorted(set(missing))}",
                remediation="Set them in your shell or replace the ${...} references in providers.yaml.",
            )
        return env

    def _expanded(self, value: str | None, what: str) -> str | None:
        if value is None:
            return None
        expanded, missing = expand_env(value)
        if missing:
            raise ProviderUnavailable(
                f"{self.id}: {what} references unset environment variables {missing}",
                remediation="Set them in your shell or edit providers.yaml.",
            )
        return expanded

    def _command(self) -> list[str]:
        command = self._expanded(self.config.command, "command") or ""
        if shutil.which(command) is None and not Path(command).is_file():
            raise ProviderUnavailable(
                f"{self.id}: executable {command!r} was not found (PATH or absolute path)",
                remediation="Install the upstream tool or fix 'command' in providers.yaml; other providers keep working.",
            )
        return _resolve_command(command)

    def _expand_args(self, extra: dict[str, str] | None = None) -> list[str]:
        out = []
        for arg in self.config.args:
            expanded, missing = expand_env(arg)
            if missing:
                raise ProviderUnavailable(f"{self.id}: unset variables in args: {missing}")
            if extra:
                for key, value in extra.items():
                    expanded = expanded.replace("{" + key + "}", value)
            out.append(expanded)
        return out

    def _stdio_connect(self):
        from mcp import Client
        from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client

        # The SDK merges its default environment under ``env``; the server gets exactly that merge.
        server_env = get_default_environment() | self._env()
        try:
            launch, env = _stdio_launch([*self._command(), *self._expand_args()], server_env)
        except ValueError as exc:
            raise ProviderUnavailable(f"{self.id}: {exc}") from exc
        params = StdioServerParameters(
            command=launch[0],
            args=launch[1:],
            env=env,
            cwd=self._expanded(self.config.cwd, "cwd"),
        )
        provider = self

        @contextlib.asynccontextmanager
        async def connect(owner: _ConnectionOwner):
            owner.log_path.parent.mkdir(parents=True, exist_ok=True)
            with owner.log_path.open("a", encoding="utf-8", errors="replace") as errlog:
                errlog.write(f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%S')} starting {provider.id} ===\n")
                errlog.flush()
                async with Client(stdio_client(params, errlog=errlog), **provider._client_kwargs()) as client:
                    yield client

        return connect

    def _check_http_url(self, url: str, *, launched: bool) -> bool:
        """Refuse non-loopback endpoints unless explicitly allowed; return whether it is loopback."""
        try:
            host = parse_http_url(url).host
        except ValueError as exc:
            raise ProviderUnavailable(f"{self.id}: invalid endpoint URL: {exc}") from None
        if is_loopback_host(host):
            return True
        if launched:
            raise ProviderUnavailable(f"{self.id}: launched server URL points at non-loopback host {host!r}")
        if not (self.config.allow_remote and self.runtime.config.policy.allow_remote_providers):
            raise PolicyViolation(
                f"{self.id}: endpoint host {host!r} is not loopback. Sending targets and tool calls to a "
                "remote MCP server needs allow_remote: true on the provider AND policy.allow_remote_providers: true.",
            )
        return False

    def _open_client(self, url: str, *, loopback: bool):
        """MCP client over a Nexus-owned HTTP client: no proxy env for loopback, SDK redirect rules."""
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client

        provider = self

        @contextlib.asynccontextmanager
        async def opened():
            # trust_env=False: HTTP(S)_PROXY or the Windows proxy registry must not route loopback
            # traffic (target bytes, decompiled code) through a proxy.
            async with httpx2.AsyncClient(
                timeout=httpx2.Timeout(30.0, read=300.0), trust_env=not loopback, follow_redirects=False
            ) as http:
                transport = streamable_http_client(url, http_client=http)
                async with Client(transport, **provider._client_kwargs()) as client:
                    yield client

        return opened()

    def _http_connect(self, url: str):
        provider = self

        @contextlib.asynccontextmanager
        async def connect(owner: _ConnectionOwner):
            loopback = provider._check_http_url(url, launched=False)
            async with provider._open_client(url, loopback=loopback) as client:
                yield client

        return connect

    def _launched_connect(self, target: TargetContext | None):
        provider = self
        cfg = self.config

        @contextlib.asynccontextmanager
        async def connect(owner: _ConnectionOwner):
            extra: dict[str, str] = {}
            if target is not None:
                staged = target.staged_path(provider.id)
                extra = {"target": str(staged), "workdir": str(target.provider_dir(provider.id))}
            argv = [*provider._command(), *provider._expand_args(extra)]
            env = provider._env()
            owner.log_path.parent.mkdir(parents=True, exist_ok=True)
            errlog = owner.log_path.open("a", encoding="utf-8", errors="replace")
            errlog.write(f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%S')} launching {provider.id} ===\n")
            errlog.flush()
            tree = _ProcessTree()
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=errlog,
                env=env,
                cwd=provider._expanded(cfg.cwd, "cwd"),
                **tree.popen_kwargs(),
            )
            tree.adopt(proc)
            drain: asyncio.Task[None] | None = None
            try:
                ready = await provider._await_ready(proc, errlog)
                if not is_loopback_host(ready["host"]):
                    raise ProviderUnavailable(f"{provider.id}: launched server bound to non-loopback {ready['host']!r}")
                url = cfg.launch.url_template.format(host=format_host(ready["host"]), port=int(ready["port"]))
                # The template is operator text: check the URL actually connected to, not only the
                # announced host (http://example.com:{port}/mcp would otherwise bypass the check).
                provider._check_http_url(url, launched=True)

                async def drain_stdout() -> None:
                    assert proc.stdout is not None
                    while line := await proc.stdout.readline():
                        errlog.write("[stdout] " + line.decode("utf-8", errors="replace"))
                        errlog.flush()

                drain = asyncio.create_task(drain_stdout())
                async with provider._open_client(url, loopback=True) as client:
                    provider.adapter_state["launched"] = {"pid": proc.pid, "port": ready["port"]}
                    yield client
            finally:
                if proc.returncode is None:
                    tree.terminate(proc)
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=15)
                    except TimeoutError:
                        tree.kill(proc)
                        with contextlib.suppress(Exception):
                            await asyncio.wait_for(proc.wait(), timeout=5)
                else:
                    tree.terminate(proc)  # the launcher exited; reap anything it left behind
                tree.close()
                for message in tree.errors:
                    errlog.write(f"=== {provider.id}: {message} ===\n")
                # Let the drain reach EOF so asyncio can close the pipe transports cleanly.
                if drain is not None:
                    try:
                        await asyncio.wait_for(drain, timeout=5)
                    except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                        drain.cancel()
                elif proc.stdout is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(proc.stdout.read(), timeout=5)
                errlog.write(f"=== {provider.id} exited with {proc.returncode} ===\n")
                errlog.close()

        return connect

    async def _await_ready(self, proc: asyncio.subprocess.Process, errlog) -> dict[str, Any]:
        """Read stdout until a JSON readiness line; non-JSON noise is logged and skipped."""
        assert proc.stdout is not None
        deadline = time.monotonic() + self.config.launch.startup_timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderUnavailable(f"{self.id}: no readiness signal within the startup timeout")
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except TimeoutError:
                raise ProviderUnavailable(f"{self.id}: no readiness signal within the startup timeout") from None
            if not line:
                code = await proc.wait()
                raise ProviderUnavailable(
                    f"{self.id}: server exited with code {code} before becoming ready; see {self.log_path}"
                )
            text = line.decode("utf-8", errors="replace").strip()
            errlog.write("[stdout] " + text + "\n")
            errlog.flush()
            if not text.startswith("{"):
                continue
            try:
                message = json.loads(text)
            except ValueError:
                continue
            if message.get("status") == "ready" and "port" in message:
                port = message["port"]
                if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise ProviderUnavailable(f"{self.id}: readiness line has an invalid port")
                return {"host": str(message.get("host", "127.0.0.1")), "port": port}
            if message.get("status") == "error":
                raise ProviderUnavailable(
                    f"{self.id}: server reported startup error {message.get('reason')!r}: "
                    f"{redact_text(str(message.get('detail', '')))[:400]}"
                )

    # -- lifecycle --------------------------------------------------------------
    @property
    def per_target(self) -> bool:
        return self.config.type == "mcp_launched_http" and self.config.launch.per_target

    async def initialize(self) -> None:
        if self.per_target:
            # The server needs a target to start; only verify that the command resolves.
            command = self._expanded(self.config.command, "command") or ""
            if shutil.which(command) is None and not Path(command).is_file():
                raise ProviderUnavailable(f"{self.id}: command {command!r} not found on PATH")
            self._env()
            self.started = True
            return
        await self._connect_global()

    async def _connect_global(self) -> None:
        if self.config.type == "mcp_stdio":
            connect = self._stdio_connect()
        elif self.config.type == "mcp_http":
            connect = self._http_connect(self.config.url or "")
        else:
            connect = self._launched_connect(None)
        owner = _ConnectionOwner(self.id, connect, self.log_path)
        client = await owner.start(timeout=float(self.config.startup_timeout_seconds))
        self._owner = owner
        await self._after_connect(client)

    async def _after_connect(self, client: Any) -> None:
        info = getattr(client, "server_info", None)
        self.server_info = info.model_dump(exclude_none=True) if info is not None else {}
        self.started = True
        self.last_error = None
        # The first listing belongs to startup and may be as slow as the handshake.
        await self.refresh_tools(client, budget=self._startup_budget())
        self._reset_sessions()

    def _reset_sessions(self) -> None:
        """Forget engine sessions after a (re)connect, *in place*.

        Adapters hold a reference to this dict across the call that opens a target; that call
        may itself trigger the reconnect. Replacing the dict would drop the new server's session
        record, so the old database was never closed on the next target switch.
        """
        self.adapter_state.setdefault("sessions", {}).clear()

    async def _client_for(self, target: TargetContext | None) -> Any:
        if not self.per_target:
            if self._owner is None or not self._owner.alive:
                await self._restart_global()
            assert self._owner is not None
            return self._owner.client
        if target is None:
            if self._active_target and self._active_target in self._target_owners:
                owner = self._target_owners[self._active_target]
                if owner.alive:
                    return owner.client
            raise ProviderUnavailable(
                f"{self.id} starts one server per target; analyse a target first (e.g. nexus_analyze_binary)"
            )
        existing = self._target_owners.get(target.sha256)
        if existing is not None and existing.alive:
            self._target_owners.move_to_end(target.sha256)
            self._active_target = target.sha256
            return existing.client
        max_sessions = int(self.config.settings.get("max_sessions", 1))
        while len(self._target_owners) >= max(1, max_sessions):
            _, old = self._target_owners.popitem(last=False)
            await old.close()
        new_owner = _ConnectionOwner(f"{self.id}:{target.sha256[:12]}", self._launched_connect(target), self.log_path)
        client = await new_owner.start(timeout=float(self.config.launch.startup_timeout_seconds))
        self._target_owners[target.sha256] = new_owner
        self._active_target = target.sha256
        await self._after_connect(client)
        return client

    async def _restart_global(self) -> None:
        if self._last_restart is not None and time.monotonic() - self._last_restart >= _RESTART_RESET_SECONDS:
            self._restarts = 0
        if self._restarts >= _MAX_RESTARTS:
            raise ProviderUnavailable(
                f"{self.id}: connection lost and restart budget ({_MAX_RESTARTS}) is exhausted; see {self.log_path}"
            )
        self._restarts += 1
        if self._owner is not None:
            await self._owner.close()
        self.started = False
        try:
            await anyio.sleep(min(2.0 * self._restarts, 5.0))
            await self._connect_global()
        finally:
            # Quiet time is counted from the end of the last attempt, failed or not: a child that
            # no longer starts gets _MAX_RESTARTS attempts per window, not one per caller request.
            self._last_restart = time.monotonic()

    async def release_target(self, sha256: str) -> None:
        owner = self._target_owners.pop(sha256, None)
        if owner is not None:
            await owner.close()
        if self.adapter is not None:
            await self.adapter.release(self, sha256)

    async def shutdown(self) -> None:
        if self.adapter is not None:
            with contextlib.suppress(Exception):
                await self.adapter.shutdown(self)
        for owner in list(self._target_owners.values()):
            await owner.close()
        self._target_owners.clear()
        if self._owner is not None:
            await self._owner.close()
            self._owner = None
        self.started = False

    async def health_check(self) -> ProviderHealth:
        version = self.server_info.get("version")
        name = self.server_info.get("name")
        # serverInfo names the MCP server, not the engine (re-mcp says "Ghidra 3.4.8": FastMCP's version).
        label = f"MCP server {name or '?'} {version or '?'} (server-reported)" if name or version else None
        if self.per_target:
            live = [sha[:12] for sha, o in self._target_owners.items() if o.alive]
            if self.started and self.adapter is not None:
                # Before the first session the pin is trusted; once a server has listed its tools,
                # zero usable operations (or an adapter with no bindings) is not "ready".
                caps = self.adapter.capabilities(self)
                usable = sorted(op for op, status in caps.items() if status.get("available"))
                if not usable:
                    return ProviderHealth(
                        "degraded",
                        f"launches one server per target, but none of the adapter's {len(caps)} operations "
                        f"are usable ({len(self._tools)} tools listed); see {self.log_path}",
                        version=label,
                        extra={"usable_operations": []},
                    )
            return ProviderHealth(
                "ready" if self.started else "unavailable",
                "launches one server per target" + (f"; live sessions: {live}" if live else "; no live session"),
                version=label,
            )
        if self._owner is None or not self._owner.alive:
            detail = _describe(self._owner.error) if self._owner and self._owner.error else "not connected"
            return ProviderHealth("unavailable", detail, version=label)
        client = self._owner.client
        try:
            with anyio.fail_after(15):
                # ping is deprecated in the 2026-07-28 protocol (and warns under SDK 2.3 even for
                # legacy sessions); a fresh tools/list round-trip proves liveness in both eras.
                await client.list_tools(cache_mode="refresh")
        except Exception as exc:  # noqa: BLE001
            return ProviderHealth("degraded", f"liveness probe failed: {_describe(exc)}", version=label)
        callable_tools = sorted(name for name, info in self._tools.items() if info.callable)
        if self.adapter is not None and not self.adapter.bindings:
            # e.g. ida_official: analysis exists only behind execute_python. Under the current
            # policy no Nexus operation can reach a target, so this is not "ready".
            return ProviderHealth(
                "degraded",
                f"connected ({len(self._tools)} tools listed), but adapter {self.adapter.name!r} binds no "
                f"normalised operations; raw tools callable under policy: {callable_tools or 'none'}",
                version=label,
                extra={"usable_operations": [], "callable_tools": callable_tools},
            )
        if self.adapter is None and not callable_tools:
            return ProviderHealth(
                "degraded",
                f"connected, but none of its {len(self._tools)} tools is callable under the current policy",
                version=label,
                extra={"usable_operations": [], "callable_tools": []},
            )
        if self.adapter is not None:
            caps = self.adapter.capabilities(self)
            usable = [op for op, status in caps.items() if status.get("available")]
            if not usable:
                # Observed with re-mcp-ghidra and a wrong GHIDRA_INSTALL_DIR: the MCP server answers,
                # but its worker failed, so only a handful of meta tools are listed. Not "ready".
                return ProviderHealth(
                    "degraded",
                    f"connected, but none of the adapter's {len(caps)} operations are usable "
                    f"({len(self._tools)} tools listed); the engine backend may have failed: see {self.log_path}",
                    version=label,
                    extra={"usable_operations": []},
                )
            return ProviderHealth(
                "ready",
                f"{len(self._tools)} tools discovered; {len(usable)}/{len(caps)} operations usable",
                version=label,
                extra={"usable_operations": sorted(usable)},
            )
        return ProviderHealth("ready", f"{len(self._tools)} tools discovered", version=label)

    # -- tools --------------------------------------------------------------------
    async def refresh_tools(self, client: Any | None = None, *, budget: float | None = None) -> list[ToolInfo]:
        """Re-list the server's tools under ONE deadline for the whole pagination.

        ``budget`` defaults to ``timeout_seconds``; the listing made right after a (re)connect
        passes the startup budget. A hung or slowly paginating server therefore costs at most
        ``budget`` seconds in total, never ``pages x per-page timeout``.
        """
        client = client or await self._client_for(None)
        limit = float(budget if budget is not None else self.config.timeout_seconds)
        tools: list[Any] = []
        cursor = None
        pages = 0
        try:
            with anyio.fail_after(limit):
                for _ in range(_MAX_TOOL_PAGES):
                    page = await client.list_tools(cursor=cursor) if cursor else await client.list_tools()
                    pages += 1
                    tools.extend(page.tools)
                    cursor = page.next_cursor
                    if not cursor:
                        break
        except TimeoutError:
            raise ProviderUnavailable(
                f"{self.id}: tools/list did not complete within {limit:.0f}s "
                f"({pages} page(s), {len(tools)} tool(s) received)",
                remediation="The server is hung or very slow; raise timeout_seconds or check the provider log.",
            ) from None
        manifest = self.adapter.manifest if self.adapter else None
        trust_default = self.adapter.trust_annotations if self.adapter else False
        policy = self.runtime.policy
        catalogue: dict[str, ToolInfo] = {}
        for tool in tools:
            annotations = tool.annotations.model_dump(by_alias=True, exclude_none=True) if tool.annotations else {}
            classification = policy.classify(
                self.config,
                tool.name,
                annotations=annotations,
                manifest=manifest,
                trust_annotations_default=trust_default,
                unlisted_class=self.adapter.unlisted_tool_class if self.adapter else None,
            )
            input_schema = dict(tool.input_schema or {"type": "object", "properties": {}})
            decision = policy.decide(self.config, tool.name, classification, input_schema=input_schema)
            catalogue[tool.name] = ToolInfo(
                provider_id=self.id,
                name=tool.name,
                description=redact_text(tool.description or "")[:1200],
                input_schema=input_schema,
                annotations=annotations,
                classification=classification,
                decision=decision,
                adapter_only=bool(self.adapter and self.adapter.adapter_only),
            )
        self._tools = catalogue
        return list(catalogue.values())

    async def _raw_call(
        self, name: str, arguments: dict[str, Any], timeout: float, *, target_sha256: str | None = None
    ) -> Any:
        if self.per_target and target_sha256:
            # Route by the call's own target, never by "whichever target was opened last": another
            # coroutine may have switched _active_target between opening this target and calling.
            owner = self._target_owners.get(target_sha256)
            if owner is None or not owner.alive:
                raise ProviderUnavailable(f"{self.id}: no live session for target {target_sha256[:12]}; retry")
            client = owner.client
        else:
            client = await self._client_for(None)
        try:
            return await client.call_tool(name, arguments, read_timeout_seconds=timeout)
        except Exception as exc:
            if _is_connection_lost(exc) or (not self.per_target and (self._owner is None or not self._owner.alive)):
                # The child died (or closed its pipes). Tear the connection down so the next call
                # reconnects within the restart budget; per-target sessions are dropped entirely.
                self.last_error = {"message": _describe(exc), "at": time.time()}
                await self._drop_connection(target_sha256)
                raise ProviderUnavailable(f"{self.id}: connection lost during {name}: {_describe(exc)}") from exc
            raise

    async def _drop_connection(self, target_sha256: str | None = None) -> None:
        self._reset_sessions()
        if self.per_target:
            sha = target_sha256 or self._active_target
            owner = self._target_owners.pop(sha, None) if sha else None
            if owner is not None:
                await owner.close(timeout=5)
            return
        if self._owner is not None:
            await self._owner.close(timeout=5)

    async def call_for_target(self, target: TargetContext, name: str, arguments: dict[str, Any], **kw: Any) -> Any:
        """Adapter helper: make sure the per-target server (if any) is up, then call."""
        if self.per_target:
            await self._client_for(target)
        async with self._call_lock if self.config.max_concurrency == 1 else contextlib.nullcontext():
            return await self.call_tool(
                name, arguments, internal=True, target_sha256=target.sha256, case_id=target.case_id, **kw
            )

    # -- capabilities & operations ---------------------------------------------------
    def list_capabilities(self) -> dict[str, dict[str, Any]]:
        if self.adapter is None:
            return {
                op: {"available": False, "reason": "no adapter configured; use nexus_call_provider_tool"}
                for op in self.config.capabilities
            }
        return self.adapter.capabilities(self)

    async def perform(self, operation: str, target: TargetContext, params: dict[str, Any]) -> OperationResult:
        if self.adapter is None:
            raise ProviderCallError(f"{self.id} has no adapter; normalised operations are unavailable")
        if self.per_target:
            await self._client_for(target)
        started = time.monotonic()
        result = await self.adapter.perform(self, operation, target, params)
        result.duration_ms = round((time.monotonic() - started) * 1000)
        if result.engine_version is None:
            # serverInfo describes the MCP *server* (e.g. re-mcp reports "Ghidra 3.4.8", which is
            # its framework version, not Ghidra's). Label it so it is not mistaken for the engine.
            name, version = self.server_info.get("name"), self.server_info.get("version")
            if name or version:
                result.engine_version = f"MCP server {name or '?'} {version or '?'} (server-reported)"
        return result

    def describe(self) -> dict[str, Any]:
        out = super().describe()
        out["server_info"] = self.server_info
        out["restarts"] = self._restarts
        out["log_file"] = str(self.log_path)
        if self.per_target:
            out["live_target_sessions"] = [sha[:16] for sha, o in self._target_owners.items() if o.alive]
        return out


def unwrap_result(result: Any) -> tuple[Any, str]:
    """Return (structured-or-parsed payload, concatenated text) from a CallToolResult."""
    texts = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text is not None:
            texts.append(text)
    joined = "\n".join(texts)
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured, joined
    if joined.strip().startswith(("{", "[")):
        try:
            return json.loads(joined), joined
        except ValueError:
            pass
    return None, joined


def result_to_jsonable(result: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"is_error": bool(getattr(result, "is_error", False)), "content": []}
    for block in getattr(result, "content", None) or []:
        if hasattr(block, "model_dump"):
            payload["content"].append(block.model_dump(mode="json", by_alias=True, exclude_none=True))
        else:
            payload["content"].append(str(block))
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        payload["structured_content"] = structured
    return payload


__all__ = ["McpProvider", "build_child_env", "result_to_jsonable", "unwrap_result"]
