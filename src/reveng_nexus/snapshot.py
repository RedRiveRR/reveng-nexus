"""Read-only state snapshots of a running gateway, for the local dashboard.

The gateway (``reveng-nexus serve``) writes ``<data_dir>/dashboard/gateway-<pid>.json``
after provider startup and then every few seconds. The dashboard only *reads* these files:
it never starts providers, never talks to the gateway and never re-derives a policy
decision. Every ``allowed``/``callable``/``exposed``/``access_state`` value below was computed
by the gateway's own ``PolicyEngine`` and ``access.py`` (the functions MCP ``tools/list`` uses)
for its live catalogue.

Writing is best-effort and isolated: a failure is counted and logged to stderr, never
raised into the MCP server, and nothing is written to stdout (the stdio transport).

Sanitisation: provider commands, arguments and environments are never included; the
user's home directory is shortened to ``~``; credential-shaped text is redacted; values of
credential-named keys are replaced.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__
from .access import TOOL_STATES, provider_state, public_names, tool_access
from .config import ACCESS_PROFILES
from .policy import _UNRELAXABLE, TOOL_CLASS_DESCRIPTIONS
from .redaction import SENSITIVE_KEY, redact_text
from .security import DEFAULT_BLOCKED_TOOL_PATTERNS
from .verification import documented_state

SCHEMA_VERSION = 2  # 2: access_profile, per-tool access_state, tool_states counts
SNAPSHOT_DIRNAME = "dashboard"
HEARTBEAT_SECONDS = 10.0
HEALTH_REFRESH_SECONDS = 300.0
_MAX_DESCRIPTION = 1200

# Which Nexus operation(s) each nexus_* tool reaches. "local" tools work on the evidence store
# or gateway state only and never call a provider. tests/test_dashboard.py checks that every
# tool in server.TOOL_SPECS has an entry.
NEXUS_TOOL_OPERATIONS: dict[str, list[str]] = {
    "nexus_status": ["local"],
    "nexus_list_providers": ["local"],
    "nexus_list_capabilities": ["local"],
    "nexus_list_tools": ["local"],
    "nexus_call_provider_tool": ["raw provider tool (policy-checked per call)"],
    "nexus_inspect_target": ["local", "binary.metadata"],
    "nexus_list_targets": ["local"],
    "nexus_analyze_binary": ["binary.metadata", "binary.functions", "binary.decompile", "binary.strings"],
    "nexus_get_binary_metadata": ["binary.metadata"],
    "nexus_list_functions": ["binary.functions"],
    "nexus_decompile_function": ["binary.decompile"],
    "nexus_disassemble_function": ["binary.disassemble"],
    "nexus_get_xrefs": ["binary.xrefs"],
    "nexus_get_control_flow": ["binary.cfg"],
    "nexus_search_strings": ["binary.strings"],
    "nexus_compare_function": ["binary.decompile"],
    "nexus_ai_decompile": ["ai.decompile"],
    "nexus_analyze_apk": ["apk.manifest", "apk.components"],
    "nexus_inspect_android_components": ["apk.components"],
    "nexus_get_class_source": ["apk.class_source"],
    "nexus_analyze_javascript_app": ["js.application"],
    "nexus_get_electron_fuses": ["electron.fuses"],
    "nexus_inspect_artifact": ["artifact.inspect"],
    "nexus_dynamic_analysis_status": ["dynamic.status"],
    "nexus_record_finding": ["local"],
    "nexus_get_findings": ["local"],
    "nexus_record_evidence": ["local"],
    "nexus_get_evidence": ["local"],
    "nexus_review": ["local"],
    "nexus_export_report": ["local"],
    "nexus_plan_analysis": ["local"],
    "nexus_case_brief": ["local"],
    "nexus_record_question": ["local"],
    "nexus_update_question": ["local"],
    "nexus_list_questions": ["local"],
}


# -- sanitisation -----------------------------------------------------------------
def _home_variants() -> list[str]:
    home = str(Path.home())
    return sorted({home, home.replace("\\", "/"), home.replace("/", "\\")}, key=len, reverse=True)


def sanitize_text(text: str, homes: list[str] | None = None) -> str:
    out = redact_text(str(text))
    for home in homes if homes is not None else _home_variants():
        if not home or len(home) < 3:
            continue
        lowered = out.lower()
        needle = home.lower()
        start = lowered.find(needle)
        while start != -1:
            out = out[:start] + "~" + out[start + len(home) :]
            lowered = out.lower()
            start = lowered.find(needle, start + 1)
    return out


def sanitize(value: Any, homes: list[str] | None = None, *, _depth: int = 0) -> Any:
    """Recursively redact credentials and shorten home paths; credential-named keys lose their value."""
    homes = homes if homes is not None else _home_variants()
    if _depth > 40:
        return "[nested too deeply]"
    if isinstance(value, str):
        return sanitize_text(value, homes)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if SENSITIVE_KEY.search(key_text) and isinstance(item, str | int | float) and item != "":
                out[key_text] = "[REDACTED]"
            else:
                out[key_text] = sanitize(item, homes, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [sanitize(v, homes, _depth=_depth + 1) for v in value]
    return value


# -- snapshot -----------------------------------------------------------------------
def count_states_rows(tools: list[dict[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in TOOL_STATES}
    for tool in tools:
        counts[tool["access_state"]] += 1
    return counts


def _tool_rows(
    provider: Any, names: dict[tuple[str, str], str], bindings: dict[str, list[str]]
) -> list[dict[str, Any]]:
    rows = []
    for info in provider._tools.values():
        access = tool_access(provider, info, names)
        rows.append(
            {
                "name": info.name,
                "public_name": access.public_name,
                "description": info.description[:_MAX_DESCRIPTION],
                "input_schema": info.input_schema,
                "annotations": info.annotations,
                "tool_class": info.classification.tool_class,
                "class_meaning": TOOL_CLASS_DESCRIPTIONS.get(info.classification.tool_class, ""),
                "classification_source": info.classification.source,
                "classification_verified": info.classification.verified,
                "access_state": access.state,
                "policy_allowed": access.policy_allowed,
                "profile_allowed": access.profile_allowed,
                "available": access.available,
                "callable": access.callable,
                "exposed_to_clients": access.exposed,
                "adapter_only": info.adapter_only,
                "policy_reason": access.reason,
                "used_by_operations": sorted(op for op, tools in bindings.items() if info.name in tools),
            }
        )
    return sorted(rows, key=lambda r: r["name"])


def _provider_entry(manager: Any, summary: dict[str, Any], names: dict[tuple[str, str], str]) -> dict[str, Any]:
    pid = summary["id"]
    provider = manager.providers.get(pid)
    started = bool(provider is not None and provider.started)
    capabilities: dict[str, Any] = {}
    if started and provider is not None:
        try:
            capabilities = provider.list_capabilities()
        except Exception as exc:  # noqa: BLE001 - one provider must not break the snapshot
            capabilities = {"_error": {"available": False, "reason": str(exc)}}
    bindings = {op: list(c.get("tools") or []) for op, c in capabilities.items() if isinstance(c, dict)}
    tools = _tool_rows(provider, names, bindings) if started and provider is not None else []
    usable = sorted(op for op, c in capabilities.items() if isinstance(c, dict) and c.get("available"))
    summary = {k: v for k, v in summary.items() if k not in {"log_file", "access"}}  # path not needed
    access_state, access_reason = provider_state(manager, pid)
    health = manager.last_health.get(pid)
    return {
        **summary,
        "started": started,
        "health": health,
        "operations": capabilities,
        "counts": {
            "upstream_tools_discovered": len(tools),
            "policy_allowed_tools": sum(1 for t in tools if t["policy_allowed"]),
            "callable_tools": sum(1 for t in tools if t["callable"]),
            "exposed_tools": sum(1 for t in tools if t["exposed_to_clients"]),
            "blocked_tools": sum(1 for t in tools if not t["policy_allowed"]),
            "available_tools": sum(1 for t in tools if t["available"]),
            "operations_declared": len(capabilities),
            "operations_usable": len(usable),
        },
        "usable_operations": usable,
        "access_state": access_state,
        "access_reason": access_reason,
        "tool_states": count_states_rows(tools),
        "tools": tools,
        "verification": documented_state(pid),
    }


def build_snapshot(
    manager: Any, *, tool_mode: str | None = None, transport: str = "stdio", writer_failures: int = 0
) -> dict[str, Any]:
    """A sanitised, JSON-serialisable view of the gateway's current state."""
    from .server import TOOL_SPECS

    cfg = manager.config
    mode: str = tool_mode or cfg.tool_mode
    policy = cfg.policy
    names = public_names(manager.providers.values(), mode)
    providers = [_provider_entry(manager, s, names) for s in manager.provider_summaries()]
    totals = {
        key: sum(p["counts"][key] for p in providers)
        for key in (
            "upstream_tools_discovered",
            "policy_allowed_tools",
            "callable_tools",
            "exposed_tools",
            "blocked_tools",
            "available_tools",
            "operations_usable",
        )
    }
    totals["tool_states"] = {state: sum(p["tool_states"][state] for p in providers) for state in TOOL_STATES}
    nexus_tools = [
        {
            "name": name,
            "read": spec["read"],
            "description": spec["description"],
            "input_schema": spec["schema"],
            "operations": NEXUS_TOOL_OPERATIONS.get(name, ["unmapped"]),
        }
        for name, spec in TOOL_SPECS.items()
    ]
    now = time.time()
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "written_at": now,
        "gateway": {
            "name": "RevEng Nexus",
            "version": __version__,
            "pid": os.getpid(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "transport": transport,
            "tool_mode": mode,
            "config_path": cfg.config_path,
            "started_at": manager.started_at,
            "startup_complete": manager.startup_complete,
            "last_health_at": manager.last_health_at,
            "heartbeat_seconds": HEARTBEAT_SECONDS,
            "snapshot_write_failures": writer_failures,
            "audit_write_failures": manager.audit.write_failures,
            "config_warnings": list(cfg.warnings),
        },
        "policy": {
            "access_profile": policy.access_profile,
            "profile_source": policy.profile_source,
            "access_profiles": list(ACCESS_PROFILES),
            "read_only": policy.read_only,
            "code_execution": policy.allow_code_execution,
            "code_execution_providers": list(policy.code_execution_providers),
            "dynamic_analysis": policy.dynamic.enabled,
            "dynamic_allowed_device_count": len(policy.dynamic.authorized_devices),
            "dynamic_allowed_target_count": len(policy.dynamic.authorized_targets),
            "remote_ai": policy.allow_remote_ai,
            "remote_providers": policy.allow_remote_providers,
            "global_blocked_tool_patterns": list(policy.global_blocked_tool_patterns),
            "default_blocked_tool_patterns": list(DEFAULT_BLOCKED_TOOL_PATTERNS),
            "unrelaxable_classes": sorted(_UNRELAXABLE),
            "tool_classes": TOOL_CLASS_DESCRIPTIONS,
        },
        "workspace": {
            "allowed_roots": [str(r) for r in manager.guard.roots],
            "target_intake_enabled": manager.guard.enabled,
            "max_artifact_bytes": manager.guard.max_bytes,
            "follow_symlinks": cfg.follow_symlinks,
        },
        "totals": totals,
        "nexus_tools": nexus_tools,
        "providers": providers,
    }
    return sanitize(snapshot)


# -- retention ------------------------------------------------------------------------
# Only files this feature creates, in <data_dir>/dashboard, are ever considered for removal.
SNAPSHOT_NAME = re.compile(r"^gateway-\d+\.json$")
TEMP_NAME = re.compile(r"^gateway-\d+\.(json\.)?tmp$")
KEEP_INACTIVE = 10  # newest stopped/stale snapshots kept for history
MAX_INACTIVE_AGE_SECONDS = 7 * 86400
ACTIVE_GRACE_SECONDS = 15 * 60  # a file touched this recently may belong to a running gateway
FULL_REWRITE_SECONDS = 300.0  # unchanged content is only touched (mtime) between full rewrites
PRUNE_EVERY_SECONDS = 3600.0
_REPLACE_ATTEMPTS = 10


def prune_snapshots(directory: Path, *, keep_path: Path | None = None, now: float | None = None) -> list[str]:
    """Remove old snapshot files of stopped or crashed gateways; returns the names removed.

    Bounded and owner-scoped: only regular files named ``gateway-<pid>.json`` (or an interrupted
    write's ``.tmp``) directly in ``directory``. Never the caller's own file, never anything
    touched within ACTIVE_GRACE_SECONDS (running gateways refresh theirs every few seconds).
    Keeps the KEEP_INACTIVE newest inactive snapshots younger than MAX_INACTIVE_AGE_SECONDS.
    """
    now = time.time() if now is None else now
    if not directory.is_dir():
        return []
    removed: list[str] = []
    inactive: list[tuple[float, Path]] = []
    for path in directory.iterdir():
        name = path.name
        if not (SNAPSHOT_NAME.match(name) or TEMP_NAME.match(name)):
            continue
        if keep_path is not None and path == keep_path:
            continue
        try:
            if path.is_symlink() or not path.is_file():
                continue
            age = now - path.stat().st_mtime
        except OSError:
            continue
        if age < ACTIVE_GRACE_SECONDS:
            continue
        if TEMP_NAME.match(name):  # an interrupted write: never valid, never read
            inactive.append((-1.0, path))
            continue
        inactive.append((age, path))
    inactive.sort(key=lambda item: item[0])  # newest first; temp files (age -1) handled below
    kept = 0
    for age, path in inactive:
        drop = age < 0 or age > MAX_INACTIVE_AGE_SECONDS or kept >= KEEP_INACTIVE
        if not drop:
            kept += 1
            continue
        try:
            path.unlink()
            removed.append(path.name)
        except OSError:
            pass
    return removed


def _replace_with_retry(source: Path, target: Path) -> None:
    """os.replace, retried briefly: on Windows a reader holding the target makes it fail."""
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(0.02 * (attempt + 1))  # worker thread; at most ~0.9 s in total


# -- writer -------------------------------------------------------------------------
class SnapshotWriter:
    """One stable file per gateway process, replaced atomically; never raises into the gateway.

    Readers only ever see a complete file: the snapshot is written to ``<name>.json.tmp`` and
    moved over ``<name>.json`` with an atomic replace (readers never open ``.tmp`` files). When
    nothing but the timestamp changed, the file is only touched, so a ~1 MB catalogue is not
    rewritten every heartbeat; readers take liveness from the newer of ``written_at`` and the
    file's modification time.
    """

    def __init__(self, manager: Any, *, transport: str = "stdio", heartbeat: float = HEARTBEAT_SECONDS) -> None:
        self.manager = manager
        self.transport = transport
        self.heartbeat = heartbeat
        self.failures = 0
        self.full_writes = 0
        self.touches = 0
        self.path = Path(manager.config.data_dir) / SNAPSHOT_DIRNAME / f"gateway-{os.getpid()}.json"
        self._digest: str | None = None
        self._last_full = 0.0
        self._last_prune = 0.0

    def _prune(self) -> None:
        if time.time() - self._last_prune < PRUNE_EVERY_SECONDS:
            return
        self._last_prune = time.time()
        try:
            prune_snapshots(self.path.parent, keep_path=self.path)
        except Exception as exc:  # noqa: BLE001
            print(f"reveng-nexus: old dashboard snapshots not pruned: {exc}", file=sys.stderr)

    def compose(self, *, stopped: bool = False) -> tuple[dict[str, Any], str] | None:
        """Build the snapshot and its content digest. Runs on the gateway's event loop (fast,
        and the only safe place to read live manager state); never raises."""
        try:
            data = build_snapshot(self.manager, transport=self.transport, writer_failures=self.failures)
            if stopped:
                data["gateway"]["stopped_at"] = time.time()
            body = {k: v for k, v in data.items() if k != "written_at"}
            return data, hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        except Exception as exc:  # noqa: BLE001
            self.failures += 1
            print(f"reveng-nexus: dashboard snapshot not built: {exc}", file=sys.stderr)
            return None

    def persist(self, data: dict[str, Any], digest: str, *, stopped: bool = False) -> bool:
        """File I/O only (safe in a worker thread): touch, or write + atomic replace."""
        try:
            fresh = time.time() - self._last_full < FULL_REWRITE_SECONDS
            if not stopped and digest == self._digest and fresh and self.path.is_file():
                os.utime(self.path)  # heartbeat only
                self.touches += 1
                return True
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._prune()
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
            _replace_with_retry(tmp, self.path)
            self._digest, self._last_full = digest, time.time()
            self.full_writes += 1
            return True
        except Exception as exc:  # noqa: BLE001 - the dashboard is optional; MCP must keep working
            self.failures += 1
            print(f"reveng-nexus: dashboard snapshot not written: {exc}", file=sys.stderr)
            return False

    def write(self, *, stopped: bool = False) -> bool:
        """Compose and persist synchronously (shutdown and tests)."""
        built = self.compose(stopped=stopped)
        return built is not None and self.persist(*built, stopped=stopped)

    async def run(self) -> None:
        try:
            await self.manager.wait_until_started()
            while True:
                stale = (
                    self.manager.last_health_at is None
                    or time.time() - self.manager.last_health_at >= HEALTH_REFRESH_SECONDS
                )
                if stale:
                    try:
                        await asyncio.wait_for(self.manager.health(), timeout=60)
                    except Exception:  # noqa: BLE001
                        pass
                built = self.compose()
                if built is not None:
                    # File I/O, including replace retries, runs off the event loop.
                    await asyncio.to_thread(self.persist, *built)
                await asyncio.sleep(self.heartbeat)
        finally:
            self.write(stopped=True)


def snapshots_enabled() -> bool:
    return os.environ.get("REVENG_NEXUS_DASHBOARD_SNAPSHOT", "1") != "0"
