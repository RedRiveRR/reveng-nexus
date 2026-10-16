"""Read-only data sources for the dashboard.

Three sources, all inside the configured ``data_dir`` and none chosen by a request:

* gateway snapshots (``dashboard/gateway-*.json``, written by ``reveng-nexus serve``):
  live state and every policy decision, as computed by the gateway itself;
* the metadata-only audit log (tail only);
* the evidence database, opened ``mode=ro`` for aggregate counts (no claims, paths or output).

Nothing here starts a provider, contacts a gateway or writes a file.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Any

from ..config import NexusConfig
from ..policy import TOOL_CLASS_DESCRIPTIONS
from ..snapshot import HEARTBEAT_SECONDS, SNAPSHOT_DIRNAME, SNAPSHOT_NAME, sanitize, sanitize_text
from ..verification import STATES, documented_state

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_FILES = 50
_READ_ATTEMPTS = 5
AUDIT_TAIL_BYTES = 2 * 1024 * 1024
LIVE_AFTER_SECONDS = 3 * HEARTBEAT_SECONDS

METRIC_DEFINITIONS: dict[str, dict[str, str]] = {
    "upstream_tools_discovered": {
        "label": "Upstream tools discovered",
        "definition": "Tools the provider's MCP server returned from tools/list, after the gateway's last discovery.",
        "source": "gateway snapshot (provider catalogue)",
    },
    "policy_allowed_tools": {
        "label": "Allowed by policy",
        "definition": "Discovered tools whose catalogue decision from the gateway's PolicyEngine is 'allowed'. "
        "Includes tools an adapter-only provider may use internally for its nexus_* operations.",
        "source": "gateway snapshot (PolicyDecision.allowed)",
    },
    "callable_tools": {
        "label": "Callable through Nexus",
        "definition": "Allowed tools a caller may invoke directly (nexus_call_provider_tool or namespaced tools): "
        "allowed and not adapter-only. Every call is still re-checked with its actual arguments.",
        "source": "gateway snapshot (ToolInfo.callable)",
    },
    "exposed_tools": {
        "label": "Exposed to MCP clients",
        "definition": "Raw provider tools listed to Claude Code as their own MCP tools. Only in tool_mode "
        "'namespaced' with expose_tools; in 'compact' mode (default) this is 0 and raw tools are reached "
        "through nexus_call_provider_tool.",
        "source": "gateway snapshot (tool_mode, expose_tools, callable)",
    },
    "blocked_tools": {
        "label": "Blocked",
        "definition": "Discovered tools the policy denies (mutate under read-only, execute, dynamic, lifecycle "
        "for callers, blocked, unknown). Visible for transparency; never executable.",
        "source": "gateway snapshot",
    },
    "operations_declared": {
        "label": "Operations declared",
        "definition": "Nexus operations (binary.decompile, js.application, ...) the provider's adapter binds.",
        "source": "gateway snapshot (provider.list_capabilities)",
    },
    "operations_usable": {
        "label": "Operations usable",
        "definition": "Declared operations whose required upstream tools are present and allowed right now.",
        "source": "gateway snapshot (capability 'available')",
    },
    "nexus_tools": {
        "label": "Nexus tools exposed",
        "definition": "The gateway's own nexus_* MCP tools, always listed to clients; each reaches operations "
        "or local evidence functions, never an arbitrary upstream tool.",
        "source": "gateway snapshot (server.TOOL_SPECS)",
    },
}

LEGACY_CANCEL_NOTE = (
    "recorded before the 2026-10-16 fix: a provider start cut short by the gateway's own shutdown "
    "(e.g. `claude mcp list`) was logged as 'failed' with CancelledError; it is now logged as 'cancelled'. "
    "The original outcome is shown unchanged."
)

FRESHNESS = {
    "live": "from a gateway whose last heartbeat is recent",
    "stale": "from a gateway that stopped writing heartbeats without a clean shutdown",
    "stopped": "from a gateway that has shut down (last known state)",
    "historical": "a documented record from the provider matrix, not a measurement",
    "unavailable": "no source exists for this datum",
}


def _now() -> float:
    return time.time()


class DashboardData:
    def __init__(self, config: NexusConfig) -> None:
        self.config = config
        self.data_dir = Path(config.data_dir)
        self.snapshot_dir = self.data_dir / SNAPSHOT_DIRNAME
        self.unreadable_snapshots = 0
        self.read_errors: list[str] = []  # every failed read attempt, by exception type (diagnostics)

    # -- snapshots --------------------------------------------------------------------
    def snapshots(self) -> list[dict[str, Any]]:
        if not self.snapshot_dir.is_dir():
            return []
        # Only complete files: the writer replaces <name>.json atomically and never exposes its
        # <name>.json.tmp, which this pattern does not match.
        files = sorted(
            (p for p in self.snapshot_dir.iterdir() if SNAPSHOT_NAME.match(p.name) and p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:MAX_SNAPSHOT_FILES]
        out = []
        self.unreadable_snapshots = 0
        self.read_errors = []
        for path in files:
            loaded = self._read_snapshot(path)
            if loaded is None:
                self.unreadable_snapshots += 1
                continue
            stat, data = loaded
            if not isinstance(data, dict) or not isinstance(data.get("gateway"), dict):
                self.unreadable_snapshots += 1
                continue
            gateway = data["gateway"]
            # Heartbeats without content changes only touch the file, so liveness is the newer
            # of the recorded write time and the modification time.
            last_seen = max(float(data.get("written_at") or 0), stat.st_mtime)
            age = max(0.0, _now() - last_seen)
            if gateway.get("stopped_at"):
                freshness = "stopped"
            elif age <= LIVE_AFTER_SECONDS:
                freshness = "live"
            else:
                freshness = "stale"
            data["freshness"] = freshness
            data["age_seconds"] = round(age, 1)
            out.append(data)
        return out

    def _read_snapshot(self, path: Path) -> tuple[os.stat_result, Any] | None:
        """Read one complete snapshot, retrying briefly.

        The writer replaces the file atomically, so its content is never partial; on Windows,
        though, opening it at the instant of the replace can fail with a sharing violation or
        a momentary not-found. Those are retried; anything else counts as unreadable.
        """
        for attempt in range(_READ_ATTEMPTS):
            try:
                stat = path.stat()
                if stat.st_size > MAX_SNAPSHOT_BYTES:
                    self.read_errors.append("TooLarge")
                    return None
                return stat, json.loads(path.read_text(encoding="utf-8"))
            except (PermissionError, FileNotFoundError) as exc:
                self.read_errors.append(type(exc).__name__)
                time.sleep(0.02 * (attempt + 1))
            except (OSError, ValueError) as exc:
                self.read_errors.append(type(exc).__name__)
                return None
        return None

    def _configured(self) -> dict[str, Any]:
        cfg = self.config
        policy = cfg.policy
        return sanitize(
            {
                "config_path": cfg.config_path,
                "tool_mode": cfg.tool_mode,
                "read_only": policy.read_only,
                "code_execution": policy.allow_code_execution,
                "dynamic_analysis": policy.dynamic.enabled,
                "remote_ai": policy.allow_remote_ai,
                "remote_providers": policy.allow_remote_providers,
                "providers": [
                    {
                        "id": p.id,
                        "name": p.name,
                        "type": p.type,
                        "adapter": p.adapter,
                        "engine": p.engine,
                        "kind": p.kind,
                        "enabled": p.enabled,
                        "transport": p.transport,
                        "capabilities": list(p.capabilities),
                        "verification": documented_state(p.id),
                    }
                    for p in cfg.providers
                ],
                "warnings": list(cfg.warnings),
            }
        )

    def state(self) -> dict[str, Any]:
        snaps = self.snapshots()
        live = [s for s in snaps if s["freshness"] == "live"]
        primary = live[0] if live else (snaps[0] if snaps else None)
        configured = self._configured()
        mismatches: list[str] = []
        if primary is not None:
            eff = primary["policy"]
            for key in ("read_only", "code_execution", "dynamic_analysis", "remote_ai", "remote_providers"):
                if eff.get(key) != configured.get(key):
                    mismatches.append(
                        f"{key}: configured {configured.get(key)!r}, gateway reports {eff.get(key)!r} "
                        "(the config changed after the gateway started, or another config is in use)"
                    )
        return {
            "generated_at": _now(),
            "primary": primary,
            "instances": [
                {
                    "pid": s["gateway"].get("pid"),
                    "freshness": s["freshness"],
                    "age_seconds": s["age_seconds"],
                    "started_at": s["gateway"].get("started_at"),
                    "stopped_at": s["gateway"].get("stopped_at"),
                    "transport": s["gateway"].get("transport"),
                    "startup_complete": s["gateway"].get("startup_complete"),
                }
                for s in snaps
            ],
            "unreadable_snapshots": self.unreadable_snapshots,
            "configured": configured,
            "policy_mismatches": mismatches,
            "definitions": METRIC_DEFINITIONS,
            "freshness_legend": FRESHNESS,
            "verification_states": STATES,
            "tool_classes": TOOL_CLASS_DESCRIPTIONS,
            "architecture": self.architecture(primary, configured),
        }

    # -- architecture -----------------------------------------------------------------
    @staticmethod
    def architecture(primary: dict[str, Any] | None, configured: dict[str, Any]) -> dict[str, Any]:
        providers = {p["id"]: p for p in (primary or {}).get("providers", [])}
        policy = (primary or {}).get("policy") or {}
        nodes: list[dict[str, Any]] = [
            {
                "id": "client",
                "label": "MCP client",
                "subtitle": "Claude Code",
                "group": "client",
                "responsibility": "Sends MCP tool calls; sees only the nexus_* tools (compact mode).",
                "inputs": "user prompts",
                "outputs": "JSON-RPC tools/list and tools/call over stdio",
                "dependencies": ["reveng-nexus serve (stdio)"],
            },
            {
                "id": "gateway",
                "label": "Nexus gateway",
                "subtitle": "server.py",
                "group": "core",
                "responsibility": "Validates arguments against each nexus_* schema and dispatches to the registry.",
                "inputs": "MCP tools/call",
                "outputs": "normalised results with provenance and an untrusted-content notice",
                "dependencies": ["registry", "policy", "evidence"],
                "status": "live" if primary and primary.get("freshness") == "live" else "unknown",
            },
            {
                "id": "registry",
                "label": "Provider registry",
                "subtitle": "registry.py",
                "group": "core",
                "responsibility": "Starts providers, routes operations by priority, fails over, holds per-provider locks.",
                "inputs": "operation + target",
                "outputs": "OperationResult from one provider",
                "dependencies": ["providers"],
            },
            {
                "id": "policy",
                "label": "Security policy",
                "subtitle": "policy.py",
                "group": "core",
                "responsibility": "Classifies every upstream tool and decides each call with its actual arguments. "
                "The only place callability is decided.",
                "inputs": "tool name, annotations, adapter manifest, arguments",
                "outputs": "PolicyDecision (allowed, class, reason)",
                "dependencies": [],
                "restrictions": [
                    f"read_only={policy.get('read_only')}",
                    f"code_execution={policy.get('code_execution')}",
                    f"dynamic_analysis={policy.get('dynamic_analysis')}",
                    f"never relaxable: {', '.join(policy.get('unrelaxable_classes') or [])}",
                ],
            },
            {
                "id": "guard",
                "label": "Workspace guard",
                "subtitle": "artifacts.py",
                "group": "core",
                "responsibility": "Admits targets only from allowed roots; hashes them; hands providers a "
                "hash-verified staged copy, never the original.",
                "inputs": "target path",
                "outputs": "SHA-256 + staged copy",
                "dependencies": [],
            },
            {
                "id": "evidence",
                "label": "Evidence store",
                "subtitle": "evidence.py (SQLite)",
                "group": "store",
                "responsibility": "Stores every result with target SHA-256, provider and tool provenance.",
                "inputs": "OperationResult",
                "outputs": "evidence records, reports",
                "dependencies": [],
            },
            {
                "id": "audit",
                "label": "Audit log",
                "subtitle": "audit.py (JSONL)",
                "group": "store",
                "responsibility": "Metadata-only log of operations, calls, blocks and provider starts.",
                "inputs": "events",
                "outputs": "append-only JSON lines",
                "dependencies": [],
            },
        ]
        edges: list[dict[str, Any]] = [
            {"from": "client", "to": "gateway", "label": "MCP stdio"},
            {"from": "gateway", "to": "registry", "label": "operation"},
            {"from": "registry", "to": "policy", "label": "decide"},
            {"from": "gateway", "to": "guard", "label": "intake"},
            {"from": "registry", "to": "evidence", "label": "record"},
            {"from": "registry", "to": "audit", "label": "log"},
        ]
        for cfg in configured.get("providers", []):
            pid = cfg["id"]
            live = providers.get(pid) or {}
            health = (live.get("health") or {}).get("status") if live else None
            status = health or ("disabled" if not cfg["enabled"] else "unknown")
            counts = live.get("counts") or {}
            nodes.append(
                {
                    "id": f"provider:{pid}",
                    "label": pid,
                    "subtitle": f"{cfg.get('adapter') or cfg.get('type')} adapter",
                    "group": "provider",
                    "status": status,
                    "enabled": cfg["enabled"],
                    "responsibility": "Adapter: binds Nexus operations to pinned upstream tools and "
                    "normalises their answers."
                    + (" Adapter-only: no raw tool is callable." if live.get("adapter_only") else ""),
                    "inputs": "operation + staged target",
                    "outputs": "normalised result + raw output",
                    "dependencies": [f"upstream:{pid}"],
                    "verification": cfg.get("verification"),
                    "counts": counts,
                    "usable_operations": live.get("usable_operations", []),
                }
            )
            upstream = (live.get("upstream") or {}) if live else {}
            nodes.append(
                {
                    "id": f"upstream:{pid}",
                    "label": upstream.get("package") or cfg.get("engine") or cfg.get("type"),
                    "subtitle": f"{cfg.get('engine') or ''} {('@' + upstream['package_version']) if upstream.get('package_version') else ''}".strip(),
                    "group": "upstream",
                    "status": status,
                    "enabled": cfg["enabled"],
                    "responsibility": "Upstream implementation, run as its own process (or in-process for built-in).",
                    "inputs": f"{cfg.get('transport') or 'in-process'}",
                    "outputs": "upstream tool results (untrusted data)",
                    "dependencies": [upstream.get("upstream")] if upstream.get("upstream") else [],
                    "pin": upstream.get("pinned_revision"),
                }
            )
            edges.append(
                {"from": "registry", "to": f"provider:{pid}", "label": "operation", "active": status == "ready"}
            )
            edges.append(
                {
                    "from": f"provider:{pid}",
                    "to": f"upstream:{pid}",
                    "label": cfg.get("transport") or "call",
                    "active": status == "ready",
                }
            )
        return {"nodes": nodes, "edges": edges}

    # -- activity ---------------------------------------------------------------------
    def _audit_tail(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        path = Path(self.config.audit_log)
        if not path.is_file():
            return [], {"available": False, "reason": "no audit log yet"}
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > AUDIT_TAIL_BYTES:
                handle.seek(size - AUDIT_TAIL_BYTES)
                handle.readline()  # drop the partial first line
            chunk = handle.read()
        rows = []
        for line in chunk.decode("utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                if isinstance(row.get("target_sha256"), str):
                    row["target_sha256"] = row["target_sha256"][:12]
                rows.append(row)
        info = {
            "available": True,
            "bytes": size,
            "tail_only": size > AUDIT_TAIL_BYTES,
            "records_read": len(rows),
            "last_modified": path.stat().st_mtime,
        }
        return sanitize(rows), info

    def _evidence_summary(self) -> dict[str, Any]:
        path = Path(self.config.evidence_db)
        if not path.is_file():
            return {"available": False, "reason": "no evidence database yet"}
        try:
            conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=1.0)
        except sqlite3.Error as exc:
            return {"available": False, "reason": sanitize_text(str(exc))}
        try:
            counts = {}
            for table in ("cases", "targets", "evidence", "findings", "comparisons", "reviews"):
                try:
                    counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608 - fixed names
                except sqlite3.Error:
                    counts[table] = None
            by_provider = [
                {"provider_id": r[0], "tool_name": r[1], "count": r[2], "latest": r[3]}
                for r in conn.execute(
                    "SELECT provider_id, tool_name, COUNT(*), MAX(created_at) FROM evidence "
                    "GROUP BY provider_id, tool_name ORDER BY COUNT(*) DESC LIMIT 50"
                ).fetchall()
            ]
            return {
                "available": True,
                "counts": counts,
                "evidence_by_provider_tool": by_provider,
                "opened": "read-only",
            }
        except sqlite3.Error as exc:
            return {"available": False, "reason": sanitize_text(str(exc))}
        finally:
            conn.close()

    def activity(self, limit: int = 300) -> dict[str, Any]:
        rows, info = self._audit_tail()
        # Audit records are history. Each is labelled against the running gateway's start so an
        # old failure is never read as current health (which comes from the gateway snapshot).
        live = [s for s in self.snapshots() if s["freshness"] == "live"]
        current_since = min((float(s["gateway"].get("started_at") or 0) for s in live), default=None)
        for r in rows:
            ts = float(r.get("timestamp") or 0)
            r["era"] = "current" if current_since is not None and ts >= current_since else "historical"
            if (
                r.get("event") == "provider_started"
                and r.get("outcome") == "failed"
                and str(r.get("error") or "").startswith("CancelledError")
            ):
                r["note"] = LEGACY_CANCEL_NOTE
        events = Counter((r.get("event"), r.get("outcome")) for r in rows)
        blocked = [r for r in rows if r.get("event") == "tool_call_blocked"]
        calls = [r for r in rows if r.get("event") in {"tool_call", "operation", "model_call"}]
        by_provider: dict[str, dict[str, Any]] = {}
        for r in calls:
            pid = str(r.get("provider_id") or "?")
            entry = by_provider.setdefault(pid, {"calls": 0, "errors": 0, "total_ms": 0})
            entry["calls"] += 1
            entry["errors"] += 1 if r.get("outcome") not in {"ok", None} else 0
            entry["total_ms"] += int(r.get("duration_ms") or 0)
        starts = [r for r in rows if r.get("event") == "provider_started"]
        return {
            "generated_at": _now(),
            "audit": info,
            "current_gateway_since": current_since,
            "legacy_cancel_records": sum(1 for r in rows if r.get("note") == LEGACY_CANCEL_NOTE),
            "recent": list(reversed(rows))[: max(1, min(limit, 1000))],
            "event_counts": [{"event": e, "outcome": o, "count": c} for (e, o), c in events.most_common()],
            "policy_denials": list(reversed(blocked))[:100],
            "provider_starts": list(reversed(starts))[:100],
            "calls_by_provider": by_provider,
            "evidence": self._evidence_summary(),
            "telemetry_notes": [
                "Activity comes only from the audit log: request arguments and results are never logged.",
                "There is no live request stream; refresh to re-read the log.",
                "Every audit record is history. Records before the running gateway started are labelled "
                "'historical'; current provider health comes from the gateway snapshot, not from these records.",
            ],
        }
