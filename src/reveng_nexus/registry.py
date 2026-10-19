"""Provider manager: lifecycle, capability registry, routing, failover, locking, evidence.

Routing is deterministic: an explicit ``provider`` wins; otherwise
``routing.preferred[operation]`` order, then descending ``priority``, then id. A failed
candidate is followed by at most ``analysis.max_failover`` alternatives, one at a time.
Calls are bounded by a global semaphore, a per-provider semaphore (``max_concurrency``,
default 1) and a per-(conflict_group, target) lock so two drivers of the same engine
never work on one target at the same time.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import anyio

from .access import exposure_map, provider_access, public_names, tool_access
from .artifacts import WorkspaceGuard, identify
from .audit import AuditLog
from .config import NexusConfig, ProviderConfig
from .errors import (
    ArgumentError,
    CapabilityUnavailable,
    NexusError,
    PolicyViolation,
    ProviderCallError,
    ProviderTimeout,
    ProviderUnavailable,
    describe_exception,
)
from .evidence import EvidenceStore
from .mutation_journal import ALL_TARGETS, MutationJournal
from .policy import PolicyEngine
from .providers import OPERATIONS, AnalysisProvider, OperationResult, ProviderRuntime, TargetContext, create_provider

_FAILOVER_ERRORS = (CapabilityUnavailable, ProviderUnavailable, ProviderTimeout, ProviderCallError)
_BUILTIN_ID = "builtin"


def _jsonable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


class ProviderManager:
    def __init__(self, config: NexusConfig) -> None:
        self.config = config
        self.policy = PolicyEngine(config)
        self.audit = AuditLog(config.audit_log)
        self.audit_path = self.audit.path
        self.evidence = EvidenceStore(
            config.evidence_db,
            allowed_roots=config.allowed_roots,
            max_target_size_mb=config.max_target_size_mb,
            follow_symlinks=config.follow_symlinks,
        )
        self.guard = WorkspaceGuard(
            config.allowed_roots, config.max_target_size_mb * 1024 * 1024, config.follow_symlinks
        )
        data_dir = Path(config.data_dir)
        self.runtime = ProviderRuntime(config, self.policy, self.audit, data_dir / "logs")
        configs = list(config.providers)
        if not any(p.type == "builtin" for p in configs):
            configs.insert(
                0,
                ProviderConfig(
                    id=_BUILTIN_ID,
                    name="RevEng Nexus built-in static engine",
                    enabled=True,
                    type="builtin",
                    engine="nexus-builtin",
                    priority=10,
                ),
            )
        self.provider_configs: dict[str, ProviderConfig] = {p.id: p for p in configs}
        self.providers: dict[str, AnalysisProvider] = {}
        self.provider_errors: dict[str, str] = {}
        self.skipped: dict[str, str] = {}
        # Result of the most recent health() run and when it finished (read by the dashboard
        # snapshot, which never triggers a liveness probe of its own).
        self.last_health: dict[str, Any] = {}
        self.last_health_at: float | None = None
        self.started_at = time.time()
        self._provider_sems: dict[str, asyncio.Semaphore] = {}
        self._group_locks: dict[tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)
        self._global_sem = asyncio.Semaphore(config.analysis.max_concurrent_provider_calls)
        # Reuse protection that does not wait for the database, keyed (provider, target or '*' for
        # a shared server) like the persisted reuse blocks: raw calls that may change an engine's
        # state and have not finished writing their block yet, and blocks whose write failed (kept
        # for the life of the process, so a failed write fails closed instead of re-enabling reuse).
        self._mutations_in_flight: Counter[tuple[str, str]] = Counter()
        self._unpersisted_blocks: dict[tuple[str, str], str] = {}
        # The same protection on disk, so it survives a failed block write and a restart (see
        # mutation_journal). Until start() has recovered it, no result is reused at all.
        self.mutation_journal = MutationJournal(Path(config.data_dir) / "mutation-journal")
        self._journal_recovered = False
        self._journal_unreadable: str | None = None
        self._started = False
        self._start_lock = asyncio.Lock()
        # Set once start() has finished (successfully or not) so the MCP server can answer
        # initialize/tools/list immediately while slow engines (JVMs, uvx installs) come up.
        self._startup_done = asyncio.Event()

    # -- compatibility helpers for the 0.1 API ---------------------------------
    @property
    def sessions(self) -> dict[str, AnalysisProvider]:
        return {pid: p for pid, p in self.providers.items() if p.started}

    @property
    def routes(self) -> dict[str, Any]:
        return {name: info for name, (_provider, info) in exposure_map(self).items()}

    # -- lifecycle ----------------------------------------------------------------
    def _skip_reason(self, cfg: ProviderConfig) -> str | None:
        if not cfg.enabled:
            return "disabled in config"
        if cfg.kind == "dynamic" and not self.config.policy.dynamic.enabled:
            return "dynamic provider; policy.dynamic_analysis.enabled is false"
        return None

    async def start(self, only: list[str] | None = None) -> None:
        async with self._start_lock:
            if self._started:
                return
            await self._recover_mutation_journal()
            pending = []
            for cfg in self.provider_configs.values():
                if only is not None and cfg.id not in only and cfg.type != "builtin":
                    continue
                reason = self._skip_reason(cfg)
                if reason:
                    self.skipped[cfg.id] = reason
                    continue
                try:
                    provider = create_provider(cfg, self.runtime)
                except NexusError as exc:
                    self.provider_errors[cfg.id] = exc.message
                    continue
                self.providers[cfg.id] = provider
                self._provider_sems[cfg.id] = asyncio.Semaphore(cfg.max_concurrency)
                pending.append(provider)

            async def init(provider: AnalysisProvider) -> None:
                started = time.monotonic()
                try:
                    with anyio.fail_after(provider.config.startup_timeout_seconds + 5):
                        await provider.initialize()
                    self.provider_errors.pop(provider.id, None)
                    self.audit.write(
                        "provider_started",
                        provider_id=provider.id,
                        outcome="ok",
                        duration_ms=round((time.monotonic() - started) * 1000),
                    )
                except BaseException as exc:  # noqa: BLE001 - isolate every provider failure
                    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                        raise
                    # A start cut short by the gateway's own shutdown (e.g. `claude mcp list` stops
                    # the server after the handshake) is a cancellation, not a provider failure.
                    cancelled = isinstance(exc, asyncio.CancelledError)
                    if cancelled:
                        message = "startup cancelled: the gateway stopped before this provider was ready"
                    elif isinstance(exc, TimeoutError):
                        message = f"startup exceeded {provider.config.startup_timeout_seconds}s"
                    else:
                        message = describe_exception(exc)["message"]
                    self.provider_errors[provider.id] = message
                    provider.last_error = {"message": message, "at": time.time()}
                    self.audit.write(
                        "provider_started",
                        provider_id=provider.id,
                        outcome="cancelled" if cancelled else "failed",
                        error=message,
                        duration_ms=round((time.monotonic() - started) * 1000),
                    )
                    try:
                        await provider.shutdown()
                    except Exception:  # noqa: BLE001
                        pass

            try:
                await asyncio.gather(*(init(p) for p in pending))
            finally:
                self._started = True
                self._startup_done.set()

    @property
    def startup_complete(self) -> bool:
        return self._startup_done.is_set()

    async def wait_until_started(self) -> None:
        """Wait for provider startup when it runs in the background (see ``cli serve``)."""
        await self._startup_done.wait()

    async def close(self) -> None:
        for provider in list(self.providers.values()):
            try:
                with anyio.fail_after(30):
                    await provider.shutdown()
            except BaseException as exc:  # noqa: BLE001
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                self.audit.write(
                    "provider_stopped",
                    provider_id=provider.id,
                    outcome="error",
                    error=describe_exception(exc)["message"],
                )
        self._started = False

    async def refresh_tools(self) -> list[Any]:
        out = []
        for provider in self.providers.values():
            refresh = getattr(provider, "refresh_tools", None)
            if refresh is None or not provider.started:
                continue
            if getattr(provider, "per_target", False) and not provider._tools:
                continue
            try:
                out.extend(await refresh())
            except Exception as exc:  # noqa: BLE001
                self.provider_errors[provider.id] = f"tool discovery failed: {describe_exception(exc)['message']}"
        return out

    # -- introspection ---------------------------------------------------------------
    def provider_summaries(self) -> list[dict[str, Any]]:
        rows = []
        for cfg in self.provider_configs.values():
            provider = self.providers.get(cfg.id)
            if provider is not None:
                row = provider.describe()
            else:
                row = {
                    "id": cfg.id,
                    "name": cfg.name,
                    "type": cfg.type,
                    "adapter": cfg.adapter,
                    "engine": cfg.engine,
                    "kind": cfg.kind,
                    "enabled_in_config": cfg.enabled,
                    "connected": False,
                    "priority": cfg.priority,
                    "tool_count": 0,
                }
            row["transport"] = cfg.transport
            row["capabilities"] = list(cfg.capabilities)
            row["error"] = self.provider_errors.get(cfg.id)
            row["skipped"] = self.skipped.get(cfg.id)
            row["access"] = provider_access(self, cfg.id)
            if provider is not None and provider.started:
                # the describe() counts, made consistent with exposure (namespaced mode, collisions)
                counts = row["access"]["tool_states"]
                row["policy_allowed_tool_count"] = counts["policy_allowed"]
                row["available_tool_count"] = counts["available"]
                row["callable_tool_count"] = counts["exposed"] + counts["callable"]
                row["exposed_tool_count"] = counts["exposed"]
            if cfg.adapter:
                from .adapters import ADAPTERS

                adapter = ADAPTERS.get(cfg.adapter)
                if adapter is not None:
                    row["upstream"] = adapter.describe()
            rows.append(row)
        return rows

    async def health(self) -> dict[str, Any]:
        out = {}
        for cfg in self.provider_configs.values():
            provider = self.providers.get(cfg.id)
            if provider is None:
                out[cfg.id] = {
                    "status": "disabled" if not cfg.enabled else "unavailable",
                    "detail": self.skipped.get(cfg.id) or self.provider_errors.get(cfg.id, ""),
                }
                continue
            if not provider.started:
                out[cfg.id] = {"status": "unavailable", "detail": self.provider_errors.get(cfg.id, "not started")}
                continue
            try:
                with anyio.fail_after(30):
                    out[cfg.id] = (await provider.health_check()).to_dict()
            except BaseException as exc:  # noqa: BLE001
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                out[cfg.id] = {"status": "unavailable", "detail": describe_exception(exc)["message"]}
        self.last_health, self.last_health_at = dict(out), time.time()
        return out

    def capability_registry(self) -> dict[str, Any]:
        operations: dict[str, list[dict[str, Any]]] = {op: [] for op in OPERATIONS}
        for provider in self.providers.values():
            if not provider.started:
                continue
            try:
                caps = provider.list_capabilities()
            except Exception as exc:  # noqa: BLE001
                caps = {}
                self.provider_errors[provider.id] = describe_exception(exc)["message"]
            for op, status in caps.items():
                operations.setdefault(op, []).append(
                    {
                        "provider_id": provider.id,
                        "engine": provider.engine,
                        "engine_family": status.get("engine_family", provider.engine_family),
                        "priority": provider.config.priority,
                        **status,
                    }
                )
        for cfg in self.provider_configs.values():
            if cfg.id in self.providers and self.providers[cfg.id].started:
                continue
            for op in cfg.capabilities:
                if op in operations:
                    operations[op].append(
                        {
                            "provider_id": cfg.id,
                            "available": False,
                            "reason": self.skipped.get(cfg.id) or self.provider_errors.get(cfg.id, "not started"),
                        }
                    )
        duplicates = []
        for op, rows in operations.items():
            available = [r for r in rows if r.get("available")]
            by_family: dict[str, list[str]] = defaultdict(list)
            for row in available:
                by_family[str(row.get("engine_family"))].append(row["provider_id"])
            for family, ids in by_family.items():
                if len(ids) > 1:
                    duplicates.append(
                        {
                            "operation": op,
                            "engine_family": family,
                            "providers": sorted(ids),
                            "note": "overlapping providers wrap the same engine; one is preferred, "
                            "the others are failover/consistency checks, not independent",
                        }
                    )
        return {
            "operations": {
                op: sorted(rows, key=lambda r: (not r.get("available"), -int(r.get("priority") or 0)))
                for op, rows in operations.items()
            },
            "duplicates": duplicates,
            "descriptions": OPERATIONS,
        }

    async def list_tools(
        self, query: str = "", provider_id: str | None = None, include_blocked: bool = False, limit: int = 50
    ) -> list[dict[str, Any]]:
        terms = [t.casefold() for t in query.split() if t]
        names = public_names(self.providers.values(), self.config.tool_mode)
        out = []
        for provider in self.providers.values():
            if provider_id and provider.id != provider_id:
                continue
            for info in await provider.list_tools():
                access = tool_access(provider, info, names)
                if not include_blocked and not access.callable:
                    continue
                hay = f"{info.name} {info.description}".casefold()
                if all(t in hay for t in terms):
                    row = info.to_dict()
                    row.update(
                        public_name=access.public_name,
                        callable=access.callable,
                        exposed=access.exposed,
                        access_state=access.state,
                        policy_reason=access.reason,
                    )
                    out.append(row)
        return out[: max(1, min(limit, 200))]

    # -- targets ---------------------------------------------------------------------
    async def intake(
        self, path: str, *, case_id: str | None = None, case_title: str | None = None, label: str = ""
    ) -> dict[str, Any]:
        resolved = self.guard.check(path)
        identity = await anyio.to_thread.run_sync(identify, resolved)
        if case_title:
            case_id = (await anyio.to_thread.run_sync(lambda: self.evidence.create_case(case_title)))["case_id"]
        row = await anyio.to_thread.run_sync(lambda: self.evidence.upsert_target(identity, case_id, label))
        self.audit.write("target_intake", target_sha256=identity.sha256, case_id=row["case_id"], outcome="ok")
        return {"target": row, "metadata": identity.metadata, "case_id": row["case_id"]}

    def target_context(self, sha256: str, case_id: str | None = None) -> TargetContext:
        row = self.evidence.get_target(sha256, include_path=True)
        path = self.guard.check(row["absolute_path"])
        cases = self.evidence.target_cases(row["target_id"])
        cid = case_id or (cases[0] if cases else "default")
        if case_id and case_id not in cases:
            raise ArgumentError(f"target is not part of case {case_id!r}; inspect it with that case_id first")
        return TargetContext(
            sha256=row["target_id"],
            display_name=row["display_name"],
            original_path=path,
            kind=row.get("kind") or "unknown",
            format=row.get("format") or "unknown",
            metadata=row.get("metadata") or {},
            work_dir=self.config.work_dir,
            case_id=cid,
        )

    # -- routing & execution ---------------------------------------------------------
    def rank(
        self, operation: str, target: TargetContext | None, provider_id: str | None = None
    ) -> tuple[list[AnalysisProvider], list[dict[str, Any]]]:
        rejected: list[dict[str, Any]] = []
        if provider_id:
            provider = self.providers.get(provider_id)
            if provider is None or not provider.started:
                reason = self.skipped.get(provider_id) or self.provider_errors.get(provider_id) or "unknown provider"
                raise ProviderUnavailable(f"provider {provider_id!r} is unavailable: {reason}")
            candidates = [provider]
        else:
            preferred = self.config.routing.get(operation, ())
            ordered = sorted(
                (p for p in self.providers.values() if p.started),
                key=lambda p: (
                    preferred.index(p.id) if p.id in preferred else len(preferred),
                    -p.config.priority,
                    p.id,
                ),
            )
            candidates = ordered
        usable = []
        for provider in candidates:
            try:
                caps = provider.list_capabilities()
            except Exception as exc:  # noqa: BLE001
                rejected.append({"provider_id": provider.id, "reason": describe_exception(exc)["message"]})
                continue
            status = caps.get(operation)
            if status is None:
                if provider_id:
                    rejected.append({"provider_id": provider.id, "reason": f"does not implement {operation}"})
                continue
            if not status.get("available"):
                rejected.append({"provider_id": provider.id, "reason": status.get("reason", "unavailable")})
                continue
            formats = status.get("formats")
            if target is not None and formats and "any" not in formats and target.format not in formats:
                rejected.append({"provider_id": provider.id, "reason": f"does not handle {target.format!r} targets"})
                continue
            if provider.kind == "ai" and not operation.startswith("ai."):
                continue
            usable.append(provider)
        return usable, rejected

    async def perform(
        self,
        operation: str,
        target: TargetContext,
        params: dict[str, Any] | None = None,
        *,
        provider_id: str | None = None,
        record: bool = True,
        max_failover: int | None = None,
        reuse: bool = False,
    ) -> dict[str, Any]:
        """Run one normalised operation with routing/failover and record evidence.

        With ``reuse``, the provider routing would pick first is asked for nothing if this case
        already holds evidence from it for the same target, operation, parameters and engine
        fingerprint (see ``reuse_key``); that evidence is returned with ``reused: True``.
        """
        params = dict(params or {})
        candidates, rejected = self.rank(operation, target, provider_id)
        budget = self.config.analysis.max_failover if max_failover is None else max_failover
        attempts: list[dict[str, Any]] = [
            {"provider_id": r["provider_id"], "outcome": "skipped", "reason": r["reason"]} for r in rejected
        ]
        if not candidates:
            raise CapabilityUnavailable(
                f"no available provider implements {operation} for this {target.format} target",
                details={"attempts": attempts, "alternatives": self._alternatives(operation)},
                remediation="Enable/configure a provider that offers this capability (see nexus_list_capabilities).",
            )
        reuse_status: dict[str, Any] | None = None
        if reuse and record:
            reused, reuse_status = await self._reuse(candidates[0], operation, target, params)
            if reused is not None:
                return reused
        for index, provider in enumerate(candidates[: 1 + budget]):
            started = time.monotonic()
            try:
                result = await self._run_on(provider, operation, target, params)
            except PolicyViolation:
                raise
            except _FAILOVER_ERRORS as exc:
                attempts.append(
                    {
                        "provider_id": provider.id,
                        "outcome": "failed",
                        **exc.to_dict(),
                        "duration_ms": round((time.monotonic() - started) * 1000),
                    }
                )
                self.audit.write(
                    "operation",
                    provider_id=provider.id,
                    operation=operation,
                    outcome="failed",
                    error_code=exc.code,
                    error=exc.message,
                    target_sha256=target.sha256,
                    case_id=target.case_id,
                    attempt=index + 1,
                )
                continue
            attempts.append({"provider_id": provider.id, "outcome": "ok", "duration_ms": result.duration_ms})
            self.audit.write(
                "operation",
                provider_id=provider.id,
                operation=operation,
                outcome="ok",
                duration_ms=result.duration_ms,
                target_sha256=target.sha256,
                case_id=target.case_id,
                attempt=index + 1,
            )
            evidence = None
            if record:
                keys, _status = self.reuse_key(provider, operation, target, params, result)
                if self._reuse_guard(provider.id, target.sha256):
                    keys = None  # an engine-state change is in flight or its block was not persisted
                evidence = await anyio.to_thread.run_sync(functools.partial(self.record_result, result, target, keys))
            out = {"result": result, "evidence": evidence, "attempts": attempts, "reused": False}
            if reuse_status is not None:
                out["reuse_status"] = reuse_status
            return out
        raise CapabilityUnavailable(
            f"{operation} failed on every candidate provider",
            details={"attempts": attempts, "alternatives": self._alternatives(operation)},
        )

    async def _run_on(
        self, provider: AnalysisProvider, operation: str, target: TargetContext, params: dict[str, Any]
    ) -> OperationResult:
        group = provider.config.conflict_group
        lock = self._group_locks[(group, target.sha256)] if group else None
        started = time.monotonic()
        async with self._global_sem, self._provider_sems.setdefault(provider.id, asyncio.Semaphore(1)):
            if lock is not None:
                await lock.acquire()
            try:
                with anyio.fail_after(self.config.analysis.operation_timeout_seconds):
                    result = await provider.perform(operation, target, params)
            except TimeoutError as exc:
                raise ProviderTimeout(
                    f"{provider.id}: {operation} exceeded analysis.operation_timeout_seconds "
                    f"({self.config.analysis.operation_timeout_seconds}s)"
                ) from exc
            except NexusError:
                raise
            except Exception as exc:  # noqa: BLE001 - normalise unexpected adapter errors
                raise ProviderCallError(
                    f"{provider.id}: {operation} failed: {describe_exception(exc)['message']}"
                ) from exc
            finally:
                if lock is not None:
                    lock.release()
        if not result.duration_ms:
            result.duration_ms = round((time.monotonic() - started) * 1000)
        return result

    def _alternatives(self, operation: str) -> list[dict[str, Any]]:
        out = []
        for cfg in self.provider_configs.values():
            adapter_ops: set[str] = set()
            if cfg.adapter:
                from .adapters import ADAPTERS

                adapter = ADAPTERS.get(cfg.adapter)
                adapter_ops = set(adapter.bindings) if adapter else set()
            if operation in adapter_ops or operation in cfg.capabilities:
                state = (
                    self.skipped.get(cfg.id)
                    or self.provider_errors.get(cfg.id)
                    or ("running" if cfg.id in self.providers and self.providers[cfg.id].started else "not started")
                )
                out.append({"provider_id": cfg.id, "state": state})
        return out

    # -- result reuse -------------------------------------------------------------------
    def reuse_key(
        self,
        provider: AnalysisProvider,
        operation: str,
        target: TargetContext,
        params: dict[str, Any],
        result: OperationResult | None = None,
    ) -> tuple[tuple[str, str] | None, dict[str, Any]]:
        """((reuse_key, params_hash) or None, status) for a result of ``provider``.

        The key covers the target hash, provider id, operation, canonical parameters and an engine
        fingerprint: policy/access profile, provider class and config, adapter pin, this package's
        code, and a verified engine identity (``engine_identity``). Without a verified identity
        nothing is reused, and ``status`` says why. AI-generated and dynamic results are never reused.
        """
        if provider.config.kind in {"dynamic", "ai"} or operation.startswith("ai."):
            return None, {"eligible": False, "reason": "AI-generated and dynamic results are never reused"}
        if result is not None and result.evidence_kind == "ai_generated":
            return None, {"eligible": False, "reason": "AI-generated results are never reused"}
        identity, source = engine_identity(provider)
        if identity is None:
            return None, {"eligible": False, "reason": source}
        fingerprint = _engine_fingerprint(provider, self.config.policy, identity)
        params_hash = hashlib.sha256(_canonical(params).encode("utf-8")).hexdigest()
        key = hashlib.sha256(
            _canonical([target.sha256, provider.id, operation, params_hash, fingerprint]).encode("utf-8")
        ).hexdigest()
        return (key, params_hash), {"eligible": True, "identity_source": source}

    def _reuse_guard(self, provider_id: str, target_sha256: str) -> str | None:
        """Why results of this provider for this target must not be reused right now, if so."""
        if not self._journal_recovered:
            return "reuse is held off until the mutation journal has been recovered at start"
        if self._journal_unreadable:
            return self._journal_unreadable
        for scope in (target_sha256.lower(), "*"):
            if self._mutations_in_flight.get((provider_id, scope)):
                return (
                    f"a raw call that may change {provider_id}'s analysis state is still running or "
                    "writing its reuse block"
                )
            if (provider_id, scope) in self._unpersisted_blocks:
                return self._unpersisted_blocks[(provider_id, scope)]
        return None

    async def _reuse(
        self, provider: AnalysisProvider, operation: str, target: TargetContext, params: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        keys, status = self.reuse_key(provider, operation, target, params)
        if keys is None:
            return None, {"provider_id": provider.id, **status}
        if guard := self._reuse_guard(provider.id, target.sha256):
            return None, {"provider_id": provider.id, "eligible": False, "reason": guard}
        block = await anyio.to_thread.run_sync(lambda: self.evidence.reuse_block(provider.id, target.sha256))
        if block is not None:
            return None, {"provider_id": provider.id, "eligible": False, "reason": block["reason"]}
        record = await anyio.to_thread.run_sync(
            lambda: self.evidence.find_reusable(keys[0], target.case_id, target.sha256, provider.id)
        )
        if record is None:
            return None, {"provider_id": provider.id, **status, "reason": "no stored result with this key"}
        if guard := self._reuse_guard(provider.id, target.sha256):  # a mutation started meanwhile
            return None, {"provider_id": provider.id, "eligible": False, "reason": guard}
        self.audit.write(
            "operation",
            provider_id=provider.id,
            operation=operation,
            outcome="reused",
            evidence_id=record["evidence_id"],
            target_sha256=target.sha256,
            case_id=target.case_id,
        )
        result = OperationResult(
            provider_id=record["provider_id"],
            operation=record["operation"],
            tool_name=record["tool_name"],
            engine=record.get("engine") or "",
            engine_family=record.get("engine_family") or "",
            evidence_kind=record["evidence_kind"],
            normalized=record.get("normalized") or {},
            subject_type=record.get("subject_type") or "binary",
            subject_address=record.get("subject_address"),
            subject_name=record.get("subject_name"),
            engine_version=record.get("engine_version"),
            warnings=list(record.get("warnings") or []),
            model=record.get("model"),
            claim=record.get("claim") or "",
        )
        attempt = {"provider_id": provider.id, "outcome": "reused", "evidence_id": record["evidence_id"]}
        reuse_status = {"provider_id": provider.id, **status}
        return {
            "result": result,
            "evidence": record,
            "attempts": [attempt],
            "reused": True,
            "reuse_status": reuse_status,
        }, reuse_status

    def record_result(
        self, result: OperationResult, target: TargetContext, reuse: tuple[str, str] | None = None
    ) -> dict[str, Any]:
        raw_text = _jsonable(result.raw) if result.raw is not None else None
        return self.evidence.add_evidence(
            target_id=target.sha256,
            case_id=target.case_id,
            provider_id=result.provider_id,
            tool_name=result.tool_name,
            operation=result.operation,
            evidence_kind=result.evidence_kind,
            claim=result.claim or result.operation,
            subject=result.subject_label(),
            subject_type=result.subject_type,
            subject_address=result.subject_address,
            subject_name=result.subject_name,
            normalized=result.normalized,
            raw=raw_text,
            raw_limit_bytes=self.config.analysis.raw_output_limit_kb * 1024,
            engine=result.engine,
            engine_family=result.engine_family,
            engine_version=result.engine_version,
            warnings=result.warnings,
            model=result.model,
            confidence="medium" if result.evidence_kind != "ai_generated" else "low",
            reuse_key=reuse[0] if reuse else None,
            params_hash=reuse[1] if reuse else None,
        )

    async def call_provider_tool(
        self, provider_id: str, tool_name: str, arguments: dict[str, Any], target_sha256: str | None = None
    ) -> Any:
        provider = self.providers.get(provider_id)
        if provider is None or not provider.started:
            reason = self.skipped.get(provider_id) or self.provider_errors.get(provider_id, "not configured")
            raise ProviderUnavailable(f"Provider {provider_id!r} is unavailable: {reason}")
        target = None
        if getattr(provider, "per_target", False):
            if not target_sha256:
                raise ArgumentError(f"{provider_id} runs one server per target; pass target (sha256)")
            target = self.target_context(target_sha256)
        async with self._provider_sems.setdefault(provider_id, asyncio.Semaphore(1)):
            # Open the per-target server under the provider semaphore: opening it outside let a
            # concurrent operation switch (or, with max_sessions=1, close) the session in between.
            if target is not None:
                await provider._client_for(target)  # type: ignore[attr-defined]
            # provider.call_tool checks this same catalogue entry first, with no await in between,
            # and refuses a name it does not list (a typo, or a catalogue that could not be
            # discovered) before any contact with the engine: such a call cannot change anything.
            known = getattr(provider, "_tools", {}).get(tool_name)
            # Marked before the call (no await in between) and cleared only after the reuse block
            # write below has finished, so a concurrent reuse lookup cannot see the gap.
            marked = known is not None and known.classification.tool_class != "read"
            mark = (provider_id, (target_sha256 or "").lower() if target is not None else "*")
            if marked:
                self._mutations_in_flight[mark] += 1
            try:
                # Durable before the call is sent; if it cannot be written, nothing is sent.
                entry = await self._open_mutation_entry(provider_id, mark[1], tool_name) if marked else None
                changes_state = False
                succeeded = False
                try:
                    result = await provider.call_tool(tool_name, arguments, internal=False, target_sha256=target_sha256)
                    # It ran: anything not classified read may have changed the engine's state.
                    changes_state = known is None or known.classification.tool_class != "read"
                    succeeded = True
                    return result
                except PolicyViolation:
                    raise  # refused before anything reached the engine
                except BaseException:
                    # Failures (errors, timeouts, cancellation) of a listed tool that is not
                    # classified read are treated as possible mutations.
                    changes_state = known is not None and known.classification.tool_class != "read"
                    raise
                finally:
                    if changes_state:
                        await self._block_reuse_after_mutation(
                            provider_id,
                            tool_name,
                            target_sha256 if target else None,
                            raise_on_failure=succeeded,
                            journal_entry=entry,
                        )
                    elif entry is not None:
                        # Refused before the engine was contacted: nothing can have changed.
                        await self._close_mutation_entry(entry)
            finally:
                if marked:
                    self._mutations_in_flight[mark] -= 1
                    if self._mutations_in_flight[mark] <= 0:
                        del self._mutations_in_flight[mark]

    async def _open_mutation_entry(self, provider_id: str, scope: str, tool_name: str) -> Path:
        """Durably journal a call that may change engine state, before it is sent."""
        created: dict[str, Path] = {}

        def record() -> None:
            created["entry"] = self.mutation_journal.record(provider_id, scope, tool_name)

        failure, cancellation = await _finish_despite_cancellation(record)
        if cancellation is not None:
            if failure is None:  # written, but the call will not be sent: drop the entry again
                await self._close_mutation_entry(created["entry"])
            raise cancellation
        if failure is not None:
            self.audit.write(
                "mutation_journal_failed",
                provider_id=provider_id,
                tool_name=tool_name,
                outcome="refused",
                error=describe_exception(failure)["message"],
            )
            raise ProviderCallError(
                f"{provider_id}: '{tool_name}' was not sent: the mutation journal could not be written "
                f"durably ({describe_exception(failure)['message']})",
                remediation="Check that the data directory is writable; nothing reached the engine.",
            ) from failure
        return created["entry"]

    async def _close_mutation_entry(self, entry: Path) -> bool:
        """Remove a resolved journal entry. A failure keeps it: reuse then stays blocked at the next
        start, where recovery re-applies the (idempotent) block and removes it."""
        failure, cancellation = await _finish_despite_cancellation(lambda: self.mutation_journal.resolve(entry))
        if failure is not None:
            self.audit.write(
                "mutation_journal_failed",
                outcome="kept",
                error=describe_exception(failure)["message"],
            )
        if cancellation is not None:
            raise cancellation
        return failure is None

    async def _recover_mutation_journal(self) -> None:
        """Re-apply the reuse block for every journal entry left by an earlier process (a failed
        block write, or a stop before it). Until this has run, nothing is reused; an entry whose
        block cannot be written now keeps reuse off in this process and stays on disk."""
        try:
            entries, unknown = await anyio.to_thread.run_sync(self.mutation_journal.pending)
        except OSError as exc:
            self._journal_unreadable = (
                "reuse is off for every provider: the mutation journal could not be read "
                f"({describe_exception(exc)['message']}); fix or remove {self.mutation_journal.directory}"
            )
            self.audit.write("mutation_journal_unreadable", outcome="failed", error=self._journal_unreadable)
            self._journal_recovered = True
            return
        if unknown:
            self._journal_unreadable = (
                "reuse is off for every provider: the mutation journal holds entries that cannot be read "
                f"({unknown[:5]}); inspect and remove them in {self.mutation_journal.directory}"
            )
            self.audit.write("mutation_journal_unreadable", outcome="failed", error=self._journal_unreadable)
        for provider_id, scope, path in entries:
            target_id = None if scope == ALL_TARGETS else scope
            scope_text = "every target (one shared server)" if target_id is None else "this target"
            reason = (
                f"reuse disabled for this provider on {scope_text}: a raw call that may have changed its "
                "analysis state was journalled, but its reuse block was not confirmed before the gateway stopped"
            )
            self._unpersisted_blocks[(provider_id, scope)] = reason
            failure, _ = await _finish_despite_cancellation(
                functools.partial(self.evidence.invalidate_reuse, provider_id, target_id, reason)
            )
            if failure is None and await self._close_mutation_entry(path):
                self._unpersisted_blocks.pop((provider_id, scope), None)  # the persisted block now applies
            self.audit.write(
                "mutation_journal_recovered",
                provider_id=provider_id,
                target_sha256=target_id,
                outcome="ok" if failure is None else "failed",
                error=describe_exception(failure)["message"] if failure is not None else None,
            )
        self._journal_recovered = True

    async def _block_reuse_after_mutation(
        self,
        provider_id: str,
        tool_name: str,
        target_sha256: str | None,
        *,
        raise_on_failure: bool,
        journal_entry: Path | None = None,
    ) -> None:
        """Persist the reuse block for a raw call that may have changed the engine's state.

        The write cannot be skipped by cancellation: a caller cancelling the request (an MCP
        ``notifications/cancelled``, an AnyIO scope, or plain ``Task.cancel()``, once or repeatedly)
        after it reached the engine still gets the block persisted, and the cancellation propagates
        once the write has finished (see ``_finish_despite_cancellation``). Cancellation cannot help
        if the database write fails or cannot be started; that is audited, and turned into an error
        when the call had succeeded (so it is not reported as a clean success), while an exception
        already propagating, such as the cancellation, is left unchanged.
        """
        # The engine's state may have changed (rename, patch, script): results stored from this
        # provider must not be handed out again. Their evidence stays.
        scope = "this target" if target_sha256 else "every target (one shared server)"
        reason = (
            f"reuse disabled for this provider on {scope}: its analysis state was changed by a raw "
            f"'{tool_name}' call, and state changes may not survive an engine restart or rebuild"
        )
        failure, cancellation = await _finish_despite_cancellation(
            lambda: self.evidence.invalidate_reuse(provider_id, target_sha256, reason)
        )
        if failure is None and journal_entry is not None:
            # The block is persisted: the journal entry has done its job. Removing it is cancellation
            # safe like the write; if it fails, the next start re-applies the block and removes it.
            removal_failure, late = await _finish_despite_cancellation(
                lambda: self.mutation_journal.resolve(journal_entry)
            )
            cancellation = cancellation or late
            if removal_failure is not None:
                self.audit.write(
                    "mutation_journal_failed",
                    provider_id=provider_id,
                    outcome="kept",
                    error=describe_exception(removal_failure)["message"],
                )
        if failure is not None:
            # Fail closed: without the persisted block, keep reuse off here for the life of the process
            # (the journal entry stays on disk, so the next start keeps it off and retries the block).
            self._unpersisted_blocks[(provider_id, target_sha256.lower() if target_sha256 else "*")] = (
                f"{reason}; the persisted reuse block could not be written, so reuse stays off (the mutation "
                "journal keeps it off after a restart until the block is written)"
            )
            self.audit.write(
                "reuse_block_failed",
                provider_id=provider_id,
                tool_name=tool_name,
                outcome="failed",
                error=describe_exception(failure)["message"],
                target_sha256=target_sha256,
            )
        if cancellation is not None:
            raise cancellation  # a cancellation that arrived during the write still wins
        if failure is None:
            return
        if raise_on_failure:
            raise ProviderCallError(
                f"{provider_id}: '{tool_name}' ran, but stored results could not be marked non-reusable: "
                f"{describe_exception(failure)['message']}",
                remediation="Use refresh: true for this provider until the evidence database is writable again.",
            ) from failure

    # 0.1 compatibility: ``manager.call(provider, tool, args)``
    async def call(self, provider_id: str, tool_name: str, arguments: dict[str, Any]) -> Any:
        return await self.call_provider_tool(provider_id, tool_name, arguments)

    def with_config(self, **changes: Any) -> NexusConfig:
        return replace(self.config, **changes)


async def _finish_despite_cancellation(
    write: Callable[[], Any],
) -> tuple[Exception | None, BaseException | None]:
    """Run ``write`` in a worker thread and wait until it has finished, whatever cancels the caller.

    Returns ``(failure, cancellation)``: the exception ``write`` raised, or the one that kept it
    from being started, if any, and the last cancellation that arrived while waiting, which the
    caller must re-raise. The write is one executor job, so it is neither repeated nor dropped;
    each wait is bounded by that single job (SQLite's busy timeout). The event loop is not
    blocked meanwhile.

    An AnyIO shield alone is not enough on asyncio: it does not stop ``Task.cancel()``, and
    ``anyio.to_thread.run_sync`` drops a job whose wait was cancelled before the worker started.
    Here the job is submitted to the loop's executor up front and awaited through
    ``asyncio.shield``, so a cancelled wait leaves the job running and is simply resumed.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is None:
        # Other AnyIO backends (trio) cancel only through scopes, which the shield covers.
        failure: Exception | None = None
        with anyio.CancelScope(shield=True):
            try:
                await anyio.to_thread.run_sync(write)
            except Exception as exc:  # noqa: BLE001 - returned to the caller, which reports it
                failure = exc
        return failure, None
    try:
        job = loop.run_in_executor(None, write)
    except Exception as exc:  # noqa: BLE001 - never started (executor shut down, no thread): a failure
        return exc, None  # nothing was awaited yet, so no cancellation can have arrived
    cancellation: BaseException | None = None
    while True:
        try:
            with anyio.CancelScope(shield=True):  # AnyIO scope cancellation is held off here
                await asyncio.shield(job)  # a native Task.cancel() cancels only this wait
            return None, cancellation
        except asyncio.CancelledError as exc:
            cancellation = exc
            if job.done():
                break  # finished at the same moment; fall through to collect its outcome
        except Exception as exc:  # noqa: BLE001 - the write's own failure, returned to the caller
            return exc, cancellation
    error = job.exception()
    return (error if isinstance(error, Exception) else None), cancellation


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@functools.lru_cache(maxsize=1)
def _code_fingerprint() -> str:
    """Hash of this package's Python sources: normalisation code is part of the engine."""
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _engine_fingerprint(provider: AnalysisProvider, policy: Any, identity: dict[str, Any]) -> str:
    """Everything that decides a provider's answer, known before the call.

    The policy (access profile included) is part of it: a result produced under one profile is
    not handed back under another, where the same request might be refused.
    """
    from dataclasses import asdict

    parts: dict[str, Any] = {
        "policy": hashlib.sha256(_canonical(asdict(policy)).encode("utf-8")).hexdigest(),
        "provider": provider.id,
        "class": type(provider).__name__,
        "engine": provider.engine,
        "family": provider.engine_family,
        "config": hashlib.sha256(_canonical(asdict(provider.config)).encode("utf-8")).hexdigest(),
        "code": _code_fingerprint(),
        "identity": identity,
    }
    adapter = getattr(provider, "adapter", None)
    if adapter is not None:
        parts["pin"] = [adapter.pin.revision, adapter.pin.package_version]
    return _canonical(parts)


def engine_identity(provider: AnalysisProvider) -> tuple[dict[str, Any] | None, str]:
    """(identity, source) of the engine behind ``provider``, or (None, reason) when it is unknown.

    Only identities that can be verified before a call count:
    - built-in engine: its parser and disassembler library versions (with the package code hash);
    - Ghidra (re-mcp-ghidra, MCPyGhidra): the installation's Ghidra/application.properties, read
      from the GHIDRA_INSTALL_DIR the child is given (the file pyghidra reads at launch): version,
      release, build date, Ghidra git revision and the file's hash. An in-place upgrade changes it.
      The MCP serverInfo of these wrappers is the FastMCP framework version and is never used;
    - REA: the server-reported rea-agents version, which the adapter pins (drift disables REA);
    - otherwise an operator-attested ``settings.engine_identity`` string, if configured.
    """
    family = provider.engine_family or provider.engine
    if type(provider).__name__ == "BuiltinStaticProvider":
        from .providers import builtin

        return {"libraries": [builtin._capstone_version(), builtin._parser_versions()]}, "builtin libraries"
    reason = "the engine version cannot be verified for this provider"
    if family == "ghidra" and provider.config.type not in {"mcp_stdio", "mcp_launched_http"}:
        reason = "the Ghidra server is not launched by Nexus, so its installation cannot be identified"
    elif family == "ghidra":
        identity, why = ghidra_installation_identity(provider)
        if identity is not None:
            source = "Ghidra installation metadata (application.properties, launch.properties, JDK release)"
            if not identity.get("jdk"):
                source += "; JDK not identified (no JAVA_HOME for the child: Ghidra locates its own JDK)"
            return identity, source
        reason = why
    elif (provider.config.adapter or "") == "rea":
        version = (getattr(provider, "server_info", None) or {}).get("version")
        if version:
            return {"rea_agents": version}, "REA server version (pinned and drift-checked by the adapter)"
        reason = "REA has not reported its version yet (not connected)"
    attested = str((provider.config.settings or {}).get("engine_identity") or "").strip()
    if attested:
        return {"operator_attested": attested}, "operator-attested settings.engine_identity"
    return (
        None,
        f"{reason}; reuse is disabled (set settings.engine_identity after confirming the engine version to opt in)",
    )


_GHIDRA_KEYS = (
    "application.name",
    "application.version",
    "application.release.name",
    "application.build.date",
    "application.revision.ghidra",
)


def ghidra_installation_identity(provider: AnalysisProvider) -> tuple[dict[str, Any] | None, str]:
    """Identity of the Ghidra installation a provider's child process will use, or (None, reason)."""
    child_env, missing = _child_env(provider)
    if missing:
        return None, f"the provider environment refers to unset variables {sorted(set(missing))}"
    value = _env_get(child_env, "GHIDRA_INSTALL_DIR")
    if not value:
        return None, "GHIDRA_INSTALL_DIR is not set, so the Ghidra installation cannot be identified"
    install = Path(value)
    if not install.is_absolute():
        return None, "GHIDRA_INSTALL_DIR is relative (the child resolves it elsewhere), so it cannot be identified"
    if not install.is_dir():
        # The wrappers then fall back to other locations on their own, which Nexus cannot see.
        return None, "GHIDRA_INSTALL_DIR is not a directory, so the Ghidra installation cannot be identified"
    props = install / "Ghidra" / "application.properties"
    if not props.is_file():
        return None, "Ghidra/application.properties is missing under GHIDRA_INSTALL_DIR"
    identity: dict[str, Any] | None = _read_ghidra_properties(props)
    if identity is None:
        return None, "Ghidra/application.properties does not name a Ghidra version and build"
    launch = install / "support" / "launch.properties"  # JAVA_HOME_OVERRIDE, JVM arguments
    if launch.is_file():
        identity["launch_properties_sha256"] = hashlib.sha256(launch.read_bytes()).hexdigest()
    java_home = _env_get(child_env, "JAVA_HOME")
    identity["jdk"] = _jdk_release(Path(java_home)) if java_home and Path(java_home).is_absolute() else None
    return identity, ""


def _child_env(provider: AnalysisProvider) -> tuple[dict[str, str], list[str]]:
    """The environment the provider's child process is started with (providers/mcp.py)."""
    from .providers.mcp import build_child_env

    inherit = (provider.config.settings or {}).get("inherit_env", [])
    return build_child_env(provider.config.env or {}, inherit if isinstance(inherit, list) else [])


def _env_get(env: dict[str, str], name: str) -> str:
    """Look a variable up the way the child sees it: case-insensitively on Windows, where the
    last of several case variants wins when the process environment is built."""
    import os

    if os.name != "nt":
        return env.get(name, "")
    value = ""
    for key, val in env.items():
        if key.upper() == name.upper():
            value = val
    return value


def _jdk_release(java_home: Path) -> dict[str, str] | None:
    """Runtime version and vendor from <JAVA_HOME>/release (present in every modern JDK)."""
    try:
        text = (java_home / "release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    values = {}
    for line in text.splitlines():
        key, _, val = line.partition("=")
        if key.strip() in {"JAVA_RUNTIME_VERSION", "JAVA_VERSION", "IMPLEMENTOR"}:
            values[key.strip()] = val.strip().strip('"')
    return values or None


def _read_ghidra_properties(path: Path) -> dict[str, str] | None:
    """Read and hash the file on every check (about 1 KB), so no replacement can go unnoticed."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    values: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")) or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    if values.get("application.name") != "Ghidra" or not values.get("application.version"):
        return None
    if not (values.get("application.build.date") or values.get("application.revision.ghidra")):
        return None
    out = {key: values.get(key, "") for key in _GHIDRA_KEYS}
    out["sha256"] = hashlib.sha256(data).hexdigest()
    return out
