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
import json
import time
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

import anyio

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
        self._provider_sems: dict[str, asyncio.Semaphore] = {}
        self._group_locks: dict[tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)
        self._global_sem = asyncio.Semaphore(config.analysis.max_concurrent_provider_calls)
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
        out = {}
        for provider in self.providers.values():
            for info in provider._tools.values():
                if info.callable:
                    out[info.public_name] = info
        return out

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
                    message = (
                        describe_exception(exc)["message"]
                        if not isinstance(exc, TimeoutError)
                        else (f"startup exceeded {provider.config.startup_timeout_seconds}s")
                    )
                    self.provider_errors[provider.id] = message
                    provider.last_error = {"message": message, "at": time.time()}
                    self.audit.write(
                        "provider_started",
                        provider_id=provider.id,
                        outcome="failed",
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
        out = []
        for provider in self.providers.values():
            if provider_id and provider.id != provider_id:
                continue
            for info in await provider.list_tools():
                if not include_blocked and not info.callable:
                    continue
                hay = f"{info.name} {info.description}".casefold()
                if all(t in hay for t in terms):
                    out.append(info.to_dict())
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
    ) -> dict[str, Any]:
        """Run one normalised operation with routing/failover and record evidence."""
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
                evidence = await anyio.to_thread.run_sync(self.record_result, result, target)
            return {"result": result, "evidence": evidence, "attempts": attempts}
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

    def record_result(self, result: OperationResult, target: TargetContext) -> dict[str, Any]:
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
        )

    async def call_provider_tool(
        self, provider_id: str, tool_name: str, arguments: dict[str, Any], target_sha256: str | None = None
    ) -> Any:
        provider = self.providers.get(provider_id)
        if provider is None or not provider.started:
            reason = self.skipped.get(provider_id) or self.provider_errors.get(provider_id, "not configured")
            raise ProviderUnavailable(f"Provider {provider_id!r} is unavailable: {reason}")
        if getattr(provider, "per_target", False):
            if not target_sha256:
                raise ArgumentError(f"{provider_id} runs one server per target; pass target (sha256)")
            target = self.target_context(target_sha256)
            await provider._client_for(target)  # type: ignore[attr-defined]
        async with self._provider_sems.setdefault(provider_id, asyncio.Semaphore(1)):
            return await provider.call_tool(tool_name, arguments, internal=False, target_sha256=target_sha256)

    # 0.1 compatibility: ``manager.call(provider, tool, args)``
    async def call(self, provider_id: str, tool_name: str, arguments: dict[str, Any]) -> Any:
        return await self.call_provider_tool(provider_id, tool_name, arguments)

    def with_config(self, **changes: Any) -> NexusConfig:
        return replace(self.config, **changes)
