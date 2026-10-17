"""Provider interface shared by every analysis backend."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio

from ..errors import NexusError, ProviderCallError, ProviderTimeout, describe_exception
from ..policy import PolicyDecision, ToolClassification

if TYPE_CHECKING:
    from ..audit import AuditLog
    from ..config import NexusConfig, ProviderConfig
    from ..policy import PolicyEngine

# Stable operation vocabulary. Providers advertise the subset they implement.
OPERATIONS: dict[str, str] = {
    "binary.metadata": "format, architecture, entry point, image base, sections",
    "binary.functions": "function list with addresses (and sizes when known)",
    "binary.decompile": "decompiled pseudocode for one function",
    "binary.disassemble": "instruction listing for one function or address range",
    "binary.xrefs": "cross-references to/from an address or function",
    "binary.cfg": "basic blocks and control-flow edges for one function",
    "binary.strings": "printable strings with locations",
    "binary.imports": "imported symbols/libraries",
    "binary.exports": "exported symbols",
    "apk.manifest": "decoded AndroidManifest.xml",
    "apk.components": "activities, services, receivers, providers, permissions",
    "apk.classes": "class inventory",
    "apk.class_source": "decompiled Java source of one class",
    "apk.search": "class/method search",
    "dynamic.status": "dynamic-analysis environment status (read-only)",
    "js.application": "static JavaScript/Electron application analysis of an ASAR archive (parsed as inert text)",
    "electron.fuses": "Electron fuse configuration read from an executable's bytes",
    "artifact.inspect": "one named static analysis of an artifact's bytes (Go/Rust metadata, PE resources, .NET, "
    "SQLite, WASM); the target is never run",
    "ai.decompile": "model-generated source reconstruction (always unverified)",
}


@dataclass(slots=True)
class TargetContext:
    """What a provider needs to know about the artifact it is asked to analyse."""

    sha256: str
    display_name: str
    original_path: Path
    kind: str
    format: str
    metadata: dict[str, Any]
    work_dir: Path
    case_id: str = "default"

    def staged_path(self, provider_id: str) -> Path:
        from ..artifacts import stage_copy

        return stage_copy(self.work_dir, self.sha256, provider_id, self.original_path, self.display_name)

    def provider_dir(self, provider_id: str) -> Path:
        path = self.work_dir / self.sha256[:16] / provider_id
        path.mkdir(parents=True, exist_ok=True)
        return path


@dataclass(slots=True)
class ToolInfo:
    provider_id: str
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    classification: ToolClassification
    decision: PolicyDecision
    adapter_only: bool = False  # usable by the adapter's nexus_* operations, never by callers

    @property
    def callable(self) -> bool:
        """Whether a caller may invoke this raw tool (nexus_call_provider_tool / namespaced tools)."""
        return self.decision.allowed and not self.adapter_only

    @property
    def public_name(self) -> str:
        import re

        safe_provider = re.sub(r"[^A-Za-z0-9_-]", "_", self.provider_id)
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", self.name)
        return f"{safe_provider}__{safe_name}"[:128]

    def to_dict(self, *, include_schema: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "provider_id": self.provider_id,
            "tool_name": self.name,
            "public_name": self.public_name,
            "description": self.description[:1200],
            "tool_class": self.classification.tool_class,
            "classification_source": self.classification.source,
            "callable": self.callable,
            "policy_reason": (
                "adapter-only provider: used by nexus_* operations, not callable directly"
                if self.adapter_only and self.decision.allowed
                else self.decision.reason
            ),
        }
        if self.annotations:
            out["annotations"] = self.annotations
        if include_schema:
            out["input_schema"] = self.input_schema
        return out


@dataclass(slots=True)
class ProviderHealth:
    status: str  # ready | degraded | unavailable | disabled | stopped | policy_disabled
    detail: str = ""
    version: str | None = None
    checked_at: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = {"status": self.status, "detail": self.detail, "checked_at": round(self.checked_at, 3)}
        if self.version:
            out["version"] = self.version
        out.update(self.extra)
        return out


@dataclass(slots=True)
class OperationResult:
    """Normalised output plus everything needed to reproduce and attribute it."""

    provider_id: str
    operation: str
    tool_name: str
    engine: str
    engine_family: str
    evidence_kind: str  # direct_observation | engine_derived | ai_generated
    normalized: dict[str, Any]
    raw: Any = None
    subject_type: str = "binary"
    subject_address: int | None = None
    subject_name: str | None = None
    engine_version: str | None = None
    warnings: list[str] = field(default_factory=list)
    model: dict[str, Any] | None = None
    claim: str = ""
    duration_ms: int = 0

    def subject_label(self) -> str:
        if self.subject_address is not None and self.subject_name:
            return f"{self.subject_name}@{self.subject_address:#x}"
        if self.subject_address is not None:
            return f"{self.subject_address:#x}"
        return self.subject_name or self.subject_type


class ProviderRuntime:
    """Services the manager hands to providers (policy, audit, config)."""

    def __init__(self, config: NexusConfig, policy: PolicyEngine, audit: AuditLog, log_dir: Path):
        self.config = config
        self.policy = policy
        self.audit = audit
        self.log_dir = log_dir


class AnalysisProvider(ABC):
    """Lifecycle: initialize → health_check/list_tools/perform … → shutdown."""

    engine: str = ""
    engine_family: str = ""

    def __init__(self, config: ProviderConfig, runtime: ProviderRuntime) -> None:
        self.config = config
        self.runtime = runtime
        self.id = config.id
        if config.engine:
            self.engine = config.engine
        if not self.engine_family:
            self.engine_family = self.engine or config.id
        self.started = False
        self.last_error: dict[str, Any] | None = None
        self._tools: dict[str, ToolInfo] = {}
        self.stats = {"calls": 0, "errors": 0, "timeouts": 0, "total_ms": 0}

    @property
    def kind(self) -> str:
        return self.config.kind

    # -- lifecycle ---------------------------------------------------------
    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def health_check(self) -> ProviderHealth: ...

    async def shutdown(self) -> None:
        self.started = False

    async def release_target(self, sha256: str) -> None:  # noqa: B027 - optional hook
        """Drop per-target sessions (launched servers, open databases)."""

    # -- capabilities --------------------------------------------------------
    @abstractmethod
    def list_capabilities(self) -> dict[str, dict[str, Any]]:
        """Map operation -> {"available": bool, "reason": str, ...}."""

    async def list_tools(self) -> list[ToolInfo]:
        return list(self._tools.values())

    @abstractmethod
    async def perform(self, operation: str, target: TargetContext, params: dict[str, Any]) -> OperationResult: ...

    # -- raw tool calls (policy + timeout + audit) --------------------------
    async def _raw_call(
        self, name: str, arguments: dict[str, Any], timeout: float, *, target_sha256: str | None = None
    ) -> Any:
        raise ProviderCallError(f"provider {self.id!r} has no raw tool interface")

    def tool_info(self, name: str) -> ToolInfo | None:
        return self._tools.get(name)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        internal: bool = False,
        timeout: float | None = None,
        target_sha256: str | None = None,
        case_id: str | None = None,
    ) -> Any:
        info = self._tools.get(name)
        if info is None:
            raise ProviderCallError(
                f"tool {self.id}/{name} is not in the provider's current catalogue",
                remediation="Use nexus_list_tools to see the tools this provider exposes.",
            )
        # Re-decide with the actual arguments (dynamic tools check device/target allowlists).
        adapter = getattr(self, "adapter", None)
        gate = adapter.tool_gate(self, name) if adapter is not None else None
        if not internal and adapter is not None and adapter.adapter_only:
            from ..policy import PolicyDecision

            decision = PolicyDecision(
                False,
                info.classification.tool_class,
                info.classification.source,
                f"{adapter.name} is reachable only through nexus_* operations (adapter-only provider)",
                "policy",
            )
        elif gate is not None:
            from ..policy import PolicyDecision

            decision = PolicyDecision(
                False,
                info.classification.tool_class,
                info.classification.source,
                gate[1],
                "profile" if gate[0] == "blocked_by_profile" else "policy",
            )
        else:
            decision = self.runtime.policy.decide(
                self.config,
                name,
                info.classification,
                internal=internal,
                arguments=arguments,
                input_schema=info.input_schema,
            )
        audit = self.runtime.audit
        if not decision.allowed:
            audit.write(
                "tool_call_blocked",
                provider_id=self.id,
                tool_name=name,
                outcome="blocked",
                tool_class=decision.tool_class,
                policy_reason=decision.reason,
                argument_keys=list(arguments),
                target_sha256=target_sha256,
                case_id=case_id,
            )
            self.runtime.policy.enforce(decision, self.id, name)
        budget = float(timeout or self.config.timeout_seconds)
        started = time.monotonic()
        outcome, error_code, error = "ok", None, None
        try:
            with anyio.fail_after(budget):
                result = await self._raw_call(name, arguments, budget, target_sha256=target_sha256)
            if getattr(result, "is_error", False):
                outcome = "provider_error"
            return result
        except TimeoutError as exc:
            outcome, error_code = "timeout", "provider_timeout"
            self.stats["timeouts"] += 1
            raise ProviderTimeout(
                f"{self.id}/{name} did not answer within {budget:.0f}s",
                remediation="Raise timeout_seconds for this provider or analyse a smaller target.",
            ) from exc
        except NexusError as exc:
            outcome, error_code, error = "exception", exc.code, exc.message
            raise
        except Exception as exc:
            outcome, error_code = "exception", "provider_error"
            error = describe_exception(exc)["message"]
            raise ProviderCallError(f"{self.id}/{name} failed: {error}") from exc
        finally:
            elapsed = round((time.monotonic() - started) * 1000)
            self.stats["calls"] += 1
            self.stats["total_ms"] += elapsed
            if outcome != "ok":
                self.stats["errors"] += 1
            audit.write(
                "tool_call",
                provider_id=self.id,
                tool_name=name,
                outcome=outcome,
                duration_ms=elapsed,
                argument_keys=list(arguments),
                tool_class=decision.tool_class,
                target_sha256=target_sha256,
                case_id=case_id,
                error_code=error_code,
                error=error,
            )

    # -- reporting ------------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        from ..access import public_names, tool_access

        cfg = self.config
        names = public_names([self], self.runtime.config.tool_mode)
        access = [tool_access(self, info, names) for info in self._tools.values()]
        return {
            "id": cfg.id,
            "name": cfg.name,
            "type": cfg.type,
            "adapter": cfg.adapter,
            "engine": self.engine,
            "engine_family": self.engine_family,
            "kind": cfg.kind,
            "enabled_in_config": cfg.enabled,
            "connected": self.started,
            "priority": cfg.priority,
            "conflict_group": cfg.conflict_group,
            "max_concurrency": cfg.max_concurrency,
            "timeout_seconds": cfg.timeout_seconds,
            # Three different counts (docs/DASHBOARD.md "Metric definitions"): tools the upstream
            # listed, tools the policy allows at all (adapter-internal use included), and raw tools a
            # caller may invoke directly. An adapter-only provider (REA) has allowed > callable == 0.
            # Computed by access.py, the same function the snapshot, CLI and tools/list use.
            "tool_count": len(self._tools),
            "policy_allowed_tool_count": sum(1 for a in access if a.policy_allowed),
            "callable_tool_count": sum(1 for a in access if a.callable),
            "adapter_only": bool(getattr(getattr(self, "adapter", None), "adapter_only", False)),
            "stats": dict(self.stats),
            "last_error": self.last_error,
        }
