"""Execution policy: tool classification and enforcement.

Every provider tool is classified before it is advertised and again before it is
called. Classification sources, strongest first:

1. ``tool_overrides`` in the provider config (explicit operator decision);
2. the adapter manifest, written against a pinned upstream revision;
3. MCP tool annotations, when the adapter/provider trusts them;
4. a verb heuristic (``security.heuristic_tool_class``).

Deny patterns (global and per-provider) always win. Unknown tools are blocked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import NexusConfig, ProviderConfig
from .errors import PolicyViolation
from .security import DEFAULT_BLOCKED_TOOL_PATTERNS, heuristic_tool_class, matches_patterns

TOOL_CLASS_DESCRIPTIONS = {
    "read": "observes analysis state without changing it",
    "lifecycle": "opens/closes/waits on an analysis session (gateway-internal by default)",
    "mutate": "changes an analysis database or artefact",
    "execute": "runs arbitrary code supplied in its arguments",
    "dynamic": "instruments, launches or controls a live process or device",
    "blocked": "never callable through Nexus",
    "unknown": "not classified; blocked until an operator classifies it with tool_overrides",
}

# Argument names that identify a device or an analysed app/process in dynamic tools.
_DEVICE_ARGS = ("device", "device_id", "deviceId", "serial")
_TARGET_ARGS = ("target", "package", "package_name", "bundle_id", "identifier", "app", "app_id")


@dataclass(frozen=True, slots=True)
class ToolClassification:
    tool_class: str
    source: str  # override | manifest | annotations | heuristic | pattern


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    tool_class: str
    source: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "tool_class": self.tool_class,
            "classification_source": self.source,
            "reason": self.reason,
        }


class PolicyEngine:
    def __init__(self, config: NexusConfig) -> None:
        self.config = config
        self.policy = config.policy

    # -- classification -------------------------------------------------
    def classify(
        self,
        provider: ProviderConfig,
        tool_name: str,
        *,
        annotations: dict[str, Any] | None = None,
        manifest: dict[str, str] | None = None,
        trust_annotations_default: bool = False,
    ) -> ToolClassification:
        patterns = (*self.policy.global_blocked_tool_patterns, *provider.blocked_tool_patterns)
        if patterns and matches_patterns(tool_name, patterns):
            return ToolClassification("blocked", "pattern")

        if tool_name in provider.tool_overrides:
            return ToolClassification(provider.tool_overrides[tool_name], "override")
        if manifest and tool_name in manifest:
            return ToolClassification(manifest[tool_name], "manifest")

        heuristic = heuristic_tool_class(tool_name)
        trust = provider.trust_annotations
        if trust is None:
            trust = trust_annotations_default
        if trust and annotations:
            if annotations.get("readOnlyHint") is True:
                # A read-only hint never overrides an execution/instrumentation-shaped name.
                if heuristic in {"execute", "dynamic"}:
                    return ToolClassification(heuristic, "heuristic")
                return ToolClassification("read", "annotations")
            if annotations.get("destructiveHint") is True or annotations.get("readOnlyHint") is False:
                if heuristic in {"execute", "dynamic"}:
                    return ToolClassification(heuristic, "heuristic")
                return ToolClassification("mutate", "annotations")

        if self.policy.read_only and heuristic == "read" and matches_patterns(tool_name, DEFAULT_BLOCKED_TOOL_PATTERNS):
            return ToolClassification("mutate", "pattern")
        return ToolClassification(heuristic, "heuristic")

    # -- decisions --------------------------------------------------------
    def decide(
        self,
        provider: ProviderConfig,
        tool_name: str,
        classification: ToolClassification,
        *,
        internal: bool = False,
        arguments: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        cls, src = classification.tool_class, classification.source

        def deny(reason: str) -> PolicyDecision:
            return PolicyDecision(False, cls, src, reason)

        def allow(reason: str) -> PolicyDecision:
            return PolicyDecision(True, cls, src, reason)

        if cls == "blocked":
            return deny("tool is on a deny-list or hard-blocked by the adapter")
        if provider.kind == "dynamic" or cls == "dynamic":
            return self._decide_dynamic(provider, tool_name, cls, src, arguments or {})
        if cls == "read":
            return allow("read-only observation")
        if cls == "lifecycle":
            if internal or self.policy.allow_lifecycle_passthrough:
                return allow("session lifecycle tool used by the gateway adapter")
            return deny(
                "session lifecycle tools are managed by the gateway; use nexus_* tools or set "
                "policy.allow_lifecycle_passthrough"
            )
        if cls == "mutate":
            if self.policy.read_only:
                return deny("read-only policy blocks tools that modify analysis state")
            return allow("read_only is disabled in policy")
        if cls == "execute":
            if (
                self.policy.allow_code_execution
                and provider.id in self.policy.code_execution_providers
                and not internal
            ):
                return allow("code execution explicitly enabled for this provider")
            return deny(
                "arbitrary code execution is disabled (policy.allow_code_execution with code_execution_providers)"
            )
        return deny("tool is unclassified; classify it explicitly with tool_overrides after reviewing it")

    def _decide_dynamic(
        self, provider: ProviderConfig, tool_name: str, cls: str, src: str, arguments: dict[str, Any]
    ) -> PolicyDecision:
        dyn = self.policy.dynamic
        if not dyn.enabled:
            return PolicyDecision(False, cls, src, "dynamic analysis is disabled (policy.dynamic_analysis.enabled)")
        if cls in {"execute", "mutate", "blocked", "unknown"}:
            return PolicyDecision(False, cls, src, f"{cls} tools stay blocked on dynamic providers")
        if cls != "read" and tool_name not in dyn.allowed_tools:
            return PolicyDecision(
                False,
                cls,
                src,
                "instrumentation tools must be listed in policy.dynamic_analysis.allowed_tools",
            )
        for key in _DEVICE_ARGS:
            value = arguments.get(key)
            if isinstance(value, str) and value and value not in dyn.authorized_devices:
                return PolicyDecision(False, cls, src, f"device {value!r} is not authorised")
        for key in _TARGET_ARGS:
            value = arguments.get(key)
            if isinstance(value, str) and value and value not in dyn.authorized_targets:
                return PolicyDecision(False, cls, src, f"target {value!r} is not authorised")
        if cls != "read" and not any(isinstance(arguments.get(k), str) and arguments.get(k) for k in _TARGET_ARGS):
            return PolicyDecision(False, cls, src, "instrumentation calls must name an authorised target explicitly")
        return PolicyDecision(True, cls, src, "authorised dynamic-analysis call")

    def enforce(self, decision: PolicyDecision, provider_id: str, tool_name: str) -> None:
        if not decision.allowed:
            raise PolicyViolation(
                f"Blocked {provider_id}/{tool_name}: {decision.reason}",
                details=decision.to_dict(),
            )
