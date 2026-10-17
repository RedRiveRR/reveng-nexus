"""Execution policy: tool classification and enforcement.

Every provider tool is classified before it is advertised and again before it is
called. Classification sources, strongest first:

1. ``tool_overrides`` in the provider config (explicit operator decision);
2. the adapter manifest, written against a pinned upstream revision;
3. MCP tool annotations, when the adapter/provider trusts them;
4. a verb heuristic (``security.heuristic_tool_class``).

Deny patterns (global and per-provider) always win. Unknown tools are blocked.

Sources 1-2 are *verified* (an operator or a reviewed pin decided); 3-4 are *derived* from what the
upstream says about itself. The access profile (``policy.access_profile``) decides how far derived
classifications are trusted:

* restricted: a caller may invoke only reads with a verified classification;
* balanced (default): derived reads are callable too (the 0.2 behaviour);
* full_access: read_only defaults to off.

In every profile a mutating tool needs a verified classification before it may run: an annotation
or a verb is never sufficient proof that a write is the one the operator meant to allow. Code
execution, dynamic analysis and lifecycle tools keep their own explicit gates; no profile opens them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .config import NexusConfig, ProviderConfig
from .errors import PolicyViolation
from .security import (
    DEFAULT_BLOCKED_TOOL_PATTERNS,
    PROTECTION_BYPASS_PATTERNS,
    heuristic_tool_class,
    matches_patterns,
)

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
# Classes an operator `tool_overrides` entry may tighten (to "blocked") but never relax.
# "lifecycle" tools take filesystem paths (open_idb path/idb_out, open_database file_path,
# load_apk apkPath) that the workspace guard never sees, so they cannot become "read" either.
_UNRELAXABLE = frozenset({"blocked", "execute", "dynamic", "lifecycle"})
# Classification sources an operator or a reviewed upstream pin stands behind.
VERIFIED_SOURCES = frozenset({"manifest", "override"})


@dataclass(frozen=True, slots=True)
class ToolClassification:
    tool_class: str
    source: str  # override | manifest | annotations | heuristic | pattern

    @property
    def verified(self) -> bool:
        return self.source in VERIFIED_SOURCES


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    tool_class: str
    source: str
    reason: str
    # Why a denial happened: "profile" (the access profile withholds it) or "policy" (class, gates,
    # deny-lists, arguments). Empty when allowed.
    denied_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = {
            "allowed": self.allowed,
            "tool_class": self.tool_class,
            "classification_source": self.source,
            "reason": self.reason,
        }
        if self.denied_by:
            out["denied_by"] = self.denied_by
        return out


def _declared_arguments(schema: dict[str, Any] | None) -> frozenset[str] | None:
    """Argument names a tool's input schema declares; None when the schema does not enumerate them."""
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties")
    if not isinstance(props, dict) or (not props and schema.get("additionalProperties") is not False):
        return None
    return frozenset(props)


def _undeclared(arguments: dict[str, Any] | None, declared: frozenset[str] | None) -> list[str]:
    if not arguments or declared is None:
        return []
    return sorted(k for k in arguments if k not in declared)[:8]


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
        unlisted_class: str | None = None,
    ) -> ToolClassification:
        patterns = (
            *PROTECTION_BYPASS_PATTERNS,
            *self.policy.global_blocked_tool_patterns,
            *provider.blocked_tool_patterns,
        )
        if matches_patterns(tool_name, patterns):
            return ToolClassification("blocked", "pattern")

        heuristic = heuristic_tool_class(tool_name)
        pinned = manifest.get(tool_name) if manifest else None
        if pinned is None and unlisted_class is not None:
            pinned = unlisted_class
        if tool_name in provider.tool_overrides:
            override = provider.tool_overrides[tool_name]
            # An override may tighten but never relax a hard block, a lifecycle tool or an
            # execution/instrumentation class, whether it comes from the pinned manifest or from the
            # tool's name (an unlisted "frobnicate_exec_shell" keeps its execute-shaped heuristic).
            protected = {c for c in (pinned, heuristic) if c in _UNRELAXABLE}
            if not protected or override == "blocked" or protected == {override}:
                return ToolClassification(override, "override")
        if pinned is not None:
            return ToolClassification(pinned, "manifest")

        trust = provider.trust_annotations
        if trust is None:
            trust = trust_annotations_default
        if trust and annotations:
            if annotations.get("readOnlyHint") is True:
                # A read-only hint is the upstream's own claim: it never overrides an execution,
                # instrumentation or mutation-shaped name (an unlisted "patch_bytes" or
                # "open_database" flagged readOnlyHint stays blocked under read-only policy).
                if heuristic in {"execute", "dynamic", "mutate"}:
                    return ToolClassification(heuristic, "heuristic")
                if matches_patterns(tool_name, DEFAULT_BLOCKED_TOOL_PATTERNS):
                    return ToolClassification("mutate", "pattern")
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
        input_schema: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        cls, src = classification.tool_class, classification.source
        declared = _declared_arguments(input_schema)
        profile = self.policy.access_profile

        def deny(reason: str, by: str = "policy") -> PolicyDecision:
            return PolicyDecision(False, cls, src, reason, by)

        def allow(reason: str) -> PolicyDecision:
            return PolicyDecision(True, cls, src, reason)

        if cls == "blocked":
            return deny("tool is on a deny-list or hard-blocked by the adapter")
        if provider.kind == "dynamic" or cls == "dynamic":
            decision = self._decide_dynamic(provider, tool_name, cls, src, arguments, declared, internal)
            # dynamic gates are explicit operator settings, never the profile
            return decision if decision.allowed else replace(decision, denied_by="policy")
        extra = _undeclared(arguments, declared)
        if extra and not internal and cls != "unknown":
            return deny(f"arguments not declared by the tool's input schema: {extra}")
        if cls == "read":
            if profile == "restricted" and not internal and not classification.verified:
                return deny(
                    f"access_profile restricted: only reads classified by a pinned adapter manifest or an "
                    f"operator tool_overrides entry are callable; this one was classified by {src}",
                    "profile",
                )
            return allow("read-only observation")
        if cls == "lifecycle":
            if internal:
                return allow("session lifecycle tool used by the gateway adapter")
            return deny(
                "session lifecycle tools are managed by the gateway and take filesystem paths outside the "
                "workspace guard; they are never forwarded for a caller (use nexus_inspect_target and nexus_* tools)"
            )
        if cls == "mutate":
            if self.policy.read_only:
                # "profile" only when full_access would actually allow it (a verified classification)
                by = "profile" if profile != "full_access" and classification.verified else "policy"
                return deny("read-only policy blocks tools that modify analysis state", by)
            if not classification.verified:
                # Broader access must not rest on an upstream's own claims (a destructiveHint, a verb).
                return deny(
                    f"mutating tool classified only by {src}; classify it with tool_overrides (or a pinned "
                    "manifest) after reviewing it before it may run"
                )
            return allow(f"read_only is disabled (access_profile {profile})")
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
        self,
        provider: ProviderConfig,
        tool_name: str,
        cls: str,
        src: str,
        arguments: dict[str, Any] | None,
        declared: frozenset[str] | None = None,
        internal: bool = False,
    ) -> PolicyDecision:
        # arguments=None: a catalogue (listing) decision; the per-call schema and device checks
        # below run only when a call's actual arguments are known.
        listing = arguments is None
        arguments = arguments or {}
        dyn = self.policy.dynamic
        if not dyn.enabled:
            return PolicyDecision(False, cls, src, "dynamic analysis is disabled (policy.dynamic_analysis.enabled)")
        if cls == "lifecycle" and internal:
            return PolicyDecision(True, cls, src, "gateway-internal cleanup on a dynamic provider")
        if cls == "lifecycle":
            return PolicyDecision(False, cls, src, "lifecycle tools are gateway-internal; never forwarded for a caller")
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
        if declared is None and not internal and not listing:
            # Without an enumerated schema the decoy and explicit-device checks cannot work: fail closed.
            return PolicyDecision(False, cls, src, "dynamic tools need an input schema that enumerates its arguments")
        extra = _undeclared(arguments, declared)
        if extra:
            # Upstream schemas silently drop unknown keys, so an undeclared argument could only
            # serve to satisfy a Nexus check (e.g. a decoy "target") without reaching the tool.
            return PolicyDecision(False, cls, src, f"arguments not declared by the tool's input schema: {extra}")
        for key in _TARGET_ARGS:
            value = arguments.get(key)
            if value is not None and not isinstance(value, str):
                # e.g. a numeric attach_process target is a pid (session.ts:81), not an authorised app id
                return PolicyDecision(False, cls, src, f"{key!r} must be an authorised app identifier string")
        device_keys = [k for k in _DEVICE_ARGS if declared and k in declared]
        if (
            not listing
            and device_keys
            and not any(isinstance(arguments.get(k), str) and arguments.get(k) for k in device_keys)
        ):
            # Without an explicit device, upstreams fall back to an environment default, the first
            # USB device or the local host (frida-mobile-mcp device/resolver.ts:42-61).
            return PolicyDecision(False, cls, src, "dynamic calls must name an authorised device explicitly")
        if cls != "read" and not any(isinstance(arguments.get(k), str) and arguments.get(k) for k in _TARGET_ARGS):
            return PolicyDecision(False, cls, src, "instrumentation calls must name an authorised target explicitly")
        return PolicyDecision(True, cls, src, "authorised dynamic-analysis call")

    def enforce(self, decision: PolicyDecision, provider_id: str, tool_name: str) -> None:
        if not decision.allowed:
            raise PolicyViolation(
                f"Blocked {provider_id}/{tool_name}: {decision.reason}",
                details=decision.to_dict(),
            )
