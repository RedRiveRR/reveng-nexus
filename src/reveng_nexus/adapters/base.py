"""Adapter base: binds stable Nexus operations to one upstream MCP server's real tools.

An adapter records, for a pinned upstream revision, which tools exist, how they are
classified, which arguments they take and how to normalise their output. At runtime
``capabilities()`` re-checks the live ``tools/list`` so upstream drift shows up as an
explicit "tool missing" reason instead of a confusing call failure.
"""

from __future__ import annotations

import contextvars
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..errors import CapabilityUnavailable, ProviderCallError

if TYPE_CHECKING:
    from ..providers.base import OperationResult, TargetContext
    from ..providers.mcp import McpProvider


@dataclass(frozen=True)
class UpstreamPin:
    repository: str
    revision: str
    package: str | None
    package_version: str | None
    verified: str  # "runtime" | "source" | "snapshot"
    verified_on: str
    notes: str = ""


# Warnings raised *inside* one operation (a partial upstream answer, an unexpected page shape).
# Task-local, so concurrent operations on one provider never see each other's notes.
_PENDING_WARNINGS: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar(
    "nexus_adapter_pending_warnings", default=None
)


def note_warning(message: str) -> None:
    """Attach ``message`` to the result of the operation running in this task."""
    pending = _PENDING_WARNINGS.get()
    if pending is not None:
        pending.append(message)


_HEX = re.compile(r"^(?:0x)?([0-9a-fA-F]+)h?$")


def parse_address(value: Any) -> int | None:
    """Parse engine address strings ('0x400100', '400100', '00400100h', ints)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if ":" in text:  # Ghidra overlay/space-qualified addresses, e.g. "ram:00400100"
        text = text.rsplit(":", 1)[-1]
    match = _HEX.fullmatch(text)
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


def fmt_address(value: int) -> str:
    return f"{value:#x}"


@dataclass
class McpAdapter:
    name: str
    engine: str
    engine_family: str | None  # None: take the provider's configured engine
    pin: UpstreamPin
    manifest: dict[str, str] = field(default_factory=dict)
    bindings: dict[str, tuple[str, ...]] = field(default_factory=dict)
    trust_annotations: bool = False
    protocol_mode: str = "legacy"
    limitations: tuple[str, ...] = ()
    # Class of a tool missing from the pinned manifest. None: fall back to the verb heuristic.
    # "unknown" (blocked until an operator classifies it) or "blocked" (never forwarded, not even
    # through tool_overrides) for upstreams whose catalogue was reviewed tool by tool.
    unlisted_tool_class: str | None = None
    # True: the upstream is reachable only through this adapter's normalised operations; raw
    # passthrough (nexus_call_provider_tool, namespaced tools) is refused. For upstreams whose
    # tools take arbitrary filesystem paths that Nexus cannot confine.
    adapter_only: bool = False
    # Set when the upstream is inherently of one kind (Frida: "dynamic"); the provider config
    # must then declare the same kind, so gating can never be skipped by omitting it.
    provider_kind: str | None = None

    # -- tool gating -------------------------------------------------------------
    def tool_gate(self, provider: McpProvider, tool: str) -> tuple[str, str] | None:
        """Why this adapter withholds ``tool`` beyond its policy class, as (access state, reason).

        States are ``access.TOOL_STATES`` (catalogue_mismatch, blocked_by_profile,
        blocked_by_policy, missing_prerequisite). None: nothing beyond policy. The gate applies to
        listings, capability status and every call, the adapter's own (internal) calls included.
        """
        return None

    # -- capability checks ---------------------------------------------------
    def capabilities(self, provider: McpProvider) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for operation, required in self.bindings.items():
            out[operation] = self._binding_status(provider, required)
        return out

    def _binding_status(self, provider: McpProvider, required: tuple[str, ...]) -> dict[str, Any]:
        if not provider.started:
            return {"available": False, "reason": "provider not connected", "tools": list(required)}
        if not provider._tools and provider.per_target:
            # Per-target servers expose tools only after a target is opened; trust the pin.
            return {"available": True, "tools": list(required), "note": "verified on first target"}
        for tool in required:
            info = provider.tool_info(tool)
            if info is None:
                return {
                    "available": False,
                    "reason": (
                        f"tool {tool!r} is not in the server's current tool list: the upstream version differs "
                        f"from the pin ({self.pin.revision[:12]}) or its engine backend failed to start "
                        f"(see {provider.log_path})"
                    ),
                    "tools": list(required),
                }
            decision = info.decision
            if not decision.allowed and decision.denied_by == "profile":
                # The catalogue decision is the caller-facing one. A profile that withholds a raw
                # read from callers (restricted) still lets the adapter use it inside its operations.
                decision = provider.runtime.policy.decide(
                    provider.config, tool, info.classification, internal=True, input_schema=info.input_schema
                )
            if not decision.allowed and info.classification.tool_class != "lifecycle":
                return {
                    "available": False,
                    "reason": f"{tool!r} blocked: {decision.reason}",
                    "tools": list(required),
                }
            gate = self.tool_gate(provider, tool)
            if gate is not None:
                return {"available": False, "reason": f"{tool!r}: {gate[1]}", "state": gate[0], "tools": list(required)}
        return {"available": True, "tools": list(required)}

    def require(self, provider: McpProvider, operation: str) -> None:
        status = self._binding_status(provider, self.bindings.get(operation, ()))
        if operation not in self.bindings:
            raise CapabilityUnavailable(f"{provider.id} ({self.name}) does not implement {operation}")
        if not status["available"]:
            raise CapabilityUnavailable(f"{provider.id}: {operation} unavailable: {status['reason']}")

    # -- hooks -----------------------------------------------------------------
    async def prepare(self, provider: McpProvider, target: TargetContext) -> dict[str, Any]:
        return {}

    async def release(self, provider: McpProvider, sha256: str) -> None:
        provider.adapter_state.setdefault("sessions", {}).pop(sha256, None)

    async def shutdown(self, provider: McpProvider) -> None:
        for sha in list(provider.adapter_state.get("sessions", {})):
            await self.release(provider, sha)

    async def perform(
        self, provider: McpProvider, operation: str, target: TargetContext, params: dict[str, Any]
    ) -> OperationResult:
        self.require(provider, operation)
        handler = getattr(self, "op_" + operation.replace(".", "_"), None)
        if handler is None:
            raise CapabilityUnavailable(f"{self.name} adapter has no handler for {operation}")
        token = _PENDING_WARNINGS.set([])
        try:
            session = await self.prepare(provider, target)
            result = await handler(provider, target, session, params)
            pending = _PENDING_WARNINGS.get() or []
            result.warnings.extend(w for w in pending if w not in result.warnings)
            return result
        finally:
            _PENDING_WARNINGS.reset(token)

    # -- helpers -----------------------------------------------------------------
    async def call(
        self, provider: McpProvider, target: TargetContext, tool: str, arguments: dict[str, Any], **kw: Any
    ) -> tuple[Any, str, Any]:
        """Call a tool and return (parsed payload, text, raw result). Raises on tool errors."""
        from ..providers.mcp import result_to_jsonable, unwrap_result

        result = await provider.call_for_target(target, tool, arguments, **kw)
        payload, text = unwrap_result(result)
        if getattr(result, "is_error", False):
            message = text or str(payload)
            raise ProviderCallError(
                f"{provider.id}/{tool} reported an error: {message[:600]}",
                details={"tool": tool, "provider_error": (payload if isinstance(payload, dict) else None)},
            )
        if isinstance(payload, dict) and payload.get("error"):
            if not payload.get("items"):
                raise ProviderCallError(f"{provider.id}/{tool} reported an error: {str(payload['error'])[:600]}")
            # Error *and* items: a partial answer. Keep the items, never as a clean success.
            note_warning(f"{tool}: partial result; upstream also reported an error: {str(payload['error'])[:300]}")
        return payload, text, result_to_jsonable(result)

    def result(
        self,
        provider: McpProvider,
        operation: str,
        tool: str,
        normalized: dict[str, Any],
        raw: Any,
        **kw: Any,
    ) -> OperationResult:
        from ..providers.base import OperationResult

        return OperationResult(
            provider_id=provider.id,
            operation=operation,
            tool_name=tool,
            engine=provider.engine,
            engine_family=provider.engine_family,
            evidence_kind=kw.pop("evidence_kind", "engine_derived"),
            normalized=normalized,
            raw=raw,
            **kw,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "engine": self.engine,
            "upstream": self.pin.repository,
            "pinned_revision": self.pin.revision,
            "package": self.pin.package,
            "package_version": self.pin.package_version,
            "verification": self.pin.verified,
            "verified_on": self.pin.verified_on,
            "operations": sorted(self.bindings),
            "limitations": list(self.limitations),
        }


def function_ref(params: dict[str, Any]) -> tuple[int | None, str | None, str]:
    """Normalise an operation's function selector into (address, name, display string)."""
    address = params.get("address")
    name = params.get("name")
    if address is not None:
        address = int(address)
        return address, name, fmt_address(address)
    if name:
        return None, str(name), str(name)
    raise CapabilityUnavailable("a function address or name is required")


def parse_listing_lines(text: str) -> list[dict[str, Any]]:
    """Parse 'ADDR: BYTES  MNEMONIC OPS' style listings into instruction dicts."""
    out = []
    for line in text.splitlines():
        match = re.match(r"^\s*(?:0x)?([0-9a-fA-F]+)h?:?\s+((?:[0-9a-fA-F]{2}\s)+)?\s*(\S+)\s*(.*)$", line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        raw_bytes = (match.group(2) or "").replace(" ", "").lower()
        out.append(
            {
                "address": addr,
                "bytes": raw_bytes or None,
                "mnemonic": match.group(3).lower(),
                "op_str": match.group(4).strip(),
            }
        )
    return out
