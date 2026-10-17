"""One definition of what a caller can reach: tool access states, MCP exposure and counts.

Every surface (MCP ``tools/list`` and namespaced dispatch in ``server.py``, ``nexus_list_tools`` and
provider summaries in ``registry.py``, the CLI and the dashboard snapshot) asks this module instead of
re-deriving the rules, so their names and numbers agree.

Tool states (exactly one per discovered tool, first match wins):

* ``catalogue_mismatch``: the live upstream differs from the adapter's pin; nothing is used.
* ``unknown``: not classified; blocked until an operator classifies it.
* ``blocked_by_profile``: the access profile withholds it (a wider profile would allow it).
* ``blocked_by_policy``: its class, a deny-list, an explicit gate or the adapter forbids it.
* ``missing_prerequisite``: allowed, but a helper it needs is not configured for this provider.
* ``adapter_only``: allowed, reachable only through the adapter's ``nexus_*`` operations.
* ``callable``: a caller may invoke it with ``nexus_call_provider_tool``.
* ``exposed``: callable and also listed as its own MCP tool (``tool_mode: namespaced``).

Provider states: ``ready``, ``disabled_by_config``, ``blocked_by_policy`` (e.g. a dynamic
provider while dynamic analysis is off), ``unavailable`` (failed to start or lost),
``catalogue_mismatch`` and ``unknown`` (not started yet, or in background startup).
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

TOOL_STATES = (
    "exposed",
    "callable",
    "adapter_only",
    "missing_prerequisite",
    "blocked_by_profile",
    "blocked_by_policy",
    "catalogue_mismatch",
    "unknown",
)
AVAILABLE_STATES = frozenset({"exposed", "callable", "adapter_only"})
PROVIDER_STATES = ("ready", "disabled_by_config", "blocked_by_policy", "unavailable", "catalogue_mismatch", "unknown")
_MAX_NAME = 128


@dataclass(frozen=True, slots=True)
class ToolAccess:
    state: str
    reason: str
    policy_allowed: bool  # the policy decision (class, gates, deny-lists) allows it
    profile_allowed: bool  # the access profile does not withhold it
    available: bool  # usable now, directly or through a nexus_* operation
    callable: bool  # a caller may invoke the raw tool
    exposed: bool  # listed as its own MCP tool
    public_name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _base_name(provider_id: str, tool: str) -> str:
    safe_provider = re.sub(r"[^A-Za-z0-9_-]", "_", provider_id)
    safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", tool)
    return f"{safe_provider}__{safe_name}"[:_MAX_NAME]


def _disambiguated(provider_id: str, tool: str) -> str:
    digest = hashlib.sha256(f"{provider_id}\0{tool}".encode()).hexdigest()[:8]
    return f"{_base_name(provider_id, tool)[: _MAX_NAME - 9]}_{digest}"


def _is_exposable(provider: Any, info: Any, tool_mode: str) -> bool:
    adapter = getattr(provider, "adapter", None)
    return bool(
        tool_mode == "namespaced"
        and provider.started
        and provider.config.expose_tools
        and not (adapter is not None and adapter.adapter_only)
        and info.callable
        and getattr(adapter, "tool_gate", lambda *_: None)(provider, info.name) is None
    )


def public_names(providers: Any, tool_mode: str) -> dict[tuple[str, str], str]:
    """Unique MCP names for every exposable tool, keyed by (provider id, tool name).

    Names are ``<provider>__<tool>`` with unsafe characters replaced and at most 128 characters.
    When two tools would get the same name (``a.b``/``a_b``, or truncation), each gets a short
    stable hash suffix instead, so dispatch can never pick the wrong tool.
    """
    candidates = [
        (provider.id, info.name)
        for provider in providers
        for info in provider._tools.values()
        if _is_exposable(provider, info, tool_mode)
    ]
    counts = Counter(_base_name(pid, tool) for pid, tool in candidates)
    return {
        (pid, tool): _base_name(pid, tool) if counts[_base_name(pid, tool)] == 1 else _disambiguated(pid, tool)
        for pid, tool in candidates
    }


def exposure_map(manager: Any) -> dict[str, tuple[Any, Any]]:
    """Public MCP name -> (provider, ToolInfo) for exactly the tools ``tools/list`` advertises."""
    providers = {p.id: p for p in manager.providers.values()}
    out = {}
    for (pid, tool), name in public_names(providers.values(), manager.config.tool_mode).items():
        provider = providers[pid]
        out[name] = (provider, provider._tools[tool])
    return out


def tool_access(provider: Any, info: Any, names: dict[tuple[str, str], str]) -> ToolAccess:
    adapter = getattr(provider, "adapter", None)
    gate = adapter.tool_gate(provider, info.name) if adapter is not None else None
    decision = info.decision
    public = names.get((provider.id, info.name))
    gate_state = gate[0] if gate else ""
    # policy_allowed is the effective decision (profile and adapter gate included), as the dashboard's
    # "Allowed by policy" always meant; a missing prerequisite is allowed but not yet usable.
    # profile_allowed says only whether the profile is what withholds it (a wider one would help);
    # a tool the adapter withholds in every profile (unreviewed, drifted) is never profile-blocked.
    policy_allowed = decision.allowed and gate_state in {"", "missing_prerequisite"}
    unconditional = gate_state in {"catalogue_mismatch", "blocked_by_policy"}
    profile_allowed = unconditional or (decision.denied_by != "profile" and gate_state != "blocked_by_profile")
    if unconditional and gate:
        state, reason = gate
    elif not decision.allowed:
        if info.classification.tool_class == "unknown":
            state = "unknown"
        else:
            state = "blocked_by_profile" if decision.denied_by == "profile" else "blocked_by_policy"
        reason = decision.reason
    elif gate:
        state, reason = gate
    elif info.adapter_only:
        state, reason = "adapter_only", "adapter-only provider: used by nexus_* operations, not callable directly"
    elif public is not None:
        state, reason = "exposed", decision.reason
    else:
        state, reason = "callable", decision.reason
    return ToolAccess(
        state=state,
        reason=reason,
        policy_allowed=policy_allowed,
        profile_allowed=profile_allowed,
        available=state in AVAILABLE_STATES,
        callable=state in {"exposed", "callable"},
        exposed=state == "exposed",
        public_name=public or info.public_name,
    )


def provider_tool_access(manager: Any, provider: Any) -> dict[str, ToolAccess]:
    names = public_names(manager.providers.values(), manager.config.tool_mode)
    return {name: tool_access(provider, info, names) for name, info in provider._tools.items()}


def count_states(accesses: Any) -> dict[str, int]:
    rows = list(accesses)
    counts = {state: 0 for state in TOOL_STATES}
    counts.update(Counter(a.state for a in rows))
    counts["discovered"] = len(rows)
    counts["available"] = sum(1 for a in rows if a.available)
    counts["policy_allowed"] = sum(1 for a in rows if a.policy_allowed)
    counts["profile_allowed"] = sum(1 for a in rows if a.profile_allowed)
    return counts


def provider_state(manager: Any, provider_id: str) -> tuple[str, str]:
    cfg = manager.provider_configs.get(provider_id)
    if cfg is None:
        return "unknown", "not configured"
    if not cfg.enabled:
        return "disabled_by_config", "enabled: false"
    skipped = manager.skipped.get(provider_id)
    if skipped:
        return "blocked_by_policy", skipped
    provider = manager.providers.get(provider_id)
    error = manager.provider_errors.get(provider_id)
    if provider is None or not provider.started:
        if error:
            return "unavailable", error
        return "unknown", "not started yet" if not manager.startup_complete else "not started"
    adapter = getattr(provider, "adapter", None)
    if adapter is not None and provider._tools:
        gates = [adapter.tool_gate(provider, name) for name in provider._tools]
        mismatch = next((g for g in gates if g and g[0] == "catalogue_mismatch"), None)
        if mismatch:
            return "catalogue_mismatch", mismatch[1]
    return "ready", ""


def provider_access(manager: Any, provider_id: str) -> dict[str, Any]:
    state, reason = provider_state(manager, provider_id)
    provider = manager.providers.get(provider_id)
    accesses = provider_tool_access(manager, provider).values() if provider is not None and provider.started else []
    return {"state": state, "reason": reason, "tool_states": count_states(accesses)}


def profile_summary(config: Any) -> dict[str, Any]:
    policy = config.policy
    return {
        "access_profile": policy.access_profile,
        "profile_source": policy.profile_source,
        "read_only": policy.read_only,
        "code_execution": policy.allow_code_execution,
        "code_execution_providers": list(policy.code_execution_providers),
        "dynamic_analysis": policy.dynamic.enabled,
        "remote_ai": policy.allow_remote_ai,
        "remote_providers": policy.allow_remote_providers,
        "tool_mode": config.tool_mode,
    }
