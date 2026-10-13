"""Evidence-oriented analysis workflow suggestions."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

WORKFLOWS: dict[str, list[dict[str, str]]] = {
    "native_binary": [
        {"step": "identify", "goal": "Record architecture, format, entry point, imports, and hashes."},
        {"step": "map", "goal": "Enumerate functions, strings, imports, callers/callees, and control flow."},
        {
            "step": "prioritize",
            "goal": "Prioritize externally reachable, crypto, parsing, auth, and memory-handling functions.",
        },
        {
            "step": "decompile",
            "goal": "Decompile high-priority functions and retain the original disassembly as evidence.",
        },
        {"step": "cross_check", "goal": "Compare material findings across a second engine when available."},
        {"step": "report", "goal": "Separate confirmed observations, hypotheses, and unknowns in the report."},
    ],
    "android_apk": [
        {
            "step": "manifest",
            "goal": "Inspect package, permissions, exported components, deep links, and SDK settings.",
        },
        {"step": "inventory", "goal": "Map classes, entry activities, services, receivers, and application resources."},
        {
            "step": "search",
            "goal": "Search for network endpoints, crypto use, storage, WebView, and authentication flows.",
        },
        {"step": "trace", "goal": "Follow callers/callees around high-risk methods and record source locations."},
        {
            "step": "runtime",
            "goal": "If authorized, validate selected hypotheses on a disposable test device with Frida.",
        },
        {"step": "report", "goal": "Correlate static and runtime evidence and identify limitations."},
    ],
    "ios_app": [
        {"step": "inventory", "goal": "Identify bundle metadata, binary format, frameworks, and available symbols."},
        {
            "step": "static",
            "goal": "Inspect strings, imports, class/method metadata, and control flow using a compatible engine.",
        },
        {"step": "runtime", "goal": "If authorized, inspect behavior in a controlled test device using Frida."},
        {"step": "report", "goal": "Correlate observations and label unverified hypotheses."},
    ],
    "mobile_runtime": [
        {"step": "scope", "goal": "Confirm the authorized app, device, process, and test environment."},
        {
            "step": "observe",
            "goal": "Begin with read-only process, API, network, filesystem, and preference observation.",
        },
        {
            "step": "validate",
            "goal": "Validate static-analysis hypotheses without writing memory or altering app protections.",
        },
        {"step": "report", "goal": "Record device/app versions, steps, timestamps, and reproducible evidence."},
    ],
    "unknown": [
        {
            "step": "identify",
            "goal": "Determine file type, architecture, platform, and whether static or runtime analysis is appropriate.",
        },
        {"step": "triage", "goal": "Use read-only metadata, strings, imports, and entry-point discovery first."},
        {"step": "report", "goal": "State which providers are unavailable and what evidence is still missing."},
    ],
}


def build_analysis_plan(
    target_kind: str,
    providers: Iterable[dict[str, Any]],
    tools: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build a tool-aware plan without executing any target or provider tool."""
    kind = target_kind if target_kind in WORKFLOWS else "unknown"
    provider_rows = list(providers)
    tool_rows = list(tools)

    # Both the 0.1 free-form capability tags and the 0.2 operation names are accepted.
    if kind == "android_apk":
        relevant_caps = {
            "android",
            "apk",
            "mobile_static",
            "jadx",
            "apk.manifest",
            "apk.components",
            "apk.class_source",
        }
    elif kind == "ios_app":
        relevant_caps = {"native", "mobile_dynamic", "frida", "apple", "binary.metadata", "dynamic.status"}
    elif kind == "mobile_runtime":
        relevant_caps = {"mobile_dynamic", "frida", "runtime", "dynamic.status"}
    else:
        relevant_caps = {
            "native",
            "static",
            "binary",
            "decompile",
            "xrefs",
            "binary.decompile",
            "binary.functions",
            "binary.xrefs",
            "binary.disassemble",
        }

    matching = [
        p
        for p in provider_rows
        if p.get("enabled") and (not p.get("capabilities") or relevant_caps.intersection(p["capabilities"]))
    ]
    tool_names = [t.get("name", "") for t in tool_rows]
    return {
        "target_kind": kind,
        "mode": "read-only-first",
        "available_provider_ids": [p["id"] for p in matching],
        "available_tool_count": len(tool_rows),
        "suggested_steps": WORKFLOWS[kind],
        "tool_hints": [
            name
            for name in tool_names
            if any(
                word in name.lower()
                for word in (
                    "function",
                    "decomp",
                    "manifest",
                    "class",
                    "xref",
                    "cross_ref",
                    "import",
                    "string",
                    "method",
                )
            )
        ][:30],
        "limitations": [
            "This is a plan, not a claim that the analysis has been performed.",
            "Every AI hypothesis must be tied to provider evidence and independently checked where feasible.",
        ],
    }
