"""Documented verification state per provider, as recorded in docs/PROVIDER_MATRIX.md.

This is a *record*, not a measurement: it says which state a provider reached on the
integration machine and when, so the dashboard can show it next to live health without
inferring "verified" from "enabled" or "ready". ``tests/test_dashboard.py`` checks every
entry against the matrix, so the two cannot drift apart silently.
"""

from __future__ import annotations

from typing import Any

SOURCE = "docs/PROVIDER_MATRIX.md"

# State names and meanings: docs/PROVIDER_MATRIX.md "Verification states".
STATES = {
    "live_analysis_verified": "a real read-only analysis ran through Nexus against the real engine on a generated fixture",
    "connection_verified": "the real upstream answered tools/list through Nexus; no analysis result verified",
    "mock_tested": "the call path is tested against a local mock of the upstream contract; the real upstream never ran",
    "unit_tested": "only classification or config handling is unit-tested",
    "reviewed_not_tested": "written from the pinned upstream source; no test exercises it",
    "blocked": "live use is impossible here (missing licence, software, device or model)",
    "not_integrated": "no integration exists",
}

DOCUMENTED: dict[str, dict[str, Any]] = {
    "builtin": {
        "state": "live_analysis_verified",
        "scope": "generated ELF/PE/Mach-O/APK fixtures, for the operations the built-in tests assert",
        "last_recorded": "2026-10-16",
        "blocker": None,
    },
    "ghidra_remcp": {
        "state": "live_analysis_verified",
        "scope": "metadata, functions, decompile, disassemble, xrefs, cfg, strings, imports, exports on one generated ELF",
        "last_recorded": "2026-10-16",
        "blocker": None,
    },
    "ghidra_mcpy": {
        "state": "live_analysis_verified",
        "scope": "metadata, functions, decompile, disassemble, xrefs, cfg, strings, imports, exports on one generated ELF",
        "last_recorded": "2026-10-16",
        "blocker": None,
    },
    "rea": {
        "state": "live_analysis_verified",
        "scope": "live: js.application and electron.fuses; artifact.inspect (8 analyses) mock_tested only, "
        "reviewed at the pin; session, device, debugger and code-running tools unreachable",
        "last_recorded": "2026-10-16",
        "blocker": None,
    },
    "re_mcp_ida": {
        "state": "mock_tested",
        "scope": "shared call path; IDA response shapes unit-tested against the pinned source",
        "last_recorded": "2026-10-15",
        "blocker": "licensed IDA 9+",
    },
    "ida_official": {
        "state": "unit_tested",
        "scope": "manifest / code-execution gate",
        "last_recorded": "2026-10-15",
        "blocker": "licensed IDA 9.4+ with idalib",
    },
    "ida_rs": {
        "state": "mock_tested",
        "scope": "mock fixtures built from the pinned upstream source",
        "last_recorded": "2026-10-15",
        "blocker": "licensed IDA Pro 9.4",
    },
    "binary_ninja": {
        "state": "mock_tested",
        "scope": "mock fixtures built from the pinned upstream source",
        "last_recorded": "2026-10-15",
        "blocker": "Binary Ninja licence, GUI and plugin",
    },
    "jadx": {
        "state": "mock_tested",
        "scope": "mock fixtures built from the pinned upstream source",
        "last_recorded": "2026-10-15",
        "blocker": "Maven build of the jadx-mcp daemon",
    },
    "frida_mobile": {
        "state": "mock_tested",
        "scope": "mock built from the pinned source; never run against real Frida or a device",
        "last_recorded": "2026-10-15",
        "blocker": "no authorised test device; dynamic analysis disabled by design",
    },
    "llm4decompile": {
        "state": "mock_tested",
        "scope": "local mock HTTP endpoint",
        "last_recorded": "2026-10-15",
        "blocker": "no served checkpoint",
    },
}


def documented_state(provider_id: str) -> dict[str, Any]:
    """The documented record for ``provider_id``; ``unrecorded`` when the matrix has no row."""
    entry = DOCUMENTED.get(provider_id)
    if entry is None:
        return {"state": "unrecorded", "meaning": "no row in the provider matrix", "source": SOURCE}
    return {**entry, "meaning": STATES[entry["state"]], "source": SOURCE}
