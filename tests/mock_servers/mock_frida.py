"""Mock MCP server (SDK 2.x, stdio) for the frida_mobile adapter. Never imports or runs Frida.

Reproduces the tool list and response envelope of monkeywave/frida-mobile-mcp at
b2da55d6429438ed36e829e7478de42430cb4ef9 (npm frida-mobile-mcp@0.2.3), read from source as data:

* 32 tools registered in src/server.ts:61-81 (names, argument names, required-ness, annotations
  copied from each ``server.registerTool`` call; see docs/ADAPTER_CONTRACTS.md draft section).
* Success (src/helpers/result-builder.ts:27-53 ``formatToolResponse``): one text block rendered in
  ``response_format`` (default ``toon``; ``json`` = ``JSON.stringify(data, null, 2)``) **plus**
  ``structuredContent = {result, session_context, suggested_next}``; ``isError`` unset.
  Text above 25 000 chars is truncated (constants.ts:4) - structuredContent is not.
* Failure (``FridaMcpError.toErrorResponse``, helpers/errors.ts:21-30): one text block of
  ``{error: {code, message, recovery_actions, context}}`` rendered in ``response_format``,
  ``isError: true``, **no** structuredContent.
* In-band failure without isError: ``get_device_info`` with no device selected answers a normal
  success envelope whose ``result`` is ``{error: "No device selected. ..."}``
  (tools/advanced/device.ts:95-98); ``frida_help`` with an unknown topic answers ``result.message``
  (tools/help.ts:256-263).
* ``get_status`` swallows device-enumeration failures and reports ``devices: []``
  (tools/status.ts:32-36).
* The real server imports the native ``frida`` package at module load (device/manager.ts:1), so a
  missing/broken install kills the process before ``initialize``: reproduced by
  MOCK_FRIDA_MODE=missing_frida.

The TOON text is an approximation (the @toon-format/toon encoder is not reproduced); Nexus must not
depend on the text of a success answer. Device/process data are hardcoded and fictional.

Switches (environment):
  MOCK_FRIDA_MODE      ok (default) | no_device | missing_frida
  MOCK_EXTRA_TOOLS     comma list of extra tool names (simulates upstream drift)
  MOCK_SLOW_TOOL / MOCK_SLOW_SECONDS   sleep inside one tool
  MOCK_CRASH_TOOL      exit abruptly inside one tool
  MOCK_ERROR_TOOL      answer one tool with the upstream isError envelope (FRIDA_ERROR)
  MOCK_GARBAGE_TOOL    answer one tool with an unexpected envelope; MOCK_GARBAGE_KIND =
                       no_structured (JSON text only, list) | wrong_structured | toon_only | inband_error
  MOCK_CALL_LOG        append one JSON line per call: tool name + argument keys
  MOCK_PID_FILE        write this process's pid here (cleanup tests)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations

MODE = os.environ.get("MOCK_FRIDA_MODE", "ok")
CHARACTER_LIMIT = 25_000

_RESPONSE_FORMAT = {
    "type": "string",
    "enum": ["toon", "markdown", "json"],
    "default": "toon",
    "description": 'Output format: "toon" (default, ~40% fewer tokens — recommended), "markdown" for '
    'human-readable, "json" for raw structured data',
}

# (name, {arg: json-type}, required args, (readOnly, destructive, idempotent, openWorld), source)
_S, _B, _N, _O = {"type": "string"}, {"type": "boolean"}, {"type": "number"}, {"type": "object"}
UPSTREAM: list[tuple[str, dict[str, Any], tuple[str, ...], tuple[bool, bool, bool, bool], str]] = [
    ("get_status", {}, (), (True, False, True, True), "tools/status.ts:12"),
    ("frida_help", {"topic": _S}, (), (True, False, True, False), "tools/help.ts:235"),
    (
        "explore_app",
        {"target": _S, "device": _S, "class_filter": _S},
        ("target",),
        (False, False, False, True),
        "tools/explore.ts:15",
    ),
    (
        "hook_method",
        {"target": _S, "method": _S, "device": _S, "log_args": _B, "log_retval": _B, "log_backtrace": _B, "spawn": _B},
        ("target", "method"),
        (False, False, False, True),
        "tools/hook.ts:14",
    ),
    (
        "trace_method",
        {"target": _S, "method": _S, "device": _S, "duration_seconds": _N, "log_args": _B, "log_retval": _B},
        ("target", "method"),
        (False, False, False, True),
        "tools/trace.ts:14",
    ),
    (
        "execute_script",
        {"target": _S, "source": _S, "file_path": _S, "device": _S, "session_id": _S, "persistent": _B},
        ("target",),
        (False, True, False, True),
        "tools/script.ts:17",
    ),
    (
        "run_prebuilt_script",
        {"script_name": _S, "target": _S, "device": _S, "options": _O},
        (),
        (False, False, False, True),
        "tools/prebuilt.ts:16",
    ),
    (
        "search_classes_and_methods",
        {"target": _S, "pattern": _S, "device": _S, "include_methods": _B, "limit": _N},
        ("target", "pattern"),
        (True, False, True, True),
        "tools/search.ts:14",
    ),
    (
        "read_memory",
        {"session_id": _S, "address": _S, "size": _N},
        ("session_id", "address", "size"),
        (True, False, True, True),
        "tools/memory.ts:13",
    ),
    (
        "write_memory",
        {"session_id": _S, "address": _S, "data": _S},
        ("session_id", "address", "data"),
        (False, True, False, True),
        "tools/memory.ts:85",
    ),
    (
        "scan_memory",
        {"session_id": _S, "pattern": _S, "module": _S},
        ("session_id", "pattern"),
        (True, False, True, True),
        "tools/memory.ts:161",
    ),
    ("bypass_ssl_pinning", {"target": _S, "device": _S}, ("target",), (False, True, True, True), "tools/ssl.ts:16"),
    (
        "get_messages",
        {"session_id": _S, "script_id": _S, "since": _N, "limit": _N},
        ("session_id",),
        (True, False, True, False),
        "tools/messages.ts:10",
    ),
    (
        "stop_instrumentation",
        {"session_id": _S, "target": _S, "all": _B},
        (),
        (False, True, True, True),
        "tools/cleanup.ts:11",
    ),
    ("mobile_action", {"action": _S, "params": _O}, (), (False, False, False, True), "tools/mobile.ts:36"),
    (
        "detect_app_technologies",
        {"target": _S, "device": _S},
        ("target",),
        (True, False, True, True),
        "tools/detect.ts:55",
    ),
    ("list_devices", {}, (), (True, False, True, True), "tools/advanced/device.ts:11"),
    (
        "select_device",
        {"device_id": _S, "type": {"type": "string", "enum": ["usb", "local", "remote"]}, "host": _S},
        (),
        (False, False, True, True),
        "tools/advanced/device.ts:39",
    ),
    ("get_device_info", {"device_id": _S}, (), (True, False, True, True), "tools/advanced/device.ts:76"),
    ("list_processes", {"device_id": _S}, (), (True, False, True, True), "tools/advanced/process.ts:11"),
    ("list_applications", {"device_id": _S}, (), (True, False, True, True), "tools/advanced/process.ts:53"),
    ("get_frontmost_application", {"device_id": _S}, (), (True, False, True, True), "tools/advanced/process.ts:97"),
    (
        "spawn_process",
        {"program": _S, "device": _S},
        ("program",),
        (False, False, False, True),
        "tools/advanced/session.ts:14",
    ),
    (
        "attach_process",
        {"target": {"anyOf": [{"type": "string"}, {"type": "number"}]}, "device": _S},
        ("target",),
        (False, False, True, True),
        "tools/advanced/session.ts:76",
    ),
    (
        "resume_process",
        {"pid": _N, "device": _S},
        ("pid",),
        (False, False, True, True),
        "tools/advanced/session.ts:150",
    ),
    ("kill_process", {"pid": _N, "device": _S}, ("pid",), (False, True, True, True), "tools/advanced/session.ts:184"),
    (
        "detach_session",
        {"session_id": _S},
        ("session_id",),
        (False, False, True, True),
        "tools/advanced/session.ts:216",
    ),
    ("list_sessions", {}, (), (True, False, True, False), "tools/advanced/session.ts:247"),
    (
        "enumerate_modules",
        {"session_id": _S},
        ("session_id",),
        (True, False, True, True),
        "tools/advanced/modules.ts:10",
    ),
    (
        "enumerate_exports",
        {"session_id": _S, "module_name": _S},
        ("session_id", "module_name"),
        (True, False, True, True),
        "tools/advanced/modules.ts:52",
    ),
    (
        "hook_function",
        {"session_id": _S, "target": _S, "on_enter": _S, "on_leave": _S},
        ("session_id", "target"),
        (False, False, False, True),
        "tools/advanced/intercept.ts:10",
    ),
    ("unhook_function", {"hook_id": _S}, ("hook_id",), (False, False, True, True), "tools/advanced/intercept.ts:114"),
]
UPSTREAM_TOOL_NAMES = frozenset(t[0] for t in UPSTREAM)


def _tool(name: str, props: dict[str, Any], required: tuple[str, ...], hints: tuple[bool, bool, bool, bool]) -> Tool:
    ro, destructive, idempotent, open_world = hints
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {**props, "response_format": _RESPONSE_FORMAT},
        "additionalProperties": False,
        "$schema": "http://json-schema.org/draft-07/schema#",
    }
    if required:
        schema["required"] = list(required)
    return Tool(
        name=name,
        description=f"mock {name}",
        input_schema=schema,
        annotations=ToolAnnotations(
            read_only_hint=ro, destructive_hint=destructive, idempotent_hint=idempotent, open_world_hint=open_world
        ),
    )


TOOLS = [_tool(n, p, r, h) for n, p, r, h, _src in UPSTREAM]
for _extra in filter(None, os.environ.get("MOCK_EXTRA_TOOLS", "").split(",")):
    TOOLS.append(_tool(_extra.strip(), {}, (), (True, False, True, True)))

DEVICES = (
    []
    if MODE == "no_device"
    else [
        {"id": "local", "name": "Local System", "type": "local"},
        {"id": "emulator-5554", "name": "Nexus Disposable Emulator", "type": "usb"},
    ]
)
STATE: dict[str, Any] = {"selected": None, "sessions": {}}


# -- envelopes ------------------------------------------------------------------------------------
def _toon(value: Any, depth: int = 0) -> str:
    """Rough stand-in for @toon-format/toon: indented ``key: value`` lines (NOT JSON)."""
    pad = "  " * depth
    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:" if isinstance(v, dict) else f"{pad}{k}[{len(v)}]:")
                lines.append(_toon(v, depth + 1))
            else:
                lines.append(f"{pad}{k}: {json.dumps(v) if not isinstance(v, str) else v}")
        return "\n".join(lines)
    if isinstance(value, list):
        return "\n".join(f"{pad}- " + _toon(v, depth + 1).lstrip() for v in value)
    return f"{pad}{value}"


def _render(data: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(data, indent=2)
    return _toon(data)  # toon (default) and markdown are both non-JSON text


def _session_context() -> dict[str, Any]:
    sel = STATE["selected"]
    return {
        "device": f"{sel['name']} ({sel['type']}:{sel['id']})" if sel else None,
        "platform": None,
        "active_sessions": [{"id": s, "target": v["target"], "pid": v["pid"]} for s, v in STATE["sessions"].items()],
        "active_hooks": 0,
        "active_scripts": 0,
    }


def ok(result: dict[str, Any], suggested: list[dict[str, Any]] | None, fmt: str) -> CallToolResult:
    """formatToolResponse(buildResult(result, suggested), fmt) - result-builder.ts:11-21, 27-53."""
    envelope = {"result": result, "session_context": _session_context(), "suggested_next": suggested or []}
    text = _render(envelope, fmt)
    if len(text) > CHARACTER_LIMIT:
        text = text[:CHARACTER_LIMIT] + "\n\n_...response truncated. ..._"
    return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=envelope)


def err(
    code: str, message: str, recovery: list[dict[str, Any]], context: dict[str, Any] | None, fmt: str
) -> CallToolResult:
    """formatToolResponse(FridaMcpError.toErrorResponse(), fmt): isError, text only."""
    body = {"error": {"code": code, "message": message, "recovery_actions": recovery, "context": context or {}}}
    return CallToolResult(content=[TextContent(type="text", text=_render(body, fmt))], is_error=True)


def _device_not_found(fmt: str, requested: str | None = None) -> CallToolResult:
    # errors.ts:33-50 DeviceNotFoundError
    msg = f'Device "{requested}" not found or disconnected.' if requested else "No USB device detected."
    return err(
        "DEVICE_NOT_FOUND",
        msg,
        [
            {"tool": "get_status", "reason": "Check available devices"},
            {"action": "user_intervention", "message": "Connect a device and ensure frida-server is running on it"},
        ],
        {"requested_device": requested, "available_devices": [d["id"] for d in DEVICES]},
        fmt,
    )


def _disabled(code: str, message: str, fmt: str) -> CallToolResult:
    return err(code, message, [{"action": "user_intervention", "message": "see upstream config"}], None, fmt)


# -- handlers -------------------------------------------------------------------------------------
def handle(name: str, args: dict[str, Any]) -> CallToolResult:
    fmt = str(args.get("response_format") or "toon")
    if name == "get_status":
        return ok(
            {
                "devices": DEVICES,
                "current_device": STATE["selected"],
                "sessions": [],
                "hooks": [],
                "traces": [],
                "config": {
                    "custom_scripts_enabled": False,
                    "memory_write_enabled": False,
                    "mobile_mcp_enabled": False,
                    "max_sessions": 4,
                },
            },
            [{"tool": "explore_app", "reason": "Start exploring an app on a connected device"}]
            if DEVICES
            else [
                {"tool": "frida_help", "args": {"topic": "overview"}, "reason": "No devices found - get help on setup"}
            ],
            fmt,
        )
    if name == "frida_help":
        topic = args.get("topic") or "overview"
        if topic not in {"overview", "hooking"}:
            return ok({"message": f'Unknown topic "{topic}". Available topics: overview, hooking'}, [], fmt)
        return ok({"topic": topic, "content": "# frida-mobile-mcp (mock help)"}, [], fmt)
    if name == "list_devices":
        return ok({"devices": DEVICES}, [], fmt)
    if name == "list_sessions":
        return ok({"sessions": []}, [], fmt)
    if name == "get_device_info":
        device_id = args.get("device_id") or (STATE["selected"] or {}).get("id")
        if not device_id:  # device.ts:95-98: in-band error, NOT isError
            return ok(
                {"error": "No device selected. Use select_device or provide device_id."},
                [{"tool": "list_devices", "reason": "List available devices"}],
                fmt,
            )
        device = next((d for d in DEVICES if d["id"] == device_id), None)
        return (
            ok({"device": {**device, "platform": "android", "os": "mock", "arch": "x64"}}, [], fmt)
            if device
            else _device_not_found(fmt)
        )
    if name == "execute_script":  # script.ts:43-45 (allowCustomScripts default false)
        return _disabled(
            "CUSTOM_SCRIPTS_DISABLED",
            "Custom script execution is disabled. Use pre-built scripts or enable allowCustomScripts in config.",
            fmt,
        )
    if name == "write_memory":  # memory.ts:105-107
        return _disabled("MEMORY_WRITE_DISABLED", "Memory write operations are disabled by default for safety.", fmt)
    if name == "mobile_action":  # mobile.ts:56-58 with --no-mobile-mcp
        return _disabled(
            "MOBILE_MCP_UNAVAILABLE", "mobile-mcp is not available: mobile-mcp integration is disabled in config", fmt
        )
    if name in {
        "read_memory",
        "scan_memory",
        "get_messages",
        "enumerate_modules",
        "enumerate_exports",
        "detach_session",
    }:
        sid = str(args.get("session_id"))
        if sid not in STATE["sessions"]:
            return err(
                "SESSION_NOT_FOUND",
                f'Session "{sid}" not found.',
                [{"tool": "get_status", "reason": "List sessions"}],
                None,
                fmt,
            )
        return ok({"session_id": sid, "mock": True}, [], fmt)
    if name == "attach_process":
        # errors.ts:164-166 (via ProcessNotFoundError, errors.ts:52-64): wrapFridaError passes the whole Frida message as the "target"
        return err(
            "PROCESS_NOT_FOUND",
            f'Process "unable to find process with pid {args.get("target")}" not found on the device.',
            [{"tool": "get_status", "reason": "List running processes"}],
            {"target": f"unable to find process with pid {args.get('target')}"},
            fmt,
        )
    if name in {"explore_app", "hook_method", "trace_method", "detect_app_technologies", "search_classes_and_methods"}:
        if not DEVICES:
            return _device_not_found(fmt, args.get("device"))
        if args.get("device") and args["device"] not in {d["id"] for d in DEVICES}:
            return _device_not_found(fmt, args["device"])
        return ok({"target": args.get("target"), "mock": "instrumentation simulated, nothing ran"}, [], fmt)
    if name == "stop_instrumentation":
        return ok(
            {"cleaned_sessions": [], "message": "Cleaned up 0 session(s). All hooks, scripts, and traces removed."},
            [],
            fmt,
        )
    return ok({"mock": f"{name} accepted (simulated)"}, [], fmt)


def _garbage(name: str) -> CallToolResult:
    kind = os.environ.get("MOCK_GARBAGE_KIND", "no_structured")
    if kind == "no_structured":
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(["not", "an", "envelope"]))])
    if kind == "wrong_structured":
        return CallToolResult(content=[TextContent(type="text", text="?")], structured_content={"unexpected": 1})
    if kind == "inband_error":  # a normal envelope whose result carries an error (device.ts:95-98 style)
        return ok({"error": "mock in-band failure"}, [], "toon")
    return CallToolResult(content=[TextContent(type="text", text="devices[0]:\n  weird: true")])  # toon_only


def _log(name: str, args: dict[str, Any]) -> None:
    path = os.environ.get("MOCK_CALL_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"tool": name, "arg_keys": sorted(args)}) + "\n")


async def on_list_tools(ctx, params) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


async def on_call_tool(ctx, params) -> CallToolResult:
    name, args = params.name, params.arguments or {}
    _log(name, args)
    if name == os.environ.get("MOCK_SLOW_TOOL"):
        await anyio.sleep(float(os.environ.get("MOCK_SLOW_SECONDS", "30")))
    if name == os.environ.get("MOCK_CRASH_TOOL"):
        sys.stdout.flush()
        os._exit(3)
    if name == os.environ.get("MOCK_ERROR_TOOL"):
        return err(
            "FRIDA_ERROR",
            f"mock frida failure in {name}",
            [{"tool": "get_status", "reason": "Check current state"}],
            None,
            str(args.get("response_format") or "toon"),
        )
    if name == os.environ.get("MOCK_GARBAGE_TOOL"):
        return _garbage(name)
    return handle(name, args)


async def main() -> None:
    if os.environ.get("MOCK_PID_FILE"):
        Path(os.environ["MOCK_PID_FILE"]).write_text(str(os.getpid()), encoding="utf-8")
    if MODE == "missing_frida":
        # Node's ESM loader failing on `import frida from 'frida'` (device/manager.ts:1) before any MCP I/O.
        sys.stderr.write(
            "node:internal/modules/esm/resolve: Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'frida' "
            "imported from dist/device/manager.js\n"
        )
        sys.stderr.flush()
        sys.exit(1)
    # Upstream's version string is hardcoded '0.1.0' (server.ts:46-49) although the package is 0.2.3.
    server = Server("frida-mobile-mcp", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
