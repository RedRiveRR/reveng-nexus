"""Mock MCP server (SDK 2.x, stdio) for the rea adapter. Never imports or runs REA or Node.

Reproduces what the pinned REA (npm rea-agents 6.5.0, morluto/rea 3b79af28) showed on this machine
on 2026-10-15 through a real ``tools/list`` and two real calls on generated fixtures:

* serverInfo ``rea`` / ``6.5.0``; all 207 tool names in catalogue order (src/contracts/
  toolContracts.ts:39-76). The ten tools Nexus can enable carry their real input schemas (the
  eight nexus_inspect_artifact ones as exported from the pinned contracts) and are validated
  against them like REA's zod schemas; the others get an empty object schema (never called).
* Success (src/server/toolResult.ts:152-170): one text block of compact JSON **and**
  ``structuredContent`` with the same REA Evidence record (``evidence_id``, ``subject.digest
  .sha256``, ``provider``, ``operation``, ``normalized_result``, ``limitations``, ...), plus
  ``_meta.provenance.untrusted_content``.
* Failure: ``isError: true`` and a text block ``{"error": {"code", "message"}}``, no structuredContent.

The mock hashes the file it is given (as REA does) but never interprets or runs it.

Switches (environment):
  MOCK_REA_DIGEST      wrong -> report a different subject sha256; upper -> the right digest in
                       uppercase; missing -> no sha256 key; nondict -> subject is a string
  MOCK_ERROR_TOOL      answer one tool with the isError envelope
  MOCK_GARBAGE_TOOL    answer one tool with a non-Evidence JSON body
  MOCK_MALFORMED_TOOL  answer inspect_electron_fuses with the right digest but wrongly typed fields
  MOCK_EXTRA_TOOL      list one more tool than the pinned catalogue (upstream drift)
  MOCK_SERVER_VERSION  report this serverInfo version instead of 6.5.0
  MOCK_SLOW_TOOL / MOCK_SLOW_SECONDS   sleep inside one tool
  MOCK_CRASH_TOOL      exit abruptly inside one tool
  MOCK_CALL_LOG        append one JSON line per call: tool, argument keys, path facts
  MOCK_PID_FILE        write this process's pid here
  MOCK_GRANDCHILD_PID_FILE   spawn a sleeping grandchild (like REA's analysis worker), write its pid
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import anyio
import jsonschema
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations

NAMES = [
    "annotate_native_function",
    "inspect_native_load_image",
    "inspect_native_data_type",
    "inspect_native_instruction",
    "resolve_native_call_targets",
    "address_name",
    "comment",
    "current_address",
    "current_procedure",
    "current_document",
    "goto_address",
    "inline_comment",
    "list_bookmarks",
    "list_documents",
    "list_names",
    "list_procedures",
    "list_segments",
    "list_strings",
    "next_address",
    "prev_address",
    "procedure_address",
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "read_function_instructions",
    "search_bytes",
    "read_bytes",
    "address_to_file_offset",
    "procedure_references",
    "procedure_pseudo_code",
    "resolve_containing_procedure",
    "search_procedures",
    "search_strings",
    "set_address_name",
    "set_addresses_names",
    "set_bookmark",
    "set_comment",
    "set_inline_comment",
    "unset_bookmark",
    "xrefs",
    "trace_native_values",
    "inspect_native_dispatch_metadata",
    "get_objc_classes",
    "get_objc_protocols",
    "batch_decompile",
    "get_call_graph",
    "analyze_swift_types",
    "find_xrefs_to_name",
    "binary_overview",
    "analyze_function",
    "inspect_native_api",
    "trace_feature",
    "trace_call_path",
    "trace_native_ui_action",
    "observe_native_ui",
    "capture_native_ui_scenario",
    "observe_native_calls",
    "inspect_macho",
    "inspect_signature",
    "inspect_plist",
    "list_architectures",
    "demangle_swift",
    "inspect_artifact",
    "extract_artifact",
    "decode_interface_builder",
    "inspect_keyed_archive",
    "inspect_asset_catalog",
    "trace_dylib_resolution",
    "inspect_managed_artifact",
    "inspect_managed_members",
    "inspect_managed_native_boundaries",
    "compare_managed_members",
    "verify_managed_native_boundaries",
    "import_managed_reconstruction",
    "project_managed_application_graph",
    "inspect_with_objdump",
    "execute_rizin_command",
    "list_frida_devices",
    "list_frida_processes",
    "start_frida_session",
    "load_frida_script",
    "resume_frida_session",
    "unload_frida_script",
    "frida_session_status",
    "close_frida_session",
    "instrument_with_frida",
    "list_cutter_sessions",
    "cutter_command",
    "start_gdb_session",
    "gdb_console",
    "gdb_session_status",
    "close_gdb_session",
    "start_rizin_debug_session",
    "rizin_debug_command",
    "rizin_debug_session_status",
    "close_rizin_debug_session",
    "inspect_packet_capture",
    "inspect_packet_fields",
    "decode_signal_recording",
    "inspect_signal_decoders",
    "inspect_android_package",
    "search_android_classes",
    "inspect_android_class",
    "inspect_android_method",
    "trace_android_references",
    "inspect_jeb_client",
    "open_jeb_project",
    "list_jeb_units",
    "decompile_jeb_item",
    "inspect_binary_layout",
    "inspect_analysis_view",
    "inspect_pe_resources",
    "inspect_go_binary",
    "inspect_rust_binary",
    "compare_wasm_interfaces",
    "inspect_wasm_artifact",
    "inspect_evm_interface",
    "inspect_sqlite_database",
    "inspect_recorded_crash",
    "inspect_firmware_regions",
    "extract_firmware",
    "trace_web_module_imports",
    "trace_web_source_location",
    "observe_web_execution",
    "inspect_web_event_listeners",
    "inspect_web_network_capture",
    "recover_javascript_sources",
    "inspect_adb_client",
    "list_adb_devices",
    "inspect_adb_device",
    "list_adb_packages",
    "pull_adb_package",
    "read_adb_logcat",
    "inspect_adb_package",
    "pull_adb_file",
    "push_adb_file",
    "capture_adb_screen",
    "list_adb_processes",
    "list_adb_directory",
    "list_adb_features",
    "list_adb_services",
    "inspect_adb_display",
    "inspect_adb_window",
    "read_adb_setting",
    "collect_adb_bugreport",
    "resolve_adb_packages",
    "install_adb_package",
    "uninstall_adb_package",
    "start_adb_app",
    "start_adb_activity",
    "stop_adb_app",
    "inspect_pcap_client",
    "inspect_pcap_capture",
    "identify_flutter_build",
    "inspect_dart_aot",
    "inspect_apktool_client",
    "decode_android_resources",
    "export_web_scripts",
    "list_browser_targets",
    "inspect_web_page",
    "analyze_web_bundle",
    "observe_web_session",
    "discover_webmcp_tools",
    "compare_web_captures",
    "capture_web_screenshot",
    "compare_web_screenshots",
    "capture_browser_scenario",
    "inspect_electron_fuses",
    "list_electron_targets",
    "inspect_electron_page",
    "analyze_javascript_application",
    "reconcile_javascript_runtime",
    "capture_electron_scenario",
    "list_javascript_runtime_targets",
    "observe_javascript_runtime",
    "trace_application_feature",
    "trace_javascript_semantics",
    "compare_application_versions",
    "compare_source_to_bundle",
    "compare_javascript_export_shapes",
    "build_reconstruction_obligation_ledger",
    "evaluate_reconstruction_coverage",
    "project_android_application_graph",
    "project_apple_application_graph",
    "project_harmony_application_graph",
    "open_binary",
    "close_binary",
    "binary_session",
    "export_evidence_bundle",
    "import_evidence_bundle",
    "get_evidence_bundle",
    "capture_process_scenario",
    "compare_process_captures",
    "compare_artifacts",
    "compare_functions",
    "compare_bundles",
    "find_changed_behavior",
    "build_call_path",
    "correlate_static_and_runtime",
    "verify_reconstruction",
    "list_unknowns",
    "record_unknown",
    "update_unknown",
    "verify_unknown_resolution",
    "get_navigation_context",
    "inspect_address_context",
]

_PATH = {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"}
SCHEMAS: dict[str, dict[str, Any]] = {
    "analyze_javascript_application": {
        "type": "object",
        "properties": {
            "input_path": _PATH,
            "format": {"type": "string", "enum": ["auto", "asar", "directory"], "default": "auto"},
            "integrity_policy": {"type": "string", "enum": ["fail", "record-and-continue"], "default": "fail"},
            "source_paths": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
            "max_semantic_nodes": {"type": "integer", "minimum": 1, "maximum": 1000000},
            "max_semantic_nodes_per_file": {"type": "integer", "minimum": 1, "maximum": 1000000},
            "max_heap_mb": {"type": "integer"},
            "analysis_timeout_ms": {"type": "integer"},
            "detail": {"type": "string", "enum": ["complete", "summary"]},
        },
        "required": ["input_path"],
        "additionalProperties": False,
    },
    "inspect_electron_fuses": {
        "type": "object",
        "properties": {"path": _PATH},
        "required": ["path"],
        "additionalProperties": False,
    },
}
# Real input schemas of the analyses behind nexus_inspect_artifact, as zod's JSON Schema export of the
# pinned contracts (rea-agents 6.5.0 dist/contracts, z.toJSONSchema(io=input)); descriptions dropped.
ANALYSIS_SCHEMAS: dict[str, dict[str, Any]] = {
    "inspect_go_binary": {
        "type": "object",
        "properties": {"path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"}},
        "required": ["path"],
        "additionalProperties": False,
    },
    "inspect_rust_binary": {
        "type": "object",
        "properties": {"path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"}},
        "required": ["path"],
        "additionalProperties": False,
    },
    "inspect_pe_resources": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            "max_file_bytes": {"default": 67108864, "type": "integer", "minimum": 64, "maximum": 536870912},
            "max_entries": {"default": 16384, "type": "integer", "minimum": 1, "maximum": 65536},
        },
        "required": ["path"],
        "additionalProperties": False,
    },
    "inspect_managed_artifact": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            "detail": {"type": "string", "enum": ["complete", "summary"]},
        },
        "additionalProperties": False,
    },
    "inspect_managed_members": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            "detail": {"type": "string", "enum": ["complete", "summary"]},
            "type_names": {
                "minItems": 1,
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "uniqueItems": True,
            },
        },
        "additionalProperties": False,
    },
    "inspect_managed_native_boundaries": {
        "type": "object",
        "properties": {"path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"}},
        "additionalProperties": False,
    },
    "inspect_sqlite_database": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            "table": {"type": "string"},
            "columns": {"minItems": 1, "type": "array", "items": {"type": "string"}},
            "schema_scope": {"type": "string", "enum": ["inventory", "selected_table", "database"]},
            "row_limit": {"type": "integer", "minimum": 1, "maximum": 9007199254740991},
        },
        "required": ["path"],
        "additionalProperties": False,
        "dependentRequired": {"row_limit": ["table"], "columns": ["table"]},
        "if": {"properties": {"schema_scope": {"const": "selected_table"}}, "required": ["schema_scope"]},
        "then": {"required": ["table"]},
    },
    "inspect_wasm_artifact": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            "glue_paths": {
                "default": [],
                "maxItems": 16,
                "type": "array",
                "items": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            },
            "candidate_paths": {
                "default": [],
                "maxItems": 16,
                "type": "array",
                "items": {"type": "string", "minLength": 1, "pattern": "^[^\\x00]*$"},
            },
            "detail": {"type": "string", "enum": ["complete", "summary"]},
        },
        "required": ["path"],
        "additionalProperties": False,
    },
}
SCHEMAS.update(ANALYSIS_SCHEMAS)

# Upstream annotations are derived from each tool's effect audit (toolEffects.ts:714-773) and
# registered unchanged (server/toolRegistrationOptions.ts:33). At the pin, these six tools declare no
# effects at all and so carry readOnlyHint: true; every other tool's is false. Only readOnlyHint is
# reproduced per tool; the other hints are simplified. Nexus never trusts any of them for REA.
READ_ONLY_HINTED = frozenset(
    {
        "evaluate_reconstruction_coverage",
        "list_unknowns",
        "verify_unknown_resolution",
        "get_evidence_bundle",
        "gdb_session_status",
        "frida_session_status",
    }
)
_ANN = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
_ANN_RO = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
TOOLS = [
    Tool(
        name=n,
        description=f"mock {n}",
        input_schema=SCHEMAS.get(n, {"type": "object", "properties": {}}),
        annotations=_ANN_RO if n in READ_ONLY_HINTED else _ANN,
    )
    for n in NAMES
]
_META = {"provenance": {"untrusted_content": True, "source": "analysis_target"}}
FUSE_NAMES = (
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
)
SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"


def _evidence(operation: str, path: str, data: bytes, normalized: dict[str, Any], provider: dict[str, Any]) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    mode = os.environ.get("MOCK_REA_DIGEST")
    if mode == "wrong":
        digest = "0" * 64
    elif mode == "upper":
        digest = digest.upper()
    subject: Any = {"name": Path(path).name, "digest": {"sha256": digest}, "local_path": path, "format": None}
    if mode == "missing":
        subject["digest"] = {"sha512": "0" * 128}
    elif mode == "nondict":
        subject = path
    return {
        "evidence_id": "ev_" + hashlib.sha256((operation + digest).encode()).hexdigest(),
        "subject": subject,
        "provider": provider,
        "analysis_profile": None,
        "predicate_type": "rea.analysis",
        "operation": operation,
        "parameters": {"path": path},
        "raw_result": None,
        "normalized_result": normalized,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": None,
        "limitations": ["mock limitation: values are fixed, not REA's analysis"],
        "relationship_coverage": None,
        "locations": [],
        "evidence_links": [],
    }


def _fuses(path: str) -> dict:
    data = Path(path).read_bytes()
    at = data.find(SENTINEL)
    sentinels = []
    if at >= 0:
        version, length = data[at + len(SENTINEL)], data[at + len(SENTINEL) + 1]
        raw = data[at + len(SENTINEL) + 2 : at + len(SENTINEL) + 2 + length]
        sentinels.append(
            {
                "sentinel_offset": at,
                "wire_version": version,
                "declared_length": length,
                "fuses": [
                    {
                        "index": i,
                        "name": FUSE_NAMES[i] if i < len(FUSE_NAMES) else None,
                        "state": {0x30: "disabled", 0x31: "enabled"}.get(b, "unknown"),
                        "raw_byte": b,
                    }
                    for i, b in enumerate(raw)
                ],
            }
        )
    normalized = {
        "artifact": {"selected_path": path, "resolved_path": path, "bytes": len(data), "format": "elf"},
        "slices": [
            {"index": 0, "file_offset": 0, "size": len(data), "sentinel_count": len(sentinels), "sentinels": sentinels}
        ],
        "runtime_implications": [{"relationship": "derivation", "subject": "electron_run_as_node", "fuse_index": 0}],
        "limitations": ["A missing sentinel means fuse state is unknown, not that every fuse is disabled."],
    }
    return _evidence("inspect_electron_fuses", path, data, normalized, {"id": "electron-fuses", "version": "1"})


def _javascript(path: str) -> dict:
    data = Path(path).read_bytes()
    normalized = {
        "kind": "summary",
        "view": {"kind": "summary"},
        "parent_evidence_id": "ev_" + hashlib.sha256(data).hexdigest(),
        "parent_operation": "analyze_javascript_application",
        "artifact": {"path": path, "sha256": hashlib.sha256(data).hexdigest()},
        "coverage": {"status": "complete-within-view", "exhausted": True},
        "limitations": ["JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed."],
        "unknowns": ["mock unknown"],
        "summary": {
            "input_path": path,
            "format": "asar",
            "statistics": {"relevant_files": 3, "parsed_javascript_files": 2, "parse_failures": 0},
            "electron": {"browser_windows": 0, "preload_entrypoints": 0},
            "coverage": {"application": {"status": "complete", "truncated": False}},
        },
    }
    record = _evidence("inspect_analysis_view", path, data, normalized, {"id": "rea-analysis-view", "version": "1"})
    record["predicate_type"] = "rea.analysis-view"
    record["confidence"] = "derived"
    return record


def _analysis(name: str, args: dict[str, Any]) -> dict:
    """A fixed Evidence record for one nexus_inspect_artifact analysis (values are not REA's analysis)."""
    path = args["path"]
    data = Path(path).read_bytes()
    normalized = {
        "artifact": {"path": path, "bytes": len(data)},
        "mock_tool": name,
        "options": {k: v for k, v in args.items() if k != "path"},
        "limitations": [f"mock {name}: fixed values"],
    }
    return _evidence(name, path, data, normalized, {"id": f"mock-{name}", "version": "1"})


def _ok(record: dict) -> CallToolResult:
    text = json.dumps(record, separators=(",", ":"))
    return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=record, _meta=_META)


def _err(code: str, message: str) -> CallToolResult:
    body = {"error": {"code": code, "message": message}}
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(body))], is_error=True)


def _log(name: str, args: dict[str, Any]) -> None:
    log = os.environ.get("MOCK_CALL_LOG")
    if not log:
        return
    path = args.get("input_path") or args.get("path")
    entry: dict[str, Any] = {"tool": name, "arg_keys": sorted(args)}
    if isinstance(path, str):
        entry["path_is_absolute"] = os.path.isabs(path)
        entry["path_name"] = Path(path).name
        entry["path"] = path
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


async def on_list_tools(ctx, params) -> ListToolsResult:
    if os.environ.get("MOCK_EXTRA_TOOL"):
        extra = Tool(name="a_future_tool_not_in_the_pin", description="mock", input_schema={"type": "object"})
        return ListToolsResult(tools=[*TOOLS, extra])
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
        return _err("analysis_failed", f"mock REA failure in {name}")
    if name == os.environ.get("MOCK_GARBAGE_TOOL"):
        body = {"unexpected": True}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(body))], structured_content=body)
    if name == os.environ.get("MOCK_MALFORMED_TOOL") == "inspect_electron_fuses":
        record = _fuses(args["path"])
        record["normalized_result"] = {
            "artifact": "elf",
            "slices": [{"index": 0, "sentinels": ["x"]}],
            "limitations": 3,
        }
        return _ok(record)
    if name == "inspect_electron_fuses":
        return _ok(_fuses(args["path"]))
    if name == "analyze_javascript_application":
        return _ok(_javascript(args["input_path"]))
    if name in ANALYSIS_SCHEMAS:
        # REA validates every request with the tool's zod schema before running it.
        problems = list(jsonschema.Draft202012Validator(ANALYSIS_SCHEMAS[name]).iter_errors(args))
        if problems:
            return _err("invalid_request", f"mock: {name} input rejected: {problems[0].message}")
        return _ok(_analysis(name, args))
    return _err("invalid_request", f"mock: {name} is not simulated")


async def main() -> None:
    if os.environ.get("MOCK_PID_FILE"):
        Path(os.environ["MOCK_PID_FILE"]).write_text(str(os.getpid()), encoding="utf-8")
    if os.environ.get("MOCK_GRANDCHILD_PID_FILE"):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        Path(os.environ["MOCK_GRANDCHILD_PID_FILE"]).write_text(str(child.pid), encoding="utf-8")
    version = os.environ.get("MOCK_SERVER_VERSION", "6.5.0")
    server = Server("rea", version=version, on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
