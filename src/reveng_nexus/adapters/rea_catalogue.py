"""Tool-by-tool classification of REA's pinned catalogue (npm rea-agents 6.5.0, morluto/rea 3b79af28).

Every one of the 207 tools is classified from three sources read at the pin, never from its MCP
annotations alone:

* REA's own effect audit (``src/contracts/toolEffects.ts`` ``TOOL_EFFECTS``: mutatesTarget,
  writesFilesystem, launchesProcess, accessesNetwork, executesForeignCode, mutatesDevice, ...);
* the tool's input schema and contract kind (``src/contracts/*ToolContracts.ts``), which tell
  whether it reads one explicit file, an REA session's active target, a device, or a live runtime;
* for the enabled analyses, the implementation (``src/go``, ``src/rust``, ``src/native/pe``,
  ``src/dotnet``, ``src/sqlite``, ``src/wasm``) and REA's availability rules
  (``src/application/CapabilityInventory.ts``).

Classes follow ``policy.TOOL_CLASS_DESCRIPTIONS``. Scopes for reads:

* ``file``: reads one explicit local file path. Only these can be confined by Nexus, which passes
  the hash-verified staged copy of an admitted target and nothing else.
* ``session``: works on REA's session state (the target opened by ``open_binary``, a Hopper, JEB or
  Cutter document, or REA Evidence ids). Nexus does not manage REA sessions, so none is wired.
* ``probe``: reports whether an REA helper (apktool, tshark, sigrok, JEB, Cutter) is installed.
* ``multi_path``: needs several caller-chosen paths, which cannot be confined to one target.

An analysis is *enabled* only when its tool was reviewed at the pin and Nexus can confine it. The
tiers (``ANALYSES[...].min_profile``) map to access profiles:

* restricted: the two tools verified live through Nexus on 2026-10-15;
* balanced: + file-scoped parsers whose implementation was reviewed at the pin (not run live);
* full_access: no further REA tools. REA's mutate/lifecycle/execute/dynamic tools take paths,
  session ids, devices or commands that Nexus cannot confine, and REA is adapter-only, so no
  profile and no policy gate can reach them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_FILE_READS = (
    "analyze_javascript_application", "decode_android_resources", "decode_signal_recording",
    "identify_flutter_build", "inspect_android_class", "inspect_android_method", "inspect_android_package",
    "inspect_binary_layout", "inspect_dart_aot", "inspect_electron_fuses", "inspect_evm_interface",
    "inspect_firmware_regions", "inspect_go_binary", "inspect_keyed_archive", "inspect_managed_artifact",
    "inspect_managed_members", "inspect_managed_native_boundaries", "inspect_packet_capture",
    "inspect_pcap_capture", "inspect_pe_resources", "inspect_plist", "inspect_recorded_crash",
    "inspect_rust_binary", "inspect_sqlite_database", "inspect_wasm_artifact",
    "inspect_web_network_capture", "inspect_with_objdump", "search_android_classes",
    "trace_android_references", "trace_web_source_location",
)  # fmt: skip
_SESSION_READS = (
    "address_name", "address_to_file_offset", "analyze_function", "analyze_swift_types", "batch_decompile",
    "binary_overview", "build_call_path", "build_reconstruction_obligation_ledger", "comment",
    "compare_application_versions", "compare_artifacts", "compare_functions",
    "compare_javascript_export_shapes", "compare_managed_members", "compare_process_captures",
    "compare_source_to_bundle", "compare_wasm_interfaces", "compare_web_captures",
    "compare_web_screenshots", "correlate_static_and_runtime", "current_address", "current_document",
    "current_procedure", "decode_interface_builder", "decompile_jeb_item", "demangle_swift",
    "evaluate_reconstruction_coverage", "find_changed_behavior", "find_xrefs_to_name", "get_call_graph",
    "get_evidence_bundle", "get_navigation_context", "get_objc_classes", "get_objc_protocols",
    "inline_comment", "inspect_address_context", "inspect_analysis_view", "inspect_artifact",
    "inspect_asset_catalog", "inspect_macho", "inspect_native_api", "inspect_native_data_type",
    "inspect_native_dispatch_metadata", "inspect_native_instruction", "inspect_native_load_image",
    "inspect_signature", "list_architectures", "list_bookmarks", "list_documents", "list_jeb_units",
    "list_names", "list_procedures", "list_segments", "list_strings", "list_unknowns", "next_address",
    "prev_address", "procedure_address", "procedure_assembly", "procedure_callees", "procedure_callers",
    "procedure_info", "procedure_pseudo_code", "procedure_references", "project_android_application_graph",
    "project_apple_application_graph", "project_harmony_application_graph",
    "project_managed_application_graph", "read_bytes", "read_function_instructions",
    "reconcile_javascript_runtime", "resolve_containing_procedure", "resolve_native_call_targets",
    "search_bytes", "search_procedures", "search_strings", "trace_application_feature", "trace_call_path",
    "trace_dylib_resolution", "trace_feature", "trace_javascript_semantics", "trace_native_ui_action",
    "trace_native_values", "verify_managed_native_boundaries", "verify_reconstruction",
    "verify_unknown_resolution", "xrefs",
)  # fmt: skip
_PROBES = (
    "binary_session", "inspect_apktool_client", "inspect_jeb_client", "inspect_packet_fields",
    "inspect_pcap_client", "inspect_signal_decoders", "list_cutter_sessions",
)  # fmt: skip
_MULTI_PATH = ("compare_bundles",)
# mutatesTarget / changesUiState / session-state writes, or files written to a caller-chosen place
_MUTATE = (
    "annotate_native_function", "export_evidence_bundle", "export_web_scripts", "extract_artifact",
    "extract_firmware", "goto_address", "import_managed_reconstruction", "record_unknown",
    "recover_javascript_sources", "set_address_name", "set_addresses_names", "set_bookmark", "set_comment",
    "set_inline_comment", "unset_bookmark", "update_unknown",
)  # fmt: skip
# open/close an REA analysis, JEB, debugger or Frida session (paths or session ids)
_LIFECYCLE = (
    "close_binary", "close_frida_session", "import_evidence_bundle", "open_binary", "open_jeb_project",
    "start_frida_session", "start_gdb_session", "unload_frida_script",
)  # fmt: skip
# executesForeignCode: true in REA's effect audit (the target, a caller command, script or debugger)
_EXECUTE = (
    "capture_browser_scenario", "capture_electron_scenario", "capture_native_ui_scenario",
    "capture_process_scenario", "close_gdb_session", "close_rizin_debug_session", "cutter_command",
    "execute_rizin_command", "gdb_console", "instrument_with_frida", "load_frida_script",
    "observe_native_calls", "resume_frida_session", "rizin_debug_command", "start_rizin_debug_session",
)  # fmt: skip
# devices (adb), live processes (Frida, debugger sessions, native UI), CDP/Inspector runtimes,
# and a browser launched for module resolution
_DYNAMIC = (
    "analyze_web_bundle", "capture_adb_screen", "capture_web_screenshot", "collect_adb_bugreport",
    "discover_webmcp_tools", "frida_session_status", "gdb_session_status", "inspect_adb_client",
    "inspect_adb_device", "inspect_adb_display", "inspect_adb_package", "inspect_adb_window",
    "inspect_electron_page", "inspect_web_event_listeners", "inspect_web_page", "install_adb_package",
    "list_adb_devices", "list_adb_directory", "list_adb_features", "list_adb_packages",
    "list_adb_processes", "list_adb_services", "list_browser_targets", "list_electron_targets",
    "list_frida_devices", "list_frida_processes", "list_javascript_runtime_targets",
    "observe_javascript_runtime", "observe_native_ui", "observe_web_execution", "observe_web_session",
    "pull_adb_file", "pull_adb_package", "push_adb_file", "read_adb_logcat", "read_adb_setting",
    "resolve_adb_packages", "rizin_debug_session_status", "start_adb_activity", "start_adb_app",
    "stop_adb_app", "trace_web_module_imports", "uninstall_adb_package",
)  # fmt: skip

_SCOPE_NOTE = {
    "session": "works on an REA analysis session's target or Evidence ids; Nexus does not manage REA sessions",
    "probe": "probes an REA helper installation; Nexus reports prerequisites from the provider config instead",
    "multi_path": "needs several caller-chosen paths, which Nexus cannot confine to one admitted target",
    "file": "file-scoped read whose implementation has not been reviewed at the pin yet",
}
_CLASS_NOTE = {
    "mutate": "changes REA analysis state or writes files to a caller-chosen location",
    "lifecycle": "opens or closes an REA, JEB, debugger or Frida session from a caller path or session id",
    "execute": "runs code REA does not own (REA effect audit: executesForeignCode)",
    "dynamic": "drives a device, a live process or a CDP/Inspector runtime",
}


@dataclass(frozen=True, slots=True)
class ReaTool:
    name: str
    tool_class: str  # read | mutate | lifecycle | execute | dynamic
    scope: str  # file | session | probe | multi_path | "" (non-read classes)
    note: str


def _build() -> dict[str, ReaTool]:
    out: dict[str, ReaTool] = {}
    for names, cls, scope in (
        (_FILE_READS, "read", "file"),
        (_SESSION_READS, "read", "session"),
        (_PROBES, "read", "probe"),
        (_MULTI_PATH, "read", "multi_path"),
        (_MUTATE, "mutate", ""),
        (_LIFECYCLE, "lifecycle", ""),
        (_EXECUTE, "execute", ""),
        (_DYNAMIC, "dynamic", ""),
    ):
        for name in names:
            if name in out:
                raise AssertionError(f"REA tool {name} classified twice")
            out[name] = ReaTool(name, cls, scope, _SCOPE_NOTE.get(scope) or _CLASS_NOTE[cls])
    return out


CATALOGUE: dict[str, ReaTool] = _build()


@dataclass(frozen=True, slots=True)
class ReaAnalysis:
    """One enabled REA tool, reachable only through Nexus with the staged target as its one path."""

    analysis: str  # engine-neutral name used by nexus_inspect_artifact
    tool: str
    path_argument: str
    min_profile: str  # restricted | balanced | full_access
    verification: str  # live_analysis_verified | source_reviewed
    description: str
    # JSON Schema properties of the caller options forwarded to REA (never a path)
    options: dict[str, Any] = field(default_factory=dict)
    # provider env variables REA needs for this tool (CapabilityInventory.ts remediation)
    prerequisites_env: tuple[tuple[str, ...], ...] = ()
    # fixed arguments Nexus always sends
    fixed: dict[str, Any] = field(default_factory=dict)
    review_notes: str = ""


_DETAIL = {"type": "string", "enum": ["complete", "summary"]}

ANALYSES: dict[str, ReaAnalysis] = {
    a.analysis: a
    for a in (
        ReaAnalysis(
            analysis="go_binary",
            tool="inspect_go_binary",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description="Go build info, module graph and runtime metadata of an executable or library",
            review_notes="src/go/GoBinaryProvider.ts: one readStableArtifact read, in-process parsing; no process, no writes",
        ),
        ReaAnalysis(
            analysis="rust_binary",
            tool="inspect_rust_binary",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description="Rust toolchain, crate and panic-location metadata of an executable or library",
            review_notes="src/rust/RustBinaryProvider.ts: one readStableArtifact read, in-process parsing",
        ),
        ReaAnalysis(
            analysis="pe_resources",
            tool="inspect_pe_resources",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description="PE resource directory (version info, manifests, icons, string tables) of a PE image",
            options={
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 65536},
                "max_file_bytes": {"type": "integer", "minimum": 64, "maximum": 536870912},
            },
            review_notes="src/native/pe/PeResourcesProvider.ts: readStableArtifact + in-process PeResourceParser",
        ),
        ReaAnalysis(
            analysis="managed_artifact",
            tool="inspect_managed_artifact",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description=".NET CLI metadata inventory (assemblies, types, references) of a managed PE",
            options={"detail": _DETAIL},
            review_notes="src/dotnet/ManagedStaticProvider.ts -> ManagedArtifactInspector: byte-level metadata decoding",
        ),
        ReaAnalysis(
            analysis="managed_members",
            tool="inspect_managed_members",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description=".NET fields, methods, call edges and loaded user strings, optionally per type",
            options={
                "detail": _DETAIL,
                "type_names": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 256,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 1024},
                },
            },
            review_notes="src/dotnet/ManagedMemberInspector.ts: CIL decoded as data, never executed",
        ),
        ReaAnalysis(
            analysis="managed_native_boundaries",
            tool="inspect_managed_native_boundaries",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description=".NET P/Invoke and native-boundary declarations of a managed PE",
            review_notes="src/dotnet/ManagedNativeBoundaryInspector.ts: metadata tables only",
        ),
        ReaAnalysis(
            analysis="sqlite_database",
            tool="inspect_sqlite_database",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description="Schema inventory and bounded row samples of an offline SQLite database",
            options={
                "table": {"type": "string", "minLength": 1, "maxLength": 1024},
                "columns": {"type": "array", "minItems": 1, "maxItems": 256, "items": {"type": "string"}},
                "schema_scope": {"type": "string", "enum": ["inventory", "selected_table", "database"]},
                "row_limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
            review_notes=(
                "src/sqlite/SqliteDatabaseProvider.ts: snapshot copied into REA's private runtime root, read by "
                "REA's own node:sqlite worker process; views and virtual tables are never executed"
            ),
        ),
        ReaAnalysis(
            analysis="wasm_artifact",
            tool="inspect_wasm_artifact",
            path_argument="path",
            min_profile="balanced",
            verification="source_reviewed",
            description="WebAssembly module validation, imports/exports and disassembly summary (WABT)",
            options={"detail": _DETAIL},
            prerequisites_env=(("REA_WABT_BIN_DIRECTORY",),),
            review_notes=(
                "src/wasm/WabtArtifactProvider.ts: snapshot module.wasm in a private root; runs only "
                "wasm-validate, wasm-objdump and wasm2wat from REA_WABT_BIN_DIRECTORY; glue/candidate paths "
                "are never sent"
            ),
        ),
    )
}
# The two tools behind the js.application and electron.fuses operations (verified live).
LIVE_VERIFIED = ("analyze_javascript_application", "inspect_electron_fuses")
ENABLED_TOOLS: dict[str, str] = {
    **{tool: "restricted" for tool in LIVE_VERIFIED},
    **{a.tool: a.min_profile for a in ANALYSES.values()},
}
PROFILE_RANK = {"restricted": 0, "balanced": 1, "full_access": 2}


def manifest() -> dict[str, str]:
    return {name: tool.tool_class for name, tool in CATALOGUE.items()}
