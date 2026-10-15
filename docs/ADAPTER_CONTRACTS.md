# Upstream response contracts behind the mock-tested adapters

The `ida_rs`, `binary_ninja` and `jadx` adapters have never run against their real engines
here (no IDA licence, no Binary Ninja, no Maven). Their mock fixtures
(`tests/mock_servers/mock_adapters.py`) are built from the **pinned upstream source**, read as
data on 2026-10-14. This file records, per bound tool, what that source says: input, response
envelope, error behaviour and the file it comes from. A passing mock test means "matches this
reading of the source", not "verified against the live engine". Rows marked *unresolved* were
not determinable from the source and are not relied upon.

Since 2026-10-15 the file also covers Frida Mobile MCP (mock built from its pinned source,
never run against Frida or a device) and REA (mock built from the real server's answers on
this machine, plus an opt-in live test).

Clones (shallow, unmodified): one scratch directory per upstream, outside the repository, on
the integration machine.

## ida-mcp-rs: blacktop/ida-mcp-rs `15d16aba427bedc8a23c7a54d8adee06d427b740`

Envelope: one text block of `serde_json::to_string_pretty(value)`. Handlers using
`typed_result` (`src/server/mod.rs`) also attach the same value as structured content **when it
is a JSON object**. Errors: `ToolError::to_tool_result()` → `CallToolResult::error` (`isError`).

| Tool | Input used by Nexus | Success response | Source |
|---|---|---|---|
| `open_idb` | `path`, `idb_out`, `auto_analyse: true` (upstream default `false` opens "fast with analysis incomplete", `server/requests.rs:55-60`) | `DbInfo` with `analysis_status` (`src/ida/types.rs:87-97`, `:132-139`); an incomplete or backgrounded analysis adds a warning to every result until the session is reopened | `server/mod.rs` `open_idb` |
| `close_idb` | — | pretty JSON text | `server/mod.rs` `close_idb` |
| `idb_meta` | — | object: `processor`, `bits`, `file_type`, `loader`, `function_count`, `image_base`, `base_address`, `min_address`, `max_address`, `main_address`, `input_file_*` (hex strings). **No entry-point key.** | `ida/handlers/globals.rs` |
| `list_functions` | `limit`, `offset`, `filter` | `FunctionListResult {functions:[{address,name,size}], total, next_offset?}` (typed) | `ida/types.rs` |
| `decompile` | `address` (**numeric only**) | single address: **plain text** pseudocode | `server/mod.rs` `decompile` |
| `disasm_function_at` | `address` or `target_name` | **plain text**, one `"{:#x}:\t{line}"` per instruction | `ida/handlers/disasm.rs` |
| `xrefs_to` / `xrefs_from` | `address` (**numeric only**), `limit` | `XRefListResult {xrefs:[{from,to,type,is_code}], truncated}` (typed) | `ida/types.rs`, `XrefsOutput::Single` |
| `strings` | `limit`, `filter` | `StringListResult {strings:[{address,content,length}], total}` (typed); the text is in **`content`** | `ida/types.rs` |
| `imports` | `limit` | JSON **array** of `ImportInfo {address,name,ordinal}`: **no module field** | `ida/types.rs` |
| `exports` | `limit` | JSON array of `ExportInfo {address,name,is_public}` | `ida/types.rs` |
| `basic_blocks` | `address` (**numeric only**) | JSON array of `BasicBlockInfo {start,end,size,block_type,successors,predecessors}` | `ida/types.rs` |

Numeric-only: `parse_address` accepts `0x`/`0b`/`0o`/decimal and rejects symbols as
`InvalidAddress`. Nexus therefore resolves a function **name** to exactly one address with
`list_functions` before `decompile`, `xrefs_*` and `basic_blocks`.

Adapter behaviour: strings read `content`; import `library` is `None` (unknown); `entry_point`
stays `None` and `main_address` is reported separately (main() is not the image entry point).

## Binary Ninja MCP: fosdickio/binary_ninja_mcp `8c5134ee46e2bf44f9a4d846bd971c3e39b3e306`

Envelope: one text block. The bridge (`bridge/src/tools.ts`) **never sets `isError`**. `getLines`
fetches with `responseType: "text"`, so list tools return the plugin's compact JSON body
(`plugin/server/http_server.py` `_send_json_response` = `json.dumps(data)`) as text.
Failures: a non-2xx plugin answer becomes `Error: GET <endpoint> failed: <reason>` text
(`client.ts` `handleError`, e.g. `Server returned 500: ...`, `No response from server - is Binary
Ninja running with the MCP plugin?`); `getJson` tools return `Error: <message>`.

| Tool | Input | Response text | Source |
|---|---|---|---|
| `get_binary_status` | — | first line of `/status` JSON: `{"loaded": bool, "filename": path or null}` | `tools.ts`, `http_server.py` |
| `list_methods` | `offset`, `limit` | `File: <active view path>\n` + `{"functions":[{name,address,raw_name}]}` | `tools.ts`, `binary_operations.py get_function_names` |
| `search_functions_by_name` | `query`, `offset`, `limit` | `{"matches":[{name,address}]}` (no preamble) | `endpoints.py search_functions` |
| `function_at` | `address` | `{"address": hex, "functions": [names]}` | `binary_operations.py get_functions_containing_address` |
| `decompile_function` | `name` | `File: <path>\n\n<HLIL text>` or `File: <path>\n\nError: <msg>` | `tools.ts`, `http_server.py _handle_decompile` |
| `fetch_disassembly` | `name` | `File: <path>\n\n<listing>`; lines `"{addr:08x}  {bytes:<16} {disasm}"` | `binary_operations.py _get_instruction_with_annotations` |
| `get_xrefs_to` | `address` | `{"address", "code_references":[{function,address}], "data_references":[...]}`; data-reference record shape *unresolved* (Nexus keeps only entries with an address) | `binary_operations.py get_xrefs_to_address` |
| `list_strings` / `list_strings_filter` | `count`, `offset` (`filter`) | `{"strings":[{address,length,type,value}]}` (+ `total` for filter) | `http_server.py` |
| `list_imports` / `list_exports` | `offset`, `limit` | `{"imports":[{name,address,raw_name,full_name}]}` / `{"exports":[{name,address,...}]}` | `endpoints.py` |

Adapter behaviour: the `File:` preamble is stripped and its path must be this target's staged
copy, compared by full normalised path (a same-named file elsewhere or a `.bndb` is refused; the
same check runs on `get_binary_status` before and after each operation); in-band `Error...` text is raised as a bounded provider error; JSON bodies are
parsed per operation; an address inside several functions is refused as ambiguous;
unrecognised shapes give an empty result plus a warning, never invented rows.

## jadx-mcp-server: Qtty/jadx-mcp-server `4e6d890d1d3753d2bb47d492a9523ef98874df85`

Envelope: every tool is `structured_output=False`, annotated `-> str`, and returns `_json(value)` =
`json.dumps(value, ensure_ascii=False, separators=(",", ":"))`, so **strings arrive as JSON string
literals**. Daemon failures raise `RuntimeError` (`JadxClient._unwrap`); FastMCP reports them with
`isError` (exact wording depends on `mcp==1.27.2` and is *unresolved*; Nexus only uses the flag).
Bookkeeping: in lists, entries starting with `@` (`@truncated: ...`, `@oversized: ...`,
`@rejected`) or one-key objects with an `@` key are notices, not data; `get_class_source` may lead
with `@outline:` / `@oversized:` / `@truncated:` lines (partial answer).

| Tool | Input | Decoded value | Source |
|---|---|---|---|
| `load_apk` | `apkPath` | object whose `apkPath` echoes the loaded file (`core/JadxAnalyzerCore.java:461`, `:509-519`); a missing or different path is refused, because the daemon answers every later request for its most recently loaded APK (`core/AnalyzerRegistry.java:188-199`) | `jadx_mcp.py` |
| `get_android_manifest` | — | string (XML) | `JadxClient.get_android_manifest` |
| `get_main_activity_class` | — | string | `JadxClient.get_main_activity_class` |
| `get_exported_components` / `get_deeplink_components` | — | list of `{name,type,is_main,is_browsable,exported,exported_reason,intent_filters[,permission,alias_of]}` | tool docstrings |
| `get_all_classes` | `packagePrefix`, `limit` | list of class-name strings | `JadxClient.get_all_classes` |
| `get_class_source` | `className`, `maxBytes` | string (Java) | `JadxClient.get_class_source` |
| `search_classes_by_keyword` | `keyword`, `limit` | list of strings | `JadxClient.search_classes_by_keyword` |
| `search_method_by_name` | `methodName`, `limit` | object `{class: [methods]}` | `JadxClient.search_method_by_name` |

Adapter behaviour: each answer is decoded **once** (a decoded string is never re-parsed, so
source text that looks like JSON is kept verbatim); a value of the wrong JSON type is an error;
non-JSON plain text is accepted only where a string is expected, with a warning; bookkeeping
entries become warnings; partial class source is kept verbatim and flagged `partial: true`.

## Frida Mobile MCP: monkeywave/frida-mobile-mcp `b2da55d6429438ed36e829e7478de42430cb4ef9`

npm `frida-mobile-mcp@0.2.3`. Read as data on 2026-10-15; the mock
(`tests/mock_servers/mock_frida.py`) serves the 32 tools registered in `src/server.ts:61-81`
with the argument names, required arguments and annotations of each `server.registerTool`
call. No Frida, frida-server, npx, device or app was installed, launched or contacted.

Envelope (`src/helpers/result-builder.ts:27-53`, `formatToolResponse`): one text block in
`response_format` (default `toon`; `json` = `JSON.stringify(data, null, 2)`) **plus**
`structuredContent = {result, session_context, suggested_next}`; `isError` unset. Text above
25 000 characters is truncated (`constants.ts:4`); `structuredContent` is not. Failure
(`helpers/errors.ts:21-30`): one text block `{error: {code, message, recovery_actions,
context}}`, `isError: true`, no `structuredContent`. The real server imports the native `frida`
package at load time (`device/manager.ts:1`), so a missing install ends the process before
`initialize`.

| Tool | Input | Response / behaviour | Source |
|---|---|---|---|
| `get_status` | — | success envelope; device-enumeration failures are swallowed and reported as `devices: []` | `tools/status.ts:12`, `:32-36` |
| `get_device_info` | — | with no device selected: a **success** envelope whose `result` is `{error: "No device selected. ..."}` (in-band, no `isError`) | `tools/advanced/device.ts:95-98` |
| `frida_help` | `topic` | unknown topic: `result.message` | `tools/help.ts:256-263` |
| `stop_instrumentation` | `session_id`, `target`, `all` | cleans up sessions, hooks, scripts and traces | `tools/cleanup.ts:11` |
| instrumentation tools (`explore_app`, `hook_method`, `trace_method`, `search_classes_and_methods`, `detect_app_technologies`, ...) | `target` (required), optional `device` | — | `tools/*.ts` |
| session-based tools (`read_memory`, `scan_memory`, `get_messages`) | `session_id` (required), **no** `target` | — | `tools/memory.ts`, `tools/messages.ts` |

Device resolution (`device/resolver.ts:42-61`): without a `device` argument the server uses
`FRIDA_DEVICE_ID`, then the first USB device, then the local host. Unknown argument keys are
dropped by the schema. Shutdown cleanup runs only on SIGINT/SIGTERM (`index.ts:68-79`). The
`FRIDA_MCP_*` switches count only when set to `1`.

Adapter behaviour: `get_status` is accepted only as a structured envelope whose `result` is
an object, and an in-band `result.error` string is raised as a bounded provider error;
otherwise the status is left empty with a warning and the raw output kept. Nexus never depends
on the TOON text. On shutdown the adapter calls `stop_instrumentation {all: true}` internally
(5 s bound, errors suppressed). Policy refuses undeclared arguments, device-less calls to tools
that declare a device argument, and unmanifested tools; the mock's TOON text is an
approximation, which is why it is never parsed.

## REA: morluto/rea `3b79af28e80785afce9f5998d8f03289402a1847` (npm `rea-agents` 6.5.0)

Unlike the sections above, this contract was observed on the **real** server on 2026-10-15
(pinned install, generated fixtures) and then reproduced in the mock
(`tests/mock_servers/mock_rea.py`): `serverInfo` `rea`/`6.5.0`, all 207 tool names in catalogue
order (`src/contracts/toolContracts.ts:39-76`). Only the two allowlisted tools carry their real
argument names in the mock; the others have an empty schema, because Nexus blocks them before
any call.

Envelope (`src/server/toolResult.ts:152-170`): one text block of compact JSON **and**
`structuredContent` with the same REA Evidence record (`evidence_id`, `subject.digest.sha256`,
`provider`, `operation`, `normalized_result`, `limitations`, ...), plus
`_meta.provenance.untrusted_content`. Failure: `isError: true` and a text block
`{"error": {"code", "message"}}`, no `structuredContent`.

| Tool (Nexus operation) | Input sent by Nexus | Used from the result |
|---|---|---|
| `analyze_javascript_application` (`js.application`) | `input_path` = staged copy, `format` (`asar` for `.asar`, else `auto`), `integrity_policy: record-and-continue`, `detail: summary`, `analysis_timeout_ms` = min(provider timeout − 10 s, 300 s) | `normalized_result.summary` (`format`, `statistics`, `electron`, `coverage`), `unknowns`, `limitations`, `parent_evidence_id`/`parent_operation`, record `confidence` |
| `inspect_electron_fuses` (`electron.fuses`) | `path` = staged copy | `normalized_result.slices[].sentinels[].fuses[]` (`index`, `name`, `state`, with slice and wire version), `runtime_implications`, `limitations`, `artifact.format` |

Adapter behaviour: a body that is not an Evidence record with an object `normalized_result`
is an error; `subject.digest.sha256` must equal the target's SHA-256, otherwise the call fails
("analysed a different file") and no evidence is stored. No fuse wire found gives an empty list
plus a warning (state unknown, not disabled). If REA kept the full JavaScript analysis in its own
session (`raw_result` absent), a warning says only the summary view is stored. In the
normalised result, strings that start with a local path Nexus itself passed (the staged copy, the
work directory, the original path; case-insensitive) are replaced by the target's display name;
the raw output keeps the original. Target-derived strings that only look like paths (`/api/x`,
other drives, UNC names) are kept verbatim
(`test_path_scrub_replaces_only_the_local_paths_nexus_passed`).

Drift: once connected, both operations are reported unavailable (and `require()` refuses them, so
nothing is sent) unless the catalogue has exactly 207 tools whose sorted names hash to the pinned
value and `serverInfo.version` is `6.5.0` (`test_upstream_drift_disables_both_operations`). A
wrongly typed Evidence field is a bounded provider error. What the two tools do at the pin:
`analyze_javascript_application` copies the ASAR to a `rea-asar-snapshot-*` temp directory and
parses it in a REA Node worker (REA-owned Job Object, private temp cwd), never executing it;
`analysis_timeout_ms` applies per JavaScript source, and the whole call is bounded by Nexus's
`timeout_seconds`. `inspect_electron_fuses` reads bytes in process. Nexus never stages an
`.asar.unpacked` directory, so unpacked entries are reported unavailable.

## re-mcp IDA backend: jtsylve/re-mcp `7b38aa9` (PyPI `re-mcp-ida` 3.0.3)

Read as data on 2026-10-15. The shared `re_mcp` adapter's mock (`tests/mock_servers/mock_engine.py`)
imitates the **Ghidra** backend; the IDA shapes differ and are covered by unit tests on the
normalisers (`tests/test_interop_d.py`), not by a mock server:

| Tool | IDA shape (pinned source) | Ghidra shape |
|---|---|---|
| `get_xrefs_to` / `get_xrefs_from` | rows `{from, from_name, type, is_code}` / `{to, to_name, type, is_code}`; the result echoes the resolved `address` (`re_mcp_ida/tools/xrefs.py:38-69`) | `{from_address, from_function, ref_type, is_call}` / `{to_address, to_function, ref_type, is_call}` (`re_mcp_ghidra/tools/xrefs.py:24-35`) |
| `decompile_function` | `{address, name, pseudocode}` (`tools/functions.py:99-104`) | `{function_name, address, decompiled_code}` |
| `disassemble_function` | instructions `{address, disasm}` (`tools/functions.py:107-120`) | `{address, mnemonic, operands, bytes}`, result `start`/`end` |
| `get_database_info` | no image base; `min_address` is not one (`tools/database.py:67-80`) | `image_base` |

A row carries only the far end of a reference; the near end is the queried (resolved) address.
A decompile answer without a pseudocode field is an error, never the JSON text stored as code.
