# Upstream response contracts behind the mock-tested adapters

The `ida_rs`, `binary_ninja` and `jadx` adapters have never run against their real engines
here (no IDA licence, no Binary Ninja, no Maven). Their mock fixtures
(`tests/mock_servers/mock_adapters.py`) are built from the **pinned upstream source**, read as
data on 2026-10-14. This file records, per bound tool, what that source says: input, response
envelope, error behaviour and the file it comes from. A passing mock test means "matches this
reading of the source", not "verified against the live engine". Rows marked *unresolved* were
not determinable from the source and are not relied upon.

Clones (shallow, unmodified): `C:\tmp\rnx-up\<owner>_<repo>` on the integration machine.

## ida-mcp-rs: blacktop/ida-mcp-rs `15d16aba427bedc8a23c7a54d8adee06d427b740`

Envelope: one text block of `serde_json::to_string_pretty(value)`. Handlers using
`typed_result` (`src/server/mod.rs`) also attach the same value as structured content **when it
is a JSON object**. Errors: `ToolError::to_tool_result()` → `CallToolResult::error` (`isError`).

| Tool | Input used by Nexus | Success response | Source |
|---|---|---|---|
| `open_idb` | `path`, `idb_out` | pretty JSON text; body *unresolved* (Nexus ignores it) | `server/mod.rs` `open_idb` |
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

Adapter behaviour: the `File:` preamble is stripped and its basename must equal the target's
(else refused); in-band `Error...` text is raised as a bounded provider error; JSON bodies are
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
| `load_apk` | `apkPath` | object | `jadx_mcp.py` |
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

## Not covered

Frida Mobile MCP has **no** mock contract tests (only policy/gating unit tests). Its contract
has not been read to this level.
