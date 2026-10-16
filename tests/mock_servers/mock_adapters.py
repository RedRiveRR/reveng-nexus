"""Mock MCP servers (SDK 2.x, stdio) for the ida_rs, binary_ninja and jadx adapters.

Each profile reproduces the *response envelope* of the pinned upstream, read from its source
(see docs/ADAPTER_CONTRACTS.md for the per-tool table and file references):

* ida_rs  - blacktop/ida-mcp-rs 15d16ab: pretty JSON text; ``typed_result`` tools (list_functions,
  strings, xrefs) also attach the same object as structured content; decompile and
  disasm_function_at answer plain text; errors set ``isError``.
* binja   - fosdickio/binary_ninja_mcp 8c5134e: never sets ``isError``. List tools return the
  plugin's compact JSON body as text, list_methods/decompile_function/fetch_disassembly behind a
  ``File: <active view path>`` preamble; failures come back as ``Error: ...`` text.
* jadx    - Qtty/jadx-mcp-server 4e6d890: every tool returns one text block ``json.dumps(value)``
  (strings too); daemon failures raise, which FastMCP reports with ``isError``.

Data values are hardcoded and small; only the envelopes follow upstream. Passing tests here means
"mock-tested", never "upstream-verified".

MOCK_PROFILE=ida_rs|binja|jadx. Switches (environment):
  MOCK_SLOW_TOOL / MOCK_SLOW_SECONDS   sleep inside one tool (timeout/cancellation tests)
  MOCK_CRASH_TOOL                      exit abruptly inside one tool (crash isolation)
  MOCK_ERROR_TOOL                      fail one tool the way that upstream fails (isError or text)
  MOCK_GARBAGE_TOOL                    answer one tool with a well-formed but wrong-shaped document
  MOCK_GARBAGE_KIND                    object (default) | list_of_strings | invalid_json | plain_text
  MOCK_BINJA_VIEW                      path of the binary Binary Ninja has "open" ("" = none)
  MOCK_BINJA_PREAMBLE_VIEW             path reported in the "File:" preamble instead
  MOCK_BINJA_OVERLAP                   function_at reports two functions at an address
  MOCK_JADX_PARTIAL                    get_class_source / get_all_classes answer a capped result
  MOCK_JADX_LOADED_PATH                apkPath load_apk reports (another client switched the daemon)
  MOCK_CALL_LOG                        append one JSON line per call: tool name + argument keys
                                       (+ the path handed to open_idb/load_apk)
The file handed to open_idb/load_apk is only checked to exist, never read or run.
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

PROFILE = os.environ.get("MOCK_PROFILE", "ida_rs")
STATE: dict[str, Any] = {"open": None}

RO = ToolAnnotations(read_only_hint=True)
MUT = ToolAnnotations(read_only_hint=False)

FUNCS = [
    {"name": "main", "address": 0x401000, "size": 0x30},
    {"name": "check_key", "address": 0x401030, "size": 0x10},
    {"name": "add_numbers", "address": 0x401040, "size": 0x10},
]
CALLS = {"check_key": 0x401012, "add_numbers": 0x401008}  # call sites inside main
GREETING = "Hello from the RevEng Nexus fixture"


def _tool(name: str, *props: str, annotations: ToolAnnotations | None = None) -> Tool:
    return Tool(
        name=name,
        description=f"mock {name}",
        input_schema={"type": "object", "properties": {p: {} for p in props}},
        annotations=annotations,
    )


# ida-mcp-rs annotates its tools; the adapter trusts annotations but its manifest wins.
IDA_TOOLS = [
    _tool("open_idb", "path", "idb_out", annotations=MUT),
    _tool("close_idb", annotations=MUT),
    _tool("idb_meta", annotations=RO),
    _tool("list_functions", "limit", "offset", "filter", annotations=RO),
    _tool("decompile", "address", annotations=RO),
    _tool("disasm_function_at", "address", "target_name", "offset", "count", annotations=RO),  # requests.rs:339-351
    _tool("xrefs_to", "address", "limit", annotations=RO),
    _tool("xrefs_from", "address", "limit", annotations=RO),
    _tool("strings", "limit", "filter", annotations=RO),
    _tool("imports", "limit", annotations=RO),
    _tool("exports", "limit", annotations=RO),
    _tool("basic_blocks", "address", annotations=RO),
    # Dangerous tools, some deliberately mis-annotated read-only: the manifest must still block them.
    _tool("run_script", "code", annotations=RO),
    _tool("save_idb", annotations=MUT),
    _tool("lumina_lookup", "address", annotations=RO),
    _tool("debug_attach", "pid", annotations=RO),
    _tool("mystery_tool"),
]

# The Binary Ninja bridge carries no annotations; Nexus relies on its explicit allowlist.
BINJA_TOOLS = [
    _tool(n, *p)
    for n, p in (
        ("get_binary_status", ()),
        ("select_binary", ("view",)),
        ("list_methods", ("offset", "limit")),
        ("search_functions_by_name", ("query", "offset", "limit")),
        ("function_at", ("address",)),
        ("decompile_function", ("name",)),
        ("fetch_disassembly", ("name",)),
        ("get_xrefs_to", ("address",)),
        ("list_strings", ("count", "offset")),
        ("list_strings_filter", ("filter", "count", "offset")),
        ("list_imports", ("offset", "limit")),
        ("list_exports", ("offset", "limit")),
        ("rename_function", ("old_name", "new_name")),
        ("patch_bytes", ("address", "data")),
        ("set_comment", ("address", "comment")),
        ("frobnicate_view", ()),
    )
]

JADX_TOOLS = [
    _tool(n, *p)
    for n, p in (
        ("load_apk", ("apkPath",)),
        ("get_android_manifest", ()),
        ("get_main_activity_class", ()),
        ("get_exported_components", ()),
        ("get_deeplink_components", ()),
        ("get_all_classes", ("packagePrefix", "limit")),
        ("get_class_source", ("className", "maxBytes")),
        ("search_classes_by_keyword", ("keyword", "limit")),
        ("search_method_by_name", ("methodName", "limit")),
        ("rename_class", ("className", "newName")),
        ("frobnicate_apk", ()),
    )
]

TOOLS = {"ida_rs": IDA_TOOLS, "binja": BINJA_TOOLS, "jadx": JADX_TOOLS}[PROFILE]
GARBAGE_OBJECT = {"unexpected": {"shape": [1, 2, 3]}, "note": "not what the adapter expects"}


# -- envelopes --------------------------------------------------------------------------------
def _text(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)])


def _error(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def _rust_pretty(value: Any) -> CallToolResult:
    """ida-mcp-rs ``Content::text(serde_json::to_string_pretty(&value))``."""
    return _text(json.dumps(value, indent=2))


def _rust_typed(value: Any) -> CallToolResult:
    """ida-mcp-rs ``typed_result``: pretty text, plus structured content when it is an object."""
    result = _rust_pretty(value)
    if isinstance(value, dict):
        result.structured_content = value
    return result


def _plugin_json(value: Any) -> str:
    """Binary Ninja plugin ``_send_json_response``: ``json.dumps(data)`` (compact separators)."""
    return json.dumps(value)


CURRENT: dict[str, str] = {"tool": ""}


def _jadx(value: Any) -> CallToolResult:
    """jadx-mcp-server ``_json``: ``json.dumps(value, ensure_ascii=False, separators=(",", ":"))``.

    MOCK_GARBAGE_TOOL swaps the value for a wrong-shaped document (or non-JSON text) in the same
    envelope.
    """
    if os.environ.get("MOCK_GARBAGE_TOOL") == CURRENT["tool"]:
        if os.environ.get("MOCK_GARBAGE_KIND", "object") in {"invalid_json", "plain_text"}:
            return _text(_garbage())
        value = json.loads(_garbage())
    return _text(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _garbage() -> str:
    kind = os.environ.get("MOCK_GARBAGE_KIND", "object")
    if kind == "list_of_strings":
        return json.dumps(["not", "a", "record"])
    if kind == "invalid_json":
        return '{"truncated": [1, 2'
    if kind == "plain_text":
        return "this is not the pinned envelope"
    return json.dumps(GARBAGE_OBJECT)


def _fn(ref: Any) -> dict[str, Any] | None:
    text = str(ref or "")
    if text.lower().startswith("0x"):
        return next((f for f in FUNCS if f["address"] == int(text, 16)), None)
    return next((f for f in FUNCS if f["name"] == text), None)


def _log(name: str, args: dict[str, Any]) -> None:
    path = os.environ.get("MOCK_CALL_LOG")
    if path:
        entry: dict[str, Any] = {"tool": name, "arg_keys": sorted(args)}
        if name in {"open_idb", "load_apk"}:
            entry["path"] = args.get("path") or args.get("apkPath")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")


# -- ida-mcp-rs ----------------------------------------------------------------------------------
def _ida(name: str, args: dict[str, Any]) -> CallToolResult:
    if name == "open_idb":
        if not Path(args.get("path", "")).is_file():
            return _error(f"Failed to open database: {Path(args.get('path', '')).name}")
        STATE["open"] = Path(args["path"]).name
        # DbInfo (src/ida/types.rs:87-97, built in handlers/database.rs:76-90) as pretty JSON text;
        # without auto_analyse (requests.rs:55-60, default false) analysis is left incomplete.
        auto = bool(args.get("auto_analyse"))
        return _rust_pretty(
            {
                "path": args.get("idb_out") or args["path"],
                "file_type": "ELF",
                "loader": "ELF64 for x86-64 (Executable)",
                "processor": "metapc",
                "bits": 64,
                "function_count": len(FUNCS),
                "debug_info": None,
                "analysis_status": {
                    "auto_enabled": True,
                    "auto_is_ok": auto,
                    "auto_state": "AU_NONE" if auto else "AU_USED",
                    "auto_state_id": 0 if auto else 1,
                    "analysis_running": False,
                },
            }
        )
    if name == "close_idb":
        STATE["open"] = None
        return _rust_pretty({"closed": True})
    if name in {"run_script", "save_idb", "lumina_lookup", "debug_attach", "mystery_tool"}:
        return _text(json.dumps({"status": "side effect performed", "tool": name}))
    if STATE["open"] is None:
        return _error("No database is open")
    if name == "idb_meta":  # src/ida/handlers/globals.rs
        return _rust_pretty(
            {
                "processor": "metapc",
                "bits": 64,
                "file_type": "ELF64",
                "loader": "elf",
                "function_count": len(FUNCS),
                "image_base": "0x400000",
                "base_address": "0x400000",
                "min_address": "0x400000",
                "max_address": "0x403000",
                "main_address": "0x401000",
                "input_file_path": STATE["open"],
                "input_file_size": 4096,
            }
        )
    if name == "list_functions":  # FunctionListResult {functions[{address,name,size}], total}
        flt = args.get("filter")
        rows = [
            {"address": hex(f["address"]), "name": f["name"], "size": f["size"]}
            for f in FUNCS
            if not flt or flt in f["name"]
        ]
        return _rust_typed({"functions": rows[: int(args.get("limit", 100))], "total": len(rows)})
    if name in {"decompile", "disasm_function_at", "xrefs_to", "xrefs_from", "basic_blocks"}:
        address = str(args.get("address") or "")
        if name != "disasm_function_at" and not address.lower().startswith("0x"):
            # server/mod.rs parse_address: numeric addresses only; a symbol is an InvalidAddress.
            return _error(f"Invalid address: {address!r} looks like a symbol name; pass its address")
        fn = _fn(args.get("address") or args.get("target_name"))
        if fn is None:
            return _error(f"Function not found: {args.get('address') or args.get('target_name')}")
        start = fn["address"]
        if name == "decompile":  # single address: Content::text(code)
            return _text(f"__int64 __fastcall {fn['name']}()\n{{\n  return 0LL;\n}}")
        if name == "disasm_function_at":  # handlers/disasm.rs: "{:#x}:\t{line}" per instruction, at most `count`
            lines = [f"{start:#x}:\tpush    rbp", f"{start + 1:#x}:\tretn"]
            return _text("\n".join(lines[: int(args.get("count") or 200)]))
        if name == "basic_blocks":  # Vec<BasicBlockInfo> as a pretty JSON array
            return _rust_pretty(
                [
                    {
                        "start": hex(start),
                        "end": hex(start + fn["size"]),
                        "size": fn["size"],
                        "block_type": "normal",
                        "successors": [],
                        "predecessors": [],
                    }
                ]
            )
        if name == "xrefs_to":  # XRefListResult {xrefs[{from,to,type,is_code}], truncated}
            site = CALLS.get(fn["name"])
            xrefs = [{"from": hex(site), "to": hex(start), "type": "call", "is_code": True}] if site else []
            return _rust_typed({"xrefs": xrefs, "truncated": False})
        return _rust_typed(
            {"xrefs": [{"from": hex(start + 8), "to": "0x401040", "type": "call", "is_code": True}], "truncated": False}
        )
    if name == "strings":  # StringListResult {strings[{address,content,length}], total}
        return _rust_typed(
            {"strings": [{"address": "0x402000", "content": GREETING, "length": len(GREETING)}], "total": 1}
        )
    if name == "imports":  # Vec<ImportInfo{address,name,ordinal}>: no module field upstream
        return _rust_pretty([{"address": "0x403000", "name": "puts", "ordinal": 0}])
    if name == "exports":  # Vec<ExportInfo{address,name,is_public}>
        return _rust_pretty([{"address": "0x401000", "name": "main", "is_public": True}])
    return _error(f"unknown tool {name}")


# -- Binary Ninja bridge ---------------------------------------------------------------------------
def _binja_view() -> str:
    return os.environ.get("MOCK_BINJA_VIEW", "C:\\samples\\nexus_fixture.elf")


def _binja_file() -> str:
    # tools.ts getActiveFilename(); MOCK_BINJA_PREAMBLE_VIEW simulates the user switching views
    # between the status check and the call.
    return os.environ.get("MOCK_BINJA_PREAMBLE_VIEW") or _binja_view() or "(none)"


def _binja_http_error(endpoint: str) -> str:
    # client.ts getText() -> handleError(): axios throws for a non-2xx plugin response.
    return f"Error: GET {endpoint} failed: Server returned 500: Internal Server Error"


_BINJA_ENDPOINT = {
    "list_methods": "methods",
    "search_functions_by_name": "searchFunctions",
    "function_at": "functionAt",
    "get_xrefs_to": "getXrefsTo",
    "list_strings": "strings",
    "list_strings_filter": "strings/filter",
    "list_imports": "imports",
    "list_exports": "exports",
    "get_binary_status": "status",
}
_BINJA_PREAMBLE = {"list_methods"}  # getLines tools that prefix "File: <name>\n"
_BINJA_CODE = {"decompile_function", "fetch_disassembly"}  # getJson tools: "File: <name>\n\n<body>"


def _binja_answer(name: str, body: str) -> CallToolResult:
    if name in _BINJA_PREAMBLE:
        return _text(f"File: {_binja_file()}\n{body}")
    if name in _BINJA_CODE:
        return _text(f"File: {_binja_file()}\n\n{body}")
    return _text(body)


def _binja(name: str, args: dict[str, Any]) -> CallToolResult:
    if name == os.environ.get("MOCK_ERROR_TOOL"):
        # The bridge never sets isError: getLines tools carry the HTTP failure as text, getJson
        # tools as "Error: <message>".
        if name in _BINJA_CODE:
            return _binja_answer(name, "Error: Function not found")
        return _binja_answer(name, _binja_http_error(_BINJA_ENDPOINT.get(name, name)))
    if name == os.environ.get("MOCK_GARBAGE_TOOL"):
        return _binja_answer(name, _garbage())
    if name == "get_binary_status":  # lines[0] of the plugin's /status JSON
        view = _binja_view()
        return _text(_plugin_json({"loaded": bool(view), "filename": view or None}))
    if name in {"rename_function", "patch_bytes", "set_comment", "select_binary", "frobnicate_view"}:
        return _text(f"{name}: side effect performed")
    if not _binja_view():
        return _binja_answer(name, _binja_http_error(_BINJA_ENDPOINT.get(name, name)))
    if name == "list_methods":  # /methods -> {"functions": [{name, address, raw_name}]}
        rows = [{"name": f["name"], "address": hex(f["address"]), "raw_name": f["name"]} for f in FUNCS]
        return _binja_answer(name, _plugin_json({"functions": rows}))
    if name == "search_functions_by_name":  # /searchFunctions -> {"matches": [{name, address}]}
        query = str(args.get("query", ""))
        rows = [{"name": f["name"], "address": hex(f["address"])} for f in FUNCS if query in f["name"]]
        return _binja_answer(name, _plugin_json({"matches": rows}))
    if name == "function_at":  # /functionAt -> {"address", "functions": [names]}
        address = int(str(args.get("address", "0")), 16)
        names = [f["name"] for f in FUNCS if f["address"] <= address < f["address"] + f["size"]]
        if os.environ.get("MOCK_BINJA_OVERLAP") and names:
            names.append(names[0] + "_thunk")
        return _binja_answer(name, _plugin_json({"address": hex(address), "functions": names}))
    if name == "decompile_function":
        fn = _fn(args.get("name"))
        if fn is None:
            return _binja_answer(name, "Error: Function not found")
        return _binja_answer(name, f"int64_t {fn['name']}()\n{{\n    return 0;\n}}")
    if name == "fetch_disassembly":  # plugin: f"{addr:08x}  {bytes:<16} {disasm}"
        fn = _fn(args.get("name"))
        if fn is None:
            return _binja_answer(name, "Error: Function not found")
        start = fn["address"]
        lines = [f"{start:08x}  {'55'.ljust(16)} push    rbp", f"{start + 1:08x}  {'c3'.ljust(16)} retn"]
        return _binja_answer(name, "\n".join(lines))
    if name == "get_xrefs_to":  # /getXrefsTo -> {address, code_references[{function,address}], data_references}
        fn = _fn(args.get("address"))
        site = CALLS.get(fn["name"]) if fn else None
        code = [{"function": "main", "address": hex(site)}] if site else []
        return _binja_answer(
            name,
            _plugin_json({"address": args.get("address"), "code_references": code, "data_references": []}),
        )
    if name in {"list_strings", "list_strings_filter"}:  # {"strings": [{address, length, type, value}]}
        wanted = str(args.get("filter", "")).lower()
        rows = [{"address": "0x402000", "length": len(GREETING), "type": "ascii", "value": GREETING}]
        rows = [r for r in rows if wanted in r["value"].lower()]
        body: dict[str, Any] = {"strings": rows}
        if name == "list_strings_filter":
            body["total"] = len(rows)
        return _binja_answer(name, _plugin_json(body))
    if name == "list_imports":  # {"imports": [{name, address, raw_name, full_name}]}
        rows = [
            {"name": n, "address": a, "raw_name": n, "full_name": n}
            for n, a in (("puts", "0x403000"), ("printf", "0x403008"))
        ]
        return _binja_answer(name, _plugin_json({"imports": rows}))
    if name == "list_exports":
        return _binja_answer(name, _plugin_json({"exports": [{"name": "main", "address": "0x401000"}]}))
    return _text(f"Error: unknown tool {name}")


# -- jadx-mcp-server -------------------------------------------------------------------------------
JADX_CLASSES = ["com.example.nexus.MainActivity", "com.example.nexus.KeyCheck"]
JADX_SOURCE = (
    "package com.example.nexus;\n\n"
    'public class KeyCheck {\n    // {"looks": "like JSON"}\n    boolean ok(int k) { return k == 0x1337; }\n}'
)
JADX_COMPONENT = {
    "name": "com.example.nexus.MainActivity",
    "type": "activity",
    "is_main": True,
    "is_browsable": False,
    "exported": True,
    "exported_reason": "has MAIN/LAUNCHER intent filter",
    "intent_filters": [{"actions": ["android.intent.action.MAIN"], "categories": [], "data": []}],
}


def _jadx_tool(name: str, args: dict[str, Any]) -> CallToolResult:
    if name == "load_apk":
        path = Path(args.get("apkPath", ""))
        if path.suffix.lower() != ".apk" or not path.is_file():
            return _error(f"Error executing tool load_apk: not an APK: {path.name}")
        STATE["open"] = path.name
        # JadxAnalyzerCore.getApkInfo (core/JadxAnalyzerCore.java:509-519): apkPath is echoed verbatim.
        return _jadx(
            {
                "apkPath": os.environ.get("MOCK_JADX_LOADED_PATH") or args.get("apkPath"),
                "packageName": "com.example.nexus",
                "totalClasses": len(JADX_CLASSES),
                "exportedComponents": 1,
                "mainActivity": "com.example.nexus.MainActivity",
            }
        )
    if name in {"rename_class", "frobnicate_apk"}:
        return _jadx(f"{name}: side effect performed")
    if STATE["open"] is None:
        return _error(f"Error executing tool {name}: no APK loaded")
    partial = bool(os.environ.get("MOCK_JADX_PARTIAL"))
    if name == "get_android_manifest":  # str -> JSON-encoded string literal
        return _jadx('<manifest package="com.example.nexus">\n  <application android:label="Nexus"/>\n</manifest>')
    if name == "get_main_activity_class":
        return _jadx("com.example.nexus.MainActivity")
    if name == "get_exported_components":
        return _jadx([JADX_COMPONENT, {"@truncated": "1 of 2 shown"}] if partial else [JADX_COMPONENT])
    if name == "get_deeplink_components":
        return _jadx([JADX_COMPONENT])
    if name == "get_all_classes":
        prefix = args.get("packagePrefix") or ""
        names = [c for c in JADX_CLASSES if c.lower().startswith(prefix.lower())]
        if partial:
            names = names[:1] + ["@truncated: 1 of 2 class names shown"]
        return _jadx(names)
    if name == "get_class_source":
        cls = str(args.get("className"))
        if cls != "com.example.nexus.KeyCheck":
            return _error(f"Error executing tool get_class_source: Class not found: {cls}")
        if partial:
            return _jadx("@outline: class exceeds maxBytes; fields and method signatures only\n" + JADX_SOURCE)
        return _jadx(JADX_SOURCE)
    if name == "search_classes_by_keyword":
        keyword = str(args.get("keyword", "")).lower()
        return _jadx([c for c in JADX_CLASSES if keyword in c.lower()])
    if name == "search_method_by_name":
        return _jadx({"com.example.nexus.KeyCheck": [f"boolean {args.get('methodName')}(int)"]})
    return _error(f"Error executing tool {name}: unknown tool")


HANDLERS = {"ida_rs": _ida, "binja": _binja, "jadx": _jadx_tool}


async def on_list_tools(ctx, params) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


async def on_call_tool(ctx, params) -> CallToolResult:
    name, args = params.name, params.arguments or {}
    CURRENT["tool"] = name
    _log(name, args)
    if name == os.environ.get("MOCK_SLOW_TOOL"):
        await anyio.sleep(float(os.environ.get("MOCK_SLOW_SECONDS", "30")))
    if name == os.environ.get("MOCK_CRASH_TOOL"):
        sys.stdout.flush()
        os._exit(3)
    if PROFILE != "binja":  # the Binary Ninja profile reproduces its textual failures itself
        if name == os.environ.get("MOCK_ERROR_TOOL"):
            return _error(f"mock failure in {name}")
        if PROFILE == "ida_rs" and name == os.environ.get("MOCK_GARBAGE_TOOL"):
            kind = os.environ.get("MOCK_GARBAGE_KIND", "object")
            garbage = _garbage()
            return _rust_typed(json.loads(garbage)) if kind in {"object", "list_of_strings"} else _text(garbage)
    return HANDLERS[PROFILE](name, args)


async def main() -> None:
    server = Server(f"mock-{PROFILE}", version="mock-1", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
