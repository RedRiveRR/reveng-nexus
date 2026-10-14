"""Mock analysis engine speaking real MCP (SDK 2.x) over stdio, mimicking the re-mcp
tool contract that was runtime-verified against re-mcp-ghidra 3.0.3.

Behaviour switches (environment variables):
  MOCK_FLAVOR=a|b          b emits pseudocode that disagrees for ``main`` (different callee)
  MOCK_BASE_SHIFT=0x...    report every address shifted by this amount (different load base)
  MOCK_SLOW_TOOL / MOCK_SLOW_SECONDS   sleep inside one tool (timeout tests)
  MOCK_CRASH_TOOL          exit the process abruptly inside one tool (crash isolation tests)
  MOCK_ERROR_TOOL          return isError for one tool
  MOCK_PAGE_SIZE           tools/list page size (pagination tests)
  MOCK_SLOW_LIST_AFTER / MOCK_SLOW_LIST_SECONDS   after N complete listings, sleep before every page
  MOCK_PID_FILE            write this process's pid here (process-cleanup tests)
It only *reads* the file handed to open_database; nothing is executed.
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

FLAVOR = os.environ.get("MOCK_FLAVOR", "a")
SHIFT = int(os.environ.get("MOCK_BASE_SHIFT", "0"), 0)
PAGE = int(os.environ.get("MOCK_PAGE_SIZE", "0"))
DATABASES: dict[str, dict[str, Any]] = {}

RO = ToolAnnotations(read_only_hint=True)
MUT = ToolAnnotations(read_only_hint=False)
DESTR = ToolAnnotations(read_only_hint=False, destructive_hint=True)


def _schema(*props: str, required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": {p: {} for p in props}, "required": list(required)}


TOOLS = [
    Tool(
        name="open_database",
        description="Open a binary",
        input_schema=_schema("file_path", "database_id", "run_auto_analysis", "keep_open", required=("file_path",)),
        annotations=MUT,
    ),
    Tool(
        name="wait_for_analysis",
        description="Wait for a database",
        input_schema=_schema("database", "databases"),
        annotations=MUT,
    ),
    Tool(
        name="close_database",
        description="Close a database",
        input_schema=_schema("database", "save", "force"),
        annotations=MUT,
    ),
    Tool(
        name="get_database_info",
        description="Database metadata",
        input_schema=_schema("database", required=("database",)),
        annotations=RO,
    ),
    Tool(
        name="list_functions",
        description="List functions",
        input_schema=_schema("database", "offset", "limit", "filter_pattern"),
        annotations=RO,
    ),
    Tool(
        name="decompile_function",
        description="Decompile a function",
        input_schema=_schema("address", "database", required=("address",)),
        annotations=RO,
    ),
    Tool(
        name="disassemble_function",
        description="Disassemble a function",
        input_schema=_schema("address", "database"),
        annotations=RO,
    ),
    Tool(
        name="get_xrefs_to",
        description="Xrefs to",
        input_schema=_schema("address", "database", "offset", "limit"),
        annotations=RO,
    ),
    Tool(
        name="get_xrefs_from",
        description="Xrefs from",
        input_schema=_schema("address", "database", "offset", "limit"),
        annotations=RO,
    ),
    Tool(
        name="get_basic_blocks", description="Basic blocks", input_schema=_schema("address", "database"), annotations=RO
    ),
    Tool(
        name="get_strings",
        description="Strings",
        input_schema=_schema("database", "offset", "limit", "filter_pattern", "min_length"),
        annotations=RO,
    ),
    Tool(
        name="get_imports", description="Imports", input_schema=_schema("database", "offset", "limit"), annotations=RO
    ),
    Tool(
        name="get_exports", description="Exports", input_schema=_schema("database", "offset", "limit"), annotations=RO
    ),
    Tool(
        name="rename_function",
        description="Rename a function",
        input_schema=_schema("address", "new_name", "database"),
        annotations=MUT,
    ),
    Tool(
        name="patch_bytes",
        description="Patch bytes",
        input_schema=_schema("address", "hex_bytes", "database"),
        annotations=DESTR,
    ),
    Tool(
        name="call",
        description="Meta-tool: call any tool by name",
        input_schema=_schema("tool", "params"),
        annotations=RO,
    ),
]

PSEUDO = {
    "a": {
        "main": "undefined8 main(void)\n{\n  undefined4 uVar1;\n  \n  uVar1 = add_numbers(2,3);\n  check_key(uVar1);\n  get_greeting();\n  return 0;\n}\n",
        "check_key": "bool check_key(int param_1)\n{\n  return param_1 == 0x1337;\n}\n",
        "add_numbers": "int add_numbers(int param_1,int param_2)\n{\n  return param_1 + param_2;\n}\n",
        "get_greeting": 'char * get_greeting(void)\n{\n  return "Hello from the RevEng Nexus fixture";\n}\n',
    },
    "b": {
        "main": "int main(void)\n{\n  int r = add_numbers(2, 3);\n  validate_key(r);\n  return 0;\n}\n",
        "check_key": "bool check_key(int x)\n{\n  return x == 0x1337;\n}\n",
        "add_numbers": "int add_numbers(int a, int b)\n{\n  return a + b;\n}\n",
        "get_greeting": 'const char *get_greeting(void)\n{\n  return "Hello from the RevEng Nexus fixture";\n}\n',
    },
}


def _ok(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(payload))], structured_content=payload)


def _err(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=json.dumps({"error": message}))], is_error=True)


def _load(path: str) -> dict[str, Any]:
    from reveng_nexus.formats import inspect_file

    data = Path(path).read_bytes()
    meta = inspect_file(Path(path), data)
    return {"meta": meta, "data": data}


def _resolve(db: dict[str, Any], ref: str) -> dict[str, Any] | None:
    funcs = db["meta"].get("functions", [])
    if ref.lower().startswith("0x"):
        addr = int(ref, 16) - SHIFT
        return next((f for f in funcs if f["address"] == addr), None)
    return next((f for f in funcs if f["name"] == ref), None)


def _page(items: list[Any], args: dict[str, Any]) -> dict[str, Any]:
    offset, limit = int(args.get("offset", 0)), int(args.get("limit", 100))
    window = items[offset : offset + limit]
    return {
        "items": window,
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < len(items),
    }


LISTINGS = {"started": 0}


async def on_list_tools(ctx, params) -> ListToolsResult:
    if params is None or not params.cursor:
        LISTINGS["started"] += 1
    if LISTINGS["started"] > int(os.environ.get("MOCK_SLOW_LIST_AFTER", "1000000")):
        await anyio.sleep(float(os.environ.get("MOCK_SLOW_LIST_SECONDS", "30")))
    subset = os.environ.get("MOCK_TOOLS_SUBSET")
    if subset:
        # Mimics re-mcp-ghidra with a broken engine backend: only meta/lifecycle tools are listed.
        names = set(subset.split(","))
        return ListToolsResult(tools=[t for t in TOOLS if t.name in names])
    if not PAGE:
        return ListToolsResult(tools=TOOLS)
    start = int(params.cursor) if params is not None and params.cursor else 0
    chunk = TOOLS[start : start + PAGE]
    nxt = str(start + PAGE) if start + PAGE < len(TOOLS) else None
    return ListToolsResult(tools=chunk, next_cursor=nxt)


async def on_call_tool(ctx, params) -> CallToolResult:
    name, args = params.name, params.arguments or {}
    if name == os.environ.get("MOCK_SLOW_TOOL"):
        await anyio.sleep(float(os.environ.get("MOCK_SLOW_SECONDS", "30")))
    if name == os.environ.get("MOCK_CRASH_TOOL"):
        sys.stdout.flush()
        os._exit(3)
    if name == os.environ.get("MOCK_ERROR_TOOL"):
        return _err(f"mock failure in {name}")
    if name == "open_database":
        db_id = args.get("database_id") or Path(args["file_path"]).stem
        DATABASES[db_id] = _load(args["file_path"])
        DATABASES[db_id]["force_new"] = bool(args.get("force_new"))
        return _ok({"status": "opening", "database": db_id, "opening": True})
    if name == "wait_for_analysis":
        db_id = args.get("database")
        if db_id not in DATABASES:
            return _err("The 'database' parameter is required.")
        if os.environ.get("MOCK_STALE_PROJECT") and not DATABASES[db_id]["force_new"]:
            # mimics re-mcp-ghidra reopening a half-written project left by an interrupted session
            return _err("Failed to open database: java.io.FileNotFoundException: File not found: //x.elf")
        meta = DATABASES[db_id]["meta"]
        return _ok(
            {
                "status": "ready",
                "database": db_id,
                "processor": "x86:LE:64:default",
                "bitness": 64,
                "file_type": "Executable and Linking Format (ELF)",
                "function_count": len(meta.get("functions", [])),
            }
        )
    if name == "close_database":
        DATABASES.pop(args.get("database"), None)
        return _ok({"status": "closed"})
    db = DATABASES.get(args.get("database", ""))
    if name in {"rename_function", "patch_bytes", "call"}:
        return _ok({"status": "mutated", "tool": name})
    if db is None:
        return _err("Database not open")
    meta = db["meta"]
    funcs = meta.get("functions", [])
    if name == "get_database_info":
        return _ok(
            {
                "processor": "x86:LE:64:default",
                "bitness": 64,
                "image_base": hex(meta["image_base"] + SHIFT),
                "function_count": len(funcs),
                "file_type": "ELF",
            }
        )
    if name == "list_functions":
        pattern = args.get("filter_pattern")
        rows = [
            {
                "name": f["name"],
                "start": hex(f["address"] + SHIFT),
                "end": hex(f["address"] + SHIFT + f["size"]),
                "size": f["size"],
            }
            for f in funcs
            if not pattern or pattern in f["name"]
        ]
        return _ok(_page(rows, args))
    if name in {"decompile_function", "disassemble_function", "get_basic_blocks", "get_xrefs_to", "get_xrefs_from"}:
        fn = _resolve(db, str(args.get("address", "")))
        if fn is None:
            return _err(f"no function at {args.get('address')}")
        addr = fn["address"] + SHIFT
        if name == "decompile_function":
            code = PSEUDO[FLAVOR].get(fn["name"], f"void {fn['name']}(void)\n{{\n  return;\n}}\n")
            return _ok({"function_name": fn["name"], "address": hex(addr), "decompiled_code": code})
        if name == "disassemble_function":
            import capstone

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            off = fn["address"] - meta["image_base"]
            insns = [
                {
                    "address": hex(i.address + SHIFT),
                    "bytes": i.bytes.hex(),
                    "mnemonic": i.mnemonic,
                    "operands": i.op_str if i.mnemonic != "call" else hex(int(i.op_str, 16) + SHIFT),
                }
                for i in md.disasm(db["data"][off : off + fn["size"]], fn["address"])
            ]
            return _ok({"function_name": fn["name"], "address": hex(addr), "instructions": insns})
        if name == "get_basic_blocks":
            return _ok({"blocks": [{"start": hex(addr), "end": hex(addr + fn["size"]), "successors": []}]})
        if name == "get_xrefs_to":
            callers = [f for f in funcs if f["name"] == "main"] if fn["name"] != "main" else []
            return _ok(
                _page(
                    [
                        {
                            "from_address": hex(c["address"] + SHIFT + 0xE),
                            "from_function": c["name"],
                            "ref_type": "UNCONDITIONAL_CALL",
                            "is_call": True,
                        }
                        for c in callers
                    ],
                    args,
                )
            )
        return _ok(_page([], args))
    if name == "get_strings":
        from reveng_nexus.formats.strings import extract_strings

        found = extract_strings(db["data"], meta, min_length=int(args.get("min_length", 6)))["strings"]
        rows = [
            {"address": hex(s["address"] + SHIFT), "value": s["value"], "length": s["length"], "type": "string"}
            for s in found
            if "address" in s
        ]
        return _ok(_page(rows, args))
    if name in {"get_imports", "get_exports"}:
        return _ok(_page([], args))
    return _err(f"unknown tool {name}")


async def main() -> None:
    # MOCK_STARTUP_DELAY simulates a slow engine start (uvx install + JVM) before the MCP handshake.
    if os.environ.get("MOCK_PID_FILE"):
        Path(os.environ["MOCK_PID_FILE"]).write_text(str(os.getpid()), encoding="utf-8")
    await anyio.sleep(float(os.environ.get("MOCK_STARTUP_DELAY", "0")))
    server = Server("mock-engine", version=f"mock-{FLAVOR}", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
