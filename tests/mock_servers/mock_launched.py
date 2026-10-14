"""Mock 'launch then connect' MCP server mimicking mcpyghidra-headless 0.8.0's contract:
``mock_launched.py <binary> --port 0`` prints log noise, then a JSON readiness line on
stdout, then serves Streamable HTTP at /mcp. Tool payloads are JSON *text* blocks.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
from pathlib import Path

from mcp.server import Server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations

RO = ToolAnnotations(read_only_hint=True)


def _schema(*props: str) -> dict:
    return {"type": "object", "properties": {p: {} for p in props}}


TOOLS = [
    Tool(name="context", description="Binary context", input_schema=_schema(), annotations=RO),
    Tool(
        name="list",
        description="List entries",
        input_schema=_schema("entry_type", "offset", "limit", "match_filter"),
        annotations=RO,
    ),
    Tool(name="decompile", description="Decompile", input_schema=_schema("addr", "name", "items"), annotations=RO),
    Tool(name="disasm", description="Disassemble", input_schema=_schema("addr", "name", "count"), annotations=RO),
    Tool(name="xrefs", description="Xrefs", input_schema=_schema("target", "direction", "limit"), annotations=RO),
    Tool(name="cfg", description="CFG", input_schema=_schema("address"), annotations=RO),
    Tool(name="pyghidra", description="Run Python", input_schema=_schema("code"), annotations=ToolAnnotations()),
    Tool(name="rename", description="Rename", input_schema=_schema("addr", "new_name"), annotations=ToolAnnotations()),
]


def build_server(binary: Path) -> Server:
    from reveng_nexus.formats import inspect_file

    meta = inspect_file(binary)
    funcs = meta["functions"]

    def text(payload) -> CallToolResult:
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(payload, indent=2))])

    async def on_list_tools(ctx, params):
        return ListToolsResult(tools=TOOLS)

    async def on_call_tool(ctx, params):
        name, args = params.name, params.arguments or {}
        if name == "context":
            return text(
                {
                    "architecture": {"processor": "x86", "bitness": 64, "endianness": "little"},
                    "memory": {"image_base": hex(meta["image_base"]), "entry_point": hex(meta["entry_point"])},
                    "program": {"file_format": "ELF"},
                    "analysis": {"function_count": len(funcs)},
                    "application": {"name": "Ghidra", "version": "mock"},
                }
            )
        if name == "list":
            if args.get("entry_type") == "function":
                items = [{"type": "function", "name": f["name"], "addr": hex(f["address"])} for f in funcs]
            else:
                items = []
            return text({"items": items, "page_info": {"has_more": False}})
        if name == "decompile":
            fn = next(
                (f for f in funcs if f["name"] == args.get("name") or hex(f["address"]) == args.get("addr")), None
            )
            if fn is None:
                return text({"error": "not found", "code": None})
            body = "  add_numbers(2,3);\n  check_key(5);\n  get_greeting();\n" if fn["name"] == "main" else ""
            return text(
                {
                    "name": fn["name"],
                    "entrypoint": hex(fn["address"]),
                    "code": f"\r\nundefined8 {fn['name']}(void)\r\n{{\r\n{body}  return 0;\r\n}}\r\n",
                    "error": None,
                }
            )
        if name == "disasm":
            return text(
                {
                    "addr": args.get("addr"),
                    "name": args.get("name"),
                    "mode": "function",
                    "asm": "400119: 48 83 EC 08          SUB RSP,0x8\n400127: E8 D4 FF FF FF       CALL 0x00400100",
                }
            )
        if name == "xrefs":
            return text(
                {
                    "direction": "to",
                    "addr": args.get("target"),
                    "items": [{"from": {"addr": "0x400127", "function": "main"}, "xref-type": "UNCONDITIONAL_CALL"}],
                }
            )
        if name == "cfg":
            return text(
                {
                    "entry": args.get("address"),
                    "blocks": {"0x400119": {"address": "0x400119", "size": 38, "successors": []}},
                }
            )
        return text({"status": "mutated", "tool": name})

    return Server("ghidra-mcp-mock", version="mock", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="0")
    parser.add_argument("--project-dir")
    parser.add_argument("--fail", action="store_true")
    parser.add_argument("--spawn-child", help="start a sleeping grandchild and write its pid here")
    parser.add_argument("--initialize-delay", type=float, default=0.0, help="delay the first MCP POST (initialize)")
    args = parser.parse_args()
    print("decaf_load() started", flush=True)  # noise before readiness, like the real server
    print("Registering plugins...", flush=True)
    if args.spawn_child:
        import subprocess

        # Mimics uvx/launcher chains: the process that really holds resources is a grandchild.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        Path(args.spawn_child).write_text(str(child.pid), encoding="utf-8")
    if args.fail:
        print(json.dumps({"status": "error", "reason": "open_failed", "detail": "mock failure"}), flush=True)
        sys.exit(7)
    server = build_server(Path(args.binary))
    app = server.streamable_http_app(host=args.host)
    if args.initialize_delay:
        inner, pending = app, {"first_post": True}

        async def delayed(scope, receive, send):
            # A slow engine that is "ready" (port open) but answers its first MCP request late.
            if scope["type"] == "http" and scope.get("method") == "POST" and pending["first_post"]:
                pending["first_post"] = False
                await asyncio.sleep(args.initialize_delay)
            await inner(scope, receive, send)

        app = delayed
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.host, int(args.port)))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, host=args.host, port=port, log_level="warning", lifespan="on")
    uv = uvicorn.Server(config)
    print(json.dumps({"status": "ready", "host": args.host, "port": port, "binary": args.binary}), flush=True)
    await uv.serve(sockets=[sock])


if __name__ == "__main__":
    asyncio.run(main())
