"""Mock stdio MCP server with a process tree, for lifecycle tests. Never analyses anything.

At start it spawns a child that spawns a grandchild (both bounded ``sleep``-style processes) and
writes ``{"server": pid, "child": pid, "grandchild": pid}`` to ``MOCK_TREE_PIDS``. Then, by
``MOCK_TREE_MODE``:

* ``graceful`` (default): serves MCP and exits as soon as stdin reaches EOF, leaving its
  descendants behind, the behaviour of a well-behaved server whose workers outlive it;
* ``stubborn``: ignores SIGTERM and keeps running after stdin EOF (needs a SIGKILL);
* ``hang``: never answers the MCP handshake (startup cancellation and timeouts).

Tools: ``echo`` returns its ``text`` argument unchanged (framing round trips); ``initial_environ``
returns the environment block the process was started with (Linux ``/proc/self/environ``, read
before Python's own start-up changes such as locale coercion) as JSON.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

# Bounded lifetimes: even if a test failed to clean up, nothing outlives two minutes.
_CHILD = (
    "import subprocess, sys, time\n"
    "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    "print(gc.pid, flush=True)\n"
    "time.sleep(120)\n"
)


def _spawn_tree() -> dict[str, int]:
    child = subprocess.Popen([sys.executable, "-c", _CHILD], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    assert child.stdout is not None
    grandchild = int(child.stdout.readline())
    return {"server": os.getpid(), "child": child.pid, "grandchild": grandchild}


async def on_list_tools(ctx, params) -> ListToolsResult:
    schema = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}
    return ListToolsResult(
        tools=[
            Tool(name="echo", description="echo text", input_schema=schema),
            Tool(name="initial_environ", description="start-up environment", input_schema={"type": "object"}),
        ]
    )


def _initial_environ() -> str:
    raw = Path("/proc/self/environ").read_bytes()
    pairs = (entry.partition(b"=") for entry in raw.split(b"\0") if entry)
    return json.dumps({os.fsdecode(k): os.fsdecode(v) for k, _, v in pairs})


async def on_call_tool(ctx, params) -> CallToolResult:
    if params.name == "initial_environ":
        return CallToolResult(content=[TextContent(type="text", text=_initial_environ())])
    return CallToolResult(content=[TextContent(type="text", text=(params.arguments or {})["text"])])


async def main() -> None:
    mode = os.environ.get("MOCK_TREE_MODE", "graceful")
    pids = _spawn_tree()
    path = Path(os.environ["MOCK_TREE_PIDS"])
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(pids), encoding="utf-8")
    tmp.replace(path)  # readers never see a partial file
    if mode == "stubborn":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode == "hang":
        time.sleep(120)
        return
    server = Server("tree", version="1", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
    if mode == "stubborn":
        time.sleep(120)


if __name__ == "__main__":
    asyncio.run(main())
