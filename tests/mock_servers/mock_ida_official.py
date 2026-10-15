"""Minimal stdio MCP server listing the 6 pinned ida_official tools (snapshot names). Never runs IDA."""

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

S = {"type": "object", "properties": {}}
TOOLS = [
    Tool(name=n, description=n, input_schema=S)
    for n in ("reference", "list_databases", "open_database", "close_database", "save_database", "execute_python")
]


async def on_list_tools(ctx, params):
    return ListToolsResult(tools=TOOLS)


async def on_call_tool(ctx, params):
    return CallToolResult(content=[TextContent(type="text", text="[]")])


async def main():
    server = Server("mock-ida-official", version="mock-1", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


asyncio.run(main())
