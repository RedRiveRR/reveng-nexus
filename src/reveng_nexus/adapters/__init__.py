"""Registry of upstream adapters, keyed by the ``adapter`` field in provider config."""

from __future__ import annotations

from .base import McpAdapter, UpstreamPin, parse_address
from .mcpyghidra import MCPYGHIDRA
from .others import BINJA, FRIDA, IDA_OFFICIAL, IDA_RS, JADX
from .re_mcp import RE_MCP

ADAPTERS: dict[str, McpAdapter] = {
    adapter.name: adapter for adapter in (RE_MCP, MCPYGHIDRA, IDA_OFFICIAL, IDA_RS, BINJA, JADX, FRIDA)
}


def get_adapter(name: str | None) -> McpAdapter | None:
    if not name:
        return None
    if name not in ADAPTERS:
        from ..errors import ConfigError

        raise ConfigError(f"unknown adapter {name!r}; known adapters: {sorted(ADAPTERS)}")
    return ADAPTERS[name]


__all__ = ["ADAPTERS", "McpAdapter", "UpstreamPin", "get_adapter", "parse_address"]
