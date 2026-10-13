"""Provider implementations and factory."""

from __future__ import annotations

from ..config import ProviderConfig
from .base import (
    OPERATIONS,
    AnalysisProvider,
    OperationResult,
    ProviderHealth,
    ProviderRuntime,
    TargetContext,
    ToolInfo,
)


def create_provider(config: ProviderConfig, runtime: ProviderRuntime) -> AnalysisProvider:
    if config.type == "builtin":
        from .builtin import BuiltinStaticProvider

        return BuiltinStaticProvider(config, runtime)
    if config.type == "llm4decompile":
        from .llm4decompile import Llm4DecompileProvider

        return Llm4DecompileProvider(config, runtime)
    from .mcp import McpProvider

    return McpProvider(config, runtime)


__all__ = [
    "OPERATIONS",
    "AnalysisProvider",
    "OperationResult",
    "ProviderHealth",
    "ProviderRuntime",
    "TargetContext",
    "ToolInfo",
    "create_provider",
]
