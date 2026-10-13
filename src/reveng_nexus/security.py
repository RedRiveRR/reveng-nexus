"""Name-based tool heuristics. These supplement — never replace — verified adapter
manifests, upstream read-only switches and OS-level isolation."""

from __future__ import annotations

import re
from collections.abc import Iterable

# Conservative regex deny-list kept from the 0.1 scaffold (still applied in read-only mode).
DEFAULT_BLOCKED_TOOL_PATTERNS = (
    r"(^|_)(patch|write_memory|memory_write|write_bytes|delete|remove|rename|edit|modify|inject)(_|$)",
    r"(^|_)(run_script|execute_script|eval|shell|run_command|exec_command)(_|$)",
    r"(^|_)(set_comments?|set_type|set_name|save_idb|apply_patch)(_|$)",
    r"(^|_)(debugger_attach|attach_debugger|start_debugger|continue_execution|step_execution)(_|$)",
    r"(^|_)(bypass|unpin|disable_pinning)(_|$)",
)

READ_VERBS = frozenset(
    {
        "get",
        "list",
        "search",
        "find",
        "read",
        "decompile",
        "disassemble",
        "disasm",
        "xrefs",
        "xref",
        "lookup",
        "query",
        "describe",
        "info",
        "status",
        "fetch",
        "show",
        "resolve",
        "demangle",
        "decode",
        "is",
        "hexdump",
        "function",
        "functions",
        "symbols",
        "strings",
        "imports",
        "exports",
        "segments",
        "sections",
        "entrypoints",
        "cfg",
        "callgraph",
        "callers",
        "callees",
        "basic",
        "addr",
        "address",
        "type",
        "struct",
        "structs",
        "local",
        "pseudocode",
        "render",
        "analysis",
        "idb",
        "tool",
        "reference",
        "convert",
        "format",
        "help",
        "context",
        "cursor",
        "funcs",
    }
)
MUTATE_VERBS = frozenset(
    {
        "patch",
        "write",
        "delete",
        "remove",
        "rename",
        "edit",
        "modify",
        "set",
        "create",
        "add",
        "apply",
        "define",
        "declare",
        "make",
        "undefine",
        "rebase",
        "retype",
        "update",
        "save",
        "load",
        "append",
        "begin",
        "end",
        "take",
        "restore",
        "undo",
        "redo",
        "import",
        "open",
        "close",
        "reanalyze",
        "analyze",
        "assemble",
        "flush",
        "reload",
        "move",
        "copy",
        "insert",
    }
)
EXECUTE_VERBS = frozenset(
    {
        "exec",
        "execute",
        "eval",
        "run",
        "script",
        "shell",
        "command",
        "python",
        "pyghidra",
        "invoke",
        "call",
        "batch",
        "idc",
        "jshell",
    }
)
DYNAMIC_VERBS = frozenset(
    {
        "attach",
        "detach",
        "spawn",
        "launch",
        "hook",
        "trace",
        "debugger",
        "debug",
        "resume",
        "kill",
        "inject",
        "intercept",
        "bypass",
        "instrument",
        "mobile",
        "unhook",
        "stop",
        "scan",
        "memory",
        "process",
    }
)
# Tokens that are dangerous wherever they appear in a tool name.
HARD_DANGER_TOKENS = frozenset(
    {
        "patch",
        "write",
        "delete",
        "exec",
        "execute",
        "eval",
        "script",
        "shell",
        "inject",
        "bypass",
        "attach",
        "spawn",
        "debugger",
    }
)


def tokenize_tool_name(tool_name: str) -> list[str]:
    """Split snake_case / camelCase / kebab-case tool names into lowercase tokens."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", tool_name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def heuristic_tool_class(tool_name: str) -> str:
    """Best-effort classification by verb. Returns read|mutate|execute|dynamic|unknown."""
    tokens = tokenize_tool_name(tool_name)
    if not tokens:
        return "unknown"
    danger = HARD_DANGER_TOKENS.intersection(tokens)
    if danger:
        if danger & {"exec", "execute", "eval", "script", "shell"}:
            return "execute"
        if danger & {"bypass", "attach", "spawn", "debugger", "inject"}:
            return "dynamic"
        return "mutate"
    verb = tokens[0]
    if verb in EXECUTE_VERBS:
        return "execute"
    if verb in DYNAMIC_VERBS:
        return "dynamic"
    if verb in MUTATE_VERBS:
        return "mutate"
    if verb in READ_VERBS:
        return "read"
    return "unknown"


def matches_patterns(tool_name: str, patterns: Iterable[str]) -> bool:
    normalized_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", tool_name)
    for pattern in patterns:
        try:
            if re.search(pattern, normalized_name, flags=re.IGNORECASE):
                return True
        except re.error as exc:
            raise ValueError(f"Invalid blocked-tool regex {pattern!r}: {exc}") from exc
    return False


def is_tool_blocked(
    tool_name: str,
    *,
    read_only: bool,
    configured_patterns: Iterable[str] = (),
) -> bool:
    """Return True when a tool name matches a configured or default deny-list.

    Kept for compatibility; the gateway itself uses :class:`reveng_nexus.policy.PolicyEngine`,
    which also consults verified adapter manifests and tool annotations.
    """
    patterns = tuple(configured_patterns)
    if read_only:
        patterns = (*DEFAULT_BLOCKED_TOOL_PATTERNS, *patterns)
        if heuristic_tool_class(tool_name) in {"mutate", "execute", "dynamic"}:
            return True
    return matches_patterns(tool_name, patterns)
