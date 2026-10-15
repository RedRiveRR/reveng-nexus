"""Adapter for nightwing-us/mcpyghidra (``mcpyghidra-headless``), launched Streamable HTTP.

Runtime-verified on 2026-10-13 with mcpyghidra 0.8.0 + Ghidra 12.1.4 (Windows 11):
the headless launcher imports and analyses one binary, prints a JSON readiness line
(``{"status": "ready", "host", "port"}``) on stdout — preceded by plugin log noise —
then serves MCP at ``http://host:port/mcp``. Tool results are JSON text blocks.
Nexus therefore runs it as ``mcp_launched_http`` with one server per target.
"""

from __future__ import annotations

from typing import Any

from .base import McpAdapter, UpstreamPin, function_ref, parse_address, parse_listing_lines


def _unquote(value: Any) -> Any:
    if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


class McPyGhidraAdapter(McpAdapter):
    async def _list(self, provider, target, entry_type: str, params: dict[str, Any], limit: int):
        items: list[dict[str, Any]] = []
        raws = []
        offset = 0
        while len(items) < limit:
            args: dict[str, Any] = {"entry_type": entry_type, "offset": offset, "limit": min(1000, limit - len(items))}
            if params.get("query"):
                args["match_filter"] = str(params["query"])
            payload, _t, raw = await self.call(provider, target, "list", args)
            raws.append(raw)
            page = (payload or {}).get("items", []) if isinstance(payload, dict) else []
            items.extend(page)
            info = (payload or {}).get("page_info", {}) if isinstance(payload, dict) else {}
            if not page or not info.get("has_more"):
                break
            offset = info.get("next_offset") or offset + len(page)
        return items, raws

    async def op_binary_metadata(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "context", {})
        ctx = payload if isinstance(payload, dict) else {}
        # A section the server reports as null (or not a mapping) is unknown, never a crash.
        arch, memory, app = (
            ctx.get(k) if isinstance(ctx.get(k), dict) else {} for k in ("architecture", "memory", "application")
        )
        normalized = {
            "processor": arch.get("processor"),
            "bits": arch.get("bitness"),
            "endianness": arch.get("endianness"),
            "compiler": arch.get("compiler"),
            "file_format": (ctx.get("program") or {}).get("file_format"),
            "image_base": parse_address(memory.get("image_base")),
            "entry_point": parse_address(memory.get("entry_point")),
            "function_count": (ctx.get("analysis") or {}).get("function_count"),
            "engine_version": f"{app.get('name', 'Ghidra')} {app.get('version', '')}".strip(),
        }
        return self.result(
            provider,
            "binary.metadata",
            "context",
            normalized,
            raw,
            engine_version=normalized["engine_version"],
            claim=f"{normalized['processor']} {normalized['bits']}-bit",
        )

    async def op_binary_functions(self, provider, target, session, params):
        items, raws = await self._list(provider, target, "function", params, int(params.get("limit", 500)))
        functions = [{"name": i.get("name"), "address": parse_address(i.get("addr")), "size": None} for i in items]
        return self.result(
            provider,
            "binary.functions",
            "list",
            {"functions": functions, "total": len(functions), "note": "MCPyGhidra's list does not report sizes"},
            raws,
            claim=f"{len(functions)} functions",
        )

    async def op_binary_decompile(self, provider, target, session, params):
        address, name, _ref = function_ref(params)
        args = {"addr": f"{address:#x}"} if address is not None else {"name": name}
        payload, text, raw = await self.call(provider, target, "decompile", args)
        info = payload if isinstance(payload, dict) else {}
        resolved = parse_address(info.get("entrypoint")) or address
        fname = info.get("name") or name
        code = (info.get("code") or text or "").replace("\r\n", "\n")
        return self.result(
            provider,
            "binary.decompile",
            "decompile",
            {"function": {"name": fname, "address": resolved}, "code": code, "language": "c-like pseudocode"},
            raw,
            subject_type="function",
            subject_address=resolved,
            subject_name=fname,
            claim=f"pseudocode for {fname}",
        )

    async def op_binary_disassemble(self, provider, target, session, params):
        address, name, _ref = function_ref(params)
        args: dict[str, Any] = {"addr": f"{address:#x}"} if address is not None else {"name": name}
        if params.get("count") is not None:
            args["count"] = int(params["count"])
        payload, text, raw = await self.call(provider, target, "disasm", args)
        info = payload if isinstance(payload, dict) else {}
        instructions = parse_listing_lines(str(info.get("asm") or text))
        resolved = parse_address(info.get("addr")) or address
        fname = info.get("name") or name
        return self.result(
            provider,
            "binary.disassemble",
            "disasm",
            {"function": {"name": fname, "address": resolved}, "instructions": instructions, "mode": info.get("mode")},
            raw,
            subject_type="function",
            subject_address=resolved,
            subject_name=fname,
            claim=f"{len(instructions)} instructions",
        )

    async def op_binary_xrefs(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        direction = params.get("direction", "to")
        payload, _t, raw = await self.call(
            provider, target, "xrefs", {"target": ref, "direction": direction, "limit": int(params.get("limit", 200))}
        )
        refs = []
        warnings: list[str] = []
        resolved = parse_address((payload or {}).get("addr")) if isinstance(payload, dict) else None
        subject = resolved if resolved is not None else address
        for item in (payload or {}).get("items", []) if isinstance(payload, dict) else []:
            if not isinstance(item, dict):
                continue
            # Pinned analysis.py: "to" rows carry only "from", "from" rows only "to"; the other end
            # is the queried address (the flat answer's "addr").
            src = item.get("from", {}) if isinstance(item.get("from"), dict) else {}
            dst = item.get("to", {}) if isinstance(item.get("to"), dict) else {}
            refs.append(
                {
                    "from": parse_address(src.get("addr")) if src else subject,
                    "to": parse_address(dst.get("addr")) if dst else subject,
                    "from_function": src.get("function"),
                    "type": item.get("xref-type"),
                    "is_call": "CALL" in str(item.get("xref-type", "")).upper(),
                }
            )
        if isinstance(payload, dict) and (payload.get("page_info") or {}).get("has_more"):
            warnings.append(f"xrefs: more than {len(refs)} references exist; the result is truncated")
        return self.result(
            provider,
            "binary.xrefs",
            "xrefs",
            {"subject": {"address": resolved or address, "name": name}, "direction": direction, "refs": refs},
            raw,
            warnings=warnings,
            subject_type="address" if (resolved or address) is not None else "function",
            subject_address=resolved or address,
            subject_name=name,
            claim=f"{len(refs)} xrefs {direction}",
        )

    async def op_binary_cfg(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        payload, _t, raw = await self.call(provider, target, "cfg", {"address": ref})
        blocks = []
        warnings: list[str] = []
        raw_blocks = (payload or {}).get("blocks") if isinstance(payload, dict) else None
        if not isinstance(raw_blocks, dict):
            # Pinned 0.8.0 (tools/cfg.py, models.CFGResult) returns {hex address: BasicBlock}. Anything
            # else is not that contract; a list index must never become a block address.
            warnings.append(
                f"cfg: blocks is {type(raw_blocks).__name__}, not the pinned {{address: block}} map; see the raw output"
            )
            raw_blocks = {}
        for key, block in raw_blocks.items():
            if not isinstance(block, dict):
                warnings.append(f"cfg: block {str(key)[:40]!r} is not an object and was ignored")
                continue
            start = parse_address(block.get("address", key))
            if start is None:
                warnings.append(f"cfg: block {str(key)[:40]!r} has no parseable address and was ignored")
                continue
            size = block.get("size")
            blocks.append(
                {
                    "start": start,
                    "end": start + size if start is not None and isinstance(size, int) else None,
                    "successors": [parse_address(s) for s in block.get("successors", []) or []],
                    "called": sorted((block.get("called_funcs") or {}).values()),
                }
            )
        entry = parse_address((payload or {}).get("entry")) if isinstance(payload, dict) else None
        return self.result(
            provider,
            "binary.cfg",
            "cfg",
            {"function": {"address": entry or address, "name": name}, "blocks": blocks},
            raw,
            warnings=warnings,
            subject_type="function",
            subject_address=entry or address,
            subject_name=name,
            claim=f"{len(blocks)} basic blocks",
        )

    async def op_binary_strings(self, provider, target, session, params):
        items, raws = await self._list(provider, target, "string", params, int(params.get("limit", 200)))
        strings = [{"address": parse_address(i.get("addr")), "value": _unquote(i.get("value"))} for i in items]
        return self.result(
            provider,
            "binary.strings",
            "list",
            {"strings": strings, "returned": len(strings)},
            raws,
            claim=f"{len(strings)} strings",
        )

    async def op_binary_imports(self, provider, target, session, params):
        items, raws = await self._list(provider, target, "import", {}, int(params.get("limit", 2000)))
        imports = [
            {
                "name": i.get("name"),
                "library": i.get("library") or i.get("namespace"),
                "address": parse_address(i.get("addr")),
            }
            for i in items
        ]
        return self.result(
            provider,
            "binary.imports",
            "list",
            {"imports": imports, "total": len(imports)},
            raws,
            claim=f"{len(imports)} imports",
        )

    async def op_binary_exports(self, provider, target, session, params):
        items, raws = await self._list(provider, target, "export", {}, int(params.get("limit", 2000)))
        exports = [{"name": i.get("name"), "address": parse_address(i.get("addr"))} for i in items]
        return self.result(
            provider,
            "binary.exports",
            "list",
            {"exports": exports, "total": len(exports)},
            raws,
            claim=f"{len(exports)} exports",
        )


MCPYGHIDRA = McPyGhidraAdapter(
    name="mcpyghidra",
    engine="ghidra",
    engine_family="ghidra",
    pin=UpstreamPin(
        repository="https://github.com/nightwing-us/mcpyghidra",
        revision="f1e130cb12bca7fcbadbfa7ad86bb860c651dc3f",
        package="mcpyghidra",
        package_version="0.8.0",
        verified="runtime",
        verified_on="2026-10-13",
        notes="Upstream pins mcp<2; it runs in its own uvx environment.",
    ),
    manifest={
        # Write-capable / code tools per upstream docs/tools-reference.md (v0.8.0).
        "rename": "mutate",
        "update_vars": "mutate",
        "set_comments": "mutate",
        "set_prototype": "mutate",
        "patch": "mutate",
        "begin_trans": "mutate",
        "end_trans": "mutate",
        "create_struct": "mutate",
        "add_field": "mutate",
        "open_program": "lifecycle",  # GUI-only upstream; imports an arbitrary path_or_name (tools/open_program.py)
        "pyghidra": "execute",
    },
    bindings={
        "binary.metadata": ("context",),
        "binary.functions": ("list",),
        "binary.decompile": ("decompile",),
        "binary.disassemble": ("disasm",),
        "binary.xrefs": ("xrefs",),
        "binary.cfg": ("cfg",),
        "binary.strings": ("list",),
        "binary.imports": ("list",),
        "binary.exports": ("list",),
    },
    trust_annotations=True,
    protocol_mode="legacy",
    limitations=(
        "One headless server (JVM) per target; first start includes Ghidra auto-analysis.",
        "Function listings carry no sizes; boundary comparison needs another engine.",
        "On Windows the server is stopped with TerminateProcess, so the project is not saved on exit "
        "(acceptable under read-only policy).",
    ),
)
