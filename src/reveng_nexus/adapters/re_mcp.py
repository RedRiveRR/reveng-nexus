"""Adapter for jtsylve/re-mcp (re-mcp-ghidra / re-mcp-ida), stdio transport.

Runtime-verified on 2026-10-13 with re-mcp-ghidra 3.0.3 + Ghidra 12.1.4 (Windows 11,
JDK 25) against the generated ELF fixture. Observed contract:

* ``open_database(file_path, database_id, run_auto_analysis, keep_open)`` returns
  immediately with status "opening"; ``wait_for_analysis(database=...)`` blocks until
  ready. ``run_auto_analysis`` defaults to **False** upstream — without it function
  bodies, string definitions and many xrefs are missing, so Nexus always passes True.
* Every analysis tool requires ``database``.
* Results are structured JSON (``structured_content``); pagination uses
  ``offset/limit`` with ``has_more``.
"""

from __future__ import annotations

from typing import Any

from ..errors import ProviderCallError
from .base import (
    McpAdapter,
    UpstreamPin,
    fmt_address,
    function_ref,
    note_warning,
    parse_address,
    parse_listing_lines,
)

_LIFECYCLE = {"open_database": "lifecycle", "close_database": "lifecycle", "wait_for_analysis": "lifecycle"}
# Meta-tools proxy to *any* tool (including hidden mutating ones) by name, bypassing
# per-tool classification, so Nexus never forwards them.
_META = {"call": "blocked", "batch": "blocked", "execute": "blocked", "run_script": "execute"}
_EXTRA = {
    "save_database": "mutate",
    "list_databases": "read",
    "list_targets": "read",
    "search_tools": "read",
    "get_schema": "read",
    "reanalyze_range": "mutate",
    "assemble_instruction": "read",  # returns encoded bytes; patching is patch_asm
    "export_all_pseudocode": "read",
    "export_all_disassembly": "read",
    "generate_signatures": "read",
}


class ReMcpAdapter(McpAdapter):
    def database_id(self, sha256: str) -> str:
        return "n" + sha256[:15]

    async def prepare(self, provider, target) -> dict[str, Any]:
        sessions = provider.adapter_state.setdefault("sessions", {})
        if target.sha256 in sessions:
            return sessions[target.sha256]
        staged = target.staged_path(provider.id)
        db = self.database_id(target.sha256)
        warnings: list[str] = []
        try:
            payload, wait_payload = await self._open(provider, target, str(staged), db, force_new=False)
        except ProviderCallError as first:
            # Observed live: a project left in the staging dir by an interrupted session can be
            # unreadable ("File not found: //<name>"). The database lives only in Nexus' private
            # staging directory, so rebuilding it from the staged copy is safe.
            warnings.append(f"existing engine database could not be reopened ({first.message[:160]}); rebuilt it")
            payload, wait_payload = await self._open(provider, target, str(staged), db, force_new=True)
        session = {"database": db, "open": payload, "ready": wait_payload, "warnings": warnings}
        sessions[target.sha256] = session
        return session

    async def perform(self, provider, operation, target, params):
        result = await super().perform(provider, operation, target, params)
        session = provider.adapter_state.get("sessions", {}).get(target.sha256, {})
        if session.get("warnings"):
            result.warnings.extend(session.pop("warnings"))  # reported once, on the next result
        return result

    async def _open(self, provider, target, path: str, db: str, *, force_new: bool) -> tuple[Any, dict[str, Any]]:
        args: dict[str, Any] = {"file_path": path, "database_id": db, "run_auto_analysis": True, "keep_open": True}
        if force_new:
            args["force_new"] = True
        payload, _text, _raw = await self.call(provider, target, "open_database", args)
        wait_payload, _t, _r = await self.call(
            provider,
            target,
            "wait_for_analysis",
            {"database": db},
            timeout=float(provider.config.startup_timeout_seconds),
        )
        if not isinstance(wait_payload, dict) or wait_payload.get("status") != "ready":
            raise ProviderCallError(f"{provider.id}: database did not become ready: {str(wait_payload)[:300]}")
        return payload, wait_payload

    async def release(self, provider, sha256: str) -> None:
        session = provider.adapter_state.setdefault("sessions", {}).pop(sha256, None)
        if not session or provider._owner is None or not provider._owner.alive:
            return
        try:
            # Saving persists *Nexus' private* engine database (never the target) so the next
            # session can reuse auto-analysis instead of finding a half-written project.
            await provider.call_tool(
                "close_database", {"database": session["database"], "save": True}, internal=True, target_sha256=sha256
            )
        except Exception:  # noqa: BLE001 - best effort; the worker dies with the provider anyway
            pass

    async def _paged(
        self, provider, target, tool: str, args: dict[str, Any], limit: int, meta: dict[str, Any] | None = None
    ) -> tuple[list[dict], list]:
        """Page through a PaginatedResult (re-mcp-core models.py:12-21). ``meta`` receives the
        first page's non-item keys (re-mcp-ida echoes the resolved ``address``)."""
        items: list[dict[str, Any]] = []
        raws = []
        offset = 0
        while len(items) < limit:
            page_args = {**args, "offset": offset, "limit": min(500, limit - len(items))}
            payload, _text, raw = await self.call(provider, target, tool, page_args)
            raws.append(raw)
            page = payload.get("items") if isinstance(payload, dict) else None
            if not isinstance(page, list):
                shape = f"keys {sorted(payload)[:8]}" if isinstance(payload, dict) else type(payload).__name__
                note_warning(f"{tool} returned an unrecognised page ({shape}); the result is empty, see the raw output")
                break
            if meta is not None and offset == 0:
                meta.update({k: v for k, v in payload.items() if k != "items"})
            items.extend(row for row in page if isinstance(row, dict))
            if not page or not payload.get("has_more"):
                break
            offset += len(page)
        else:
            note_warning(f"{tool}: stopped at the requested limit of {limit}; more entries exist")
        return items, raws

    # -- operations ----------------------------------------------------------------
    async def op_binary_metadata(self, provider, target, session, params):
        db = session["database"]
        payload, _text, raw = await self.call(provider, target, "get_database_info", {"database": db})
        info = payload if isinstance(payload, dict) else {}
        ready = session.get("ready", {})
        normalized = {
            "processor": info.get("processor", ready.get("processor")),
            "bits": info.get("bitness", ready.get("bitness")),
            "file_type": info.get("file_type", ready.get("file_type")),
            "function_count": info.get("function_count", ready.get("function_count")),
            # re-mcp-ghidra reports image_base (tools/database.py:32-46); re-mcp-ida has none
            # (re_mcp_ida tools/database.py:67-80), and min_address is not an image base.
            "image_base": parse_address(info.get("image_base")),
            "min_address": parse_address(info.get("min_address")),
            "entry_point": parse_address(info.get("entry_point")),
            "engine_info": {k: v for k, v in info.items() if k not in {"database", "file_path"}},
        }
        return self.result(
            provider,
            "binary.metadata",
            "get_database_info",
            normalized,
            raw,
            claim=f"{normalized['processor']} {normalized['file_type']}",
        )

    async def op_binary_functions(self, provider, target, session, params):
        args: dict[str, Any] = {"database": session["database"]}
        if params.get("query"):
            args["filter_pattern"] = str(params["query"])
        items, raws = await self._paged(provider, target, "list_functions", args, int(params.get("limit", 500)))
        functions = []
        for item in items:
            start = parse_address(item.get("start"))
            end = parse_address(item.get("end"))
            functions.append(
                {
                    "name": item.get("name"),
                    "address": start,
                    "size": item.get("size")
                    if item.get("size") is not None
                    else (end - start if start and end else None),
                    "end": end,
                }
            )
        return self.result(
            provider,
            "binary.functions",
            "list_functions",
            {"functions": functions, "total": len(functions)},
            raws,
            claim=f"{len(functions)} functions",
        )

    async def op_binary_decompile(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        payload, text, raw = await self.call(
            provider, target, "decompile_function", {"address": ref, "database": session["database"]}
        )
        info = payload if isinstance(payload, dict) else {}
        # Ghidra: {function_name, address, decompiled_code} (tools/functions.py:42-45);
        # IDA: {address, name, pseudocode} (re_mcp_ida tools/functions.py:99-104).
        code = next((info[k] for k in ("decompiled_code", "pseudocode") if isinstance(info.get(k), str)), None)
        if code is None:
            if isinstance(payload, (dict, list)):
                # Never present the JSON document itself as pseudocode.
                raise ProviderCallError(
                    f"{provider.id}/decompile_function returned no pseudocode field "
                    f"({sorted(info)[:8] if info else type(payload).__name__})",
                    details={"tool": "decompile_function"},
                )
            code = text
        resolved = parse_address(info.get("address")) or address
        fname = info.get("function_name") or info.get("name") or name
        return self.result(
            provider,
            "binary.decompile",
            "decompile_function",
            {
                "function": {"name": fname, "address": resolved},
                "code": code.replace("\r\n", "\n"),
                "language": "c-like pseudocode",
            },
            raw,
            subject_type="function",
            subject_address=resolved,
            subject_name=fname,
            claim=f"pseudocode for {fname or ref}",
        )

    async def op_binary_disassemble(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        payload, text, raw = await self.call(
            provider, target, "disassemble_function", {"address": ref, "database": session["database"]}
        )
        info = payload if isinstance(payload, dict) else {}
        instructions = []
        for item in info.get("instructions", []) or info.get("items", []) or []:
            if not isinstance(item, dict):
                continue
            mnemonic, op_str = item.get("mnemonic"), item.get("operands", item.get("op_str"))
            if mnemonic is None and isinstance(item.get("disasm"), str):
                # re-mcp-ida DisassemblyInstruction is {address, disasm} (tools/functions.py:107-111)
                mnemonic, _, op_str = item["disasm"].strip().partition(" ")
            instructions.append(
                {
                    "address": parse_address(item.get("address")),
                    "bytes": (item.get("bytes") or "").replace(" ", "").lower() or None,
                    "mnemonic": str(mnemonic or "").lower(),
                    "op_str": str(op_str or "").strip(),
                }
            )
        if not instructions:
            listing = info.get("disassembly") or info.get("listing") or text
            instructions = parse_listing_lines(str(listing))
        # Ghidra DisassemblyResult has start/end (tools/functions.py:55-60); IDA has address.
        resolved = parse_address(info.get("address") or info.get("start")) or address
        fname = info.get("function_name") or info.get("name") or name
        return self.result(
            provider,
            "binary.disassemble",
            "disassemble_function",
            {"function": {"name": fname, "address": resolved}, "instructions": instructions},
            raw,
            subject_type="function",
            subject_address=resolved,
            subject_name=fname,
            claim=f"{len(instructions)} instructions",
        )

    async def op_binary_xrefs(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        direction = params.get("direction", "to")
        tool = "get_xrefs_to" if direction == "to" else "get_xrefs_from"
        meta: dict[str, Any] = {}
        items, raws = await self._paged(
            provider,
            target,
            tool,
            {"address": ref, "database": session["database"]},
            int(params.get("limit", 200)),
            meta,
        )
        # Ghidra rows: XrefTo {from_address, from_function, ref_type, is_call} / XrefFrom {to_address,
        # to_function, ref_type, is_call} (tools/xrefs.py:24-35). IDA rows: {from, from_name, type,
        # is_code} / {to, to_name, type, is_code} (re_mcp_ida tools/xrefs.py:38-69). A row carries
        # only the far end; the near end is the queried address (IDA echoes it, resolved).
        subject = parse_address(meta.get("address"))
        if subject is None:
            subject = address
        near, far_key = ("to", "from") if direction == "to" else ("from", "to")
        refs = []
        for item in items:
            far = parse_address(item.get(f"{far_key}_address", item.get(far_key)))
            if far is None:
                note_warning(f"{tool}: a reference without a parseable '{far_key}' end was ignored")
                continue
            refs.append(
                {
                    near: subject,
                    far_key: far,
                    "from_function": (item.get("from_function") or item.get("from_name") or None)
                    if direction == "to"
                    else None,
                    "to_function": (item.get("to_function") or item.get("to_name") or None)
                    if direction != "to"
                    else None,
                    "type": item.get("ref_type", item.get("type")),
                    "is_call": item.get("is_call"),
                    "is_code": item.get("is_code"),
                }
            )
        return self.result(
            provider,
            "binary.xrefs",
            tool,
            {"subject": {"address": address, "name": name}, "direction": direction, "refs": refs},
            raws,
            subject_type="address" if address is not None else "function",
            subject_address=address,
            subject_name=name,
            claim=f"{len(refs)} xrefs {direction}",
        )

    async def op_binary_cfg(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        payload, _text, raw = await self.call(
            provider, target, "get_basic_blocks", {"address": ref, "database": session["database"]}
        )
        rows = [
            block
            for block in (
                (payload or {}).get("blocks", (payload or {}).get("items", [])) if isinstance(payload, dict) else []
            )
            if isinstance(block, dict)
        ]
        starts = {parse_address(b.get("start") or b.get("start_address")) for b in rows} - {None}
        blocks = []
        for block in rows:
            # re-mcp-ghidra takes successors from BasicBlockModel.getDestinations() without the flow
            # type (tools/cfg.py:89-96), so call targets in other functions arrive as "successors".
            # Only destinations that are blocks of this function are CFG edges; the rest are kept
            # apart, unlabelled (call or jump: upstream does not say).
            raw_targets = block.get("successors", []) or []
            targets = [t for t in (parse_address(s) for s in raw_targets) if t is not None]
            if len(targets) < len(raw_targets):
                note_warning("get_basic_blocks: a successor address that could not be parsed was ignored")
            blocks.append(
                {
                    "start": parse_address(block.get("start") or block.get("start_address")),
                    "end": parse_address(block.get("end") or block.get("end_address")),
                    "successors": [t for t in targets if t in starts],
                    "external_targets": [t for t in targets if t not in starts],
                }
            )
        return self.result(
            provider,
            "binary.cfg",
            "get_basic_blocks",
            {"function": {"address": address, "name": name}, "blocks": blocks},
            raw,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"{len(blocks)} basic blocks",
        )

    async def op_binary_strings(self, provider, target, session, params):
        args: dict[str, Any] = {"database": session["database"]}
        if params.get("query"):
            args["filter_pattern"] = str(params["query"])
        if params.get("min_length"):
            args["min_length"] = int(params["min_length"])
        items, raws = await self._paged(provider, target, "get_strings", args, int(params.get("limit", 200)))
        strings = [
            {
                "address": parse_address(i.get("address")),
                "value": i.get("value"),
                "length": i.get("length"),
                "encoding": i.get("type"),
            }
            for i in items
        ]
        return self.result(
            provider,
            "binary.strings",
            "get_strings",
            {"strings": strings, "returned": len(strings)},
            raws,
            claim=f"{len(strings)} strings",
        )

    async def op_binary_imports(self, provider, target, session, params):
        items, raws = await self._paged(
            provider, target, "get_imports", {"database": session["database"]}, int(params.get("limit", 2000))
        )
        imports = [
            {
                "name": i.get("name"),
                "library": i.get("module") or i.get("library"),
                "address": parse_address(i.get("address")),
            }
            for i in items
        ]
        return self.result(
            provider,
            "binary.imports",
            "get_imports",
            {"imports": imports, "total": len(imports)},
            raws,
            claim=f"{len(imports)} imports",
        )

    async def op_binary_exports(self, provider, target, session, params):
        items, raws = await self._paged(
            provider, target, "get_exports", {"database": session["database"]}, int(params.get("limit", 2000))
        )
        exports = [{"name": i.get("name"), "address": parse_address(i.get("address"))} for i in items]
        return self.result(
            provider,
            "binary.exports",
            "get_exports",
            {"exports": exports, "total": len(exports)},
            raws,
            claim=f"{len(exports)} exports",
        )


RE_MCP = ReMcpAdapter(
    name="re_mcp",
    engine="ghidra",
    engine_family=None,
    pin=UpstreamPin(
        repository="https://github.com/jtsylve/re-mcp",
        revision="7b38aa92952bd0621e8c964dc859f1515fe26a10",
        package="re-mcp-ghidra / re-mcp-ida",
        package_version="3.0.3",
        verified="runtime",
        verified_on="2026-10-13",
        notes="Ghidra backend runtime-verified; IDA backend shares tool names but was not run (no IDA licence).",
    ),
    manifest={**_LIFECYCLE, **_META, **_EXTRA},
    bindings={
        "binary.metadata": ("open_database", "wait_for_analysis", "get_database_info"),
        "binary.functions": ("open_database", "wait_for_analysis", "list_functions"),
        "binary.decompile": ("open_database", "wait_for_analysis", "decompile_function"),
        "binary.disassemble": ("open_database", "wait_for_analysis", "disassemble_function"),
        "binary.xrefs": ("open_database", "wait_for_analysis", "get_xrefs_to", "get_xrefs_from"),
        "binary.cfg": ("open_database", "wait_for_analysis", "get_basic_blocks"),
        "binary.strings": ("open_database", "wait_for_analysis", "get_strings"),
        "binary.imports": ("open_database", "wait_for_analysis", "get_imports"),
        "binary.exports": ("open_database", "wait_for_analysis", "get_exports"),
    },
    trust_annotations=True,
    protocol_mode="legacy",
    limitations=(
        "Workers create Ghidra/IDA databases next to the file they open; Nexus passes a staged copy.",
        "Without run_auto_analysis upstream returns 1-byte function bounds and few xrefs/strings "
        "(observed); Nexus always requests auto-analysis.",
        "Set GHIDRA_MCP_DISABLE_EXECUTE=1 / GHIDRA_MCP_DISABLE_BATCH=1 so code-mode tools are not even offered.",
    ),
)

_ = fmt_address  # re-exported for adapters that format addresses
