"""Adapters verified against upstream *source* at a pinned commit, not run locally.

The machine used for this integration had no IDA Pro, Binary Ninja, Maven-built JADX
daemon or Frida device, so these adapters bind to tool and argument names read from
the pinned source/snapshot. Their normalisers are deliberately tolerant and always
keep the raw provider output; run ``reveng-nexus providers check`` after installing an
engine to confirm the live ``tools/list`` still matches.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from pathlib import PureWindowsPath
from typing import Any

from ..errors import CapabilityUnavailable, ProviderCallError
from .base import McpAdapter, UpstreamPin, fmt_address, function_ref, parse_address, parse_listing_lines


def _find_list(payload: Any, *keys: str) -> list[Any] | None:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in (*keys, "items", "results", "functions", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return None


def _items(payload: Any, *keys: str) -> list[Any]:
    return _find_list(payload, *keys) or []


def _shape(payload: Any) -> str:
    if payload is None:
        return "plain text where JSON was expected"
    if isinstance(payload, dict):
        return f"keys {sorted(payload)[:8]}"
    return type(payload).__name__


def _shape_warning(tool: str, payload: Any) -> str:
    return f"{tool} returned an unrecognised payload ({_shape(payload)}); the normalised result is empty, see the raw output"


def _json_listing(payload: Any, tool: str, *keys: str) -> tuple[list[Any], list[str]]:
    """Rows of a JSON list response, plus a warning when no recognised list is present."""
    rows = _find_list(payload, *keys)
    if rows is None:
        return [], [_shape_warning(tool, payload)]
    return rows, []


def _addr_of(item: Any, *keys: str) -> int | None:
    if not isinstance(item, dict):
        return None
    for key in (*keys, "address", "addr", "start", "ea", "start_ea"):
        if key in item:
            parsed = parse_address(item[key])
            if parsed is not None:
                return parsed
    return None


# ---------------------------------------------------------------------------
# Hex-Rays official ida-mcp
# ---------------------------------------------------------------------------
class IdaOfficialAdapter(McpAdapter):
    """Official server exposes analysis only through ``execute_python`` (arbitrary code).

    Nexus does not synthesise IDAPython for it: generated scripts would be unreviewed
    code execution and could not be verified here without IDA. Under the default
    read-only policy the provider is therefore limited to ``reference`` and
    ``list_databases``; ``nexus_call_provider_tool`` can call ``execute_python`` only when
    the operator enables ``policy.allow_code_execution`` for this provider id.
    """


IDA_OFFICIAL = IdaOfficialAdapter(
    name="ida_official",
    engine="ida",
    engine_family="ida",
    pin=UpstreamPin(
        repository="https://github.com/HexRaysSA/ida-mcp",
        revision="df6de7985b534a964c125d5a86e41b26b17b14f6",
        package="ida-mcp",
        package_version="20261008.0.1",
        verified="snapshot",
        verified_on="2026-10-13",
        notes="Tool list from upstream tests/snapshots/mcp_metadata.json (6 tools). Requires IDA 9.4+ with idalib.",
    ),
    manifest={
        "reference": "read",
        "list_databases": "read",
        "open_database": "lifecycle",
        "close_database": "lifecycle",
        "save_database": "mutate",
        "execute_python": "execute",
    },
    bindings={},
    trust_annotations=True,
    protocol_mode="auto",
    limitations=(
        "Decompilation/disassembly/xrefs require execute_python (arbitrary IDAPython); blocked by default.",
        "There is no upstream read-only switch; the 0.1 example's IDA_MCP_READ_ONLY/IDA_MCP_TOOLSETS "
        "variables belong to blacktop/ida-mcp-rs, not this server.",
    ),
)


# ---------------------------------------------------------------------------
# blacktop/ida-mcp-rs
# ---------------------------------------------------------------------------
def _ida_analysis_gap(payload: Any) -> str | None:
    """open_idb's DbInfo (src/ida/types.rs:87-97) carries AnalysisStatus (types.rs:132-139); large
    inputs may route analysis to a background task (server/mod.rs open_idb ``analysis_background``)."""
    if not isinstance(payload, dict):
        return "open_idb did not return DbInfo; IDA auto-analysis state is unknown, results may be partial"
    status = payload.get("analysis_status")
    if payload.get("analysis_background") or not isinstance(status, dict) or status.get("auto_is_ok") is not True:
        state = status.get("auto_state") if isinstance(status, dict) else None
        return f"IDA auto-analysis was not complete when the database opened (auto_state={state!r}); results may be partial"
    return None


def _ida_more(tool: str, payload: Any) -> list[str]:
    """Pagination markers (types.rs:201-206 next_offset, 390-396 truncated) mean a partial answer."""
    if isinstance(payload, dict) and (payload.get("truncated") or payload.get("next_offset") is not None):
        total = payload.get("total")
        return [f"{tool}: result truncated upstream" + (f" ({total} in total)" if total is not None else "")]
    return []


class IdaRsAdapter(McpAdapter):
    async def prepare(self, provider, target) -> dict[str, Any]:
        sessions = provider.adapter_state.setdefault("sessions", {})
        if target.sha256 in sessions:
            return sessions[target.sha256]
        # Only one database is open per server (without --workspace); close any other.
        for sha in list(sessions):
            await self.release(provider, sha)
        staged = target.staged_path(provider.id)
        idb_out = target.provider_dir(provider.id) / (staged.stem + ".i64")
        # auto_analyse defaults to false upstream (src/server/requests.rs:55-60): a raw binary is then
        # opened "fast with analysis incomplete", and function lists/xrefs/strings would be partial.
        payload, _t, raw = await self.call(
            provider,
            target,
            "open_idb",
            {"path": str(staged), "idb_out": str(idb_out), "auto_analyse": True},
            timeout=float(provider.config.startup_timeout_seconds),
        )
        session = {"open": payload, "idb_out": str(idb_out), "incomplete": _ida_analysis_gap(payload)}
        sessions[target.sha256] = session
        return session

    async def perform(self, provider, operation, target, params):
        result = await super().perform(provider, operation, target, params)
        gap = provider.adapter_state.get("sessions", {}).get(target.sha256, {}).get("incomplete")
        if gap and gap not in result.warnings:
            result.warnings.append(gap)  # until the session is reopened: Nexus cannot see it finish
        return result

    async def release(self, provider, sha256: str) -> None:
        session = provider.adapter_state.setdefault("sessions", {}).pop(sha256, None)
        if session and provider._owner is not None and provider._owner.alive:
            try:
                await provider.call_tool("close_idb", {}, internal=True, target_sha256=sha256)
            except Exception:  # noqa: BLE001 - best effort
                pass

    async def _address(self, provider, target, params) -> tuple[int, str | None]:
        """decompile, xrefs_to/from and basic_blocks take numeric addresses only (pinned
        server/mod.rs ``parse_address`` rejects symbols), so a name is resolved first, to exactly
        one function, via list_functions."""
        address, name, _ref = function_ref(params)
        if address is not None:
            return address, name
        payload, _t, _raw = await self.call(
            provider, target, "list_functions", {"filter": name, "limit": 50, "offset": 0}
        )
        rows, _w = _json_listing(payload, "list_functions", "functions")
        matches = [_addr_of(r) for r in rows if isinstance(r, dict) and r.get("name") == name]
        if len(matches) != 1 or matches[0] is None:
            raise ProviderCallError(
                f"{provider.id}: cannot resolve {name!r} to one function address ({len(matches)} exact matches)"
            )
        return matches[0], name

    async def op_binary_metadata(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "idb_meta", {})
        meta = payload if isinstance(payload, dict) else {}
        warnings = [] if isinstance(payload, dict) else [_shape_warning("idb_meta", payload)]
        # Pinned keys (src/ida/handlers/globals.rs): processor, bits, image_base, main_address,
        # min/max_address, ... There is no entry-point key, and main() is not the image entry
        # point, so entry_point stays unknown rather than being relabelled from main_address.
        normalized = {
            "processor": meta.get("processor"),
            "bits": meta.get("bits"),
            "image_base": parse_address(meta.get("image_base")),
            "entry_point": parse_address(meta.get("entry_point")),
            "main_address": parse_address(meta.get("main_address")),
            "engine_info": meta,
        }
        return self.result(
            provider, "binary.metadata", "idb_meta", normalized, raw, warnings=warnings, claim="IDA database metadata"
        )

    async def op_binary_functions(self, provider, target, session, params):
        args: dict[str, Any] = {"limit": int(params.get("limit", 500)), "offset": 0}
        if params.get("query"):
            args["filter"] = str(params["query"])
        payload, _t, raw = await self.call(provider, target, "list_functions", args)
        rows, warnings = _json_listing(payload, "list_functions", "functions")
        warnings += _ida_more("list_functions", payload)
        functions = []
        for item in rows:
            start = _addr_of(item)
            end = _addr_of(item, "end", "end_ea")
            size = item.get("size") if isinstance(item, dict) else None
            functions.append(
                {
                    "name": item.get("name") if isinstance(item, dict) else str(item),
                    "address": start,
                    "size": size if size is not None else (end - start if start and end else None),
                }
            )
        return self.result(
            provider,
            "binary.functions",
            "list_functions",
            {"functions": functions, "total": len(functions)},
            raw,
            warnings=warnings,
            claim=f"{len(functions)} functions",
        )

    async def op_binary_decompile(self, provider, target, session, params):
        address, name = await self._address(provider, target, params)
        ref = fmt_address(address)
        payload, text, raw = await self.call(provider, target, "decompile", {"address": ref})
        info = payload if isinstance(payload, dict) else {}
        entry = (_items(payload, "results") or [info])[0] if isinstance(payload, (dict, list)) else {}
        if payload is None:
            code: Any = text
        else:
            code = next(
                (
                    entry[k]
                    for k in ("pseudocode", "code", "text")
                    if isinstance(entry, dict) and isinstance(entry.get(k), str)
                ),
                None,
            )
            if code is None:
                # Never present an unexpected JSON document as Hex-Rays output.
                raise ProviderCallError(
                    f"{provider.id}/decompile returned no pseudocode field ({_shape(payload)})",
                    details={"tool": "decompile"},
                )
        resolved = _addr_of(entry) if isinstance(entry, dict) else None
        fname = entry.get("name") if isinstance(entry, dict) else None
        return self.result(
            provider,
            "binary.decompile",
            "decompile",
            {
                "function": {"name": fname or name, "address": resolved or address},
                "code": str(code),
                "language": "Hex-Rays pseudocode",
            },
            raw,
            subject_type="function",
            subject_address=resolved or address,
            subject_name=fname or name,
            claim=f"Hex-Rays pseudocode for {fname or ref}",
        )

    async def op_binary_disassemble(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        args: dict[str, Any] = {"address": ref} if address is not None else {"target_name": name}
        payload, text, raw = await self.call(provider, target, "disasm_function_at", args)
        # A plain-text listing is parsed below; a JSON payload must carry an instruction list.
        warnings = [] if payload is None else _json_listing(payload, "disasm_function_at", "instructions", "lines")[1]
        instructions = []
        for item in _items(payload, "instructions", "lines"):
            if isinstance(item, dict):
                instructions.append(
                    {
                        "address": _addr_of(item),
                        "bytes": item.get("bytes"),
                        "mnemonic": str(item.get("mnemonic", "")).lower(),
                        "op_str": item.get("operands", item.get("op_str", "")),
                    }
                )
        if not instructions:
            instructions = parse_listing_lines(text)
        return self.result(
            provider,
            "binary.disassemble",
            "disasm_function_at",
            {"function": {"name": name, "address": address}, "instructions": instructions},
            raw,
            warnings=warnings,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"{len(instructions)} instructions",
        )

    async def op_binary_xrefs(self, provider, target, session, params):
        address, name = await self._address(provider, target, params)
        ref = fmt_address(address)
        direction = params.get("direction", "to")
        tool = "xrefs_to" if direction == "to" else "xrefs_from"
        payload, _t, raw = await self.call(
            provider, target, tool, {"address": ref, "limit": int(params.get("limit", 200))}
        )
        rows, warnings = _json_listing(payload, tool, "xrefs", "refs")
        warnings += _ida_more(tool, payload)
        refs = [
            {
                "from": _addr_of(i, "from", "frm", "source"),
                "to": _addr_of(i, "to", "target") or address,
                "type": i.get("type") if isinstance(i, dict) else None,
            }
            for i in rows
        ]
        return self.result(
            provider,
            "binary.xrefs",
            tool,
            {"subject": {"address": address, "name": name}, "direction": direction, "refs": refs},
            raw,
            warnings=warnings,
            subject_type="address",
            subject_address=address,
            subject_name=name,
            claim=f"{len(refs)} xrefs {direction}",
        )

    async def op_binary_strings(self, provider, target, session, params):
        args: dict[str, Any] = {"limit": int(params.get("limit", 200))}
        if params.get("query"):
            args["filter"] = str(params["query"])
        payload, _t, raw = await self.call(provider, target, "strings", args)
        rows, warnings = _json_listing(payload, "strings", "strings")
        warnings += _ida_more("strings", payload)
        # Pinned StringInfo is {address, content, length}: the text lives in "content".
        strings = [
            {"address": _addr_of(i), "value": i.get("content"), "length": i.get("length")}
            for i in rows
            if isinstance(i, dict)
        ]
        return self.result(
            provider,
            "binary.strings",
            "strings",
            {"strings": strings, "returned": len(strings)},
            raw,
            warnings=warnings,
            claim=f"{len(strings)} strings",
        )

    async def op_binary_imports(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "imports", {"limit": int(params.get("limit", 2000))})
        rows, warnings = _json_listing(payload, "imports", "imports")
        # Pinned ImportInfo is {address, name, ordinal}; it names no module, so the library is
        # unknown (None) rather than guessed.
        imports = [
            {"name": i.get("name"), "library": None, "address": _addr_of(i), "ordinal": i.get("ordinal")}
            for i in rows
            if isinstance(i, dict)
        ]
        return self.result(
            provider,
            "binary.imports",
            "imports",
            {"imports": imports, "total": len(imports)},
            raw,
            warnings=warnings,
            claim=f"{len(imports)} imports",
        )

    async def op_binary_exports(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "exports", {"limit": int(params.get("limit", 2000))})
        rows, warnings = _json_listing(payload, "exports", "exports")
        exports = [{"name": i.get("name"), "address": _addr_of(i)} for i in rows if isinstance(i, dict)]
        return self.result(
            provider,
            "binary.exports",
            "exports",
            {"exports": exports, "total": len(exports)},
            raw,
            warnings=warnings,
            claim=f"{len(exports)} exports",
        )

    async def op_binary_cfg(self, provider, target, session, params):
        address, name = await self._address(provider, target, params)
        payload, _t, raw = await self.call(provider, target, "basic_blocks", {"address": fmt_address(address)})
        rows, warnings = _json_listing(payload, "basic_blocks", "blocks")
        blocks = [
            {
                "start": _addr_of(b, "start", "start_ea"),
                "end": _addr_of(b, "end", "end_ea"),
                "successors": [parse_address(s) for s in (b.get("succs") or b.get("successors") or [])],
            }
            for b in rows
            if isinstance(b, dict)
        ]
        return self.result(
            provider,
            "binary.cfg",
            "basic_blocks",
            {"function": {"address": address, "name": name}, "blocks": blocks},
            raw,
            warnings=warnings,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"{len(blocks)} basic blocks",
        )


IDA_RS = IdaRsAdapter(
    name="ida_rs",
    engine="ida",
    engine_family="ida",
    pin=UpstreamPin(
        repository="https://github.com/blacktop/ida-mcp-rs",
        revision="15d16aba427bedc8a23c7a54d8adee06d427b740",
        package="ida-mcp (Rust binary)",
        package_version="v9.5.0-beta.6 (main); v9.4.5 is the latest stable tag",
        verified="source",
        verified_on="2026-10-13",
        notes="Argument names from src/server/requests.rs; run with --read-only. Requires licensed IDA Pro 9.4.",
    ),
    manifest={
        "open_idb": "lifecycle",
        "close_idb": "lifecycle",
        "analysis_status": "read",
        "task_status": "read",
        "open_dsc": "lifecycle",
        "save_idb": "mutate",
        "analyze_funcs": "mutate",
        "run_script": "execute",
        "lumina_apply": "mutate",
        "lumina_lookup": "blocked",  # sends function metadata to a remote service
        "debug_attach": "dynamic",
        "debug_launch": "dynamic",
        "debug_stop": "dynamic",
        "debug_open_module": "dynamic",
        "debug_modules": "dynamic",
        "debug_status": "read",
        "list_patches": "read",
        "load_debug_info": "lifecycle",
        "dsc_add_dylib": "lifecycle",
        "dsc_add_region": "lifecycle",
    },
    bindings={
        "binary.metadata": ("open_idb", "idb_meta"),
        "binary.functions": ("open_idb", "list_functions"),
        "binary.decompile": ("open_idb", "decompile"),
        "binary.disassemble": ("open_idb", "disasm_function_at"),
        "binary.xrefs": ("open_idb", "xrefs_to", "xrefs_from"),
        "binary.cfg": ("open_idb", "basic_blocks"),
        "binary.strings": ("open_idb", "strings"),
        "binary.imports": ("open_idb", "imports"),
        "binary.exports": ("open_idb", "exports"),
    },
    trust_annotations=True,
    protocol_mode="auto",
    limitations=(
        "Not runtime-tested here (no IDA licence on the integration machine).",
        "Result normalisation is tolerant; raw output is always preserved as evidence.",
        "lumina_lookup is blocked: it queries Hex-Rays' Lumina service with function metadata.",
    ),
)


_BINJA_ERROR = re.compile(r"^(Error\b|Server returned \d{3}\b|No response from server\b|Request failed:)")


def _basename(path: str) -> str:
    return PureWindowsPath(path).name  # accepts both "/" and "\" separators


def _norm_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _binja_check_view(provider: Any, target: Any, tool: str, shown: str) -> None:
    """The active view must be *this target's staged copy*, compared by full path.

    The pinned plugin exposes only ``FileMetadata.filename`` (no hash, no view identity
    beyond the path). A basename match is not identity: any same-named file would be
    attributed to this SHA-256. ``staged_path`` re-verifies the staged copy's hash on every
    call and the copy is read-only, so the full staged path is the strongest identity the
    upstream allows. A ``.bndb`` path (database) is refused for the same reason.
    """
    staged = target.staged_path(provider.id)
    if _norm_path(shown) != _norm_path(str(staged)):
        raise CapabilityUnavailable(
            f"{provider.id}/{tool}: Binary Ninja's active view is {_basename(shown)!r}, "
            f"which is not this target's staged copy",
            remediation=f"Open {staged} in Binary Ninja (File > Open) and retry.",
            details={"active_view": _basename(shown)},
        )


def _binja_body(provider: Any, target: Any, tool: str, text: str) -> str:
    """Unwrap one bridge answer (pinned ``bridge/src/tools.ts``).

    Some tools prefix ``File: <active view path>``; that name must be the target, or the answer
    belongs to another binary. The bridge never sets MCP ``isError``: HTTP and plugin failures
    arrive as text (``Error: ...``, ``Error: GET <endpoint> failed: ...``), which is raised here
    instead of being parsed as data.
    """
    body = text
    if body.startswith("File: "):
        first, _, rest = body.partition("\n")
        shown = first[len("File: ") :].strip()
        if not shown or shown == "(none)":
            raise CapabilityUnavailable(f"{provider.id}/{tool}: Binary Ninja reports no open binary")
        _binja_check_view(provider, target, tool, shown)
        body = rest[1:] if rest.startswith("\n") else rest
    if _BINJA_ERROR.match(body.strip()):
        raise ProviderCallError(
            f"{provider.id}/{tool}: Binary Ninja bridge reported an error: {body.strip()[:300]}",
            details={"tool": tool},
        )
    return body


def _json_document(text: str) -> dict[str, Any] | list[Any] | None:
    """Return ``text`` parsed when it is exactly one JSON object or array, else None."""
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        value = json.loads(stripped)
    except ValueError:
        return None
    return value if isinstance(value, (dict, list)) else None


def _binja_json(provider: Any, tool: str, body: str) -> Any:
    """The plugin answers these endpoints with one compact JSON document (``_send_json_response``)."""
    try:
        data = json.loads(body)
    except ValueError:
        raise ProviderCallError(
            f"{provider.id}/{tool}: expected the plugin's JSON document, got {len(body)} chars of text",
            details={"tool": tool},
        ) from None
    if isinstance(data, dict) and data.get("error"):
        raise ProviderCallError(f"{provider.id}/{tool}: {str(data['error'])[:300]}", details={"tool": tool})
    return data


def _binja_rows(provider: Any, tool: str, body: str, key: str) -> tuple[list[dict[str, Any]], list[str]]:
    data = _binja_json(provider, tool, body)
    rows = data.get(key) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return [], [_shape_warning(tool, data)]
    kept = [r for r in rows if isinstance(r, dict)]
    warnings = (
        [f"{tool}: {len(rows) - len(kept)} entr(y/ies) were not objects and were ignored"]
        if len(kept) < len(rows)
        else []
    )
    return kept, warnings


# ---------------------------------------------------------------------------
# fosdickio/binary_ninja_mcp (npm bridge "binary-ninja-mcp" → BN plugin HTTP :9009)
# ---------------------------------------------------------------------------
class BinjaAdapter(McpAdapter):
    """The Binary Ninja plugin serves whatever the *user* opened in the BN GUI.

    Nexus cannot load a file into Binary Ninja through this bridge, so before every
    operation it checks that the active view's file name equals the target's and refuses
    otherwise, rather than attributing another binary's analysis to this SHA-256. Tools that
    carry a ``File:`` preamble are checked again per answer.
    """

    async def prepare(self, provider, target) -> dict[str, Any]:
        _payload, text, _raw = await self.call(provider, target, "get_binary_status", {})
        body = _binja_body(provider, target, "get_binary_status", text)
        try:
            status = json.loads(body.strip())  # first line of the plugin's /status JSON
        except ValueError:
            status = None
        if not isinstance(status, dict):
            raise CapabilityUnavailable(f"{provider.id}: unrecognised get_binary_status answer ({len(body)} chars)")
        filename = status.get("filename")
        if not status.get("loaded") or not filename:
            raise CapabilityUnavailable(
                f"{provider.id}: Binary Ninja has no binary open",
                remediation="Open the target in Binary Ninja (or select it with select_binary) and retry.",
            )
        _binja_check_view(provider, target, "get_binary_status", str(filename))
        return {"active_view": _basename(str(filename))}

    async def perform(self, provider, operation, target, params):
        result = await super().perform(provider, operation, target, params)
        # Most bridge answers carry no "File:" preamble: confirm the view did not change while the
        # operation ran (GUI switch or another client's select_binary) before it becomes evidence.
        await self.prepare(provider, target)
        return result

    async def _function_name(self, provider, target, params) -> tuple[int | None, str]:
        address, name, ref = function_ref(params)
        if name is not None:
            return address, name
        _payload, text, _raw = await self.call(provider, target, "function_at", {"address": ref})
        data = _binja_json(provider, "function_at", _binja_body(provider, target, "function_at", text))
        names = [n for n in (data.get("functions") if isinstance(data, dict) else None) or [] if isinstance(n, str)]
        if not names:
            raise ProviderCallError(f"{provider.id}: no function contains {ref}")
        if len(names) > 1:
            raise ProviderCallError(
                f"{provider.id}: {ref} lies in {len(names)} functions ({', '.join(names[:5])}); pass a name instead"
            )
        return address, names[0]

    async def op_binary_functions(self, provider, target, session, params):
        if params.get("query"):
            tool, key, args = (
                "search_functions_by_name",
                "matches",
                {"query": str(params["query"]), "limit": int(params.get("limit", 500))},
            )
        else:
            tool, key, args = "list_methods", "functions", {"limit": int(params.get("limit", 500)), "offset": 0}
        _payload, text, raw = await self.call(provider, target, tool, args)
        rows, warnings = _binja_rows(provider, tool, _binja_body(provider, target, tool, text), key)
        functions = [{"name": r.get("name"), "address": _addr_of(r), "size": None} for r in rows]
        return self.result(
            provider,
            "binary.functions",
            tool,
            {"functions": functions, "total": len(functions)},
            raw,
            warnings=warnings,
            claim=f"{len(functions)} functions",
        )

    async def op_binary_decompile(self, provider, target, session, params):
        address, name = await self._function_name(provider, target, params)
        _payload, text, raw = await self.call(provider, target, "decompile_function", {"name": name})
        code = _binja_body(provider, target, "decompile_function", text)
        if not code.strip():
            raise ProviderCallError(f"{provider.id}/decompile_function returned no HLIL for {name!r}")
        if _json_document(code) is not None:
            # HLIL text is never a JSON object/array: do not label a stray document as code.
            raise ProviderCallError(
                f"{provider.id}/decompile_function returned a JSON document ({_shape(_json_document(code))}) "
                "where HLIL text was expected",
                details={"tool": "decompile_function"},
            )
        return self.result(
            provider,
            "binary.decompile",
            "decompile_function",
            {"function": {"name": name, "address": address}, "code": code, "language": "HLIL"},
            raw,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"HLIL for {name}",
        )

    async def op_binary_disassemble(self, provider, target, session, params):
        address, name = await self._function_name(provider, target, params)
        _payload, text, raw = await self.call(provider, target, "fetch_disassembly", {"name": name})
        listing = _binja_body(provider, target, "fetch_disassembly", text)
        instructions = parse_listing_lines(listing)
        warnings = (
            [f"fetch_disassembly: no instruction lines recognised in {len(listing)} chars; see the raw output"]
            if listing.strip() and not instructions
            else []
        )
        return self.result(
            provider,
            "binary.disassemble",
            "fetch_disassembly",
            {"function": {"name": name, "address": address}, "instructions": instructions},
            raw,
            warnings=warnings,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"disassembly of {name}",
        )

    async def op_binary_xrefs(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        if params.get("direction", "to") != "to":
            raise CapabilityUnavailable("binary_ninja_mcp exposes xrefs *to* an address only (use get_callees)")
        _payload, text, raw = await self.call(provider, target, "get_xrefs_to", {"address": ref})
        data = _binja_json(provider, "get_xrefs_to", _binja_body(provider, target, "get_xrefs_to", text))
        warnings: list[str] = []
        refs: list[dict[str, Any]] = []
        if not isinstance(data, dict) or not (
            isinstance(data.get("code_references"), list) or isinstance(data.get("data_references"), list)
        ):
            warnings.append(_shape_warning("get_xrefs_to", data))
        else:
            for kind in ("code", "data"):
                for entry in data.get(f"{kind}_references") or []:
                    source = _addr_of(entry)
                    if source is None:
                        # The data_references record shape is not pinned down upstream; never guess.
                        warnings.append(f"get_xrefs_to: a {kind} reference without an address was ignored")
                        continue
                    refs.append({"from": source, "to": address, "type": kind, "function": entry.get("function")})
        return self.result(
            provider,
            "binary.xrefs",
            "get_xrefs_to",
            {"subject": {"address": address, "name": name}, "direction": "to", "refs": refs},
            raw,
            warnings=warnings,
            subject_type="address",
            subject_address=address,
            subject_name=name,
            claim=f"{len(refs)} xrefs to",
        )

    async def op_binary_strings(self, provider, target, session, params):
        if params.get("query"):
            tool, args = (
                "list_strings_filter",
                {"filter": str(params["query"]), "count": int(params.get("limit", 200)), "offset": 0},
            )
        else:
            tool, args = "list_strings", {"count": int(params.get("limit", 200)), "offset": 0}
        _payload, text, raw = await self.call(provider, target, tool, args)
        rows, warnings = _binja_rows(provider, tool, _binja_body(provider, target, tool, text), "strings")
        strings = [{"address": _addr_of(r), "value": r.get("value"), "length": r.get("length")} for r in rows]
        return self.result(
            provider,
            "binary.strings",
            tool,
            {"strings": strings, "returned": len(strings)},
            raw,
            warnings=warnings,
            claim=f"{len(strings)} strings",
        )

    async def _symbols(self, provider, target, params, tool: str, key: str, operation: str):
        _payload, text, raw = await self.call(
            provider, target, tool, {"offset": 0, "limit": int(params.get("limit", 2000))}
        )
        rows, warnings = _binja_rows(provider, tool, _binja_body(provider, target, tool, text), key)
        symbols = [{"name": r.get("name"), "address": _addr_of(r)} for r in rows]
        return self.result(
            provider,
            operation,
            tool,
            {key: symbols, "total": len(symbols)},
            raw,
            warnings=warnings,
            claim=f"{len(symbols)} {key}",
        )

    async def op_binary_imports(self, provider, target, session, params):
        return await self._symbols(provider, target, params, "list_imports", "imports", "binary.imports")

    async def op_binary_exports(self, provider, target, session, params):
        return await self._symbols(provider, target, params, "list_exports", "exports", "binary.exports")


_BINJA_READ = (
    "list_methods get_entry_points search_functions_by_name decompile_function get_il fetch_disassembly "
    "get_comment get_function_comment list_local_types search_types get_user_defined_type get_type_info "
    "list_data_items hexdump_address hexdump_data get_data_decl get_xrefs_to get_xrefs_to_field "
    "get_xrefs_to_struct get_xrefs_to_type get_xrefs_to_enum get_xrefs_to_union function_at "
    "get_stack_frame_vars list_classes list_namespaces list_segments list_sections list_imports list_exports "
    "list_strings list_strings_filter list_all_strings get_binary_status list_binaries list_platforms "
    "convert_number get_callers get_callees"
).split()
_BINJA_MUTATE = (
    "rename_function rename_single_variable rename_multi_variables rename_data set_comment delete_comment "
    "set_function_comment delete_function_comment define_types declare_c_type retype_variable "
    "set_local_variable_type set_function_prototype make_function_at patch_bytes format_value"
).split()

BINJA = BinjaAdapter(
    name="binary_ninja",
    engine="binaryninja",
    engine_family="binaryninja",
    pin=UpstreamPin(
        repository="https://github.com/fosdickio/binary_ninja_mcp",
        revision="8c5134ee46e2bf44f9a4d846bd971c3e39b3e306",
        package="binary-ninja-mcp (npm bridge)",
        package_version="1.0.0",
        verified="source",
        verified_on="2026-10-13",
        notes="GPL-3.0. Bridge tools carry no MCP annotations, so Nexus uses an explicit allowlist.",
    ),
    manifest={**{t: "read" for t in _BINJA_READ}, **{t: "mutate" for t in _BINJA_MUTATE}, "select_binary": "lifecycle"},
    bindings={
        "binary.functions": ("get_binary_status", "list_methods", "search_functions_by_name"),
        "binary.decompile": ("get_binary_status", "decompile_function", "function_at"),
        "binary.disassemble": ("get_binary_status", "fetch_disassembly", "function_at"),
        "binary.xrefs": ("get_binary_status", "get_xrefs_to"),
        "binary.strings": ("get_binary_status", "list_strings", "list_strings_filter"),
        "binary.imports": ("get_binary_status", "list_imports"),
        "binary.exports": ("get_binary_status", "list_exports"),
    },
    trust_annotations=False,
    protocol_mode="legacy",
    limitations=(
        "Requires the Binary Ninja GUI running with the plugin's HTTP server (default 127.0.0.1:9009).",
        "Operates on the binary open in the GUI; Nexus refuses when the active view's name differs from the target.",
        "Not runtime-tested here (no Binary Ninja installation).",
    ),
)


# ---------------------------------------------------------------------------
# Qtty/jadx-mcp-server (Python MCP layer → local JADX JVM daemon)
# ---------------------------------------------------------------------------
_JADX_PARTIAL = re.compile(r"^@(outline|oversized|truncated|ambiguous)\b")


def _jadx_decode(provider: Any, tool: str, text: str, expect: type) -> tuple[Any, list[str]]:
    """Decode the pinned server's answer: exactly one text block holding ``json.dumps(value)``.

    Decoded once, never again: a decoded string is returned as-is even if its contents look
    like JSON. Plain text that is not JSON at all is accepted only where a string is expected
    (an older/unpinned server), with a warning; anything else of the wrong type is an error.
    """
    try:
        value = json.loads(text)
    except ValueError:
        if expect is str and text.strip():
            return text, [f"{tool}: plain text instead of the pinned JSON-encoded string; used verbatim"]
        raise ProviderCallError(
            f"{provider.id}/{tool} returned {len(text)} chars that are not valid JSON", details={"tool": tool}
        ) from None
    if not isinstance(value, expect):
        raise ProviderCallError(
            f"{provider.id}/{tool} returned JSON {type(value).__name__} where {expect.__name__} was expected",
            details={"tool": tool},
        )
    return value, []


def _jadx_split(tool: str, items: list[Any]) -> tuple[list[Any], list[str]]:
    """Separate bookkeeping entries from data: a string starting with '@', or a one-key object
    whose key starts with '@' (``@truncated``, ``@oversized``, ``@rejected``, ...)."""
    data: list[Any] = []
    notes: list[str] = []
    for item in items:
        if isinstance(item, str) and item.startswith("@"):
            notes.append(item)
        elif isinstance(item, dict) and len(item) == 1 and str(next(iter(item))).startswith("@"):
            key = next(iter(item))
            notes.append(f"{key}: {item[key]}")
        else:
            data.append(item)
    return data, [f"{tool}: {note[:300]}" for note in notes[:10]]


class JadxAdapter(McpAdapter):
    async def prepare(self, provider, target) -> dict[str, Any]:
        if target.format != "apk":
            raise CapabilityUnavailable(f"JADX operations need an APK target, got {target.format!r}")
        sessions = provider.adapter_state.setdefault("sessions", {})
        if target.sha256 in sessions:
            return sessions[target.sha256]
        sessions.clear()  # the daemon keeps one APK warm by default (jadx.maxLoadedApks=1)
        staged = target.staged_path(provider.id)
        _payload, text, _raw = await self.call(
            provider,
            target,
            "load_apk",
            {"apkPath": str(staged)},
            timeout=float(provider.config.startup_timeout_seconds),
        )
        loaded, _w = _jadx_decode(provider, "load_apk", text, dict)
        # The daemon answers every later request against its most recently loaded APK
        # (core/AnalyzerRegistry.java:188-199); getApkInfo echoes that path verbatim
        # (core/JadxAnalyzerCore.java:461,509-519). Without a matching path, attribution is unsafe.
        shown = loaded.get("apkPath")
        if not isinstance(shown, str) or not shown.strip():
            raise CapabilityUnavailable(
                f"{provider.id}/load_apk did not report the loaded APK path; target identity cannot be confirmed"
            )
        if _norm_path(shown) != _norm_path(str(staged)):
            raise CapabilityUnavailable(
                f"{provider.id}/load_apk reports {_basename(shown)!r}, not this target's staged copy",
                remediation="Run one JADX daemon per concurrent analysis (JADX_URL / server.port).",
                details={"loaded_apk": _basename(shown)},
            )
        sessions[target.sha256] = {"loaded": loaded}
        return sessions[target.sha256]

    async def op_apk_manifest(self, provider, target, session, params):
        _p, text, raw = await self.call(provider, target, "get_android_manifest", {})
        manifest, warnings = _jadx_decode(provider, "get_android_manifest", text, str)
        _p2, main_text, _r = await self.call(provider, target, "get_main_activity_class", {})
        main_activity, main_warnings = _jadx_decode(provider, "get_main_activity_class", main_text, str)
        return self.result(
            provider,
            "apk.manifest",
            "get_android_manifest",
            {"manifest_xml": manifest, "main_activity": main_activity.strip() or None},
            raw,
            warnings=warnings + main_warnings,
            claim="decoded AndroidManifest.xml (JADX)",
        )

    async def op_apk_components(self, provider, target, session, params):
        _p, text, raw = await self.call(provider, target, "get_exported_components", {})
        exported, warnings = _jadx_decode(provider, "get_exported_components", text, list)
        exported, notes = _jadx_split("get_exported_components", exported)
        _p2, deep_text, _r = await self.call(provider, target, "get_deeplink_components", {})
        deeplinks, deep_warnings = _jadx_decode(provider, "get_deeplink_components", deep_text, list)
        deeplinks, deep_notes = _jadx_split("get_deeplink_components", deeplinks)
        return self.result(
            provider,
            "apk.components",
            "get_exported_components",
            {"exported_components": exported, "deeplink_components": deeplinks},
            raw,
            warnings=warnings + notes + deep_warnings + deep_notes,
            claim=f"{len(exported)} exported components (JADX)",
        )

    async def op_apk_classes(self, provider, target, session, params):
        args: dict[str, Any] = {"limit": int(params.get("limit", 1000))}
        if params.get("query"):
            args["packagePrefix"] = str(params["query"])
        _p, text, raw = await self.call(provider, target, "get_all_classes", args)
        names, warnings = _jadx_decode(provider, "get_all_classes", text, list)
        names, notes = _jadx_split("get_all_classes", names)
        classes = [n for n in names if isinstance(n, str)]
        if len(classes) < len(names):
            notes.append(f"get_all_classes: {len(names) - len(classes)} non-string entr(y/ies) ignored")
        return self.result(
            provider,
            "apk.classes",
            "get_all_classes",
            {"classes": classes, "returned": len(classes)},
            raw,
            warnings=warnings + notes,
            claim=f"{len(classes)} classes",
        )

    async def op_apk_class_source(self, provider, target, session, params):
        class_name = params.get("class_name")
        if not class_name:
            raise CapabilityUnavailable("class_name is required")
        args: dict[str, Any] = {"className": str(class_name)}
        if params.get("max_bytes") is not None:
            args["maxBytes"] = int(params["max_bytes"])
        _p, text, raw = await self.call(provider, target, "get_class_source", args)
        source, warnings = _jadx_decode(provider, "get_class_source", text, str)
        # Upstream leads a cut or outlined answer with "@outline: " / "@oversized: " /
        # "@truncated: " lines. The text is kept exactly; it is flagged as partial.
        markers = [line for line in source.splitlines()[:3] if _JADX_PARTIAL.match(line)]
        warnings += [f"get_class_source: partial answer ({m[:200]})" for m in markers]
        return self.result(
            provider,
            "apk.class_source",
            "get_class_source",
            {
                "class_name": class_name,
                "source": source,
                "language": "java (JADX decompilation)",
                "partial": bool(markers),
            },
            raw,
            warnings=warnings,
            subject_type="class",
            subject_name=str(class_name),
            claim=f"JADX source of {class_name}" + (" (partial)" if markers else ""),
        )

    async def op_apk_search(self, provider, target, session, params):
        query = str(params.get("query") or "")
        if not query:
            raise CapabilityUnavailable("query is required")
        limit = int(params.get("limit", 100))
        if params.get("kind") == "method":
            tool = "search_method_by_name"
            _p, text, raw = await self.call(provider, target, tool, {"methodName": query, "limit": limit})
            found, warnings = _jadx_decode(provider, tool, text, dict)  # {class name: [methods]}
            notes = [f"{tool}: {k}: {str(v)[:300]}" for k, v in found.items() if str(k).startswith("@")]
            results: Any = {k: v for k, v in found.items() if not str(k).startswith("@")}
        else:
            tool = "search_classes_by_keyword"
            _p, text, raw = await self.call(provider, target, tool, {"keyword": query, "limit": limit})
            found, warnings = _jadx_decode(provider, tool, text, list)
            results, notes = _jadx_split(tool, found)
        return self.result(
            provider,
            "apk.search",
            tool,
            {"query": query, "results": results},
            raw,
            warnings=warnings + notes,
            claim=f"search {query!r}",
        )


JADX = JadxAdapter(
    name="jadx",
    engine="jadx",
    engine_family="jadx",
    pin=UpstreamPin(
        repository="https://github.com/Qtty/jadx-mcp-server",
        revision="4e6d890d1d3753d2bb47d492a9523ef98874df85",
        package=None,
        package_version="1.0.0 (pom.xml)",
        verified="source",
        verified_on="2026-10-13",
        notes="No LICENSE file at this revision: no redistribution rights are granted; use your own checkout.",
    ),
    manifest={"load_apk": "lifecycle"},
    bindings={
        "apk.manifest": ("load_apk", "get_android_manifest", "get_main_activity_class"),
        "apk.components": ("load_apk", "get_exported_components", "get_deeplink_components"),
        "apk.classes": ("load_apk", "get_all_classes"),
        "apk.class_source": ("load_apk", "get_class_source"),
        "apk.search": ("load_apk", "search_classes_by_keyword", "search_method_by_name"),
    },
    trust_annotations=False,
    protocol_mode="legacy",
    limitations=(
        "Needs a Maven build of the JVM daemon (target/jadx-mcp-server-1.0.0.jar) and Java 17+.",
        "Default JADX_HEAP is 24g upstream; set a smaller JADX_HEAP in provider env on small machines.",
        "Not runtime-tested here (Maven not installed).",
    ),
)


# ---------------------------------------------------------------------------
# monkeywave/frida-mobile-mcp (dynamic; disabled unless policy.dynamic_analysis.enabled)
# ---------------------------------------------------------------------------
def _opt_str(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _int_like(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _frida_envelope(payload: Any) -> bool:
    """True only for the pinned ToolResult shape (types.ts:61-85, result-builder.ts:11-21, :51)."""
    if not isinstance(payload, dict) or set(payload) != {"result", "session_context", "suggested_next"}:
        return False
    ctx, nxt = payload["session_context"], payload["suggested_next"]
    if not isinstance(payload["result"], dict) or not isinstance(ctx, dict) or not isinstance(nxt, list):
        return False
    sessions = ctx.get("active_sessions")
    if not (
        _opt_str(ctx.get("device"))
        and _opt_str(ctx.get("platform"))
        and isinstance(sessions, list)
        and all(
            isinstance(s, dict)
            and isinstance(s.get("id"), str)
            and isinstance(s.get("target"), str)
            and _int_like(s.get("pid"))
            for s in sessions
        )
        and _int_like(ctx.get("active_hooks"))
        and _int_like(ctx.get("active_scripts"))
    ):
        return False
    return all(
        isinstance(a, dict)
        and isinstance(a.get("tool"), str)
        and isinstance(a.get("reason", ""), str)
        and isinstance(a.get("args", {}), dict)
        for a in nxt
    )


class FridaAdapter(McpAdapter):
    async def op_dynamic_status(self, provider, target, session, params):
        payload, text, raw = await self.call(provider, target, "get_status", {})
        warnings: list[str] = []
        # Pinned envelope (helpers/result-builder.ts:27-53): structuredContent
        # {result, session_context, suggested_next}; the text block is TOON, not JSON.
        if _frida_envelope(payload):
            status: Any = payload
            if isinstance(payload["result"].get("error"), str):  # in-band error without isError
                message = payload["result"]["error"][:600]
                raise ProviderCallError(f"{provider.id}/get_status reported an error: {message}")
        else:
            status = None
            warnings.append(
                "get_status did not return the pinned {result, session_context, suggested_next} envelope; "
                "the status is left empty and the raw output is kept"
            )
        return self.result(
            provider,
            "dynamic.status",
            "get_status",
            {"status": status},
            raw,
            evidence_kind="engine_derived",
            claim="Frida environment status",
            warnings=warnings,
        )

    async def shutdown(self, provider) -> None:
        # Upstream detaches sessions only on SIGINT/SIGTERM (index.ts:68-79), which a Windows
        # child never receives; ask it to stop all instrumentation before the pipes close.
        # Only on a live connection: call_tool -> _client_for would otherwise relaunch a dead child
        # (spending the restart budget) just to clean up a process that holds no sessions.
        owner = getattr(provider, "_owner", None)
        live = provider.started and owner is not None and owner.alive
        if live and provider.tool_info("stop_instrumentation") is not None:
            with contextlib.suppress(Exception):
                await provider.call_tool("stop_instrumentation", {"all": True}, internal=True, timeout=5.0)
        await super().shutdown(provider)


_FRIDA_READ = ("get_status", "frida_help", "list_devices", "get_device_info", "list_sessions")
_FRIDA_DYNAMIC = (
    "detect_app_technologies",
    "explore_app",
    "hook_method",
    "trace_method",
    "search_classes_and_methods",
    "read_memory",
    "scan_memory",
    "get_messages",
    "list_processes",
    "list_applications",
    "get_frontmost_application",
    "enumerate_modules",
    "enumerate_exports",
    "spawn_process",
    "attach_process",
    "resume_process",
    "detach_session",
    "select_device",
)
# Hard-blocked through Nexus: protection bypass, memory writes, custom/prebuilt JS payloads,
# process termination and custom hook bodies. Use Frida directly if an authorised test needs them.
# mobile_action proxies arbitrary mobile-mcp actions (install/uninstall/launch apps, taps, URLs;
# tools/mobile.ts:10-32) to a second server launched as `npx -y @mobilenext/mobile-mcp@latest`
# (config.ts:14-18, mobile-mcp/client.ts:32-42); it takes no device or target to authorise.
_FRIDA_BLOCKED = (
    "bypass_ssl_pinning",
    "mobile_action",
    "run_prebuilt_script",
    "execute_script",
    "write_memory",
    "kill_process",
    "hook_function",
    "unhook_function",
)

FRIDA = FridaAdapter(
    name="frida_mobile",
    engine="frida",
    engine_family="frida",
    pin=UpstreamPin(
        repository="https://github.com/monkeywave/frida-mobile-mcp",
        revision="b2da55d6429438ed36e829e7478de42430cb4ef9",
        package="frida-mobile-mcp (npm)",
        package_version="0.2.3",
        verified="source",
        verified_on="2026-10-13",
        notes="Upstream defaults: custom scripts and memory writes disabled; Nexus additionally hard-blocks bypass tools.",
    ),
    manifest={
        **{t: "read" for t in _FRIDA_READ},
        **{t: "dynamic" for t in _FRIDA_DYNAMIC},
        **{t: "blocked" for t in _FRIDA_BLOCKED},
        # Gateway-internal cleanup only (see FridaAdapter.shutdown); not forwarded to callers.
        "stop_instrumentation": "lifecycle",
    },
    bindings={"dynamic.status": ("get_status",)},
    trust_annotations=False,
    protocol_mode="legacy",
    # A tool outside the pinned 32 means upstream drift on a dynamic provider: re-pin and review it.
    # "blocked" (not "unknown") so a tool_overrides entry cannot relax it to "read".
    unlisted_tool_class="blocked",
    provider_kind="dynamic",
    limitations=(
        "Started only when policy.dynamic_analysis.enabled with authorised devices and app identifiers.",
        "Protection-bypass, memory-write and custom-script tools are never forwarded by Nexus.",
        "Not runtime-tested here (no authorised test device).",
    ),
)
