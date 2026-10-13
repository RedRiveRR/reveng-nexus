"""Adapters verified against upstream *source* at a pinned commit, not run locally.

The machine used for this integration had no IDA Pro, Binary Ninja, Maven-built JADX
daemon or Frida device, so these adapters bind to tool and argument names read from
the pinned source/snapshot. Their normalisers are deliberately tolerant and always
keep the raw provider output; run ``reveng-nexus providers check`` after installing an
engine to confirm the live ``tools/list`` still matches.
"""

from __future__ import annotations

from typing import Any

from ..errors import CapabilityUnavailable, ProviderCallError
from .base import McpAdapter, UpstreamPin, function_ref, parse_address, parse_listing_lines


def _items(payload: Any, *keys: str) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in (*keys, "items", "results", "functions", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


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
        payload, _t, raw = await self.call(
            provider,
            target,
            "open_idb",
            {"path": str(staged), "idb_out": str(idb_out)},
            timeout=float(provider.config.startup_timeout_seconds),
        )
        session = {"open": payload, "idb_out": str(idb_out)}
        sessions[target.sha256] = session
        return session

    async def release(self, provider, sha256: str) -> None:
        session = provider.adapter_state.setdefault("sessions", {}).pop(sha256, None)
        if session and provider._owner is not None and provider._owner.alive:
            try:
                await provider.call_tool("close_idb", {}, internal=True, target_sha256=sha256)
            except Exception:  # noqa: BLE001 - best effort
                pass

    async def op_binary_metadata(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "idb_meta", {})
        meta = payload if isinstance(payload, dict) else {}
        normalized = {
            "processor": meta.get("processor") or meta.get("proc_name"),
            "bits": meta.get("bits") or meta.get("bitness"),
            "image_base": parse_address(meta.get("image_base") or meta.get("imagebase") or meta.get("base")),
            "entry_point": parse_address(meta.get("entry_point") or meta.get("start_ea")),
            "engine_info": meta,
        }
        return self.result(provider, "binary.metadata", "idb_meta", normalized, raw, claim="IDA database metadata")

    async def op_binary_functions(self, provider, target, session, params):
        args: dict[str, Any] = {"limit": int(params.get("limit", 500)), "offset": 0}
        if params.get("query"):
            args["filter"] = str(params["query"])
        payload, _t, raw = await self.call(provider, target, "list_functions", args)
        functions = []
        for item in _items(payload, "functions"):
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
            claim=f"{len(functions)} functions",
        )

    async def op_binary_decompile(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        payload, text, raw = await self.call(provider, target, "decompile", {"address": ref})
        info = payload if isinstance(payload, dict) else {}
        entry = (_items(payload, "results") or [info])[0] if isinstance(payload, (dict, list)) else {}
        code = (
            (entry.get("pseudocode") or entry.get("code") or entry.get("text") or text)
            if isinstance(entry, dict)
            else text
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
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"{len(instructions)} instructions",
        )

    async def op_binary_xrefs(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        direction = params.get("direction", "to")
        tool = "xrefs_to" if direction == "to" else "xrefs_from"
        payload, _t, raw = await self.call(
            provider, target, tool, {"address": ref, "limit": int(params.get("limit", 200))}
        )
        refs = [
            {
                "from": _addr_of(i, "from", "frm", "source"),
                "to": _addr_of(i, "to", "target") or address,
                "type": i.get("type") if isinstance(i, dict) else None,
            }
            for i in _items(payload, "xrefs", "refs")
        ]
        return self.result(
            provider,
            "binary.xrefs",
            tool,
            {"subject": {"address": address, "name": name}, "direction": direction, "refs": refs},
            raw,
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
        strings = [
            {"address": _addr_of(i), "value": i.get("value", i.get("string")) if isinstance(i, dict) else i}
            for i in _items(payload, "strings")
        ]
        return self.result(
            provider,
            "binary.strings",
            "strings",
            {"strings": strings, "returned": len(strings)},
            raw,
            claim=f"{len(strings)} strings",
        )

    async def op_binary_imports(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "imports", {"limit": int(params.get("limit", 2000))})
        imports = [
            {"name": i.get("name"), "library": i.get("module"), "address": _addr_of(i)}
            for i in _items(payload, "imports")
            if isinstance(i, dict)
        ]
        return self.result(
            provider,
            "binary.imports",
            "imports",
            {"imports": imports, "total": len(imports)},
            raw,
            claim=f"{len(imports)} imports",
        )

    async def op_binary_exports(self, provider, target, session, params):
        payload, _t, raw = await self.call(provider, target, "exports", {"limit": int(params.get("limit", 2000))})
        exports = [
            {"name": i.get("name"), "address": _addr_of(i)} for i in _items(payload, "exports") if isinstance(i, dict)
        ]
        return self.result(
            provider,
            "binary.exports",
            "exports",
            {"exports": exports, "total": len(exports)},
            raw,
            claim=f"{len(exports)} exports",
        )

    async def op_binary_cfg(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        payload, _t, raw = await self.call(provider, target, "basic_blocks", {"address": ref})
        blocks = [
            {
                "start": _addr_of(b, "start", "start_ea"),
                "end": _addr_of(b, "end", "end_ea"),
                "successors": [parse_address(s) for s in (b.get("succs") or b.get("successors") or [])],
            }
            for b in _items(payload, "blocks")
            if isinstance(b, dict)
        ]
        return self.result(
            provider,
            "binary.cfg",
            "basic_blocks",
            {"function": {"address": address, "name": name}, "blocks": blocks},
            raw,
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


# ---------------------------------------------------------------------------
# fosdickio/binary_ninja_mcp (npm bridge "binary-ninja-mcp" → BN plugin HTTP :9009)
# ---------------------------------------------------------------------------
class BinjaAdapter(McpAdapter):
    """The Binary Ninja plugin serves whatever the *user* opened in the BN GUI.

    Nexus cannot load a file into Binary Ninja through this bridge, so before every
    operation it checks that the active view's filename matches the target and refuses
    otherwise, rather than attributing another binary's analysis to this SHA-256.
    """

    async def prepare(self, provider, target) -> dict[str, Any]:
        payload, text, _raw = await self.call(provider, target, "get_binary_status", {})
        blob = (str(payload) if payload is not None else "") + text
        if target.display_name not in blob:
            raise CapabilityUnavailable(
                f"Binary Ninja's active view does not appear to be {target.display_name!r}",
                remediation="Open the target in Binary Ninja (or select it with select_binary) and retry.",
                details={"binary_status": blob[:400]},
            )
        return {"status": blob[:400]}

    async def op_binary_functions(self, provider, target, session, params):
        if params.get("query"):
            tool, args = (
                "search_functions_by_name",
                {"query": str(params["query"]), "limit": int(params.get("limit", 500))},
            )
        else:
            tool, args = "list_methods", {"limit": int(params.get("limit", 500)), "offset": 0}
        payload, text, raw = await self.call(provider, target, tool, args)
        rows = _items(payload, "functions", "methods") or [line for line in text.splitlines() if line.strip()]
        functions = []
        for row in rows:
            if isinstance(row, dict):
                functions.append({"name": row.get("name"), "address": _addr_of(row), "size": row.get("size")})
            else:
                parts = str(row).rsplit(" at ", 1)
                functions.append(
                    {
                        "name": parts[0].strip(),
                        "address": parse_address(parts[1]) if len(parts) == 2 else None,
                        "size": None,
                    }
                )
        return self.result(
            provider,
            "binary.functions",
            tool,
            {"functions": functions, "total": len(functions)},
            raw,
            claim=f"{len(functions)} functions",
        )

    async def op_binary_decompile(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        if name is None:
            payload, text, _raw = await self.call(provider, target, "function_at", {"address": ref})
            name = (
                (payload or {}).get("name")
                if isinstance(payload, dict)
                else text.strip().splitlines()[0]
                if text.strip()
                else None
            )
            if not name:
                raise ProviderCallError(f"{provider.id}: no function at {ref}")
        payload, text, raw = await self.call(provider, target, "decompile_function", {"name": name})
        return self.result(
            provider,
            "binary.decompile",
            "decompile_function",
            {"function": {"name": name, "address": address}, "code": text, "language": "HLIL"},
            raw,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"HLIL for {name}",
        )

    async def op_binary_disassemble(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        if name is None:
            payload, text, _raw = await self.call(provider, target, "function_at", {"address": ref})
            name = text.strip().splitlines()[0] if text.strip() else None
        payload, text, raw = await self.call(provider, target, "fetch_disassembly", {"name": name})
        return self.result(
            provider,
            "binary.disassemble",
            "fetch_disassembly",
            {"function": {"name": name, "address": address}, "instructions": parse_listing_lines(text)},
            raw,
            subject_type="function",
            subject_address=address,
            subject_name=name,
            claim=f"disassembly of {name}",
        )

    async def op_binary_xrefs(self, provider, target, session, params):
        address, name, ref = function_ref(params)
        if params.get("direction", "to") != "to":
            raise CapabilityUnavailable("binary_ninja_mcp exposes xrefs *to* an address only (use get_callees)")
        payload, text, raw = await self.call(provider, target, "get_xrefs_to", {"address": ref})
        refs = [{"from": _addr_of(i, "from", "address"), "to": address} for i in _items(payload, "xrefs")]
        if not refs:
            refs = [
                {"from": parse_address(tok), "to": address}
                for line in text.splitlines()
                for tok in line.split()[:1]
                if parse_address(tok) is not None
            ]
        return self.result(
            provider,
            "binary.xrefs",
            "get_xrefs_to",
            {"subject": {"address": address, "name": name}, "direction": "to", "refs": refs},
            raw,
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
        payload, text, raw = await self.call(provider, target, tool, args)
        strings = [
            {"address": _addr_of(i), "value": i.get("value", i.get("string"))}
            for i in _items(payload, "strings")
            if isinstance(i, dict)
        ] or [{"value": line} for line in text.splitlines() if line.strip()]
        return self.result(
            provider,
            "binary.strings",
            tool,
            {"strings": strings, "returned": len(strings)},
            raw,
            claim=f"{len(strings)} strings",
        )

    async def op_binary_imports(self, provider, target, session, params):
        payload, text, raw = await self.call(
            provider, target, "list_imports", {"offset": 0, "limit": int(params.get("limit", 2000))}
        )
        rows = _items(payload, "imports") or [line for line in text.splitlines() if line.strip()]
        imports = [{"name": r.get("name") if isinstance(r, dict) else str(r)} for r in rows]
        return self.result(
            provider,
            "binary.imports",
            "list_imports",
            {"imports": imports, "total": len(imports)},
            raw,
            claim=f"{len(imports)} imports",
        )

    async def op_binary_exports(self, provider, target, session, params):
        payload, text, raw = await self.call(
            provider, target, "list_exports", {"offset": 0, "limit": int(params.get("limit", 2000))}
        )
        rows = _items(payload, "exports") or [line for line in text.splitlines() if line.strip()]
        exports = [{"name": r.get("name") if isinstance(r, dict) else str(r)} for r in rows]
        return self.result(
            provider,
            "binary.exports",
            "list_exports",
            {"exports": exports, "total": len(exports)},
            raw,
            claim=f"{len(exports)} exports",
        )


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
class JadxAdapter(McpAdapter):
    async def prepare(self, provider, target) -> dict[str, Any]:
        if target.format != "apk":
            raise CapabilityUnavailable(f"JADX operations need an APK target, got {target.format!r}")
        sessions = provider.adapter_state.setdefault("sessions", {})
        if target.sha256 in sessions:
            return sessions[target.sha256]
        sessions.clear()  # the daemon keeps one APK warm by default (jadx.maxLoadedApks=1)
        staged = target.staged_path(provider.id)
        payload, text, _raw = await self.call(
            provider,
            target,
            "load_apk",
            {"apkPath": str(staged)},
            timeout=float(provider.config.startup_timeout_seconds),
        )
        sessions[target.sha256] = {"loaded": payload if payload is not None else text[:400]}
        return sessions[target.sha256]

    async def op_apk_manifest(self, provider, target, session, params):
        _payload, text, raw = await self.call(provider, target, "get_android_manifest", {})
        main_payload, main_text, _r = await self.call(provider, target, "get_main_activity_class", {})
        return self.result(
            provider,
            "apk.manifest",
            "get_android_manifest",
            {"manifest_xml": text, "main_activity": main_text.strip() or main_payload},
            raw,
            claim="decoded AndroidManifest.xml (JADX)",
        )

    async def op_apk_components(self, provider, target, session, params):
        payload, text, raw = await self.call(provider, target, "get_exported_components", {})
        deep_payload, deep_text, _r = await self.call(provider, target, "get_deeplink_components", {})
        return self.result(
            provider,
            "apk.components",
            "get_exported_components",
            {
                "exported_components": payload if payload is not None else text,
                "deeplink_components": deep_payload if deep_payload is not None else deep_text,
            },
            raw,
            claim="exported components (JADX)",
        )

    async def op_apk_classes(self, provider, target, session, params):
        args: dict[str, Any] = {"limit": int(params.get("limit", 1000))}
        if params.get("query"):
            args["packagePrefix"] = str(params["query"])
        payload, text, raw = await self.call(provider, target, "get_all_classes", args)
        classes = _items(payload, "classes") or [line.strip() for line in text.splitlines() if line.strip()]
        return self.result(
            provider,
            "apk.classes",
            "get_all_classes",
            {"classes": classes, "returned": len(classes)},
            raw,
            claim=f"{len(classes)} classes",
        )

    async def op_apk_class_source(self, provider, target, session, params):
        class_name = params.get("class_name")
        if not class_name:
            raise CapabilityUnavailable("class_name is required")
        args: dict[str, Any] = {"className": str(class_name)}
        if params.get("max_bytes") is not None:
            args["maxBytes"] = int(params["max_bytes"])
        _payload, text, raw = await self.call(provider, target, "get_class_source", args)
        return self.result(
            provider,
            "apk.class_source",
            "get_class_source",
            {"class_name": class_name, "source": text, "language": "java (JADX decompilation)"},
            raw,
            subject_type="class",
            subject_name=str(class_name),
            claim=f"JADX source of {class_name}",
        )

    async def op_apk_search(self, provider, target, session, params):
        query = str(params.get("query") or "")
        if not query:
            raise CapabilityUnavailable("query is required")
        tool, args = (
            ("search_method_by_name", {"methodName": query})
            if params.get("kind") == "method"
            else ("search_classes_by_keyword", {"keyword": query})
        )
        args["limit"] = int(params.get("limit", 100))
        payload, text, raw = await self.call(provider, target, tool, args)
        return self.result(
            provider,
            "apk.search",
            tool,
            {"query": query, "results": payload if payload is not None else text.splitlines()},
            raw,
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
class FridaAdapter(McpAdapter):
    async def op_dynamic_status(self, provider, target, session, params):
        payload, text, raw = await self.call(provider, target, "get_status", {})
        return self.result(
            provider,
            "dynamic.status",
            "get_status",
            {"status": payload if payload is not None else text},
            raw,
            evidence_kind="engine_derived",
            claim="Frida environment status",
        )


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
    "stop_instrumentation",
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
    "mobile_action",
)
# Hard-blocked through Nexus: protection bypass, memory writes, custom/prebuilt JS payloads,
# process termination and custom hook bodies. Use Frida directly if an authorised test needs them.
_FRIDA_BLOCKED = (
    "bypass_ssl_pinning",
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
    },
    bindings={"dynamic.status": ("get_status",)},
    trust_annotations=False,
    protocol_mode="legacy",
    limitations=(
        "Started only when policy.dynamic_analysis.enabled with authorised devices and app identifiers.",
        "Protection-bypass, memory-write and custom-script tools are never forwarded by Nexus.",
        "Not runtime-tested here (no authorised test device).",
    ),
)
