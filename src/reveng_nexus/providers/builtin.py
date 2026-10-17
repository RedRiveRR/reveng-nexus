"""Built-in static provider: always available, no external engine or licence.

* Format metadata, symbols, imports/exports — parsed from bytes (pyelftools, pefile,
  Nexus' own Mach-O/APK/DEX parsers). Evidence kind: ``direct_observation``.
* Disassembly — Capstone linear sweep over symbol-bounded ranges when Capstone is
  installed. Evidence kind: ``engine_derived``. This is *not* code discovery: it has no
  control-flow recovery, so it is a useful independent decoder to cross-check a full
  engine's instruction listing, not a replacement for one.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
from typing import Any

import anyio

from ..errors import ArgumentError, CapabilityUnavailable, NotFound
from ..formats.strings import extract_strings
from .base import AnalysisProvider, OperationResult, ProviderHealth, TargetContext

_NATIVE = {"elf", "pe", "macho", "macho_universal"}
_DISASM_MAX_INSNS = 4000
_DISASM_MAX_BYTES = 256 * 1024


def _capstone_version() -> str | None:
    try:
        return importlib.metadata.version("capstone")
    except importlib.metadata.PackageNotFoundError:
        return None


def _parser_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for dist in ("pyelftools", "pefile"):
        try:
            versions[dist] = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            versions[dist] = None
    return versions


def _capstone_mode(arch: str, bits: int, endianness: str) -> tuple[int, int] | None:
    import capstone as cs

    endian = cs.CS_MODE_BIG_ENDIAN if endianness == "big" else cs.CS_MODE_LITTLE_ENDIAN
    table = {
        "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "arm64": (cs.CS_ARCH_ARM64, endian),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | endian),
        "mips": (cs.CS_ARCH_MIPS, (cs.CS_MODE_MIPS64 if bits == 64 else cs.CS_MODE_MIPS32) | endian),
    }
    return table.get(arch)


def _va_to_offset(address: int, meta: dict[str, Any]) -> tuple[int, int] | None:
    """Return (file_offset, bytes_available) for a virtual address."""
    for seg in meta.get("segments", []) or []:
        if seg.get("type", "PT_LOAD") != "PT_LOAD":
            continue
        start, fsize = seg.get("vaddr", 0), seg.get("file_size", seg.get("size", 0)) or 0
        if start <= address < start + fsize:
            return seg["offset"] + (address - start), start + fsize - address
    for sec in meta.get("sections", []) or []:
        start = sec.get("vaddr") or 0
        fsize = sec.get("file_size", sec.get("size")) or 0
        if start and start <= address < start + fsize and sec.get("offset") is not None:
            return sec["offset"] + (address - start), start + fsize - address
    return None


def _symbol_table_warnings(meta: dict[str, Any]) -> list[str]:
    """An empty list from a missing or unusable symbol table is unknown, not empty."""
    if meta.get("format") == "macho_universal":
        return ["universal Mach-O: symbols are decoded per architecture slice (binary.metadata) and not merged here"]
    state = meta.get("symbol_table")
    if meta.get("error") and state is None:
        # The ELF/PE/APK parser raised at intake (hostile or truncated bytes); Mach-O reports its
        # own symbol_table state below.
        return [
            f"the {meta.get('format', 'file')} could not be decoded ({str(meta['error'])[:200]}): "
            "functions, imports and exports are unknown, not empty"
        ]
    if state == "not_decoded":
        return ["the Mach-O header could not be decoded: functions, imports and exports are unknown, not empty"]
    if state == "absent":
        return ["no symbol table (LC_SYMTAB) in this file: functions, imports and exports are unknown, not empty"]
    if state == "incomplete":
        return [
            "the Mach-O load commands could not all be decoded: functions, imports and exports are unknown, not empty"
        ]
    if state == "out_of_bounds":
        return ["the symbol table points outside the file and was not decoded: results are unknown, not empty"]
    if state == "partial":
        return ["only part of a very large symbol table was decoded"]
    return []


class BuiltinStaticProvider(AnalysisProvider):
    engine = "nexus-builtin"
    engine_family = "nexus-formats"

    async def initialize(self) -> None:
        self.started = True

    async def health_check(self) -> ProviderHealth:
        versions = _parser_versions()
        cap = _capstone_version()
        missing = [name for name, version in versions.items() if version is None]
        status = "degraded" if missing else "ready"
        detail = "format parsers available" if not missing else f"missing parsers: {missing}"
        if cap is None:
            detail += "; disassembly unavailable (pip install capstone)"
        return ProviderHealth(
            status,
            detail,
            version=f"reveng-nexus builtin; capstone {cap or 'absent'}",
            extra={"parsers": versions, "capstone": cap},
        )

    def list_capabilities(self) -> dict[str, dict[str, Any]]:
        cap = _capstone_version() is not None
        native = {"available": True, "formats": sorted(_NATIVE), "engine_family": "nexus-formats"}
        return {
            "binary.metadata": native,
            "binary.functions": {**native, "note": "symbol-table/export derived; no code discovery"},
            "binary.strings": {**native, "formats": ["any"]},
            "binary.imports": native,
            "binary.exports": native,
            "binary.disassemble": {
                "available": cap,
                "engine_family": "capstone",
                "reason": "" if cap else "capstone is not installed",
                "note": "linear sweep over symbol bounds; no control-flow recovery",
            },
            "apk.manifest": {"available": True, "formats": ["apk"], "engine_family": "nexus-formats"},
            "apk.components": {"available": True, "formats": ["apk"], "engine_family": "nexus-formats"},
        }

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _read_verified(target: TargetContext) -> bytes:
        data = target.original_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != target.sha256:
            raise ArgumentError("target bytes no longer match the SHA-256 recorded at intake; re-inspect the file")
        return data

    def _result(self, operation: str, target: TargetContext, normalized: dict[str, Any], **kw: Any) -> OperationResult:
        return OperationResult(
            provider_id=self.id,
            operation=operation,
            tool_name=kw.pop("tool_name", f"builtin.{operation}"),
            engine=kw.pop("engine", self.engine),
            engine_family=kw.pop("engine_family", "nexus-formats"),
            evidence_kind=kw.pop("evidence_kind", "direct_observation"),
            normalized=normalized,
            raw=kw.pop("raw", None),
            engine_version=kw.pop("engine_version", "reveng-nexus " + _engine_version()),
            **kw,
        )

    # -- operations ------------------------------------------------------------
    async def perform(self, operation: str, target: TargetContext, params: dict[str, Any]) -> OperationResult:
        meta = target.metadata
        fmt = target.format
        if operation.startswith("binary.") and operation != "binary.strings" and fmt not in _NATIVE:
            raise CapabilityUnavailable(f"built-in {operation} supports {sorted(_NATIVE)}, not {fmt!r}")
        if operation.startswith("apk.") and fmt != "apk":
            raise CapabilityUnavailable(f"{operation} requires an APK target, got {fmt!r}")

        if operation == "binary.metadata":
            keys = (
                "format",
                "format_detail",
                "arch",
                "bits",
                "endianness",
                "entry_point",
                "image_base",
                "image_base_source",
                "is_pie",
                "stripped",
                "libraries",
                "file_type",
                "encrypted",
                "notes",
            )
            normalized = {k: meta.get(k) for k in keys if k in meta}
            normalized["sections"] = meta.get("sections", [])
            normalized["segments"] = meta.get("segments", [])
            normalized["counts"] = {
                "functions": len(meta.get("functions", []) or []),
                "imports": len(meta.get("imports", []) or []),
                "exports": len(meta.get("exports", []) or []),
            }
            return self._result(
                operation,
                target,
                normalized,
                warnings=_symbol_table_warnings(meta) if meta.get("error") else [],
                claim=f"{meta.get('format_detail') or fmt} {meta.get('arch')}",
            )

        if operation == "binary.functions":
            functions = meta.get("functions", []) or []
            query = (params.get("query") or "").casefold()
            rows = [f for f in functions if not query or query in str(f.get("name", "")).casefold()]
            limit = int(params.get("limit", 500))
            normalized = {
                "functions": rows[:limit],
                "total": len(rows),
                "basis": "symbol tables / exports / entry point (no code discovery)",
                "image_base": meta.get("image_base"),
            }
            warnings = _symbol_table_warnings(meta)
            if meta.get("stripped"):
                warnings.append("target is stripped; built-in function list is incomplete by construction")
            return self._result(
                operation, target, normalized, warnings=warnings, claim=f"{len(rows)} symbol-table functions"
            )

        if operation in {"binary.imports", "binary.exports"}:
            key = operation.split(".")[1]
            rows = meta.get(key, []) or []
            return self._result(
                operation,
                target,
                {
                    key: rows[: int(params.get("limit", 2000))],
                    "total": len(rows),
                    "libraries": meta.get("libraries", []),
                },
                warnings=_symbol_table_warnings(meta),
                claim=f"{len(rows)} {key}",
            )

        if operation == "binary.strings":
            data = await anyio.to_thread.run_sync(self._read_verified, target)
            found = await anyio.to_thread.run_sync(
                lambda: extract_strings(
                    data,
                    meta,
                    min_length=int(params.get("min_length", 4)),
                    query=params.get("query"),
                    limit=int(params.get("limit", 200)),
                )
            )
            found["image_base"] = meta.get("image_base")
            return self._result(operation, target, found, claim=f"{found['total_matches']} strings")

        if operation == "binary.disassemble":
            return await self._disassemble(target, params)

        if operation in {"apk.manifest", "apk.components"}:
            manifest = meta.get("manifest")
            if manifest is None:
                raise CapabilityUnavailable(meta.get("manifest_error", "manifest could not be decoded"))
            if operation == "apk.manifest":
                normalized = {k: v for k, v in manifest.items() if k != "components"}
                normalized["component_count"] = len(manifest.get("components", []))
                normalized["dex_files"] = meta.get("dex_files", [])
                normalized["native_libraries"] = meta.get("native_libraries", [])
            else:
                normalized = {
                    "package": manifest.get("package"),
                    "target_sdk": manifest.get("target_sdk"),
                    "permissions_requested": manifest.get("permissions_requested", []),
                    "permissions_declared": manifest.get("permissions_declared", []),
                    "application": manifest.get("application", {}),
                    "components": manifest.get("components", []),
                    "exported_components": [c for c in manifest.get("components", []) if c.get("exported")],
                }
            return self._result(operation, target, normalized, claim=f"manifest of {manifest.get('package')}")

        raise CapabilityUnavailable(f"built-in provider does not implement {operation}")

    async def _disassemble(self, target: TargetContext, params: dict[str, Any]) -> OperationResult:
        version = _capstone_version()
        if version is None:
            raise CapabilityUnavailable("capstone is not installed", remediation="pip install capstone")
        meta = target.metadata
        mode = _capstone_mode(str(meta.get("arch")), int(meta.get("bits") or 0), str(meta.get("endianness")))
        if mode is None:
            raise CapabilityUnavailable(f"built-in disassembly does not support arch {meta.get('arch')!r}")
        functions = meta.get("functions", []) or []
        name = params.get("name")
        address = params.get("address")
        count = params.get("count")
        func = None
        if name:
            func = next((f for f in functions if f.get("name") == name), None)
            if func is None:
                raise NotFound(f"function {name!r} is not in the symbol table; pass an address instead")
            address = func["address"]
        elif address is not None:
            func = next((f for f in functions if f.get("address") == address), None)
        if address is None:
            raise ArgumentError("disassembly needs a function name or address")
        mapped = _va_to_offset(int(address), meta)
        if mapped is None:
            raise ArgumentError(f"address {int(address):#x} is not backed by file data")
        offset, available = mapped
        if func is not None and func.get("size") and count is None:
            length = min(int(func["size"]), available, _DISASM_MAX_BYTES)
            basis = f"symbol-table bounds ({func.get('source')})"
            max_insns = _DISASM_MAX_INSNS
        else:
            max_insns = max(1, min(int(count or 64), _DISASM_MAX_INSNS))
            length = min(available, max_insns * 16, _DISASM_MAX_BYTES)
            basis = f"linear sweep of up to {max_insns} instructions (no function bounds known)"
        data = await anyio.to_thread.run_sync(self._read_verified, target)
        chunk = data[offset : offset + length]

        def run() -> list[dict[str, Any]]:
            import capstone as cs

            md = cs.Cs(*mode)
            out = []
            for insn in md.disasm(chunk, int(address)):
                out.append(
                    {
                        "address": insn.address,
                        "bytes": insn.bytes.hex(),
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                    }
                )
                if len(out) >= max_insns:
                    break
            return out

        insns = await anyio.to_thread.run_sync(run)
        warnings = []
        decoded = sum(len(i["bytes"]) // 2 for i in insns)
        if func is not None and func.get("size") and decoded < length:
            warnings.append(f"decoding stopped after {decoded}/{length} bytes (invalid instruction or data)")
        normalized = {
            "function": {
                "name": func.get("name") if func else None,
                "address": int(address),
                "size": func.get("size") if func else None,
            },
            "instructions": insns,
            "basis": basis,
            "decoder": f"capstone {version}",
        }
        return self._result(
            "binary.disassemble",
            target,
            normalized,
            engine="capstone",
            engine_family="capstone",
            evidence_kind="engine_derived",
            engine_version=f"capstone {version}",
            subject_type="function",
            subject_address=int(address),
            subject_name=func.get("name") if func else None,
            warnings=warnings,
            claim=f"{len(insns)} instructions decoded",
            tool_name="builtin.capstone_disasm",
        )


def _engine_version() -> str:
    from .. import __version__

    return __version__
