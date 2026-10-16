"""Minimal Mach-O / universal header parsing (no third-party dependency).

Decoded: the header, the load-command inventory, segments with their sections and the
``LC_SYMTAB`` symbol table. Functions are defined symbols in instruction sections, imports are
undefined external symbols and exports are defined external symbols; nothing is inferred from
code. Mach-O symbols carry no size, so function sizes stay unknown. Every offset and count is
bounds-checked; ``symbol_table`` says whether symbols were decoded, absent or unusable, so an
absent table is never reported as an empty one.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

_CPU = {
    7: ("x86", 32),
    0x01000007: ("x86_64", 64),
    12: ("arm", 32),
    0x0100000C: ("arm64", 64),
    0x0200000C: ("arm64_32", 32),
}
_FILETYPES = {1: "object", 2: "execute", 6: "dylib", 8: "bundle", 9: "dylib_stub", 10: "dsym"}
_LC_NAMES = {
    0x1: "LC_SEGMENT",
    0x19: "LC_SEGMENT_64",
    0x2: "LC_SYMTAB",
    0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0x80000028: "LC_MAIN",
    0x1D: "LC_CODE_SIGNATURE",
    0x21: "LC_ENCRYPTION_INFO",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x1B: "LC_UUID",
    0x32: "LC_BUILD_VERSION",
}
_MAX_COMMANDS = 4096
_MAX_SYMBOLS = 200_000
_MAX_SECTIONS = 1024
# nlist n_type bits (mach-o/nlist.h)
_N_STAB, _N_TYPE, _N_EXT = 0xE0, 0x0E, 0x01
_N_UNDF, _N_SECT = 0x0, 0xE
# section flags (mach-o/loader.h): instruction attributes and the zero-fill section types
_S_ATTR_PURE_INSTRUCTIONS, _S_ATTR_SOME_INSTRUCTIONS = 0x80000000, 0x00000400
_S_ZEROFILL_TYPES = {0x1, 0xC, 0x12}  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
# Bytes each decoded load command must span (segment_command/_64, dylib_command, ...).
_MIN_CMD_SIZE = {
    "LC_SEGMENT": 56,
    "LC_SEGMENT_64": 72,
    "LC_LOAD_DYLIB": 24,
    "LC_LOAD_WEAK_DYLIB": 24,
    "LC_ENCRYPTION_INFO": 20,
    "LC_ENCRYPTION_INFO_64": 24,
    "LC_MAIN": 24,
    "LC_SYMTAB": 24,
}


def _parse_thin(blob: bytes, offset: int = 0) -> dict[str, Any]:
    magic = blob[offset : offset + 4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        endian = ">"
    elif magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        endian = "<"
    else:
        return {"error": "not a thin Mach-O header"}
    is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    header_size = 32 if is64 else 28
    if offset + header_size > len(blob):
        return {"error": "truncated Mach-O header", "truncated": True}
    cputype, _sub, filetype, ncmds, _sizeofcmds, flags = struct.unpack_from(endian + "iiIIII", blob, offset + 4)
    arch, bits = _CPU.get(cputype & 0xFFFFFFFF, (f"cpu_0x{cputype & 0xFFFFFFFF:x}", 64 if is64 else 32))
    cursor = offset + header_size
    commands: list[str] = []
    segments: list[dict[str, Any]] = []
    libraries: list[str] = []
    sections: list[dict[str, Any]] = []
    symtab: tuple[int, int, int, int] | None = None
    encrypted = False
    truncated = False
    entry_offset = None
    for _ in range(min(ncmds, _MAX_COMMANDS)):
        if cursor + 8 > len(blob):
            truncated = True
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", blob, cursor)
        if cmdsize < 8:
            break
        name = _LC_NAMES.get(cmd, f"0x{cmd:x}")
        if cursor + max(cmdsize, _MIN_CMD_SIZE.get(name, 8)) > len(blob):
            # The command runs past the end of the file: keep what was decoded, flag the rest.
            truncated = True
            break
        commands.append(name)
        if cmdsize < _MIN_CMD_SIZE.get(name, 8):
            cursor += cmdsize  # malformed: too short for its own fields; do not decode it
            continue
        if name in ("LC_SEGMENT", "LC_SEGMENT_64"):
            segname = blob[cursor + 8 : cursor + 24].rstrip(b"\x00").decode("latin-1")
            if name == "LC_SEGMENT_64":
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "QQQQ", blob, cursor + 24)
            else:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "IIII", blob, cursor + 24)
            # offset/file_size are needed to map addresses to file bytes (disassembly, strings).
            segments.append(
                {
                    "name": segname,
                    "vaddr": vmaddr,
                    "size": vmsize,
                    "offset": offset + fileoff,
                    "file_size": filesize,
                }
            )
            sections.extend(_sections(blob, endian, cursor, cmdsize, name == "LC_SEGMENT_64", offset))
        elif name in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"):
            (str_off,) = struct.unpack_from(endian + "I", blob, cursor + 8)
            raw = blob[cursor + str_off : cursor + cmdsize]
            libraries.append(raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace"))
        elif name in ("LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64"):
            (cryptid,) = struct.unpack_from(endian + "I", blob, cursor + 16)
            encrypted = encrypted or cryptid != 0
        elif name == "LC_MAIN":
            (entry_offset,) = struct.unpack_from(endian + "Q", blob, cursor + 8)
        elif name == "LC_SYMTAB" and symtab is None:
            symtab = struct.unpack_from(endian + "IIII", blob, cursor + 8)
        cursor += cmdsize
    text = next((s for s in segments if s["name"] == "__TEXT"), None)
    image_base = text["vaddr"] if text else None
    symbols = _symbols(blob, endian, is64, offset, symtab, sections, libraries)
    return {
        "arch": arch,
        "bits": bits,
        "endianness": "big" if endian == ">" else "little",
        "file_type": _FILETYPES.get(filetype, str(filetype)),
        "flags": flags,
        "image_base": image_base,
        "image_base_source": "__TEXT vmaddr" if text else None,
        "entry_point": (image_base + entry_offset) if (image_base is not None and entry_offset is not None) else None,
        "is_pie": bool(flags & 0x200000),
        "segments": segments,
        "sections": sections,
        "libraries": libraries,
        **symbols,
        "load_commands": commands,
        "encrypted": encrypted,
        "truncated": truncated,
    }


def _sections(blob: bytes, endian: str, cursor: int, cmdsize: int, is64: bool, base: int) -> list[dict[str, Any]]:
    """section/section_64 records that follow a segment command, within that command's bytes."""
    head, size = (72, 80) if is64 else (56, 68)
    (nsects,) = struct.unpack_from(endian + "I", blob, cursor + head - 8)
    out = []
    for i in range(min(nsects, _MAX_SECTIONS, max(0, (cmdsize - head) // size))):
        at = cursor + head + i * size
        sect = blob[at : at + 16].rstrip(b"\x00").decode("latin-1")
        seg = blob[at + 16 : at + 32].rstrip(b"\x00").decode("latin-1")
        if is64:
            addr, length, fileoff = struct.unpack_from(endian + "QQI", blob, at + 32)
            (flags,) = struct.unpack_from(endian + "I", blob, at + 64)
        else:
            addr, length, fileoff = struct.unpack_from(endian + "III", blob, at + 32)
            (flags,) = struct.unpack_from(endian + "I", blob, at + 56)
        zerofill = (flags & 0xFF) in _S_ZEROFILL_TYPES
        out.append(
            {
                "name": f"{seg},{sect}",
                "vaddr": addr,
                "size": length,
                "offset": None if zerofill else base + fileoff,
                "file_size": 0 if zerofill else length,
                "executable": bool(flags & (_S_ATTR_PURE_INSTRUCTIONS | _S_ATTR_SOME_INSTRUCTIONS)),
            }
        )
    return out


def _symbols(
    blob: bytes,
    endian: str,
    is64: bool,
    base: int,
    symtab: tuple[int, int, int, int] | None,
    sections: list[dict[str, Any]],
    libraries: list[str],
) -> dict[str, Any]:
    """Functions, imports and exports from LC_SYMTAB; a status says why nothing was decoded."""
    empty: dict[str, Any] = {"functions": [], "imports": [], "exports": []}
    if symtab is None:
        return {**empty, "symbol_table": "absent"}
    symoff, nsyms, stroff, strsize = symtab
    entry = 16 if is64 else 12
    sym_start, str_start = base + symoff, base + stroff
    if sym_start + nsyms * entry > len(blob) or str_start + strsize > len(blob):
        return {**empty, "symbol_table": "out_of_bounds"}
    strtab = blob[str_start : str_start + strsize]
    functions: dict[int, dict[str, Any]] = {}
    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    skipped = 0
    for i in range(min(nsyms, _MAX_SYMBOLS)):
        at = sym_start + i * entry
        if is64:
            strx, ntype, nsect, ndesc, value = struct.unpack_from(endian + "IBBHQ", blob, at)
        else:
            strx, ntype, nsect, ndesc, value = struct.unpack_from(endian + "IBBHI", blob, at)
        if ntype & _N_STAB:
            continue  # debugger entry, not a symbol
        if not 0 < strx < strsize:
            skipped += 1
            continue
        name = strtab[strx:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        kind, external = ntype & _N_TYPE, bool(ntype & _N_EXT)
        if kind == _N_UNDF and external and value == 0:
            ordinal = (ndesc >> 8) & 0xFF  # two-level namespace library ordinal
            library = libraries[ordinal - 1] if 1 <= ordinal <= len(libraries) else None
            imports.append({"name": name, "library": library, "kind": "N_UNDF"})
        elif kind == _N_SECT and 1 <= nsect <= len(sections):
            section = sections[nsect - 1]
            if section["executable"] and value not in functions:
                functions[value] = {"name": name, "address": value, "size": None, "source": section["name"]}
            if external:
                exports.append({"name": name, "address": value, "kind": "N_SECT"})
        elif kind == _N_SECT:
            skipped += 1  # section ordinal outside this image
    return {
        "functions": sorted(functions.values(), key=lambda f: f["address"]),
        "imports": imports,
        "exports": exports,
        "symbol_table": "decoded" if nsyms <= _MAX_SYMBOLS else "partial",
        "symbols_skipped": skipped,
    }


def inspect_macho(path: Path, blob: bytes) -> dict[str, Any]:
    notes: list[str] = []
    if blob[:4] == b"\xca\xfe\xba\xbe":
        if len(blob) < 8:
            return {"format": "macho_universal", "slices": [], "truncated": True, "notes": notes}
        (nfat,) = struct.unpack_from(">I", blob, 4)
        if nfat > 64:
            # 0xCAFEBABE is shared with Java class files, which carry a small "count" here.
            return {"format": "java_class_or_unknown", "notes": ["0xCAFEBABE with implausible fat count"]}
        slices = []
        if 8 + nfat * 20 > len(blob):
            notes.append("fat_arch table runs past the end of the file (truncated input).")
            return {"format": "macho_universal", "slices": [], "truncated": True, "notes": notes}
        for i in range(nfat):
            cputype, _sub, off, size, _align = struct.unpack_from(">iiIII", blob, 8 + i * 20)
            # Bound every read to the slice's declared extent, so a malformed slice can never be
            # decoded from the bytes of the next slice or of the fat padding.
            thin = (
                _parse_thin(blob[: off + size], off)
                if off + 32 <= min(len(blob), off + size)
                else {"error": "slice out of range"}
            )
            thin.update({"offset": off, "size": size})
            slices.append(thin)
        return {"format": "macho_universal", "slices": slices, "notes": notes}
    info = _parse_thin(blob)
    info.update({"format": "macho", "notes": notes})
    for key in ("functions", "imports", "exports"):
        info.setdefault(key, [])
    if "error" in info:
        info["symbol_table"] = "not_decoded"
    status = info.get("symbol_table")
    if status == "not_decoded":
        notes.append("The Mach-O header could not be decoded: symbols are unknown, not empty.")
    elif status == "absent":
        notes.append("No LC_SYMTAB: functions, imports and exports are unknown, not empty.")
    elif status == "out_of_bounds":
        notes.append("LC_SYMTAB points outside the file: symbols were not decoded (unknown, not empty).")
    elif status == "partial":
        notes.append(f"Symbol table larger than {_MAX_SYMBOLS} entries: only the first ones were decoded.")
    if status in {"decoded", "partial"}:
        notes.append("Functions are symbol-table entries in instruction sections; sizes are not recorded in Mach-O.")
    if info.get("symbols_skipped"):
        notes.append(f"{info['symbols_skipped']} symbol(s) with an invalid name or section index were skipped.")
    if info.get("truncated"):
        notes.append("Load commands run past the end of the file: metadata is partial (truncated input).")
    if info.get("encrypted"):
        notes.append("LC_ENCRYPTION_INFO cryptid != 0: code is encrypted; static output will be unreliable.")
    return info
