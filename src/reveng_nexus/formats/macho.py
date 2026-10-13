"""Minimal Mach-O / universal header parsing (no third-party dependency).

Only headers and load-command inventory are decoded; symbol tables are left to a
full engine. This is deliberately conservative.
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


def _parse_thin(blob: bytes, offset: int = 0) -> dict[str, Any]:
    magic = blob[offset : offset + 4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        endian = ">"
    elif magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        endian = "<"
    else:
        return {"error": "not a thin Mach-O header"}
    is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    cputype, _sub, filetype, ncmds, _sizeofcmds, flags = struct.unpack_from(endian + "iiIIII", blob, offset + 4)
    arch, bits = _CPU.get(cputype & 0xFFFFFFFF, (f"cpu_0x{cputype & 0xFFFFFFFF:x}", 64 if is64 else 32))
    cursor = offset + (32 if is64 else 28)
    commands: list[str] = []
    segments: list[dict[str, Any]] = []
    libraries: list[str] = []
    encrypted = False
    entry_offset = None
    for _ in range(min(ncmds, _MAX_COMMANDS)):
        if cursor + 8 > len(blob):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", blob, cursor)
        if cmdsize < 8:
            break
        name = _LC_NAMES.get(cmd, f"0x{cmd:x}")
        commands.append(name)
        if name in ("LC_SEGMENT", "LC_SEGMENT_64"):
            segname = blob[cursor + 8 : cursor + 24].rstrip(b"\x00").decode("latin-1")
            if name == "LC_SEGMENT_64":
                vmaddr, vmsize = struct.unpack_from(endian + "QQ", blob, cursor + 24)
            else:
                vmaddr, vmsize = struct.unpack_from(endian + "II", blob, cursor + 24)
            segments.append({"name": segname, "vaddr": vmaddr, "size": vmsize})
        elif name in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"):
            (str_off,) = struct.unpack_from(endian + "I", blob, cursor + 8)
            raw = blob[cursor + str_off : cursor + cmdsize]
            libraries.append(raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace"))
        elif name in ("LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64"):
            (cryptid,) = struct.unpack_from(endian + "I", blob, cursor + 16)
            encrypted = encrypted or cryptid != 0
        elif name == "LC_MAIN":
            (entry_offset,) = struct.unpack_from(endian + "Q", blob, cursor + 8)
        cursor += cmdsize
    text = next((s for s in segments if s["name"] == "__TEXT"), None)
    image_base = text["vaddr"] if text else None
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
        "libraries": libraries,
        "load_commands": commands,
        "encrypted": encrypted,
    }


def inspect_macho(path: Path, blob: bytes) -> dict[str, Any]:
    notes = ["Mach-O symbols are not decoded by the built-in parser; use a full engine."]
    if blob[:4] == b"\xca\xfe\xba\xbe":
        (nfat,) = struct.unpack_from(">I", blob, 4)
        if nfat > 64:
            # 0xCAFEBABE is shared with Java class files, which carry a small "count" here.
            return {"format": "java_class_or_unknown", "notes": ["0xCAFEBABE with implausible fat count"]}
        slices = []
        for i in range(nfat):
            cputype, _sub, off, size, _align = struct.unpack_from(">iiIII", blob, 8 + i * 20)
            thin = _parse_thin(blob, off) if off + 32 <= len(blob) else {"error": "slice out of range"}
            thin.update({"offset": off, "size": size})
            slices.append(thin)
        return {"format": "macho_universal", "slices": slices, "notes": notes}
    info = _parse_thin(blob)
    info.update({"format": "macho", "notes": notes, "functions": [], "imports": [], "exports": []})
    if info.get("encrypted"):
        notes.append("LC_ENCRYPTION_INFO cryptid != 0: code is encrypted; static output will be unreliable.")
    return info
