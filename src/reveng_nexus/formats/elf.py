"""ELF metadata via pyelftools (public domain)."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

_ARCH = {
    "EM_X86_64": ("x86_64", 64),
    "EM_386": ("x86", 32),
    "EM_AARCH64": ("arm64", 64),
    "EM_ARM": ("arm", 32),
    "EM_MIPS": ("mips", 32),
    "EM_PPC": ("ppc", 32),
    "EM_PPC64": ("ppc64", 64),
    "EM_RISCV": ("riscv", 0),
}

_MAX_SYMBOLS = 20000


def inspect_elf(path: Path, blob: bytes) -> dict[str, Any]:
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    notes: list[str] = []
    try:
        elf = ELFFile(io.BytesIO(blob))
    except ELFError as exc:
        return {"format": "elf", "error": f"malformed ELF header: {exc}"}

    machine = elf["e_machine"]
    arch, bits = _ARCH.get(machine, (str(machine).lower(), 0))
    if bits == 0:
        bits = elf.elfclass
    e_type = elf["e_type"]

    segments: list[dict[str, Any]] = []
    load_vaddrs: list[int] = []
    for seg in elf.iter_segments():
        entry = {
            "type": seg["p_type"],
            "vaddr": seg["p_vaddr"],
            "offset": seg["p_offset"],
            "file_size": seg["p_filesz"],
            "mem_size": seg["p_memsz"],
            "flags": "".join(flag for bit, flag in ((4, "r"), (2, "w"), (1, "x")) if seg["p_flags"] & bit),
        }
        segments.append(entry)
        if seg["p_type"] == "PT_LOAD":
            load_vaddrs.append(seg["p_vaddr"])
    image_base = min(load_vaddrs) if load_vaddrs else 0

    sections: list[dict[str, Any]] = []
    for sec in elf.iter_sections():
        if not sec.name:
            continue
        flags = sec["sh_flags"]
        sections.append(
            {
                "name": sec.name,
                "type": sec["sh_type"],
                "vaddr": sec["sh_addr"],
                "offset": sec["sh_offset"],
                "size": sec["sh_size"],
                "alloc": bool(flags & 0x2),
                "exec": bool(flags & 0x4),
                "write": bool(flags & 0x1),
            }
        )

    functions: dict[int, dict[str, Any]] = {}
    exports: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    has_symtab = False
    for sec_name in (".symtab", ".dynsym"):
        sec = elf.get_section_by_name(sec_name)
        if sec is None or not hasattr(sec, "iter_symbols"):
            continue
        if sec_name == ".symtab":
            has_symtab = True
        for count, sym in enumerate(sec.iter_symbols()):
            if count > _MAX_SYMBOLS:
                notes.append(f"{sec_name} truncated at {_MAX_SYMBOLS} symbols")
                break
            if not sym.name:
                continue
            stype = sym["st_info"]["type"]
            bind = sym["st_info"]["bind"]
            shndx = sym["st_shndx"]
            value = sym["st_value"]
            if sec_name == ".dynsym" and shndx == "SHN_UNDEF":
                imports.append({"name": sym.name, "library": None, "kind": stype})
                continue
            if stype == "STT_FUNC" and shndx != "SHN_UNDEF" and value:
                functions.setdefault(
                    value,
                    {
                        "name": sym.name,
                        "address": value,
                        "size": sym["st_size"],
                        "source": sec_name,
                    },
                )
            if sec_name == ".dynsym" and bind in ("STB_GLOBAL", "STB_WEAK") and shndx != "SHN_UNDEF":
                exports.append({"name": sym.name, "address": value, "kind": stype})

    needed: list[str] = []
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is not None and hasattr(dynamic, "iter_tags"):
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                needed.append(tag.needed)
    if not has_symtab:
        notes.append("No .symtab: binary is stripped; function list comes from .dynsym only.")

    return {
        "format": "elf",
        "format_detail": f"ELF{elf.elfclass} {e_type}",
        "arch": arch,
        "bits": bits,
        "endianness": "little" if elf.little_endian else "big",
        "entry_point": elf["e_entry"],
        "image_base": image_base,
        "image_base_source": "lowest PT_LOAD p_vaddr",
        "is_pie": e_type == "ET_DYN",
        "stripped": not has_symtab,
        "segments": segments,
        "sections": sections,
        "libraries": needed,
        "imports": imports,
        "exports": exports,
        "functions": sorted(functions.values(), key=lambda f: f["address"]),
        "notes": notes,
    }
