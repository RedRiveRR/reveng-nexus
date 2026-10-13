"""PE/COFF metadata via pefile (MIT)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

_MACHINES = {
    0x14C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x1C0: ("arm", 32),
    0x1C4: ("arm", 32),
    0xAA64: ("arm64", 64),
}
_MAX_IMPORTS = 20000


def inspect_pe(path: Path, blob: bytes) -> dict[str, Any]:
    import pefile

    notes: list[str] = []
    try:
        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
    except pefile.PEFormatError as exc:
        return {"format": "pe", "error": f"malformed PE: {exc}"}

    try:
        machine = pe.FILE_HEADER.Machine
        arch, bits = _MACHINES.get(machine, (f"machine_0x{machine:x}", 0))
        image_base = pe.OPTIONAL_HEADER.ImageBase
        characteristics = pe.FILE_HEADER.Characteristics
        dll_chars = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)

        sections = []
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
            chars = sec.Characteristics
            sections.append(
                {
                    "name": name,
                    "vaddr": image_base + sec.VirtualAddress,
                    "rva": sec.VirtualAddress,
                    "offset": sec.PointerToRawData,
                    "size": sec.Misc_VirtualSize,
                    "file_size": sec.SizeOfRawData,
                    "exec": bool(chars & 0x20000000),
                    "write": bool(chars & 0x80000000),
                    "entropy": round(sec.get_entropy(), 3),
                }
            )

        imports: list[dict[str, Any]] = []
        libraries: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            lib = entry.dll.decode("latin-1", errors="replace") if entry.dll else None
            if lib:
                libraries.append(lib)
            for imp in entry.imports:
                if len(imports) >= _MAX_IMPORTS:
                    notes.append(f"imports truncated at {_MAX_IMPORTS}")
                    break
                name = imp.name.decode("latin-1", errors="replace") if imp.name else None
                imports.append(
                    {
                        "library": lib,
                        "name": name or f"ordinal_{imp.ordinal}",
                        "address": imp.address,
                        "by_ordinal": imp.name is None,
                    }
                )

        exports: list[dict[str, Any]] = []
        functions: list[dict[str, Any]] = []
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_dir is not None:
            for sym in export_dir.symbols:
                name = sym.name.decode("latin-1", errors="replace") if sym.name else f"ordinal_{sym.ordinal}"
                address = image_base + sym.address
                exports.append({"name": name, "address": address, "ordinal": sym.ordinal})
                if sym.forwarder is None:
                    functions.append({"name": name, "address": address, "size": None, "source": "export"})

        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if entry_rva:
            functions.append(
                {
                    "name": "entry",
                    "address": image_base + entry_rva,
                    "size": None,
                    "source": "optional_header.AddressOfEntryPoint",
                }
            )
        notes.append(
            "PE symbol tables are rarely present; functions listed here are exports and the entry "
            "point only. Use a code-discovery engine (Ghidra/IDA/Binary Ninja) for full listings."
        )
        is_dll = bool(characteristics & 0x2000)
        return {
            "format": "pe",
            "format_detail": f"PE{'32+' if pe.OPTIONAL_HEADER.Magic == 0x20B else '32'} {'DLL' if is_dll else 'EXE'}",
            "arch": arch,
            "bits": bits,
            "endianness": "little",
            "entry_point": image_base + entry_rva if entry_rva else None,
            "image_base": image_base,
            "image_base_source": "OptionalHeader.ImageBase",
            "is_pie": bool(dll_chars & 0x40),  # DYNAMIC_BASE (ASLR)
            "stripped": True,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "sections": sections,
            "libraries": libraries,
            "imports": imports,
            "exports": exports,
            "functions": sorted(functions, key=lambda f: f["address"]),
            "notes": notes,
        }
    finally:
        pe.close()
