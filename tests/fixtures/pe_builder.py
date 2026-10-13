"""Deterministic builder for a minimal, benign PE32+ fixture (never executed).

One .text section (``sub rsp,28h; xor ecx,ecx; call [ExitProcess]; int3``) and one
.idata section importing KERNEL32.dll!ExitProcess.
"""

from __future__ import annotations

import struct
from pathlib import Path

IMAGE_BASE = 0x140000000
TEXT_RVA, IDATA_RVA = 0x1000, 0x2000


def build_pe() -> bytes:
    file_align = 0x200
    # --- .idata layout (RVAs) ---
    desc_rva = IDATA_RVA
    ilt_rva = IDATA_RVA + 0x28
    iat_rva = IDATA_RVA + 0x38
    hint_rva = IDATA_RVA + 0x48
    dll_rva = IDATA_RVA + 0x60
    idata = bytearray(file_align)
    struct.pack_into("<IIIII", idata, 0, ilt_rva, 0, 0, dll_rva, iat_rva)
    struct.pack_into("<QQ", idata, ilt_rva - IDATA_RVA, hint_rva, 0)
    struct.pack_into("<QQ", idata, iat_rva - IDATA_RVA, hint_rva, 0)
    struct.pack_into("<H", idata, hint_rva - IDATA_RVA, 0)
    idata[hint_rva - IDATA_RVA + 2 : hint_rva - IDATA_RVA + 2 + 12] = b"ExitProcess\x00"
    idata[dll_rva - IDATA_RVA : dll_rva - IDATA_RVA + 13] = b"KERNEL32.dll\x00"

    # --- .text ---
    code = bytearray(bytes.fromhex("4883ec28") + bytes.fromhex("31c9"))
    next_ip = TEXT_RVA + len(code) + 6
    code += b"\xff\x15" + struct.pack("<i", iat_rva - next_ip) + b"\xcc"
    text = bytes(code) + b"\x00" * (file_align - len(code))

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        file_align,
        file_align,
        0,
        TEXT_RVA,
        TEXT_RVA,
        IMAGE_BASE,
        0x1000,
        file_align,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x3000,
        file_align,
        0,
        3,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    dirs = [(0, 0)] * 16
    dirs[1] = (desc_rva, 40)
    dirs[12] = (iat_rva, 16)
    opt += b"".join(struct.pack("<II", rva, size) for rva, size in dirs)
    assert len(opt) == 240

    def section(name: bytes, vsize: int, rva: int, raw_size: int, raw_ptr: int, chars: int) -> bytes:
        return struct.pack("<8sIIIIIIHHI", name, vsize, rva, raw_size, raw_ptr, 0, 0, 0, 0, chars)

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt
    headers += section(b".text", len(code), TEXT_RVA, file_align, 0x200, 0x60000020)
    headers += section(b".idata", 0x70, IDATA_RVA, file_align, 0x400, 0xC0000040)
    headers += b"\x00" * (file_align - len(headers))
    return headers + text + bytes(idata)


def write_pe(path: Path) -> Path:
    path.write_bytes(build_pe())
    return path
