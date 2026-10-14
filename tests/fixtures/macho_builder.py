"""Deterministic builder for a minimal, benign x86-64 Mach-O fixture (never executed).

Thin image: MH_EXECUTE | MH_PIE with __PAGEZERO and __TEXT segments, LC_LOAD_DYLIB
(/usr/lib/libSystem.B.dylib), LC_UUID and LC_MAIN pointing at ``xor eax, eax ; ret``.
``build_universal`` wraps the thin image in a one-slice fat (universal) container.
No symbol table is emitted: the built-in parser decodes headers and load commands only.
"""

from __future__ import annotations

import struct
from pathlib import Path

TEXT_VMADDR = 0x100000000
ENTRY_OFF = 0x400
CODE = bytes.fromhex("31c0c3")  # xor eax, eax ; ret
DYLIB = b"/usr/lib/libSystem.B.dylib\x00"

LC_SEGMENT_64, LC_LOAD_DYLIB, LC_UUID, LC_MAIN = 0x19, 0xC, 0x1B, 0x80000028
CPU_X86_64, MH_EXECUTE = 0x01000007, 2
MH_FLAGS = 0x1 | 0x4 | 0x80 | 0x200000  # NOUNDEFS | DYLDLINK | TWOLEVEL | PIE


def _segment(name: bytes, vmaddr: int, vmsize: int, fileoff: int, filesize: int, prot: int) -> bytes:
    return struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, 72, name, vmaddr, vmsize, fileoff, filesize, prot, prot, 0, 0)


def build_thin() -> bytes:
    dylib_size = (24 + len(DYLIB) + 7) & ~7
    dylib = struct.pack("<IIIIII", LC_LOAD_DYLIB, dylib_size, 24, 2, 0x10000, 0x10000) + DYLIB
    dylib += b"\x00" * (dylib_size - len(dylib))
    commands = [
        _segment(b"__PAGEZERO", 0, TEXT_VMADDR, 0, 0, 0),
        _segment(b"__TEXT", TEXT_VMADDR, 0x1000, 0, 0x1000, 5),
        dylib,
        struct.pack("<II16s", LC_UUID, 24, bytes(range(16))),
        struct.pack("<IIQQ", LC_MAIN, 24, ENTRY_OFF, 0),
    ]
    body = b"".join(commands)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, CPU_X86_64, 3, MH_EXECUTE, len(commands), len(body), MH_FLAGS, 0)
    image = bytearray(0x1000)
    image[: len(header) + len(body)] = header + body
    image[ENTRY_OFF : ENTRY_OFF + len(CODE)] = CODE
    return bytes(image)


TEXT_VMADDR_32 = 0x1000
LC_SEGMENT, CPU_X86 = 0x1, 7


def _segment32(name: bytes, vmaddr: int, vmsize: int, fileoff: int, filesize: int, prot: int) -> bytes:
    return struct.pack("<II16sIIIIiiII", LC_SEGMENT, 56, name, vmaddr, vmsize, fileoff, filesize, prot, prot, 0, 0)


def build_thin32() -> bytes:
    """32-bit i386 image: LC_SEGMENT (not _64) segments and a 28-byte mach_header."""
    commands = [
        _segment32(b"__PAGEZERO", 0, TEXT_VMADDR_32, 0, 0, 0),
        _segment32(b"__TEXT", TEXT_VMADDR_32, 0x1000, 0, 0x1000, 5),
        struct.pack("<IIQQ", LC_MAIN, 24, ENTRY_OFF, 0),
    ]
    body = b"".join(commands)
    header = struct.pack("<IiiIIII", 0xFEEDFACE, CPU_X86, 3, MH_EXECUTE, len(commands), len(body), MH_FLAGS)
    image = bytearray(0x1000)
    image[: len(header) + len(body)] = header + body
    image[ENTRY_OFF : ENTRY_OFF + len(CODE)] = CODE
    return bytes(image)


def build_universal(thin: bytes | None = None, cputype: int = CPU_X86_64) -> bytes:
    thin = build_thin() if thin is None else thin
    offset = 0x1000
    fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">iiIII", cputype, 3, offset, len(thin), 12)
    return fat + b"\x00" * (offset - len(fat)) + thin


def write_macho(path: Path, universal: bool = False) -> Path:
    path.write_bytes(build_universal() if universal else build_thin())
    return path
