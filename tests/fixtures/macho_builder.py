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


# --- thin image with sections and an LC_SYMTAB (symbol decoding tests) -----------------------
LC_SYMTAB = 0x2
TEXT_SECT_OFF, CSTRING_OFF, LINKEDIT_OFF = 0x400, 0x500, 0x1000
MAIN_OFF, HELPER_OFF = 0x400, 0x410
SYM_CODE = {
    MAIN_OFF: bytes.fromhex("e80b00000031c0c3"),  # call _helper ; xor eax, eax ; ret
    HELPER_OFF: bytes.fromhex("b801000000c3"),  # mov eax, 1 ; ret
}
CSTRING = b"nexus fixture\x00"
STRTAB = b"\x00_main\x00_helper\x00_greeting\x00_printf\x00"
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
SYMBOLS = {  # name -> (address, kind); what a correct decoder must report
    "_main": TEXT_VMADDR + MAIN_OFF,
    "_helper": TEXT_VMADDR + HELPER_OFF,
    "_greeting": TEXT_VMADDR + CSTRING_OFF,
}


def _section64(sect: bytes, seg: bytes, addr: int, size: int, offset: int, flags: int) -> bytes:
    return struct.pack("<16s16sQQIIIIIIII", sect, seg, addr, size, offset, 0, 0, 0, flags, 0, 0, 0)


def _nlist64(strx: int, ntype: int, nsect: int, desc: int, value: int) -> bytes:
    return struct.pack("<IBBHQ", strx, ntype, nsect, desc, value)


def build_thin_with_symbols(*, symoff: int | None = None) -> bytes:
    """__TEXT (__text, __cstring), __LINKEDIT and LC_SYMTAB. Symbols, in order: a stab entry
    (skipped), local _helper and external _main in __text, external _greeting in __cstring (an
    export, not a function), undefined _printf from library ordinal 1, then one entry with an
    out-of-range name index and one with an out-of-range section index (both skipped)."""
    s = {name: STRTAB.index(name.encode() + b"\x00") for name in ("_main", "_helper", "_greeting", "_printf")}
    nlists = [
        _nlist64(s["_main"], 0x24, 1, 0, TEXT_VMADDR + MAIN_OFF),  # N_FUN stab
        _nlist64(s["_helper"], 0x0E, 1, 0, TEXT_VMADDR + HELPER_OFF),  # N_SECT
        _nlist64(s["_main"], 0x0F, 1, 0, TEXT_VMADDR + MAIN_OFF),  # N_SECT | N_EXT
        _nlist64(s["_greeting"], 0x0F, 2, 0, TEXT_VMADDR + CSTRING_OFF),
        _nlist64(s["_printf"], 0x01, 0, 1 << 8, 0),  # N_UNDF | N_EXT, ordinal 1
        _nlist64(0xFFFF, 0x0F, 1, 0, TEXT_VMADDR + MAIN_OFF),  # name index past the string table
        _nlist64(s["_helper"], 0x0E, 9, 0, TEXT_VMADDR + HELPER_OFF),  # section 9 does not exist
    ]
    symtab = b"".join(nlists)
    stroff = LINKEDIT_OFF + len(symtab)
    linkedit = symtab + STRTAB
    dylib_size = (24 + len(DYLIB) + 7) & ~7
    dylib = struct.pack("<IIIIII", LC_LOAD_DYLIB, dylib_size, 24, 2, 0x10000, 0x10000) + DYLIB
    dylib += b"\x00" * (dylib_size - len(dylib))
    text_seg = struct.pack(
        "<II16sQQQQiiII", LC_SEGMENT_64, 72 + 2 * 80, b"__TEXT", TEXT_VMADDR, 0x1000, 0, 0x1000, 5, 5, 2, 0
    )
    text_seg += _section64(
        b"__text", b"__TEXT", TEXT_VMADDR + TEXT_SECT_OFF, 0x20, TEXT_SECT_OFF, S_ATTR_PURE_INSTRUCTIONS
    )
    text_seg += _section64(b"__cstring", b"__TEXT", TEXT_VMADDR + CSTRING_OFF, len(CSTRING), CSTRING_OFF, 0x2)
    commands = [
        _segment(b"__PAGEZERO", 0, TEXT_VMADDR, 0, 0, 0),
        text_seg,
        _segment(b"__LINKEDIT", TEXT_VMADDR + 0x1000, 0x1000, LINKEDIT_OFF, len(linkedit), 1),
        dylib,
        struct.pack("<IIQQ", LC_MAIN, 24, MAIN_OFF, 0),
        struct.pack(
            "<IIIIII", LC_SYMTAB, 24, LINKEDIT_OFF if symoff is None else symoff, len(nlists), stroff, len(STRTAB)
        ),
    ]
    body = b"".join(commands)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, CPU_X86_64, 3, MH_EXECUTE, len(commands), len(body), MH_FLAGS, 0)
    image = bytearray(LINKEDIT_OFF + len(linkedit))
    image[: len(header) + len(body)] = header + body
    for off, code in SYM_CODE.items():
        image[off : off + len(code)] = code
    image[CSTRING_OFF : CSTRING_OFF + len(CSTRING)] = CSTRING
    image[LINKEDIT_OFF:] = linkedit
    return bytes(image)
