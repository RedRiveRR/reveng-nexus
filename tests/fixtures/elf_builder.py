"""Deterministic builder for a tiny, benign x86-64 ELF analysis fixture.

The fixture is generated at test time so no binary is committed to Git. It is
never executed by the test-suite; it only exists so static-analysis engines have
a small, known input with symbols, strings and direct calls.

Layout (ET_EXEC, single RX PT_LOAD at 0x400000):

    add_numbers(a, b)   lea eax, [rdi+rsi] ; ret
    check_key(x)        cmp edi, 0x1337 ; sete al ; movzx eax, al ; ret
    get_greeting()      lea rax, [rip+greeting] ; ret
    main()              calls add_numbers, check_key, get_greeting
    _start              call main ; exit syscall  (never run by tests)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

BASE = 0x400000
GREETING = b"Hello from the RevEng Nexus fixture\x00"
KEY_LABEL = b"LICENSE-KEY-CHECK\x00"


@dataclass(frozen=True)
class FixtureFunction:
    name: str
    address: int
    size: int


def _rel32(src_next: int, dst: int) -> bytes:
    return struct.pack("<i", dst - src_next)


def build_elf() -> tuple[bytes, dict[str, FixtureFunction], dict[str, int]]:
    """Return (elf_bytes, functions_by_name, string_addresses)."""
    ehdr_size, phdr_size = 64, 56
    text_off = 0x100  # keep headers well clear of code
    text_addr = BASE + text_off

    # Code is assembled in two passes because main/_start need final addresses.
    add_numbers = bytes.fromhex("8d0437c3")
    check_key = bytes.fromhex("81ff371300000f94c00fb6c0c3")
    funcs: list[tuple[str, bytes]] = [("add_numbers", add_numbers), ("check_key", check_key)]

    # get_greeting placeholder, patched once .rodata address is known.
    get_greeting_len = 8
    main_len = 4 + 5 + 5 + 5 + 2 + 5 + 5 + 2 + 4 + 1
    start_len = 5 + 2 + 5 + 2

    addrs: dict[str, int] = {}
    cursor = text_addr
    for name, code in funcs:
        addrs[name] = cursor
        cursor += len(code)
    addrs["get_greeting"] = cursor
    cursor += get_greeting_len
    addrs["main"] = cursor
    cursor += main_len
    addrs["_start"] = cursor
    cursor += start_len
    text_end = cursor

    rodata_addr = (text_end + 0xF) & ~0xF
    greeting_addr = rodata_addr
    key_addr = rodata_addr + len(GREETING)
    rodata = GREETING + KEY_LABEL

    gg_next = addrs["get_greeting"] + 7
    get_greeting = b"\x48\x8d\x05" + _rel32(gg_next, greeting_addr) + b"\xc3"

    m = addrs["main"]
    main = bytearray()
    main += bytes.fromhex("4883ec08")  # sub rsp, 8
    main += bytes.fromhex("bf02000000")  # mov edi, 2
    main += bytes.fromhex("be03000000")  # mov esi, 3
    main += b"\xe8" + _rel32(m + len(main) + 5, addrs["add_numbers"])
    main += bytes.fromhex("89c7")  # mov edi, eax
    main += b"\xe8" + _rel32(m + len(main) + 5, addrs["check_key"])
    main += b"\xe8" + _rel32(m + len(main) + 5, addrs["get_greeting"])
    main += bytes.fromhex("31c0")  # xor eax, eax
    main += bytes.fromhex("4883c408")  # add rsp, 8
    main += b"\xc3"
    assert len(main) == main_len

    s = addrs["_start"]
    start = bytearray()
    start += b"\xe8" + _rel32(s + 5, m)
    start += bytes.fromhex("89c7")  # mov edi, eax
    start += bytes.fromhex("b83c000000")  # mov eax, 60 (exit)
    start += bytes.fromhex("0f05")  # syscall
    assert len(start) == start_len

    text = add_numbers + check_key + get_greeting + bytes(main) + bytes(start)
    assert text_addr + len(text) == text_end

    rodata_off = rodata_addr - BASE
    image = bytearray(rodata_off + len(rodata))
    image[text_off : text_off + len(text)] = text
    image[rodata_off : rodata_off + len(rodata)] = rodata
    load_size = len(image)

    sizes = {
        "add_numbers": len(add_numbers),
        "check_key": len(check_key),
        "get_greeting": len(get_greeting),
        "main": len(main),
        "_start": len(start),
    }
    functions = {name: FixtureFunction(name=name, address=addrs[name], size=sizes[name]) for name in sizes}

    # --- string tables and symbols ---
    shstr = b"\x00.text\x00.rodata\x00.symtab\x00.strtab\x00.shstrtab\x00"

    def shname(name: str) -> int:
        return shstr.index(name.encode() + b"\x00")

    strtab = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name in [*sizes.keys(), "greeting", "key_label"]:
        name_offsets[name] = len(strtab)
        strtab += name.encode() + b"\x00"

    def sym(name_off: int, info: int, shndx: int, value: int, size: int) -> bytes:
        return struct.pack("<IBBHQQ", name_off, info, 0, shndx, value, size)

    STB_GLOBAL, STT_FUNC, STT_OBJECT = 1, 2, 1
    symtab = sym(0, 0, 0, 0, 0)
    for name in sizes:
        symtab += sym(name_offsets[name], (STB_GLOBAL << 4) | STT_FUNC, 1, addrs[name], sizes[name])
    symtab += sym(name_offsets["greeting"], (STB_GLOBAL << 4) | STT_OBJECT, 2, greeting_addr, len(GREETING))
    symtab += sym(name_offsets["key_label"], (STB_GLOBAL << 4) | STT_OBJECT, 2, key_addr, len(KEY_LABEL))

    blob = bytearray(image)

    def append(data: bytes, align: int = 8) -> int:
        while len(blob) % align:
            blob.append(0)
        off = len(blob)
        blob.extend(data)
        return off

    symtab_off = append(symtab)
    strtab_off = append(bytes(strtab), 1)
    shstr_off = append(shstr, 1)
    while len(blob) % 8:
        blob.append(0)
    shoff = len(blob)

    SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 1, 2, 3
    SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4

    def shdr(name, typ, flags, addr, off, size, link=0, info=0, align=1, entsize=0) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size, link, info, align, entsize)

    sections = [
        shdr(0, 0, 0, 0, 0, 0),
        shdr(
            shname(".text"),
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            text_addr,
            text_off,
            len(text),
            align=16,
        ),
        shdr(shname(".rodata"), SHT_PROGBITS, SHF_ALLOC, rodata_addr, rodata_off, len(rodata)),
        shdr(
            shname(".symtab"),
            SHT_SYMTAB,
            0,
            0,
            symtab_off,
            len(symtab),
            link=4,
            info=1,
            align=8,
            entsize=24,
        ),
        shdr(shname(".strtab"), SHT_STRTAB, 0, 0, strtab_off, len(strtab)),
        shdr(shname(".shstrtab"), SHT_STRTAB, 0, 0, shstr_off, len(shstr)),
    ]
    blob.extend(b"".join(sections))

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        0x3E,  # EM_X86_64
        1,
        addrs["_start"],
        ehdr_size,  # phoff
        shoff,
        0,
        ehdr_size,
        phdr_size,
        1,
        64,
        len(sections),
        5,  # shstrndx
    )
    PF_X, PF_R = 1, 4
    phdr = struct.pack("<IIQQQQQQ", 1, PF_R | PF_X, 0, BASE, BASE, load_size, load_size, 0x1000)
    blob[0 : len(ehdr)] = ehdr
    blob[ehdr_size : ehdr_size + phdr_size] = phdr

    strings = {"greeting": greeting_addr, "key_label": key_addr}
    return bytes(blob), functions, strings


def write_elf(path: Path) -> dict[str, FixtureFunction]:
    data, functions, _ = build_elf()
    path.write_bytes(data)
    return functions


if __name__ == "__main__":  # pragma: no cover - manual helper
    import sys

    out = Path(sys.argv[1] if len(sys.argv) > 1 else "nexus_fixture.elf")
    for fn in write_elf(out).values():
        print(f"{fn.name:14s} 0x{fn.address:x} size={fn.size}")
