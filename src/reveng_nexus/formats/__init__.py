"""Read-only executable/package format parsing used by the built-in provider.

Nothing here executes, loads or maps the target as code; files are parsed as bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .android import inspect_apk, inspect_dex
from .elf import inspect_elf
from .macho import inspect_macho
from .pe import inspect_pe

MAGIC_TABLE: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho_fat_or_java_class"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
)


def sniff_format(header: bytes) -> str:
    for magic, name in MAGIC_TABLE:
        if header.startswith(magic):
            return name
    return "unknown"


def inspect_file(path: Path, data: bytes | None = None) -> dict[str, Any]:
    """Return format metadata for ``path``. ``data`` may supply already-read bytes."""
    blob = data if data is not None else path.read_bytes()
    kind = sniff_format(blob[:8])
    if kind == "elf":
        return inspect_elf(path, blob)
    if kind == "pe":
        return inspect_pe(path, blob)
    if kind in {"macho", "macho_fat_or_java_class"}:
        return inspect_macho(path, blob)
    if kind == "dex":
        return inspect_dex(blob)
    if kind == "zip":
        return inspect_apk(path)
    return {
        "format": "unknown",
        "notes": ["No supported executable or package magic was recognised; treat as raw data."],
    }


__all__ = ["inspect_file", "sniff_format"]
