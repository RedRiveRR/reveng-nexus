"""Printable-string extraction with file offsets and (when mappable) virtual addresses."""

from __future__ import annotations

import re
from typing import Any

_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}")


def _offset_to_va(offset: int, info: dict[str, Any]) -> int | None:
    for seg in info.get("segments", []) or []:
        file_size = seg.get("file_size")
        if seg.get("type", "PT_LOAD") not in ("PT_LOAD", None) or file_size is None:
            continue
        start = seg.get("offset", 0)
        if start <= offset < start + file_size:
            return seg["vaddr"] + (offset - start)
    for sec in info.get("sections", []) or []:
        start = sec.get("offset")
        size = sec.get("file_size", sec.get("size"))
        if start is None or size is None or not sec.get("vaddr"):
            continue
        if sec.get("alloc") is False:
            continue
        if start <= offset < start + size:
            return sec["vaddr"] + (offset - start)
    return None


def extract_strings(
    blob: bytes,
    info: dict[str, Any] | None = None,
    *,
    min_length: int = 4,
    query: str | None = None,
    limit: int = 500,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
) -> dict[str, Any]:
    """Return strings sorted by offset. ``query`` is a case-insensitive substring filter."""
    min_length = max(2, min(int(min_length), 256))
    limit = max(1, min(int(limit), 10000))
    needle = query.casefold() if query else None
    found: list[dict[str, Any]] = []
    total = 0
    patterns = []
    if "ascii" in encodings:
        patterns.append(("ascii", re.compile(_ASCII.pattern % min_length)))
    if "utf-16le" in encodings:
        patterns.append(("utf-16le", re.compile(_UTF16.pattern % min_length)))
    for encoding, pattern in patterns:
        for match in pattern.finditer(blob):
            raw = match.group(0)
            text = raw.decode("ascii" if encoding == "ascii" else "utf-16-le", errors="replace")
            if needle and needle not in text.casefold():
                continue
            total += 1
            if len(found) >= limit:
                continue
            offset = match.start()
            entry: dict[str, Any] = {
                "offset": offset,
                "encoding": encoding,
                "value": text[:1024],
                "length": len(text),
            }
            if info is not None:
                va = _offset_to_va(offset, info)
                if va is not None:
                    entry["address"] = va
            found.append(entry)
    found.sort(key=lambda s: s["offset"])
    return {"strings": found, "returned": len(found), "total_matches": total, "truncated": total > len(found)}
