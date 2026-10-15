"""Deterministic builders for tiny, benign Electron-style analysis fixtures.

Generated at test time; nothing is committed as a binary and nothing is ever executed.

* ``build_asar`` packs a two-file JavaScript "application" into the Electron ASAR archive format
  (``@electron/asar``: an 8-byte size pickle, a JSON header pickle, then the file bytes, with
  per-file SHA-256 integrity blocks).
* ``build_fuse_elf`` takes the ELF fixture and appends an Electron fuse wire (the
  ``dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`` sentinel, wire version 1, a length byte and one ASCII
  ``0``/``1`` byte per fuse) so a fuse reader has a known answer. It is not a real Electron build.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from .elf_builder import build_elf

FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
# FuseV1 order: RunAsNode, EnableCookieEncryption, EnableNodeOptionsEnvironmentVariable,
# EnableNodeCliInspectArguments, EnableEmbeddedAsarIntegrityValidation, OnlyLoadAppFromAsar,
# LoadBrowserProcessSpecificV8Snapshot, GrantFileProtocolExtraPrivileges.
FUSES = b"01001101"

APP_FILES: dict[str, bytes] = {
    "package.json": json.dumps({"name": "nexus-fixture-app", "version": "1.0.0", "main": "main.js"}, indent=2).encode(),
    "main.js": (
        b'"use strict";\n'
        b'const { greet } = require("./lib/greeter.js");\n'
        b"function start(name) {\n"
        b"  return greet(name);\n"
        b"}\n"
        b"module.exports = { start };\n"
    ),
    "lib/greeter.js": (
        b'"use strict";\n'
        b'const GREETING = "Hello from the RevEng Nexus fixture";\n'
        b"function greet(name) {\n"
        b"  return `${GREETING}, ${name}`;\n"
        b"}\n"
        b"module.exports = { greet };\n"
    ),
}

_BLOCK = 4 * 1024 * 1024


def _pickle(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def build_asar(files: dict[str, bytes] | None = None) -> bytes:
    files = APP_FILES if files is None else files
    tree: dict = {"files": {}}
    body = b""
    for name, data in files.items():
        node = tree
        *dirs, leaf = name.split("/")
        for part in dirs:
            node = node["files"].setdefault(part, {"files": {}})
        node["files"][leaf] = {
            "size": len(data),
            "offset": str(len(body)),
            "integrity": {
                "algorithm": "SHA256",
                "hash": hashlib.sha256(data).hexdigest(),
                "blockSize": _BLOCK,
                "blocks": [
                    hashlib.sha256(data[i : i + _BLOCK]).hexdigest() for i in range(0, max(len(data), 1), _BLOCK)
                ],
            },
        }
        body += data
    header = json.dumps(tree, separators=(",", ":")).encode()
    string = struct.pack("<I", len(header)) + header + b"\0" * (-len(header) % 4)
    header_pickle = _pickle(string)
    size_pickle = _pickle(struct.pack("<I", len(header_pickle)))
    return size_pickle + header_pickle + body


def build_fuse_elf(fuses: bytes = FUSES) -> bytes:
    elf, _functions, _strings = build_elf()
    return elf + FUSE_SENTINEL + bytes([1, len(fuses)]) + fuses


def write_asar(path: Path) -> Path:
    path.write_bytes(build_asar())
    return path


def write_fuse_elf(path: Path) -> Path:
    path.write_bytes(build_fuse_elf())
    return path
