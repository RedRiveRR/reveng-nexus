"""Build a tiny APK-shaped ZIP with a binary (AXML) AndroidManifest.xml.

Written for this project to exercise the manifest parser; it is not an installable
app (no signature, the DEX is a bare header) and is never executed.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_IDS = {
    "name": 0x01010003,
    "exported": 0x01010010,
    "permission": 0x01010006,
    "debuggable": 0x0101000F,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270,
    "allowBackup": 0x01010280,
    "authorities": 0x01010018,
}
T_STRING, T_INT, T_BOOL = 0x03, 0x10, 0x12
NO = 0xFFFFFFFF

# (tag, [(ns_is_android, attr, kind, value)], children)
MANIFEST = (
    "manifest",
    [
        (False, "package", "s", "com.example.nexusfixture"),
        (True, "versionCode", "i", 7),
        (True, "versionName", "s", "1.0-fixture"),
    ],
    [
        ("uses-sdk", [(True, "minSdkVersion", "i", 24), (True, "targetSdkVersion", "i", 34)], []),
        ("uses-permission", [(True, "name", "s", "android.permission.INTERNET")], []),
        ("uses-permission", [(True, "name", "s", "android.permission.CAMERA")], []),
        (
            "application",
            [(True, "debuggable", "b", True), (True, "allowBackup", "b", False)],
            [
                (
                    "activity",
                    [(True, "name", "s", ".MainActivity"), (True, "exported", "b", True)],
                    [
                        (
                            "intent-filter",
                            [],
                            [
                                ("action", [(True, "name", "s", "android.intent.action.MAIN")], []),
                                ("category", [(True, "name", "s", "android.intent.category.LAUNCHER")], []),
                            ],
                        ),
                    ],
                ),
                ("activity", [(True, "name", "s", ".HiddenActivity")], []),
                ("service", [(True, "name", "s", ".SyncService"), (True, "exported", "b", False)], []),
                (
                    "receiver",
                    [(True, "name", "s", "com.example.nexusfixture.BootReceiver")],
                    [
                        (
                            "intent-filter",
                            [],
                            [
                                ("action", [(True, "name", "s", "android.intent.action.BOOT_COMPLETED")], []),
                            ],
                        ),
                    ],
                ),
                (
                    "provider",
                    [
                        (True, "name", "s", ".DataProvider"),
                        (True, "exported", "b", True),
                        (True, "authorities", "s", "com.example.nexusfixture.data"),
                    ],
                    [],
                ),
            ],
        ),
    ],
)


def _walk_strings(node, out: list[str]) -> None:
    tag, attrs, children = node
    for _ns, attr, kind, value in attrs:
        if attr not in out:
            out.append(attr)
        if kind == "s" and value not in out:
            out.append(value)
    if tag not in out:
        out.append(tag)
    for child in children:
        _walk_strings(child, out)


def build_axml() -> bytes:
    # Attribute names with resource ids must come first so the resource map lines up.
    strings: list[str] = list(ATTR_IDS)
    for extra in ("android", ANDROID_NS):
        strings.append(extra)
    _walk_strings(MANIFEST, strings)
    index = {s: i for i, s in enumerate(strings)}

    # --- string pool (UTF-16) ---
    offsets, blob = [], bytearray()
    for s in strings:
        offsets.append(len(blob))
        encoded = s.encode("utf-16-le")
        blob += struct.pack("<H", len(s)) + encoded + b"\x00\x00"
    while len(blob) % 4:
        blob += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = struct.pack(
        "<HHIIIIII", 0x0001, header_size, strings_start + len(blob), len(strings), 0, 0, strings_start, 0
    )
    pool += b"".join(struct.pack("<I", o) for o in offsets) + bytes(blob)

    resmap_body = b"".join(struct.pack("<I", ATTR_IDS[name]) for name in ATTR_IDS)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + len(resmap_body)) + resmap_body

    chunks = bytearray()
    ns_prefix, ns_uri = index["android"], index[ANDROID_NS]
    chunks += struct.pack("<HHIII", 0x0100, 16, 24, 1, NO) + struct.pack("<II", ns_prefix, ns_uri)

    def emit(node) -> None:
        tag, attrs, children = node
        attr_bytes = bytearray()
        for is_android, attr, kind, value in attrs:
            ns = ns_uri if is_android else NO
            if kind == "s":
                raw, vtype, data = index[value], T_STRING, index[value]
            elif kind == "b":
                raw, vtype, data = NO, T_BOOL, 0xFFFFFFFF if value else 0
            else:
                raw, vtype, data = NO, T_INT, int(value)
            attr_bytes += struct.pack("<IIIHBBI", ns, index[attr], raw, 8, 0, vtype, data)
        ext = struct.pack("<IIHHHHHH", NO, index[tag], 20, 20, len(attrs), 0, 0, 0)
        body = ext + bytes(attr_bytes)
        chunks.extend(struct.pack("<HHIII", 0x0102, 16, 16 + len(body), 1, NO) + body)
        for child in children:
            emit(child)
        chunks.extend(struct.pack("<HHIII", 0x0103, 16, 24, 1, NO) + struct.pack("<II", NO, index[tag]))

    emit(MANIFEST)
    chunks += struct.pack("<HHIII", 0x0101, 16, 24, 1, NO) + struct.pack("<II", ns_prefix, ns_uri)
    body = pool + resmap + bytes(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def build_dex_header() -> bytes:
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, 0x70)  # file_size
    struct.pack_into("<I", header, 0x24, 0x70)  # header_size
    struct.pack_into("<I", header, 0x28, 0x12345678)  # endian tag
    return bytes(header)


def write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", build_axml())
        zf.writestr("classes.dex", build_dex_header())
        zf.writestr("res/values/strings.xml", "<resources/>")
    return path
