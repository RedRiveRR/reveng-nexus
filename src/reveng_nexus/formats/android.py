"""APK / DEX inspection without executing anything.

The APK is opened as a ZIP archive. ``AndroidManifest.xml`` is decoded from Android's
binary XML ("AXML") format by a small parser written for this project. It handles
the chunks needed for manifest metadata (string pool, resource map, namespaces and
elements). Obfuscated or malformed manifests are reported, not guessed.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Fallback names for android:* attributes when the string pool name is blank
# (seen in some obfuscated APKs). Values are android.R.attr constants.
_ATTR_BY_RESID = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010027: "scheme",
    0x01010028: "host",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic",
}

_RES_XML = 0x0003
_STRING_POOL = 0x0001
_RESOURCE_MAP = 0x0180
_START_NS, _END_NS, _START_EL, _END_EL, _CDATA = 0x0100, 0x0101, 0x0102, 0x0103, 0x0104
_UTF8_FLAG = 0x100
_NO_ENTRY = 0xFFFFFFFF
_MAX_ELEMENTS = 200_000
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_APK_ENTRIES = 200_000

_TYPE_REFERENCE, _TYPE_STRING = 0x01, 0x03
_TYPE_INT_DEC, _TYPE_INT_HEX, _TYPE_INT_BOOLEAN = 0x10, 0x11, 0x12


class AxmlError(ValueError):
    pass


def _decode_string_pool(data: bytes, start: int) -> list[str]:
    _type, header_size, size = struct.unpack_from("<HHI", data, start)
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", data, start + 8)
    if count > 1_000_000:
        raise AxmlError("string pool too large")
    utf8 = bool(flags & _UTF8_FLAG)
    offsets = struct.unpack_from(f"<{count}I", data, start + header_size) if count else ()
    base = start + strings_start
    out: list[str] = []
    for off in offsets:
        pos = base + off
        if pos >= start + size:
            out.append("")
            continue
        if utf8:
            # u16 length (1-2 bytes) then u8 length (1-2 bytes) then bytes.
            n = data[pos]
            pos += 2 if n & 0x80 else 1
            n = data[pos]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                pos += 1
            out.append(data[pos : pos + n].decode("utf-8", errors="replace"))
        else:
            (n,) = struct.unpack_from("<H", data, pos)
            pos += 2
            if n & 0x8000:
                (n2,) = struct.unpack_from("<H", data, pos)
                n = ((n & 0x7FFF) << 16) | n2
                pos += 2
            out.append(data[pos : pos + n * 2].decode("utf-16-le", errors="replace"))
    return out


def parse_axml(data: bytes) -> dict[str, Any]:
    """Decode binary XML into a nested ``{"tag", "attrs", "children"}`` tree."""
    if len(data) < 8:
        raise AxmlError("file too short")
    typ, _hsize, total = struct.unpack_from("<HHI", data, 0)
    if typ != _RES_XML:
        raise AxmlError(f"not binary XML (chunk type 0x{typ:04x})")
    total = min(total, len(data))
    strings: list[str] = []
    resource_ids: list[int] = []
    root: dict[str, Any] | None = None
    stack: list[dict[str, Any]] = []
    elements = 0
    pos = 8
    while pos + 8 <= total:
        ctype, chsize, csize = struct.unpack_from("<HHI", data, pos)
        if csize < 8 or pos + csize > total:
            raise AxmlError(f"bad chunk size at offset {pos}")
        if ctype == _STRING_POOL:
            strings = _decode_string_pool(data, pos)
        elif ctype == _RESOURCE_MAP:
            n = (csize - chsize) // 4
            resource_ids = list(struct.unpack_from(f"<{n}I", data, pos + chsize))
        elif ctype == _START_EL:
            elements += 1
            if elements > _MAX_ELEMENTS:
                raise AxmlError("too many elements")
            ext = pos + chsize
            ns_idx, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, ext)
            del ns_idx
            attrs: dict[str, Any] = {}
            apos = ext + attr_start
            for _ in range(attr_count):
                a_ns, a_name, a_raw, _vsize, _res0, vtype, vdata = struct.unpack_from("<IIIHBBI", data, apos)
                apos += attr_size
                name = strings[a_name] if a_name < len(strings) else ""
                if not name and a_name < len(resource_ids):
                    name = _ATTR_BY_RESID.get(resource_ids[a_name], f"attr_0x{resource_ids[a_name]:08x}")
                ns = strings[a_ns] if a_ns != _NO_ENTRY and a_ns < len(strings) else ""
                key = f"android:{name}" if ns == ANDROID_NS else name
                if vtype == _TYPE_STRING and a_raw != _NO_ENTRY and a_raw < len(strings):
                    value: Any = strings[a_raw]
                elif vtype == _TYPE_INT_BOOLEAN:
                    value = vdata != 0
                elif vtype in (_TYPE_INT_DEC, _TYPE_INT_HEX):
                    value = vdata
                elif vtype == _TYPE_REFERENCE:
                    value = f"@0x{vdata:08x}"
                elif a_raw != _NO_ENTRY and a_raw < len(strings):
                    value = strings[a_raw]
                else:
                    value = vdata
                attrs[key] = value
            node: dict[str, Any] = {
                "tag": strings[name_idx] if name_idx < len(strings) else "?",
                "attrs": attrs,
                "children": [],
            }
            if stack:
                stack[-1]["children"].append(node)
            elif root is None:
                root = node
            stack.append(node)
        elif ctype == _END_EL:
            if stack:
                stack.pop()
        pos += csize
    if root is None:
        raise AxmlError("no root element")
    return root


_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def _resolve_class(package: str, name: str) -> str:
    if name.startswith("."):
        return package + name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def summarize_manifest(root: dict[str, Any]) -> dict[str, Any]:
    if root.get("tag") != "manifest":
        raise AxmlError("root element is not <manifest>")
    attrs = root["attrs"]
    package = str(attrs.get("package", ""))
    summary: dict[str, Any] = {
        "package": package,
        "version_code": attrs.get("android:versionCode"),
        "version_name": attrs.get("android:versionName"),
        "min_sdk": None,
        "target_sdk": None,
        "permissions_requested": [],
        "permissions_declared": [],
        "application": {},
        "components": [],
        "notes": [],
    }
    application: dict[str, Any] | None = None
    for child in root["children"]:
        tag, cattrs = child["tag"], child["attrs"]
        if tag == "uses-sdk":
            summary["min_sdk"] = cattrs.get("android:minSdkVersion")
            summary["target_sdk"] = cattrs.get("android:targetSdkVersion")
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            summary["permissions_requested"].append(cattrs.get("android:name"))
        elif tag == "permission":
            summary["permissions_declared"].append(
                {
                    "name": cattrs.get("android:name"),
                    "protection_level": cattrs.get("android:protectionLevel"),
                }
            )
        elif tag == "application":
            application = child
    target_sdk = summary["target_sdk"] if isinstance(summary["target_sdk"], int) else None
    if application is not None:
        aattrs = application["attrs"]
        summary["application"] = {
            "name": aattrs.get("android:name"),
            "debuggable": aattrs.get("android:debuggable"),
            "allow_backup": aattrs.get("android:allowBackup"),
            "uses_cleartext_traffic": aattrs.get("android:usesCleartextTraffic"),
            "network_security_config": aattrs.get("android:networkSecurityConfig"),
        }
        for comp in application["children"]:
            if comp["tag"] not in _COMPONENT_TAGS:
                continue
            cattrs = comp["attrs"]
            filters = []
            for flt in comp["children"]:
                if flt["tag"] != "intent-filter":
                    continue
                entry: dict[str, list[Any]] = {"actions": [], "categories": [], "data": []}
                for item in flt["children"]:
                    if item["tag"] == "action":
                        entry["actions"].append(item["attrs"].get("android:name"))
                    elif item["tag"] == "category":
                        entry["categories"].append(item["attrs"].get("android:name"))
                    elif item["tag"] == "data":
                        entry["data"].append({k.split(":", 1)[-1]: v for k, v in item["attrs"].items()})
                filters.append(entry)
            explicit = cattrs.get("android:exported")
            if isinstance(explicit, bool):
                exported, basis = explicit, "explicit android:exported"
            elif comp["tag"] == "provider":
                exported = target_sdk is not None and target_sdk < 17
                basis = "implicit (provider default depends on targetSdk < 17)"
            elif filters:
                exported = target_sdk is None or target_sdk < 31
                basis = (
                    "implicit: has intent-filter and no android:exported "
                    "(Android 12+/targetSdk>=31 requires an explicit value)"
                )
            else:
                exported, basis = False, "implicit: no intent-filter"
            raw_name = str(cattrs.get("android:name", ""))
            summary["components"].append(
                {
                    "type": comp["tag"],
                    "name": _resolve_class(package, raw_name) if raw_name else None,
                    "exported": exported,
                    "exported_basis": basis,
                    "permission": cattrs.get("android:permission"),
                    "enabled": cattrs.get("android:enabled"),
                    "authorities": cattrs.get("android:authorities"),
                    "intent_filters": filters,
                }
            )
    if summary["application"].get("debuggable") is True:
        summary["notes"].append("android:debuggable=true is set in the manifest.")
    return summary


def inspect_dex(blob: bytes) -> dict[str, Any]:
    if len(blob) < 0x70:
        return {"format": "dex", "error": "truncated DEX header"}
    version = blob[4:7].decode("ascii", errors="replace")
    fields = struct.unpack_from("<IIIIIIIIIIIIIIIIII", blob, 0x20)
    (
        file_size,
        _hsize,
        endian_tag,
        _link_size,
        _link_off,
        _map_off,
        string_ids,
        _soff,
        type_ids,
        _toff,
        proto_ids,
        _poff,
        field_ids,
        _foff,
        method_ids,
        _moff,
        class_defs,
        _coff,
    ) = fields
    return {
        "format": "dex",
        "dex_version": version,
        "file_size": file_size,
        "endian_tag": hex(endian_tag),
        "counts": {
            "strings": string_ids,
            "types": type_ids,
            "protos": proto_ids,
            "fields": field_ids,
            "methods": method_ids,
            "classes": class_defs,
        },
    }


def inspect_apk(path: Path) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return {"format": "zip", "error": f"bad ZIP: {exc}"}
    with archive:
        infos = archive.infolist()
        if len(infos) > _MAX_APK_ENTRIES:
            return {"format": "zip", "error": f"archive has more than {_MAX_APK_ENTRIES} entries"}
        names = [info.filename for info in infos]
        if "AndroidManifest.xml" not in names:
            return {
                "format": "zip",
                "entries": len(names),
                "notes": ["ZIP archive without AndroidManifest.xml: not an APK."],
            }
        result: dict[str, Any] = {
            "format": "apk",
            "entries": len(names),
            "dex_files": sorted(n for n in names if n.startswith("classes") and n.endswith(".dex")),
            "native_libraries": sorted(n for n in names if n.startswith("lib/") and n.endswith(".so")),
            "signing_files": sorted(n for n in names if n.upper().startswith("META-INF/")),
            "notes": [],
        }
        manifest_info = archive.getinfo("AndroidManifest.xml")
        if manifest_info.file_size > _MAX_MANIFEST_BYTES:
            result["manifest_error"] = "AndroidManifest.xml exceeds size limit"
            return result
        raw = archive.read("AndroidManifest.xml")
        try:
            result["manifest"] = summarize_manifest(parse_axml(raw))
        except (AxmlError, struct.error, IndexError) as exc:
            result["manifest_error"] = f"could not decode binary manifest: {exc}"
        dex_counts = []
        for dex_name in result["dex_files"][:16]:
            header = archive.open(dex_name).read(0x70)
            info = inspect_dex(header + b"\x00" * max(0, 0x70 - len(header)))
            dex_counts.append({"file": dex_name, **info.get("counts", {})})
        result["dex_summary"] = dex_counts
        return result
