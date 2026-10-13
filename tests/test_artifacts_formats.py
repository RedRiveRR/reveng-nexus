import hashlib
import os
import stat
import zipfile
from pathlib import Path

import pytest

from reveng_nexus.artifacts import WorkspaceGuard, identify, stage_copy
from reveng_nexus.errors import ArgumentError, WorkspaceViolation
from reveng_nexus.formats import inspect_file, sniff_format
from reveng_nexus.formats.android import AxmlError, parse_axml
from reveng_nexus.formats.strings import extract_strings


def guard(root: Path, max_bytes: int = 1 << 20) -> WorkspaceGuard:
    return WorkspaceGuard((str(root),), max_bytes)


def test_guard_disabled_without_roots(elf_sample):
    with pytest.raises(WorkspaceViolation, match="allowed_roots"):
        WorkspaceGuard((), 100).check(str(elf_sample))


def test_guard_rejects_outside_relative_traversal_and_size(tmp_path, workspace, elf_sample):
    g = guard(workspace)
    assert g.check(str(elf_sample)) == elf_sample.resolve()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    with pytest.raises(WorkspaceViolation, match="outside"):
        g.check(str(outside))
    with pytest.raises(ArgumentError, match="absolute"):
        g.check("samples/nexus_fixture.elf")
    with pytest.raises(WorkspaceViolation, match=r"\.\."):
        g.check(str(workspace / ".." / "outside.bin"))
    with pytest.raises(ArgumentError, match="limit"):
        guard(workspace, max_bytes=10).check(str(elf_sample))
    with pytest.raises(ArgumentError, match="regular file"):
        sub = workspace / "subdir"
        sub.mkdir()
        g.check(str(sub))


def test_guard_rejects_prefix_sibling_directory(tmp_path, workspace):
    sibling = tmp_path / "samples_evil"
    sibling.mkdir()
    (sibling / "x.bin").write_bytes(b"x")
    with pytest.raises(WorkspaceViolation, match="outside"):
        guard(workspace).check(str(sibling / "x.bin"))


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data streams")
def test_guard_rejects_alternate_data_streams(workspace, elf_sample):
    with pytest.raises(WorkspaceViolation, match="alternate data stream"):
        guard(workspace).check(str(elf_sample) + ":hidden")


def test_guard_refuses_symlinks(tmp_path, workspace):
    secret = tmp_path / "secret.txt"
    secret.write_text("not for analysis")
    link = workspace / "link.bin"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs Developer Mode/admin on this Windows host")
    with pytest.raises(WorkspaceViolation):
        guard(workspace).check(str(link))


def test_identify_hashes_without_executing(elf_sample, pe_sample, apk_sample):
    ident = identify(elf_sample)
    assert ident.sha256 == hashlib.sha256(elf_sample.read_bytes()).hexdigest()
    assert (ident.format, ident.kind, ident.metadata["arch"]) == ("elf", "native_binary", "x86_64")
    assert identify(pe_sample).format == "pe"
    assert identify(apk_sample).kind == "android_apk"


def test_stage_copy_is_verified_and_read_only(tmp_path, elf_sample):
    ident = identify(elf_sample)
    staged = stage_copy(tmp_path / "work", ident.sha256, "ghidra", elf_sample, ident.display_name)
    assert staged.read_bytes() == elf_sample.read_bytes()
    assert staged.parent.name == "ghidra" and staged.parent.parent.name == ident.sha256[:16]
    assert not os.access(staged, os.W_OK) or not (staged.stat().st_mode & stat.S_IWRITE)
    assert stage_copy(tmp_path / "work", ident.sha256, "ghidra", elf_sample, ident.display_name) == staged
    elf_sample.write_bytes(b"changed")
    other = stage_copy  # a changed original must not be staged under the old hash
    with pytest.raises(ArgumentError, match="hash mismatch"):
        other(tmp_path / "work", ident.sha256, "ida", elf_sample, ident.display_name)


def test_elf_metadata(elf_sample):
    meta = inspect_file(elf_sample)
    assert meta["format_detail"] == "ELF64 ET_EXEC"
    assert meta["image_base"] == 0x400000 and meta["entry_point"] == 0x40013F
    names = {f["name"]: f for f in meta["functions"]}
    assert names["main"]["size"] == 38 and names["check_key"]["address"] == 0x400104
    assert not meta["stripped"]


def test_pe_metadata(pe_sample):
    meta = inspect_file(pe_sample)
    assert meta["format_detail"] == "PE32+ EXE"
    assert meta["image_base"] == 0x140000000 and meta["entry_point"] == 0x140001000
    assert meta["imports"][0]["library"] == "KERNEL32.dll" and meta["imports"][0]["name"] == "ExitProcess"
    assert meta["is_pie"] is True


def test_apk_manifest_and_export_rules(apk_sample):
    meta = inspect_file(apk_sample)
    manifest = meta["manifest"]
    assert manifest["package"] == "com.example.nexusfixture"
    assert manifest["target_sdk"] == 34 and manifest["version_code"] == 7
    assert manifest["permissions_requested"] == ["android.permission.INTERNET", "android.permission.CAMERA"]
    assert manifest["application"]["debuggable"] is True
    comps = {c["name"]: c for c in manifest["components"]}
    assert comps["com.example.nexusfixture.MainActivity"]["exported"] is True
    assert comps["com.example.nexusfixture.HiddenActivity"]["exported"] is False
    receiver = comps["com.example.nexusfixture.BootReceiver"]
    assert receiver["exported"] is False and "targetSdk>=31" in receiver["exported_basis"]
    assert comps["com.example.nexusfixture.DataProvider"]["authorities"] == "com.example.nexusfixture.data"
    assert meta["dex_files"] == ["classes.dex"]
    assert any("debuggable" in note for note in manifest["notes"])


def test_strings_have_offsets_and_virtual_addresses(elf_sample):
    meta = inspect_file(elf_sample)
    found = extract_strings(elf_sample.read_bytes(), meta, min_length=8, query="nexus")
    assert found["returned"] == 1
    assert found["strings"][0]["address"] == 0x400150


@pytest.mark.parametrize(
    "payload",
    [
        b"\x7fELF" + b"\x00" * 10,
        b"MZ" + os.urandom(100),
        b"\xcf\xfa\xed\xfe" + b"\x00" * 8,
        b"dex\n035\x00" + b"\x00" * 10,
        os.urandom(512),
    ],
)
def test_malformed_inputs_do_not_crash(tmp_path, payload):
    path = tmp_path / "bad.bin"
    path.write_bytes(payload)
    ident = identify(path)
    assert ident.sha256 and isinstance(ident.metadata, dict)


def test_bad_zip_and_corrupt_manifest(tmp_path):
    bad_zip = tmp_path / "bad.apk"
    bad_zip.write_bytes(b"PK\x03\x04garbage")
    assert "error" in inspect_file(bad_zip)
    apk = tmp_path / "corrupt.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00\xff\xff\xff\x7f" + os.urandom(64))
    meta = inspect_file(apk)
    assert meta["format"] == "apk" and "manifest_error" in meta
    with pytest.raises(AxmlError):
        parse_axml(b"<manifest/>")


def test_sniff_format():
    assert sniff_format(b"\x7fELF\x02") == "elf"
    assert sniff_format(b"PK\x03\x04") == "zip"
    assert sniff_format(b"hello") == "unknown"
