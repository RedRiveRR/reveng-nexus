"""Built-in engine against every generated fixture: recognition, metadata, truncation, hash preservation."""

import hashlib

import pytest
from fixtures.macho_builder import (
    CPU_X86,
    ENTRY_OFF,
    TEXT_VMADDR,
    TEXT_VMADDR_32,
    build_thin,
    build_thin32,
    build_universal,
    write_macho,
)

from reveng_nexus.artifacts import identify
from reveng_nexus.formats import inspect_file
from reveng_nexus.registry import ProviderManager


@pytest.fixture
def macho_sample(workspace):
    return write_macho(workspace / "nexus_fixture.macho")


def test_macho_thin_metadata(macho_sample):
    meta = inspect_file(macho_sample)
    assert (meta["format"], meta["arch"], meta["bits"], meta["file_type"]) == ("macho", "x86_64", 64, "execute")
    assert meta["image_base"] == TEXT_VMADDR and meta["entry_point"] == TEXT_VMADDR + ENTRY_OFF
    assert meta["is_pie"] is True and meta["encrypted"] is False
    assert meta["libraries"] == ["/usr/lib/libSystem.B.dylib"]
    assert {"LC_SEGMENT_64", "LC_LOAD_DYLIB", "LC_UUID", "LC_MAIN"} <= set(meta["load_commands"])
    text = next(s for s in meta["segments"] if s["name"] == "__TEXT")
    assert text["offset"] == 0 and text["file_size"] == 0x1000
    assert meta["functions"] == [] and any("symbols are not decoded" in n for n in meta["notes"])


def test_macho_universal_slice(workspace):
    meta = inspect_file(write_macho(workspace / "fat.macho", universal=True))
    assert meta["format"] == "macho_universal" and len(meta["slices"]) == 1
    slice0 = meta["slices"][0]
    assert slice0["arch"] == "x86_64" and slice0["offset"] == 0x1000
    assert slice0["entry_point"] == TEXT_VMADDR + ENTRY_OFF
    assert slice0["segments"][1]["offset"] == 0x1000, "segment offsets are absolute within the fat file"


async def test_macho_disassembly_at_entry(config_factory, workspace, macho_sample):
    mgr = ProviderManager(config_factory(workspace))
    await mgr.start()
    try:
        intake = await mgr.intake(str(macho_sample))
        target = mgr.target_context(intake["target"]["sha256"])
        out = await mgr.perform(
            "binary.disassemble", target, {"address": TEXT_VMADDR + ENTRY_OFF, "count": 2}, provider_id="builtin"
        )
        insns = out["result"].normalized["instructions"]
        assert [i["mnemonic"] for i in insns] == ["xor", "ret"]
        assert "no function bounds known" in out["result"].normalized["basis"]
    finally:
        await mgr.close()


@pytest.mark.parametrize("cut", [4, 20, 40, 120])
def test_truncated_macho_does_not_crash(tmp_path, cut):
    path = tmp_path / "cut.macho"
    path.write_bytes(build_thin()[:cut])
    ident = identify(path)
    assert ident.format in {"macho", "unknown"} and ident.sha256


@pytest.mark.parametrize("name", ["elf", "pe", "apk"])
def test_truncated_fixtures_do_not_crash(request, tmp_path, name):
    source = request.getfixturevalue(f"{name}_sample")
    data = source.read_bytes()
    for cut in (8, 64, len(data) // 2):
        path = tmp_path / f"cut_{cut}.{name}"
        path.write_bytes(data[:cut])
        ident = identify(path)
        assert ident.sha256 == hashlib.sha256(data[:cut]).hexdigest()
        assert isinstance(ident.metadata, dict)


@pytest.mark.parametrize(
    "name,expected_format,operations",
    [
        ("elf", "elf", ["binary.metadata", "binary.functions", "binary.strings", "binary.disassemble"]),
        ("pe", "pe", ["binary.metadata", "binary.imports", "binary.strings"]),
        ("macho", "macho", ["binary.metadata", "binary.strings"]),
        ("apk", "apk", ["apk.manifest", "apk.components", "binary.strings"]),
    ],
)
async def test_every_fixture_is_recognised_retained_and_unmodified(
    request, config_factory, workspace, name, expected_format, operations
):
    sample = request.getfixturevalue(f"{name}_sample")
    before = (hashlib.sha256(sample.read_bytes()).hexdigest(), sample.stat().st_mtime_ns)
    mgr = ProviderManager(config_factory(workspace))
    await mgr.start()
    try:
        intake = await mgr.intake(str(sample))
        assert intake["target"]["format"] == expected_format
        target = mgr.target_context(intake["target"]["sha256"])
        evidence_ids = []
        for op in operations:
            params = {"name": "main"} if op == "binary.disassemble" else {}
            out = await mgr.perform(op, target, params, provider_id="builtin")
            assert out["result"].provider_id == "builtin"
            evidence_ids.append(out["evidence"]["evidence_id"])
        for eid in evidence_ids:
            record = mgr.evidence.get_evidence_record(eid)
            assert record["target_id"] == before[0] and record["provider_id"] == "builtin"
    finally:
        await mgr.close()
    assert (hashlib.sha256(sample.read_bytes()).hexdigest(), sample.stat().st_mtime_ns) == before


def test_macho_thin32_lc_segment_offsets(tmp_path):
    """32-bit images use LC_SEGMENT (uint32 fields) after a 28-byte mach_header."""
    path = tmp_path / "nexus_fixture32.macho"
    path.write_bytes(build_thin32())
    meta = inspect_file(path)
    assert (meta["format"], meta["arch"], meta["bits"]) == ("macho", "x86", 32)
    assert meta["load_commands"] == ["LC_SEGMENT", "LC_SEGMENT", "LC_MAIN"]
    text = next(s for s in meta["segments"] if s["name"] == "__TEXT")
    assert (text["vaddr"], text["size"], text["offset"], text["file_size"]) == (TEXT_VMADDR_32, 0x1000, 0, 0x1000)
    assert meta["image_base"] == TEXT_VMADDR_32 and meta["entry_point"] == TEXT_VMADDR_32 + ENTRY_OFF
    assert meta["truncated"] is False and meta["functions"] == []


def test_macho_universal32_slice_offsets_are_absolute(tmp_path):
    path = tmp_path / "fat32.macho"
    path.write_bytes(build_universal(build_thin32(), CPU_X86))
    slice0 = inspect_file(path)["slices"][0]
    assert (slice0["arch"], slice0["bits"], slice0["offset"]) == ("x86", 32, 0x1000)
    assert [s["offset"] for s in slice0["segments"]] == [0x1000, 0x1000]


@pytest.mark.parametrize("builder", ["thin32", "thin64", "universal"])
def test_truncated_macho_parses_what_is_present(tmp_path, builder):
    """Regression: input ending inside the header or a load command raised struct.error from
    inspect_file (identify() hid it), losing even the complete segments before the cut."""
    blob = {"thin32": build_thin32(), "thin64": build_thin(), "universal": build_universal()}[builder]
    for cut in (4, 8, 27, 28, 40, 60, 83, 84, 100, 140, len(blob) - 1):
        path = tmp_path / f"cut_{builder}_{cut}"
        path.write_bytes(blob[:cut])
        meta = inspect_file(path)  # must not raise
        assert meta["format"] in {"macho", "macho_universal"}
        if builder == "universal":
            continue
        complete = [s["name"] for s in meta.get("segments", [])]
        seg = 56 if builder == "thin32" else 72
        header = 28 if builder == "thin32" else 32
        expected = ["__PAGEZERO", "__TEXT"][: max(0, min(2, (cut - header) // seg))]
        assert complete == expected, (builder, cut, complete)
        if cut < len(blob) and len(expected) < 2:
            assert meta.get("truncated") is True
