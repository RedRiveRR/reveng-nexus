import pytest

from reveng_nexus.errors import ArgumentError, CapabilityUnavailable
from reveng_nexus.registry import ProviderManager


@pytest.fixture
async def manager(config_factory, workspace):
    mgr = ProviderManager(config_factory(workspace))
    await mgr.start()
    yield mgr
    await mgr.close()


async def _target(mgr, path):
    intake = await mgr.intake(str(path))
    return mgr.target_context(intake["target"]["sha256"])


async def test_builtin_is_always_present_and_ready(manager):
    health = await manager.health()
    assert health["builtin"]["status"] == "ready"
    caps = manager.capability_registry()["operations"]
    assert any(r["provider_id"] == "builtin" and r["available"] for r in caps["binary.metadata"])


async def test_metadata_functions_strings_are_direct_observations(manager, elf_sample):
    target = await _target(manager, elf_sample)
    meta = await manager.perform("binary.metadata", target, {}, provider_id="builtin")
    assert meta["result"].evidence_kind == "direct_observation"
    assert meta["result"].normalized["image_base"] == 0x400000
    funcs = await manager.perform("binary.functions", target, {}, provider_id="builtin")
    names = [f["name"] for f in funcs["result"].normalized["functions"]]
    assert names == ["add_numbers", "check_key", "get_greeting", "main", "_start"]
    strings = await manager.perform("binary.strings", target, {"query": "LICENSE"}, provider_id="builtin")
    assert strings["result"].normalized["strings"][0]["address"] == 0x400174
    stored = manager.evidence.get_evidence_record(strings["evidence"]["evidence_id"], include_raw=False)
    assert stored["provider_id"] == "builtin" and stored["target_id"] == target.sha256


async def test_capstone_disassembly_is_engine_derived(manager, elf_sample):
    target = await _target(manager, elf_sample)
    out = await manager.perform("binary.disassemble", target, {"name": "main"}, provider_id="builtin")
    res = out["result"]
    assert res.evidence_kind == "engine_derived" and res.engine_family == "capstone"
    calls = [i["op_str"] for i in res.normalized["instructions"] if i["mnemonic"] == "call"]
    assert calls == ["0x400100", "0x400104", "0x400111"]
    assert res.normalized["instructions"][-1]["mnemonic"] == "ret"


async def test_builtin_refuses_operations_for_wrong_format(manager, apk_sample, elf_sample):
    apk = await _target(manager, apk_sample)
    with pytest.raises(CapabilityUnavailable):
        await manager.perform("binary.functions", apk, {}, provider_id="builtin")
    elf = await _target(manager, elf_sample)
    with pytest.raises(CapabilityUnavailable):
        await manager.perform("apk.manifest", elf, {}, provider_id="builtin")


async def test_apk_components(manager, apk_sample):
    target = await _target(manager, apk_sample)
    out = await manager.perform("apk.components", target, {}, provider_id="builtin")
    exported = {c["name"] for c in out["result"].normalized["exported_components"]}
    assert exported == {"com.example.nexusfixture.MainActivity", "com.example.nexusfixture.DataProvider"}


async def test_changed_file_after_intake_is_detected(manager, elf_sample):
    target = await _target(manager, elf_sample)
    elf_sample.write_bytes(elf_sample.read_bytes() + b"tampered")
    with pytest.raises(ArgumentError, match="no longer match"):
        await manager.perform("binary.strings", target, {}, provider_id="builtin")


async def test_capability_unavailable_lists_alternatives(manager, elf_sample):
    target = await _target(manager, elf_sample)
    with pytest.raises(CapabilityUnavailable) as info:
        await manager.perform("binary.decompile", target, {"name": "main"})
    assert "alternatives" in info.value.details
