import asyncio
import time

import pytest
from conftest import mock_engine, mock_launched

from reveng_nexus.errors import ArgumentError, CapabilityUnavailable
from reveng_nexus.orchestrator import Orchestrator, prioritize_functions, translate_address
from reveng_nexus.registry import ProviderManager


@pytest.fixture
async def make_manager(config_factory, workspace):
    managers = []

    async def factory(providers, **sections):
        mgr = ProviderManager(config_factory(workspace, providers, **sections))
        await mgr.start()
        managers.append(mgr)
        return mgr

    yield factory
    for mgr in managers:
        await mgr.close()


async def target_of(mgr, path):
    intake = await mgr.intake(str(path))
    return mgr.target_context(intake["target"]["sha256"])


async def test_priority_and_preference_ordering(make_manager, elf_sample):
    mgr = await make_manager([mock_engine("low", priority=10), mock_engine("high", engine="ida", priority=90)])
    target = await target_of(mgr, elf_sample)
    ranked, _ = mgr.rank("binary.decompile", target)
    assert [p.id for p in ranked] == ["high", "low"]
    mgr2 = await make_manager(
        [mock_engine("low", priority=10), mock_engine("high", engine="ida", priority=90)],
        routing={"preferred": {"binary.decompile": ["low"]}},
    )
    ranked2, _ = mgr2.rank("binary.decompile", target)
    assert ranked2[0].id == "low"


async def test_duplicate_capabilities_are_reported_per_engine_family(make_manager):
    mgr = await make_manager(
        [
            mock_engine("remcp", engine="ghidra"),
            mock_engine("other_ghidra", engine="ghidra"),
            mock_engine("ida", engine="ida"),
        ]
    )
    dups = [d for d in mgr.capability_registry()["duplicates"] if d["operation"] == "binary.decompile"]
    assert dups == [
        {
            "operation": "binary.decompile",
            "engine_family": "ghidra",
            "providers": ["other_ghidra", "remcp"],
            "note": dups[0]["note"],
        }
    ]


async def test_sequential_failover_records_attempts(make_manager, elf_sample):
    failing = mock_engine("broken", priority=90, env={"MOCK_ERROR_TOOL": "decompile_function"})
    mgr = await make_manager([failing, mock_engine("backup", engine="ida", priority=10)])
    target = await target_of(mgr, elf_sample)
    out = await mgr.perform("binary.decompile", target, {"name": "main"})
    assert out["result"].provider_id == "backup"
    assert [a["outcome"] for a in out["attempts"] if a["provider_id"] in {"broken", "backup"}] == ["failed", "ok"]
    # explicit provider selection never fails over silently
    with pytest.raises(CapabilityUnavailable):
        await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="broken")
    # failover budget 0 stops after the first candidate
    with pytest.raises(CapabilityUnavailable):
        await mgr.perform("binary.decompile", target, {"name": "main"}, max_failover=0)


async def test_same_provider_calls_are_serialised(make_manager, elf_sample):
    slow = mock_engine("slow", env={"MOCK_SLOW_TOOL": "get_strings", "MOCK_SLOW_SECONDS": "0.8"})
    mgr = await make_manager([slow], analysis={"max_concurrent_provider_calls": 4})
    target = await target_of(mgr, elf_sample)
    await mgr.perform("binary.functions", target, {}, provider_id="slow")  # open the database first
    t0 = time.monotonic()
    await asyncio.gather(*(mgr.perform("binary.strings", target, {}, provider_id="slow") for _ in range(2)))
    assert time.monotonic() - t0 >= 1.5, "max_concurrency=1 must serialise calls into one analysis session"


async def test_conflict_group_serialises_controllers_of_one_engine(make_manager, elf_sample):
    env = {"MOCK_SLOW_TOOL": "get_strings", "MOCK_SLOW_SECONDS": "0.8"}
    mgr = await make_manager(
        [
            mock_engine("ida_a", engine="ida", env=env, conflict_group="ida"),
            mock_engine("ida_b", engine="ida", env=env, conflict_group="ida"),
        ],
        analysis={"max_concurrent_provider_calls": 4},
    )
    target = await target_of(mgr, elf_sample)
    for pid in ("ida_a", "ida_b"):
        await mgr.perform("binary.functions", target, {}, provider_id=pid)
    t0 = time.monotonic()
    await asyncio.gather(
        mgr.perform("binary.strings", target, {}, provider_id="ida_a"),
        mgr.perform("binary.strings", target, {}, provider_id="ida_b"),
    )
    assert time.monotonic() - t0 >= 1.5


async def test_independent_providers_run_concurrently(make_manager, elf_sample):
    env = {"MOCK_SLOW_TOOL": "get_strings", "MOCK_SLOW_SECONDS": "1.0"}
    mgr = await make_manager(
        [mock_engine("gh", engine="ghidra", env=env), mock_engine("id", engine="ida", env=env)],
        analysis={"max_concurrent_provider_calls": 4},
    )
    target = await target_of(mgr, elf_sample)
    for pid in ("gh", "id"):
        await mgr.perform("binary.functions", target, {}, provider_id=pid)
    t0 = time.monotonic()
    await asyncio.gather(
        mgr.perform("binary.strings", target, {}, provider_id="gh"),
        mgr.perform("binary.strings", target, {}, provider_id="id"),
    )
    assert time.monotonic() - t0 < 1.9


def test_function_prioritisation_is_deterministic():
    funcs = [
        {"name": "sub_401000", "address": 1, "size": 200},
        {"name": "check_license", "address": 2, "size": 80},
        {"name": "main", "address": 3, "size": 40},
        {"name": "__libc_csu_init", "address": 4, "size": 90},
    ]
    ranked = prioritize_functions(funcs, entry_point=3, limit=4)
    assert [f["name"] for f in ranked][:2] == ["main", "check_license"]
    assert ranked[-1]["name"] == "__libc_csu_init"
    assert "library/thunk-like name" in ranked[-1]["reasons"]


def test_translate_address():
    assert translate_address(0x401119, 0x400000, 0x100000) == 0x101119
    assert translate_address(0x401119, None, 0x100000) == 0x401119


async def test_analyze_binary_builtin_only_degrades_gracefully(make_manager, elf_sample):
    mgr = await make_manager([])
    target = await target_of(mgr, elf_sample)
    out = await Orchestrator(mgr).analyze_binary(target, depth="standard", max_functions=2)
    assert out["primary_engine"] is None
    assert out["missing_capabilities"][0]["capability"] == "binary.decompile"
    assert len(out["decompiled"]) == 2, "falls back to built-in disassembly"
    assert all(step["ok"] for step in out["steps"])


async def test_analyze_binary_with_engine_and_auto_compare(make_manager, elf_sample):
    mgr = await make_manager(
        [
            mock_engine("ghidra_a", engine="ghidra"),
            mock_engine("ida_b", engine="ida", flavor="b", env={"MOCK_BASE_SHIFT": "0x1000"}),
        ]
    )
    target = await target_of(mgr, elf_sample)
    out = await Orchestrator(mgr).analyze_binary(target, compare=True, max_functions=3)
    assert out["primary_engine"] in {"ghidra_a", "ida_b"}
    assert out["decompiled"] and out["comparisons"]
    evidence = mgr.evidence.query_evidence(target_id=target.sha256, limit=200)
    kinds = {e["evidence_kind"] for e in evidence}
    assert {"direct_observation", "engine_derived"} <= kinds


async def test_compare_function_records_disagreement_and_links(make_manager, elf_sample):
    mgr = await make_manager(
        [
            mock_engine("ghidra_a", engine="ghidra"),
            mock_engine("ida_b", engine="ida", flavor="b", env={"MOCK_BASE_SHIFT": "0x1000"}),
        ]
    )
    target = await target_of(mgr, elf_sample)
    orch = Orchestrator(mgr)
    main = await orch.compare_function(target, name="main")
    assert main["assessment"] == "disagreement"
    callees = next(d for d in main["disagreements"] if d["aspect"] == "callees")
    assert "validate_key" in callees["values"]["ida_b"]
    assert {r["rva"] for r in main["identity"] if r["rva"] is not None} == {0x119}, "rebased identity agrees"
    stored = mgr.evidence.list_comparisons(target_id=target.sha256)
    assert stored[0]["assessment"] == "disagreement"
    record = mgr.evidence.get_evidence_record(main["evidence_ids"][0])
    assert any(link["relation"] == "contradicts" for link in record["links"])

    key = await orch.compare_function(target, address=0x400104, providers=["ghidra_a", "ida_b"])
    assert key["assessment"].startswith("independent")
    assert {"ghidra", "ida"} <= set(key["engine_families"])


async def test_compare_same_family_wrappers(make_manager, elf_sample):
    mgr = await make_manager([mock_engine("remcp", engine="ghidra"), mock_launched("mcpy")])
    target = await target_of(mgr, elf_sample)
    out = await Orchestrator(mgr).compare_function(target, name="get_greeting", include_disassembly=False)
    assert out["engine_families"] == ["ghidra"] or out["assessment"] in {"same_family_consistency", "disagreement"}
    assert out["assessment"] != "independent_agreement"


async def test_analyze_apk_without_jadx(make_manager, apk_sample):
    mgr = await make_manager([])
    target = await target_of(mgr, apk_sample)
    out = await Orchestrator(mgr).analyze_apk(target)
    assert out["summary"]["package"] == "com.example.nexusfixture"
    assert {c["name"] for c in out["summary"]["exported_components"]} == {
        "com.example.nexusfixture.MainActivity",
        "com.example.nexusfixture.DataProvider",
    }
    assert out["missing_capabilities"][0]["capability"] == "apk.class_source"
    with pytest.raises(ArgumentError):
        await Orchestrator(mgr).analyze_binary(target)


async def test_target_must_belong_to_requested_case(make_manager, elf_sample):
    mgr = await make_manager([])
    intake = await mgr.intake(str(elf_sample), case_title="Case A")
    with pytest.raises(ArgumentError, match="not part of case"):
        mgr.target_context(intake["target"]["sha256"], "default")
