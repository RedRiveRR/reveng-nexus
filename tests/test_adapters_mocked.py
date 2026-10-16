"""Deterministic mock tests for the source-verified ida_rs, binary_ninja and jadx adapters.

Each provider is a real MCP subprocess (tests/mock_servers/mock_adapters.py) that serves the tool
names and argument names the adapter binds to at its pinned upstream revision. No IDA, Binary
Ninja or JADX is installed, downloaded or launched, and no target is executed. Passing these
tests makes an adapter "mock-tested"; it says nothing about the real upstream response shapes.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import TESTS

from reveng_nexus.adapters import ADAPTERS
from reveng_nexus.errors import CapabilityUnavailable, PolicyViolation, ProviderUnavailable
from reveng_nexus.registry import ProviderManager

MOCK_ADAPTERS = str(TESTS / "mock_servers" / "mock_adapters.py")
PROFILE = {"ida_rs": "ida_rs", "binary_ninja": "binja", "jadx": "jadx"}


BINJA_VIEW: dict[str, str] = {}


@pytest.fixture(autouse=True)
def _binja_staged_view(tmp_path, elf_sample):
    """Binary Ninja must show the target's staged copy: <data>/work/<sha16>/<provider>/<name>."""
    import hashlib

    sha = hashlib.sha256(elf_sample.read_bytes()).hexdigest()
    BINJA_VIEW["bn"] = str((tmp_path / "data").resolve() / "work" / sha[:16] / "bn" / elf_sample.name)
    yield
    BINJA_VIEW.clear()


def adapter_mock(
    provider_id: str, adapter: str, *, call_log: Path | None = None, env: dict[str, str] | None = None, **extra: Any
) -> dict[str, Any]:
    child_env = {"MOCK_PROFILE": PROFILE[adapter], **(env or {})}
    if adapter == "binary_ninja" and "MOCK_BINJA_VIEW" not in child_env and provider_id in BINJA_VIEW:
        child_env["MOCK_BINJA_VIEW"] = BINJA_VIEW[provider_id]
    if call_log is not None:
        child_env["MOCK_CALL_LOG"] = str(call_log)
    return {
        "id": provider_id,
        "enabled": True,
        "type": "mcp_stdio",
        "adapter": adapter,
        "command": sys.executable,
        "args": [MOCK_ADAPTERS],
        "env": child_env,
        "timeout_seconds": extra.pop("timeout_seconds", 20),
        "startup_timeout_seconds": extra.pop("startup_timeout_seconds", 60),
        **extra,
    }


def calls(log: Path) -> list[dict[str, Any]]:
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


async def started(config):
    mgr = ProviderManager(config)
    await mgr.start()
    return mgr


async def target_of(mgr, path):
    intake = await mgr.intake(str(path))
    return mgr.target_context(intake["target"]["sha256"])


def last_attempt(info: pytest.ExceptionInfo) -> dict[str, Any]:
    return info.value.details["attempts"][-1]


# -- config validation and missing providers --------------------------------------------------


async def test_unknown_adapter_and_missing_installs_do_not_block_others(config_factory, workspace, elf_sample):
    providers = [
        {**adapter_mock("typo", "ida_rs"), "adapter": "ida_rss"},
        # mirrors config/providers.example.yaml with IDADIR / JADX_MCP_HOME unset
        {**adapter_mock("ida", "ida_rs"), "command": "${NEXUS_TEST_UNSET_IDADIR}/ida-mcp.exe"},
        {**adapter_mock("jadx", "jadx"), "command": "${NEXUS_TEST_UNSET_JADX_HOME}/.venv/Scripts/python.exe"},
        {**adapter_mock("bn", "binary_ninja"), "command": "definitely-not-installed-binja-bridge"},
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        assert "unknown adapter 'ida_rss'" in mgr.provider_errors["typo"]
        assert "NEXUS_TEST_UNSET_IDADIR" in mgr.provider_errors["ida"]
        assert "NEXUS_TEST_UNSET_JADX_HOME" in mgr.provider_errors["jadx"]
        assert "was not found" in mgr.provider_errors["bn"]
        health = await mgr.health()
        assert all(health[p]["status"] == "unavailable" for p in ("ida", "jadx", "bn"))
        target = await target_of(mgr, elf_sample)
        with pytest.raises(ProviderUnavailable):
            await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="ida")
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"name": "main"})
        states = {a["provider_id"]: a["state"] for a in info.value.details["alternatives"]}
        assert "NEXUS_TEST_UNSET_IDADIR" in states["ida"] and "was not found" in states["bn"]
        fallback = await mgr.perform("binary.functions", target, {})
        assert fallback["result"].provider_id == "builtin"
    finally:
        await mgr.close()


# -- discovery, classification and capability reporting ----------------------------------------

_EXPECTED_CLASSES = {
    "ida_rs": {
        "open_idb": ("lifecycle", False),
        "idb_meta": ("read", True),
        "decompile": ("read", True),
        "run_script": ("execute", False),  # annotated read-only by the mock: the manifest must win
        "save_idb": ("mutate", False),
        "lumina_lookup": ("blocked", False),
        "debug_attach": ("dynamic", False),
        "mystery_tool": ("unknown", False),
    },
    "binary_ninja": {
        "get_binary_status": ("read", True),
        "decompile_function": ("read", True),
        "select_binary": ("lifecycle", False),
        "rename_function": ("mutate", False),
        "patch_bytes": ("mutate", False),
        "set_comment": ("mutate", False),
        "frobnicate_view": ("unknown", False),
    },
    "jadx": {
        "load_apk": ("lifecycle", False),
        "get_class_source": ("read", True),
        "search_method_by_name": ("read", True),
        "rename_class": ("mutate", False),
        "frobnicate_apk": ("unknown", False),
    },
}


@pytest.mark.parametrize("adapter", sorted(_EXPECTED_CLASSES))
async def test_discovery_classification_and_capabilities(config_factory, workspace, adapter):
    mgr = await started(config_factory(workspace, [adapter_mock("eng", adapter)]))
    try:
        assert mgr.provider_errors == {}
        provider = mgr.providers["eng"]
        tools = {t.name: t for t in await provider.list_tools()}
        for name, (tool_class, allowed) in _EXPECTED_CLASSES[adapter].items():
            assert tools[name].classification.tool_class == tool_class, name
            assert tools[name].decision.allowed is allowed, name
        caps = provider.list_capabilities()
        assert set(caps) == set(ADAPTERS[adapter].bindings)
        assert all(status["available"] for status in caps.values()), caps
        health = (await mgr.health())["eng"]
        assert health["status"] == "ready"
        described = provider.describe()
        assert described["engine"] == ADAPTERS[adapter].engine
        assert ADAPTERS[adapter].describe()["verification"] == "source"
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("adapter", "blocked", "match"),
    [
        ("ida_rs", "run_script", "execut"),
        ("ida_rs", "save_idb", "read-only"),
        ("ida_rs", "lumina_lookup", "blocked"),
        ("ida_rs", "debug_attach", "dynamic"),
        ("ida_rs", "mystery_tool", "unknown|unclassified"),
        ("ida_rs", "open_idb", "lifecycle"),
        ("binary_ninja", "rename_function", "read-only"),
        ("binary_ninja", "patch_bytes", "read-only"),
        ("binary_ninja", "set_comment", "read-only"),
        ("binary_ninja", "frobnicate_view", "unknown|unclassified"),
        ("binary_ninja", "select_binary", "lifecycle"),
        ("jadx", "rename_class", "read-only"),
        ("jadx", "frobnicate_apk", "unknown|unclassified"),
        ("jadx", "load_apk", "lifecycle"),
    ],
)
async def test_policy_blocks_direct_calls_before_they_reach_the_server(
    config_factory, workspace, tmp_path, adapter, blocked, match
):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [adapter_mock("eng", adapter, call_log=log)]))
    try:
        with pytest.raises(PolicyViolation, match=match):
            await mgr.call_provider_tool("eng", blocked, {})
        assert blocked not in {c["tool"] for c in calls(log)}
        records = [json.loads(line) for line in mgr.audit.path.read_text(encoding="utf-8").splitlines()]
        assert any(r["event"] == "tool_call_blocked" and r.get("tool_name") == blocked for r in records)
    finally:
        await mgr.close()


# -- normalised success through Nexus, with evidence and provenance ------------------------------


async def test_ida_rs_operations_normalise_and_keep_provenance(config_factory, workspace, elf_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [adapter_mock("ida", "ida_rs", call_log=log)]))
    try:
        target = await target_of(mgr, elf_sample)

        async def run(op: str, params: dict[str, Any] | None = None):
            return await mgr.perform(op, target, params or {}, provider_id="ida")

        meta = (await run("binary.metadata"))["result"].normalized
        assert (meta["processor"], meta["bits"], meta["image_base"]) == ("metapc", 64, 0x400000)
        # ida-mcp-rs reports main_address, not an entry point: the entry point stays unknown
        assert meta["entry_point"] is None and meta["main_address"] == 0x401000
        funcs = (await run("binary.functions"))["result"].normalized
        assert funcs["total"] == 3 and funcs["functions"][1] == {"name": "check_key", "address": 0x401030, "size": 16}
        filtered = (await run("binary.functions", {"query": "add"}))["result"].normalized
        assert [f["name"] for f in filtered["functions"]] == ["add_numbers"]
        out = await run("binary.decompile", {"name": "check_key"})
        dec = out["result"]
        assert dec.subject_address == 0x401030 and dec.subject_name == "check_key"
        assert "check_key" in dec.normalized["code"] and dec.normalized["language"] == "Hex-Rays pseudocode"
        dis = (await run("binary.disassemble", {"address": 0x401000}))["result"].normalized
        assert [i["mnemonic"] for i in dis["instructions"]] == ["push", "retn"]
        xto = (await run("binary.xrefs", {"name": "check_key"}))["result"].normalized
        assert xto["refs"] == [{"from": 0x401012, "to": 0x401030, "type": "call"}]
        xfrom = (await run("binary.xrefs", {"address": 0x401000, "direction": "from"}))["result"]
        assert xfrom.tool_name == "xrefs_from" and xfrom.normalized["refs"][0]["to"] == 0x401040
        cfg = (await run("binary.cfg", {"address": 0x401000}))["result"].normalized
        assert cfg["blocks"] == [{"start": 0x401000, "end": 0x401030, "successors": []}]
        strings = (await run("binary.strings"))["result"].normalized
        assert strings["strings"][0]["value"].startswith("Hello from"), "read from StringInfo.content"
        assert strings["strings"][0]["length"] == len(strings["strings"][0]["value"])
        imports = (await run("binary.imports"))["result"].normalized
        # pinned ImportInfo has no module field: the library is unknown, never invented
        assert imports["imports"] == [{"name": "puts", "library": None, "address": 0x403000, "ordinal": 0}]
        exports = (await run("binary.exports"))["result"].normalized
        assert exports["exports"] == [{"name": "main", "address": 0x401000}]

        # provenance: original tool name, engine family, target hash, subject, raw output retained
        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["target_id"] == target.sha256 and record["provider_id"] == "ida"
        assert record["tool_name"] == "decompile" and record["operation"] == "binary.decompile"
        assert (record["engine"], record["engine_family"]) == ("ida", "ida")
        assert record["subject_address"] == 0x401030 and record["subject_name"] == "check_key"
        assert record["evidence_kind"] == "engine_derived" and record["status"] == "unverified"
        assert "__int64 __fastcall check_key()" in record["raw"]["content"] and record["raw_sha256"]

        # one database per target: opened once on the staged copy, never on the original
        opens = [c for c in calls(log) if c["tool"] == "open_idb"]
        assert len(opens) == 1 and opens[0]["arg_keys"] == ["auto_analyse", "idb_out", "path"]
        assert Path(opens[0]["path"]) == target.staged_path("ida") and Path(opens[0]["path"]) != elf_sample
        audit = mgr.audit.path.read_text(encoding="utf-8")
        assert "__fastcall check_key" not in audit and str(elf_sample) not in audit
    finally:
        await mgr.close()
    assert calls(log)[-1]["tool"] == "close_idb", "shutdown releases the open database"


async def test_binary_ninja_operations_normalise_and_keep_provenance(config_factory, workspace, elf_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [adapter_mock("bn", "binary_ninja", call_log=log)]))
    try:
        target = await target_of(mgr, elf_sample)

        async def run(op: str, params: dict[str, Any] | None = None):
            return await mgr.perform(op, target, params or {}, provider_id="bn")

        funcs = await run("binary.functions")
        assert funcs["result"].tool_name == "list_methods"
        assert funcs["result"].normalized["functions"][0] == {"name": "main", "address": 0x401000, "size": None}
        searched = (await run("binary.functions", {"query": "check"}))["result"]
        assert searched.tool_name == "search_functions_by_name" and searched.normalized["total"] == 1
        out = await run("binary.decompile", {"address": 0x401030})
        dec = out["result"]
        assert dec.subject_name == "check_key" and dec.subject_address == 0x401030
        assert dec.normalized["language"] == "HLIL" and "check_key" in dec.normalized["code"]
        dis = (await run("binary.disassemble", {"name": "main"}))["result"].normalized
        assert dis["instructions"][0] == {"address": 0x401000, "bytes": "55", "mnemonic": "push", "op_str": "rbp"}
        xrefs = (await run("binary.xrefs", {"address": 0x401030}))["result"].normalized
        assert xrefs["refs"] == [{"from": 0x401012, "to": 0x401030, "type": "code", "function": "main"}]
        strings = (await run("binary.strings", {"query": "Hello"}))["result"]
        assert strings.tool_name == "list_strings_filter" and strings.normalized["returned"] == 1
        assert (await run("binary.imports"))["result"].normalized["total"] == 2
        assert (await run("binary.exports"))["result"].normalized["exports"] == [{"name": "main", "address": 0x401000}]

        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["tool_name"] == "decompile_function" and record["provider_id"] == "bn"
        assert (record["engine"], record["engine_family"]) == ("binaryninja", "binaryninja")
        assert record["target_id"] == target.sha256 and record["subject_name"] == "check_key"
        assert "int64_t check_key" in record["raw"]["content"]
        # the active view is checked before every operation
        tools = [c["tool"] for c in calls(log)]
        assert tools.count("get_binary_status") == 16
    finally:
        await mgr.close()


async def test_jadx_operations_normalise_and_keep_provenance(config_factory, workspace, apk_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [adapter_mock("jadx", "jadx", call_log=log)]))
    try:
        target = await target_of(mgr, apk_sample)
        assert target.format == "apk"

        async def run(op: str, params: dict[str, Any] | None = None):
            return await mgr.perform(op, target, params or {}, provider_id="jadx")

        manifest = (await run("apk.manifest"))["result"].normalized
        assert "com.example.nexus" in manifest["manifest_xml"]
        assert manifest["main_activity"] == "com.example.nexus.MainActivity"
        comps = (await run("apk.components"))["result"].normalized
        # pinned record shape: name, type, is_main, is_browsable, exported, exported_reason, intent_filters
        assert [(c["name"], c["exported"]) for c in comps["exported_components"]] == [
            ("com.example.nexus.MainActivity", True)
        ]
        assert [c["name"] for c in comps["deeplink_components"]] == ["com.example.nexus.MainActivity"]
        classes = (await run("apk.classes", {"query": "com.example.nexus.K"}))["result"].normalized
        assert classes == {"classes": ["com.example.nexus.KeyCheck"], "returned": 1}
        out = await run("apk.class_source", {"class_name": "com.example.nexus.KeyCheck", "max_bytes": 4096})
        src = out["result"]
        assert src.subject_type == "class" and src.subject_name == "com.example.nexus.KeyCheck"
        assert "class KeyCheck" in src.normalized["source"]
        method = (await run("apk.search", {"query": "ok", "kind": "method"}))["result"]
        assert method.tool_name == "search_method_by_name" and method.normalized["results"] == {
            "com.example.nexus.KeyCheck": ["boolean ok(int)"]
        }
        keyword = (await run("apk.search", {"query": "Key"}))["result"]
        assert keyword.tool_name == "search_classes_by_keyword"

        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["tool_name"] == "get_class_source" and record["subject_type"] == "class"
        assert (record["engine"], record["engine_family"]) == ("jadx", "jadx")
        assert record["target_id"] == target.sha256 and "0x1337" in record["raw"]["content"]
        loads = [c for c in calls(log) if c["tool"] == "load_apk"]
        assert len(loads) == 1 and Path(loads[0]["path"]) == target.staged_path("jadx")
        source_call = next(c for c in calls(log) if c["tool"] == "get_class_source")
        assert source_call["arg_keys"] == ["className", "maxBytes"]
    finally:
        await mgr.close()


# -- unsupported operations and refusals ------------------------------------------------------


async def test_unsupported_operations_are_rejected_without_calling_tools(
    config_factory, workspace, elf_sample, apk_sample, tmp_path
):
    logs = {p: tmp_path / f"{p}.jsonl" for p in ("ida", "bn", "jadx")}
    providers = [
        adapter_mock("ida", "ida_rs", call_log=logs["ida"]),
        adapter_mock("bn", "binary_ninja", call_log=logs["bn"]),
        adapter_mock("jadx", "jadx", call_log=logs["jadx"]),
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        elf = await target_of(mgr, elf_sample)
        apk = await target_of(mgr, apk_sample)
        cases = [
            ("bn", "binary.metadata", elf, {}, "does not implement"),
            ("bn", "binary.cfg", elf, {}, "does not implement"),
            ("ida", "apk.manifest", apk, {}, "does not implement"),
            ("jadx", "binary.decompile", elf, {"name": "main"}, "does not implement"),
        ]
        for pid, op, target, params, match in cases:
            with pytest.raises(CapabilityUnavailable) as info:
                await mgr.perform(op, target, params, provider_id=pid)
            assert match in last_attempt(info)["reason"], (pid, op)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.xrefs", elf, {"address": 0x401000, "direction": "from"}, provider_id="bn")
        assert "xrefs *to*" in last_attempt(info)["message"]
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("apk.manifest", elf, {}, provider_id="jadx")
        assert "need an APK target" in last_attempt(info)["message"]
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("apk.class_source", apk, {}, provider_id="jadx")
        assert "class_name is required" in last_attempt(info)["message"]
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", elf, {}, provider_id="ida")
        assert "address or name is required" in last_attempt(info)["message"]
        assert "get_xrefs_to" not in {c["tool"] for c in calls(logs["bn"])}
        assert {c["tool"] for c in calls(logs["jadx"])} <= {"load_apk"}
        assert mgr.evidence.query_evidence(target_id=elf.sha256) == []
    finally:
        await mgr.close()


async def test_binary_ninja_refuses_when_another_binary_is_open(config_factory, workspace, elf_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    provider = adapter_mock("bn", "binary_ninja", call_log=log, env={"MOCK_BINJA_VIEW": "someone_else.bin"})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, elf_sample)
        for op, params in (("binary.functions", {}), ("binary.decompile", {"name": "main"})):
            with pytest.raises(CapabilityUnavailable) as info:
                await mgr.perform(op, target, params, provider_id="bn")
            attempt = last_attempt(info)
            assert "active view is 'someone_else.bin', which is not this target's staged copy" in attempt["message"]
            assert attempt["details"]["active_view"] == "someone_else.bin", "basename only, no full path"
        assert {c["tool"] for c in calls(log)} == {"get_binary_status"}, "no analysis of the wrong binary"
        assert mgr.evidence.query_evidence(target_id=target.sha256) == []
    finally:
        await mgr.close()


# -- invalid / unexpected responses and error propagation ------------------------------------------


async def test_provider_errors_propagate_without_evidence(config_factory, workspace, elf_sample):
    providers = [
        adapter_mock("ida", "ida_rs", env={"MOCK_ERROR_TOOL": "decompile"}, priority=80),  # ranked first
        adapter_mock("bn", "binary_ninja"),
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="ida")
        attempt = last_attempt(info)
        assert attempt["provider_id"] == "ida" and attempt["outcome"] == "failed"
        assert "ida/decompile reported an error: mock failure in decompile" in attempt["message"]
        # an engine-reported "not found" is an error, not an empty result
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"address": 0x409999}, provider_id="bn")
        assert "no function contains 0x409999" in last_attempt(info)["message"]
        assert mgr.evidence.query_evidence(target_id=target.sha256, operation="binary.decompile") == []
        records = [json.loads(line) for line in mgr.audit.path.read_text(encoding="utf-8").splitlines()]
        failed = [r for r in records if r["event"] == "operation" and r["outcome"] == "failed"]
        assert {r["provider_id"] for r in failed} == {"ida", "bn"}
        # routing without a pinned provider fails over from the broken IDA decompiler to Binary Ninja
        out = await mgr.perform("binary.decompile", target, {"name": "main"})
        assert out["result"].provider_id == "bn"
        assert [a["provider_id"] for a in out["attempts"] if a["outcome"] == "failed"] == ["ida"]
    finally:
        await mgr.close()


async def test_open_failure_is_reported_and_not_cached(config_factory, workspace, elf_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(
        config_factory(workspace, [adapter_mock("ida", "ida_rs", call_log=log, env={"MOCK_ERROR_TOOL": "open_idb"})])
    )
    try:
        target = await target_of(mgr, elf_sample)
        for _ in range(2):
            with pytest.raises(CapabilityUnavailable) as info:
                await mgr.perform("binary.functions", target, {}, provider_id="ida")
            assert "ida/open_idb reported an error" in last_attempt(info)["message"]
        assert [c["tool"] for c in calls(log)] == ["open_idb", "open_idb"]
        assert mgr.providers["ida"].adapter_state.get("sessions") == {}
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("adapter", "provider_id", "operation", "tool", "params", "field"),
    [
        ("ida_rs", "ida", "binary.functions", "list_functions", {}, "functions"),
        ("ida_rs", "ida", "binary.xrefs", "xrefs_to", {"address": 0x401030}, "refs"),
        ("ida_rs", "ida", "binary.cfg", "basic_blocks", {"address": 0x401000}, "blocks"),
        ("binary_ninja", "bn", "binary.imports", "list_imports", {}, "imports"),
        ("binary_ninja", "bn", "binary.strings", "list_strings", {}, "strings"),
    ],
)
async def test_unexpected_list_payloads_are_flagged_not_fabricated(
    config_factory, workspace, elf_sample, apk_sample, adapter, provider_id, operation, tool, params, field
):
    """Regression (2026-10-14): a JSON payload of an unexpected shape was re-read as text lines, so
    Binary Ninja/JADX reported the JSON document itself as an import/class name. It must yield an
    empty list plus a warning, with the raw output kept as evidence for review."""
    provider = adapter_mock(provider_id, adapter, env={"MOCK_GARBAGE_TOOL": tool})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample if adapter == "jadx" else elf_sample)
        out = await mgr.perform(operation, target, params, provider_id=provider_id)
        assert out["result"].normalized[field] == []
        assert any(f"{tool} returned an unrecognised payload" in w for w in out["result"].warnings)
        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["tool_name"] == tool and "unexpected" in record["raw"]["content"]
        assert any("unrecognised payload" in w for w in record["warnings"])
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("adapter", "provider_id", "operation", "tool", "params", "match"),
    [
        ("ida_rs", "ida", "binary.decompile", "decompile", {"name": "main"}, "returned no pseudocode field"),
        (
            "binary_ninja",
            "bn",
            "binary.decompile",
            "decompile_function",
            {"name": "main"},
            "returned a JSON document (keys ['note', 'unexpected']) where HLIL",
        ),
        (
            "jadx",
            "jadx",
            "apk.class_source",
            "get_class_source",
            {"class_name": "com.example.nexus.KeyCheck"},
            "returned JSON dict where str was expected",
        ),
    ],
)
async def test_unexpected_code_payloads_are_not_labelled_as_code(
    config_factory, workspace, elf_sample, apk_sample, adapter, provider_id, operation, tool, params, match
):
    """Regression (2026-10-14): an unexpected JSON document was stored as 'Hex-Rays pseudocode',
    'HLIL' or 'java (JADX decompilation)'. It must fail the attempt instead."""
    provider = adapter_mock(provider_id, adapter, env={"MOCK_GARBAGE_TOOL": tool})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample if adapter == "jadx" else elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform(operation, target, params, provider_id=provider_id)
        assert match in last_attempt(info)["message"]
        assert mgr.evidence.query_evidence(target_id=target.sha256, operation=operation) == []
    finally:
        await mgr.close()


# -- timeout, cancellation, crash and cleanup ---------------------------------------------------


@pytest.mark.parametrize(
    ("adapter", "provider_id", "slow_tool", "operation", "params", "after"),
    [
        ("ida_rs", "ida", "decompile", "binary.decompile", {"name": "main"}, "binary.functions"),
        ("binary_ninja", "bn", "decompile_function", "binary.decompile", {"name": "main"}, "binary.functions"),
        ("jadx", "jadx", "get_class_source", "apk.class_source", {"class_name": "x.Y"}, "apk.classes"),
    ],
)
async def test_timeout_is_bounded_and_provider_stays_usable(
    config_factory, workspace, elf_sample, apk_sample, adapter, provider_id, slow_tool, operation, params, after
):
    provider = adapter_mock(
        provider_id,
        adapter,
        env={"MOCK_SLOW_TOOL": slow_tool, "MOCK_SLOW_SECONDS": "30"},
        timeout_seconds=2,
    )
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample if adapter == "jadx" else elf_sample)
        t0 = time.monotonic()
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform(operation, target, params, provider_id=provider_id)
        assert time.monotonic() - t0 < 15
        assert last_attempt(info)["error"] == "provider_timeout"
        ok = await mgr.perform(after, target, {}, provider_id=provider_id)
        assert ok["result"].provider_id == provider_id
    finally:
        await mgr.close()


async def test_target_open_uses_startup_timeout(config_factory, workspace, apk_sample, tmp_path):
    # startup_timeout_seconds also bounds the child's MCP handshake, which took up to 2.5 s on an
    # idle host, so the budget must leave headroom; load_apk sleeps far past both budgets.
    startup, call = 8, 60
    log = tmp_path / "calls.jsonl"
    provider = adapter_mock(
        "jadx",
        "jadx",
        call_log=log,
        env={"MOCK_SLOW_TOOL": "load_apk", "MOCK_SLOW_SECONDS": "120"},
        timeout_seconds=call,
        startup_timeout_seconds=startup,
    )
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample)
        t0 = time.monotonic()
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("apk.manifest", target, {}, provider_id="jadx")
        elapsed = time.monotonic() - t0
        # cut off by the startup budget: not earlier, and long before the ordinary call timeout
        assert startup - 0.5 <= elapsed < call / 2, elapsed
        assert last_attempt(info)["error"] == "provider_timeout"
        assert mgr.providers["jadx"].adapter_state.get("sessions") == {}
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("adapter", "provider_id", "slow_tool", "operation", "params", "after"),
    [
        ("ida_rs", "ida", "decompile", "binary.decompile", {"name": "main"}, "binary.functions"),
        ("binary_ninja", "bn", "decompile_function", "binary.decompile", {"name": "main"}, "binary.functions"),
        ("jadx", "jadx", "get_class_source", "apk.class_source", {"class_name": "x.Y"}, "apk.classes"),
    ],
)
async def test_cancelled_operation_releases_the_provider(
    config_factory, workspace, elf_sample, apk_sample, adapter, provider_id, slow_tool, operation, params, after
):
    provider = adapter_mock(provider_id, adapter, env={"MOCK_SLOW_TOOL": slow_tool, "MOCK_SLOW_SECONDS": "30"})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample if adapter == "jadx" else elf_sample)
        await mgr.perform(after, target, {}, provider_id=provider_id)  # warm the session first
        task = asyncio.create_task(mgr.perform(operation, target, params, provider_id=provider_id))
        await asyncio.sleep(1.0)
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # per-provider semaphore, call lock and MCP session must all be released by the cancellation
        ok = await asyncio.wait_for(mgr.perform(after, target, {}, provider_id=provider_id), timeout=10)
        assert ok["result"].provider_id == provider_id
        assert mgr.evidence.query_evidence(target_id=target.sha256, operation=operation) == []
    finally:
        await mgr.close()
    assert not mgr.providers[provider_id].started


async def test_ida_rs_reopens_after_crash_and_switches_databases(
    config_factory, workspace, elf_sample, pe_sample, tmp_path
):
    log = tmp_path / "calls.jsonl"
    mgr = await started(
        config_factory(workspace, [adapter_mock("ida", "ida_rs", call_log=log, env={"MOCK_CRASH_TOOL": "strings"})])
    )
    try:
        elf = await target_of(mgr, elf_sample)
        await mgr.perform("binary.functions", elf, {}, provider_id="ida")
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("binary.strings", elf, {}, provider_id="ida", max_failover=0)
        # the restarted server has no database open: the adapter must re-open, not reuse stale state
        again = await mgr.perform("binary.functions", elf, {}, provider_id="ida")
        assert again["result"].normalized["total"] == 3
        assert mgr.providers["ida"].describe()["restarts"] >= 1
        pe = await target_of(mgr, pe_sample)
        await mgr.perform("binary.functions", pe, {}, provider_id="ida")
        seq = [c["tool"] for c in calls(log)]
        assert seq == [
            "open_idb",
            "list_functions",
            "strings",
            "open_idb",
            "list_functions",
            "close_idb",  # only one database per server: the ELF is closed before the PE opens
            "open_idb",
            "list_functions",
        ], seq
        opened = [Path(c["path"]).name for c in calls(log) if c["tool"] == "open_idb"]
        assert opened == ["nexus_fixture.elf", "nexus_fixture.elf", "nexus_fixture.exe"]
    finally:
        await mgr.close()
    assert calls(log)[-1]["tool"] == "close_idb"


async def test_binary_ninja_crash_is_isolated_and_restarted(config_factory, workspace, elf_sample):
    providers = [
        adapter_mock("bn", "binary_ninja", env={"MOCK_CRASH_TOOL": "list_exports"}),
        adapter_mock("ida", "ida_rs"),
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("binary.exports", target, {}, provider_id="bn", max_failover=0)
        assert (await mgr.perform("binary.exports", target, {}, provider_id="ida"))["result"].provider_id == "ida"
        again = await mgr.perform("binary.functions", target, {}, provider_id="bn")
        assert again["result"].normalized["total"] == 3
        assert mgr.providers["bn"].describe()["restarts"] >= 1
    finally:
        await mgr.close()


# -- pinned upstream response contracts (docs/ADAPTER_CONTRACTS.md) ----------------------------------
# Regression tests for mismatches found on 2026-10-14 by reading the pinned upstream source.

JADX_SOURCE_PREFIX = "package com.example.nexus;\n\npublic class KeyCheck {"


async def test_jadx_json_encoded_strings_are_decoded_exactly_once(config_factory, workspace, apk_sample):
    """jadx-mcp-server returns json.dumps(str) for source, manifest and main activity; the adapter
    passed the quoted, escaped literal through as Java source / XML."""
    mgr = await started(config_factory(workspace, [adapter_mock("jadx", "jadx")]))
    try:
        target = await target_of(mgr, apk_sample)
        src = await mgr.perform(
            "apk.class_source", target, {"class_name": "com.example.nexus.KeyCheck"}, provider_id="jadx"
        )
        source = src["result"].normalized["source"]
        assert source.startswith(JADX_SOURCE_PREFIX) and "\\n" not in source
        # decoded once: a JSON-looking comment inside the source is kept verbatim
        assert '// {"looks": "like JSON"}' in source and src["result"].normalized["partial"] is False
        assert src["result"].warnings == []
        record = mgr.evidence.get_evidence_record(src["evidence"]["evidence_id"], include_raw=True)
        assert '\\"package com.example.nexus;' in record["raw"]["content"], "raw keeps the encoded envelope"
        manifest = (await mgr.perform("apk.manifest", target, {}, provider_id="jadx"))["result"].normalized
        assert manifest["manifest_xml"].startswith('<manifest package="com.example.nexus">\n')
        assert manifest["main_activity"] == "com.example.nexus.MainActivity"
    finally:
        await mgr.close()


async def test_jadx_bookkeeping_entries_are_not_data(config_factory, workspace, apk_sample):
    provider = adapter_mock("jadx", "jadx", env={"MOCK_JADX_PARTIAL": "1"})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample)
        classes = (await mgr.perform("apk.classes", target, {}, provider_id="jadx"))["result"]
        assert classes.normalized["classes"] == ["com.example.nexus.MainActivity"]
        assert any("@truncated: 1 of 2 class names shown" in w for w in classes.warnings)
        comps = (await mgr.perform("apk.components", target, {}, provider_id="jadx"))["result"]
        assert [c["name"] for c in comps.normalized["exported_components"]] == ["com.example.nexus.MainActivity"]
        assert any("@truncated: 1 of 2 shown" in w for w in comps.warnings)
        src = (
            await mgr.perform(
                "apk.class_source", target, {"class_name": "com.example.nexus.KeyCheck"}, provider_id="jadx"
            )
        )["result"]
        assert src.normalized["partial"] is True and src.normalized["source"].startswith("@outline: ")
        assert any("partial answer (@outline:" in w for w in src.warnings)
        assert "(partial)" in src.claim
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("tool", "operation", "params", "kind", "outcome"),
    [
        ("get_all_classes", "apk.classes", {}, "invalid_json", "are not valid JSON"),
        ("get_all_classes", "apk.classes", {}, "object", "returned JSON dict where list was expected"),
        (
            "get_class_source",
            "apk.class_source",
            {"class_name": "com.example.nexus.KeyCheck"},
            "list_of_strings",
            "JSON list where str",
        ),
        ("get_class_source", "apk.class_source", {"class_name": "com.example.nexus.KeyCheck"}, "plain_text", None),
    ],
)
async def test_jadx_malformed_and_plain_text_answers(
    config_factory, workspace, apk_sample, tool, operation, params, kind, outcome
):
    provider = adapter_mock("jadx", "jadx", env={"MOCK_GARBAGE_TOOL": tool, "MOCK_GARBAGE_KIND": kind})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample)
        if outcome is None:  # plain text where a string is expected: used verbatim, flagged
            out = await mgr.perform(operation, target, params, provider_id="jadx")
            assert out["result"].normalized["source"] == "this is not the pinned envelope"
            assert any("plain text instead of the pinned JSON-encoded string" in w for w in out["result"].warnings)
            return
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform(operation, target, params, provider_id="jadx")
        assert outcome in last_attempt(info)["message"]
        assert mgr.evidence.query_evidence(target_id=target.sha256, operation=operation) == []
    finally:
        await mgr.close()


async def test_ida_rs_decompile_rejects_non_dict_json(config_factory, workspace, elf_sample):
    env = {"MOCK_GARBAGE_TOOL": "decompile", "MOCK_GARBAGE_KIND": "list_of_strings"}
    mgr = await started(config_factory(workspace, [adapter_mock("ida", "ida_rs", env=env)]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="ida")
        assert "returned no pseudocode field (list)" in last_attempt(info)["message"]
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("operation", "tool", "params", "field"),
    [
        ("binary.strings", "strings", {}, "strings"),
        ("binary.imports", "imports", {}, "imports"),
        ("binary.exports", "exports", {}, "exports"),
        ("binary.disassemble", "disasm_function_at", {"address": 0x401000}, "instructions"),
    ],
)
async def test_ida_rs_answers_without_a_recognised_list_are_flagged(
    config_factory, workspace, elf_sample, operation, tool, params, field
):
    mgr = await started(config_factory(workspace, [adapter_mock("ida", "ida_rs", env={"MOCK_GARBAGE_TOOL": tool})]))
    try:
        target = await target_of(mgr, elf_sample)
        out = await mgr.perform(operation, target, params, provider_id="ida")
        assert out["result"].normalized[field] == []
        assert any(f"{tool} returned an unrecognised payload" in w for w in out["result"].warnings)
    finally:
        await mgr.close()


async def test_binary_ninja_file_preamble_is_not_a_function(config_factory, workspace, elf_sample):
    mgr = await started(config_factory(workspace, [adapter_mock("bn", "binary_ninja")]))
    try:
        target = await target_of(mgr, elf_sample)
        funcs = (await mgr.perform("binary.functions", target, {}, provider_id="bn"))["result"].normalized
        assert [f["name"] for f in funcs["functions"]] == ["main", "check_key", "add_numbers"]
        assert [f["address"] for f in funcs["functions"]] == [0x401000, 0x401030, 0x401040]
        dec = (await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="bn"))["result"]
        assert dec.normalized["code"].startswith("int64_t main()")
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("tool", "operation", "params"),
    [
        ("list_methods", "binary.functions", {}),
        ("list_imports", "binary.imports", {}),
        ("list_strings", "binary.strings", {}),
        ("get_xrefs_to", "binary.xrefs", {"address": 0x401030}),
        ("decompile_function", "binary.decompile", {"name": "main"}),
        ("fetch_disassembly", "binary.disassemble", {"name": "main"}),
    ],
)
async def test_binary_ninja_textual_errors_are_errors(config_factory, workspace, elf_sample, tool, operation, params):
    """The bridge never sets isError: 'Error: ...' text used to become HLIL, disassembly or list rows."""
    mgr = await started(config_factory(workspace, [adapter_mock("bn", "binary_ninja", env={"MOCK_ERROR_TOOL": tool})]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform(operation, target, params, provider_id="bn")
        message = last_attempt(info)["message"]
        assert "Binary Ninja bridge reported an error: Error" in message and len(message) < 600
        assert mgr.evidence.query_evidence(target_id=target.sha256) == []
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("env", "match"),
    [
        ({"MOCK_BINJA_VIEW": ""}, "Binary Ninja has no binary open"),
        (
            {"MOCK_BINJA_PREAMBLE_VIEW": "/tmp/other.elf"},
            "active view is 'other.elf', which is not this target's staged copy",
        ),
    ],
)
async def test_binary_ninja_answers_for_another_view_are_refused(config_factory, workspace, elf_sample, env, match):
    mgr = await started(config_factory(workspace, [adapter_mock("bn", "binary_ninja", env=env)]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.functions", target, {}, provider_id="bn")
        assert match in last_attempt(info)["message"]
        assert mgr.evidence.query_evidence(target_id=target.sha256) == []
    finally:
        await mgr.close()


async def test_binary_ninja_function_at_ambiguity_is_refused(config_factory, workspace, elf_sample):
    provider = adapter_mock("bn", "binary_ninja", env={"MOCK_BINJA_OVERLAP": "1"})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"address": 0x401030}, provider_id="bn")
        assert "lies in 2 functions (check_key, check_key_thunk); pass a name" in last_attempt(info)["message"]
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("tool", "operation", "params", "kind", "field", "warning"),
    [
        ("get_xrefs_to", "binary.xrefs", {"address": 0x401030}, "object", "refs", "get_xrefs_to returned an"),
        ("fetch_disassembly", "binary.disassemble", {"name": "main"}, "plain_text", "instructions", "no instruction"),
        ("search_functions_by_name", "binary.functions", {"query": "main"}, "object", "functions", "unrecognised"),
    ],
)
async def test_binary_ninja_unexpected_answers_are_flagged(
    config_factory, workspace, elf_sample, tool, operation, params, kind, field, warning
):
    env = {"MOCK_GARBAGE_TOOL": tool, "MOCK_GARBAGE_KIND": kind}
    mgr = await started(config_factory(workspace, [adapter_mock("bn", "binary_ninja", env=env)]))
    try:
        target = await target_of(mgr, elf_sample)
        out = await mgr.perform(operation, target, params, provider_id="bn")
        assert out["result"].normalized[field] == []
        assert any(warning in w for w in out["result"].warnings), out["result"].warnings
    finally:
        await mgr.close()


async def test_jadx_reconnect_inside_load_keeps_the_new_session(config_factory, workspace, apk_sample, tmp_path):
    """Shared session reset (providers/mcp.py): a reconnect triggered by load_apk itself must not
    drop the session it just created, or every later call reloads the APK."""
    log = tmp_path / "calls.jsonl"
    provider = adapter_mock("jadx", "jadx", call_log=log, env={"MOCK_CRASH_TOOL": "get_android_manifest"})
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, apk_sample)
        await mgr.perform("apk.classes", target, {}, provider_id="jadx")
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("apk.manifest", target, {}, provider_id="jadx", max_failover=0)
        for _ in range(2):
            await mgr.perform("apk.classes", target, {}, provider_id="jadx")
        tools = [c["tool"] for c in calls(log)]
        assert tools.count("load_apk") == 2, tools
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    "view",
    [r"D:\unrelated\nexus_fixture.elf", "/home/someone/nexus_fixture.elf", "ORIGINAL"],
)
async def test_binary_ninja_same_basename_elsewhere_is_refused(config_factory, workspace, elf_sample, tmp_path, view):
    """Regression (audit C, 2026-10-15): a different file with the target's basename was accepted and
    its analysis stored under the target's SHA-256. Even the operator's original path is refused:
    only the hash-verified, read-only staged copy is the target."""
    log = tmp_path / "calls.jsonl"
    view = str(elf_sample) if view == "ORIGINAL" else view
    mgr = await started(
        config_factory(workspace, [adapter_mock("bn", "binary_ninja", call_log=log, env={"MOCK_BINJA_VIEW": view})])
    )
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.functions", target, {}, provider_id="bn")
        attempt = last_attempt(info)
        assert "not this target's staged copy" in attempt["message"]
        assert attempt["details"]["active_view"] == "nexus_fixture.elf"
        assert {c["tool"] for c in calls(log)} == {"get_binary_status"}
        assert mgr.evidence.query_evidence(target_id=target.sha256) == []
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("adapter", "tool", "arguments"),
    [
        ("ida_rs", "open_idb", {"path": r"C:\Windows\win.ini", "idb_out": r"C:\Windows\Temp\x.i64"}),
        ("jadx", "load_apk", {"apkPath": r"C:\Windows\win.ini"}),
    ],
)
async def test_lifecycle_tools_never_reach_server_even_with_overrides(
    config_factory, workspace, tmp_path, adapter, tool, arguments
):
    log = tmp_path / "calls.jsonl"
    provider = adapter_mock("lc", adapter, call_log=log, tool_overrides={tool: "read"})
    mgr = await started(config_factory(workspace, [provider], policy={"read_only": False}))
    try:
        assert mgr.providers["lc"].tool_info(tool).classification.tool_class == "lifecycle"
        with pytest.raises(PolicyViolation, match="never forwarded"):
            await mgr.call_provider_tool("lc", tool, arguments)
        assert tool not in {c["tool"] for c in calls(log)}
    finally:
        await mgr.close()


@pytest.mark.parametrize(("count", "expected", "warned"), [(None, 2, False), (2, 2, True), (1, 1, True)])
async def test_ida_rs_disassembly_requests_a_count_and_flags_a_listing_at_its_limit(
    config_factory, workspace, elf_sample, tmp_path, count, expected, warned
):
    """disasm_function_at stops after `count` lines (default 200) without saying so
    (handlers/disasm.rs:245-283): the adapter always sends a count and warns when it is reached."""
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [adapter_mock("ida", "ida_rs", call_log=log)]))
    try:
        target = await target_of(mgr, elf_sample)
        params = {"address": 0x401000, **({"count": count} if count else {})}
        out = (await mgr.perform("binary.disassemble", target, params, provider_id="ida"))["result"]
        assert len(out.normalized["instructions"]) == expected
        assert any("returned its limit" in w for w in out.warnings) is warned
        disasm = [c for c in calls(log) if c["tool"] == "disasm_function_at"]
        assert disasm and "count" in disasm[-1]["arg_keys"]
    finally:
        await mgr.close()
