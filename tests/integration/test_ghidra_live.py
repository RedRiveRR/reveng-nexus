"""Opt-in end-to-end tests against a real Ghidra installation.

Enable with:
    $env:REVENG_NEXUS_LIVE_GHIDRA = "1"
    $env:GHIDRA_INSTALL_DIR = "C:\\path\\to\\ghidra_12.x_PUBLIC"
    python -m pytest tests/integration -m integration -v

Requires ``uvx`` on PATH (downloads re-mcp-ghidra 3.0.3 / mcpyghidra 0.8.0 into isolated
environments on first use) and a JDK 21+. Only the generated benign ELF fixture is
analysed; nothing is executed.
"""

import os
import shutil

import pytest

from reveng_nexus.orchestrator import Orchestrator
from reveng_nexus.registry import ProviderManager

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("REVENG_NEXUS_LIVE_GHIDRA") != "1",
        reason="set REVENG_NEXUS_LIVE_GHIDRA=1 and GHIDRA_INSTALL_DIR to run live Ghidra tests",
    ),
    pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="GHIDRA_INSTALL_DIR is not set"),
    pytest.mark.skipif(shutil.which("uvx") is None, reason="uvx is not on PATH"),
]

REMCP = {
    "id": "ghidra_remcp",
    "enabled": True,
    "type": "mcp_stdio",
    "adapter": "re_mcp",
    "engine": "ghidra",
    "command": "uvx",
    "args": ["--python", "3.12", "re-mcp-ghidra==3.0.3"],
    "env": {
        "GHIDRA_INSTALL_DIR": "${GHIDRA_INSTALL_DIR}",
        "GHIDRA_MCP_DISABLE_EXECUTE": "1",
        "GHIDRA_MCP_DISABLE_BATCH": "1",
        "GHIDRA_MCP_DISABLE_TOOL_SEARCH": "1",
    },
    "protocol_mode": "legacy",
    "priority": 80,
    "timeout_seconds": 600,
    "startup_timeout_seconds": 900,
}
MCPY = {
    "id": "ghidra_mcpy",
    "enabled": True,
    "type": "mcp_launched_http",
    "adapter": "mcpyghidra",
    "engine": "ghidra",
    "command": "uvx",
    "args": [
        "--python",
        "3.12",
        "--from",
        "mcpyghidra==0.8.0",
        "mcpyghidra-headless",
        "{target}",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--project-dir",
        "{workdir}",
    ],
    "env": {"GHIDRA_INSTALL_DIR": "${GHIDRA_INSTALL_DIR}"},
    "launch": {"startup_timeout_seconds": 900},
    "protocol_mode": "legacy",
    "priority": 60,
    "timeout_seconds": 600,
}


async def test_live_ghidra_providers_end_to_end(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, [REMCP, MCPY], analysis={"operation_timeout_seconds": 1800}))
    await mgr.start()
    try:
        assert mgr.provider_errors == {}, mgr.provider_errors
        intake = await mgr.intake(str(elf_sample), case_title="live ghidra")
        target = mgr.target_context(intake["target"]["sha256"], intake["case_id"])

        funcs = await mgr.perform("binary.functions", target, {}, provider_id="ghidra_remcp")
        by_name = {f["name"]: f for f in funcs["result"].normalized["functions"]}
        assert {"main", "check_key", "add_numbers", "get_greeting"} <= set(by_name)
        assert by_name["main"]["address"] == 0x400119

        for pid in ("ghidra_remcp", "ghidra_mcpy"):
            dec = await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id=pid)
            code = dec["result"].normalized["code"]
            assert "add_numbers(2,3)" in code and "check_key" in code and "get_greeting" in code, (pid, code)

        xrefs = await mgr.perform("binary.xrefs", target, {"address": 0x400100}, provider_id="ghidra_remcp")
        assert any(r.get("from") == 0x400127 for r in xrefs["result"].normalized["refs"]), xrefs["result"].normalized

        cmp_ = await Orchestrator(mgr).compare_function(target, name="main")
        assert cmp_["assessment"] != "independent_agreement" or "capstone" in cmp_["engine_families"]
        assert "ghidra" in cmp_["engine_families"]
    finally:
        await mgr.close()


async def test_live_ghidra_operations_per_provider(config_factory, workspace, elf_sample):
    """Each read-only operation on both wrappers, checked against the fixture's own layout
    (tests/fixtures/elf_builder.py). Addresses are file addresses (ET_EXEC at 0x400000)."""
    from fixtures.elf_builder import GREETING, KEY_LABEL, build_elf

    _blob, fx, symbols = build_elf()
    strings = {
        GREETING.rstrip(b"\x00").decode(): symbols["greeting"],
        KEY_LABEL.rstrip(b"\x00").decode(): symbols["key_label"],
    }
    main = fx["main"].address
    calls = {
        main + 14: fx["add_numbers"].address,
        main + 21: fx["check_key"].address,
        main + 26: fx["get_greeting"].address,
    }
    mgr = ProviderManager(config_factory(workspace, [REMCP, MCPY], analysis={"operation_timeout_seconds": 1800}))
    await mgr.start()
    try:
        assert mgr.provider_errors == {}, mgr.provider_errors
        intake = await mgr.intake(str(elf_sample), case_title="live ghidra per operation")
        target = mgr.target_context(intake["target"]["sha256"], intake["case_id"])

        async def run(pid, operation, params):
            out = await mgr.perform(operation, target, params, provider_id=pid, max_failover=0)
            record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"])
            assert (record["provider_id"], record["target_id"]) == (pid, target.sha256)
            return out["result"]

        for pid in ("ghidra_remcp", "ghidra_mcpy"):
            meta = (await run(pid, "binary.metadata", {})).normalized
            assert (meta["bits"], meta["image_base"], meta["function_count"]) == (64, 0x400000, 5), (pid, meta)
            # neither wrapper reports the ELF entry point (re-mcp-ghidra has no field; MCPyGhidra's
            # "entry_point" is its first external entry), so Nexus reports it as unknown
            assert meta["entry_point"] is None, (pid, meta)

            funcs = {f["name"]: f for f in (await run(pid, "binary.functions", {})).normalized["functions"]}
            assert {n: f["address"] for n, f in funcs.items()} == {n: f.address for n, f in fx.items()}, pid
            if pid == "ghidra_remcp":
                assert {n: f["size"] for n, f in funcs.items()} == {n: f.size for n, f in fx.items()}

            insns = (await run(pid, "binary.disassemble", {"name": "main"})).normalized["instructions"]
            assert insns[0]["address"] == main and insns[-1]["mnemonic"] == "ret", (pid, insns)
            assert [i["address"] for i in insns if i["mnemonic"] == "call"] == list(calls), pid

            refs_to = (await run(pid, "binary.xrefs", {"address": fx["add_numbers"].address})).normalized["refs"]
            assert any(r["from"] == main + 14 and r["is_call"] for r in refs_to), (pid, refs_to)
            refs_from = (await run(pid, "binary.xrefs", {"address": main + 14, "direction": "from"})).normalized
            assert [(r["from"], r["to"], r["is_call"]) for r in refs_from["refs"]] == [
                (main + 14, fx["add_numbers"].address, True)
            ], pid

            (block,) = (await run(pid, "binary.cfg", {"name": "main"})).normalized["blocks"]
            assert (block["start"], block["end"], block["successors"]) == (main, main + fx["main"].size, []), pid
            if pid == "ghidra_remcp":
                assert sorted(block["external_targets"]) == sorted(calls.values())
            else:
                assert sorted(block["called"]) == ["add_numbers", "check_key", "get_greeting"]

            found = {s["value"]: s["address"] for s in (await run(pid, "binary.strings", {})).normalized["strings"]}
            for value, address in strings.items():
                assert found.get(value) == address, (pid, value, found)

            assert (await run(pid, "binary.imports", {})).normalized["imports"] == [], pid  # static, no imports
            exports = {e["name"] for e in (await run(pid, "binary.exports", {})).normalized["exports"]}
            assert set(fx) <= exports, (pid, exports)
    finally:
        await mgr.close()
