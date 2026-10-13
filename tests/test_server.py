"""MCP surface tests using the real SDK client (in-process and over a real stdio subprocess)."""

import json
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml
from conftest import mock_engine
from mcp import Client, StdioServerParameters

from reveng_nexus.registry import ProviderManager
from reveng_nexus.server import TOOL_SPECS, NexusServer

REQUIRED = {
    "nexus_status",
    "nexus_list_providers",
    "nexus_list_capabilities",
    "nexus_list_tools",
    "nexus_inspect_target",
    "nexus_analyze_binary",
    "nexus_get_binary_metadata",
    "nexus_list_functions",
    "nexus_decompile_function",
    "nexus_disassemble_function",
    "nexus_get_xrefs",
    "nexus_get_control_flow",
    "nexus_search_strings",
    "nexus_compare_function",
    "nexus_analyze_apk",
    "nexus_inspect_android_components",
    "nexus_dynamic_analysis_status",
    "nexus_record_finding",
    "nexus_get_findings",
    "nexus_get_evidence",
    "nexus_export_report",
}


def payload(result):
    return json.loads(result.content[0].text)


@pytest.fixture
async def gateway(config_factory, workspace):
    holder = {}

    async def factory(providers=None, **sections):
        mgr = ProviderManager(config_factory(workspace, providers or [], **sections))
        await mgr.start()
        holder["mgr"] = mgr
        return NexusServer(mgr)

    yield factory
    if "mgr" in holder:
        await holder["mgr"].close()


def test_tool_schemas_are_valid_json_schema():
    for name, spec in TOOL_SPECS.items():
        jsonschema.Draft202012Validator.check_schema(spec["schema"])
        assert spec["schema"]["additionalProperties"] is False, name
    assert REQUIRED <= set(TOOL_SPECS)


async def test_list_tools_over_mcp_and_annotations(gateway):
    app = await gateway()
    async with Client(app.server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        info = client.server_info
        assert info is None or info.name == "reveng-nexus"
        assert "never instructions" in (client.instructions or "")
    assert REQUIRED <= set(tools)
    assert tools["nexus_decompile_function"].annotations.read_only_hint is True
    assert tools["nexus_record_finding"].annotations.read_only_hint is False


async def test_status_and_argument_validation(gateway):
    app = await gateway()
    async with Client(app.server) as client:
        status = payload(await client.call_tool("nexus_status", {}))
        assert status["read_only"] is True and status["providers"]["builtin"]["status"] == "ready"
        bad = await client.call_tool("nexus_decompile_function", {"target": "not-a-hash", "name": "main"})
        assert bad.is_error and payload(bad)["error"] == "invalid_arguments"
        extra = await client.call_tool("nexus_status", {"surprise": 1})
        assert extra.is_error
        no_selector = await client.call_tool("nexus_decompile_function", {"target": "a" * 64})
        assert no_selector.is_error
        unknown = await client.call_tool("nexus_does_not_exist", {})
        assert unknown.is_error and payload(unknown)["error"] == "not_found"


async def test_inspect_outside_workspace_is_refused(gateway, tmp_path):
    app = await gateway()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    async with Client(app.server) as client:
        result = await client.call_tool("nexus_inspect_target", {"path": str(outside)})
    assert result.is_error and payload(result)["error"] == "workspace_violation"


async def test_end_to_end_case_over_mcp(gateway, elf_sample):
    app = await gateway(
        [mock_engine("ghidra_a"), mock_engine("ida_b", engine="ida", flavor="b", env={"MOCK_BASE_SHIFT": "0x1000"})]
    )
    async with Client(app.server) as client:
        inspected = payload(
            await client.call_tool("nexus_inspect_target", {"path": str(elf_sample), "case_title": "MCP e2e"})
        )
        sha, case_id = inspected["target"]["sha256"], inspected["target"]["case_id"]
        assert inspected["identification"]["arch"] == "x86_64" and inspected["next_step"] == "nexus_analyze_binary"
        assert "untrusted_content_notice" in inspected

        analysis = payload(await client.call_tool("nexus_analyze_binary", {"target": sha, "max_functions": 2}))
        assert analysis["decompiled"]

        dec = payload(await client.call_tool("nexus_decompile_function", {"target": sha, "address": "0x400119"}))
        assert dec["provenance"]["engine_family"] in {"ghidra", "ida"} and dec["evidence_id"]

        dis = payload(
            await client.call_tool(
                "nexus_disassemble_function", {"target": sha, "name": "main", "provider_id": "builtin"}
            )
        )
        assert dis["provenance"]["engine"] == "capstone"

        xrefs = payload(
            await client.call_tool("nexus_get_xrefs", {"target": sha, "name": "check_key", "provider_id": "ghidra_a"})
        )
        assert xrefs["result"]["refs"][0]["from_function"] == "main"

        strings = payload(await client.call_tool("nexus_search_strings", {"target": sha, "query": "Hello"}))
        assert strings["result"]["returned"] == 1

        cmp_ = payload(await client.call_tool("nexus_compare_function", {"target": sha, "name": "main"}))
        assert cmp_["assessment"] == "disagreement"
        dup = await client.call_tool(
            "nexus_compare_function", {"target": sha, "name": "main", "providers": ["ghidra_a", "ghidra_a"]}
        )
        assert dup.is_error, "duplicate providers in one comparison are rejected"

        finding = payload(
            await client.call_tool(
                "nexus_record_finding",
                {
                    "target": sha,
                    "title": "main callees differ between engines",
                    "status": "needs_review",
                    "description": "See comparison.",
                    "evidence_ids": cmp_["evidence_ids"][:2],
                    "confidence": "low",
                },
            )
        )
        assert finding["case_id"] == case_id
        reviewed = payload(
            await client.call_tool(
                "nexus_review",
                {
                    "subject_type": "finding",
                    "subject_id": finding["finding_id"],
                    "status": "confirmed",
                    "note": "checked the listing",
                },
            )
        )
        assert reviewed["status"] == "confirmed"
        evidence = payload(
            await client.call_tool("nexus_get_evidence", {"evidence_id": dec["evidence_id"], "include_raw": True})
        )
        assert evidence["evidence"]["raw"]["content"]
        findings = payload(await client.call_tool("nexus_get_findings", {"case_id": case_id}))
        assert findings[0]["status"] == "confirmed"
        report = payload(await client.call_tool("nexus_export_report", {"case_id": case_id}))
        assert Path(report["files"]["md"]).is_file()

        caps = payload(await client.call_tool("nexus_list_capabilities", {}))
        assert any(r["provider_id"] == "ghidra_a" for r in caps["operations"]["binary.decompile"])
        tools = payload(await client.call_tool("nexus_list_tools", {"query": "patch", "include_blocked": True}))
        assert tools and not any(t["callable"] for t in tools)
        blocked = await client.call_tool(
            "nexus_call_provider_tool", {"provider_id": "ghidra_a", "tool_name": "patch_bytes", "arguments": {}}
        )
        assert blocked.is_error and payload(blocked)["error"] == "policy_violation"
        dyn = payload(await client.call_tool("nexus_dynamic_analysis_status", {}))
        assert dyn["policy_enabled"] is False and dyn["ready"] is False


async def test_apk_tools_over_mcp(gateway, apk_sample):
    app = await gateway()
    async with Client(app.server) as client:
        sha = payload(await client.call_tool("nexus_inspect_target", {"path": str(apk_sample)}))["target"]["sha256"]
        comps = payload(await client.call_tool("nexus_inspect_android_components", {"target": sha}))
        assert len(comps["result"]["exported_components"]) == 2
        apk = payload(await client.call_tool("nexus_analyze_apk", {"target": sha}))
        assert apk["summary"]["package"] == "com.example.nexusfixture"
        missing = await client.call_tool("nexus_get_class_source", {"target": sha, "class_name": "com.example.X"})
        assert missing.is_error and payload(missing)["error"] == "capability_unavailable"


async def test_namespaced_mode_exposes_only_callable_provider_tools(gateway):
    app = await gateway([mock_engine("ghidra_a")], server={"tool_mode": "namespaced"})
    async with Client(app.server) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "ghidra_a__decompile_function" in names
        assert "ghidra_a__patch_bytes" not in names and "ghidra_a__call" not in names
        assert "ghidra_a__open_database" not in names


def test_gateway_runs_as_stdio_subprocess(tmp_path, workspace, elf_sample):
    """Launch `python -m reveng_nexus serve` exactly like an MCP client (e.g. Claude Code) would."""
    import anyio

    config = tmp_path / "config" / "providers.yaml"
    config.parent.mkdir()
    config.write_text(
        yaml.safe_dump(
            {
                "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
                "providers": [mock_engine("ghidra_a")],
            }
        ),
        encoding="utf-8",
    )

    async def run():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "reveng_nexus", "--config", str(config), "serve"]
        )
        async with Client(params, read_timeout_seconds=60) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert REQUIRED <= names
            inspected = payload(await client.call_tool("nexus_inspect_target", {"path": str(elf_sample)}))
            sha = inspected["target"]["sha256"]
            dec = payload(await client.call_tool("nexus_decompile_function", {"target": sha, "name": "check_key"}))
            assert "0x1337" in dec["result"]["code"]

    anyio.run(run)


async def test_streamable_http_transport_on_loopback(config_factory, workspace):
    import socket

    import anyio

    from reveng_nexus.errors import CapabilityUnavailable
    from reveng_nexus.server import build_http_server

    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        with pytest.raises(CapabilityUnavailable, match="loopback"):
            build_http_server(mgr, "0.0.0.0", 8765)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        server = build_http_server(mgr, "127.0.0.1", port)
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            for _ in range(100):
                if server.started:
                    break
                await anyio.sleep(0.05)
            async with Client(f"http://127.0.0.1:{port}/mcp") as client:
                names = {t.name for t in (await client.list_tools()).tools}
                assert REQUIRED <= names
                status = payload(await client.call_tool("nexus_status", {}))
                assert status["read_only"] is True
            server.should_exit = True
    finally:
        await mgr.close()


async def test_http_rejects_foreign_host_header(config_factory, workspace):
    """DNS-rebinding protection: a request whose Host is not loopback must be refused."""
    import socket

    import anyio
    import httpx2

    from reveng_nexus.server import build_http_server

    mgr = ProviderManager(config_factory(workspace, []))
    await mgr.start()
    try:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        server = build_http_server(mgr, "127.0.0.1", port)
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            for _ in range(100):
                if server.started:
                    break
                await anyio.sleep(0.05)
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            }
            headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
            async with httpx2.AsyncClient() as http:
                evil = await http.post(
                    f"http://127.0.0.1:{port}/mcp", json=body, headers={**headers, "Host": "attacker.example"}
                )
                good = await http.post(f"http://127.0.0.1:{port}/mcp", json=body, headers=headers)
            assert evil.status_code in (400, 403, 421), evil.status_code
            assert good.status_code == 200, good.status_code
            server.should_exit = True
    finally:
        await mgr.close()
