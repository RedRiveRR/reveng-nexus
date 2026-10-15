"""Regressions proposed by audit C (2026-10-15)."""

from __future__ import annotations

import asyncio
import copy
import json
import sys
import types

import pytest
from conftest import TESTS, mock_launched
from fixtures.elf_builder import write_elf
from fixtures.pe_builder import write_pe

from reveng_nexus.adapters.mcpyghidra import MCPYGHIDRA
from reveng_nexus.providers.mcp import unwrap_result
from reveng_nexus.registry import ProviderManager

MOCK_IDA_OFFICIAL = str(TESTS / "mock_servers" / "mock_ida_official.py")


def ida_official() -> dict:
    return {
        "id": "ida_official",
        "enabled": True,
        "type": "mcp_stdio",
        "adapter": "ida_official",
        "command": sys.executable,
        "args": [MOCK_IDA_OFFICIAL],
        "timeout_seconds": 20,
        "startup_timeout_seconds": 60,
    }


async def test_provider_without_bound_operations_is_degraded(config_factory, workspace):
    """ida_official binds no operation (analysis only via execute_python): it must not report ready."""
    mgr = ProviderManager(config_factory(workspace, [ida_official()]))
    await mgr.start()
    try:
        health = (await mgr.health())["ida_official"]
        assert health["status"] == "degraded"
        assert health["usable_operations"] == []
        assert health["callable_tools"] == ["list_databases", "reference"]
        assert "execute_python" not in health["callable_tools"]
    finally:
        await mgr.close()


def test_providers_check_fails_for_provider_without_operations(tmp_path, workspace):
    import subprocess

    import yaml

    cfg = {
        "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
        "providers": [ida_official()],
    }
    path = tmp_path / "providers.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "reveng_nexus", "--config", str(path), "providers", "check", "ida_official"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    report = json.loads(proc.stdout)
    assert report["ida_official"]["health"]["status"] == "degraded"
    assert proc.returncode == 1


async def _two_targets(config_factory, workspace, **settings):
    a = workspace / "a.elf"
    write_elf(a)
    b = write_pe(workspace / "b.exe")
    mgr = ProviderManager(config_factory(workspace, [mock_launched("mcpy", settings=settings)]))
    await mgr.start()
    ta = mgr.target_context((await mgr.intake(str(a)))["target"]["sha256"])
    tb = mgr.target_context((await mgr.intake(str(b)))["target"]["sha256"])
    return mgr, ta, tb


@pytest.mark.parametrize("max_sessions", [1, 2])
async def test_raw_call_is_answered_by_its_own_targets_server(config_factory, workspace, max_sessions):
    """Regression: call_provider_tool opened B's server outside the provider semaphore and then
    called whichever target was active, so a concurrent operation on A answered B's raw call."""
    mgr, ta, tb = await _two_targets(config_factory, workspace, max_sessions=max_sessions)
    try:
        for _ in range(10):
            op, raw = await asyncio.gather(
                mgr.perform("binary.metadata", ta, {}, provider_id="mcpy"),
                mgr.call_provider_tool("mcpy", "context", {}, target_sha256=tb.sha256),
            )
            assert op["result"].normalized["image_base"] == 0x400000
            assert unwrap_result(raw)[0]["memory"]["image_base"] == "0x140000000"
    finally:
        await mgr.close()


async def test_raw_call_never_falls_back_to_another_targets_session(config_factory, workspace):
    mgr, ta, tb = await _two_targets(config_factory, workspace, max_sessions=1)
    try:
        provider = mgr.providers["mcpy"]
        await provider._client_for(tb)
        await mgr.perform("binary.metadata", ta, {}, provider_id="mcpy")  # evicts B (max_sessions=1)
        with pytest.raises(Exception, match="no live session for target"):
            await provider.call_tool("context", {}, internal=False, target_sha256=tb.sha256)
    finally:
        await mgr.close()


# -- MCPyGhidra normalisers against payloads shaped like the pinned 0.8.0 source ------------------
PROV = types.SimpleNamespace(id="mcpy", engine="ghidra", engine_family="ghidra")
TGT = types.SimpleNamespace(sha256="0" * 64, display_name="x.elf")


def _adapter(payload):
    adapter = copy.copy(MCPYGHIDRA)

    async def call(provider, target, tool, args, **kw):
        return payload, json.dumps(payload), {"content": []}

    adapter.call = call
    return adapter


@pytest.mark.parametrize(
    "blocks",
    [[{"size": 4}, {"size": 2}], ["0x401000"], {"0x401000": "junk"}, {"k": {"size": 4}}, None],
)
async def test_mcpyghidra_cfg_never_invents_block_addresses(blocks):
    out = await _adapter({"entry": "0x401000", "blocks": blocks}).op_binary_cfg(PROV, TGT, {}, {"address": 0x401000})
    assert out.normalized["blocks"] == []
    assert out.warnings


async def test_mcpyghidra_cfg_pinned_shape():
    payload = {
        "entry": "0x401000",
        "blocks": {"0x401000": {"address": "0x401000", "size": 4, "successors": ["0x401004"]}},
    }
    out = await _adapter(payload).op_binary_cfg(PROV, TGT, {}, {"address": 0x401000})
    assert out.normalized["blocks"] == [{"start": 0x401000, "end": 0x401004, "successors": [0x401004], "called": []}]
    assert out.warnings == []


async def test_mcpyghidra_xrefs_from_rows_use_the_queried_address_as_source():
    payload = {
        "direction": "from",
        "addr": "0x401000",
        "error": None,
        "items": [{"to": {"addr": "0x402000", "function": "puts"}, "xref-type": "UNCONDITIONAL_CALL"}],
        "page_info": {"has_more": True},
    }
    out = await _adapter(payload).op_binary_xrefs(PROV, TGT, {}, {"name": "main", "direction": "from"})
    assert out.normalized["refs"][0]["from"] == 0x401000 and out.normalized["refs"][0]["to"] == 0x402000
    assert any("truncated" in w for w in out.warnings)


async def test_mcpyghidra_xrefs_to_by_name_uses_the_resolved_address():
    payload = {"direction": "to", "addr": "0x402000", "error": None, "items": [{"from": {"addr": "0x401005"}}]}
    out = await _adapter(payload).op_binary_xrefs(PROV, TGT, {}, {"name": "puts"})
    assert out.normalized["refs"][0]["to"] == 0x402000


@pytest.mark.skipif(sys.platform != "win32", reason="UNC paths are a Windows concept")
@pytest.mark.parametrize(
    "path",
    [
        r"\\attacker.invalid\share\x.bin",
        "//attacker.invalid/share/x.bin",
        r"\\?\UNC\attacker.invalid\share\x.bin",
        r"\\.\UNC\attacker.invalid\share\x.bin",
    ],
)
def test_unc_paths_are_refused_before_any_filesystem_access(tmp_path, monkeypatch, path):
    """resolve() on a UNC path makes Windows contact the server over SMB (NTLM credential leak)."""
    import pathlib

    from reveng_nexus.artifacts import WorkspaceGuard
    from reveng_nexus.errors import WorkspaceViolation

    guard = WorkspaceGuard((str(tmp_path),), 1024)
    touched: list[str] = []

    def no_resolve(self, strict=False):
        touched.append(str(self))
        raise AssertionError("filesystem touched")

    monkeypatch.setattr(pathlib.Path, "resolve", no_resolve)
    with pytest.raises(WorkspaceViolation):
        guard.check(path)
    assert touched == []


async def test_per_target_provider_with_no_usable_operations_is_degraded(config_factory, workspace):
    """A per-target server whose listing lacks every bound tool (backend failed) must not report ready."""
    mgr, ta, _ = await _two_targets(config_factory, workspace)
    try:
        provider = mgr.providers["mcpy"]
        await provider._client_for(ta)
        assert (await mgr.health())["mcpy"]["status"] == "ready"
        # Simulate the observed failure mode: only meta tools are listed.
        bound = {tool for required in provider.adapter.bindings.values() for tool in required}
        provider._tools = {name: info for name, info in provider._tools.items() if name not in bound}
        assert provider._tools
        health = (await mgr.health())["mcpy"]
        assert health["status"] == "degraded"
        assert health["usable_operations"] == []
    finally:
        await mgr.close()


@pytest.mark.parametrize("section", ["architecture", "memory", "application"])
async def test_mcpyghidra_metadata_null_sections_are_unknown_not_a_crash(section):
    """A context section reported as null (or not a mapping) leaves its fields unknown."""
    ctx = {"architecture": {"processor": "x86"}, "memory": {"image_base": "0x400000"}, "application": {}}
    for value in (None, "n/a"):
        out = await _adapter({**ctx, section: value}).op_binary_metadata(PROV, TGT, {}, {})
        if section == "architecture":
            assert out.normalized["processor"] is None
        if section == "memory":
            assert out.normalized["image_base"] is None
