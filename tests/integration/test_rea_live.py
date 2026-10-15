"""Opt-in end-to-end test against the real, pinned REA (npm rea-agents 6.5.0) through Nexus.

Enable with:
    $env:REVENG_NEXUS_LIVE_REA = "1"
    $env:REA_NODE  = "<dedicated Node 22.19+/24.11+ node.exe>"
    $env:REA_ENTRY = "<prefix>\\node_modules\\rea-agents\\scripts\\rea.mjs"
    python -m pytest tests/integration/test_rea_live.py -m integration -v

REA runs as a Nexus-managed stdio child (``node rea.mjs mcp``, never npx), with HOME/TEMP pointed
into the test's own directory. Only generated, benign fixtures are analysed (an ASAR archive of two
small CommonJS files and an ELF carrying an Electron fuse wire); nothing is executed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from fixtures.electron_builder import write_asar, write_fuse_elf

from reveng_nexus.adapters.rea import CATALOGUE_SHA256, CATALOGUE_SIZE
from reveng_nexus.errors import CapabilityUnavailable, PolicyViolation
from reveng_nexus.registry import ProviderManager

NODE, ENTRY = os.environ.get("REA_NODE", ""), os.environ.get("REA_ENTRY", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("REVENG_NEXUS_LIVE_REA") != "1",
        reason="set REVENG_NEXUS_LIVE_REA=1, REA_NODE and REA_ENTRY to run the live REA test",
    ),
    pytest.mark.skipif(not (Path(NODE).is_file() and Path(ENTRY).is_file()), reason="REA_NODE/REA_ENTRY not found"),
]


def rea_provider(home: Path, *, enabled: bool = True) -> dict:
    return {
        "id": "rea",
        "enabled": enabled,
        "type": "mcp_stdio",
        "adapter": "rea",
        "command": NODE,
        "args": [ENTRY, "mcp"],
        "env": {
            "PATH": str(Path(NODE).parent) + os.pathsep + os.path.join(os.environ.get("SystemRoot", ""), "System32"),
            "USERPROFILE": str(home),
            "HOME": str(home),
            "TEMP": str(home / "tmp"),
            "TMP": str(home / "tmp"),
            "REA_LOG_LEVEL": "warn",
        },
        "capabilities": ["js.application", "electron.fuses"],
        "timeout_seconds": 300,
        "startup_timeout_seconds": 120,
    }


def rea_processes() -> list[int]:
    """PIDs of node processes running the pinned REA entry point (Windows only)."""
    if os.name != "nt":
        return []
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | "
        "Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
    )
    out = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True).stdout
    rows = json.loads(out) if out.strip() else []
    rows = [rows] if isinstance(rows, dict) else rows
    needle = str(Path(ENTRY).parent.parent).lower()
    return [r["ProcessId"] for r in rows if needle in (r.get("CommandLine") or "").lower()]


async def _settle_gone() -> list[int]:
    for _ in range(40):
        left = rea_processes()
        if not left:
            return []
        await asyncio.sleep(0.25)
    return rea_processes()


async def test_live_rea_static_analysis_through_nexus(config_factory, workspace, elf_sample, tmp_path):
    home = tmp_path / "rea-home"
    (home / "tmp").mkdir(parents=True)
    asar = write_asar(workspace / "nexus_fixture_app.asar")
    fuses = write_fuse_elf(workspace / "nexus_fuse_fixture.elf")
    digests = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (asar, fuses)}
    assert rea_processes() == [], "another REA process is already running"

    mgr = ProviderManager(config_factory(workspace, [rea_provider(home)]))
    await mgr.start()
    try:
        assert mgr.provider_errors == {}, mgr.provider_errors
        provider = mgr.providers["rea"]
        # 1-2. handshake and real tool discovery through Nexus
        assert provider.server_info.get("name") == "rea" and provider.server_info.get("version") == "6.5.0"
        tools = {t.name: t for t in await provider.list_tools()}
        assert len(tools) == CATALOGUE_SIZE
        assert hashlib.sha256("\n".join(sorted(tools)).encode()).hexdigest() == CATALOGUE_SHA256
        # 6. only the allowlisted operations are usable; nothing else is exposed or forwarded
        assert sorted(n for n, t in tools.items() if t.decision.allowed) == [
            "analyze_javascript_application",
            "inspect_electron_fuses",
        ]
        with pytest.raises(PolicyViolation):
            await mgr.call_provider_tool("rea", "inspect_electron_fuses", {"path": str(fuses)})
        assert rea_processes(), "the REA child should be running"

        # 3-5. one real static analysis per operation; evidence with hash, provenance and raw output
        intake = await mgr.intake(str(asar), case_title="live rea")
        target = mgr.target_context(intake["target"]["sha256"], intake["case_id"])
        out = await mgr.perform("js.application", target, {}, provider_id="rea")
        res = out["result"]
        assert (res.provider_id, res.tool_name, res.engine_family) == ("rea", "analyze_javascript_application", "rea")
        assert res.normalized["rea_operation"] == "analyze_javascript_application"
        assert res.normalized["rea_evidence_id"].startswith("ev_")
        assert res.normalized["format"] == "asar"
        assert res.normalized["statistics"]["parsed_javascript_files"] == 2
        assert any("never executed" in x for x in res.normalized["limitations"])
        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["target_id"] == target.sha256 and record["provider_id"] == "rea"
        assert record["engine_version"] == "rea-agents 6.5.0 (server-reported)"
        raw = json.loads(record["raw"]["content"])
        assert raw["structured_content"]["subject"]["digest"]["sha256"] == target.sha256
        assert str(workspace) not in json.dumps(record["normalized"])

        fuse_target = mgr.target_context((await mgr.intake(str(fuses)))["target"]["sha256"])
        fres = (await mgr.perform("electron.fuses", fuse_target, {}, provider_id="rea"))["result"]
        states = {f["name"]: f["state"] for f in fres.normalized["fuses"]}
        assert states["RunAsNode"] == "disabled" and states["EnableCookieEncryption"] == "enabled"

        # 7. cancellation leaves the provider usable
        task = asyncio.create_task(mgr.perform("js.application", target, {}, provider_id="rea"))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        again = await mgr.perform("electron.fuses", fuse_target, {}, provider_id="rea")
        assert again["result"].normalized["fuses"]
    finally:
        await mgr.close()
    # 7. shutdown reaps REA and its analysis worker
    assert await _settle_gone() == [], "REA processes outlived the gateway"

    # 8. REA disabled: existing operations keep working, REA operations are cleanly unavailable
    mgr = ProviderManager(config_factory(workspace, [rea_provider(home, enabled=False)]))
    await mgr.start()
    try:
        assert "rea" not in mgr.providers and rea_processes() == []
        elf = mgr.target_context((await mgr.intake(str(elf_sample)))["target"]["sha256"])
        assert (await mgr.perform("binary.metadata", elf, {}, provider_id="builtin"))["result"].normalized
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("js.application", mgr.target_context(digests[asar]), {})
    finally:
        await mgr.close()

    # 9. re-enabled: the normal operation works again
    mgr = ProviderManager(config_factory(workspace, [rea_provider(home)]))
    await mgr.start()
    try:
        res = (await mgr.perform("js.application", mgr.target_context(digests[asar]), {}, provider_id="rea"))["result"]
        assert res.normalized["statistics"]["parsed_javascript_files"] == 2
    finally:
        await mgr.close()
    assert await _settle_gone() == []

    # 10. the generated fixtures are unchanged, and REA left nothing in its HOME
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (asar, fuses)} == digests
    assert [p.name for p in home.iterdir() if p.name != "tmp"] == []
