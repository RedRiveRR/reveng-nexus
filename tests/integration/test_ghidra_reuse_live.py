"""Opt-in: result reuse through a real re-mcp-ghidra provider (same switches as test_ghidra_live).

Shows that reuse uses the Ghidra installation identity (Ghidra/application.properties) and not
re-mcp-ghidra's serverInfo, which is the FastMCP framework version.
"""

import os
import shutil

import pytest

from integration.test_ghidra_live import REMCP
from reveng_nexus.registry import ProviderManager, engine_identity

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("REVENG_NEXUS_LIVE_GHIDRA") != "1",
        reason="set REVENG_NEXUS_LIVE_GHIDRA=1 and GHIDRA_INSTALL_DIR to run live Ghidra tests",
    ),
    pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="GHIDRA_INSTALL_DIR is not set"),
    pytest.mark.skipif(shutil.which("uvx") is None, reason="uvx is not on PATH"),
]


async def test_live_remcp_ghidra_decompile_is_reused_by_installation_identity(config_factory, workspace, elf_sample):
    mgr = ProviderManager(config_factory(workspace, [REMCP]))
    await mgr.start()
    try:
        provider = mgr.providers["ghidra_remcp"]
        identity, source = engine_identity(provider)
        assert identity is not None and identity["application.name"] == "Ghidra", source
        intake = await mgr.intake(str(elf_sample))
        target = mgr.target_context(intake["target"]["sha256"])
        params = {"address": 0x400119}
        first = await mgr.perform("binary.decompile", target, params, provider_id="ghidra_remcp", reuse=True)
        server_version = provider.server_info.get("version")
        second = await mgr.perform("binary.decompile", target, params, provider_id="ghidra_remcp", reuse=True)
        assert first["reused"] is False and second["reused"] is True
        assert second["evidence"]["evidence_id"] == first["evidence"]["evidence_id"]
        assert identity["application.version"] not in str(server_version)  # serverInfo is not Ghidra's version
        refreshed = await mgr.perform("binary.decompile", target, params, provider_id="ghidra_remcp", reuse=False)
        assert refreshed["reused"] is False
        assert refreshed["evidence"]["evidence_id"] != first["evidence"]["evidence_id"]
    finally:
        await mgr.close()
