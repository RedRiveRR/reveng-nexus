"""Real MCP lifecycle tests: providers are actual subprocesses speaking MCP over stdio/HTTP."""

import json
import time

import pytest
from conftest import mock_engine, mock_launched

from reveng_nexus.errors import (
    CapabilityUnavailable,
    PolicyViolation,
    ProviderCallError,
    ProviderUnavailable,
)
from reveng_nexus.registry import ProviderManager


async def started(config):
    mgr = ProviderManager(config)
    await mgr.start()
    return mgr


async def target_of(mgr, path):
    intake = await mgr.intake(str(path))
    return mgr.target_context(intake["target"]["sha256"])


async def test_stdio_lifecycle_discovery_and_health(config_factory, workspace):
    mgr = await started(config_factory(workspace, [mock_engine("eng", env={"MOCK_PAGE_SIZE": "5"})]))
    try:
        assert mgr.provider_errors == {}
        provider = mgr.providers["eng"]
        tools = {t.name: t for t in await provider.list_tools()}
        assert len(tools) == 16, "all pages of tools/list must be collected"
        assert tools["decompile_function"].decision.allowed
        assert tools["open_database"].classification.tool_class == "lifecycle"
        assert not tools["patch_bytes"].decision.allowed
        assert not tools["rename_function"].decision.allowed
        assert tools["call"].classification.tool_class == "blocked"
        health = await mgr.health()
        assert health["eng"]["status"] == "ready"
        assert health["eng"]["version"] == "MCP server mock-engine mock-a (server-reported)"
    finally:
        await mgr.close()
    assert not mgr.providers["eng"].started


async def test_catalogue_enforcement_and_metadata_only_audit(config_factory, workspace, elf_sample):
    mgr = await started(config_factory(workspace, [mock_engine("eng")]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(ProviderCallError, match="not in the provider's current catalogue"):
            await mgr.call_provider_tool("eng", "hidden_mutation_tool", {})
        with pytest.raises(PolicyViolation, match="read-only"):
            await mgr.call_provider_tool("eng", "patch_bytes", {"address": "0x400100", "hex_bytes": "90"})
        with pytest.raises(PolicyViolation, match="lifecycle"):
            await mgr.call_provider_tool("eng", "open_database", {"file_path": str(elf_sample)})
        out = await mgr.perform("binary.decompile", target, {"address": 0x400119}, provider_id="eng")
        assert "add_numbers(2,3)" in out["result"].normalized["code"]
        assert out["result"].subject_name == "main"
        audit = mgr.audit.path.read_text(encoding="utf-8")
        records = [json.loads(line) for line in audit.splitlines()]
        decompile = next(r for r in records if r.get("tool_name") == "decompile_function")
        assert decompile["argument_keys"] == ["address", "database"]
        assert any(r["event"] == "tool_call_blocked" and r["tool_name"] == "patch_bytes" for r in records)
        assert "0x400119" not in audit and "add_numbers" not in audit and str(elf_sample) not in audit
    finally:
        await mgr.close()


async def test_staged_copy_is_used_and_original_untouched(config_factory, workspace, elf_sample):
    before = sorted(p.name for p in workspace.iterdir())
    mgr = await started(config_factory(workspace, [mock_engine("eng")]))
    try:
        target = await target_of(mgr, elf_sample)
        await mgr.perform("binary.functions", target, {}, provider_id="eng")
        staged = target.work_dir / target.sha256[:16] / "eng" / "nexus_fixture.elf"
        assert staged.is_file()
    finally:
        await mgr.close()
    assert sorted(p.name for p in workspace.iterdir()) == before


async def test_timeout_is_bounded_and_other_providers_keep_working(config_factory, workspace, elf_sample):
    slow = mock_engine(
        "slow", env={"MOCK_SLOW_TOOL": "decompile_function", "MOCK_SLOW_SECONDS": "30"}, timeout_seconds=2
    )
    mgr = await started(config_factory(workspace, [slow, mock_engine("fast", engine="ida")]))
    try:
        target = await target_of(mgr, elf_sample)
        t0 = time.monotonic()
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="slow")
        assert time.monotonic() - t0 < 15
        assert info.value.details["attempts"][-1]["error"] == "provider_timeout"
        ok = await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="fast")
        assert ok["result"].provider_id == "fast"
    finally:
        await mgr.close()


async def test_handshake_is_bounded_by_startup_timeout_not_call_timeout(config_factory, workspace, elf_sample):
    """Regression (2026-10-14): the MCP ``initialize`` request inherited the per-call
    ``timeout_seconds``. Under full CPU load the 2 s timeout test's child could not answer in time and
    failed with "Request 'initialize' timed out" (10 of 10 runs), although startup_timeout_seconds allowed it.

    The ``never`` provider pins a second, older defect: abandoning a handshake with a native
    task.cancel() defeated the SDK's shielded transport shutdown and livelocked forever whenever
    startup_timeout_seconds < timeout_seconds and the server never answered."""
    late = mock_engine("late", env={"MOCK_STARTUP_DELAY": "3"}, timeout_seconds=1, startup_timeout_seconds=30)
    never = mock_engine("never", env={"MOCK_STARTUP_DELAY": "60"}, timeout_seconds=30, startup_timeout_seconds=2)
    t0 = time.monotonic()
    mgr = await started(config_factory(workspace, [late, never]))
    assert time.monotonic() - t0 < 30, "an unanswered handshake must be abandoned within a bounded time"
    try:
        assert "late" not in mgr.provider_errors, mgr.provider_errors.get("late")
        assert "no MCP handshake within 2s" in mgr.provider_errors["never"]
        target = await target_of(mgr, elf_sample)
        out = await mgr.perform("binary.functions", target, {}, provider_id="late")
        assert out["result"].normalized["total"] == 5
    finally:
        t1 = time.monotonic()
        await mgr.close()
        assert time.monotonic() - t1 < 30


async def test_crash_is_isolated_and_provider_restarts(config_factory, workspace, elf_sample):
    crashing = mock_engine("crashy", env={"MOCK_CRASH_TOOL": "get_strings"})
    mgr = await started(config_factory(workspace, [crashing, mock_engine("stable", engine="ida")]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("binary.strings", target, {}, provider_id="crashy", max_failover=0)
        ok = await mgr.perform("binary.functions", target, {}, provider_id="stable")
        assert ok["result"].normalized["total"] == 5
        # the crashed provider is reconnected on the next call (bounded restart budget)
        again = await mgr.perform("binary.functions", target, {}, provider_id="crashy")
        assert again["result"].normalized["total"] == 5
        assert mgr.providers["crashy"].describe()["restarts"] >= 1
    finally:
        await mgr.close()


async def test_provider_error_results_are_normalised(config_factory, workspace, elf_sample):
    mgr = await started(config_factory(workspace, [mock_engine("eng", env={"MOCK_ERROR_TOOL": "get_strings"})]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.strings", target, {}, provider_id="eng")
        assert "mock failure" in info.value.details["attempts"][-1]["message"]
    finally:
        await mgr.close()


async def test_missing_executable_and_unset_variables_do_not_block_others(config_factory, workspace):
    providers = [
        {"id": "ghost", "enabled": True, "command": "definitely-not-installed-nexus-tool", "adapter": "re_mcp"},
        {**mock_engine("needs_env"), "env": {"GHIDRA_INSTALL_DIR": "${NEXUS_UNSET_VARIABLE_FOR_TEST}"}},
        mock_engine("eng"),
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        assert "was not found" in mgr.provider_errors["ghost"]
        assert "NEXUS_UNSET_VARIABLE_FOR_TEST" in mgr.provider_errors["needs_env"]
        health = await mgr.health()
        assert health["eng"]["status"] == "ready" and health["ghost"]["status"] == "unavailable"
        with pytest.raises(ProviderUnavailable):
            await mgr.call_provider_tool("ghost", "list_functions", {})
    finally:
        await mgr.close()


async def test_disabled_and_dynamic_providers_are_not_started(config_factory, workspace):
    providers = [
        {**mock_engine("off"), "enabled": False},
        {**mock_engine("frida_like"), "kind": "dynamic", "adapter": "frida_mobile"},
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        assert "off" not in mgr.providers and mgr.skipped["off"] == "disabled in config"
        assert "dynamic" in mgr.skipped["frida_like"]
    finally:
        await mgr.close()


async def test_launched_http_provider_per_target(config_factory, workspace, elf_sample):
    mgr = await started(config_factory(workspace, [mock_launched("mcpy")]))
    try:
        assert mgr.provider_errors == {}
        target = await target_of(mgr, elf_sample)
        out = await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="mcpy")
        assert "add_numbers(2,3)" in out["result"].normalized["code"]
        assert "\r\n" not in out["result"].normalized["code"]
        provider = mgr.providers["mcpy"]
        assert provider.describe()["live_target_sessions"] == [target.sha256[:16]]
        tools = {t.name: t for t in await provider.list_tools()}
        assert not tools["pyghidra"].decision.allowed and tools["pyghidra"].classification.tool_class == "execute"
        assert not tools["rename"].decision.allowed
        meta = await mgr.perform("binary.metadata", target, {}, provider_id="mcpy")
        assert meta["result"].normalized["image_base"] == 0x400000
        log = provider.log_path.read_text(encoding="utf-8")
        assert "decaf_load() started" in log, "pre-readiness stdout noise is logged, not parsed"
    finally:
        await mgr.close()


async def test_launched_http_startup_error_is_reported(config_factory, workspace, elf_sample):
    mgr = await started(config_factory(workspace, [mock_launched("mcpy", fail=True)]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("binary.decompile", target, {"name": "main"}, provider_id="mcpy")
        assert "open_failed" in info.value.details["attempts"][-1]["message"]
    finally:
        await mgr.close()


def _pid_alive(pid: int) -> bool:
    import os
    import subprocess

    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


async def test_launched_server_process_tree_is_reaped(config_factory, workspace, elf_sample, tmp_path):
    import asyncio

    pid_file = tmp_path / "grandchild.pid"
    provider = mock_launched("mcpy")
    provider["args"] = [*provider["args"], "--spawn-child", str(pid_file)]
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, elf_sample)
        await mgr.perform("binary.functions", target, {}, provider_id="mcpy")
        grandchild = int(pid_file.read_text(encoding="utf-8"))
        assert _pid_alive(grandchild)
    finally:
        await mgr.close()
    for _ in range(20):
        if not _pid_alive(grandchild):
            break
        await asyncio.sleep(0.25)
    assert not _pid_alive(grandchild), "descendants of a launched server must not outlive the gateway"


async def test_child_environment_is_minimal(config_factory, workspace, monkeypatch):
    from reveng_nexus.providers.mcp import build_child_env

    monkeypatch.setenv("NEXUS_PARENT_SECRET", "do-not-leak")
    env, missing = build_child_env({"A": "1"}, [])
    assert "NEXUS_PARENT_SECRET" not in env and env["A"] == "1" and not missing
    env, _ = build_child_env({}, ["NEXUS_PARENT_SECRET"])
    assert env["NEXUS_PARENT_SECRET"] == "do-not-leak", "only explicitly inherited variables pass through"


async def test_stale_engine_database_is_rebuilt_once_with_warning(config_factory, workspace, elf_sample):
    mgr = await started(config_factory(workspace, [mock_engine("eng", env={"MOCK_STALE_PROJECT": "1"})]))
    try:
        target = await target_of(mgr, elf_sample)
        first = await mgr.perform("binary.functions", target, {}, provider_id="eng")
        assert any("rebuilt" in w for w in first["result"].warnings)
        second = await mgr.perform("binary.functions", target, {}, provider_id="eng")
        assert not any("rebuilt" in w for w in second["result"].warnings), "reported once"
    finally:
        await mgr.close()


async def test_connected_provider_without_usable_operations_is_degraded(config_factory, workspace):
    """Regression (live, 2026-10-14): re-mcp-ghidra with a missing GHIDRA_INSTALL_DIR answered MCP but
    listed only meta tools; health said 'ready' and every operation silently dropped out of routing."""
    mgr = await started(
        config_factory(workspace, [mock_engine("broken", env={"MOCK_TOOLS_SUBSET": "call,close_database"})])
    )
    try:
        health = (await mgr.health())["broken"]
        assert health["status"] == "degraded" and "none of the adapter's" in health["detail"]
        reason = mgr.capability_registry()["operations"]["binary.decompile"][0]["reason"]
        assert "backend failed to start" in reason
    finally:
        await mgr.close()


async def test_launched_http_handshake_uses_the_launch_startup_timeout(config_factory, workspace, elf_sample):
    """mcp_launched_http: the server reports ready (port open) but answers ``initialize`` after 3 s.
    The 1 s per-call timeout must not cut the handshake short; launch.startup_timeout_seconds applies."""
    provider = mock_launched("mcpy", timeout_seconds=1)
    provider["args"] = [*provider["args"], "--initialize-delay", "3"]
    mgr = await started(config_factory(workspace, [provider]))
    try:
        target = await target_of(mgr, elf_sample)
        out = await mgr.perform("binary.functions", target, {}, provider_id="mcpy")
        assert out["result"].normalized["total"] == 5
    finally:
        await mgr.close()


async def test_tool_listing_shares_one_deadline_and_the_provider_recovers(
    config_factory, workspace, elf_sample, tmp_path
):
    """A re-list is bounded by ONE deadline for all pages (16 tools, 2 per page, 0.6 s per page would
    be 4.8 s), the provider keeps serving from its last catalogue, and its process is reaped."""
    import asyncio

    pid_file = tmp_path / "child.pid"
    env = {
        "MOCK_PAGE_SIZE": "2",
        "MOCK_SLOW_LIST_AFTER": "1",
        "MOCK_SLOW_LIST_SECONDS": "0.6",
        "MOCK_PID_FILE": str(pid_file),
    }
    mgr = await started(config_factory(workspace, [mock_engine("eng", env=env, timeout_seconds=2)]))
    child = None
    try:
        assert mgr.provider_errors == {}, "the startup listing is not slowed"
        child = int(pid_file.read_text(encoding="utf-8"))
        t0 = time.monotonic()
        await mgr.refresh_tools()
        assert time.monotonic() - t0 < 4.0
        assert "tools/list did not complete within 2s" in mgr.provider_errors["eng"]
        target = await target_of(mgr, elf_sample)
        out = await mgr.perform("binary.functions", target, {}, provider_id="eng")
        assert out["result"].normalized["total"] == 5, "the last good catalogue is still in use"
        assert _pid_alive(child)
    finally:
        await mgr.close()
    for _ in range(40):
        if not _pid_alive(child):
            break
        await asyncio.sleep(0.25)
    assert not _pid_alive(child), "the child must not outlive the gateway"


async def test_connection_owner_close_is_bounded_when_cooperative_cancel_is_ignored(tmp_path):
    """The SDK's transport shutdown is shielded; if it never finishes, close() falls back to a
    native cancel instead of waiting forever."""
    import asyncio
    import contextlib

    import anyio

    from reveng_nexus.providers.mcp import _ConnectionOwner

    @contextlib.asynccontextmanager
    async def shielded_handshake(owner):
        with anyio.CancelScope(shield=True):
            await anyio.sleep(30)
        yield object()

    owner = _ConnectionOwner("stubborn", shielded_handshake, tmp_path / "owner.log")
    owner._task = asyncio.create_task(owner._run())
    await asyncio.sleep(0.1)
    t0 = time.monotonic()
    await owner.close(timeout=0.5)
    assert time.monotonic() - t0 < 3
    assert owner._task.done() and not owner.alive


async def test_connection_owner_close_abandons_a_task_that_swallows_cancellation(tmp_path):
    import asyncio
    import contextlib

    from reveng_nexus.providers.mcp import _ConnectionOwner

    release = asyncio.Event()

    @contextlib.asynccontextmanager
    async def swallowing(owner):
        while not release.is_set():
            try:
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                continue
        yield object()

    owner = _ConnectionOwner("swallower", swallowing, tmp_path / "owner.log")
    owner._task = asyncio.create_task(owner._run())
    await asyncio.sleep(0.1)
    t0 = time.monotonic()
    await owner.close(timeout=0.3)
    try:
        assert time.monotonic() - t0 < 3, "every wait in close() is bounded"
        assert not owner._task.done()
        assert "did not stop after cancellation; abandoned" in str(owner.error)
    finally:
        release.set()
        await asyncio.wait({owner._task}, timeout=5)
    assert owner._task.done()
