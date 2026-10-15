"""Mock contract tests for the rea adapter (npm rea-agents 6.5.0, morluto/rea 3b79af28).

The provider is a real MCP subprocess (tests/mock_servers/mock_rea.py) serving the pinned
catalogue (207 names, captured from the real server on 2026-10-15) and REA's Evidence envelope.
No Node, REA or analysed code is run. The real server is exercised separately by
tests/integration/test_rea_live.py (opt-in).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from reveng_nexus.adapters import ADAPTERS
from reveng_nexus.adapters.rea import CATALOGUE_SHA256, CATALOGUE_SIZE
from reveng_nexus.errors import CapabilityUnavailable, PolicyViolation, ProviderTimeout
from reveng_nexus.registry import ProviderManager

HERE = Path(__file__).parent
MOCK_REA = str(HERE / "mock_servers" / "mock_rea.py")
sys.path.insert(0, str(HERE / "mock_servers"))
import mock_rea  # noqa: E402  (static data only: importing does not start a server)
from fixtures.electron_builder import write_asar, write_fuse_elf  # noqa: E402

REA = ADAPTERS["rea"]


def rea_mock(provider_id: str = "rea", *, env: dict[str, str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "id": provider_id,
        "enabled": extra.pop("enabled", True),
        "type": "mcp_stdio",
        "adapter": "rea",
        "command": sys.executable,
        "args": [MOCK_REA],
        "env": dict(env or {}),
        "capabilities": ["js.application", "electron.fuses"],
        "timeout_seconds": extra.pop("timeout_seconds", 20),
        "startup_timeout_seconds": 60,
        **extra,
    }


def calls(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.is_file() else []


async def started(config):
    mgr = ProviderManager(config)
    await mgr.start()
    return mgr


async def target_of(mgr, path):
    intake = await mgr.intake(str(path))
    return mgr.target_context(intake["target"]["sha256"])


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


@pytest.fixture
def asar_sample(workspace: Path) -> Path:
    return write_asar(workspace / "nexus_fixture_app.asar")


@pytest.fixture
def fuse_sample(workspace: Path) -> Path:
    return write_fuse_elf(workspace / "nexus_fuse_fixture.elf")


# -- pin, manifest and classification (pure unit) ---------------------------------------------------


def test_pin_and_static_allowlist():
    assert REA.pin.revision == "3b79af28e80785afce9f5998d8f03289402a1847"
    assert REA.pin.package_version == "6.5.0"
    assert REA.manifest == {"analyze_javascript_application": "read", "inspect_electron_fuses": "read"}
    assert (REA.unlisted_tool_class, REA.adapter_only, REA.trust_annotations) == ("blocked", True, False)
    assert (REA.engine, REA.engine_family) == ("rea", "rea")
    names = mock_rea.NAMES
    assert len(names) == CATALOGUE_SIZE == 207
    assert hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() == CATALOGUE_SHA256


@pytest.mark.parametrize(
    "tool",
    ["capture_process_scenario", "gdb_console", "instrument_with_frida", "push_adb_file", "extract_artifact",
     "open_binary", "procedure_pseudo_code", "set_comment", "export_evidence_bundle", "capture_web_screenshot",
     "a_future_tool_not_in_the_pin"],
)  # fmt: skip
def test_overrides_cannot_reopen_unlisted_rea_tools(tool):
    from reveng_nexus.config import NexusConfig, PolicyConfig, ProviderConfig
    from reveng_nexus.policy import PolicyEngine

    engine = PolicyEngine(NexusConfig(providers=(), policy=PolicyConfig(read_only=False), read_only=False))
    provider = ProviderConfig(id="rea", name="rea", command="x", adapter="rea", tool_overrides={tool: "read"})
    cls = engine.classify(provider, tool, manifest=REA.manifest, unlisted_class=REA.unlisted_tool_class)
    assert cls.tool_class == "blocked"
    assert not engine.decide(provider, tool, cls).allowed


def test_path_scrub_replaces_only_the_local_paths_nexus_passed():
    from reveng_nexus.adapters.rea import WORK_TOKEN, _local_path_pattern, _scrub

    def win(*parts: str) -> str:
        return "\\".join(parts)

    staged = win("C:", "work", "abc", "rea", "app.asar")
    matcher = _local_path_pattern(
        {staged: "app.asar", win("C:", "samples", "app.asar"): "app.asar", win("C:", "work"): WORK_TOKEN}
    )
    value = {
        "input_path": staged,
        "nested": [win("c:", "WORK", "abc", "rea", "inner.js"), win("C:", "samples", "app.asar")],
        "message": f"failed to read {staged}: EACCES",
        "slashed": staged.replace("\\", "/"),
        "url": "file:///" + staged.replace("\\", "/"),
        staged: "used as a key",
        "lookalike": win("C:", "work", "abc", "rea", "app.asarx"),
        "channel": "/api/x",
        "module": win("", "", "server", "share", "lib.js"),
        "other_drive": win("D:", "data", "x.js"),
        "json_text": json.dumps({"input_path": staged}),  # a path inside a JSON-encoded string
    }
    out = _scrub(value, matcher)
    assert out["input_path"] == "app.asar"
    assert out["nested"] == [win(WORK_TOKEN, "abc", "rea", "inner.js"), "app.asar"]
    assert out["message"] == "failed to read app.asar: EACCES"
    assert out["slashed"] == "app.asar" and out["url"] == "app.asar" and out["app.asar"] == "used as a key"
    # a different file next to the staged copy keeps its name; the work dir itself is hidden
    assert out["lookalike"] == win(WORK_TOKEN, "abc", "rea", "app.asarx")
    # target-derived strings that only look like paths are kept verbatim
    assert (
        out["channel"] == "/api/x" and out["module"] == value["module"] and out["other_drive"] == value["other_drive"]
    )
    assert json.loads(out["json_text"]) == {"input_path": "app.asar"}
    # a work directory with a space, echoed as a percent-encoded file URL
    spaced = win("C:", "work dir", "abc", "rea", "app.asar")
    spaced_matcher = _local_path_pattern({spaced: "app.asar", win("C:", "work dir"): WORK_TOKEN})
    assert _scrub("file:///C:/work%20dir/abc/rea/app.asar", spaced_matcher) == "app.asar"
    assert _scrub("file:///c:/WORK%20DIR/abc/rea/x.js", spaced_matcher) == WORK_TOKEN + "/abc/rea/x.js"


# -- catalogue, exposure and passthrough -------------------------------------------------------------


async def test_only_the_two_allowlisted_tools_are_allowed(config_factory, workspace):
    mgr = await started(config_factory(workspace, [rea_mock()]))
    try:
        tools = {t.name: t for t in await mgr.providers["rea"].list_tools()}
        assert len(tools) == 207
        allowed = sorted(n for n, t in tools.items() if t.decision.allowed)
        assert allowed == ["analyze_javascript_application", "inspect_electron_fuses"]
        assert all(t.classification.tool_class == "blocked" for n, t in tools.items() if n not in allowed)
        caps = mgr.providers["rea"].list_capabilities()
        assert caps["js.application"]["available"] and caps["electron.fuses"]["available"]
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("inspect_electron_fuses", {"path": "C:\\Windows\\System32\\notepad.exe"}),
        ("analyze_javascript_application", {"input_path": "C:\\outside\\app.asar"}),
        ("capture_process_scenario", {}),
    ],
)
async def test_raw_passthrough_is_refused_before_the_server(config_factory, workspace, tmp_path, tool, arguments):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [rea_mock(env={"MOCK_CALL_LOG": str(log)})]))
    try:
        with pytest.raises(PolicyViolation, match="adapter-only|blocked"):
            await mgr.call_provider_tool("rea", tool, arguments)
        assert calls(log) == []
        blocked = [
            json.loads(line)
            for line in mgr.audit.path.read_text(encoding="utf-8").splitlines()
            if '"tool_call_blocked"' in line
        ]
        assert blocked and blocked[-1]["tool_name"] == tool
        assert "C:\\" not in json.dumps(blocked[-1])  # argument values never reach the audit log
    finally:
        await mgr.close()


async def test_rea_tools_are_not_exposed_as_namespaced_tools(config_factory, workspace):
    from reveng_nexus.server import NexusServer

    config = config_factory(workspace, [rea_mock()], tool_mode="namespaced")
    mgr = await started(config)
    try:
        server = NexusServer(mgr)
        listed = await server.list_tools()
        names = [t.name for t in getattr(listed, "tools", listed)]
        assert not any(n.startswith("rea") for n in names)
        assert "nexus_analyze_javascript_app" in names and "nexus_get_electron_fuses" in names
    finally:
        await mgr.close()


# -- normalised operations, provenance and evidence ------------------------------------------------------


async def test_js_application_is_normalised_with_provenance(config_factory, workspace, asar_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [rea_mock(env={"MOCK_CALL_LOG": str(log)})]))
    try:
        before = asar_sample.read_bytes()
        target = await target_of(mgr, asar_sample)
        out = await mgr.perform("js.application", target, {}, provider_id="rea")
        res = out["result"]
        assert (res.provider_id, res.tool_name, res.operation) == (
            "rea",
            "analyze_javascript_application",
            "js.application",
        )
        assert (res.engine, res.engine_family, res.evidence_kind) == ("rea", "rea", "engine_derived")
        assert res.engine_version == "rea-agents 6.5.0 (server-reported)"
        assert res.subject_name == "nexus_fixture_app.asar"
        n = res.normalized
        assert n["rea_evidence_id"].startswith("ev_") and n["rea_parent_evidence_id"].startswith("ev_")
        assert n["format"] == "asar" and n["statistics"]["parsed_javascript_files"] == 2
        assert any("inert text" in x for x in n["limitations"])
        assert str(workspace) not in json.dumps(n) and ":\\" not in json.dumps(n)  # no local paths
        # REA got the hash-verified staged copy, never the original, with bounded parameters
        call = calls(log)[-1]
        assert call["path_is_absolute"] and Path(call["path"]).resolve() != asar_sample.resolve()
        assert call["arg_keys"] == ["analysis_timeout_ms", "detail", "format", "input_path", "integrity_policy"]
        # evidence: target hash, provider, tool, raw output retained
        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["provider_id"] == "rea" and record["tool_name"] == "analyze_javascript_application"
        assert record["target_id"] == target.sha256
        assert (record["engine_family"], record["engine_version"]) == ("rea", "rea-agents 6.5.0 (server-reported)")
        assert out["evidence"]["raw_sha256"] and "structured_content" in json.dumps(record)
        assert asar_sample.read_bytes() == before
    finally:
        await mgr.close()


async def test_electron_fuses_are_normalised(config_factory, workspace, fuse_sample):
    mgr = await started(config_factory(workspace, [rea_mock()]))
    try:
        target = await target_of(mgr, fuse_sample)
        res = (await mgr.perform("electron.fuses", target, {}, provider_id="rea"))["result"]
        fuses = {f["name"]: f["state"] for f in res.normalized["fuses"]}
        assert fuses["RunAsNode"] == "disabled" and fuses["EnableCookieEncryption"] == "enabled"
        assert len(fuses) == 8 and res.normalized["runtime_implications"] and res.warnings == []
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("env", "match"),
    [
        ({"MOCK_REA_DIGEST": "wrong"}, "different file"),
        ({"MOCK_REA_DIGEST": "upper"}, "different file"),  # REA's digestSchema is lowercase hex: fail closed
        ({"MOCK_REA_DIGEST": "missing"}, "different file"),  # no sha256 (another algorithm only)
        ({"MOCK_REA_DIGEST": "nondict"}, "different file"),
        ({"MOCK_ERROR_TOOL": "inspect_electron_fuses"}, "mock REA failure"),
        ({"MOCK_GARBAGE_TOOL": "inspect_electron_fuses"}, "Evidence record"),
        ({"MOCK_MALFORMED_TOOL": "inspect_electron_fuses"}, "malformed"),
    ],
)
async def test_bad_answers_are_bounded_errors_without_evidence(config_factory, workspace, fuse_sample, env, match):
    mgr = await started(config_factory(workspace, [rea_mock(env=env)]))
    try:
        target = await target_of(mgr, fuse_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("electron.fuses", target, {}, provider_id="rea")
        attempt = info.value.details["attempts"][-1]
        assert attempt["outcome"] == "failed" and match in attempt["message"] and len(attempt["message"]) < 1000
        assert mgr.evidence.list_evidence(limit=10) == [] or all(
            e["provider_id"] != "rea" for e in mgr.evidence.list_evidence(limit=10)
        )
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    "env",
    [{"MOCK_EXTRA_TOOL": "1"}, {"MOCK_SERVER_VERSION": "6.6.0"}],
    ids=["catalogue", "version"],
)
async def test_upstream_drift_disables_both_operations(config_factory, workspace, fuse_sample, tmp_path, env):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [rea_mock(env={**env, "MOCK_CALL_LOG": str(log)})]))
    try:
        rea = mgr.providers["rea"]
        caps = rea.list_capabilities()
        assert not caps["js.application"]["available"] and not caps["electron.fuses"]["available"]
        assert "differs from the pin" in caps["electron.fuses"]["reason"]
        assert (await rea.health_check()).status != "ready"
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("electron.fuses", await target_of(mgr, fuse_sample), {}, provider_id="rea")
        assert calls(log) == []  # nothing reached the drifted server
    finally:
        await mgr.close()


# -- timeout, crash, cleanup, disable --------------------------------------------------------------------


async def test_timeout_is_bounded_and_the_provider_recovers(config_factory, workspace, fuse_sample, asar_sample):
    env = {"MOCK_SLOW_TOOL": "analyze_javascript_application", "MOCK_SLOW_SECONDS": "30"}
    mgr = await started(config_factory(workspace, [rea_mock(env=env, timeout_seconds=12)]))
    try:
        slow = await target_of(mgr, asar_sample)
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("js.application", slow, {}, provider_id="rea")
        assert loop.time() - t0 < 25
        assert "did not answer" in info.value.details["attempts"][-1]["message"]
        fast = await target_of(mgr, fuse_sample)
        assert (await mgr.perform("electron.fuses", fast, {}, provider_id="rea"))["result"].normalized["fuses"]
    finally:
        await mgr.close()
    assert ProviderTimeout  # imported for the error type named in the message


async def test_crash_is_reported_and_the_next_call_reconnects(config_factory, workspace, fuse_sample, asar_sample):
    mgr = await started(
        config_factory(workspace, [rea_mock(env={"MOCK_CRASH_TOOL": "analyze_javascript_application"})])
    )
    try:
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("js.application", await target_of(mgr, asar_sample), {}, provider_id="rea")
        res = (await mgr.perform("electron.fuses", await target_of(mgr, fuse_sample), {}, provider_id="rea"))["result"]
        assert res.normalized["fuses"]
    finally:
        await mgr.close()


async def test_shutdown_reaps_the_whole_process_tree(config_factory, workspace, tmp_path):
    pid_file, grandchild_file = tmp_path / "rea.pid", tmp_path / "worker.pid"
    env = {"MOCK_PID_FILE": str(pid_file), "MOCK_GRANDCHILD_PID_FILE": str(grandchild_file)}
    mgr = await started(config_factory(workspace, [rea_mock(env=env)]))
    try:
        for _ in range(40):
            if grandchild_file.is_file():
                break
            await asyncio.sleep(0.25)
        child, grandchild = int(pid_file.read_text()), int(grandchild_file.read_text())
        assert _pid_alive(child) and _pid_alive(grandchild)
    finally:
        await mgr.close()
    for _ in range(40):
        if not _pid_alive(child) and not _pid_alive(grandchild):
            break
        await asyncio.sleep(0.25)
    assert not _pid_alive(child), "the REA child must not outlive the gateway"
    assert not _pid_alive(grandchild), "REA's worker processes must not outlive the gateway"


async def test_disabled_rea_leaves_other_operations_working(config_factory, workspace, elf_sample, asar_sample):
    mgr = await started(config_factory(workspace, [rea_mock(enabled=False)]))
    try:
        assert "rea" not in mgr.providers and "disabled" in mgr.skipped["rea"]
        meta = await mgr.perform("binary.metadata", await target_of(mgr, elf_sample), {}, provider_id="builtin")
        assert meta["result"].normalized
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("js.application", await target_of(mgr, asar_sample), {})
    finally:
        await mgr.close()


async def test_list_tools_marks_rea_tools_not_callable(config_factory, workspace):
    mgr = await started(config_factory(workspace, [rea_mock()]))
    try:
        rea = mgr.providers["rea"]
        infos = {t.name: t for t in await rea.list_tools()}
        allowed = infos["inspect_electron_fuses"]
        assert allowed.decision.allowed and not allowed.callable  # usable by the adapter only
        assert allowed.to_dict()["callable"] is False and "adapter-only" in allowed.to_dict()["policy_reason"]
        assert rea.describe()["callable_tool_count"] == 0
        assert rea.list_capabilities()["electron.fuses"]["available"]
    finally:
        await mgr.close()
