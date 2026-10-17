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


def test_pin_and_catalogue_classification():
    from reveng_nexus.adapters.rea_catalogue import ANALYSES, CATALOGUE, ENABLED_TOOLS, LIVE_VERIFIED

    assert REA.pin.revision == "3b79af28e80785afce9f5998d8f03289402a1847"
    assert REA.pin.package_version == "6.5.0"
    assert (REA.unlisted_tool_class, REA.adapter_only, REA.trust_annotations) == ("blocked", True, False)
    assert (REA.engine, REA.engine_family) == ("rea", "rea")
    names = mock_rea.NAMES
    assert len(names) == CATALOGUE_SIZE == 207
    assert hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() == CATALOGUE_SHA256
    # every pinned tool is classified exactly once, and nothing outside the pin is
    assert sorted(CATALOGUE) == sorted(names) and REA.manifest == {n: CATALOGUE[n].tool_class for n in names}
    classes = {
        c: sum(1 for t in CATALOGUE.values() if t.tool_class == c)
        for c in ("read", "mutate", "lifecycle", "execute", "dynamic")
    }
    assert classes == {"read": 125, "mutate": 16, "lifecycle": 8, "execute": 15, "dynamic": 43}
    # only file-scoped reads can be enabled: Nexus confines them to the staged copy
    for tool in ENABLED_TOOLS:
        assert (CATALOGUE[tool].tool_class, CATALOGUE[tool].scope) == ("read", "file"), tool
    assert set(LIVE_VERIFIED) == {t for t, p in ENABLED_TOOLS.items() if p == "restricted"}
    assert len(ENABLED_TOOLS) == 10 and all(a.verification == "source_reviewed" for a in ANALYSES.values())
    # REA's effect audit marks these as running foreign code: never anything but execute
    for tool in ("gdb_console", "cutter_command", "capture_process_scenario", "instrument_with_frida"):
        assert CATALOGUE[tool].tool_class == "execute"


def test_enabled_analyses_match_the_pinned_input_schemas():
    """Each analysis sends only argument names the pinned REA schema declares, and never a path option."""
    from reveng_nexus.adapters.rea_catalogue import ANALYSES

    for spec in ANALYSES.values():
        upstream = mock_rea.ANALYSIS_SCHEMAS[spec.tool]["properties"]
        assert spec.path_argument in upstream
        for option in (*spec.options, *spec.fixed):
            assert option in upstream, (spec.tool, option)
            assert "path" not in option, (spec.tool, option)
        # upstream path-taking extras (glue_paths, candidate_paths) are never forwarded
        assert not any("path" in o for o in spec.options)


@pytest.mark.parametrize(
    ("tool", "pinned_class"),
    [("capture_process_scenario", "execute"), ("gdb_console", "execute"), ("instrument_with_frida", "execute"),
     ("push_adb_file", "dynamic"), ("capture_web_screenshot", "dynamic"), ("open_binary", "lifecycle"),
     ("a_future_tool_not_in_the_pin", "blocked")],
)  # fmt: skip
def test_overrides_cannot_relax_gated_rea_tools(tool, pinned_class):
    from reveng_nexus.config import NexusConfig, PolicyConfig, ProviderConfig
    from reveng_nexus.policy import PolicyEngine

    engine = PolicyEngine(
        NexusConfig(providers=(), policy=PolicyConfig(access_profile="full_access", read_only=False), read_only=False)
    )
    provider = ProviderConfig(id="rea", name="rea", command="x", adapter="rea", tool_overrides={tool: "read"})
    cls = engine.classify(provider, tool, manifest=REA.manifest, unlisted_class=REA.unlisted_tool_class)
    assert cls.tool_class == pinned_class
    assert not engine.decide(provider, tool, cls).allowed


async def test_overrides_cannot_enable_unreviewed_rea_tools(config_factory, workspace, tmp_path):
    """A mutate or session read reclassified as read by an operator stays unreachable: the adapter gate
    is a reviewed allowlist by tool name, not by class, and it refuses even the adapter's own calls."""
    log = tmp_path / "calls.jsonl"
    overrides = {"set_comment": "read", "procedure_pseudo_code": "read", "extract_artifact": "read"}
    provider = rea_mock(env={"MOCK_CALL_LOG": str(log)}, tool_overrides=overrides)
    mgr = await started(config_factory(workspace, [provider], policy={"access_profile": "full_access"}))
    try:
        from reveng_nexus.access import provider_tool_access

        rea = mgr.providers["rea"]
        access = provider_tool_access(mgr, rea)
        for tool in overrides:
            assert access[tool].state == "blocked_by_policy" and not access[tool].available
            with pytest.raises(PolicyViolation, match="not enabled in Nexus"):
                await rea.call_tool(tool, {}, internal=True)
        assert calls(log) == []
    finally:
        await mgr.close()


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


@pytest.mark.parametrize(
    ("profile", "env", "available"),
    [
        ("restricted", {}, {"analyze_javascript_application", "inspect_electron_fuses"}),
        ("balanced", {}, "all_but_wasm"),
        ("balanced", {"REA_WABT_BIN_DIRECTORY": "/opt/wabt/bin"}, "all"),
        ("full_access", {"REA_WABT_BIN_DIRECTORY": "/opt/wabt/bin"}, "all"),
    ],
)
async def test_enabled_rea_tools_follow_the_access_profile(config_factory, workspace, profile, env, available):
    from reveng_nexus.access import provider_tool_access
    from reveng_nexus.adapters.rea_catalogue import ENABLED_TOOLS, LIVE_VERIFIED

    mgr = await started(config_factory(workspace, [rea_mock(env=env)], policy={"access_profile": profile}))
    try:
        access = provider_tool_access(mgr, mgr.providers["rea"])
        assert len(access) == 207
        expected = (
            set(ENABLED_TOOLS)
            if available == "all"
            else set(ENABLED_TOOLS) - {"inspect_wasm_artifact"}
            if available == "all_but_wasm"
            else available
        )
        assert {n for n, a in access.items() if a.available} == expected
        assert all(a.state == "adapter_only" for n, a in access.items() if n in expected)
        assert not any(a.callable or a.exposed for a in access.values())  # adapter-only in every profile
        if profile == "restricted":
            assert access["inspect_go_binary"].state == "blocked_by_profile"
            go = access["inspect_go_binary"]
            assert not go.policy_allowed and not go.profile_allowed  # a wider profile would allow it
        if available == "all_but_wasm":
            wasm = access["inspect_wasm_artifact"]
            assert wasm.state == "missing_prerequisite" and "REA_WABT_BIN_DIRECTORY" in wasm.reason
        # never reachable, whatever the profile, and never reported as if a wider profile would help
        for tool in ("gdb_console", "open_binary", "set_comment", "list_adb_devices", "procedure_pseudo_code"):
            assert not access[tool].available
            assert access[tool].state == "blocked_by_policy" and access[tool].profile_allowed, tool
        profile_blocked = {n for n, a in access.items() if a.state == "blocked_by_profile"}
        assert profile_blocked == (set(ENABLED_TOOLS) - set(LIVE_VERIFIED) if profile == "restricted" else set())
        caps = mgr.providers["rea"].list_capabilities()
        assert caps["js.application"]["available"] and caps["electron.fuses"]["available"]
        assert caps["artifact.inspect"]["available"] == (profile != "restricted")
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("analysis", "options", "sample"),
    [
        ("go_binary", {}, "elf"),
        ("rust_binary", {}, "elf"),
        ("pe_resources", {"max_entries": 64}, "pe"),
        ("managed_artifact", {"detail": "summary"}, "pe"),
        ("managed_members", {"type_names": ["Nexus.Fixture"]}, "pe"),
        ("managed_native_boundaries", {}, "pe"),
        ("sqlite_database", {"table": "t", "row_limit": 5}, "elf"),
        ("wasm_artifact", {"detail": "summary"}, "elf"),
    ],
)
async def test_inspect_artifact_sends_only_the_staged_copy(
    config_factory, workspace, elf_sample, pe_sample, tmp_path, analysis, options, sample
):
    log = tmp_path / "calls.jsonl"
    env = {"MOCK_CALL_LOG": str(log), "REA_WABT_BIN_DIRECTORY": "/opt/wabt/bin"}
    mgr = await started(config_factory(workspace, [rea_mock(env=env)]))
    try:
        path = elf_sample if sample == "elf" else pe_sample
        before = path.read_bytes()
        target = await target_of(mgr, path)
        out = await mgr.perform(
            "artifact.inspect", target, {"analysis": analysis, "options": options}, provider_id="rea"
        )
        res = out["result"]
        assert (res.operation, res.provider_id, res.engine_family) == ("artifact.inspect", "rea", "rea")
        assert res.normalized["analysis"] == analysis and res.normalized["verification"] == "source_reviewed"
        assert any("not been verified live" in w for w in res.warnings)
        call = calls(log)[-1]
        assert call["path_is_absolute"] and Path(call["path"]).resolve() != path.resolve()
        assert call["arg_keys"] == sorted({"path", *options})
        assert str(workspace) not in json.dumps(res.normalized)
        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert record["target_id"] == target.sha256 and record["operation"] == "artifact.inspect"
        assert path.read_bytes() == before
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("analysis", "options", "match"),
    [
        ("wasm_artifact", {"glue_paths": ["/etc/passwd"]}, "invalid options"),
        ("sqlite_database", {"path": "/etc/passwd"}, "invalid options"),
        ("pe_resources", {"max_entries": 0}, "invalid options"),
        ("procedure_pseudo_code", {}, "unknown analysis"),
    ],
)
async def test_inspect_artifact_refuses_paths_and_unknown_analyses(
    config_factory, workspace, elf_sample, tmp_path, analysis, options, match
):
    from reveng_nexus.errors import ArgumentError

    log = tmp_path / "calls.jsonl"
    env = {"MOCK_CALL_LOG": str(log), "REA_WABT_BIN_DIRECTORY": "/opt/wabt/bin"}
    mgr = await started(config_factory(workspace, [rea_mock(env=env)]))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(ArgumentError, match=match):
            await mgr.perform("artifact.inspect", target, {"analysis": analysis, "options": options}, provider_id="rea")
        assert calls(log) == []
    finally:
        await mgr.close()


async def test_restricted_profile_keeps_inspect_artifact_unavailable(config_factory, workspace, elf_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    provider = rea_mock(env={"MOCK_CALL_LOG": str(log)})
    mgr = await started(config_factory(workspace, [provider], policy={"access_profile": "restricted"}))
    try:
        target = await target_of(mgr, elf_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("artifact.inspect", target, {"analysis": "go_binary"}, provider_id="rea")
        assert "access_profile balanced" in json.dumps(info.value.to_dict())
        assert calls(log) == []
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
        assert (
            not caps["artifact.inspect"]["available"] and "differs from the pin" in caps["artifact.inspect"]["reason"]
        )
        assert (await rea.health_check()).status != "ready"
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform("electron.fuses", await target_of(mgr, fuse_sample), {}, provider_id="rea")
        with pytest.raises(CapabilityUnavailable):
            await mgr.perform(
                "artifact.inspect", await target_of(mgr, fuse_sample), {"analysis": "go_binary"}, provider_id="rea"
            )
        with pytest.raises(PolicyViolation, match="differs from the pin"):
            await rea.call_tool("inspect_electron_fuses", {"path": "x"}, internal=True)
        from reveng_nexus.access import provider_access, provider_tool_access

        assert {a.state for a in provider_tool_access(mgr, rea).values()} == {"catalogue_mismatch"}
        assert provider_access(mgr, "rea")["state"] == "catalogue_mismatch"
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


async def test_upstream_read_only_hints_never_classify_or_enable_rea_tools(config_factory, workspace):
    """Six REA tools declare readOnlyHint: true at the pin (gdb_session_status among them, a
    debugger-session tool). The hint must not change their class or make them reachable."""
    from reveng_nexus.access import provider_tool_access
    from reveng_nexus.adapters.rea_catalogue import CATALOGUE

    mgr = await started(config_factory(workspace, [rea_mock()], policy={"access_profile": "full_access"}))
    try:
        rea = mgr.providers["rea"]
        access = provider_tool_access(mgr, rea)
        hinted = {n for n, t in rea._tools.items() if t.annotations.get("readOnlyHint") is True}
        assert hinted == set(mock_rea.READ_ONLY_HINTED)
        for name in hinted:
            info = rea._tools[name]
            assert info.classification.source == "manifest", name  # never "annotations"
            assert info.classification.tool_class == CATALOGUE[name].tool_class, name
            assert not access[name].available and not access[name].callable, name
        assert rea._tools["gdb_session_status"].classification.tool_class == "dynamic"
    finally:
        await mgr.close()
