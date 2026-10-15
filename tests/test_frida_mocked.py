"""Deterministic mock contract tests for the frida_mobile adapter (monkeywave/frida-mobile-mcp b2da55d).

The provider is a real MCP subprocess (tests/mock_servers/mock_frida.py) that serves the 32 tools,
argument names, annotations and response envelopes of the pinned upstream, read from its source.
No Frida, frida-server, npm/npx, device or app is installed, launched or contacted, and no target
is executed. Tests that need ``policy.dynamic_analysis.enabled`` enable it only against this mock.

Several tests pin defects found while reading the upstream source (decoy ``target`` arguments, the
implicit device fallback, unmanifested tools, kind-less configs, unrecognised status envelopes and
missing detach on shutdown); they failed before the matching fixes in policy.py, config.py and the
Frida adapter.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from reveng_nexus.adapters import ADAPTERS
from reveng_nexus.errors import CapabilityUnavailable, PolicyViolation, ProviderUnavailable
from reveng_nexus.registry import ProviderManager

HERE = Path(__file__).parent
MOCK_FRIDA = str(HERE / "mock_servers" / "mock_frida.py")
sys.path.insert(0, str(HERE / "mock_servers"))
import mock_frida  # noqa: E402  (static data only: tool table; importing does not start a server)

FRIDA = ADAPTERS["frida_mobile"]
DEVICE = "emulator-5554"
APP = "com.example.nexus"


def frida_mock(
    provider_id: str = "frida",
    *,
    call_log: Path | None = None,
    pid_file: Path | None = None,
    env: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    child_env = dict(env or {})
    if call_log is not None:
        child_env["MOCK_CALL_LOG"] = str(call_log)
    if pid_file is not None:
        child_env["MOCK_PID_FILE"] = str(pid_file)
    return {
        "id": provider_id,
        "enabled": True,
        "type": "mcp_stdio",
        "adapter": "frida_mobile",
        "kind": extra.pop("kind", "dynamic"),
        "command": sys.executable,
        "args": [MOCK_FRIDA],
        "env": child_env,
        "timeout_seconds": extra.pop("timeout_seconds", 20),
        "startup_timeout_seconds": extra.pop("startup_timeout_seconds", 60),
        **extra,
    }


def dynamic_policy(allowed_tools: tuple[str, ...] = ()) -> dict[str, Any]:
    """Dynamic analysis ON - only ever used with the mock server above."""
    return {
        "dynamic_analysis": {
            "enabled": True,
            "authorized_devices": [DEVICE],
            "authorized_targets": [APP],
            "allowed_tools": list(allowed_tools),
        }
    }


def calls(log: Path) -> list[dict[str, Any]]:
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def audit_records(mgr) -> list[dict[str, Any]]:
    return [json.loads(line) for line in mgr.audit.path.read_text(encoding="utf-8").splitlines()]


async def started(config):
    mgr = ProviderManager(config)
    await mgr.start()
    return mgr


async def target_of(mgr, path):
    intake = await mgr.intake(str(path))
    return mgr.target_context(intake["target"]["sha256"])


def last_attempt(info: pytest.ExceptionInfo) -> dict[str, Any]:
    return info.value.details["attempts"][-1]


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


# -- manifest vs pinned upstream (pure unit) ----------------------------------------------------------


def test_manifest_covers_exactly_the_pinned_tool_set():
    assert len(mock_frida.UPSTREAM_TOOL_NAMES) == 32  # src/server.ts:61-81 at b2da55d
    assert set(FRIDA.manifest) == set(mock_frida.UPSTREAM_TOOL_NAMES), set(FRIDA.manifest) ^ set(
        mock_frida.UPSTREAM_TOOL_NAMES
    )
    assert FRIDA.pin.revision == "b2da55d6429438ed36e829e7478de42430cb4ef9"
    assert (FRIDA.pin.package_version, FRIDA.trust_annotations) == ("0.2.3", False)
    # Upstream annotates these readOnlyHint=true although each injects a Frida agent script into
    # the target (memory.ts:43, :186; search/detect via getOrCreateSession): never trust annotations.
    for tool in ("read_memory", "scan_memory", "search_classes_and_methods", "detect_app_technologies"):
        assert FRIDA.manifest[tool] == "dynamic", tool
    for tool in ("bypass_ssl_pinning", "execute_script", "run_prebuilt_script", "write_memory", "kill_process"):
        assert FRIDA.manifest[tool] == "blocked", tool
    # mobile_action launches `npx -y @mobilenext/mobile-mcp@latest` and can install apps; no
    # device/target argument exists to authorise it (tools/mobile.ts:40-44).
    assert FRIDA.manifest["mobile_action"] == "blocked"


@pytest.mark.parametrize("override", ["read", "dynamic", "lifecycle", "mutate"])
def test_overrides_cannot_open_unlisted_tools_on_the_pinned_adapter(config_factory, workspace, override):
    """A tool outside the pinned 32 is upstream drift; tool_overrides must not make it callable."""
    from reveng_nexus.policy import PolicyEngine

    policy = dynamic_policy(("get_keychain_items",))
    config = config_factory(workspace, [frida_mock(tool_overrides={"get_keychain_items": override})], policy=policy)
    provider = next(p for p in config.providers if p.id == "frida")
    engine = PolicyEngine(config)
    cls = engine.classify(
        provider, "get_keychain_items", manifest=FRIDA.manifest, unlisted_class=FRIDA.unlisted_tool_class
    )
    schema = {"type": "object", "properties": {"device": {"type": "string"}}, "additionalProperties": False}
    decision = engine.decide(provider, "get_keychain_items", cls, arguments={"device": DEVICE}, input_schema=schema)
    assert not decision.allowed, (cls, decision.reason)


# -- gating before the child starts ---------------------------------------------------------------


async def test_dynamic_provider_is_not_spawned_while_policy_is_off(config_factory, workspace, apk_sample, tmp_path):
    pid_file, log = tmp_path / "frida.pid", tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [frida_mock(pid_file=pid_file, call_log=log)]))
    try:
        assert "frida" not in mgr.providers
        assert mgr.skipped["frida"] == "dynamic provider; policy.dynamic_analysis.enabled is false"
        await asyncio.sleep(0.5)
        assert not pid_file.exists(), "no child process may be launched"
        with pytest.raises(ProviderUnavailable, match="dynamic_analysis.enabled is false"):
            await mgr.call_provider_tool("frida", "get_status", {})
        target = await target_of(mgr, apk_sample)
        with pytest.raises(ProviderUnavailable, match="dynamic_analysis.enabled is false"):
            await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        assert calls(log) == []
        assert not any(
            r.get("event") == "provider_started" and r.get("provider_id") == "frida" for r in audit_records(mgr)
        )
    finally:
        await mgr.close()


async def test_frida_adapter_is_gated_even_without_kind_dynamic(config_factory, workspace, tmp_path):
    pid_file = tmp_path / "frida.pid"
    provider = frida_mock(pid_file=pid_file)
    del provider["kind"]
    mgr = await started(config_factory(workspace, [provider]))
    try:
        assert "frida" not in mgr.providers and not pid_file.exists()
    finally:
        await mgr.close()


async def test_config_rejects_dynamic_policy_without_allowlists(config_factory, workspace):
    from reveng_nexus.errors import ConfigError

    with pytest.raises(ConfigError, match="authorized_devices"):
        config_factory(workspace, [frida_mock()], policy={"dynamic_analysis": {"enabled": True}})


# -- missing package / missing launcher ---------------------------------------------------------------


async def test_missing_frida_and_missing_npx_are_isolated(config_factory, workspace, elf_sample):
    providers = [
        frida_mock("frida_broken", env={"MOCK_FRIDA_MODE": "missing_frida"}, startup_timeout_seconds=20),
        {
            **frida_mock("frida_nonpx"),
            "command": "definitely-not-installed-npx",
            "args": ["-y", "frida-mobile-mcp@0.2.3"],
        },
    ]
    mgr = await started(config_factory(workspace, providers, policy=dynamic_policy()))
    try:
        assert "frida_broken" in mgr.provider_errors and "frida_broken" not in mgr.sessions
        assert "was not found" in mgr.provider_errors["frida_nonpx"]
        health = await mgr.health()
        assert health["frida_broken"]["status"] == "unavailable"
        target = await target_of(mgr, elf_sample)
        assert (await mgr.perform("binary.functions", target, {}))["result"].provider_id == "builtin"
    finally:
        await mgr.close()


# -- discovery and classification ----------------------------------------------------------------------


_EXPECTED = {
    # read: allowed once dynamic analysis is on (no target needed)
    **{t: ("read", True) for t in ("get_status", "frida_help", "list_devices", "get_device_info", "list_sessions")},
    # dynamic: listed but not callable without allowed_tools + authorised target
    **{t: ("dynamic", False) for t in ("hook_method", "trace_method", "read_memory", "spawn_process")},
    **{
        t: ("blocked", False)
        for t in (
            "bypass_ssl_pinning",
            "run_prebuilt_script",
            "execute_script",
            "write_memory",
            "kill_process",
            "hook_function",
            "unhook_function",
            "mobile_action",
        )
    },
    "frobnicate_device": ("blocked", False),  # upstream drift, MOCK_EXTRA_TOOLS (unlisted_tool_class)
}


async def test_discovery_classification_and_capabilities(config_factory, workspace):
    env = {"MOCK_EXTRA_TOOLS": "frobnicate_device"}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy()))
    try:
        assert mgr.provider_errors == {}
        provider = mgr.providers["frida"]
        tools = {t.name: t for t in await provider.list_tools()}
        assert set(tools) == set(mock_frida.UPSTREAM_TOOL_NAMES) | {"frobnicate_device"}
        for name, (tool_class, allowed) in _EXPECTED.items():
            assert tools[name].classification.tool_class == tool_class, name
            assert tools[name].decision.allowed is allowed, name
        for name in [*mock_frida.UPSTREAM_TOOL_NAMES, "frobnicate_device"]:
            assert tools[name].classification.source == "manifest", name
        assert provider.list_capabilities() == {"dynamic.status": {"available": True, "tools": ["get_status"]}}
        assert provider.server_info.get("version") == "0.1.0", "upstream hardcodes 0.1.0 (server.ts:46-49)"
        assert (provider.engine, provider.engine_family) == ("frida", "frida")
    finally:
        await mgr.close()


async def test_unmanifested_upstream_tools_are_blocked_on_a_pinned_adapter(config_factory, workspace):
    env = {"MOCK_EXTRA_TOOLS": "get_keychain_items,dump_app_secrets"}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy()))
    try:
        tools = {t.name: t for t in await mgr.providers["frida"].list_tools()}
        for name in ("get_keychain_items", "dump_app_secrets"):
            assert not tools[name].decision.allowed, name
    finally:
        await mgr.close()


# -- policy enforcement before the call reaches the server -----------------------------------------------


@pytest.mark.parametrize(
    ("tool", "arguments", "match"),
    [
        ("bypass_ssl_pinning", {"target": APP, "device": DEVICE}, "hard-blocked"),
        ("execute_script", {"target": APP, "source": "send(1)"}, "hard-blocked"),
        ("run_prebuilt_script", {"script_name": "ssl_pinning_bypass", "target": APP}, "hard-blocked"),
        ("write_memory", {"session_id": "s1", "address": "0x1000", "data": "90", "target": APP}, "hard-blocked"),
        ("kill_process", {"pid": 1234, "target": APP}, "hard-blocked"),
        ("hook_function", {"session_id": "s1", "target": APP, "on_enter": "x"}, "hard-blocked"),
        ("unhook_function", {"hook_id": "h1"}, "hard-blocked"),
        ("frobnicate_device", {"target": APP}, "hard-blocked"),
        ("mobile_action", {"action": "mobile_install_app", "params": {"path": "x.apk"}}, "hard-blocked"),
        ("hook_method", {"target": APP, "method": "a.B.c"}, "allowed_tools"),  # not allow-listed
        ("trace_method", {"target": "com.other.app", "method": "a.B.c"}, "not authorised"),
        ("trace_method", {"target": APP, "method": "a.B.c", "device": "usb-other"}, "not authorised"),
        ("trace_method", {"method": "a.B.c", "device": DEVICE}, "name an authorised target"),
        ("trace_method", {"target": APP, "method": "a.B.c"}, "name an authorised device"),
        ("get_device_info", {}, "name an authorised device"),
    ],
)
async def test_policy_blocks_before_the_server_sees_the_call(
    config_factory, workspace, tmp_path, tool, arguments, match
):
    log = tmp_path / "calls.jsonl"
    # Even allow-listing every dangerous tool must not open them.
    allowed = (
        "trace_method",
        "bypass_ssl_pinning",
        "execute_script",
        "write_memory",
        "run_prebuilt_script",
        "frobnicate_device",
        "mobile_action",
    )
    provider = frida_mock(call_log=log, env={"MOCK_EXTRA_TOOLS": "frobnicate_device"})
    mgr = await started(config_factory(workspace, [provider], policy=dynamic_policy(allowed)))
    try:
        with pytest.raises(PolicyViolation, match=match):
            await mgr.call_provider_tool("frida", tool, arguments)
        assert tool not in {c["tool"] for c in calls(log)}
        blocked = [r for r in audit_records(mgr) if r["event"] == "tool_call_blocked" and r.get("tool_name") == tool]
        assert blocked and sorted(blocked[-1]["argument_keys"]) == sorted(arguments)
        assert "send(1)" not in mgr.audit.path.read_text(encoding="utf-8"), "audit is metadata-only"
    finally:
        await mgr.close()


async def test_authorised_instrumentation_call_reaches_the_mock(config_factory, workspace, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [frida_mock(call_log=log)], policy=dynamic_policy(("trace_method",))))
    try:
        result = await mgr.call_provider_tool(
            "frida", "trace_method", {"target": APP, "method": "a.B.c", "device": DEVICE}
        )
        assert not result.is_error
        assert result.structured_content["result"]["target"] == APP
        assert calls(log)[-1] == {"tool": "trace_method", "arg_keys": ["device", "method", "target"]}
    finally:
        await mgr.close()


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("mobile_action", {"action": "mobile_install_app", "params": {"path": "x.apk"}, "target": APP}),
        ("spawn_process", {"program": "com.unauthorised.app", "target": APP}),
        ("read_memory", {"session_id": "s-of-other-app", "address": "0x1000", "size": 16, "target": APP}),
        ("select_device", {"type": "remote", "host": "203.0.113.5:27042", "target": APP}),
    ],
)
async def test_decoy_target_argument_does_not_authorise(config_factory, workspace, tmp_path, tool, arguments):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [frida_mock(call_log=log)], policy=dynamic_policy((tool,))))
    try:
        with pytest.raises(PolicyViolation):
            await mgr.call_provider_tool("frida", tool, arguments)
        assert tool not in {c["tool"] for c in calls(log)}
    finally:
        await mgr.close()


async def test_instrumentation_without_explicit_device_is_refused(config_factory, workspace, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [frida_mock(call_log=log)], policy=dynamic_policy(("trace_method",))))
    try:
        with pytest.raises(PolicyViolation):
            await mgr.call_provider_tool("frida", "trace_method", {"target": APP, "method": "a.B.c"})
        assert calls(log) == []
    finally:
        await mgr.close()


# -- normalised operation, envelope and provenance ---------------------------------------------------------


async def test_dynamic_status_keeps_envelope_and_provenance(config_factory, workspace, apk_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [frida_mock(call_log=log)], policy=dynamic_policy()))
    try:
        target = await target_of(mgr, apk_sample)
        out = await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        res = out["result"]
        assert (res.provider_id, res.tool_name, res.operation) == ("frida", "get_status", "dynamic.status")
        assert (res.engine, res.engine_family, res.evidence_kind) == ("frida", "frida", "engine_derived")
        status = res.normalized["status"]
        # structuredContent wins over the (TOON, non-JSON) text: result-builder.ts:51-54
        assert status["result"]["devices"][1]["id"] == DEVICE
        assert status["result"]["config"] == {
            "custom_scripts_enabled": False,
            "memory_write_enabled": False,
            "mobile_mcp_enabled": False,
            "max_sessions": 4,
        }
        assert not res.raw["content"][0]["text"].lstrip().startswith("{"), "default response_format is toon"
        assert res.engine_version == "MCP server frida-mobile-mcp 0.1.0 (server-reported)"
        record = mgr.evidence.get_evidence_record(out["evidence"]["evidence_id"], include_raw=True)
        assert (record["target_id"], record["provider_id"], record["tool_name"]) == (
            target.sha256,
            "frida",
            "get_status",
        )
        assert (record["engine"], record["engine_family"]) == ("frida", "frida")
        assert calls(log) == [{"tool": "get_status", "arg_keys": []}]
        assert "Nexus Disposable Emulator" not in mgr.audit.path.read_text(encoding="utf-8")
    finally:
        await mgr.close()


async def test_no_device_is_reported_not_hidden(config_factory, workspace, apk_sample):
    mgr = await started(
        config_factory(workspace, [frida_mock(env={"MOCK_FRIDA_MODE": "no_device"})], policy=dynamic_policy())
    )
    try:
        target = await target_of(mgr, apk_sample)
        status = (await mgr.perform("dynamic.status", target, {}, provider_id="frida"))["result"].normalized["status"]
        assert status["result"]["devices"] == []  # status.ts:32-36 swallows enumeration errors
        # get_device_info without a device would fall back to the host (resolver.ts:42-61) or answer
        # in-band {result: {error}} with isError unset (device.ts:95-98); Nexus refuses it first.
        with pytest.raises(PolicyViolation, match="name an authorised device"):
            await mgr.call_provider_tool("frida", "get_device_info", {})
        # unknown device: upstream isError envelope, error text only (no structuredContent)
        missing = await mgr.call_provider_tool("frida", "get_device_info", {"device_id": DEVICE})
        assert missing.is_error and missing.structured_content is None
        assert "DEVICE_NOT_FOUND" in missing.content[0].text
    finally:
        await mgr.close()


async def test_is_error_envelope_becomes_a_bounded_provider_error(config_factory, workspace, apk_sample):
    env = {"MOCK_ERROR_TOOL": "get_status"}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy()))
    try:
        target = await target_of(mgr, apk_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        attempt = last_attempt(info)
        assert attempt["outcome"] == "failed"
        assert "frida/get_status reported an error" in attempt["message"]
        assert "FRIDA_ERROR" in attempt["message"] and len(attempt["message"]) < 800
        assert mgr.evidence.query_evidence(target_id=target.sha256) == []
    finally:
        await mgr.close()


@pytest.mark.parametrize("kind", ["no_structured", "wrong_structured", "toon_only"])
async def test_unexpected_status_envelopes_are_flagged(config_factory, workspace, apk_sample, kind):
    env = {"MOCK_GARBAGE_TOOL": "get_status", "MOCK_GARBAGE_KIND": kind}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy()))
    try:
        target = await target_of(mgr, apk_sample)
        try:
            out = await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        except CapabilityUnavailable:
            return  # refusing is also acceptable
        assert out["result"].warnings, "an unrecognised envelope must be flagged"
    finally:
        await mgr.close()


_CTX = {"device": None, "platform": None, "active_sessions": [], "active_hooks": 0, "active_scripts": 0}


@pytest.mark.parametrize(
    ("payload", "accepted"),
    [
        ({"result": {}, "session_context": _CTX, "suggested_next": []}, True),
        (
            {
                "result": {},
                "session_context": {**_CTX, "device": "x (usb:emulator-5554)"},
                "suggested_next": [{"tool": "explore_app", "reason": "r"}],
            },
            True,
        ),
        ({"result": {}, "session_context": {}, "suggested_next": []}, False),  # fields missing
        ({"result": {}, "session_context": {**_CTX, "active_hooks": "0"}, "suggested_next": []}, False),
        ({"result": {}, "session_context": {**_CTX, "active_sessions": [{"id": 1}]}, "suggested_next": []}, False),
        ({"result": {}, "session_context": {**_CTX, "active_scripts": True}, "suggested_next": []}, False),
        ({"result": {}, "session_context": _CTX, "suggested_next": ["explore_app"]}, False),
        ({"result": {}, "session_context": _CTX, "suggested_next": [{"tool": 1, "reason": "r"}]}, False),
        ({"result": {}, "session_context": _CTX, "suggested_next": [], "isError": False}, False),  # extra key
        ({"result": [], "session_context": _CTX, "suggested_next": []}, False),
    ],
)
def test_status_envelope_is_validated_strictly(payload, accepted):
    from reveng_nexus.adapters.others import _frida_envelope

    assert _frida_envelope(payload) is accepted


# -- timeout, cancellation, crash and cleanup ----------------------------------------------------------


async def test_timeout_is_bounded_and_provider_stays_usable(config_factory, workspace, apk_sample):
    env = {"MOCK_SLOW_TOOL": "trace_method", "MOCK_SLOW_SECONDS": "30"}
    provider = frida_mock(env=env, timeout_seconds=2)
    mgr = await started(config_factory(workspace, [provider], policy=dynamic_policy(("trace_method",))))
    try:
        from reveng_nexus.errors import ProviderTimeout

        t0 = time.monotonic()
        with pytest.raises(ProviderTimeout):
            await mgr.call_provider_tool("frida", "trace_method", {"target": APP, "method": "a.B.c", "device": DEVICE})
        assert time.monotonic() - t0 < 15
        target = await target_of(mgr, apk_sample)
        ok = await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        assert ok["result"].provider_id == "frida"
    finally:
        await mgr.close()


async def test_cancelled_call_releases_the_provider(config_factory, workspace, apk_sample):
    env = {"MOCK_SLOW_TOOL": "trace_method", "MOCK_SLOW_SECONDS": "30"}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy(("trace_method",))))
    try:
        target = await target_of(mgr, apk_sample)
        task = asyncio.create_task(
            mgr.call_provider_tool("frida", "trace_method", {"target": APP, "method": "a.B.c", "device": DEVICE})
        )
        await asyncio.sleep(1.0)
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        ok = await asyncio.wait_for(mgr.perform("dynamic.status", target, {}, provider_id="frida"), timeout=10)
        assert ok["result"].provider_id == "frida"
    finally:
        await mgr.close()


async def test_crash_is_isolated_and_restarted(config_factory, workspace, apk_sample, tmp_path):
    env = {"MOCK_CRASH_TOOL": "trace_method"}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy(("trace_method",))))
    try:
        with pytest.raises(ProviderUnavailable, match="connection lost"):
            await mgr.call_provider_tool("frida", "trace_method", {"target": APP, "method": "a.B.c", "device": DEVICE})
        target = await target_of(mgr, apk_sample)
        ok = await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        assert ok["result"].provider_id == "frida" and mgr.providers["frida"]._restarts == 1
    finally:
        await mgr.close()


async def test_shutdown_leaves_no_orphan_process(config_factory, workspace, apk_sample, tmp_path):
    pid_file = tmp_path / "frida.pid"
    mgr = await started(config_factory(workspace, [frida_mock(pid_file=pid_file)], policy=dynamic_policy()))
    try:
        target = await target_of(mgr, apk_sample)
        await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        child = int(pid_file.read_text(encoding="utf-8"))
        assert _pid_alive(child)
    finally:
        await mgr.close()
    for _ in range(40):
        if not _pid_alive(child):
            break
        await asyncio.sleep(0.25)
    assert not _pid_alive(child), "the Frida MCP child must not outlive the gateway"
    assert not mgr.providers["frida"].started


async def test_shutdown_detaches_instrumentation_first(config_factory, workspace, apk_sample, tmp_path):
    log = tmp_path / "calls.jsonl"
    mgr = await started(config_factory(workspace, [frida_mock(call_log=log)], policy=dynamic_policy()))
    try:
        target = await target_of(mgr, apk_sample)
        await mgr.perform("dynamic.status", target, {}, provider_id="frida")
    finally:
        await mgr.close()
    assert calls(log)[-1]["tool"] == "stop_instrumentation"


async def test_callers_cannot_invoke_stop_instrumentation(config_factory, workspace, tmp_path):
    log = tmp_path / "calls.jsonl"
    for extra in ({}, {"tool_overrides": {"stop_instrumentation": "read"}}):
        provider = frida_mock(call_log=log, **extra)
        mgr = await started(config_factory(workspace, [provider], policy=dynamic_policy(("stop_instrumentation",))))
        try:
            with pytest.raises(PolicyViolation):
                await mgr.call_provider_tool("frida", "stop_instrumentation", {"all": True, "target": APP})
        finally:
            await mgr.close()
        # only the gateway's own shutdown call may appear, never the caller's
        assert all(c["arg_keys"] == ["all"] for c in calls(log) if c["tool"] == "stop_instrumentation")


async def test_in_band_status_error_is_raised(config_factory, workspace, apk_sample):
    env = {"MOCK_GARBAGE_TOOL": "get_status", "MOCK_GARBAGE_KIND": "inband_error"}
    mgr = await started(config_factory(workspace, [frida_mock(env=env)], policy=dynamic_policy()))
    try:
        target = await target_of(mgr, apk_sample)
        with pytest.raises(CapabilityUnavailable) as info:
            await mgr.perform("dynamic.status", target, {}, provider_id="frida")
        assert "mock in-band failure" in last_attempt(info)["message"]
    finally:
        await mgr.close()


async def test_shutdown_after_crash_does_not_relaunch_the_child(config_factory, workspace, tmp_path):
    log, pid_file = tmp_path / "calls.jsonl", tmp_path / "frida.pid"
    env = {"MOCK_CRASH_TOOL": "trace_method"}
    provider = frida_mock(call_log=log, pid_file=pid_file, env=env)
    mgr = await started(config_factory(workspace, [provider], policy=dynamic_policy(("trace_method",))))
    first = pid_file.read_text()
    try:
        with pytest.raises(Exception):  # noqa: B017 - the child exits mid-call
            await mgr.call_provider_tool("frida", "trace_method", {"target": APP, "method": "a.B.c", "device": DEVICE})
        restarts = mgr.providers["frida"]._restarts
    finally:
        await mgr.close()
    assert pid_file.read_text() == first, "shutdown must not relaunch a dead child"
    assert mgr.providers["frida"]._restarts == restarts
    assert "stop_instrumentation" not in [c["tool"] for c in calls(log)]


async def test_shutdown_with_hung_stop_instrumentation_is_bounded(config_factory, workspace, tmp_path):
    pid_file = tmp_path / "frida.pid"
    env = {"MOCK_SLOW_TOOL": "stop_instrumentation", "MOCK_SLOW_SECONDS": "120"}
    mgr = await started(config_factory(workspace, [frida_mock(pid_file=pid_file, env=env)], policy=dynamic_policy()))
    child = int(pid_file.read_text())
    t0 = time.monotonic()
    await mgr.close()
    assert time.monotonic() - t0 < 30
    for _ in range(40):
        if not _pid_alive(child):
            break
        await asyncio.sleep(0.25)
    assert not _pid_alive(child)
