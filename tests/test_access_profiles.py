"""Access profiles (restricted / balanced / full_access) across config, policy, exposure and MCP.

Covers: profile validation and precedence against explicit policy keys (old configs keep their
meaning), unknown-key handling, the profile x class x classification-source decision matrix, the
hard protection-bypass block, agreement between every surface that reports access (MCP tools/list,
namespaced dispatch, nexus_list_tools, provider summaries, describe(), the dashboard snapshot, the
CLI) and actual invocation, hidden tools, namespaced name collisions, and a real stdio MCP session
against `reveng-nexus serve`. No target is ever executed; engines are the mock MCP servers.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import MOCK_ENGINE, mock_engine
from test_rea_mocked import rea_mock

from reveng_nexus.access import (
    TOOL_STATES,
    count_states,
    exposure_map,
    provider_access,
    provider_tool_access,
    public_names,
)
from reveng_nexus.config import DynamicPolicy, NexusConfig, PolicyConfig, ProviderConfig, parse_config
from reveng_nexus.errors import ConfigError, NotFound, PolicyViolation
from reveng_nexus.policy import PolicyEngine, ToolClassification
from reveng_nexus.registry import ProviderManager
from reveng_nexus.server import TOOL_SPECS, NexusServer
from reveng_nexus.snapshot import build_snapshot

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("restricted", "balanced", "full_access")


async def started(config):
    mgr = ProviderManager(config)
    await mgr.start()
    return mgr


# -- configuration: names, precedence, unknown keys --------------------------------------------------------


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ({}, ("balanced", "default", True)),
        ({"read_only": True}, ("balanced", "inferred", True)),
        ({"read_only": False}, ("full_access", "inferred", False)),
        ({"access_profile": "restricted"}, ("restricted", "explicit", True)),
        ({"access_profile": "balanced"}, ("balanced", "explicit", True)),
        ({"access_profile": "full_access"}, ("full_access", "explicit", False)),
        ({"access_profile": "full_access", "read_only": True}, ("full_access", "explicit", True)),  # tightening
        ({"access_profile": "Balanced "}, ("balanced", "explicit", True)),
    ],
)
def test_profile_precedence_keeps_old_configs_meaning(policy, expected):
    cfg = parse_config({"policy": policy})
    assert (cfg.policy.access_profile, cfg.policy.profile_source, cfg.policy.read_only) == expected
    assert cfg.read_only == cfg.policy.read_only
    inferred_writable = expected[:2] == ("full_access", "inferred")
    assert any("treated as access_profile: full_access" in w for w in cfg.warnings) == inferred_writable


def test_flat_0_1_read_only_key_is_still_honoured():
    assert parse_config({"read_only": False}).policy.access_profile == "full_access"
    with pytest.raises(ConfigError, match="loosens"):
        parse_config({"read_only": False, "policy": {"access_profile": "balanced"}})


@pytest.mark.parametrize(
    ("policy", "match"),
    [
        ({"access_profile": "admin"}, "must be one of"),
        ({"access_profile": 3}, "must be one of"),
        ({"access_profile": "restricted", "read_only": False}, "loosens access_profile: restricted"),
        ({"access_profile": "balanced", "read_only": False}, "loosens access_profile: balanced"),
        ({"access_profile": "restricted", "allow_code_execution": True, "code_execution_providers": ["x"]},
         "restricted cannot be combined"),
        ({"access_profile": "restricted", "allow_remote_providers": True}, "restricted cannot be combined"),
        ({"access_profile": "restricted", "allow_remote_ai": True}, "restricted cannot be combined"),
        ({"access_profile": "restricted",
          "dynamic_analysis": {"enabled": True, "authorized_devices": ["d"], "authorized_targets": ["t"]}},
         "restricted cannot be combined"),
        ({"acess_profile": "restricted"}, "did you mean 'access_profile'"),
        ({"read_onyl": True}, "did you mean 'read_only'"),
        ({"dynamic_analysis": {"enable": True}}, "did you mean 'enabled'"),
        ({"allow_code_execution": True}, "code_execution_providers"),
        ({"read_only": "no"}, "true or false"),
    ],
)  # fmt: skip
def test_invalid_profiles_and_policy_keys_are_errors(policy, match):
    with pytest.raises(ConfigError, match=match):
        parse_config({"policy": policy})


def test_gates_stay_explicit_under_wider_profiles():
    """balanced/full_access never open code execution, dynamic analysis or remote providers by themselves."""
    for profile in ("balanced", "full_access"):
        cfg = parse_config({"policy": {"access_profile": profile}})
        p = cfg.policy
        assert not (p.allow_code_execution or p.dynamic.enabled or p.allow_remote_ai or p.allow_remote_providers)
        opened = parse_config(
            {
                "policy": {
                    "access_profile": profile,
                    "allow_code_execution": True,
                    "code_execution_providers": ["ida"],
                    "dynamic_analysis": {"enabled": True, "authorized_devices": ["d"], "authorized_targets": ["t"]},
                }
            }
        )
        assert opened.policy.allow_code_execution and opened.policy.dynamic.enabled


def test_unknown_keys_outside_policy_warn_but_load():
    cfg = parse_config(
        {
            "polcy": {},
            "server": {"tool_mode": "compact", "toolmode": "namespaced"},
            "workspace": {"data_dirr": "x"},
            "providers": [{"id": "eng", "type": "builtin", "enabeld": True}],
        }
    )
    warnings = "\n".join(cfg.warnings)
    assert "unknown top-level key 'polcy'" in warnings and "did you mean 'policy'" in warnings
    assert "server.toolmode" in warnings and "workspace.data_dirr" in warnings
    assert "provider 'eng': unknown key 'enabeld'" in warnings and "did you mean 'enabled'" in warnings
    assert cfg.tool_mode == "compact" and cfg.policy.access_profile == "balanced"


def test_shipped_example_config_has_no_unknown_keys():
    raw = yaml.safe_load((ROOT / "config" / "providers.example.yaml").read_text(encoding="utf-8"))
    cfg = parse_config(raw, base_dir=ROOT)
    assert not [w for w in cfg.warnings if "unknown" in w]
    assert cfg.policy.access_profile == "balanced" and cfg.policy.profile_source == "explicit"


def test_namespace_separator_is_reserved_in_provider_ids():
    with pytest.raises(ConfigError, match="reserved as the namespace separator"):
        parse_config({"providers": [{"id": "ghidra__x", "type": "builtin"}]})


# -- the decision matrix -------------------------------------------------------------------------------


def _engine(profile: str, **policy: Any) -> PolicyEngine:
    read_only = policy.pop("read_only", profile != "full_access")
    cfg = PolicyConfig(access_profile=profile, read_only=read_only, **policy)
    return PolicyEngine(NexusConfig(providers=(), policy=cfg, read_only=read_only))


PROVIDER = ProviderConfig(id="prov", name="p", command="x")


@pytest.mark.parametrize(
    ("cls", "source", "allowed"),
    [
        # verified reads: every profile
        ("read", "manifest", {"restricted": True, "balanced": True, "full_access": True}),
        ("read", "override", {"restricted": True, "balanced": True, "full_access": True}),
        # reads derived from an upstream's own claims: not under restricted
        ("read", "annotations", {"restricted": False, "balanced": True, "full_access": True}),
        ("read", "heuristic", {"restricted": False, "balanced": True, "full_access": True}),
        # writes: only full_access, and only with a verified classification
        ("mutate", "manifest", {"restricted": False, "balanced": False, "full_access": True}),
        ("mutate", "override", {"restricted": False, "balanced": False, "full_access": True}),
        ("mutate", "annotations", {"restricted": False, "balanced": False, "full_access": False}),
        ("mutate", "heuristic", {"restricted": False, "balanced": False, "full_access": False}),
        ("mutate", "pattern", {"restricted": False, "balanced": False, "full_access": False}),
        # explicit gates: no profile opens them
        ("execute", "manifest", {"restricted": False, "balanced": False, "full_access": False}),
        ("dynamic", "manifest", {"restricted": False, "balanced": False, "full_access": False}),
        ("lifecycle", "manifest", {"restricted": False, "balanced": False, "full_access": False}),
        ("blocked", "manifest", {"restricted": False, "balanced": False, "full_access": False}),
        ("unknown", "heuristic", {"restricted": False, "balanced": False, "full_access": False}),
    ],
)
def test_profile_by_class_by_source_matrix(cls, source, allowed):
    for profile in PROFILES:
        decision = _engine(profile).decide(PROVIDER, "some_tool", ToolClassification(cls, source))
        assert decision.allowed is allowed[profile], (profile, cls, source, decision.reason)
        if not decision.allowed:
            assert decision.denied_by in {"profile", "policy"}
        # a profile denial means exactly: a wider profile would allow it
        if decision.denied_by == "profile":
            wider = PROFILES[PROFILES.index(profile) + 1 :]
            assert any(allowed[w] for w in wider), (profile, cls, source)


def test_restricted_keeps_adapter_internal_reads():
    engine = _engine("restricted")
    derived = ToolClassification("read", "annotations")
    assert not engine.decide(PROVIDER, "list_functions", derived).allowed
    assert engine.decide(PROVIDER, "list_functions", derived, internal=True).allowed


def test_code_execution_gate_is_independent_of_the_profile():
    cls = ToolClassification("execute", "manifest")
    for profile in ("balanced", "full_access"):
        engine = _engine(profile, allow_code_execution=True, code_execution_providers=("prov",))
        assert engine.decide(PROVIDER, "py_eval", cls).allowed
        assert not engine.decide(PROVIDER, "py_eval", cls, internal=True).allowed
        other = ProviderConfig(id="other", name="o", command="x")
        assert not engine.decide(other, "py_eval", cls).allowed


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(
    "tool", ["bypass_ssl_pinning", "ssl_unpinning", "disable_ssl_pinning", "hide_root", "anti_debug"]
)
def test_protection_bypass_is_hard_blocked_everywhere(profile, tool):
    dyn = DynamicPolicy(
        enabled=True, authorized_devices=("dev",), authorized_targets=("com.app",), allowed_tools=(tool,)
    )
    read_only = profile != "full_access"
    engine = PolicyEngine(
        NexusConfig(providers=(), policy=PolicyConfig(access_profile=profile, read_only=read_only, dynamic=dyn))
    )
    provider = ProviderConfig(id="dyn", name="d", command="x", kind="dynamic", tool_overrides={tool: "read"})
    cls = engine.classify(provider, tool, annotations={"readOnlyHint": True}, trust_annotations_default=True)
    assert (cls.tool_class, cls.source) == ("blocked", "pattern")
    schema = {"type": "object", "properties": {"device": {}, "target": {}}, "additionalProperties": False}
    args = {"device": "dev", "target": "com.app"}
    assert not engine.decide(provider, tool, cls, arguments=args, input_schema=schema).allowed


# -- tool_overrides cannot downgrade a pinned mutating tool --------------------------------------------------

_PINNED_MUTATE = [("re_mcp", "save_database"), ("mcpyghidra", "patch"), ("ida_rs", "save_idb")]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(("adapter", "tool"), _PINNED_MUTATE)
@pytest.mark.parametrize("override", ["read", "unknown", "execute", "dynamic", "lifecycle"])
def test_override_cannot_downgrade_a_manifest_mutating_tool(profile, adapter, tool, override):
    """A tool the pinned manifest classifies as mutate keeps that class whatever an override says:
    "read" would make it callable under read-only policy; other classes would move it to a different
    gate. With writes off (restricted, balanced, or full_access with read_only: true) it stays
    denied, and in every profile the decision equals the one without the override."""
    from reveng_nexus.adapters import ADAPTERS

    manifest = ADAPTERS[adapter].manifest
    assert manifest[tool] == "mutate"  # precondition: pinned as mutating at the reviewed release
    plain = ProviderConfig(id="prov", name="p", command="x", adapter=adapter)
    overridden = ProviderConfig(id="prov", name="p", command="x", adapter=adapter, tool_overrides={tool: override})
    for read_only in {profile != "full_access", True}:
        engine = _engine(profile, read_only=read_only)
        cls = engine.classify(overridden, tool, manifest=manifest)
        assert (cls.tool_class, cls.source) == ("mutate", "manifest")
        decision = engine.decide(overridden, tool, cls, arguments={})
        baseline = engine.decide(plain, tool, engine.classify(plain, tool, manifest=manifest), arguments={})
        assert decision.allowed == baseline.allowed
        if read_only:
            assert not decision.allowed, decision.reason


@pytest.mark.parametrize("override", ["read", "unknown"])
def test_override_cannot_downgrade_an_adapter_class_for_unlisted_tools(override):
    engine = _engine("balanced")
    provider = ProviderConfig(id="prov", name="p", command="x", tool_overrides={"frob": override})
    cls = engine.classify(provider, "frob", unlisted_class="mutate")
    assert (cls.tool_class, cls.source) == ("mutate", "manifest")


@pytest.mark.parametrize("profile", PROFILES)
def test_override_may_still_tighten_a_manifest_mutating_tool(profile):
    from reveng_nexus.adapters import ADAPTERS

    manifest = ADAPTERS["re_mcp"].manifest
    engine = _engine(profile)
    for override, expected in (("blocked", "blocked"), ("mutate", "mutate")):
        provider = ProviderConfig(id="prov", name="p", command="x", tool_overrides={"save_database": override})
        cls = engine.classify(provider, "save_database", manifest=manifest)
        assert (cls.tool_class, cls.source) == (expected, "override")
    blocked = ProviderConfig(id="prov", name="p", command="x", tool_overrides={"save_database": "blocked"})
    cls = engine.classify(blocked, "save_database", manifest=manifest)
    assert not engine.decide(blocked, "save_database", cls, arguments={}).allowed


@pytest.mark.parametrize("profile", PROFILES)
def test_ordinary_overrides_of_unpinned_tools_still_apply(profile):
    """Explicit classifications of tools no manifest pins stay the operator's decision, including a
    name that merely looks mutating (the heuristic is a guess, not a reviewed classification)."""
    engine = _engine(profile)
    assert engine.classify(PROVIDER, "rename_function").tool_class == "mutate"  # heuristic only
    provider = ProviderConfig(
        id="prov", name="p", command="x", tool_overrides={"frob": "read", "rename_function": "read", "list_x": "mutate"}
    )
    for tool, expected in (("frob", "read"), ("rename_function", "read"), ("list_x", "mutate")):
        cls = engine.classify(provider, tool)
        assert (cls.tool_class, cls.source) == (expected, "override")
    frob = engine.classify(provider, "frob")
    assert engine.decide(provider, "frob", frob, arguments={}).allowed  # verified read: every profile


# -- every surface agrees with the others and with invocation --------------------------------------------------


def _hidden_engine() -> dict[str, Any]:
    return mock_engine("hid", flavor="b", expose_tools=False)


async def _surfaces(mgr) -> dict[str, Any]:
    app = NexusServer(mgr)
    listed = {t.name for t in (await app.list_tools()).tools} - set(TOOL_SPECS)
    snap = build_snapshot(mgr)
    rows = await mgr.list_tools(include_blocked=True, limit=200)
    summaries = {s["id"]: s for s in mgr.provider_summaries()}
    return {"app": app, "listed": listed, "snap": snap, "rows": rows, "summaries": summaries}


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("tool_mode", ["compact", "namespaced"])
async def test_every_surface_reports_the_same_access(config_factory, workspace, profile, tool_mode):
    providers = [mock_engine("eng"), _hidden_engine(), rea_mock()]
    cfg = config_factory(workspace, providers, server={"tool_mode": tool_mode}, policy={"access_profile": profile})
    mgr = await started(cfg)
    try:
        s = await _surfaces(mgr)
        snap_exposed = {t["public_name"] for p in s["snap"]["providers"] for t in p["tools"] if t["exposed_to_clients"]}
        rows_exposed = {r["public_name"] for r in s["rows"] if r["exposed"]}
        assert s["listed"] == snap_exposed == rows_exposed == set(exposure_map(mgr))
        if tool_mode == "compact":
            assert s["listed"] == set()
        for pid in ("eng", "hid", "rea"):
            provider = mgr.providers[pid]
            access = provider_tool_access(mgr, provider)
            entry = next(p for p in s["snap"]["providers"] if p["id"] == pid)
            counts = count_states(access.values())
            assert entry["tool_states"] == {k: counts[k] for k in TOOL_STATES}
            assert entry["counts"]["callable_tools"] == counts["callable"] + counts["exposed"]
            assert entry["counts"]["policy_allowed_tools"] == counts["policy_allowed"]
            assert entry["counts"]["available_tools"] == counts["available"]
            summary = s["summaries"][pid]
            assert summary["callable_tool_count"] == entry["counts"]["callable_tools"]
            assert summary["policy_allowed_tool_count"] == entry["counts"]["policy_allowed_tools"]
            assert summary["access"]["tool_states"]["discovered"] == len(provider._tools)
            described = provider.describe()
            assert described["callable_tool_count"] == entry["counts"]["callable_tools"]
            assert described["policy_allowed_tool_count"] == entry["counts"]["policy_allowed_tools"]
            listed_callable = {r["tool_name"] for r in s["rows"] if r["provider_id"] == pid and r["callable"]}
            assert listed_callable == {n for n, a in access.items() if a.callable}
        # nothing from the hidden provider and nothing from adapter-only REA is ever listed
        assert not any(n.startswith(("hid__", "rea__")) for n in s["listed"])
        assert s["snap"]["policy"]["access_profile"] == profile
    finally:
        await mgr.close()


@pytest.mark.parametrize("profile", PROFILES)
async def test_reported_access_matches_actual_invocation(config_factory, workspace, profile):
    """For every catalogue tool: a tool reported callable is accepted by the policy at call time, a
    tool reported unavailable is refused before reaching the server (blocked calls never run)."""
    mgr = await started(config_factory(workspace, [mock_engine("eng")], policy={"access_profile": profile}))
    try:
        provider = mgr.providers["eng"]
        access = provider_tool_access(mgr, provider)
        for name, a in access.items():
            if a.callable:
                continue  # exercised below with valid arguments
            before = provider.stats["calls"]
            with pytest.raises(PolicyViolation) as info:
                await mgr.call_provider_tool("eng", name, {})
            assert provider.stats["calls"] == before, name  # refused before the server
            assert (info.value.details or {}).get("denied_by") == (
                "profile" if a.state == "blocked_by_profile" else "policy"
            ), name
        callable_names = {n for n, a in access.items() if a.callable}
        if profile == "restricted":
            assert callable_names == set()  # every mock read is annotation-derived
            assert access["list_functions"].state == "blocked_by_profile"
        else:
            assert "list_functions" in callable_names
            for name in sorted(callable_names):
                before = provider.stats["calls"]
                # accepted by the policy and answered by the server (the mock may answer with its
                # own error, e.g. "Database not open": that is upstream output, not a refusal)
                await mgr.call_provider_tool("eng", name, {})
                assert provider.stats["calls"] == before + 1, name
    finally:
        await mgr.close()


async def test_restricted_profile_keeps_nexus_operations_working(config_factory, workspace, elf_sample):
    """restricted withholds derived raw reads from callers, not from the adapter's own operations."""
    mgr = await started(config_factory(workspace, [mock_engine("eng")], policy={"access_profile": "restricted"}))
    try:
        caps = mgr.providers["eng"].list_capabilities()
        assert caps["binary.functions"]["available"], caps["binary.functions"]
        target = mgr.target_context((await mgr.intake(str(elf_sample)))["target"]["sha256"])
        out = await mgr.perform("binary.functions", target, {}, provider_id="eng")
        assert out["result"].provider_id == "eng" and out["result"].normalized
        with pytest.raises(PolicyViolation, match="access_profile restricted"):
            await mgr.call_provider_tool("eng", "list_functions", {})
    finally:
        await mgr.close()


async def test_full_access_still_needs_verified_mutating_tools(config_factory, workspace):
    overrides = {"rename_function": "mutate"}
    providers = [mock_engine("eng", tool_overrides=overrides)]
    mgr = await started(config_factory(workspace, providers, policy={"access_profile": "full_access"}))
    try:
        access = provider_tool_access(mgr, mgr.providers["eng"])
        assert access["rename_function"].callable  # reviewed by the operator
        assert access["patch_bytes"].state == "blocked_by_policy"  # annotation-derived only
        assert "tool_overrides" in access["patch_bytes"].reason
        assert access["open_database"].state == "blocked_by_policy"  # lifecycle: never for callers
    finally:
        await mgr.close()


async def test_hidden_tools_are_not_listed_or_aliased_but_stay_policy_checked(config_factory, workspace):
    """expose_tools: false hides tools from listings (docs/SECURITY.md); policy still decides calls."""
    mgr = await started(config_factory(workspace, [_hidden_engine()], server={"tool_mode": "namespaced"}))
    try:
        app = NexusServer(mgr)
        listed = {t.name for t in (await app.list_tools()).tools} - set(TOOL_SPECS)
        assert listed == set()
        access = provider_tool_access(mgr, mgr.providers["hid"])
        assert access["list_functions"].state == "callable" and not access["list_functions"].exposed
        with pytest.raises(NotFound):
            await app.dispatch("hid__list_functions", {})
        out = await app.dispatch(
            "nexus_call_provider_tool", {"provider_id": "hid", "tool_name": "list_functions", "arguments": {}}
        )
        assert "provider_result" in out
        with pytest.raises(PolicyViolation):
            await app.dispatch(
                "nexus_call_provider_tool", {"provider_id": "hid", "tool_name": "patch_bytes", "arguments": {}}
            )
    finally:
        await mgr.close()


async def test_namespaced_name_collisions_are_disambiguated(config_factory, workspace, monkeypatch):
    mgr = await started(config_factory(workspace, [mock_engine("eng")], server={"tool_mode": "namespaced"}))
    try:
        provider = mgr.providers["eng"]
        template = provider._tools["list_functions"]
        # two upstream names that sanitise to the same MCP name, plus one truncated past 128 chars
        long_a, long_b = "x" * 140 + "a", "x" * 140 + "b"
        for name in ("get.data", "get_data", long_a, long_b):
            provider._tools[name] = type(template)(**{**_fields(template), "name": name})
        names = public_names(mgr.providers.values(), "namespaced")
        clashing = [names[("eng", n)] for n in ("get.data", "get_data", long_a, long_b)]
        assert len(set(clashing)) == 4 and all(len(n) <= 128 for n in clashing)
        assert names[("eng", "list_functions")] == "eng__list_functions"  # no clash: unchanged
        app = NexusServer(mgr)
        listed = [t.name for t in (await app.list_tools()).tools]
        assert len(listed) == len(set(listed))
        seen: list[tuple[str, str]] = []

        async def record(provider_id, tool_name, arguments, target_sha256=None):
            seen.append((provider_id, tool_name))
            return {"ok": True}

        monkeypatch.setattr(mgr, "call_provider_tool", record)
        for upstream, public in zip(("get.data", "get_data", long_a, long_b), clashing, strict=True):
            await app.dispatch(public, {})
            assert seen[-1] == ("eng", upstream)
        with pytest.raises(NotFound):
            await app.dispatch("eng__get_data", {})  # the ambiguous base name resolves to nothing
    finally:
        await mgr.close()


def _fields(info) -> dict[str, Any]:
    return {f: getattr(info, f) for f in info.__slots__}


async def test_provider_states_cover_disabled_policy_and_failures(config_factory, workspace):
    providers = [
        mock_engine("eng"),
        mock_engine("off", enabled=False),
        {**mock_engine("dyn"), "adapter": None, "kind": "dynamic"},
        {**mock_engine("bad"), "command": str(ROOT / "does-not-exist")},
    ]
    mgr = await started(config_factory(workspace, providers))
    try:
        states = {pid: provider_access(mgr, pid)["state"] for pid in ("eng", "off", "dyn", "bad", "nope")}
        assert states == {
            "eng": "ready",
            "off": "disabled_by_config",
            "dyn": "blocked_by_policy",
            "bad": "unavailable",
            "nope": "unknown",
        }
        snap = {p["id"]: p for p in build_snapshot(mgr)["providers"]}
        assert (
            snap["off"]["access_state"] == "disabled_by_config" and snap["dyn"]["access_state"] == "blocked_by_policy"
        )
    finally:
        await mgr.close()


# -- the real MCP path: `reveng-nexus serve` over stdio, driven by an MCP client ---------------------------------


def _write_config(tmp_path: Path, workspace: Path, profile: str, providers: list[dict[str, Any]]) -> Path:
    raw = {
        "server": {"tool_mode": "namespaced"},
        "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
        "policy": {"access_profile": profile},
        "providers": providers,
    }
    path = tmp_path / "providers.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


async def _mcp_session(config_path: Path):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client

    env = {**get_default_environment(), "REVENG_NEXUS_DASHBOARD_SNAPSHOT": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "reveng_nexus", "--config", str(config_path), "serve"], env=env
    )
    return Client(stdio_client(params, errlog=open(os.devnull, "w")))  # noqa: SIM115


def _payload(result) -> dict[str, Any]:
    return json.loads(result.content[0].text)


@pytest.mark.parametrize("profile", ["restricted", "balanced"])
async def test_mcp_stdio_discovery_and_invocation_follow_the_profile(tmp_path, workspace, elf_sample, profile):
    providers = [mock_engine("eng"), rea_mock(env={"REA_WABT_BIN_DIRECTORY": "/opt/wabt/bin"})]
    config_path = _write_config(tmp_path, workspace, profile, providers)
    async with await _mcp_session(config_path) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert set(TOOL_SPECS) <= tools and "nexus_inspect_artifact" in tools
        raw = tools - set(TOOL_SPECS)
        assert not any(n.startswith("rea__") for n in raw)  # adapter-only in every profile
        if profile == "restricted":
            assert raw == set()  # every mock engine read is annotation-derived
        else:
            assert "eng__list_functions" in raw and "eng__patch_bytes" not in raw
            reached = await client.call_tool("eng__list_functions", {})
            text = reached.content[0].text
            # forwarded to the engine: its answer (here the mock's own "Database not open"), no refusal
            assert "provider_result" in text and "Blocked" not in text and "Unknown tool" not in text
        status = _payload(await client.call_tool("nexus_status", {}))
        assert status["access_profile"] == profile and status["policy"]["access_profile"] == profile
        listed = _payload(await client.call_tool("nexus_list_tools", {"include_blocked": True, "limit": 200}))
        assert {r["public_name"] for r in listed if r["exposed"]} == raw
        blocked = await client.call_tool(
            "nexus_call_provider_tool", {"provider_id": "eng", "tool_name": "patch_bytes", "arguments": {}}
        )
        assert blocked.is_error
        alias = await client.call_tool("eng__patch_bytes", {})
        assert alias.is_error and "Unknown tool" in alias.content[0].text
        sha = _payload(await client.call_tool("nexus_inspect_target", {"path": str(elf_sample)}))["target"]["sha256"]
        inspected = await client.call_tool("nexus_inspect_artifact", {"target": sha, "analysis": "go_binary"})
        if profile == "restricted":
            assert inspected.is_error and "access_profile balanced" in inspected.content[0].text
        else:
            body = _payload(inspected)
            assert not inspected.is_error, body
            assert body["provenance"]["provider_id"] == "rea" and body["result"]["analysis"] == "go_binary"
            assert body["evidence_id"]
        functions = await client.call_tool("nexus_list_functions", {"target": sha, "provider_id": "eng"})
        assert not functions.is_error  # nexus_* operations work in every profile


def test_mock_engine_constant_is_shared():
    assert Path(MOCK_ENGINE).is_file()
