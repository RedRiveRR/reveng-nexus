import pytest

from reveng_nexus.adapters import ADAPTERS
from reveng_nexus.config import DynamicPolicy, NexusConfig, PolicyConfig, ProviderConfig
from reveng_nexus.errors import PolicyViolation
from reveng_nexus.policy import PolicyEngine
from reveng_nexus.security import heuristic_tool_class, is_tool_blocked


@pytest.mark.parametrize(
    "tool_name",
    [
        "patch_bytes",
        "write_memory",
        "rename_function",
        "run_script",
        "set_comment",
        "debugger_attach",
        "set_comments",
        "bypass_ssl_pinning",
        "execute_python",
        "pyghidra_eval",
    ],
)
def test_read_only_blocks_mutating_or_execution_tools(tool_name: str):
    assert is_tool_blocked(tool_name, read_only=True)


def test_read_only_keeps_observation_tools():
    for name in ("decompile_function", "list_functions", "get_xrefs", "search_classes_by_keyword", "get_strings"):
        assert not is_tool_blocked(name, read_only=True)


def test_mutation_filter_can_be_disabled_explicitly():
    assert not is_tool_blocked("patch_bytes", read_only=False)


def test_custom_blocklist_is_applied():
    assert is_tool_blocked("dangerous_custom_tool", read_only=True, configured_patterns=["dangerous"])


@pytest.mark.parametrize(
    "name,expected",
    [
        ("decompile_function", "read"),
        ("getXrefsTo", "read"),
        ("create_struct", "mutate"),
        ("update_vars", "mutate"),
        ("run_prebuilt_script", "execute"),
        ("attach_process", "dynamic"),
        ("hook_method", "dynamic"),
        ("frobnicate", "unknown"),
    ],
)
def test_heuristic_classes(name, expected):
    assert heuristic_tool_class(name) == expected


def _engine(read_only=True, **policy):
    config = NexusConfig(providers=(), policy=PolicyConfig(read_only=read_only, **policy), read_only=read_only)
    return PolicyEngine(config)


def _provider(**kw):
    return ProviderConfig(id=kw.pop("id", "prov"), name="p", command="x", **kw)


def test_classification_precedence_override_manifest_annotations_heuristic():
    engine = _engine()
    provider = _provider(tool_overrides={"get_secret": "blocked"})
    assert engine.classify(provider, "get_secret").tool_class == "blocked"
    assert engine.classify(provider, "frob", manifest={"frob": "read"}).source == "manifest"
    ann = engine.classify(provider, "frob", annotations={"readOnlyHint": True}, trust_annotations_default=True)
    assert (ann.tool_class, ann.source) == ("read", "annotations")
    # annotations are ignored unless trusted
    assert engine.classify(provider, "frob", annotations={"readOnlyHint": True}).tool_class == "unknown"


def test_read_only_hint_cannot_whitelist_execution_shaped_names():
    engine = _engine()
    cls = engine.classify(
        _provider(), "execute_script", annotations={"readOnlyHint": True}, trust_annotations_default=True
    )
    assert cls.tool_class == "execute"


def test_unknown_tools_are_blocked_and_explain_why():
    engine = _engine()
    provider = _provider()
    decision = engine.decide(provider, "frob", engine.classify(provider, "frob"))
    assert not decision.allowed and "unclassified" in decision.reason
    with pytest.raises(PolicyViolation):
        engine.enforce(decision, provider.id, "frob")


def test_lifecycle_tools_internal_only():
    engine = _engine()
    provider = _provider()
    cls = engine.classify(provider, "open_database", manifest={"open_database": "lifecycle"})
    assert engine.decide(provider, "open_database", cls, internal=True).allowed
    assert not engine.decide(provider, "open_database", cls, internal=False).allowed


def test_execute_needs_explicit_provider_opt_in():
    provider = _provider(id="ida_official")
    cls = _engine().classify(provider, "execute_python", manifest=ADAPTERS["ida_official"].manifest)
    assert not _engine().decide(provider, "execute_python", cls).allowed
    opted = _engine(allow_code_execution=True, code_execution_providers=("ida_official",))
    assert opted.decide(provider, "execute_python", cls).allowed
    # adapters can never use code execution internally, even when enabled
    assert not opted.decide(provider, "execute_python", cls, internal=True).allowed


def test_mutation_allowed_only_when_read_only_disabled():
    provider = _provider()
    cls = _engine().classify(provider, "rename_function")
    assert not _engine().decide(provider, "rename_function", cls).allowed
    assert _engine(read_only=False).decide(provider, "rename_function", cls).allowed


def test_upstream_manifests_close_the_0_1_name_filter_gaps():
    engine = _engine()
    mcpy = ADAPTERS["mcpyghidra"]
    provider = _provider(id="mcpy")
    for tool in ("set_comments", "update_vars", "create_struct", "add_field", "begin_trans", "pyghidra"):
        cls = engine.classify(provider, tool, manifest=mcpy.manifest, trust_annotations_default=True)
        assert not engine.decide(provider, tool, cls).allowed, tool
    remcp = ADAPTERS["re_mcp"]
    for tool in ("call", "batch", "execute"):
        cls = engine.classify(
            provider, tool, manifest=remcp.manifest, annotations={"readOnlyHint": True}, trust_annotations_default=True
        )
        assert cls.tool_class == "blocked", tool


def test_dynamic_tools_require_policy_and_authorised_targets():
    frida = ADAPTERS["frida_mobile"]
    provider = _provider(id="frida", kind="dynamic")
    off = _engine()
    cls = off.classify(provider, "hook_method", manifest=frida.manifest)
    assert not off.decide(provider, "hook_method", cls, arguments={"target": "com.example.test"}).allowed

    dyn = DynamicPolicy(
        enabled=True,
        authorized_devices=("emulator-5554",),
        authorized_targets=("com.example.test",),
        allowed_tools=("hook_method",),
    )
    on = _engine(dynamic=dyn)
    assert on.decide(provider, "hook_method", cls, arguments={"target": "com.example.test"}).allowed
    assert not on.decide(provider, "hook_method", cls, arguments={"target": "com.other.app"}).allowed
    assert not on.decide(
        provider, "hook_method", cls, arguments={"target": "com.example.test", "device": "usb-1"}
    ).allowed
    assert not on.decide(provider, "hook_method", cls, arguments={}).allowed, "must name the target"
    trace = on.classify(provider, "trace_method", manifest=frida.manifest)
    assert not on.decide(provider, "trace_method", trace, arguments={"target": "com.example.test"}).allowed


def test_protection_bypass_is_hard_blocked_even_with_dynamic_enabled():
    frida = ADAPTERS["frida_mobile"]
    provider = _provider(id="frida", kind="dynamic")
    dyn = DynamicPolicy(
        enabled=True,
        authorized_devices=("d",),
        authorized_targets=("com.example.test",),
        allowed_tools=("bypass_ssl_pinning", "write_memory", "execute_script"),
    )
    engine = _engine(dynamic=dyn)
    for tool in ("bypass_ssl_pinning", "write_memory", "execute_script", "run_prebuilt_script"):
        cls = engine.classify(provider, tool, manifest=frida.manifest)
        assert not engine.decide(provider, tool, cls, arguments={"target": "com.example.test"}).allowed, tool


def test_global_patterns_always_win():
    config = NexusConfig(providers=(), policy=PolicyConfig(global_blocked_tool_patterns=("^decompile",)))
    engine = PolicyEngine(config)
    cls = engine.classify(_provider(), "decompile_function", manifest={"decompile_function": "read"})
    assert cls.tool_class == "blocked"
