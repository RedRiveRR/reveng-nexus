from pathlib import Path

import pytest

from reveng_nexus.config import ProviderConfig, expand_env, load_config, parse_config
from reveng_nexus.errors import ConfigError

EXAMPLE = Path(__file__).parents[1] / "config" / "providers.example.yaml"


def test_provider_stdio_config_validates():
    provider = ProviderConfig.from_dict(
        {
            "id": "ghidra",
            "name": "Ghidra",
            "transport": "stdio",
            "command": "python",
            "args": ["server.py"],
        }
    )
    assert provider.id == "ghidra"
    assert provider.command == "python"
    assert provider.enabled is False
    assert provider.type == "mcp_stdio" and provider.transport == "stdio"


def test_provider_rejects_invalid_id():
    with pytest.raises(ValueError, match="Invalid provider id"):
        ProviderConfig.from_dict({"id": "Not Valid!", "command": "python"})


def test_provider_requires_http_url():
    with pytest.raises(ValueError, match="requires an HTTP"):
        ProviderConfig.from_dict({"id": "http_tool", "transport": "streamable_http"})


def test_provider_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="timeout_seconds"):
        ProviderConfig.from_dict({"id": "ghidra", "command": "python", "timeout_seconds": 0})


def test_load_config_checks_duplicate_ids(tmp_path: Path):
    config_file = tmp_path / "providers.yaml"
    config_file.write_text(
        "providers:\n  - {id: ghidra, command: python}\n  - {id: ghidra, command: python}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="unique"):
        load_config(config_file)


def test_example_config_loads_with_everything_disabled():
    config = load_config(EXAMPLE)
    assert config.read_only is True and config.policy.read_only is True
    assert config.tool_mode == "compact"
    assert config.policy.dynamic.enabled is False
    assert config.policy.allow_code_execution is False
    assert len(config.providers) >= 9
    assert not [p.id for p in config.providers if p.enabled and p.type != "builtin"], (
        "external providers must be opt-in"
    )
    adapters = {p.adapter for p in config.providers if p.adapter}
    assert {"re_mcp", "mcpyghidra", "ida_official", "ida_rs", "binary_ninja", "jadx", "frida_mobile"} <= adapters


def test_example_config_has_no_secrets():
    text = EXAMPLE.read_text(encoding="utf-8").lower()
    for marker in ("sk-", "api_key:", "password:", "token:", "bearer "):
        assert marker not in text


def test_yaml_syntax_error_is_reported(tmp_path: Path):
    bad = tmp_path / "providers.yaml"
    bad.write_text("providers: [\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="YAML syntax"):
        load_config(bad)


def test_legacy_flat_keys_map_to_sections(tmp_path: Path):
    config = parse_config(
        {
            "tool_mode": "namespaced",
            "read_only": True,
            "allowed_roots": [str(tmp_path)],
            "max_target_size_mb": 5,
            "global_blocked_tool_patterns": ["danger"],
            "providers": [],
        },
        base_dir=tmp_path,
    )
    assert config.tool_mode == "namespaced"
    assert config.allowed_roots == (str(tmp_path.resolve()),)
    assert config.max_target_size_mb == 5
    assert config.policy.global_blocked_tool_patterns == ("danger",)


def test_relative_data_paths_anchor_to_base_dir(tmp_path: Path):
    config = parse_config({"workspace": {"data_dir": "./data"}, "providers": []}, base_dir=tmp_path)
    assert Path(config.data_dir) == (tmp_path / "data").resolve()
    assert Path(config.evidence_db).parent == Path(config.data_dir)


def test_dynamic_analysis_requires_explicit_authorisation(tmp_path: Path):
    with pytest.raises(ConfigError, match="authorized_devices"):
        parse_config({"policy": {"dynamic_analysis": {"enabled": True}}, "providers": []}, base_dir=tmp_path)
    ok = parse_config(
        {
            "policy": {
                "dynamic_analysis": {
                    "enabled": True,
                    "authorized_devices": ["emulator-5554"],
                    "authorized_targets": ["com.example.test"],
                }
            },
            "providers": [],
        },
        base_dir=tmp_path,
    )
    assert ok.policy.dynamic.enabled


def test_code_execution_requires_provider_list(tmp_path: Path):
    with pytest.raises(ConfigError, match="code_execution_providers"):
        parse_config({"policy": {"allow_code_execution": True}, "providers": []}, base_dir=tmp_path)


def test_api_keys_are_rejected_in_yaml():
    with pytest.raises(ConfigError, match="never put API keys"):
        ProviderConfig.from_dict(
            {
                "id": "llm",
                "type": "llm4decompile",
                "model": {
                    "endpoint": "http://127.0.0.1:8000",
                    "model": "LLM4Binary/llm4decompile-6.7b-v2",
                    "api_key": "x",
                },
            }
        )


def test_launched_provider_needs_target_placeholder():
    with pytest.raises(ConfigError, match="placeholder"):
        ProviderConfig.from_dict(
            {"id": "mcpy", "type": "mcp_launched_http", "command": "mcpyghidra-headless", "args": ["--port", "0"]}
        )


def test_routing_rejects_unknown_provider(tmp_path: Path):
    with pytest.raises(ConfigError, match="unknown providers"):
        parse_config({"providers": [], "routing": {"preferred": {"binary.decompile": ["nope"]}}}, base_dir=tmp_path)


def test_tool_overrides_validate_classes():
    with pytest.raises(ConfigError, match="tool_overrides"):
        ProviderConfig.from_dict({"id": "x1", "command": "x", "tool_overrides": {"foo": "harmless"}})


def test_conflict_group_and_dynamic_warnings(tmp_path: Path):
    config = parse_config(
        {
            "providers": [
                {"id": "ida_a", "command": "a", "enabled": True, "conflict_group": "ida"},
                {"id": "ida_b", "command": "b", "enabled": True, "conflict_group": "ida"},
                {"id": "frida", "command": "c", "enabled": True, "kind": "dynamic"},
            ]
        },
        base_dir=tmp_path,
    )
    joined = " ".join(config.warnings)
    assert "conflict_group 'ida'" in joined
    assert "frida" in joined and "dynamic" in joined


def test_env_expansion_reports_missing():
    value, missing = expand_env(
        "${NEXUS_TEST_SET}/x:${NEXUS_TEST_UNSET}:${NEXUS_TEST_DEFAULT:-fallback}", {"NEXUS_TEST_SET": "/opt"}
    )
    assert value == "/opt/x:${NEXUS_TEST_UNSET}:fallback"
    assert missing == ["NEXUS_TEST_UNSET"]


def test_allow_lifecycle_passthrough_true_is_rejected(config_factory, workspace):
    from reveng_nexus.errors import ConfigError

    with pytest.raises(ConfigError, match="allow_lifecycle_passthrough"):
        config_factory(workspace, [], policy={"allow_lifecycle_passthrough": True})
    assert config_factory(workspace, [], policy={"allow_lifecycle_passthrough": False})


def test_contradicting_kind_for_a_pinned_dynamic_adapter_is_a_config_error(config_factory, workspace):
    from reveng_nexus.errors import ConfigError

    frida = {"id": "fr", "type": "mcp_stdio", "adapter": "frida_mobile", "command": "x", "kind": "static"}
    with pytest.raises(ConfigError, match="kind must be 'dynamic'"):
        config_factory(workspace, [frida])
    del frida["kind"]
    assert config_factory(workspace, [frida]).providers[0].kind == "dynamic"


@pytest.mark.parametrize(
    ("command", "args", "needed"),
    [
        ("npx", ["-y", "frida-mobile-mcp@0.2.3"], "frida_mobile"),
        ("node.exe", ["C:/x/rea-agents-6.5.0/node_modules/rea-agents/scripts/rea.mjs", "mcp"], "rea"),
        ("npx", ["-y", "rea-agents@6.5.0", "mcp"], "rea"),
    ],
)
def test_servers_with_adapter_gates_cannot_run_without_their_adapter(command, args, needed):
    """Adapter-less, Frida would be a static provider (verb heuristic, no device check) and REA raw."""
    raw = {"id": "srv", "type": "mcp_stdio", "command": command, "args": args}
    for adapter in (None, "re_mcp"):
        with pytest.raises(ConfigError, match=f"needs adapter: {needed}"):
            ProviderConfig.from_dict({**raw, **({"adapter": adapter} if adapter else {})})
    assert ProviderConfig.from_dict({**raw, "adapter": needed}).adapter == needed
    # an unrelated name that merely contains the letters is not matched
    assert ProviderConfig.from_dict({**raw, "args": ["area.mjs", "frida_notes.txt"]}).adapter is None


def test_re_mcp_engine_label_is_restricted_and_inferred_from_the_package():
    """One adapter serves both re-mcp backends; the engine label decides the engine family."""
    base = {"id": "re", "type": "mcp_stdio", "adapter": "re_mcp", "command": "uvx"}
    assert ProviderConfig.from_dict({**base, "args": ["re-mcp-ida==3.0.3"]}).engine == "ida"
    assert ProviderConfig.from_dict({**base, "args": ["re-mcp-ghidra==3.0.3"]}).engine == "ghidra"
    with pytest.raises(ConfigError, match="contradicts"):
        ProviderConfig.from_dict({**base, "args": ["re-mcp-ida==3.0.3"], "engine": "ghidra"})
    with pytest.raises(ConfigError, match="engine: ghidra or engine: ida"):
        ProviderConfig.from_dict({**base, "args": ["re-mcp-ghidra==3.0.3"], "engine": "ghidra12"})
