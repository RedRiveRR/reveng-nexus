"""Configuration loading and validation for RevEng Nexus.

The YAML format is documented in ``config/providers.example.yaml``. Older flat
keys from the 0.1 scaffold (``tool_mode``, ``read_only``, ``allowed_roots`` ...)
are still accepted and mapped onto the structured sections.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError

# Launch commands that identify a server whose adapter carries its safety gates.
_FRIDA_LAUNCH = re.compile(r"frida-mobile-mcp", re.IGNORECASE)
_REA_LAUNCH = re.compile(r"(?:^|[\\/@\s])rea-agents\b|(?:^|[\\/])rea\.mjs$", re.IGNORECASE)

_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,47}$")
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

# Provider types. ``transport`` (0.1 scaffold) maps onto these.
PROVIDER_TYPES = {"builtin", "mcp_stdio", "mcp_http", "mcp_launched_http", "llm4decompile"}
_TRANSPORT_ALIASES = {"stdio": "mcp_stdio", "streamable_http": "mcp_http"}
_MCP_TYPES = {"mcp_stdio", "mcp_http", "mcp_launched_http"}
PROVIDER_KINDS = {"static", "dynamic", "ai"}
TOOL_CLASSES = {"read", "lifecycle", "mutate", "execute", "dynamic", "blocked"}
DEPTHS = {"quick", "standard", "deep"}


def _err(provider_id: str, message: str) -> ConfigError:
    return ConfigError(f"Provider {provider_id!r}: {message}")


def _str_list(value: Any, what: str, provider_id: str | None = None) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        message = f"{what} must be a list of strings."
        raise _err(provider_id, message) if provider_id else ConfigError(message)
    return tuple(value)


def _check_regexes(patterns: tuple[str, ...], where: str) -> None:
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"{where}: invalid blocked-tool regex {pattern!r}: {exc}") from exc


def _int(value: Any, what: str, low: int, high: int, provider_id: str | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        message = f"{what} must be an integer between {low} and {high}."
        raise _err(provider_id, message) if provider_id else ConfigError(message)
    return value


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{what} must be true or false.")
    return value


def expand_env(value: str, environ: dict[str, str] | None = None) -> tuple[str, list[str]]:
    """Expand ``${VAR}`` / ``${VAR:-default}``; return (value, unresolved names)."""
    env = os.environ if environ is None else environ
    missing: list[str] = []

    def substitute(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in env and env[name] != "":
            return env[name]
        if default is not None:
            return default
        missing.append(name)
        return match.group(0)

    return _ENV_REF.sub(substitute, value), missing


@dataclass(frozen=True, slots=True)
class LaunchConfig:
    """How to start a server that announces readiness on stdout (``mcp_launched_http``)."""

    ready_pattern: str = "json_status"  # JSON line with {"status": "ready", "host", "port"}
    url_template: str = "http://{host}:{port}/mcp"
    per_target: bool = True  # one server process per analysed target
    startup_timeout_seconds: int = 900


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Inference settings for ``llm4decompile`` providers."""

    endpoint: str = ""
    model: str = ""
    variant: str = "ref"  # ref = refine Ghidra pseudocode (V2); end = from assembly (V1.5)
    api: str = "openai_completions"
    max_tokens: int = 1024
    temperature: float = 0.0
    allow_remote: bool = False
    allow_unrecognized_model: bool = False
    api_key_env: str = ""  # name of an env var; the key itself never lives in YAML


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """One analysis backend: a child MCP server, the built-in engine or a model adapter."""

    id: str
    name: str
    enabled: bool = False
    type: str = "mcp_stdio"
    adapter: str | None = None
    engine: str = ""
    kind: str = "static"
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    allow_remote: bool = False  # mcp_http only; also needs policy.allow_remote_providers
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    capabilities: tuple[str, ...] = ()
    expose_tools: bool = True
    blocked_tool_patterns: tuple[str, ...] = ()
    tool_overrides: dict[str, str] = field(default_factory=dict)
    trust_annotations: bool | None = None  # None = adapter default
    timeout_seconds: int = 120
    startup_timeout_seconds: int = 300
    priority: int = 50
    max_concurrency: int = 1
    conflict_group: str | None = None
    protocol_mode: str = "auto"  # auto | legacy (forces the pre-2026 initialize handshake)
    stage_target: bool = True  # hand providers a per-provider copy, never the original
    launch: LaunchConfig = field(default_factory=LaunchConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    settings: dict[str, Any] = field(default_factory=dict)

    # Backwards-compatible alias used by the 0.1 scaffold.
    @property
    def transport(self) -> str:
        return {"mcp_stdio": "stdio", "mcp_http": "streamable_http"}.get(self.type, self.type)

    @property
    def is_mcp(self) -> bool:
        return self.type in _MCP_TYPES

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProviderConfig:
        provider_id = str(raw.get("id", "")).strip()
        if not _ID_PATTERN.fullmatch(provider_id):
            raise ConfigError(f"Invalid provider id {provider_id!r}; use 2-48 lowercase letters, digits, '_' or '-'.")

        if "type" in raw:
            ptype = str(raw["type"]).strip().lower()
        else:
            transport = str(raw.get("transport", "stdio")).strip().lower()
            if transport not in _TRANSPORT_ALIASES:
                raise _err(provider_id, f"transport must be one of {sorted(_TRANSPORT_ALIASES)}.")
            ptype = _TRANSPORT_ALIASES[transport]
        if ptype not in PROVIDER_TYPES:
            raise _err(provider_id, f"type must be one of {sorted(PROVIDER_TYPES)}.")

        command = raw.get("command")
        url = raw.get("url")
        if ptype in {"mcp_stdio", "mcp_launched_http"} and not (isinstance(command, str) and command.strip()):
            raise _err(provider_id, f"{ptype} requires a command.")
        if ptype == "mcp_http":
            if not isinstance(url, str):
                raise _err(provider_id, "streamable_http transport requires an HTTP(S) url.")
            from .netguard import parse_http_url

            try:
                parse_http_url(url.strip())
            except ValueError as exc:
                raise _err(provider_id, f"url: {exc}.") from None
        allow_remote = raw.get("allow_remote", False)
        if not isinstance(allow_remote, bool):
            raise _err(provider_id, "allow_remote must be true or false.")
        if allow_remote and ptype != "mcp_http":
            raise _err(provider_id, "allow_remote applies only to mcp_http providers.")

        args = _str_list(raw.get("args", []), "args", provider_id)
        env_raw = raw.get("env", {}) or {}
        if not isinstance(env_raw, dict) or not all(
            isinstance(k, str) and isinstance(v, (str, int, float, bool)) for k, v in env_raw.items()
        ):
            raise _err(provider_id, "env must be a string-keyed mapping.")
        capabilities = _str_list(raw.get("capabilities", []), "capabilities", provider_id)
        blocked = _str_list(raw.get("blocked_tool_patterns", []), "blocked_tool_patterns", provider_id)
        _check_regexes(blocked, f"Provider {provider_id!r}")

        timeout_seconds = raw.get("timeout_seconds", 120)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not (1 <= timeout_seconds <= 3600)
        ):
            raise _err(provider_id, "timeout_seconds must be 1-3600.")
        startup = _int(raw.get("startup_timeout_seconds", 300), "startup_timeout_seconds", 1, 7200, provider_id)
        priority = _int(raw.get("priority", 50), "priority", 0, 1000, provider_id)
        max_concurrency = _int(raw.get("max_concurrency", 1), "max_concurrency", 1, 16, provider_id)

        kind = str(raw.get("kind", "ai" if ptype == "llm4decompile" else "static")).lower()
        if kind not in PROVIDER_KINDS:
            raise _err(provider_id, f"kind must be one of {sorted(PROVIDER_KINDS)}.")
        if raw.get("adapter"):
            from .adapters import ADAPTERS

            # An unknown adapter name is reported when that provider starts, not here, so one
            # bad entry never blocks the others.
            pinned_adapter = ADAPTERS.get(str(raw["adapter"]).strip())
            required_kind = pinned_adapter.provider_kind if pinned_adapter else None
            if required_kind and "kind" not in raw:
                kind = required_kind
            elif required_kind and kind != required_kind:
                raise _err(
                    provider_id,
                    f"adapter {raw['adapter']!r} is a {required_kind} provider; kind must be {required_kind!r}.",
                )

        overrides_raw = raw.get("tool_overrides", {}) or {}
        if not isinstance(overrides_raw, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and v in TOOL_CLASSES for k, v in overrides_raw.items()
        ):
            raise _err(
                provider_id,
                f"tool_overrides must map tool names to one of {sorted(TOOL_CLASSES)}.",
            )

        trust = raw.get("trust_annotations")
        if trust is not None and not isinstance(trust, bool):
            raise _err(provider_id, "trust_annotations must be true, false or omitted.")

        protocol_mode = str(raw.get("protocol_mode", "auto")).lower()
        if protocol_mode not in {"auto", "legacy"}:
            raise _err(provider_id, "protocol_mode must be 'auto' or 'legacy'.")

        conflict_group = raw.get("conflict_group")
        if conflict_group is not None and not (
            isinstance(conflict_group, str) and _ID_PATTERN.fullmatch(conflict_group)
        ):
            raise _err(provider_id, "conflict_group must be an id-like string.")

        launch_raw = raw.get("launch", {}) or {}
        if not isinstance(launch_raw, dict):
            raise _err(provider_id, "launch must be a mapping.")
        launch = LaunchConfig(
            ready_pattern=str(launch_raw.get("ready_pattern", "json_status")),
            url_template=str(launch_raw.get("url_template", "http://{host}:{port}/mcp")),
            per_target=bool(launch_raw.get("per_target", True)),
            startup_timeout_seconds=_int(
                launch_raw.get("startup_timeout_seconds", 900),
                "launch.startup_timeout_seconds",
                1,
                7200,
                provider_id,
            ),
        )
        if launch.ready_pattern != "json_status":
            raise _err(provider_id, "launch.ready_pattern currently supports only 'json_status'.")
        if ptype == "mcp_launched_http" and "{target}" not in " ".join(args) and launch.per_target:
            raise _err(
                provider_id,
                "mcp_launched_http with per_target=true needs a '{target}' placeholder in args.",
            )

        model_raw = raw.get("model", {}) or {}
        if not isinstance(model_raw, dict):
            raise _err(provider_id, "model must be a mapping.")
        model = ModelConfig(
            endpoint=str(model_raw.get("endpoint", "")).strip(),
            model=str(model_raw.get("model", "")).strip(),
            variant=str(model_raw.get("variant", "ref")).strip().lower(),
            api=str(model_raw.get("api", "openai_completions")).strip().lower(),
            max_tokens=_int(model_raw.get("max_tokens", 1024), "model.max_tokens", 16, 8192, provider_id),
            temperature=float(model_raw.get("temperature", 0.0)),
            allow_remote=bool(model_raw.get("allow_remote", False)),
            allow_unrecognized_model=bool(model_raw.get("allow_unrecognized_model", False)),
            api_key_env=str(model_raw.get("api_key_env", "")).strip(),
        )
        if ptype == "llm4decompile":
            if model.variant not in {"ref", "end"}:
                raise _err(provider_id, "model.variant must be 'ref' or 'end'.")
            if model.api != "openai_completions":
                raise _err(provider_id, "model.api currently supports only 'openai_completions'.")
            if not model.endpoint.startswith(("http://", "https://")):
                raise _err(provider_id, "model.endpoint must be an http(s) URL.")
            if not model.model:
                raise _err(provider_id, "model.model (served model id) is required.")
            if not 0.0 <= model.temperature <= 2.0:
                raise _err(provider_id, "model.temperature must be between 0 and 2.")
            if model.api_key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", model.api_key_env):
                raise _err(provider_id, "model.api_key_env must be an environment variable name.")
            if "api_key" in model_raw:
                raise _err(provider_id, "never put API keys in YAML; use model.api_key_env.")

        settings = raw.get("settings", {}) or {}
        if not isinstance(settings, dict):
            raise _err(provider_id, "settings must be a mapping.")

        cwd = raw.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise _err(provider_id, "cwd must be a string path.")

        adapter_name = str(raw["adapter"]).strip() if raw.get("adapter") else None
        launch_words = [str(command or "")] + [str(a) for a in args]
        # Servers whose gates live in their adapter must never run without it: an adapter-less Frida
        # Mobile MCP is a static provider (verb heuristic, no device check) and an adapter-less REA
        # offers raw passthrough to its whole catalogue.
        for pattern, needed in ((_FRIDA_LAUNCH, "frida_mobile"), (_REA_LAUNCH, "rea")):
            if adapter_name != needed and any(pattern.search(word) for word in launch_words):
                raise _err(provider_id, f"this command launches a server that needs adapter: {needed}.")
        engine = str(raw.get("engine", "")).strip().lower()
        if adapter_name == "re_mcp":
            # One adapter serves both re-mcp backends; the engine label decides the engine family,
            # so free text (or a Ghidra default on re-mcp-ida) would make one engine look independent.
            backend = next((b for b in ("ida", "ghidra") if any(f"re-mcp-{b}" in w for w in launch_words)), None)
            if engine and engine not in {"ghidra", "ida"}:
                raise _err(provider_id, "adapter re_mcp needs engine: ghidra or engine: ida.")
            if backend and engine and engine != backend:
                raise _err(provider_id, f"engine {engine!r} contradicts the re-mcp-{backend} package.")
            engine = engine or backend or ""

        return cls(
            id=provider_id,
            name=str(raw.get("name", provider_id)).strip(),
            enabled=bool(raw.get("enabled", False)),
            type=ptype,
            adapter=adapter_name,
            engine=engine,
            kind=kind,
            command=str(command).strip() if command else None,
            args=args,
            url=str(url).strip() if url else None,
            allow_remote=allow_remote,
            env={str(k): str(v).lower() if isinstance(v, bool) else str(v) for k, v in env_raw.items()},
            cwd=cwd,
            capabilities=capabilities,
            expose_tools=bool(raw.get("expose_tools", True)),
            blocked_tool_patterns=blocked,
            tool_overrides=dict(overrides_raw),
            trust_annotations=trust,
            timeout_seconds=timeout_seconds,
            startup_timeout_seconds=startup,
            priority=priority,
            max_concurrency=max_concurrency,
            conflict_group=conflict_group,
            protocol_mode=protocol_mode,
            stage_target=bool(raw.get("stage_target", True)),
            launch=launch,
            model=model,
            settings=dict(settings),
        )


@dataclass(frozen=True, slots=True)
class DynamicPolicy:
    enabled: bool = False
    authorized_devices: tuple[str, ...] = ()
    authorized_targets: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    read_only: bool = True
    allow_code_execution: bool = False
    code_execution_providers: tuple[str, ...] = ()
    allow_lifecycle_passthrough: bool = False
    allow_remote_ai: bool = False
    allow_remote_providers: bool = False
    dynamic: DynamicPolicy = field(default_factory=DynamicPolicy)
    global_blocked_tool_patterns: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    default_depth: str = "standard"
    operation_timeout_seconds: int = 600
    max_concurrent_provider_calls: int = 2
    max_functions_to_decompile: int = 5
    cross_engine_comparison: str = "explicit"  # explicit | auto
    ai_enhancement: bool = False
    max_failover: int = 1
    raw_output_limit_kb: int = 256


@dataclass(frozen=True, slots=True)
class NexusConfig:
    """Top-level application configuration."""

    providers: tuple[ProviderConfig, ...]
    tool_mode: str = "compact"
    read_only: bool = True
    audit_log: str = "./data/audit.jsonl"
    evidence_db: str = "./data/evidence.sqlite3"
    allowed_roots: tuple[str, ...] = ()
    max_target_size_mb: int = 250
    global_blocked_tool_patterns: tuple[str, ...] = ()
    data_dir: str = "./data"
    follow_symlinks: bool = False
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    routing: dict[str, tuple[str, ...]] = field(default_factory=dict)
    config_path: str | None = None
    warnings: tuple[str, ...] = ()

    def provider(self, provider_id: str) -> ProviderConfig | None:
        return next((p for p in self.providers if p.id == provider_id), None)

    @property
    def work_dir(self) -> Path:
        return Path(self.data_dir).expanduser().resolve() / "work"

    @classmethod
    def for_tests(cls, providers: tuple[ProviderConfig, ...], base: Path, **kwargs: Any) -> NexusConfig:
        """Convenience constructor that keeps every artefact inside ``base``."""
        policy = kwargs.pop("policy", PolicyConfig())
        return cls(
            providers=providers,
            audit_log=str(base / "audit.jsonl"),
            evidence_db=str(base / "evidence.sqlite3"),
            data_dir=str(base / "data"),
            policy=policy,
            read_only=policy.read_only,
            **kwargs,
        )


def _resolve_relative(value: str, base: Path) -> str:
    path = Path(value).expanduser()
    return str(path if path.is_absolute() else (base / path).resolve())


def parse_config(raw: dict[str, Any], *, base_dir: Path | None = None) -> NexusConfig:
    """Validate a parsed YAML mapping. Relative data paths resolve against ``base_dir``."""
    if not isinstance(raw, dict):
        raise ConfigError("Config must be a YAML mapping at its root.")
    base = base_dir or Path.cwd()
    warnings: list[str] = []

    providers_raw = raw.get("providers", [])
    if not isinstance(providers_raw, list):
        raise ConfigError("'providers' must be a list.")
    if not all(isinstance(item, dict) for item in providers_raw):
        raise ConfigError("Every item in 'providers' must be a mapping.")
    providers = tuple(ProviderConfig.from_dict(item) for item in providers_raw)
    ids = [p.id for p in providers]
    if len(ids) != len(set(ids)):
        raise ConfigError("Provider ids must be unique.")

    server_raw = raw.get("server", {}) or {}
    tool_mode = str(server_raw.get("tool_mode", raw.get("tool_mode", "compact"))).lower()
    if tool_mode not in {"compact", "namespaced"}:
        raise ConfigError("'tool_mode' must be 'compact' or 'namespaced'.")

    workspace = raw.get("workspace", {}) or {}
    if not isinstance(workspace, dict):
        raise ConfigError("'workspace' must be a mapping.")
    allowed_roots_raw = workspace.get("allowed_roots", raw.get("allowed_roots", []))
    if not isinstance(allowed_roots_raw, list) or not all(isinstance(v, str) and v.strip() for v in allowed_roots_raw):
        raise ConfigError("'allowed_roots' must be a list of non-empty path strings.")
    allowed_roots: list[str] = []
    for root in allowed_roots_raw:
        expanded, missing = expand_env(root)
        if missing:
            warnings.append(f"allowed_roots entry {root!r} references unset variables {missing}; ignored.")
            continue
        allowed_roots.append(_resolve_relative(expanded, base))
    max_size = workspace.get("max_artifact_size_mb", raw.get("max_target_size_mb", 250))
    max_size = _int(max_size, "'max_target_size_mb'", 1, 1024 * 64)
    for key in ("data_dir", "allowed_roots"):
        # 0.1 accepted these at the top level; the workspace section wins. Say so instead of
        # silently ignoring a top-level value (a misplaced data_dir once sent writes elsewhere).
        if key in raw and key in workspace and raw[key] != workspace[key]:
            warnings.append(f"'{key}' is set both at the top level and under 'workspace'; the workspace value is used.")
    data_dir = _resolve_relative(str(workspace.get("data_dir", raw.get("data_dir", "./data"))), base)
    follow_symlinks = _bool(workspace.get("follow_symlinks", False), "workspace.follow_symlinks")

    policy_raw = raw.get("policy", {}) or {}
    if not isinstance(policy_raw, dict):
        raise ConfigError("'policy' must be a mapping.")
    read_only_value = policy_raw.get("read_only", raw.get("read_only", True))
    if not isinstance(read_only_value, bool):
        raise ConfigError("'read_only' must be true or false.")
    blocked = _str_list(
        policy_raw.get("global_blocked_tool_patterns", raw.get("global_blocked_tool_patterns", [])),
        "'global_blocked_tool_patterns'",
    )
    _check_regexes(blocked, "Global policy")
    dynamic_raw = policy_raw.get("dynamic_analysis", {}) or {}
    if not isinstance(dynamic_raw, dict):
        raise ConfigError("'policy.dynamic_analysis' must be a mapping.")
    dynamic = DynamicPolicy(
        enabled=_bool(dynamic_raw.get("enabled", False), "policy.dynamic_analysis.enabled"),
        authorized_devices=_str_list(dynamic_raw.get("authorized_devices", []), "authorized_devices"),
        authorized_targets=_str_list(dynamic_raw.get("authorized_targets", []), "authorized_targets"),
        allowed_tools=_str_list(dynamic_raw.get("allowed_tools", []), "allowed_tools"),
    )
    if dynamic.enabled and not (dynamic.authorized_devices and dynamic.authorized_targets):
        raise ConfigError(
            "policy.dynamic_analysis.enabled requires non-empty authorized_devices and "
            "authorized_targets (the device ids and app identifiers you are authorised to test)."
        )
    if _bool(policy_raw.get("allow_lifecycle_passthrough", False), "policy.allow_lifecycle_passthrough"):
        raise ConfigError(
            "policy.allow_lifecycle_passthrough was removed: lifecycle tools take filesystem paths that bypass "
            "workspace.allowed_roots. Admit targets with nexus_inspect_target instead."
        )
    policy = PolicyConfig(
        read_only=read_only_value,
        allow_code_execution=_bool(policy_raw.get("allow_code_execution", False), "policy.allow_code_execution"),
        code_execution_providers=_str_list(policy_raw.get("code_execution_providers", []), "code_execution_providers"),
        allow_lifecycle_passthrough=False,
        allow_remote_ai=_bool(policy_raw.get("allow_remote_ai", False), "policy.allow_remote_ai"),
        allow_remote_providers=_bool(policy_raw.get("allow_remote_providers", False), "policy.allow_remote_providers"),
        dynamic=dynamic,
        global_blocked_tool_patterns=blocked,
    )
    if policy.allow_code_execution and not policy.code_execution_providers:
        raise ConfigError("policy.allow_code_execution requires an explicit code_execution_providers list.")

    analysis_raw = raw.get("analysis", {}) or {}
    if not isinstance(analysis_raw, dict):
        raise ConfigError("'analysis' must be a mapping.")
    depth = str(analysis_raw.get("default_depth", "standard")).lower()
    if depth not in DEPTHS:
        raise ConfigError(f"analysis.default_depth must be one of {sorted(DEPTHS)}.")
    comparison = str(analysis_raw.get("cross_engine_comparison", "explicit")).lower()
    if comparison not in {"explicit", "auto"}:
        raise ConfigError("analysis.cross_engine_comparison must be 'explicit' or 'auto'.")
    analysis = AnalysisConfig(
        default_depth=depth,
        operation_timeout_seconds=_int(
            analysis_raw.get("operation_timeout_seconds", 600), "analysis.operation_timeout_seconds", 5, 7200
        ),
        max_concurrent_provider_calls=_int(
            analysis_raw.get("max_concurrent_provider_calls", 2), "analysis.max_concurrent_provider_calls", 1, 32
        ),
        max_functions_to_decompile=_int(
            analysis_raw.get("max_functions_to_decompile", 5), "analysis.max_functions_to_decompile", 0, 200
        ),
        cross_engine_comparison=comparison,
        ai_enhancement=_bool(analysis_raw.get("ai_enhancement", False), "analysis.ai_enhancement"),
        max_failover=_int(analysis_raw.get("max_failover", 1), "analysis.max_failover", 0, 8),
        raw_output_limit_kb=_int(
            analysis_raw.get("raw_output_limit_kb", 256), "analysis.raw_output_limit_kb", 1, 16384
        ),
    )

    routing_raw = (raw.get("routing", {}) or {}).get("preferred", {}) or {}
    if not isinstance(routing_raw, dict):
        raise ConfigError("'routing.preferred' must map operations to provider id lists.")
    routing: dict[str, tuple[str, ...]] = {}
    for operation, order in routing_raw.items():
        order_t = _str_list(order, f"routing.preferred[{operation!r}]")
        unknown = [pid for pid in order_t if pid not in ids and pid != "builtin"]
        if unknown:
            raise ConfigError(f"routing.preferred[{operation!r}] references unknown providers {unknown}.")
        routing[str(operation)] = order_t

    groups: dict[str, list[str]] = {}
    for provider in providers:
        if provider.enabled and provider.conflict_group:
            groups.setdefault(provider.conflict_group, []).append(provider.id)
    for group, members in groups.items():
        if len(members) > 1:
            warnings.append(
                f"conflict_group {group!r} has several enabled providers {members}; Nexus serialises "
                "them per target and gives each its own staged copy, but they will not be used concurrently."
            )
    for provider in providers:
        if provider.enabled and provider.kind == "dynamic" and not policy.dynamic.enabled:
            warnings.append(
                f"provider {provider.id!r} is dynamic; it stays stopped until policy.dynamic_analysis.enabled."
            )

    audit_log = _resolve_relative(str(raw.get("audit_log", str(Path(data_dir) / "audit.jsonl"))), base)
    evidence_db = _resolve_relative(str(raw.get("evidence_db", str(Path(data_dir) / "evidence.sqlite3"))), base)

    return NexusConfig(
        providers=providers,
        tool_mode=tool_mode,
        read_only=policy.read_only,
        audit_log=audit_log,
        evidence_db=evidence_db,
        allowed_roots=tuple(allowed_roots),
        max_target_size_mb=max_size,
        global_blocked_tool_patterns=blocked,
        data_dir=data_dir,
        follow_symlinks=follow_symlinks,
        policy=policy,
        analysis=analysis,
        routing=routing,
        warnings=tuple(warnings),
    )


def load_config(path: str | Path | None = None) -> NexusConfig:
    """Load the YAML config and fail early with actionable validation errors."""
    configured_path = path or os.environ.get("REVENG_NEXUS_CONFIG", "config/providers.yaml")
    config_path = Path(configured_path).expanduser().resolve()
    if not config_path.is_file():
        raise FileNotFoundError(
            f"Config not found: {config_path}\n"
            "Copy config/providers.example.yaml to config/providers.yaml and edit the provider commands."
        )
    with config_path.open("r", encoding="utf-8") as handle:
        try:
            raw = yaml.safe_load(handle) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML syntax error in {config_path}: {exc}") from exc
    # Relative data paths are anchored to the project root when the config lives in config/.
    base = config_path.parent.parent if config_path.parent.name == "config" else config_path.parent
    config = parse_config(raw, base_dir=base)
    return replace(config, config_path=str(config_path))
