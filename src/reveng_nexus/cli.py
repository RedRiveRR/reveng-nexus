"""Command-line interface.

``reveng-nexus`` with no sub-command (or ``serve``) runs the MCP server over stdio;
nothing but MCP protocol traffic is written to stdout in that mode.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import NexusConfig, load_config
from .errors import NexusError, describe_exception


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _load(args: argparse.Namespace) -> NexusConfig:
    try:
        return load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _config_summary(config: NexusConfig) -> dict[str, Any]:
    from .adapters import ADAPTERS

    return {
        "config": config.config_path,
        "tool_mode": config.tool_mode,
        "read_only": config.policy.read_only,
        "dynamic_analysis": config.policy.dynamic.enabled,
        "allowed_roots": list(config.allowed_roots),
        "data_dir": config.data_dir,
        "providers": [
            {
                "id": p.id,
                "type": p.type,
                "adapter": p.adapter,
                "engine": p.engine or (ADAPTERS[p.adapter].engine if p.adapter in ADAPTERS else ""),
                "kind": p.kind,
                "enabled": p.enabled,
            }
            for p in config.providers
        ],
        "warnings": list(config.warnings),
    }


async def _with_manager(config: NexusConfig, fn, only: list[str] | None = None):
    from .registry import ProviderManager

    manager = ProviderManager(config)
    await manager.start(only=only)
    try:
        return await fn(manager)
    finally:
        await manager.close()


def cmd_check_config(args: argparse.Namespace) -> int:
    config = _load(args)
    enabled = [p.id for p in config.providers if p.enabled]
    print(f"Config valid. Providers defined: {len(config.providers)}; enabled: {enabled or 'none'}")
    print(
        f"Tool mode: {config.tool_mode}; read-only: {config.policy.read_only}; "
        f"dynamic analysis: {config.policy.dynamic.enabled}"
    )
    print(f"Workspace roots: {list(config.allowed_roots) or 'none (target intake disabled)'}")
    print(f"Data directory: {config.data_dir}")
    for warning in config.warnings:
        print(f"warning: {warning}")
    from .diagnostics import diagnose

    findings = diagnose(config)
    for finding in findings:
        print(finding.render())
    errors = [f for f in findings if f.level == "error"]
    if findings:
        print(f"Diagnostics: {len(errors)} error(s), {len(findings) - len(errors)} warning(s)")
    return 1 if errors else 0


def _find_example(explicit: str | None) -> Path | None:
    candidates = [Path(explicit)] if explicit else []
    candidates += [
        Path.cwd() / "config" / "providers.example.yaml",
        Path(__file__).resolve().parents[2] / "config" / "providers.example.yaml",
    ]
    return next((c for c in candidates if c.is_file()), None)


def cmd_config_init(args: argparse.Namespace) -> int:
    """Write a validated user config derived from the example, enabling only what was asked."""
    import yaml

    from .config import parse_config

    example = _find_example(args.example)
    if example is None:
        print("providers.example.yaml not found; pass --example PATH", file=sys.stderr)
        return 2
    output = Path(args.output).expanduser().resolve()
    if output.exists() and not args.force:
        print(f"{output} exists; pass --force to overwrite", file=sys.stderr)
        return 2
    raw = yaml.safe_load(example.read_text(encoding="utf-8"))
    workspace = [str(Path(w).expanduser().resolve()) for w in args.workspace]
    for w in workspace:
        if not Path(w).is_dir():
            if args.create_dirs:
                Path(w).mkdir(parents=True, exist_ok=True)
                print(f"Created workspace folder {w}")
            else:
                print(f"workspace folder does not exist: {w} (pass --create-dirs to create it)", file=sys.stderr)
                return 2
    if args.data_dir and args.create_dirs:
        Path(args.data_dir).expanduser().mkdir(parents=True, exist_ok=True)
    raw.setdefault("workspace", {})["allowed_roots"] = workspace
    if args.data_dir:
        # Keep the SQLite evidence DB out of synced folders (OneDrive/Dropbox) when possible.
        raw["workspace"]["data_dir"] = str(Path(args.data_dir).expanduser().resolve())
    known = {p["id"] for p in raw.get("providers", [])}
    unknown = [pid for pid in args.enable if pid not in known]
    if unknown:
        print(f"unknown provider ids: {unknown}; choose from {sorted(known)}", file=sys.stderr)
        return 2
    for provider in raw.get("providers", []):
        if provider.get("type") == "builtin":
            provider["enabled"] = True
            continue
        provider["enabled"] = provider["id"] in args.enable
        if args.ghidra_dir and provider.get("engine") == "ghidra":
            provider.setdefault("env", {})["GHIDRA_INSTALL_DIR"] = str(Path(args.ghidra_dir).resolve())
        if args.ida_dir and provider.get("engine") == "ida":
            provider.setdefault("env", {})["IDADIR"] = str(Path(args.ida_dir).resolve())
            if str(provider.get("command", "")).startswith("${IDADIR}"):
                provider["command"] = provider["command"].replace("${IDADIR}", str(Path(args.ida_dir).resolve()))
    base = output.parent.parent if output.parent.name == "config" else output.parent
    config = parse_config(raw, base_dir=base)
    header = (
        "# Generated by `reveng-nexus config init` from providers.example.yaml.\n"
        "# See the example file for documentation of every key. Keep secrets out of this file.\n"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(header + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"Wrote {output}")
    print(f"Enabled providers: {[p.id for p in config.providers if p.enabled]}")
    for warning in config.warnings:
        print(f"warning: {warning}")
    print(f"Next: reveng-nexus --config {output} providers check")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config = _load(args)
    if args.no_start:
        _print_json(_config_summary(config))
        return 0

    async def run(manager):
        from .server import NexusServer

        return await NexusServer(manager).dispatch("nexus_status", {})

    _print_json(asyncio.run(_with_manager(config, run)))
    return 0


def cmd_providers_list(args: argparse.Namespace) -> int:
    from .adapters import ADAPTERS

    config = _load(args)
    rows = []
    for p in config.providers:
        adapter = ADAPTERS.get(p.adapter or "")
        rows.append(
            {
                "id": p.id,
                "name": p.name,
                "enabled": p.enabled,
                "type": p.type,
                "kind": p.kind,
                "adapter": p.adapter,
                "upstream": adapter.describe() if adapter else None,
            }
        )
    _print_json(rows)
    return 0


def cmd_providers_check(args: argparse.Namespace) -> int:
    """Start each selected provider in isolation, list tools, report health, then stop it."""
    config = _load(args)
    selected = args.ids or [p.id for p in config.providers if p.enabled]
    unknown = [pid for pid in selected if config.provider(pid) is None and pid != "builtin"]
    if unknown:
        print(f"Unknown provider ids: {unknown}", file=sys.stderr)
        return 2
    report: dict[str, Any] = {}
    failed = False
    for pid in ["builtin", *[s for s in selected if s != "builtin"]]:

        async def run(manager, pid=pid):
            provider = manager.providers.get(pid)
            health = (await manager.health()).get(pid, {})
            tools = await provider.list_tools() if provider is not None and provider.started else []
            caps = provider.list_capabilities() if provider is not None and provider.started else {}
            return {
                "health": health,
                "error": manager.provider_errors.get(pid),
                "skipped": manager.skipped.get(pid),
                "tools_total": len(tools),
                "tools_callable": sorted(t.name for t in tools if t.callable),
                "tools_blocked": {t.name: t.decision.reason for t in tools if not t.decision.allowed},
                "capabilities": caps,
            }

        try:
            result = asyncio.run(_with_manager(config, run, only=[pid]))
        except Exception as exc:  # noqa: BLE001
            result = {"health": {"status": "unavailable"}, "error": describe_exception(exc)["message"]}
        if not args.verbose:
            result.pop("tools_blocked", None)
            if len(result.get("tools_callable", [])) > 40:
                result["tools_callable"] = result["tools_callable"][:40] + ["..."]
        report[pid] = result
        status = (result.get("health") or {}).get("status")
        caps = result.get("capabilities") or {}
        health = result.get("health") or {}
        no_usable_ops = (bool(caps) and not any(c.get("available") for c in caps.values())) or (
            "usable_operations" in health and not health["usable_operations"]
        )
        if pid != "builtin" and not result.get("skipped") and (status not in {"ready", "degraded"} or no_usable_ops):
            # A provider that answers but can perform none of its operations is a failed check.
            failed = True
    _print_json(report)
    return 1 if failed else 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    config = _load(args)

    async def run(manager):
        return manager.capability_registry()

    registry = asyncio.run(_with_manager(config, run))
    if args.json:
        _print_json(registry)
        return 0
    for op, rows in registry["operations"].items():
        available = [r["provider_id"] for r in rows if r.get("available")]
        print(f"{op:20s} {', '.join(available) if available else '-- unavailable'}")
    for dup in registry["duplicates"]:
        print(f"note: {dup['operation']} offered by several {dup['engine_family']} providers: {dup['providers']}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    config = _load(args)
    path = str(Path(args.artifact).expanduser().resolve())

    async def run(manager):
        from .orchestrator import Orchestrator

        intake = await manager.intake(path, case_id=args.case_id, case_title=args.case_title)
        target = manager.target_context(intake["target"]["sha256"], intake["case_id"])
        orch = Orchestrator(manager)
        if target.format == "apk":
            result = await orch.analyze_apk(target)
        else:
            result = await orch.analyze_binary(
                target, depth=args.depth, provider_id=args.provider, compare=args.compare, ai=args.ai
            )
        return {"target": intake["target"], "analysis": result}

    try:
        _print_json(asyncio.run(_with_manager(config, run)))
    except NexusError as exc:
        _print_json(exc.to_dict())
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .evidence import EvidenceStore
    from .report import export_report

    config = _load(args)
    store = EvidenceStore(config.evidence_db, config.allowed_roots, config.max_target_size_mb)
    out_dir = Path(args.out).resolve() if args.out else Path(config.data_dir) / "reports"
    try:
        result = export_report(store, args.case_id, out_dir, formats=tuple(args.format), include_raw=args.include_raw)
    except NexusError as exc:
        _print_json(exc.to_dict())
        return 1
    _print_json(result)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    config = _load(args)
    transport = getattr(args, "transport", "stdio")
    if transport == "http" and args.host not in {"127.0.0.1", "localhost", "::1"}:
        # There is no authentication layer, so a non-loopback bind is refused rather than offered.
        print(
            f"Refusing to serve HTTP on {args.host!r}: RevEng Nexus has no authentication and binds "
            "loopback only (127.0.0.1, localhost, ::1). Use stdio, or an authenticated reverse proxy you operate.",
            file=sys.stderr,
        )
        return 2

    async def run() -> None:
        from .registry import ProviderManager
        from .server import serve_http, serve_stdio

        manager = ProviderManager(config)
        # Answer the MCP handshake immediately; providers (JVMs, uvx installs) start in the
        # background and tool calls wait for startup to finish.
        startup = asyncio.create_task(manager.start())
        try:
            if transport == "http":
                await serve_http(manager, args.host, args.port, background_start=True)
            else:
                await serve_stdio(manager, background_start=True)
        finally:
            if not startup.done():
                startup.cancel()
            with contextlib.suppress(BaseException):
                await startup
            await manager.close()

    asyncio.run(run())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reveng-nexus", description="RevEng Nexus MCP gateway")
    parser.add_argument("--version", action="version", version=f"reveng-nexus {__version__}")
    parser.add_argument("--config", help="YAML config path (or set REVENG_NEXUS_CONFIG)")
    parser.add_argument("--check-config", action="store_true", help="Validate config and exit")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("status", help="Show gateway, policy and provider health (starts enabled providers)")
    p.add_argument("--no-start", action="store_true", help="Only summarise the configuration")
    p.set_defaults(func=cmd_status)

    providers = sub.add_parser("providers", help="Provider inventory and checks")
    psub = providers.add_subparsers(dest="providers_command", required=True)
    pl = psub.add_parser("list", help="List configured providers and their upstream pins (no processes started)")
    pl.set_defaults(func=cmd_providers_list)
    pc = psub.add_parser("check", help="Start providers one at a time, list tools, report health")
    pc.add_argument("ids", nargs="*", help="Provider ids (default: all enabled)")
    pc.add_argument("--verbose", action="store_true", help="Also list blocked tools and reasons")
    pc.set_defaults(func=cmd_providers_check)

    c = sub.add_parser("capabilities", help="Show which operations are available from which providers")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_capabilities)

    a = sub.add_parser("analyze", help="Admit an artifact from the workspace and run the static workflow")
    a.add_argument("artifact")
    a.add_argument("--depth", choices=["quick", "standard", "deep"])
    a.add_argument("--provider", help="Explicit decompiler provider id")
    a.add_argument("--compare", action="store_true", default=None, help="Cross-engine comparison of top functions")
    a.add_argument("--ai", action="store_true", default=None, help="Request AI reconstruction (if configured)")
    a.add_argument("--case-id")
    a.add_argument("--case-title")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("report", help="Export a case report (Markdown/JSON)")
    r.add_argument("case_id")
    r.add_argument("--format", nargs="+", choices=["md", "json"], default=["md", "json"])
    r.add_argument("--out", help="Output directory (default: <data_dir>/reports)")
    r.add_argument("--include-raw", action="store_true")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("serve", help="Run the MCP server (default: stdio)")
    s.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.set_defaults(func=cmd_serve)

    cfg = sub.add_parser("config", help="Configuration helpers")
    csub = cfg.add_subparsers(dest="config_command", required=True)
    cc = csub.add_parser("check", help="Validate the configuration")
    cc.set_defaults(func=cmd_check_config)
    ci = csub.add_parser("init", help="Generate a validated providers.yaml from the example")
    ci.add_argument("--workspace", action="append", required=True, help="Folder of authorised samples (repeatable)")
    ci.add_argument("--enable", action="append", default=[], help="Provider id to enable (repeatable)")
    ci.add_argument("--ghidra-dir", help="Ghidra install dir (written into Ghidra providers' env)")
    ci.add_argument("--ida-dir", help="IDA install dir (written into IDA providers' env)")
    ci.add_argument("--data-dir", help="Evidence DB/audit/reports folder (default: ./data)")
    ci.add_argument("--create-dirs", action="store_true", help="Create the workspace and data folders if missing")
    ci.add_argument("--output", default="config/providers.yaml")
    ci.add_argument("--example", help="Path to providers.example.yaml")
    ci.add_argument("--force", action="store_true")
    ci.set_defaults(func=cmd_config_init)
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.check_config:
        raise SystemExit(cmd_check_config(args))
    if not args.command:
        args.transport = "stdio"
        raise SystemExit(cmd_serve(args))
    raise SystemExit(args.func(args))
