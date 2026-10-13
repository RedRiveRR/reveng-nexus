# Testing

## How to run

```powershell
python -m pytest -q                                   # default suite (no external engines)
$env:REVENG_NEXUS_LIVE_GHIDRA = "1"                   # opt-in: real Ghidra
$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra_12.1.4_PUBLIC"
python -m pytest tests/integration -m integration -v
```

The default suite needs no proprietary software, network service or device. Upstream
engines are simulated by **real MCP servers** (`tests/mock_servers/`): processes speaking
MCP 2.3 over stdio (`mock_engine.py`, which mirrors re-mcp's verified contract) and over
launched Streamable HTTP (`mock_launched.py`, which mirrors MCPyGhidra's readiness
protocol). Lifecycle, pagination, timeouts, crashes, failover and process-tree
containment are therefore exercised through the real SDK and real subprocesses.

Fixtures are **generated from Python source** at test time and never executed:
`elf_builder.py` (hand-assembled x86-64 ELF with symbols and calls), `pe_builder.py`
(PE32+ importing `KERNEL32!ExitProcess`) and `apk_builder.py` (ZIP with a binary
AndroidManifest and a DEX header). No binaries are committed.

## Coverage map

| Area | Tests |
|---|---|
| Configuration parsing, validation, env expansion, 0.1 compatibility, `config init` | `test_config.py`, `test_cli.py` |
| Policy and classification, heuristics, dynamic gating, hard blocks, deny patterns | `test_security.py` |
| Redaction, metadata-only audit | `test_redaction_audit.py` |
| Workspace boundary (outside, relative, `..`, prefix sibling, ADS, symlink, size), hashing, staging | `test_artifacts_formats.py` |
| ELF/PE/APK parsing, export rules, strings with VAs, malformed inputs | `test_artifacts_formats.py` |
| Evidence persistence, 0.1 → 2 migration, raw outputs, AI provenance rules, findings, reviews, links | `test_evidence.py` |
| Cross-engine comparison: independence, rebasing, disagreement preservation, AI checks, per-group verdicts | `test_compare.py` |
| Built-in provider operations, hash-change detection, capability errors | `test_builtin_provider.py` |
| MCP provider lifecycle, paginated discovery, catalogue enforcement, audit, staging, timeout, crash and restart, error normalisation, missing executable and env, dynamic skip, launched HTTP, process-tree reaping, minimal child env, stale engine DB rebuild | `test_mcp_providers.py` |
| Routing priority and preference, duplicate detection, sequential failover, per-provider serialisation, conflict-group locks, parallelism across engines, workflows | `test_routing_orchestrator.py` |
| LLM4Decompile prompt format, provenance, model verification, substitution refusal, remote-endpoint gating | `test_llm4decompile.py` |
| Report export (Markdown/JSON), fence-injection safety | `test_report.py` |
| MCP tool schemas, annotations, validation errors, end-to-end case over MCP, APK tools, namespaced mode, **gateway as a stdio subprocess**, **loopback Streamable HTTP** | `test_server.py` |
| CLI commands | `test_cli.py` |
| **Real Ghidra** through re-mcp-ghidra and MCPyGhidra | `tests/integration/test_ghidra_live.py` (opt-in) |

## Results on the integration machine (2026-10-13)

Environment: Windows 11 Pro 10.0.26200, Python 3.12 (uv-managed venv), mcp 2.3.0,
Temurin JDK 25.0.2, Ghidra 12.1.4 (`ddac49f9…d2d4db`, matching GitHub's published digest),
uv/uvx available; no IDA, Binary Ninja, Maven, adb or Frida.

| Command | Result |
|---|---|
| `python -m pytest -q -rs` | **158 passed, 2 skipped** in ~66 s. Skipped: the live Ghidra test (opt-in) and `test_guard_refuses_symlinks` (creating symlinks needs Developer Mode/admin on this host) |
| `REVENG_NEXUS_LIVE_GHIDRA=1 … pytest tests/integration -m integration -W error::ResourceWarning` | **1 passed** in ~40 s |
| `python -m compileall -q src tests` | ok |
| `ruff check src tests` | All checks passed |
| `ruff format --check src tests` | 57 files already formatted |
| `python -m mypy src --ignore-missing-imports` | Success: no issues found in 34 source files |
| `python -m reveng_nexus --config config/providers.example.yaml --check-config` | Config valid; 11 providers; enabled: builtin |
| `uv build --wheel`, then install into a fresh venv | wheel with 39 files; `reveng-nexus --version` = 0.2.0; `--check-config` ok from outside the repo |
| `reveng-nexus providers check ghidra_remcp ghidra_mcpy` (real Ghidra) | exit 0; `ghidra_remcp` ready, 134 tools / 41 callable, all 9 binary operations available; `ghidra_mcpy` ready (one server per target) |
| `reveng-nexus analyze nexus_fixture.elf --compare` (real Ghidra) | exit 0; 5 functions decompiled by ghidra_remcp; comparison of `_start`: decompilation `same_family_consistency` (ghidra ×2), disassembly `independent_agreement` (ghidra + capstone), overall `same_family_consistency`/medium |

Defects found and fixed during live verification, each now covered by a test:

1. re-mcp `open_database` defaults to `run_auto_analysis=False`, which gave 1-byte function
   sizes and missed xrefs and strings. The adapter now always enables it, and the live test
   asserts the `0x400127 → add_numbers` call xref.
2. A Ghidra project left by an interrupted session could not be reopened. Fixed with
   save-on-close plus a single `force_new` rebuild (`test_stale_engine_database_is_rebuilt_once_with_warning`).
3. On Windows, `uvx`-launched MCPyGhidra servers outlived the gateway, because
   `terminate()` killed only the launcher. Fixed with Job Objects
   (`test_launched_server_process_tree_is_reaped`, which fails with the old behaviour).
4. A dead child connection was not detected, because the SDK raises `CONNECTION_CLOSED` per
   request without exiting the client context. Fixed with teardown and reconnect
   (`test_crash_is_isolated_and_provider_restarts`).
5. Comparison counted a Capstone listing as independent confirmation of Ghidra pseudocode.
   Fixed with per-group verdicts (`test_capstone_listing_does_not_upgrade_same_family_pseudocode`).
6. Instruction call targets were not rebased, and C integer suffixes (`2LL`) produced false
   disagreements. Both fixed and tested.

## Not tested (and why)

| Item | Reason |
|---|---|
| Official Hex-Rays ida-mcp, ida-mcp-rs, re-mcp-ida against real IDA | no IDA Pro licence/installation |
| Binary Ninja MCP | no Binary Ninja installation |
| JADX MCP server | Maven not installed; the JVM daemon cannot be built here |
| Frida Mobile MCP | no authorised test device (dynamic analysis is disabled by design) |
| LLM4Decompile with real weights | no GPU or served checkpoint; weights deliberately not downloaded |
| GhidrAssist → Nexus over HTTP | no Ghidra GUI session; only Nexus' HTTP endpoint is tested |
| `claude mcp add …` registration | not run: it changes the user's Claude Code configuration. The same stdio launch is tested with the MCP SDK client |
| Linux/macOS | only Windows was available; POSIX branches (process groups) are unexercised |
| Symlink refusal | needs Developer Mode/admin on this host (junction/symlink code path is skipped, not failed) |
