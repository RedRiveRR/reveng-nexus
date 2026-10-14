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

## Test accounting

The suite collects **165 tests**. Two are environment-gated, not failing:

- `tests/integration/test_ghidra_live.py::test_live_ghidra_providers_end_to_end` is
  skipped unless `REVENG_NEXUS_LIVE_GHIDRA=1` and `GHIDRA_INSTALL_DIR` are set.
- `tests/test_artifacts_formats.py::test_guard_refuses_symlinks` is skipped when the OS
  refuses to create a symlink (Windows without Developer Mode or admin). Its assertion is
  unchanged; on a host that allows symlinks it runs.

No test is deselected by marker configuration. `-m integration` only narrows a run.

Earlier versions of this file and the README disagreed. A draft README said "159 passing",
which was a count predicted before the final run, not an observed one. The suite had
already grown from 154 to 160 tests over that session. This session added 5 tests (static
diagnostics, `config init --create-dirs`, non-loopback HTTP refusal, DNS-rebinding
rejection, background provider start), giving 165. Every count below was observed.

## Results on the integration machine (2026-10-13, permanent deployment)

Environment: Windows 11 Pro 10.0.26200, Python 3.12.13 in `%LOCALAPPDATA%\RevEngNexus\venv`,
mcp 2.3.0, Temurin JDK 25.0.2, Ghidra 12.1.4 at
`%LOCALAPPDATA%\Programs\Ghidra\ghidra_12.1.4_PUBLIC` (zip SHA-256 `ddac49f9…d2d4db`,
matching GitHub's published digest), uv/uvx and Claude Code 2.1.296. No IDA, Binary Ninja,
Maven, adb or Frida.

| Command | Collected | Passed | Skipped | Failed | Deselected |
|---|---|---|---|---|---|
| `python -m pytest -q -rs` | 165 | **163** | 2 (live Ghidra, symlink) | 0 | 0 |
| `REVENG_NEXUS_LIVE_GHIDRA=1 GHIDRA_INSTALL_DIR=<ghidra> python -m pytest tests/integration -m integration -v` | 1 | **1** | 0 | 0 | 0 |
| same env, `python -m pytest -q -rs` (combined) | 165 | **164** | 1 (symlink) | 0 | 0 |

| Other check | Result |
|---|---|
| `python -m compileall -q src tests` | ok |
| `ruff check src tests` / `ruff format --check src tests` | all checks passed / all files formatted |
| `python -m mypy src --ignore-missing-imports` | no issues in 35 source files |
| `reveng-nexus --config config/providers.example.yaml --check-config` | valid; exit 0 |
| `reveng-nexus --config %LOCALAPPDATA%\RevEngNexus\config\providers.yaml --check-config` | valid; 0 diagnostics; exit 0 |
| Wheel built with `uv build` and installed into a fresh venv | `--version` 0.2.0; `--check-config` ok from outside the repo |
| `providers check` (permanent config, real Ghidra) | exit 0; `builtin` ready; `ghidra_remcp` ready, 134 tools / 41 callable, 9 binary operations; `ghidra_mcpy` ready (per-target, no live session) |
| `analyze <workspace>\nexus_fixture.elf --compare` (permanent config) | exit 0; 0 failed steps; 5 functions decompiled by `ghidra_remcp`; `_start` comparison: decompilation `same_family_consistency` (ghidra ×2), disassembly `independent_agreement` (ghidra + capstone), overall `same_family_consistency` / medium |
| `report <case>` | Markdown/JSON written to the data dir; contains Ghidra's real pseudocode (`add_numbers(2,3)`, `0x1337`) |
| Evidence retrieval | decompile evidence readable with provider, original tool, engine family and raw-output hash |
| Sample integrity | SHA-256 and mtime of the workspace sample unchanged after analysis; workspace contains only the sample |
| Processes after exit | no Ghidra, provider or gateway process left running |
| `claude mcp get reveng-nexus` (user scope) | Status: ✔ Connected |
| `claude -p … --allowedTools mcp__reveng-nexus__nexus_status mcp__reveng-nexus__nexus_list_targets` | both tools called through Claude Code; results contained the permanent config path and the five real case titles from the evidence DB |

Defects found and fixed during live verification, each now covered by a test:

0. (Claude Code run) The gateway started every provider before answering MCP `initialize`, so
   Claude Code listed it as *pending* and the first tool search found nothing. Providers now start
   in the background (`test_gateway_answers_handshake_while_slow_providers_start`).
   The health label for server-reported versions was also made unambiguous.

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
| Linux/macOS | only Windows was available; POSIX branches (process groups) are unexercised |
| Symlink refusal | needs Developer Mode/admin on this host (junction/symlink code path is skipped, not failed) |
