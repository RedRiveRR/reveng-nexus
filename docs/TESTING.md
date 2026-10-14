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
| Every generated fixture (ELF, PE, Mach-O thin/universal, APK): recognition, metadata, truncation, evidence retention, unchanged original | `test_builtin_fixtures.py` |
| Evidence persistence, 0.1 → 2 migration, raw outputs, AI provenance rules, findings, reviews, links | `test_evidence.py` |
| Cross-engine comparison: independence, rebasing, disagreement preservation, AI checks, per-group verdicts | `test_compare.py` |
| Built-in provider operations, hash-change detection, capability errors | `test_builtin_provider.py` |
| MCP provider lifecycle, paginated discovery, catalogue enforcement, audit, staging, timeout, crash and restart, error normalisation, missing executable and env, dynamic skip, launched HTTP, process-tree reaping, minimal child env, stale engine DB rebuild, handshake bounded by the startup (not per-call) timeout and abandoned without a livelock | `test_mcp_providers.py` |
| Source-verified adapters (`ida_rs`, `binary_ninja`, `jadx`) against mock MCP servers: config/missing install, discovery and classification, normalised success with evidence provenance, unsupported operations, Binary Ninja wrong-view refusal, error propagation, unexpected payloads, timeout, cancellation, crash/restart, database switching and shutdown | `test_adapters_mocked.py` (mock: `mock_servers/mock_adapters.py`, built from the pinned source: [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)) |
| Routing priority and preference, duplicate detection, sequential failover, per-provider serialisation, conflict-group locks, parallelism across engines, workflows | `test_routing_orchestrator.py` |
| LLM4Decompile prompt format, provenance, model verification, substitution refusal, remote-endpoint gating | `test_llm4decompile.py` |
| Report export (Markdown/JSON), fence-injection safety | `test_report.py` |
| MCP tool schemas, annotations, validation errors, end-to-end case over MCP, APK tools, namespaced mode, **gateway as a stdio subprocess**, **loopback Streamable HTTP** | `test_server.py` |
| CLI commands | `test_cli.py` |
| **Real Ghidra** through re-mcp-ghidra and MCPyGhidra | `tests/integration/test_ghidra_live.py` (opt-in) |

## Test accounting

The suite collects **260 tests** (165 until 2026-10-13; on 2026-10-14: 17 in the regression re-run, 44 in the afternoon (43 adapter mock tests, 1 handshake test), 34 in the evening (upstream-contract regressions and previously uncovered paths)). Two are environment-gated, not failing:

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

## Upstream contract corrections (2026-10-14, evening)

The first mock fixtures for `ida_rs`, `binary_ninja` and `jadx` encoded the adapter author's
assumptions. The pinned upstream source (JADX `4e6d890`, Binary Ninja MCP `8c5134e`,
ida-mcp-rs `15d16ab`, the same revisions as the adapter pins) was read as data and the mocks were
rebuilt from it; the per-tool contract is in [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md). Nothing
upstream was installed, downloaded or launched. These adapters stay `mock_tested`: a corrected mock
is a reading of code, not a live run.

**Defects found and fixed** (pre-existing in HEAD unless noted):
1. JADX string results (`get_class_source`, `get_android_manifest`, `get_main_activity_class`) are
   `json.dumps(str)`; Nexus stored the quoted, escaped literal as Java source / XML. Now decoded
   exactly once; `@`-bookkeeping entries (`@truncated`, `@outline`, ...) are warnings, not data;
   partial class source is kept verbatim and flagged.
2. The Binary Ninja bridge never sets `isError`, prefixes some answers with `File: <path>` and
   returns the plugin's JSON body as text. Nexus turned the preamble into a function, error text
   into HLIL / listing rows, JSON bodies into fabricated entries, and could not decompile by address.
   Now: in-band errors are raised (bounded message), the preamble must name the target, bodies are
   parsed per operation, an address inside several functions is refused as ambiguous.
3. ida-mcp-rs strings carry `content` (Nexus read `value`: always `None`), imports have no module
   (read as `module`), and `decompile`, `xrefs_*`, `basic_blocks` accept numeric addresses only
   (Nexus sent names; the old mock accepted them). Names are now resolved to exactly one address via
   `list_functions`; `entry_point` stays unknown and `main_address` is reported separately.
4. Truncated Mach-O input made `inspect_file` raise `struct.error` (32- and 64-bit, and the fat
   header); `identify()` hid it and all metadata was lost. Now parsing stops at the first command
   that runs past the end, keeps what is complete and sets `truncated`.
5. `close()` ended with an unbounded `await` after a native cancel, so a connection task that
   swallows cancellation hung the gateway. Every wait is now bounded; such a task is reported and
   abandoned.
6. (Introduced earlier the same day, never committed.) A re-list could wait the per-page client
   timeout on each of up to 100 pages. One deadline now covers the whole pagination (see
   [ARCHITECTURE.md](ARCHITECTURE.md#timeouts-and-their-bounds-since-2026-10-14)).

**Baseline against HEAD.** The new tests were run against HEAD `6bbddad` from a byte-identical
snapshot outside the repository (`PYTHONPATH=C:\tmp\rnx-lab\head-tree\src`, bytecode writing off):
34 of the 35 new tests fail there, each for the defect it pins. Exceptions:
`test_connection_owner_close_is_bounded_when_cooperative_cancel_is_ignored` passes on HEAD too
(a characterisation test: HEAD's native-cancel fallback already handled it), and
`test_connection_owner_close_abandons_a_task_that_swallows_cancellation` **hangs** on HEAD
(faulthandler at 30 s, killed at 60 s) and passes in 1.3 s now. Tests were written after the
fixes; what is established is the HEAD-fail / working-tree-pass contrast, not a test-first
chronology.

**Tests added for previously uncovered paths:** the `mcp_launched_http` startup branch (handshake
answered after 3 s with a 1 s call timeout); the bounded shutdown fallback (two cases, neither can
hang the suite); the shared session reset after a reconnect, through re_mcp and JADX; ida-mcp-rs
non-object decompile payloads and list operations without a recognised list; Binary Ninja list,
xref and disassembly parsing, textual errors, foreign or missing views, ambiguity; JADX malformed
JSON, wrong JSON types and plain-text fallback; the 32-bit `LC_SEGMENT` path, universal slice
offsets and truncation at every boundary.

| Final run (2026-10-14 evening, working tree) | Collected | Passed | Skipped | Failed | Exit |
|---|---|---|---|---|---|
| `python -m pytest -q -p no:cacheprovider -rfEs` | 260 | **258** | 2 (live Ghidra, symlink) | 0 | 0 |
| same with `REVENG_NEXUS_LIVE_GHIDRA=1`, `GHIDRA_INSTALL_DIR=<Ghidra 12.1.4>` | 260 | **259** | 1 (symlink) | 0 | 0 |
| live test alone within that run | 1 | 1 (77.4 s, real Ghidra) | 0 | 0 | — |

| Other check | Result |
|---|---|
| `ruff check src tests scripts` / `ruff format --check src tests scripts` | all checks passed / 63 files already formatted |
| `python -m mypy src --ignore-missing-imports` | no issues in 35 source files |
| `python -m compileall -q src tests scripts` | exit 0 |
| `--check-config` (example / permanent) | exit 0 / exit 0 (example: the 2 expected warnings) |
| Permanent evidence DB, `mode=ro` | `integrity_check` ok; 0 foreign-key violations; schema 1–2; 79 rows; 0 with missing raw output or unknown target |
| Processes after the runs | no Java, mock-server, pytest or load-generator process left |

Logs: `C:\tmp\rnx-lab\flaky-investigation\final2-*` and `contracts-*` (one `.log` and JUnit `.xml`
per run, never overwritten).

## Intermittent-failure investigation and adapter mocks (2026-10-14, afternoon)

Durable logs: `C:\tmp\rnx-lab\flaky-investigation\` (one `.log` and one JUnit `.xml` per run, never overwritten; outside the repo).

**Original failure.** The failing run's log, pytest cache and temp directory were already gone, so the test that failed then is **still unidentified**.

| Run | Repetitions | Result |
|---|---|---|
| Combined (live Ghidra on), unchanged code, normal load | 8 | 8 × (181 passed, 1 skipped), 0 failures |
| *Experiment:* upper-bound timing tests under full CPU saturation (8 busy loops, 8 cores), unchanged code | 10 | `test_timeout_is_bounded_and_other_providers_keep_working` failed **10/10**: `ProviderUnavailable … failed to connect: MCPError: Request 'initialize' timed out` |
| Same experiment after the fixes | 10 | 0/10 such failures; `test_gateway_answers_handshake_while_slow_providers_start` (< 6 s) failed 2/10 (6.7 s) |
| A/B, gateway handshake under saturation, HEAD vs working tree alternating | 10 + 10 | median 1.22 s for both; HEAD max 15.08 s (1 run ≥ 6 s), working tree max 1.33 s |

**Defects found and fixed.** Each has a regression test. The chronology was not always test-first (the tests for defect 4 were written after its fix); what is established is that the relevant tests were subsequently run against HEAD `6bbddad` (a byte-identical snapshot outside the repo) and fail there, while they pass on the working tree:
1. The MCP client's default read timeout was the per-call `timeout_seconds`, and it also bounds the `initialize` handshake and `tools/list`. A child slower to answer than one tool call is allowed to take failed to connect, although `startup_timeout_seconds` allowed it. Reproduced deterministically without load (`MOCK_STARTUP_DELAY=3`, `timeout_seconds=1`). The default is now `max(timeout_seconds, startup timeout)`; tool calls still pass `timeout_seconds` explicitly (`test_handshake_is_bounded_by_startup_timeout_not_call_timeout`).
2. **Older, latent:** abandoning a handshake that never completes used a native `task.cancel()`. That defeats the MCP SDK's shielded transport shutdown, so the child was never stopped and anyio re-delivered cancellation forever (≈3.4 M re-cancellations in 30 s in a probe; it also hangs with HEAD's timeout semantics whenever `startup_timeout_seconds < timeout_seconds`). The connection now runs in an anyio cancel scope that `close()` cancels cooperatively; native cancel is a last resort. The same test pins it (abandoned within the 2 s startup bound plus shutdown, ≈5 s).
3. A reconnect triggered *inside* the call that opens a target replaced the adapter session dict, so the new session record was lost and the next target switch never sent `close_idb` (ida-mcp-rs keeps one database per server). Sessions are now reset in place (`test_ida_rs_reopens_after_crash_and_switches_databases`).
4. The source-verified adapters re-read an unexpected JSON payload as text lines (Binary Ninja/JADX reported the JSON document as an import/class name) and labelled unexpected JSON as Hex-Rays pseudocode, HLIL or JADX Java. List operations now return an empty result plus a warning, with the raw output kept as evidence; code operations fail the attempt (`test_unexpected_list_payloads_are_flagged_not_fabricated`, `test_unexpected_code_payloads_are_not_labelled_as_code`).

Defects 1 and 2 are **confirmed** bugs. Whether they caused the original intermittent failure is **not established**: the failing test was never identified. They are a probable explanation of the original failure (it came right after the CPU-heavy live Ghidra test), but that is **not proven**. The gateway-handshake threshold is left unchanged: the A/B shows rare scheduling outliers under artificial saturation on both code versions, and it never failed in the 8 normal-load combined runs.

**Adapter mock tests.** `tests/mock_servers/mock_adapters.py` serves the pinned tool and argument names of ida-mcp-rs, the Binary Ninja bridge and jadx-mcp-server over real MCP stdio, with hardcoded data (its response envelopes were corrected to the pinned upstream source the same evening, see below); the target is only checked to exist, never read or executed. `tests/test_adapters_mocked.py` has 43 tests: config/missing install, discovery and classification (including mis-annotated dangerous tools), policy blocks before the server is reached, normalised success with provenance for every bound operation, unsupported operations, Binary Ninja wrong-view refusal, error propagation and failover, unexpected payloads, timeout, cancellation, crash/restart, database switching and shutdown. These make the three adapters `mock_tested`, not upstream-verified.

| Final check (working tree) | Result |
|---|---|
| `python -m pytest -q -rfEs` | 226 collected → **224 passed**, 2 skipped (live Ghidra, symlink), 0 failed |
| combined, `REVENG_NEXUS_LIVE_GHIDRA=1` | 226 → **225 passed**, 1 skipped (symlink), 0 failed; live Ghidra test passed (48.1 s); no Java process left |
| `tests/test_mcp_providers.py` + `tests/test_adapters_mocked.py` | 58 passed; 0 mock-server processes alive afterwards |
| `ruff check` / `ruff format --check` (src, tests, scripts) | all checks passed / 63 files already formatted |
| `python -m mypy src --ignore-missing-imports` | no issues in 35 source files |
| `python -m compileall -q src tests scripts` | exit 0 |
| `--check-config` (example / permanent) | exit 0 / exit 0 (example: the 2 expected warnings) |
| Permanent evidence DB, opened `mode=ro` | `integrity_check` ok; 0 foreign-key violations; 79 evidence rows; 0 with missing raw output or unknown target |

## Results on the integration machine (2026-10-14, regression re-run)

Same environment as below, using the permanent venv (`%LOCALAPPDATA%\RevEngNexus\venv`) and
Ghidra 12.1.4. **Baseline** = HEAD `6bbddad` before any change today; **after** = with
today's working-tree changes (17 new tests).

| Command | Collected | Passed | Skipped | Failed | Deselected | Exit |
|---|---|---|---|---|---|---|
| baseline `python -m pytest -q -rs` | 165 | 163 | 2 (live Ghidra, symlink) | 0 | 0 | 0 |
| after `python -m pytest -q -rs` | 182 | **180** | 2 (live Ghidra, symlink) | 0 | 0 | 0 |
| after, live test only: `REVENG_NEXUS_LIVE_GHIDRA=1 GHIDRA_INSTALL_DIR=<ghidra> python -m pytest tests/integration -m integration -v -W error::ResourceWarning` | 1 | **1** | 0 | 0 | 0 | 0 |
| after, combined (live enabled): `python -m pytest -q -rs`, run 5 times | 182 | **181** in 4 runs | 1 (symlink) | 0 in 4 runs; **1 in 1 run** (unidentified, see below) | 0 | 0 ×4, 1 ×1 |

| Other check (after) | Result |
|---|---|
| `ruff check src tests scripts` | all checks passed (exit 0) |
| `ruff format --check src tests scripts` | 61 files already formatted (exit 0) |
| `python -m mypy src --ignore-missing-imports` | no issues in 35 source files (exit 0) |
| `python -m compileall -q src tests scripts` | exit 0 |
| `--check-config` (example / permanent config) | exit 0 / exit 0 (example: 2 expected warnings: no workspace, data dir inside OneDrive) |
| Focused subsets (baseline) | MCP handshake + tools `tests/test_server.py`: 11 passed; failure/timeout/crash/cleanup selection: 9 passed; redaction/audit: 5 passed; evidence store: 11 passed |
| Permanent evidence DB (read-only) | `PRAGMA integrity_check` ok; 0 foreign-key violations; schema 1–2; no evidence row with a missing raw output or unknown target |

**Live Ghidra (permanent config), 2026-10-14:**
- `analyze nexus_fixture.elf --compare` exit 0 with 0 failed steps. 16 evidence rows (4 `direct_observation`, 12 `engine_derived`), all tied to the target SHA-256.
- The `main` decompile (provider `ghidra_remcp`, tool `decompile_function`, family `ghidra`) contains Ghidra's real pseudocode. Its raw output is stored (657 bytes, not truncated). Comparison verdict: `same_family_consistency` (decompilation) / `independent_agreement` (disassembly, identity).
- Sample SHA-256 and mtime unchanged.
- No process left by the CLI runs. The `reveng-nexus serve` tree that was still running belongs to the Claude Code session that launched it (parent `claude.exe`), as expected.
- **Ghidra unavailable** (wrong `GHIDRA_INSTALL_DIR`, throwaway config and data dir): `--check-config` warns for both Ghidra providers. Built-in steps succeed, `ghidra_mcpy` fails fast (`provider_unavailable`, ~0.4 s per call), and there are no tracebacks.
- **Timeout** (`analysis.operation_timeout_seconds: 5`): the first two calls ended at 5016/5015 ms as `provider_timeout`. Later decompiles succeeded once the database finished opening. No tracebacks.

**Defects found today and fixed (each with a regression test):**
1. A provider that answers MCP but can perform none of its operations reported `ready`, and `providers check` exited 0. Seen live with re-mcp-ghidra and a wrong `GHIDRA_INSTALL_DIR`: it lists 7 meta tools. Now `degraded` and exit 1, and the capability reason names the possible backend failure and the log path (`test_connected_provider_without_usable_operations_is_degraded`, `test_providers_check_fails_when_no_operation_is_usable`).
2. `analyze` reported no missing capability when every decompile failed (`test_all_failed_decompiles_are_reported_as_missing`).
3. **Pre-existing bug:** the Mach-O parser recorded no segment file offsets, so mapping a Mach-O address raised `KeyError: 'offset'`. Confirmed against the committed parser. Fixed, and covered by `tests/test_builtin_fixtures.py`, which also adds a generated Mach-O fixture (thin + universal) built from Python source.

**Intermittent failure:** one combined run (live enabled) reported `1 failed, 180 passed, 1 skipped`. Its log was overwritten before the failing test was identified (my error). Four further combined runs all passed. The follow-up investigation, with durable logs, is in the section above.

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
| Frida Mobile MCP | no authorised test device (dynamic analysis is disabled by design); **no mock contract tests either**, only policy/gating unit tests |
| LLM4Decompile with real weights | no GPU or served checkpoint; weights deliberately not downloaded |
| GhidrAssist → Nexus over HTTP | no Ghidra GUI session; only Nexus' HTTP endpoint is tested |
| Linux/macOS | only Windows was available; POSIX branches (process groups) are unexercised |
| Symlink refusal | needs Developer Mode/admin on this host (junction/symlink code path is skipped, not failed) |
| ida-mcp-rs, Binary Ninja and JADX against the real upstream | only `mock_tested` (since 2026-10-14): the mock fixtures follow the pinned upstream source ([ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)), which is a reading of code, not a live run; live use is blocked (no IDA licence, Binary Ninja or Maven) |
| Mach-O symbols, functions and imports | the built-in parser decodes headers, segments, dylibs and `LC_MAIN` only, so `binary.functions` returns nothing for Mach-O |
| REA (`rea-agents`) | evaluation paused on 2026-10-14; not integrated, no tests (installed Node 25.9.0 is outside its supported range) |
| `ida_official`, `re_mcp_ida`, `binary_ninja` via `providers check` | not launched on 2026-10-14, because their `uvx`/`npx` commands would download upstream packages for engines that are not installed |
