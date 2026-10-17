# Testing

## How to run

```powershell
python -m pytest -q                                   # default suite (no external engines)
$env:REVENG_NEXUS_LIVE_GHIDRA = "1"                   # opt-in: real Ghidra
$env:GHIDRA_INSTALL_DIR = "$env:LOCALAPPDATA\Programs\Ghidra\ghidra_12.1.4_PUBLIC"
python -m pytest tests/integration -m integration -v

$env:REVENG_NEXUS_LIVE_REA = "1"                      # opt-in: real REA (pinned install, see DEPLOYMENT.md)
$env:REA_NODE  = "$env:LOCALAPPDATA\Programs\RevEngNexus\node-v24.21.0-win-x64\node.exe"
$env:REA_ENTRY = "$env:LOCALAPPDATA\Programs\RevEngNexus\rea-agents-6.5.0\node_modules\rea-agents\scripts\rea.mjs"
python -m pytest tests/integration/test_rea_live.py -m integration -v
```

The default suite needs no proprietary software, network service or device. Upstream
engines are simulated by **real MCP servers** (`tests/mock_servers/`): processes speaking
MCP 2.3 over stdio (`mock_engine.py`, which mirrors re-mcp's verified contract) and over
launched Streamable HTTP (`mock_launched.py`, which mirrors MCPyGhidra's readiness
protocol). Per-upstream mocks follow the pinned contracts in
[ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md): `mock_adapters.py` (ida-mcp-rs, Binary Ninja,
JADX), `mock_frida.py` (Frida Mobile MCP; never imports or runs Frida) and `mock_rea.py`
(REA; never runs Node or REA). Lifecycle, pagination, timeouts, crashes, failover and
process-tree containment are therefore exercised through the real SDK and real subprocesses.

Fixtures are **generated from Python source** at test time and never executed:
`elf_builder.py` (hand-assembled x86-64 ELF with symbols and calls), `pe_builder.py`
(PE32+ importing `KERNEL32!ExitProcess`), `macho_builder.py` (thin and universal Mach-O),
`apk_builder.py` (ZIP with a binary AndroidManifest and a DEX header) and
`electron_builder.py` (an ASAR archive of two small CommonJS files, and the ELF fixture with an
appended Electron fuse wire; not a real Electron build). No binaries are committed.

## Coverage map

| Area | Tests |
|---|---|
| Configuration parsing, validation, env expansion, 0.1 compatibility, `config init` | `test_config.py`, `test_cli.py` |
| Policy and classification, heuristics, dynamic gating, hard blocks, deny patterns; `tool_overrides` cannot relax `blocked`/`execute`/`dynamic`/`lifecycle`; lifecycle tools never forwarded for a caller (since 2026-10-15) | `test_security.py` |
| Redaction, metadata-only audit | `test_redaction_audit.py` |
| Workspace boundary (outside, relative, `..`, prefix sibling, ADS, symlink, size), hashing, staging | `test_artifacts_formats.py` |
| ELF/PE/APK parsing, export rules, strings with VAs, malformed inputs | `test_artifacts_formats.py` |
| Every generated fixture (ELF, PE, Mach-O thin/universal, APK): recognition, metadata, truncation, evidence retention, unchanged original | `test_builtin_fixtures.py` |
| Evidence persistence, 0.1 → 2 migration, raw outputs, AI provenance rules, findings, reviews, links | `test_evidence.py` |
| Cross-engine comparison: independence, rebasing, disagreement preservation, AI checks, per-group verdicts | `test_compare.py` |
| Built-in provider operations, hash-change detection, capability errors | `test_builtin_provider.py` |
| MCP provider lifecycle, paginated discovery, catalogue enforcement, audit, staging, timeout, crash and restart, error normalisation, missing executable and env, dynamic skip, launched HTTP, process-tree reaping, minimal child env, stale engine DB rebuild, handshake bounded by the startup (not per-call) timeout and abandoned without a livelock | `test_mcp_providers.py` |
| Source-verified adapters (`ida_rs`, `binary_ninja`, `jadx`) against mock MCP servers: config/missing install, discovery and classification, normalised success with evidence provenance, unsupported operations, Binary Ninja wrong-view refusal, error propagation, unexpected payloads, timeout, cancellation, crash/restart, database switching and shutdown | `test_adapters_mocked.py` (mock: `mock_servers/mock_adapters.py`, built from the pinned source: [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)) |
| Frida Mobile MCP (`frida_mobile`) against a mock of the 32 pinned tools: not started while policy is off, gating without `kind: dynamic`, missing Frida/npx isolation, classification and unmanifested tools, policy blocks before the server, decoy `target` arguments, missing explicit device, status envelopes and in-band errors, `isError`, timeout, cancellation, crash/restart, shutdown detach and orphan check | `test_frida_mocked.py` (mock: `mock_servers/mock_frida.py`) |
| REA (`rea`) against a mock of the real 207-tool catalogue and Evidence envelope: pin and allowlist, overrides cannot reopen other tools, raw passthrough refused before the server, not exposed in namespaced mode, normalised `js.application` / `electron.fuses` with provenance, wrong digest and malformed answers, timeout and recovery, crash/reconnect, process-tree reaping including a grandchild, REA disabled | `test_rea_mocked.py` (mock: `mock_servers/mock_rea.py`) |
| Routing priority and preference, duplicate detection, sequential failover, per-provider serialisation, conflict-group locks, parallelism across engines, workflows | `test_routing_orchestrator.py` |
| LLM4Decompile prompt format, provenance, model verification, substitution refusal, remote-endpoint gating | `test_llm4decompile.py` |
| Report export (Markdown/JSON), fence-injection safety | `test_report.py` |
| MCP tool schemas, annotations, validation errors, end-to-end case over MCP, APK tools, namespaced mode, **gateway as a stdio subprocess**, **loopback Streamable HTTP** | `test_server.py` |
| CLI commands | `test_cli.py` |
| **Real Ghidra** through re-mcp-ghidra and MCPyGhidra | `tests/integration/test_ghidra_live.py` (opt-in) |
| **Real REA** 6.5.0 through Nexus (two static operations) | `tests/integration/test_rea_live.py` (opt-in) |

## Test accounting

The suite collected **260 tests** at the end of 2026-10-14 (165 until 2026-10-13; on 2026-10-14: 17 in the regression re-run, 44 in the afternoon (43 adapter mock tests, 1 handshake test), 34 in the evening (upstream-contract regressions and previously uncovered paths)). On 2026-10-15 `test_frida_mocked.py`, `test_rea_mocked.py`, `test_rea_live.py` and two policy tests in `test_security.py` were added; the observed total is in the [2026-10-15 table](#rea-integration-frida-contracts-and-policy-fixes-2026-10-15) (328 collected at that point, before the security audit); the security audit raised it to 419 ([table](#security-audit-remediation-2026-10-15)) the final review to 476 ([table](#final-review-2026-10-15-evening)) and the follow-up batch to 497 ([table](#follow-up-batch-2026-10-16)); the pre-commit restart-budget fix added one test (498, [table](#re-verification-on-a-reinstalled-machine-2026-10-16)); the dashboard and tool-count work added 26 (524) and its pre-commit review 10 more (534, [table](#dashboard-and-tool-count-audit-2026-10-16-uncommitted)). Environment-gated tests, not failing:

- `tests/integration/test_ghidra_live.py` (`test_live_ghidra_providers_end_to_end` and, since
  2026-10-16, `test_live_ghidra_operations_per_provider`) is skipped unless `REVENG_NEXUS_LIVE_GHIDRA=1` and `GHIDRA_INSTALL_DIR` are set.
- `tests/integration/test_rea_live.py` (since 2026-10-15) is skipped unless
  `REVENG_NEXUS_LIVE_REA=1` and `REA_NODE` / `REA_ENTRY` point at existing files.
- `tests/test_artifacts_formats.py::test_guard_refuses_symlinks` is skipped when the OS
  refuses to create a symlink (Windows without Developer Mode or admin). Its assertion is
  unchanged; on a host that allows symlinks it runs.

No test is deselected by marker configuration. `-m integration` only narrows a run.

Earlier versions of this file and the README disagreed. A draft README said "159 passing",
which was a count predicted before the final run, not an observed one. The suite had
already grown from 154 to 160 tests over that session. This session added 5 tests (static
diagnostics, `config init --create-dirs`, non-loopback HTTP refusal, DNS-rebinding
rejection, background provider start), giving 165. Every count below was observed.

## Access profiles and REA catalogue (2026-10-17, cloud Linux, uncommitted)

Run in a Claude Code cloud container, **not** on the Windows integration machine: Linux, Python
3.13.16, Node 22.22.0, a venv outside the repository (`pip install -e ".[dev]"`), commands run with
`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` and `--basetemp` outside the repository. No
Ghidra, IDA, Binary Ninja, JADX, Frida, device or model exists there, and running the real REA
package was not permitted in that session, so every live test was skipped and the new REA analyses
are mock-tested only.

New: `tests/test_access_profiles.py` (74 tests: profile precedence and unknown keys, the profile x
class x classification-source matrix, protection-bypass hard block, agreement of MCP `tools/list`,
namespaced dispatch, `nexus_list_tools`, provider summaries, `describe()` and snapshots with each
other and with actual invocation in every profile and tool mode, hidden tools, name collisions,
provider states, and a real stdio MCP session against `reveng-nexus serve` per profile); REA
catalogue/profile/`artifact.inspect` tests in `test_rea_mocked.py`; updated expectations in
`test_dashboard.py`, `test_security.py`, `test_frida_mocked.py`.

| Command | Result |
|---|---|
| `pytest -q -rs` on unmodified `9a29445` (baseline, same container) | 520 passed, **9 failed**, 8 skipped |
| `pytest -q -rs` with the change | **608 passed, 9 failed, 8 skipped**, 5 min 29 s; the 9 failures are exactly the baseline's |
| `tests/test_access_profiles.py` | 74 passed (includes the stdio MCP sessions) |
| ruff check, ruff format --check (83 files), mypy (44 files), `node --check app.js`, `--check-config` on the example, `git diff --check` | clean |

The 9 failures were present before and after the access-profile change. On 2026-10-17 they were
traced as follows (same container):

* 8 launched-HTTP failures: `test_raw_call_is_answered_by_its_own_targets_server[1]`, `[2]`,
  `test_raw_call_never_falls_back_to_another_targets_session`,
  `test_per_target_provider_with_no_usable_operations_is_degraded`
  (`tests/test_audit_regressions.py`), `test_launched_http_provider_per_target`,
  `test_launched_server_process_tree_is_reaped`,
  `test_launched_http_handshake_uses_the_launch_startup_timeout` (`tests/test_mcp_providers.py`) and
  `test_compare_same_family_wrappers` (`tests/test_routing_orchestrator.py`, which needs that
  provider). Every one logged `failed to connect: ConnectError` (traceback or audit log): the mock
  printed its readiness line before the pre-bound socket was listening, and Nexus connects as soon
  as it reads that line. **Fixed in the harness**: `tests/mock_servers/mock_launched.py` now
  listens before announcing readiness; regression test
  `test_launched_mock_accepts_connections_as_soon_as_it_announces_readiness` (failed 3/3 before,
  passed 5/5 after, refused connection before).
* `test_rea_mocked.py::test_shutdown_reaps_the_whole_process_tree`: **a real POSIX containment
  defect, not an environment artefact.** A probe replaying the test read `/proc`: 10 s after
  `ProviderManager.close()` the mock's grandchild was alive (state `S`), reparented to PID 1 and
  still in the stdio child's process group. The MCP SDK's `_stop_server_process`
  (`mcp/client/stdio.py:249-268`, mcp 2.3) kills the process tree only when the server fails to
  exit within 2 s of stdin closing; a server that exits promptly (the mock, REA) leaves its
  workers running. On Windows the SDK's Job Object reaps them unconditionally, which is why the
  test passes there. Not fixed at the time: Nexus does not see the stdio child's pid, so a fix
  needed a design decision. **Fixed later the same day** (POSIX stdio guard, below).

Results after the 2026-10-17 harness, parser and coverage work (same container):

| Command | Result |
|---|---|
| `pytest -q -rs` | **631 passed, 1 failed** (`test_shutdown_reaps_the_whole_process_tree`, above), 8 skipped, 640 collected, 6 min 16 s |
| ruff check, ruff format --check (83 files), mypy (44 files), `node --check app.js`, `--check-config` on the example, `git diff --check` | clean |

Results after the 2026-10-17 process-lifecycle work (same Linux container; macOS and Windows not
run):

* **POSIX stdio servers** now start through `providers/_stdio_guard.py` (stdlib only, no shell),
  which runs the server in its own process group and empties that group (SIGTERM, then SIGKILL
  after 1 s) when the server exits or when the SDK's SIGTERM reaches the guard. Windows launch is
  unchanged (the SDK's Job Object).
* **`_ProcessTree._signal_group`** addressed the launched server's group through
  `os.getpgid(pid)`, which fails once the launcher has exited and been reaped, so the
  "launcher exited" cleanup left its workers running. It now uses the group id it created
  (`start_new_session`, so the id is the launcher's pid); a permission error is written to the
  provider log instead of being swallowed.
* New `tests/test_process_lifecycle.py` (15 tests including parameters; mock `mock_servers/mock_tree.py`): graceful,
  SIGTERM-ignoring and hanging servers with a child and a grandchild, repeated close, a 300 KB
  MCP round trip, argv/cwd/stdio byte preservation (the environment check covered only one
  variable and missed the `LC_CTYPE` change; see the review follow-up below), exit-status propagation, a missing
  executable, signal forwarding (guard exits within 2 s) and the unchanged Windows command.
  Before the fix, 3 of the 6 Nexus-level tests failed (leaked grandchild after the launcher
  exited; no error reporting; graceful stdio leak); the guard tests could not run without the guard.

| Command | Result |
|---|---|
| `test_process_lifecycle.py` + `test_shutdown_reaps_the_whole_process_tree` | 16 passed (was failing) |
| lifecycle, REA, MCP-provider and audit-regression files, 3 repeats | 107 passed, 4 skipped each time; no test process left behind |
| `pytest -q -rs` | **647 passed, 0 failed**, 8 skipped (live Ghidra ×2, live REA, NTFS ADS, UNC ×4), 655 collected, 6 min 30 s |
| ruff check, ruff format --check (86 files), mypy (45 files), `--check-config` on the example, `git diff --check` | clean |

Not covered: real REA (or any real server) behind the guard; macOS; descendants that leave the
server's process group (`setsid`); Nexus itself being SIGKILLed while a server ignores EOF.

Review follow-up (2026-10-17, same Linux container; macOS and Windows not run). An independent
review of the guard found, and probes confirmed:

* **Environment not preserved.** The guard's interpreter coerces a C locale (PEP 538) and wrote
  `LC_CTYPE=C.UTF-8` into the environment the server inherited (`/usr/bin/env` through the guard
  with `env -i PATH=… HOME=…`). Interpreter flags (`-X utf8=0`, `-E` with `PYTHONCOERCECLOCALE=0`)
  do not prevent it. Fixed by design: `_stdio_launch` encodes the environment the server must get
  (the SDK's defaults merged with what Nexus built) into `REVENG_NEXUS_GUARD_ENV_*` variables,
  byte for byte and chunked under Linux's 128 KiB per-variable limit; the guard decodes it and
  starts the server with exactly that, so neither coercion nor the markers reach the server.
* **Forwarded SIGTERM always waited the 1 s grace.** The handler's `Popen.poll()` cannot reap
  while the main flow holds the wait lock in `Popen.wait()`, so the dead server stayed a zombie
  group member. Also, in this container PID 1 does not reap orphaned zombies, so killed
  descendants keep `killpg(pgid, 0)` succeeding. Fixed: the handler only sends SIGTERM and arms
  a SIGKILL timer; the main flow reaps, then checks the group with `/proc` on Linux (zombies do
  not count). Signal handlers no longer write output.
* **Inherited ignored signals** (SIGHUP under `nohup`) were reset for the server. They now stay
  ignored; an ignored SIGTERM is still acted on by the guard, the SDK's escalation path.
* The forwarded-signal test could leave the stubborn server running if it failed (only the guard
  was killed). Guard tests now record the server's process group (`mock_servers/guard_harness.py`
  runs the real guard `main()`) and kill both groups on every exit path.

New or changed tests (lifecycle file now 28 tests including parameters): exact environment for
`/usr/bin/env` with a minimal environment (LC_CTYPE absent, `LC_CTYPE=C` kept, `LANG`/`LC_ALL=C`),
end-to-end environment of a Nexus-managed server (Linux `/proc/self/environ`), SIGKILL only for
descendants that ignore SIGTERM (otherwise cleanup within 0.6 s of the server's exit), a signal
during start-up, SIGTERM/SIGINT/SIGHUP with a promptly exiting server (guard exits within 0.6 s,
nothing written to stderr), inherited ignored SIGHUP/SIGINT, inherited ignored SIGTERM (still
bounded under 2 s), the stubborn tree (exit 137 within 2 s, both groups empty).

| Command | Result |
|---|---|
| new tests against the previous guard (temporary copy, API shimmed) | 11 failed, 17 passed |
| `test_process_lifecycle.py` + `test_shutdown_reaps_the_whole_process_tree`, 3 repeats | 29 passed each time |
| lifecycle tests with all 4 CPUs busy | 28 passed |
| two deliberately failing tests with live trees (temporary file, deleted) | every guard, server, child and grandchild PID gone afterwards |
| lifecycle, REA, MCP-provider and audit-regression files | 120 passed, 4 skipped |
| `pytest -q -rs` | **660 passed, 0 failed**, 8 skipped (as above), 668 collected, 6 min 27 s |
| ruff check, ruff format --check (87 files), mypy (45 files), compileall, `--check-config` on the example, `git diff --check` | clean |

After every run no test process was left (non-zombie check, rechecked for up to 5 s). Still not
covered: macOS (EPERM/zombie handling is from the SDK's documentation, untested), Windows, real
REA behind the guard.

Skips: live Ghidra x2, live REA x1 (opt-in variables unset), NTFS ADS x1, UNC x4 (Windows
concepts). The Windows suite and the live Ghidra/REA tests have **not** been re-run for these
changes.

## Dashboard and tool-count audit (2026-10-16; committed in `82f6955` and `9a29445`)

On the reinstalled integration machine, working tree on top of `2bbef45`, one pytest process
at a time:

| Command | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest -q -rs -p no:cacheprovider` (no live env) | **520 passed, 4 skipped**, 524 collected, exit 0, 7 min 12 s. Skips (`-rs`): live Ghidra ×2 and live REA ×1 (opt-in variables unset), symlink ×1 (no Developer Mode) |
| `tests/test_dashboard.py` | 26 passed |
| `tests/integration/test_ghidra_live.py` with `REVENG_NEXUS_LIVE_GHIDRA=1` | **2 passed**, 79 s |
| `tests/integration/test_rea_live.py` with `REVENG_NEXUS_LIVE_REA=1` | **1 passed**, 15 s |
| `ruff check`, `ruff format --check` (80 files), `mypy src` (42 files), `compileall` with SyntaxWarning as error, both `--check-config`, `node --check` on the dashboard script, `git diff --check` | clean |
| Fresh headless Claude Code session (`claude -p`, only `nexus_status` and `nexus_list_providers` allowed) | reveng-nexus connected; both calls returned; ghidra_remcp 134 discovered / 66 allowed / 66 callable; REA 207 / 2 / 0, adapter-only |
| Dashboard against the permanent config with a real gateway session | `/api/state` reported the live snapshot (same counts), all seven views rendered in headless Edge without errors; listener `127.0.0.1:8770` only |

**Pre-commit review (same day).** Snapshot retention (one atomically replaced file per gateway,
touch-only heartbeats, bounded owner-scoped pruning), reader retries for Windows sharing
violations, snapshot file I/O moved off the event loop, history-vs-health labels for audit
records, a misplaced-`data_dir` config warning and a test guard against the permanent runtime.
Results after the review:

| Command | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest -q -rs -p no:cacheprovider` (no live env, machine otherwise idle) | **530 passed, 4 skipped**, 534 collected, exit 0, 6 min 58 s; same four skips (`-rs`) |
| `tests/test_dashboard.py` | 36 passed; the two concurrency tests 10/10 and 15/15 on repetition |
| `tests/integration/test_ghidra_live.py` (live) | **2 passed**, 74 s |
| `tests/integration/test_rea_live.py` (live) | **1 passed**, 14 s |
| ruff, format (80 files), mypy (42 files), compileall, both `--check-config`, `node --check`, `git diff --check` | clean |

This measurement predates the final commit: `9a29445` added three more tests to
`tests/test_dashboard.py`, so that commit collects 537 tests (observed on Linux on 2026-10-17:
520 passed, 9 failed, 8 skipped; the failures are explained in the 2026-10-17 section).

Two intermediate full runs failed once each and were investigated: (1) the new concurrency
test caught a transient Windows sharing violation on read (fixed by the reader retry above);
(2) `test_adapters_mocked.py::test_target_open_uses_startup_timeout` (unchanged code) missed
its 8 s mock-handshake budget while headless Edge was rendering the dashboard in parallel; it
passed 3/3 alone, 75/75 in its file and in the final idle run. It is load-sensitive by design
(its comment notes a 2.5 s idle handshake).

`test_cancelled_provider_start_is_audited_as_cancelled_not_failed` reproduces the old label
against the `2bbef45` source (outcome `failed`) and passes on the working tree (`cancelled`).
The 41-versus-66 replay is described in [DASHBOARD.md](DASHBOARD.md#finding-41-callable-versus-66-re-mcp-ghidra-2026-10-16).

## Re-verification on a reinstalled machine (2026-10-16)

The integration machine's OS was reinstalled after the follow-up batch below. The permanent
layout ([DEPLOYMENT.md](DEPLOYMENT.md)) was rebuilt from the documented steps: Ghidra 12.1.4
(release ZIP SHA-256 matched GitHub's published digest), Node.js 24.21.0 (`SHASUMS256.txt.asc`
verified with the nodejs/release-keys keyring; ZIP SHA-256 as recorded), `rea-agents` 6.5.0
(lockfile integrity as pinned, 178 locked / 146 installed packages, `frida` not installed;
`npm audit signatures`: 0 invalid, 0 missing; SLSA provenance names commit `3b79af2`), a fresh
config from `config init` with REA enabled as before, and the regenerated workspace fixture
(SHA-256 `59bb6fa4…eef9f`, unchanged). The previous evidence DB was not recoverable; a new one
was created. Python 3.12.15, JDK 21.0.12. Results below are from this machine only:

| Command | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest -q -rs -p no:cacheprovider` (no live env) | **494 passed, 4 skipped**, 498 collected, exit 0, 9 min 31 s. Skip reasons (`-rs`): live Ghidra ×2 and live REA ×1 (opt-in variables unset), symlink ×1 (no Developer Mode) |
| `tests/integration/test_ghidra_live.py` with `REVENG_NEXUS_LIVE_GHIDRA=1` | **2 passed**, 104 s |
| `tests/integration/test_rea_live.py` with `REVENG_NEXUS_LIVE_REA=1` | **1 passed**, 19 s |
| `providers check` on the permanent config | exit 0: builtin, both Ghidra providers and REA ready (REA: 2/2 operations, no raw-callable tool) |
| `ruff check`, `ruff format --check` (74 files), `mypy src` (37 files), `compileall` with SyntaxWarning as error, both `--check-config`, `git diff --check` | clean |
| New evidence DB, `mode=ro` | `integrity_check` ok, 0 foreign-key violations |

The pre-commit review on this machine found that a reconnect that failed did not end the restart
window: after one completed restart more than 10 minutes earlier, a child that no longer started
was restarted on every caller request. The quiet period now counts from the end of the last
attempt, successful or not (`test_failed_reconnects_count_against_the_restart_budget`, which
fails against the previous code: a third attempt is made instead of "restart budget exhausted").

## Follow-up batch (2026-10-16)

Results in this section were observed on the integration machine before its OS reinstall.

Open Issue #12, Issue #27, part of Issue #26, Mach-O symbols and three Ghidra normalisation
defects found by a new live per-operation test. Observed on the final working tree, one pytest
process at a time (lowest free memory 6.7 GB):

| Command | Result |
|---|---|
| `python -m pytest -q` (default, no live env) | **493 passed, 4 skipped** (two live Ghidra tests, live REA, symlink), 497 collected; 7 min 9 s (after the pre-commit audit) |
| `tests/integration/test_ghidra_live.py` with `REVENG_NEXUS_LIVE_GHIDRA=1` (real Ghidra 12.1.4) | **2 passed**, 98 s: the end-to-end test and the new per-operation test (both wrappers: metadata, functions, decompile, disassemble, xrefs to/from, cfg, strings, imports, exports on the ELF fixture) |
| `tests/integration/test_rea_live.py` with `REVENG_NEXUS_LIVE_REA=1` | **1 passed**, 10 s, while the gateway's own REA child kept running (the test counts REA processes it started and orphans whose parent exited) |
| `test_security.py`, `test_config.py`, `test_net_boundary.py`, `test_server.py` | 148 passed |
| `test_audit_regressions.py`, `test_interop_d.py`, `test_mcp_providers.py`, `test_artifacts_formats.py`, `test_builtin_fixtures.py` | 104 passed, 1 skipped (symlink) |
| `test_rea_mocked.py` / `test_frida_mocked.py` / `test_adapters_mocked.py` | 34 / 57 / 75 passed (mock only) |
| `test_gateway_answers_handshake_while_slow_providers_start`, repeated | 10/10 passed normally; 5/5 passed with 8 busy-loop processes on 8 cores |
| `ruff check`, `ruff format --check` (74 files), `mypy src` (37 files), `compileall` with SyntaxWarning as error, both `--check-config` | clean |
| Permanent evidence DB, `mode=ro` | `integrity_check` ok, 0 foreign-key violations |

**Issue #12 (handshake test).** Diagnostic runs outside the suite timed spawn → `initialize` and
`initialize` → `tools/list` separately: unloaded 1.6-1.9 s with or without the slow provider;
with 8 CPU hogs a gateway **with no provider at all** took median 6.5 s, max 13.7 s (6/10 over
the old 6 s limit); with 16 hogs 25-59 s. `tools/list` itself took about 0.01 s throughout. The
6 s wall clock measured the gateway's own interpreter start, not provider startup. The test now
checks ordering: the slow mock creates a marker only after its startup delay, and the marker must
not exist when the handshake returns. With a pre-fix serve order (providers started before
serving) the check fails (marker present at 11.2 s; checked with a harness that applies the
test's assertions, because the MCP SDK strips `PYTHONPATH` from the gateway subprocess); under 8 and 16 hogs it passed 8/8 while the
old check failed 8/8. Issue #8 is unrelated and stays open.

Every new regression test was also run against the pre-change source (`git archive HEAD src`)
and failed there for the behaviour it pins: Mach-O symbols (6; missing `symbol_table`, no
functions), ida_rs disassembly count (3; no `count` sent, no warning, 2 lines for `count=1`),
guard existence oracle (1; filesystem touched), MCPyGhidra entry point and re-mcp CFG targets
(2). The two restart-budget cases fail there only at setup (the window constant does not exist);
the behaviour was checked separately: after a quiet period longer than the window, the old code
refuses with "restart budget exhausted" and the new code reconnects with a fresh budget.

A pre-commit audit then fixed: fat-slice reads not bounded to the slice's declared size, an
undecodable Mach-O header or a universal file reported as an empty symbol list without a
warning, an unparseable CFG successor reported as an edge, and the live REA test no longer
seeing an orphaned REA worker. Each has a regression test that fails against the pre-audit code
(the orphan case was checked with an inert orphaned Node process).

## Final review (2026-10-15, evening)

Five independent read-only reviews (HTTP/policy/paths, REA, Frida, provider interoperability,
docs) found 14 more defects; all were fixed with a regression test that failed before the fix
(list in [SECURITY.md](SECURITY.md#residual-risks-and-limitations)). Observed on the final
working tree, one pytest process at a time, free memory checked before each run (lowest
observed: 5.6 GB free):

| Command | Result |
|---|---|
| `python -m pytest -q` (default, no live env) | **473 passed, 3 skipped** (live Ghidra, live REA, symlink), 476 collected; 7 min 44 s |
| `tests/integration/test_ghidra_live.py` with `REVENG_NEXUS_LIVE_GHIDRA=1` (real Ghidra 12.1.4, `re_mcp` and `mcpyghidra`) | **1 passed**, 58 s |
| `tests/integration/test_rea_live.py` with `REVENG_NEXUS_LIVE_REA=1` (real `rea-agents` 6.5.0) | **1 passed**, 26 s |
| `test_security.py`, `test_config.py`, `test_net_boundary.py` | 133 passed |
| `test_audit_regressions.py`, `test_interop_d.py`, `test_mcp_providers.py`, `test_artifacts_formats.py` | 72 passed, 1 skipped (symlink) |
| `test_rea_mocked.py` | 34 passed |
| `test_frida_mocked.py` | 57 passed (mock only; no Frida, device or npx) |
| `test_adapters_mocked.py` | 72 passed |
| `ruff check`, `ruff format --check` (74 files), `mypy src` (37 files), `compileall` with SyntaxWarning as error | clean |
| `--check-config` (example config, permanent config) | exit 0 |
| Permanent evidence DB, `mode=ro` | `integrity_check` ok, 0 foreign-key violations |

After every run only processes that existed before it were running (no Java, Ghidra, REA,
Node or mock server left). The live tests ran separately, never together. The mock and unit
results are not live verification: re-mcp-ida, ida_rs, ida_official, Binary Ninja, JADX,
Frida and LLM4Decompile still have no live run.

## Security audit remediation (2026-10-15)

A five-part read-only audit before enabling REA permanently (HTTP boundary, REA confinement and
lifecycle passthrough, engine identity and readiness, Frida/policy, public repo and docs). The
fixes and the tests that pin them are listed in [SECURITY.md](SECURITY.md); the
"Not tested" table below was updated. Observed after the fixes, on the working tree, each
command run on its own (one pytest process at a time):

| Command | Result |
|---|---|
| `python -m pytest -q` (default, no live env) | **416 passed, 3 skipped** (live Ghidra, live REA, symlink), 419 collected; 6 min 17 s |
| `tests/integration/test_ghidra_live.py` with `REVENG_NEXUS_LIVE_GHIDRA=1` (real Ghidra 12.1.4, both `re_mcp` and `mcpyghidra`) | **1 passed**, 46 s |
| `tests/integration/test_rea_live.py` with `REVENG_NEXUS_LIVE_REA=1` (real `rea-agents` 6.5.0) | **1 passed**, 23 s |
| `test_frida_mocked.py` | 42 passed, 69 s |
| `test_security.py`, `test_config.py`, `test_net_boundary.py` | 119 passed |
| `test_rea_mocked.py` | 28 passed |
| `test_audit_regressions.py`, `test_adapters_mocked.py` | 85 passed |
| `ruff check`, `ruff format --check` (73 files), `mypy src` (37 files), `compileall` | clean |
| `--check-config` (example config, permanent config) | exit 0 |
| Permanent evidence DB, `mode=ro` | `integrity_check` ok |

The two live tests were run separately, not in one combined run with both live switches set;
an earlier combined attempt was stopped by the host for low memory (no REA, mock or Ghidra
process was left behind). The live results above are the first after the audit fixes; the
2026-10-15 REA live result in the next section predates them. Superseded by the
[final review](#final-review-2026-10-15-evening) above.

## REA integration, Frida contracts and policy fixes (2026-10-15)

Earlier the same day, **before** the security-audit fixes above; its counts (328/325/327) are
historical, not the current totals.

**REA** (`rea` adapter, npm `rea-agents` 6.5.0 on a dedicated Node 24.21.0; pin and install in
[PROVIDER_MATRIX.md](PROVIDER_MATRIX.md#rea-rea-static-javascriptelectron-only)):
- `tests/integration/test_rea_live.py` (opt-in) **passed 1/1 in 10 s** against the real
  server: handshake and the 207-tool catalogue through Nexus (name hash matches the pin), only
  the two allowlisted tools allowed, raw passthrough refused, a real `js.application` on a
  generated ASAR (2 JavaScript files parsed; REA reported the code as never executed) and a real
  `electron.fuses` on a generated ELF with a fuse wire, evidence stored with target SHA-256,
  provider, tool, engine version and raw output, cancellation then recovery, no REA Node
  process left after shutdown, REA disabled (built-in still works, `js.application`
  unavailable) and re-enabled, fixtures byte-unchanged, nothing written to the REA home dir.
- `tests/test_rea_mocked.py`: 27 tests passed. Timeout, malformed output, wrong digest,
  crash/reconnect and process-tree reaping (including a grandchild) are verified **only**
  against the mock.
- REA is `live_analysis_verified` for these two static operations only.

**Frida Mobile MCP** (`tests/test_frida_mocked.py`, mock of the 32 pinned tools): `mock_tested`;
no Frida, device or npx was used, so live use stays blocked. Defects found while reading the
pinned source and fixed (each pinned by a test that failed before its fix):
1. A decoy `target` argument authorised tools whose real subject is a session, program or pid.
   Arguments the tool's input schema does not declare are now refused (dynamic tools always,
   static tools on caller-initiated calls).
2. Implicit device fallback (`FRIDA_DEVICE_ID`, first USB device, local host). Dynamic calls to
   tools that declare a device argument must name an authorised device.
3. `adapter: frida_mobile` without `kind: dynamic` started as a static provider. Adapters now
   declare their kind; config forces or validates it.
4. Tools missing from the pinned manifest fell back to the verb heuristic; now `unknown`.
5. No detach on shutdown (upstream cleans up only on SIGINT/SIGTERM); the adapter now calls
   `stop_instrumentation {all: true}` internally.
6. `get_status` accepted any envelope; it now needs the pinned structured envelope, warns
   otherwise and raises on an in-band `result.error`.

**General policy fix:** `tool_overrides` were applied before the pinned manifest, so an
override could relax a hard block, contradicting [SECURITY.md](SECURITY.md). An override can now
tighten any class but never relax `blocked`, `execute` or `dynamic` (from the manifest or the
tool's name): `test_tool_overrides_cannot_unblock_adapter_hard_blocks`,
`test_tool_overrides_cannot_downgrade_execute_or_dynamic`.

**Environment re-check (2026-10-15, read-only):** IDA absent (`IDADIR` unset, no install);
Binary Ninja absent, nothing listening on `127.0.0.1:9009`; Maven absent, `JADX_MCP_HOME`
unset, JDK 25 present; no LLM endpoint on ports 8000/8080/11434/1234; frida and adb absent.
These providers keep their states and blockers.

**Live Ghidra:** re-run on 2026-10-15 in the combined run below: `test_live_ghidra_providers_end_to_end` passed in 51.5 s against Ghidra 12.1.4 (both `re_mcp` and `mcpyghidra`).

| Final run (2026-10-15, working tree) | Collected | Passed | Skipped | Failed | Exit |
|---|---|---|---|---|---|
| `python -m pytest -q -p no:cacheprovider -rfEs` | 328 | **325** | 3 (live Ghidra, live REA, symlink) | 0 | 0 |
| same with `REVENG_NEXUS_LIVE_GHIDRA=1` + `GHIDRA_INSTALL_DIR` and `REVENG_NEXUS_LIVE_REA=1` + `REA_NODE` + `REA_ENTRY` | 328 | **327** | 1 (symlink) | 0 | 0 |
| live tests within that run | 2 | 2 (Ghidra 51.5 s; REA 20.1 s, real servers) | 0 | 0 | — |
| of which Frida mock tests (`test_frida_mocked.py`) | 38 | 38 | 0 | 0 | — |
| of which REA mock tests (`test_rea_mocked.py`) | 27 | 27 | 0 | 0 | — |

| Other check (2026-10-15) | Result |
|---|---|
| `ruff check src tests scripts` / `ruff format --check src tests scripts` | all checks passed / 70 files already formatted |
| `python -m mypy src --ignore-missing-imports` | no issues in 36 source files |
| `python -m compileall -q src tests scripts` | exit 0 |
| `--check-config` (example / permanent) | exit 0 / exit 0 |
| Permanent evidence DB, `mode=ro` | `integrity_check` ok; 0 foreign-key violations; 79 evidence rows (unchanged: tests use temporary stores) |
| `git diff --check`; secret/privacy scan of every changed and new file | clean / clean |

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
snapshot outside the repository (`PYTHONPATH=<snapshot>\src`, bytecode writing off):
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

Logs: `final2-*` and `contracts-*` in a scratch directory outside the repository (one `.log`
and JUnit `.xml` per run, never overwritten).

## Intermittent-failure investigation and adapter mocks (2026-10-14, afternoon)

Durable logs: a scratch directory outside the repo (one `.log` and one JUnit `.xml` per run, never overwritten).

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
| `providers check` (permanent config, real Ghidra) | exit 0; `builtin` ready; `ghidra_remcp` ready, 134 tools / 41 callable (*corrected 2026-10-16: 41 was the length of the shortened `tools_callable` list, 40 names + `...`; the callable count was 66, see [DASHBOARD.md](DASHBOARD.md#finding-41-callable-versus-66-re-mcp-ghidra-2026-10-16)*), 9 binary operations; `ghidra_mcpy` ready (per-target, no live session) |
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
| Official Hex-Rays ida-mcp, ida-mcp-rs, re-mcp-ida against real IDA | no IDA Pro licence/installation; re-mcp-ida's IDA response shapes are only unit-tested (`test_interop_d.py`), its call path only against the Ghidra-shaped mock |
| Binary Ninja MCP | no Binary Ninja installation |
| JADX MCP server | Maven not installed; the JVM daemon cannot be built here |
| Frida Mobile MCP against real Frida | no authorised test device (dynamic analysis is disabled by design); only `mock_tested` (since 2026-10-15) against a mock built from the pinned source |
| LLM4Decompile with real weights | no GPU or served checkpoint; weights deliberately not downloaded |
| GhidrAssist → Nexus over HTTP | no Ghidra GUI session; only Nexus' HTTP endpoint is tested |
| macOS | never run; POSIX process-group code is exercised on Linux only (cloud container, 2026-10-17) |
| Symlink refusal | needs Developer Mode/admin on this host (junction/symlink code path is skipped, not failed) |
| ida-mcp-rs, Binary Ninja and JADX against the real upstream | only `mock_tested` (since 2026-10-14): the mock fixtures follow the pinned upstream source ([ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)), which is a reading of code, not a live run; live use is blocked (no IDA licence, Binary Ninja or Maven) |
| Mach-O beyond `LC_SYMTAB` | symbols come from `LC_SYMTAB` only (generated fixtures, unit-tested); function sizes are unknown by format; dyld export tries, chained fixups and `LC_DYSYMTAB` indirect symbols are not decoded; no real-world Mach-O was tried |
| REA beyond `js.application` and `electron.fuses` | its other 205 tools are blocked by design and were never called; REA timeout, malformed output, wrong digest, crash/reconnect and grandchild reaping are mock-tested only; REA on a hostile ASAR or a real Electron build was not tried |
| Ghidra beyond the generated ELF | both wrappers are live-verified per operation on one generated static x86-64 ELF only: no PE, Mach-O, PIE, stripped or larger input; neither wrapper reports the entry point; references and strings from non-loaded sections carry no address space upstream |
| Binary Ninja full-path identity against a real Binary Ninja | mock-tested only; the real `FileMetadata.filename` format (separators, case, `.bndb` after a save) is unconfirmed |
| A launched server that binds `0.0.0.0` while announcing `127.0.0.1` | cannot be detected from the readiness line; only the announced host and the final URL are checked |
| `ida_official`, `re_mcp_ida`, `binary_ninja` via `providers check` | not launched on 2026-10-14, because their `uvx`/`npx` commands would download upstream packages for engines that are not installed |
