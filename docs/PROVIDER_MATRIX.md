# Provider matrix

Last audited: **2026-10-15**.
Upstream repositories were shallow-cloned at the commits below and read as data; nothing
upstream was built or executed from those clones. REA is the exception: its pinned npm
release was verified (integrity, provenance) and installed into a dedicated directory, and
only that install is run (see [REA](#rea-rea-static-javascriptelectron-only)).

## Verification states

Re-audited **2026-10-15** against the installed environment. Each provider carries the
strongest state it has actually reached, plus a blocker when live use is impossible here.
Reading an upstream's source is **not** verification, and a passing mock is not a live test.

| State | Meaning |
|---|---|
| `live_analysis_verified` | A real read-only analysis ran through RevEng Nexus against the real engine on this machine, using a generated benign fixture, and its result was stored as evidence. |
| `connection_verified` | The real upstream server started and answered `tools/list` through Nexus, but no analysis result was verified. |
| `mock_tested` | The adapter's call path is exercised by tests against a local mock that imitates the upstream contract. The real upstream was never run. |
| `unit_tested` | Only policy/manifest classification or config handling is unit-tested; no call path to the provider is exercised. |
| `reviewed_not_tested` | The adapter was written from the upstream source or tool snapshot at the pinned commit; no test exercises it. |
| `blocked` | Live use is impossible here; the *Blocker* column names the missing licence, software, build tool, device or model. |
| `not_integrated` | No integration exists, by design or because evaluation is paused. |

`reveng-nexus --config <providers.yaml> providers check <id>` starts a provider on its own,
lists its tools with policy decisions, and reports health. Since 2026-10-14 it **fails**
(exit 1) for a provider that answers MCP but can perform none of its operations; that case
was observed live with re-mcp-ghidra and a wrong `GHIDRA_INSTALL_DIR`.

**Contract corrections (2026-10-14).** The first mock fixtures for `ida_rs`, `binary_ninja` and `jadx` encoded the adapter author's assumptions. Reading the pinned upstream source showed several were wrong, and the adapters were fixed to match it (details and file references: [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)):
- JADX returns `json.dumps(value)` for every tool, so source, manifest and main activity arrived as quoted, escaped JSON strings. They are now decoded exactly once, and `@`-bookkeeping entries are no longer data.
- The Binary Ninja bridge never sets `isError` and prefixes some answers with `File: <path>`. Error text was accepted as HLIL/listing rows, the preamble became a function name, and its JSON list bodies were mis-parsed (including decompile-by-address). Errors are now raised, the active view must be the exact staged copy (full normalised path, checked before and after each operation; since the 2026-10-15 audit, a same-named file elsewhere is refused), and bodies are parsed per operation.
- ida-mcp-rs strings carry `content` (was read as `value`, always `None`), imports have no module (was read as `module`), and `decompile`/`xrefs`/`basic_blocks` accept numeric addresses only (names were sent).
- Unrecognised shapes give an empty result plus a warning with the raw output kept; code-labelled outputs (pseudocode, HLIL, Java) are never filled from an unexpected document.

**Policy and Frida corrections (2026-10-15).** A source-based Frida mock ([ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md#frida-mobile-mcp-monkeywavefrida-mobile-mcp-b2da55d6429438ed36e829e7478de42430cb4ef9)) exposed gating defects, all fixed in the shared policy code or the Frida adapter:
- `tool_overrides` were applied before the pinned manifest, so an override could relax a hard block. An override can now tighten any class but never relax `blocked`, `execute` or `dynamic`, whether that class comes from the pinned manifest or from the tool's name.
- A decoy `target` argument could authorise a tool whose real subject is a session, program or pid. Arguments not declared in the tool's input schema are now refused (dynamic tools always; static tools on caller-initiated calls).
- Without a device argument, upstream falls back to `FRIDA_DEVICE_ID`, the first USB device or the local host. Dynamic calls to tools that declare a device argument must now name an authorised device.
- `adapter: frida_mobile` without `kind: dynamic` was started as a static provider. Adapters now declare their provider kind, and the config forces or validates it.
- Tools missing from the pinned Frida manifest fell back to the verb heuristic; they are now `unknown` (blocked until an operator classifies them).
- Upstream detaches sessions only on SIGINT/SIGTERM. On shutdown the adapter now calls `stop_instrumentation {all: true}` itself, and `get_status` must return the pinned structured envelope (an in-band `result.error` is raised).

## Summary

| Provider id | Upstream | Pinned revision / package | Licence | Integration method | Verification state | Blocker |
|---|---|---|---|---|---|---|
| `builtin` | RevEng Nexus | repo 0.2.0; pyelftools 0.32, pefile 2024.8.26, capstone 5.0.9 | MIT (deps: Public domain / MIT / BSD-3) | in-process | `live_analysis_verified` only for the generated fixtures and operations that `tests/test_builtin_fixtures.py` and `tests/test_builtin_provider.py` assert: ELF metadata, functions, strings, disassembly; PE metadata, imports, strings; Mach-O metadata, strings, entry disassembly and `LC_SYMTAB` symbols (functions = defined symbols in instruction sections, imports = undefined external symbols with their dylib, exports = defined external symbols; sizes unknown; an absent or out-of-bounds table is reported as unknown, not empty); APK manifest, components, strings | — |
| `ghidra_remcp` | [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp), Ghidra backend | `7b38aa9`; PyPI `re-mcp-ghidra==3.0.3` | MIT OR Apache-2.0 | stdio MCP child via `uvx` | `live_analysis_verified` (automated live tests, `tests/integration/test_ghidra_live.py`, passed 2026-10-15; re-run passed 2026-10-16, also on the reinstalled integration machine) for `binary.metadata` (bits, image base, function count; no entry point reported), `binary.functions` (names, addresses, sizes), `binary.decompile`, `binary.disassemble`, `binary.xrefs` in both directions, `binary.cfg` (call destinations as `external_targets`, not successors), `binary.strings`, `binary.imports` (empty on the static fixture), `binary.exports`; all on one generated static x86-64 ELF | — |
| `ghidra_mcpy` | [nightwing-us/mcpyghidra](https://github.com/nightwing-us/mcpyghidra) | `f1e130c` (v0.8.0); PyPI `mcpyghidra==0.8.0` | Apache-2.0 (+ NOTICE) | launch → JSON readiness → Streamable HTTP, one server per target | `live_analysis_verified` (automated live tests, passed 2026-10-15; re-run passed 2026-10-16, also on the reinstalled integration machine) for `binary.decompile`, `binary.metadata` (upstream's `entry_point` is its first external entry, so Nexus reports the entry as unknown), `binary.functions` (no sizes upstream), `binary.disassemble`, `binary.xrefs` in both directions, `binary.cfg`, `binary.strings`, `binary.imports` (empty on the fixture), `binary.exports`; all on one generated static x86-64 ELF | — |
| `re_mcp_ida` | jtsylve/re-mcp, IDA backend | `7b38aa9`; PyPI `re-mcp-ida==3.0.3` | MIT OR Apache-2.0 | stdio MCP child via `uvx` | `mock_tested` for the shared call path only (its mock imitates the Ghidra backend); the IDA response shapes (xref `from`/`to`, `pseudocode`, `disasm`, no image base) are `unit_tested` against the pinned source (`tests/test_interop_d.py`) | `blocked`: licensed IDA 9+ (none installed) |
| `ida_official` | [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp) | `df6de79`; PyPI `ida-mcp==20261008.0.1` | MIT | stdio MCP child; analysis only via `execute_python` (blocked by default) | `unit_tested` (manifest / code-execution gate) | `blocked`: licensed IDA 9.4+ with idalib |
| `ida_rs` | [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) | `15d16ab` (v9.5.0-beta.6); stable tag v9.4.5 | MIT | stdio MCP child (`--read-only`) | `mock_tested` (mock fixtures built from the pinned upstream source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against the real engine) | `blocked`: licensed IDA Pro 9.4; `IDADIR` unset |
| `binary_ninja` | [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) | `8c5134e`; npm `binary-ninja-mcp@1.0.0` | **GPL-3.0** | stdio npm bridge → BN plugin HTTP `127.0.0.1:9009` | `mock_tested` (mock fixtures built from the pinned upstream source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against the real engine) | `blocked`: Binary Ninja licence, GUI and plugin (nothing listening on 9009) |
| `jadx` | [Qtty/jadx-mcp-server](https://github.com/Qtty/jadx-mcp-server) | `4e6d890` (pom 1.0.0) | **no LICENSE file**: no redistribution rights | stdio Python MCP → JVM daemon `127.0.0.1:8765` | `mock_tested` (mock fixtures built from the pinned upstream source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against the real engine) | `blocked`: Maven build of the daemon (Maven absent; JDK 25 present); `JADX_MCP_HOME` unset |
| `frida_mobile` | [monkeywave/frida-mobile-mcp](https://github.com/monkeywave/frida-mobile-mcp) | `b2da55d`; npm `frida-mobile-mcp@0.2.3` | MIT | stdio npm child, **dynamic**, never started while policy is off | `mock_tested` (2026-10-15: mock built from the pinned source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against real Frida or a device) | `blocked`: no authorised test device; no frida/adb; policy disabled by design |
| `llm4decompile` | [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | `85b364b` | code MIT; **weights: DeepSeek License Agreement** | OpenAI-compatible `/v1/completions` you serve | `mock_tested` (local mock HTTP endpoint; not MCP) | `blocked`: no served checkpoint (nothing listening on 8000/8080/11434/1234); weights deliberately not downloaded |
| `rea` | [morluto/rea](https://github.com/morluto/rea), npm `rea-agents` | `3b79af2` (tag `rea-agents-6.5.0`); npm `rea-agents@6.5.0` | MIT | stdio MCP child (`node rea.mjs mcp`) on a dedicated Node 24.21.0; **adapter-only**, two static tools allowed | `live_analysis_verified` (2026-10-15; live test re-run passed 2026-10-16 on the reinstalled integration machine) **for `js.application` and `electron.fuses` only** + `mock_tested` | — (disabled in the example config; the other 205 REA tools are blocked by design) |
| — | [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist) | `db0bb3d` | MIT | none; Ghidra plugin acting as an MCP *client* of Nexus' loopback HTTP endpoint | `not_integrated` as a provider (by design); client path untested | Ghidra GUI session for the client test |
| — | [ram-elgov/awesome-llm-reverse-engineering](https://github.com/ram-elgov/awesome-llm-reverse-engineering) | `55366aa` | README states "MIT" | research reading list | `not_integrated` (not a runtime component) | — |

Unimplemented on purpose: reviewed IDAPython templates for `ida_official` (decision
pending), any Frida protection-bypass/memory-write/custom-script pass-through, automatic
model-weight download, an authenticated non-loopback HTTP mode, and any REA tool beyond
the two static parsers (REA's dynamic, debugger, extraction and deep-engine tools stay blocked).

**Integration vs. redistribution.** Running an upstream as a separate process says nothing
about the right to copy it. Binary Ninja MCP is GPL-3.0 and jadx-mcp-server has no licence,
so neither may be vendored or redistributed with this project. Nexus only launches the
operator's own installations.

Caveat for `ghidra_mcpy` health: before any target is opened, health is `ready` on the basis
that the launch command resolves, and its health detail says "no live session". Its tools
are discovered, and policy-checked, when the first per-target server starts.

All ten upstream repositories checked on 2026-10-14 existed and had recent commits on that
date (the most recent: ida-mcp 2026-10-08, ida-mcp-rs 2026-10-08, GhidrAssist 2026-09-20; the
oldest: awesome-llm-reverse-engineering 2025-07-28). The eleventh, REA, was added on
2026-10-15; its pinned release `rea-agents` 6.5.0 was published to npm on 2026-10-14.

## Per-provider notes

### Built-in (`builtin`, always on)
- **Operations:** metadata, symbol-table/export function list, imports, exports and strings
  for ELF, PE and Mach-O (Mach-O from `LC_SYMTAB` when present); Capstone disassembly of
  symbol-bounded ranges; APK manifest and components (the project's own binary-XML parser).
- **Evidence:** parsed structures are `direct_observation`; Capstone output is `engine_derived`
  with engine family `capstone`. Capstone is independent of Ghidra and IDA, which makes it a
  real cross-check for instruction listings, but it does **no code discovery**.
- **Limitations:** no decompiler; no control-flow recovery; the PE function list is exports
  plus the entry point; Mach-O function sizes are unknown (the format does not record them), and dyld export
  tries and chained fixups are not decoded.

### Ghidra via re-mcp (`ghidra_remcp`)
- **Launch:** `uvx --python 3.12 re-mcp-ghidra==3.0.3` with `GHIDRA_INSTALL_DIR`, plus
  `GHIDRA_MCP_DISABLE_EXECUTE=1`, `GHIDRA_MCP_DISABLE_BATCH=1` and
  `GHIDRA_MCP_DISABLE_TOOL_SEARCH=1`. Requires Ghidra 12+ and JDK 21+. Upstream pins
  `mcp<2`; it runs in its own uvx environment, so it never conflicts with the gateway's MCP 2.3.
- **Observed contract:** 134 tools, all MCP-annotated; **66** are callable under the default
  read-only policy (60 read by trusted annotation, 6 read by the pinned manifest; 68 blocked:
  64 mutate, 3 lifecycle, 1 meta-tool). Earlier records said "41": that was the length of the
  shortened `providers check` list (40 names + `...`), not a count; replaying today's catalogue
  through the 2026-10-13 policy code also gives 66 ([DASHBOARD.md](DASHBOARD.md#finding-41-callable-versus-66-re-mcp-ghidra-2026-10-16)). `open_database(file_path, database_id, run_auto_analysis, keep_open,
  force_new)` returns immediately; `wait_for_analysis` **requires** `database`.
- **Live findings (handled by the adapter):**
  - `run_auto_analysis` defaults to **False**. Without it the engine reported 1-byte
    function sizes, missed the call xref from `main`, and listed only section-name strings.
    The adapter always passes `True`.
  - A Ghidra project left half-written by an interrupted session cannot be reopened
    (`FileNotFoundException: //<name>`). The adapter closes with `save=True`, and if opening
    still fails it rebuilds the private staged database once with `force_new`, recording a
    warning.
  - `serverInfo` reports "Ghidra 3.4.8", which is the server framework's version, not
    Ghidra's. Nexus labels it "server-reported".
  - Addresses are bare offsets (`format_address(addr.getOffset())`, tools/xrefs.py:66 and :94):
    references and strings from non-loaded sections (symbol and string tables) arrive as small
    numbers such as 0 or 80, indistinguishable from memory addresses. Nexus does not reinterpret
    them; MCPyGhidra behaves the same way (observed live 2026-10-15).
  - `get_basic_blocks` takes successors from `BasicBlockModel.getDestinations()` without flow
    types (tools/cfg.py:89-96), so call targets arrive as successors. Destinations that are not
    blocks of the function are reported as `external_targets`.
- **Policy:** the meta-tools `call`, `batch` and `execute` can reach any tool by name, so they
  are hard-blocked. `open/close/wait_for_analysis` are lifecycle tools used only by the gateway.

### Ghidra via MCPyGhidra (`ghidra_mcpy`)
- **Launch:** `uvx --python 3.12 --from mcpyghidra==0.8.0 mcpyghidra-headless {target}
  --host 127.0.0.1 --port 0 --project-dir {workdir}`. The process prints plugin noise, then
  `{"status":"ready","host":…,"port":…}` on stdout, then serves `http://host:port/mcp`.
  Nexus skips non-JSON lines, refuses non-loopback hosts, and runs one server per target.
- **Observed contract:** 24 tools with `readOnlyHint`. Write and code tools (`rename`,
  `update_vars`, `set_comments`, `set_prototype`, `patch`, `begin_trans`, `end_trans`,
  `create_struct`, `add_field`, `pyghidra`) are classified from the upstream tool reference
  and blocked. Several of these slipped past the 0.1 name filter.
- **Live findings:** results are JSON text blocks (no `structuredContent`); the function list
  has no sizes. On Windows, `terminate()` killed only the `uvx` launcher and orphaned the
  Python/JVM grandchildren. Nexus now puts launched servers in a Job Object with
  KILL_ON_JOB_CLOSE (or a process group on POSIX); a regression test covers this. Its
  Java GUI plugin fails to compile on stderr in headless mode; this is harmless.
- **Independence:** same engine family as `ghidra_remcp`. Agreement between the two is
  reported as `same_family_consistency`, never as independent confirmation.
- **Test coverage:** live (`test_live_ghidra_operations_per_provider`, 2026-10-15): metadata,
  functions, decompile, disassemble, xrefs to/from, cfg, strings, imports, exports on the ELF
  fixture; mock (`mock_launched.py`): metadata, decompile, functions; unit
  (`tests/test_audit_regressions.py`): cfg, xref and metadata normalisers. `context`'s
  `memory.entry_point` is the first external entry point, else the first function, else the image
  base (tools/core.py:686-701): Nexus keeps it as `first_external_entry` and reports `entry_point`
  as unknown.

### Hex-Rays official IDA MCP (`ida_official`)
- Six tools (upstream snapshot): `open_database`, `execute_python`, `reference`,
  `list_databases`, `save_database`, `close_database`. **All analysis goes through
  `execute_python`, which is arbitrary IDAPython.**
- Nexus does not generate IDAPython for it: that would be unreviewed code execution and it
  cannot be verified without IDA here. Under the default policy only `reference` and
  `list_databases` are callable. To use it, set `policy.allow_code_execution: true` and
  `code_execution_providers: [ida_official]`, then call `execute_python` explicitly via
  `nexus_call_provider_tool`.
- The 0.1 example's `IDA_MCP_READ_ONLY` and `IDA_MCP_TOOLSETS` variables belong to
  ida-mcp-rs, not this server; they have been removed from its entry.
- **Health (fixed after the 2026-10-15 audit):** the adapter binds no Nexus operation, so the
  provider reports `degraded` and fails `providers check`, even when `execute_python` is
  enabled by policy (`test_provider_without_bound_operations_is_degraded`).

### ida-mcp-rs (`ida_rs`)
- Rust server over idalib. `--read-only` strips mutating and code tools; `--toolsets` limits
  the surface. Adapter arguments come from `src/server/requests.rs` (`open_idb(path, idb_out)`,
  `decompile(address)`, `disasm_function_at(address|target_name)`, `xrefs_to/xrefs_from(address)`,
  …). `lumina_lookup` is blocked because it sends function metadata to Hex-Rays' Lumina service.
- **Mock-tested 2026-10-14** (`tests/test_adapters_mocked.py`): discovery and policy classification, every bound operation normalised through Nexus with evidence provenance, refusals, provider errors, unexpected payloads, timeout, cancellation, crash/restart and shutdown. The mock reproduces the pinned tool and argument names; its response envelopes follow the pinned source ([ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)), not a live run.
- An `open_idb` that triggered a reconnect lost its session record, so the next target switch never sent `close_idb` (one database per server). Fixed in the shared provider code (sessions reset in place).
- Put all IDA providers in `conflict_group: ida`. Nexus serialises them per target and gives
  each its own staged copy, so two drivers never share one `.i64`.

### Binary Ninja (`binary_ninja`)
- The GUI plugin serves HTTP on `127.0.0.1:9009`; the npm bridge speaks MCP over stdio. The
  bridge tools carry **no annotations**, so Nexus uses an explicit read/mutate allowlist from
  `bridge/src/tools.ts`.
- Nexus cannot load a file into Binary Ninja through this bridge. Before and after each
  operation it checks that the active view is this target's staged copy, compared by full
  normalised path (a same-named file elsewhere or a `.bndb` is refused;
  `test_binary_ninja_same_basename_elsewhere_is_refused`, fixed after the 2026-10-15 audit). The
  bridge reads the view per call, so a switch between the two checks cannot be fully excluded.
- **Mock-tested 2026-10-14** (`tests/test_adapters_mocked.py`): discovery and policy classification, every bound operation normalised through Nexus with evidence provenance, refusals, provider errors, unexpected payloads, timeout, cancellation, crash/restart and shutdown. The mock reproduces the pinned tool and argument names; its response envelopes follow the pinned source ([ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)), not a live run.
- **GPL-3.0:** Nexus talks to it only as a separate process over MCP and does not copy or link
  its code.

### JADX (`jadx`)
- Python MCP layer (`mcp==1.27.2`) supervising a JADX JVM daemon on `127.0.0.1:8765`. Build
  it with `mvn clean package` (needs JDK 17+ and Maven), create a venv, then install
  `mcp_server/requirements.txt`. Set `JADX_MCP_HOME` and use a smaller `JADX_HEAP` than the
  upstream default of 24g.
- **Mock-tested 2026-10-14** (`tests/test_adapters_mocked.py`): discovery and policy classification, every bound operation normalised through Nexus with evidence provenance, refusals, provider errors, unexpected payloads, timeout, cancellation, crash/restart and shutdown. The mock reproduces the pinned tool and argument names; its response envelopes follow the pinned source ([ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md)), not a live run.
- Upstream tools all observe; `load_apk` is treated as lifecycle.
- **Licence:** the repository has no LICENSE file at the pinned commit, so no redistribution
  rights are granted. Use your own checkout and do not vendor it.
- The built-in AXML parser covers manifest and components without JADX. `nexus_analyze_apk`
  cross-checks the exported-component sets from both when JADX is present.

### Frida Mobile (`frida_mobile`, dynamic)
- Started only when `policy.dynamic_analysis.enabled` is true **and** `authorized_devices`
  and `authorized_targets` are non-empty. Instrumentation tools must also be listed in
  `allowed_tools`, and every call must name an authorised target; device and target
  arguments are checked against the allowlists.
- The adapter declares itself `dynamic`: a config entry with `adapter: frida_mobile` and no
  `kind` is treated as dynamic, and any other `kind` is a config error.
- Hard-blocked whatever the policy says: `bypass_ssl_pinning`, `run_prebuilt_script`
  (which ships SSL, root and jailbreak bypass scripts), `execute_script`, `write_memory`,
  `kill_process`, `hook_function` and `unhook_function` (custom JS bodies). `tool_overrides`
  cannot reopen them. Tools missing from the pinned manifest are `unknown` and blocked.
- **Arguments (since 2026-10-15):** an argument the tool's input schema does not declare is
  refused (upstream schemas silently drop unknown keys, so it could only serve as a decoy
  for Nexus' own checks). A tool that declares a device argument must be called with an
  explicitly named, authorised device; upstream would otherwise fall back to
  `FRIDA_DEVICE_ID`, the first USB device or the local host (`device/resolver.ts:42-61`).
- **Not authorisable (design limit):** instrumentation tools whose subject is a session id,
  pid or program, and which declare no app-identifier argument, cannot be tied to
  `authorized_targets`; a decoy `target` is refused as undeclared, so these tools stay
  unusable even when listed in `allowed_tools`.
- **Shutdown:** upstream detaches only on SIGINT/SIGTERM (`index.ts:68-79`), which a Windows
  child never receives. The adapter calls `stop_instrumentation {all: true}` itself before
  the pipes close. That tool is classified `lifecycle`, so the gateway can use it
  internally; a caller reaches it only if an operator lists it in `allowed_tools`, and the
  normal dynamic checks then apply.
- `nexus_dynamic_analysis_status` reports policy and provider state without instrumenting
  anything. `get_status` must return the pinned `{result, session_context, suggested_next}`
  structured envelope; anything else leaves the status empty with a warning (raw output
  kept), and an in-band `result.error` is raised as a provider error.
- **Upstream caveats:** the bundled mobile-mcp bridge is launched as an unpinned
  `npx -y @mobilenext/mobile-mcp@latest` unless `--no-mobile-mcp` is passed (the example
  config passes it). Upstream honours only the value `1` for its `FRIDA_MCP_*` switches, so
  `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS=0` / `FRIDA_MCP_MEMORY_WRITE=0` change nothing; Nexus' hard
  blocks are the protection.
- **Mock-tested 2026-10-15** (`tests/test_frida_mocked.py`, mock `tests/mock_servers/mock_frida.py`
  with the 32 pinned tools, their argument schemas, annotations and envelopes read from the
  source): not started while policy is off, gating without `kind`, missing Frida/npx
  isolation, classification, policy blocks before the server, decoy arguments, missing
  device, status envelopes, `isError`, timeout, cancellation, crash/restart, shutdown
  detach and process reaping. No Frida, frida-server, npx, device or app was used.

### REA (`rea`, static JavaScript/Electron only)
- **Pin:** npm `rea-agents` 6.5.0 (dist-tag `latest`, published 2026-10-14 via GitHub
  Actions trusted publishing), integrity
  `sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A==`
  (shasum `7ea5e6f669bc18c45dbf5dba653edaa1ada07ab3`); its SLSA provenance points to tag
  `rea-agents-6.5.0` = commit `3b79af28e80785afce9f5998d8f03289402a1847`. MIT. Node engines
  `^22.19.0 || ^24.11.0 || >=26.0.0`.
- **Install (operator, outside the repo):** a dedicated official Node.js 24.21.0 win-x64 ZIP
  (SHA-256 checked against `SHASUMS256.txt`, whose clearsigned signature was verified with the
  Node.js release keys) under `%LOCALAPPDATA%\Programs\RevEngNexus\node-v24.21.0-win-x64`, and
  REA in its own prefix `%LOCALAPPDATA%\Programs\RevEngNexus\rea-agents-6.5.0`, installed with
  `--ignore-scripts --omit=optional --omit=dev`, an own npm cache and an empty user config.
  `rea-agents` itself has no install scripts; only its optional `frida` dependency does, and it
  is not installed. The package ships no lockfile (the local install resolved 178 packages); the
  installed package was byte-identical to the independently verified tarball. The system Node,
  `PATH` and global npm config are not touched. Steps: [DEPLOYMENT.md](DEPLOYMENT.md#rea-optional-dedicated-node-runtime).
- **Launch:** `node.exe <prefix>\node_modules\rea-agents\scripts\rea.mjs mcp` (stdio). The
  arguments must be exactly `mcp`: anything else reaches REA's CLI, including `setup`, which
  edits agent configurations. `rea setup` was never run, and REA is not registered with Claude
  Code; Nexus is its only client. Never launch it through `npx`.
- **Observed contract (2026-10-15):** `serverInfo` rea/6.5.0, protocol 2025-11-25, 207 tools
  (SHA-256 of the sorted names `821ff86b6022644383456368e470cb72c92db8471785c41821bd0c99eeecde99`).
  Upstream has no read-only mode and no path containment; its annotations are self-declared
  (every tool reports `readOnlyHint: false`) and are not trusted.
- **Allowlist:** exactly two tools, reviewed at the pin as in-process static parsers of one
  regular file that never execute it:
  - `analyze_javascript_application` → operation `js.application`, MCP tool
    `nexus_analyze_javascript_app`. An ASAR archive is parsed as inert text in REA's own Node
    worker; Nexus passes `detail: summary`, `integrity_policy: record-and-continue` and a bounded
    `analysis_timeout_ms` (the provider timeout minus 10 s, at most 300 s).
  - `inspect_electron_fuses` → operation `electron.fuses`, MCP tool `nexus_get_electron_fuses`;
    a byte-level read of the executable's fuse wire.
  Every other tool, current or future, is `blocked` (the adapter's unlisted-tool class), and
  `tool_overrides` cannot reopen one.
- **Adapter-only:** REA has no raw passthrough. `nexus_call_provider_tool` is refused for it
  and its tools are not exposed in namespaced mode, so REA only ever receives the
  hash-verified staged copy that Nexus passes, never a caller-chosen path.
- **Envelope:** `structuredContent` is an REA Evidence record (`evidence_id`,
  `subject.digest.sha256`, `provider`, `operation`, `normalized_result`, `limitations`, …);
  errors carry `isError` and `{"error": {code, message}}`. The adapter requires the record's
  SHA-256 to equal the target's (otherwise the call fails without evidence), keeps REA's
  evidence ids, limitations and unknowns, and replaces absolute local paths in the normalised
  result with the target's display name (the raw output in the evidence DB keeps them).
  `engine_version` is "rea-agents 6.5.0 (server-reported)". The JavaScript result is REA's
  summary view; the full analysis stays in REA's session. No fuse wire found means "unknown",
  not "disabled".
- **Engine family:** `rea` (REA's own Babel-based JavaScript parsing and byte-level fuse
  reading). REA's deep-engine tools, which would drive Ghidra, IDA or Hopper, are blocked, so the
  allowed path does not overlap with Ghidra. If such tools were ever enabled, their results
  would have to carry the driven engine's family (e.g. `ghidra`), not `rea`.
- **Child environment (example config):** `PATH` = the dedicated Node directory plus
  `System32`; `USERPROFILE`/`HOME`/`TEMP`/`TMP` pointed into a Nexus-owned directory under the
  data dir; `REA_LOG_LEVEL=warn`. Do not pass `GHIDRA_INSTALL_DIR`, `HOPPER_*`,
  `REA_ANALYSIS_PROVIDER` or similar deep-engine settings.
- **Live-verified 2026-10-15** (`tests/integration/test_rea_live.py`, opt-in, 1 passed:
  10 s alone and 20.1 s in a combined run before the audit fixes; 23 s alone after them): handshake and the 207-tool catalogue through Nexus, only the two tools allowed,
  passthrough refused, a real `js.application` on a generated ASAR (2 JavaScript files parsed;
  REA reported the code as never executed) and a real `electron.fuses` on a generated ELF with
  a fuse wire, evidence stored with target SHA-256, provider, tool, engine version and raw
  output, cancellation then recovery, all REA Node processes gone after shutdown, REA disabled
  (built-in still works, `js.application` unavailable) and re-enabled, fixtures byte-unchanged,
  nothing written to the REA home directory. Timeout, malformed output, wrong digest,
  crash/reconnect and process-tree reaping including a grandchild are covered by mock tests
  only (`tests/test_rea_mocked.py`). The state applies to these two operations; no other REA
  capability is verified or integrated.
- **Residual risks:** the package ships a prebuilt Windows addon
  (`native/windows/build/rea-windows-x64.node`) whose integrity is checked only against a
  manifest inside the same tarball. REA runs with the user's privileges, without a sandbox, and
  parses attacker-controlled JavaScript text in its own process.
- **Not in the permanent config.** To use REA, copy the `rea` block from
  `config/providers.example.yaml` into your `providers.yaml` and set `enabled: true`. To
  remove it, delete that block (and optionally the two directories under
  `%LOCALAPPDATA%\Programs\RevEngNexus\`). Claude Code settings are never involved.

### LLM4Decompile (`llm4decompile`)
- No server upstream. Serve the checkpoint yourself (for example
  `vllm serve LLM4Binary/llm4decompile-6.7b-v2`) and point `model.endpoint` at it. Nexus
  never downloads weights.
- Nexus verifies that `/v1/models` lists the configured id, refuses ids that do not look like
  LLM4Decompile unless `allow_unrecognized_model` is set, and rejects responses that name a
  different model. Non-loopback endpoints need both `model.allow_remote` and
  `policy.allow_remote_ai`.
- Prompt template is the upstream one: `# This is the assembly code:\n…\n# What is the source
  code?\n`. **Ref (V2)** models get Ghidra pseudocode; **End (V1.5)** models get Nexus'
  approximation of the objdump format they were trained on.
- Output is stored as `ai_generated`, `unverified`, with model, variant, endpoint host,
  parameters and a `derived_from` link to the input evidence. It never counts towards
  cross-engine confidence, and a finding cannot be `confirmed` on AI evidence alone.
- **Weights licence:** the DeepSeek License Agreement includes use-based restrictions
  (Attachment A). Compliance is the operator's responsibility.

### GhidrAssist (companion, not a provider)
- A Ghidra GUI extension that itself acts as an **MCP client** (SSE / Streamable HTTP) and LLM
  front-end; it exposes no MCP server. To let it use Nexus' tools, run
  `reveng-nexus serve --transport http --port 8765` (loopback only) and add
  `http://127.0.0.1:8765` as a Streamable HTTP server in GhidrAssist's *MCP Servers* tab.
  This path is **not tested** with GhidrAssist here (no Ghidra GUI session). Only Nexus'
  Streamable HTTP endpoint itself is tested, by `test_streamable_http_transport_on_loopback`.
  GhidrAssist's own LLM traffic goes to whichever provider you configure inside GhidrAssist.

### Awesome LLM Reverse Engineering (reference)
- A curated README (tools, datasets, papers). It is used to find future provider
  candidates; it is not a runtime dependency.

## Overlaps and defaults

| Capability | Default (routing order in the example config) | Alternatives | Independence note |
|---|---|---|---|
| Native decompilation | `ghidra_remcp` | `ghidra_mcpy`, `ida_official` (code-exec opt-in), `ida_rs`, `re_mcp_ida`, `binary_ninja` | the two Ghidra wrappers share family `ghidra`; the three IDA drivers share `ida` |
| Instruction listing | the engine providers | `builtin` (Capstone) | Capstone is an independent decoder |
| Binary metadata | `builtin` | each engine's own view | the file parser is direct evidence; engines are interpretations |
| APK manifest/components | `builtin` | `jadx` | independent parsers; disagreements are recorded |
| JavaScript/Electron (ASAR, fuses) | `rea` (only provider; disabled in the example) | — | engine family `rea`; no second engine to cross-check against |
| Dynamic | — (disabled) | `frida_mobile` | separate evidence kind; never automatic |
| AI reconstruction | — (disabled) | `llm4decompile` | never counted as corroboration |
