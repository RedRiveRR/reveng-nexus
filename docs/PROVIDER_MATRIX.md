# Provider matrix

Last audited: **2026-10-14**.
Upstream repositories were shallow-cloned at the commits below and read as data; nothing
upstream was built or executed from those clones.

## Verification states

Re-audited **2026-10-14** against the installed environment. Each provider carries the
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
- The Binary Ninja bridge never sets `isError` and prefixes some answers with `File: <path>`. Error text was accepted as HLIL/listing rows, the preamble became a function name, and its JSON list bodies were mis-parsed (including decompile-by-address). Errors are now raised, the preamble must name the target, and bodies are parsed per operation.
- ida-mcp-rs strings carry `content` (was read as `value`, always `None`), imports have no module (was read as `module`), and `decompile`/`xrefs`/`basic_blocks` accept numeric addresses only (names were sent).
- Unrecognised shapes give an empty result plus a warning with the raw output kept; code-labelled outputs (pseudocode, HLIL, Java) are never filled from an unexpected document.

## Summary

| Provider id | Upstream | Pinned revision / package | Licence | Integration method | Verification state | Blocker |
|---|---|---|---|---|---|---|
| `builtin` | RevEng Nexus | repo 0.2.0; pyelftools 0.32, pefile 2024.8.26, capstone 5.0.9 | MIT (deps: Public domain / MIT / BSD-3) | in-process | `live_analysis_verified` (ELF, PE, Mach-O, APK fixtures) | — |
| `ghidra_remcp` | [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp), Ghidra backend | `7b38aa9`; PyPI `re-mcp-ghidra==3.0.3` | MIT OR Apache-2.0 | stdio MCP child via `uvx` | `live_analysis_verified` (2026-10-14 re-run) + `mock_tested` | — |
| `ghidra_mcpy` | [nightwing-us/mcpyghidra](https://github.com/nightwing-us/mcpyghidra) | `f1e130c` (v0.8.0); PyPI `mcpyghidra==0.8.0` | Apache-2.0 (+ NOTICE) | launch → JSON readiness → Streamable HTTP, one server per target | `live_analysis_verified` + `mock_tested` | — |
| `re_mcp_ida` | jtsylve/re-mcp, IDA backend | `7b38aa9`; PyPI `re-mcp-ida==3.0.3` | MIT OR Apache-2.0 | stdio MCP child via `uvx` | `mock_tested` (shared re_mcp adapter driven as `engine: ida` against the mock) | `blocked`: licensed IDA 9+ (none installed) |
| `ida_official` | [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp) | `df6de79`; PyPI `ida-mcp==20261008.0.1` | MIT | stdio MCP child; analysis only via `execute_python` (blocked by default) | `unit_tested` (manifest / code-execution gate) | `blocked`: licensed IDA 9.4+ with idalib |
| `ida_rs` | [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) | `15d16ab` (v9.5.0-beta.6); stable tag v9.4.5 | MIT | stdio MCP child (`--read-only`) | `mock_tested` (mock fixtures built from the pinned upstream source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against the real engine) | `blocked`: licensed IDA Pro 9.4; `IDADIR` unset |
| `binary_ninja` | [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) | `8c5134e`; npm `binary-ninja-mcp@1.0.0` | **GPL-3.0** | stdio npm bridge → BN plugin HTTP `127.0.0.1:9009` | `mock_tested` (mock fixtures built from the pinned upstream source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against the real engine) | `blocked`: Binary Ninja licence, GUI and plugin (nothing listening on 9009) |
| `jadx` | [Qtty/jadx-mcp-server](https://github.com/Qtty/jadx-mcp-server) | `4e6d890` (pom 1.0.0) | **no LICENSE file**: no redistribution rights | stdio Python MCP → JVM daemon `127.0.0.1:8765` | `mock_tested` (mock fixtures built from the pinned upstream source, see [ADAPTER_CONTRACTS.md](ADAPTER_CONTRACTS.md); never run against the real engine) | `blocked`: Maven build of the daemon (Maven absent; JDK 25 present); `JADX_MCP_HOME` unset |
| `frida_mobile` | [monkeywave/frida-mobile-mcp](https://github.com/monkeywave/frida-mobile-mcp) | `b2da55d`; npm `frida-mobile-mcp@0.2.3` | MIT | stdio npm child, **dynamic**, never started while policy is off | `unit_tested` (dynamic gating, hard blocks, not started when disabled); **no mock contract tests** | `blocked`: no authorised test device; no frida/adb; policy disabled by design |
| `llm4decompile` | [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | `85b364b` | code MIT; **weights: DeepSeek License Agreement** | OpenAI-compatible `/v1/completions` you serve | `mock_tested` (local mock HTTP endpoint; not MCP) | `blocked`: no served checkpoint (nothing listening on 8000/8080/11434/1234); weights deliberately not downloaded |
| `rea` | [morluto/rea](https://github.com/morluto/rea), npm `rea-agents` | candidate 6.4.0 (MIT, Node `^22.19 \|\| ^24.11 \|\| >=26`) | MIT | — | `not_integrated`: **evaluation paused** (2026-10-14) | installed Node 25.9.0 is outside REA's supported range; no REA code, config or download in this repo |
| — | [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist) | `db0bb3d` | MIT | none; Ghidra plugin acting as an MCP *client* of Nexus' loopback HTTP endpoint | `not_integrated` as a provider (by design); client path untested | Ghidra GUI session for the client test |
| — | [ram-elgov/awesome-llm-reverse-engineering](https://github.com/ram-elgov/awesome-llm-reverse-engineering) | `55366aa` | README states "MIT" | research reading list | `not_integrated` (not a runtime component) | — |

Unimplemented on purpose: reviewed IDAPython templates for `ida_official` (decision
pending), any Frida protection-bypass/memory-write/custom-script pass-through, automatic
model-weight download, an authenticated non-loopback HTTP mode, and REA (paused).

**Integration vs. redistribution.** Running an upstream as a separate process says nothing
about the right to copy it. Binary Ninja MCP is GPL-3.0 and jadx-mcp-server has no licence,
so neither may be vendored or redistributed with this project. Nexus only launches the
operator's own installations.

Caveat for `ghidra_mcpy` health: before any target is opened, health is `ready` on the basis
that the launch command resolves, and its health detail says "no live session". Its tools
are discovered, and policy-checked, when the first per-target server starts.

All ten upstream repositories existed and had recent commits on the verification date
(the most recent: ida-mcp 2026-10-08, ida-mcp-rs 2026-10-08, GhidrAssist 2026-09-20; the
oldest: awesome-llm-reverse-engineering 2025-07-28).

## Per-provider notes

### Built-in (`builtin`, always on)
- **Operations:** metadata, symbol-table/export function list, imports, exports and strings
  for ELF, PE and Mach-O (Mach-O is headers only); Capstone disassembly of
  symbol-bounded ranges; APK manifest and components (the project's own binary-XML parser).
- **Evidence:** parsed structures are `direct_observation`; Capstone output is `engine_derived`
  with engine family `capstone`. Capstone is independent of Ghidra and IDA, which makes it a
  real cross-check for instruction listings, but it does **no code discovery**.
- **Limitations:** no decompiler; no control-flow recovery; the PE function list is exports
  plus the entry point; Mach-O symbols are not decoded.

### Ghidra via re-mcp (`ghidra_remcp`)
- **Launch:** `uvx --python 3.12 re-mcp-ghidra==3.0.3` with `GHIDRA_INSTALL_DIR`, plus
  `GHIDRA_MCP_DISABLE_EXECUTE=1`, `GHIDRA_MCP_DISABLE_BATCH=1` and
  `GHIDRA_MCP_DISABLE_TOOL_SEARCH=1`. Requires Ghidra 12+ and JDK 21+. Upstream pins
  `mcp<2`; it runs in its own uvx environment, so it never conflicts with the gateway's MCP 2.3.
- **Observed contract:** 134 tools, all MCP-annotated; 41 remain callable under the default
  read-only policy. `open_database(file_path, database_id, run_auto_analysis, keep_open,
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
- Nexus cannot load a file into Binary Ninja through this bridge. Before each operation it
  checks that `get_binary_status` names the target, and refuses otherwise.
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
- Hard-blocked whatever the policy says: `bypass_ssl_pinning`, `run_prebuilt_script`
  (which ships SSL, root and jailbreak bypass scripts), `execute_script`, `write_memory`,
  `kill_process`, `hook_function` and `unhook_function` (custom JS bodies). Upstream's own
  defaults (custom scripts and memory writes off) are also set.
- `nexus_dynamic_analysis_status` reports policy and provider state without instrumenting
  anything.

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
| Dynamic | — (disabled) | `frida_mobile` | separate evidence kind; never automatic |
| AI reconstruction | — (disabled) | `llm4decompile` | never counted as corroboration |
