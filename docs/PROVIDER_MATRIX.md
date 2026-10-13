# Provider matrix

Verification date: **2026-10-13**. Repositories were shallow-cloned at the commits below and
read as data (nothing upstream was built or executed from the clones). Each row has a
**verification level**:

- **runtime**: launched through RevEng Nexus on this machine (Windows 11 Pro 10.0.26200,
  Python 3.12 via uv, Temurin JDK 25.0.2, Ghidra 12.1.4) against the generated benign ELF
  fixture. Tool lists and argument shapes come from the live `tools/list`.
- **source**: tool names and argument names read from the upstream source at the pinned
  commit. The adapter exists and is unit-tested against mocks of that contract, but the real
  engine was **not** available here (licence, GUI, device or build tool missing).
- **snapshot**: taken from the upstream's own committed `tools/list` snapshot.
- **reference**: not a runtime component.

Run `reveng-nexus --config config/providers.yaml providers check` after installing an engine.
It starts each enabled provider on its own, lists its tools, shows which ones policy allows,
and reports health. If an upstream renames a tool, the operation is reported as unavailable
with the reason, rather than failing at call time.

## Summary

| Provider id (example config) | Upstream | Pinned revision / package | Licence | Integration | Verification | Status here |
|---|---|---|---|---|---|---|
| `builtin` | RevEng Nexus | this repo 0.2.0; pyelftools 0.32, pefile 2024.8.26, capstone 5.0.9 | MIT (+ Public domain / MIT / BSD-3) | in-process | runtime + unit tests | **working** |
| `ghidra_remcp` | [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp) (Ghidra backend) | `7b38aa9`; PyPI `re-mcp-ghidra==3.0.3` | MIT OR Apache-2.0 | stdio MCP child via `uvx` | **runtime** | **working** (default open-source decompiler) |
| `ghidra_mcpy` | [nightwing-us/mcpyghidra](https://github.com/nightwing-us/mcpyghidra) | `f1e130c` (tag v0.8.0); PyPI `mcpyghidra==0.8.0` | Apache-2.0 (NOTICE file) | launch → JSON readiness → Streamable HTTP, one server per target | **runtime** | **working** |
| `ida_official` | [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp) | `df6de79`; PyPI `ida-mcp==20261008.0.1` | MIT | stdio MCP child | snapshot | not run (needs licensed IDA 9.4+ with idalib) |
| `ida_rs` | [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) | `15d16ab` (v9.5.0-beta.6); latest stable tag v9.4.5 | MIT | stdio MCP child (`--read-only`) | source | not run (needs licensed IDA Pro 9.4) |
| `re_mcp_ida` | jtsylve/re-mcp (IDA backend) | `7b38aa9`; PyPI `re-mcp-ida==3.0.3` | MIT OR Apache-2.0 | stdio MCP child via `uvx` | source (same tool contract as the runtime-verified Ghidra backend) | not run (needs licensed IDA 9+) |
| `binary_ninja` | [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) | `8c5134e`; npm `binary-ninja-mcp@1.0.0` | **GPL-3.0** | stdio npm bridge → BN plugin HTTP `127.0.0.1:9009` | source | not run (needs Binary Ninja GUI + plugin) |
| `jadx` | [Qtty/jadx-mcp-server](https://github.com/Qtty/jadx-mcp-server) | `4e6d890` (pom 1.0.0) | **no LICENSE file** (no rights granted) | stdio Python MCP → JVM daemon `127.0.0.1:8765` | source | not run (needs a Maven build; Maven absent) |
| `frida_mobile` | [monkeywave/frida-mobile-mcp](https://github.com/monkeywave/frida-mobile-mcp) | `b2da55d`; npm `frida-mobile-mcp@0.2.3` | MIT | stdio npm child, **dynamic** (off by default) | source | not run (no authorised test device) |
| `llm4decompile` | [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | `85b364b` | code MIT; **weights: DeepSeek License Agreement** (LICENSE-MODEL) | OpenAI-compatible `/v1/completions` endpoint that **you** serve | unit-tested against a local mock endpoint | not run against real weights (no GPU/weights downloaded) |
| — | [symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist) | `db0bb3d` | MIT | Ghidra **plugin** and MCP *client*; not a provider | source | optional companion (see below) |
| — | [ram-elgov/awesome-llm-reverse-engineering](https://github.com/ram-elgov/awesome-llm-reverse-engineering) | `55366aa` | README states "MIT" (no separate LICENSE file) | reading list | reference | not a runtime dependency |

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
- Put all IDA providers in `conflict_group: ida`. Nexus serialises them per target and gives
  each its own staged copy, so two drivers never share one `.i64`.

### Binary Ninja (`binary_ninja`)
- The GUI plugin serves HTTP on `127.0.0.1:9009`; the npm bridge speaks MCP over stdio. The
  bridge tools carry **no annotations**, so Nexus uses an explicit read/mutate allowlist from
  `bridge/src/tools.ts`.
- Nexus cannot load a file into Binary Ninja through this bridge. Before each operation it
  checks that `get_binary_status` names the target, and refuses otherwise.
- **GPL-3.0:** Nexus talks to it only as a separate process over MCP and does not copy or link
  its code.

### JADX (`jadx`)
- Python MCP layer (`mcp==1.27.2`) supervising a JADX JVM daemon on `127.0.0.1:8765`. Build
  it with `mvn clean package` (needs JDK 17+ and Maven), create a venv, then install
  `mcp_server/requirements.txt`. Set `JADX_MCP_HOME` and use a smaller `JADX_HEAP` than the
  upstream default of 24g.
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
