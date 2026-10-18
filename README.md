# RevEng Nexus

**One local MCP gateway for evidence-driven, multi-engine reverse engineering.**

RevEng Nexus gives Claude Code (or any MCP client) one stable set of `nexus_*` tools over
several reverse-engineering engines. It identifies the artefact, routes each operation to a
suitable engine, enforces a read-only-first policy, records every result as provenance-backed
evidence, compares engines without hiding their disagreements, and exports reports. Each
engine stays a separate, pinned, optional process with its own licence; nothing upstream is
vendored.

> **Status (0.2.0, updated 2026-10-16).** The gateway, policy engine, evidence store, comparison
> and reporting are implemented and tested. Exact, observed test counts for each command
> are in [docs/TESTING.md](docs/TESTING.md#test-accounting); four tests are
> environment-gated (two opt-in live Ghidra tests, opt-in live REA, and a symlink test needing Windows Developer Mode).
> The **Ghidra path is verified end to end with real Ghidra 12.1.4** through two upstreams
> (re-mcp-ghidra 3.0.3 and MCPyGhidra 0.8.0), including a permanent Windows deployment and a
> real Claude Code connection. Since 2026-10-15, REA (`rea-agents` 6.5.0) is verified live for
> two static operations only (JavaScript/Electron ASAR analysis and Electron fuses); all its
> other tools are blocked. IDA, Binary Ninja, JADX and Frida adapters are tested against mocks
> built from the pinned upstream source but **were never executed** against the real engines
> here (no licence, GUI, Maven build or test device). LLM4Decompile is tested only against a
> mock inference endpoint. See
> [docs/PROVIDER_MATRIX.md](docs/PROVIDER_MATRIX.md) for each provider's verification state.

## What works today

| Area | State |
|---|---|
| MCP gateway (stdio; loopback Streamable HTTP) | working; tested over a real stdio subprocess and over HTTP |
| Built-in engine: ELF/PE/Mach-O/DEX/APK parsing, strings, Capstone disassembly, AndroidManifest decoding | working, always available; verified on the generated ELF/PE/Mach-O/APK fixtures for the operations listed in [docs/PROVIDER_MATRIX.md](docs/PROVIDER_MATRIX.md) (Mach-O: headers, sections and `LC_SYMTAB` symbols) |
| Ghidra via `re-mcp-ghidra` (stdio) and `mcpyghidra-headless` (launched HTTP) | working: `live_analysis_verified` for the operations listed per upstream in [docs/PROVIDER_MATRIX.md](docs/PROVIDER_MATRIX.md) (on both: metadata, functions, decompile, disassemble, xrefs to/from, cfg, strings, imports, exports, on the generated ELF fixture) |
| Routing, sequential failover, per-provider concurrency, conflict-group locks, duplicate-capability detection | working (tested with real MCP mock engines) |
| Cross-engine comparison (rebased identity, callees, constants, strings, call targets; per-group independence) | working |
| Evidence store (SQLite, migrations), cases, findings, reviews, Markdown/JSON reports | working |
| Policy: read-only, code execution, dynamic analysis, workspace guard, audit, redaction | enforced and tested |
| REA: static JavaScript/Electron (ASAR) analysis and Electron fuses | working for these two operations (`live_analysis_verified`, opt-in; disabled in the example config); every other REA tool blocked |
| IDA (official / ida-mcp-rs / re-mcp-ida), Binary Ninja, JADX, Frida | adapters exist (mock-tested, except `ida_official`: gating only); **not runtime-tested here** |
| LLM4Decompile | adapter tested against a mock OpenAI-compatible server only |
| Local dashboard (`reveng-nexus dashboard`, http://127.0.0.1:8770/) | read-only console over gateway snapshots in five sections: Overview (health at a glance), Catalog (providers and tools with their policy decisions), Security, Activity (audit history) and System (architecture, definitions, diagnostics); details on demand; loopback only, GET only, no authentication, so readable by any process running as your user ([docs/DASHBOARD.md](docs/DASHBOARD.md)) |

## Quick start (Windows PowerShell, Ghidra-first, no commercial software)

Prerequisites: Python 3.11+ (3.12 tested), [uv](https://docs.astral.sh/uv/) (provides `uvx`),
a JDK 21+, and [Ghidra 12.x](https://github.com/NationalSecurityAgency/ghidra/releases)
extracted somewhere (12.1.4 was used for verification).

The recommended layout keeps everything machine-specific outside the repository and
outside OneDrive; see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full table and how to
change paths later.

```powershell
cd reveng-nexus
$base = "$env:LOCALAPPDATA\RevEngNexus"
uv venv "$base\venv" --python 3.12
$env:VIRTUAL_ENV = "$base\venv"; uv pip install -e ".[disasm]"
$nx = "$base\venv\Scripts\reveng-nexus.exe"

# Generate a validated config (never committed) and create the workspace/data folders:
& $nx config init --workspace "$env:USERPROFILE\RevEngNexus\workspace" `
    --data-dir "$base\data" --create-dirs `
    --enable ghidra_remcp --enable ghidra_mcpy `
    --ghidra-dir "$env:LOCALAPPDATA\Programs\Ghidra\ghidra_12.1.4_PUBLIC" `
    --output "$base\config\providers.yaml"
$cfg = "$base\config\providers.yaml"

& $nx --config $cfg --check-config        # static diagnostics: missing paths, tools, env vars
& $nx --config $cfg providers check       # starts each provider on its own (first run downloads pinned packages)
& $nx --config $cfg analyze "$env:USERPROFILE\RevEngNexus\workspace\sample.elf" --compare
& $nx --config $cfg report <case-id>
```

Linux/macOS: replace the paths, use `.venv/bin/reveng-nexus`, and for JADX use
`.venv/bin/python` in its `command`.

Without Ghidra, the gateway still runs: the built-in engine provides metadata, strings,
imports/exports, symbol-table functions, Capstone disassembly and APK manifest analysis.
Decompilation then reports `capability_unavailable` with the providers that could supply it.

## Connect Claude Code

Register at **user scope**, so machine-specific paths stay out of the repository. Use
absolute paths, because Claude Code starts the server from arbitrary working directories:

```powershell
claude mcp add --scope user reveng-nexus -- "$env:LOCALAPPDATA\RevEngNexus\venv\Scripts\reveng-nexus.exe" `
    --config "$env:LOCALAPPDATA\RevEngNexus\config\providers.yaml" serve
claude mcp get reveng-nexus      # expect: Status ✔ Connected
```

This was done and verified on the integration machine (2026-10-13). `claude mcp get`
reported *Connected*, and a non-interactive Claude Code session called `nexus_status` and
`nexus_list_targets` through the real connection (see [docs/TESTING.md](docs/TESTING.md)).
The gateway answers the MCP handshake immediately and starts providers in the
background, so tool calls made while Ghidra is still starting simply wait.

The server speaks MCP on stdout, so nothing else is printed there; diagnostics go to stderr
and to per-provider logs in `<data_dir>/logs/`. Avoid a project-scoped `.mcp.json` with
absolute paths (`.mcp.json` is git-ignored here for that reason).

For MCP clients that only speak HTTP (for example GhidrAssist's MCP client):
`reveng-nexus --config … serve --transport http --port 8765` serves
`http://127.0.0.1:8765/mcp`. It binds loopback only and has no authentication.

## Tool catalogue

| Group | Tools |
|---|---|
| Discovery | `nexus_status`, `nexus_list_providers`, `nexus_list_capabilities`, `nexus_list_tools`, `nexus_plan_analysis` |
| Intake | `nexus_inspect_target` (workspace check, SHA-256, format/arch, case), `nexus_list_targets` |
| Native static | `nexus_analyze_binary`, `nexus_get_binary_metadata`, `nexus_list_functions`, `nexus_decompile_function`, `nexus_disassemble_function`, `nexus_get_xrefs`, `nexus_get_control_flow`, `nexus_search_strings`, `nexus_compare_function` |
| AI (optional) | `nexus_ai_decompile` (always `ai_generated` / `unverified`) |
| Android | `nexus_analyze_apk`, `nexus_inspect_android_components`, `nexus_get_class_source` (JADX) |
| JavaScript/Electron (REA) | `nexus_analyze_javascript_app` (ASAR parsed as inert text), `nexus_get_electron_fuses` |
| Dynamic | `nexus_dynamic_analysis_status` (read-only status; instrumentation is policy-gated) |
| Findings/evidence | `nexus_record_finding`, `nexus_get_findings`, `nexus_record_evidence`, `nexus_get_evidence`, `nexus_review`, `nexus_export_report` |
| Compact retrieval | `nexus_case_brief` (bounded case/target summary for delegated work: counts, every critical/high finding, unresolved questions, an `omitted` map); `nexus_get_evidence` pages newest-first with `next_cursor` and has `view: summary` |
| Reuse and retries | Single-operation tools return an existing result (`reused: true`) when this case already holds one from the same provider for the same target, operation, parameters and engine fingerprint; `refresh: true` runs again. Writes (`nexus_record_finding`, `nexus_record_evidence`, `nexus_review`, `nexus_record_question`, `nexus_update_question`) take an optional `idempotency_key`: a retry returns the original result (`idempotent_replay: true`) |
| Investigation questions | `nexus_record_question`, `nexus_update_question` (needs `expected_revision`; evidence-gated states), `nexus_list_questions`; `nexus_plan_analysis(target)` adds a bounded checklist of open questions and existing evidence |
| Escape hatch | `nexus_call_provider_tool` (raw upstream tool, policy-checked and audited; refused for adapter-only providers such as REA) |

Every result carries an `evidence_id` and provenance (provider, original tool, engine,
engine family, version, raw-output hash). `server.tool_mode: namespaced` additionally
exposes each callable upstream tool as `<provider>__<tool>`.

Typical agent flow: `nexus_status` → `nexus_inspect_target` → `nexus_plan_analysis(target)`
(reuse existing evidence, see open questions) → `nexus_record_question` for each unknown →
`nexus_analyze_binary` → focused tools → `nexus_compare_function` on important functions → `nexus_record_finding`
citing evidence ids → `nexus_update_question` as answers arrive → `nexus_review` →
`nexus_export_report` (lists unresolved questions; never calls an incomplete case complete).

## Optional engines (manual prerequisites)

| Provider id | You must provide |
|---|---|
| `ida_official`, `ida_rs`, `re_mcp_ida` | A licensed IDA Pro 9.4+ (idalib). The official server analyses only through `execute_python`, which stays blocked unless you enable `policy.allow_code_execution` for it. Enable **one** IDA controller per installation (they share `conflict_group: ida`). |
| `binary_ninja` | A licensed Binary Ninja with the `binary_ninja_mcp` plugin running its server on `127.0.0.1:9009`, and the target open in the GUI. |
| `jadx` | A checkout of Qtty/jadx-mcp-server built with Maven (`mvn clean package`, JDK 17+), its Python venv, and `JADX_MCP_HOME` set. |
| `frida_mobile` | An authorised, disposable test device with frida-server, plus `policy.dynamic_analysis` with explicit `authorized_devices`, `authorized_targets` and `allowed_tools`. Instrumentation calls must name the authorised device and target explicitly. |
| `rea` | A dedicated Node 22.19+/24.11+ and a pinned local `rea-agents` 6.5.0 install, never `npx` (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#rea-optional-dedicated-node-runtime)). |
| `llm4decompile` | A locally served LLM4Decompile checkpoint behind `/v1/completions` (e.g. vLLM). Weights are under the DeepSeek model licence. |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, provider lifecycle, routing, evidence and comparison model
- [docs/PROVIDER_MATRIX.md](docs/PROVIDER_MATRIX.md): every upstream: pin, licence, launch command, verification level, limitations
- [docs/SECURITY.md](docs/SECURITY.md): enforced controls (with tests), residual risks, deployment advice
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): permanent Windows layout, Claude Code registration, changing paths, isolation
- [docs/DASHBOARD.md](docs/DASHBOARD.md): the local read-only dashboard: architecture, metric definitions, security, the 41-vs-66 tool-count finding
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): environment, checks, how to add an adapter
- [docs/OBSIDIAN_WORKFLOW.md](docs/OBSIDIAN_WORKFLOW.md): the private project-memory vault and token-saving session workflow
- [docs/TESTING.md](docs/TESTING.md): what the tests cover, and the exact results from this machine
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md): upstream and dependency licences
- [config/providers.example.yaml](config/providers.example.yaml): annotated configuration

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Target intake is disabled until workspace.allowed_roots is configured` | Add your samples folder to `workspace.allowed_roots`, or use `config init --workspace`. |
| `executable 'uvx' was not found` | Install uv, or set `command` to an absolute path. |
| `environment variables referenced in config are unset: ['GHIDRA_INSTALL_DIR']` | Set the variable, or rerun `config init --ghidra-dir`. |
| Ghidra provider times out on first start | The first `uvx` run downloads packages and Ghidra analyses the file; raise `startup_timeout_seconds`. Check `<data_dir>/logs/<provider>.log`. |
| `existing engine database could not be reopened … rebuilt it` | Expected after an interrupted session; Nexus rebuilt its private staged database. |
| `capability_unavailable` | `nexus_list_capabilities` shows which providers could supply the operation and why each is unavailable. |
| Tool shows `callable: false` | It is classified mutate, execute, dynamic or unknown. See `nexus_list_tools(include_blocked=true)` for the reason. Change policy only for an authorised need. |

## Licence

RevEng Nexus is MIT-licensed; that covers this repository only. Upstream engines, servers and
model weights keep their own licences (GPL-3.0 for Binary Ninja MCP, none at all for
jadx-mcp-server, the DeepSeek terms for LLM4Decompile weights, among others). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Use Nexus only on software you are
authorised to analyse, and run unknown samples in an isolated VM. Nexus provides no sandbox.
