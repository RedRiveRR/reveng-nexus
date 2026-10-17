# Roadmap

Items are ticked only when the behaviour **and** its tests exist (see `docs/TESTING.md`).

## Phase 0: gateway foundation

- [x] Provider config validation (structured sections, `${VAR}` expansion, 0.1 compatibility)
- [x] Stdio, Streamable HTTP and launch-then-connect provider lifecycle with owner tasks and bounded restart
- [x] MCP SDK 2.3 server and client integration, tested over a real stdio subprocess and loopback HTTP
- [x] Stable `nexus_*` catalogue with JSON-schema validation; optional namespaced exposure
- [x] Policy engine: manifest/annotation/heuristic classification, unknown-tool blocking, code-exec and dynamic gating
- [x] Overrides cannot relax `blocked`/`execute`/`dynamic`/`lifecycle`; lifecycle tools never forwarded for a caller; undeclared arguments refused; explicit authorised device for dynamic calls (2026-10-15)
- [x] Metadata-only audit log, redaction
- [x] Workspace guard, SHA-256 identity, hash-verified staged copies
- [x] Permanent Windows deployment (`docs/DEPLOYMENT.md`), static `--check-config` diagnostics, `config init --create-dirs`
- [x] Claude Code connection at user scope, verified with real tool calls; background provider start for a fast handshake

## Phase 1: verified provider adapters

- [x] Pin upstream commits/packages and record licences (PROVIDER_MATRIX, THIRD_PARTY_NOTICES)
- [x] Ghidra via re-mcp-ghidra 3.0.3: `live_analysis_verified` for functions, decompile and xrefs (Ghidra 12.1.4)
- [x] Ghidra via MCPyGhidra 0.8.0: `live_analysis_verified` for decompile, including process-tree containment
- [x] Adapter contract tests against real MCP mock servers; child error translation, timeouts, crash isolation
- [x] Per-provider timeouts, concurrency limits, conflict-group locks, restart budget
- [x] Frida Mobile MCP mock contract tests from the pinned source (2026-10-15)
- [x] REA 6.5.0 as an adapter-only static provider on a dedicated Node 24: `js.application` and `electron.fuses` `live_analysis_verified` (2026-10-15)
- [ ] Runtime verification: official IDA MCP, ida-mcp-rs, re-mcp-ida (needs licensed IDA)
- [ ] Runtime verification: JADX MCP (needs a Maven build), Binary Ninja MCP (needs Binary Ninja)
- [ ] Runtime verification: Frida Mobile MCP (needs an authorised test device)
- [ ] Any further REA tool (each needs a review of its implementation at the pin first)

## Phase 2: normalised evidence

- [x] SQLite schema with migrations (0.1 → 2), cases, targets, evidence kinds, raw-output store
- [x] Normalised function, decompile, disassembly, xref, CFG, string, import/export, manifest results
- [x] Provenance per claim: provider, original tool, engine family, version, target hash, subject, time
- [x] Persisted comparisons with per-group independence, preserved disagreements and evidence links
- [x] Findings (supporting and contradicting evidence), reviews, Markdown/JSON export

## Phase 3: model-assisted reconstruction

- [x] Optional LLM4Decompile adapter (OpenAI-compatible completions, model verification, provenance, unverified by construction)
- [x] AI output checked against engine evidence; excluded from confidence
- [ ] Verification against a real served checkpoint
- [ ] Token/context budgeting and evidence chunking for large functions
- [ ] Evaluation suite with known binaries and reproducible ground truth

## Phase 4: operational hardening

- [x] Access profiles (`restricted` / `balanced` / `full_access`) with precedence rules, unknown-key
  validation and one access/exposure module shared by MCP `tools/list`, dispatch, listings, CLI and
  dashboard (2026-10-17, `tests/test_access_profiles.py`)
- [x] REA: all 207 tools classified at the pin; eight reviewed file analyses behind
  `nexus_inspect_artifact` (mock-tested; live verification still open)

- [ ] Sandboxed worker per untrusted sample (VM/container); Nexus currently provides **no** sandbox
- [ ] Authenticated HTTP mode (today: loopback only, unauthenticated)
- [ ] UI for provider health, evidence graph and analysis runs
- [ ] CI matrix for Python/JDK/Ghidra versions (Linux/macOS not yet run)
