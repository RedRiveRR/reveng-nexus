# Architecture

```text
            Claude Code / any MCP client
                       │  stdio (default) or loopback Streamable HTTP
                       ▼
              ┌──────────────────┐
              │  NexusServer     │  server.py — stable nexus_* tools, JSON-schema validation,
              │  (MCP gateway)   │  bounded responses, untrusted-content notice
              └────────┬─────────┘
                       ▼
   ┌───────────────────────────────────────────────┐
   │ Orchestrator (orchestrator.py)                 │  deterministic workflows: analyze_binary,
   │                                                │  analyze_apk, compare_function, ai_decompile
   └────────┬───────────────────────────┬──────────┘
            ▼                           ▼
   ┌──────────────────┐        ┌──────────────────┐
   │ ProviderManager  │◄──────►│ PolicyEngine     │ policy.py — classify + decide every tool call
   │ (registry.py)    │        └──────────────────┘
   │ lifecycle,       │        ┌──────────────────┐
   │ capability       │───────►│ AuditLog         │ audit.py — metadata only, redacted
   │ registry,        │        └──────────────────┘
   │ routing,         │        ┌──────────────────┐
   │ failover, locks  │───────►│ EvidenceStore    │ evidence.py — SQLite, migrations, cases,
   └──┬─────┬─────┬───┘        └──────────────────┘ evidence, links, comparisons, findings
      │     │     │
      ▼     ▼     ▼
 builtin  McpProvider(s)              Llm4DecompileProvider
 (formats, + adapter per upstream:    (OpenAI-compatible completions,
 capstone) re_mcp, mcpyghidra,         operator-served model)
           ida_official, ida_rs,
           binary_ninja, jadx, frida_mobile
```

## Package layout (`src/reveng_nexus/`)

| Module | Responsibility |
|---|---|
| `config.py` | YAML schema, validation, `${VAR}` expansion, 0.1 key compatibility |
| `policy.py`, `security.py` | Tool classification (override → adapter manifest → trusted annotations → verb heuristic) and enforcement; deny patterns |
| `artifacts.py` | `WorkspaceGuard` (allowed roots, traversal, symlink/junction, NTFS ADS, size), hashing, identification, per-provider staged copies |
| `formats/` | ELF (pyelftools), PE (pefile), Mach-O headers, DEX header, APK + binary AndroidManifest parser, string extraction |
| `providers/base.py` | `AnalysisProvider` lifecycle, `ToolInfo`, `OperationResult`, policy/timeout/audit wrapper around every raw tool call |
| `providers/builtin.py` | Always-on static engine |
| `providers/mcp.py` | Child MCP servers: stdio, Streamable HTTP, launch-then-connect; owner tasks, restart budget, process-tree containment |
| `providers/llm4decompile.py` | Optional AI decompilation adapter |
| `adapters/` | Per-upstream bindings of Nexus operations to real tool names, manifests and normalisers, with pinned revisions |
| `registry.py` | `ProviderManager`: start/stop with failure isolation, capability registry and duplicate detection, routing, failover, semaphores, conflict-group locks, evidence recording |
| `compare.py` | Feature-based cross-engine comparison with rebasing and per-group independence |
| `orchestrator.py` | Workflows and function prioritisation |
| `evidence.py` | Evidence store and schema migrations |
| `report.py` | Markdown and JSON case export |
| `server.py` | MCP tool catalogue and handlers; stdio and loopback HTTP serving |
| `cli.py` | `status`, `providers list/check`, `capabilities`, `analyze`, `report`, `serve`, `config check/init` |

## Provider lifecycle

1. **Configure.** `ProviderConfig` is validated at load time: id, type, command or URL,
   timeouts, priority, `max_concurrency`, `conflict_group`, adapter, `tool_overrides`,
   environment. Unset `${VAR}` references are reported per provider; they never crash the gateway.
2. **Start.** `ProviderManager.start()` initialises every enabled provider concurrently
   with a startup timeout. A failure is recorded in `provider_errors` and the others
   continue. Dynamic providers are skipped unless dynamic analysis is enabled.
3. **Connect.** Each MCP connection lives in a dedicated *owner task*, because anyio cancel
   scopes must exit in the task that entered them. The child gets a minimal environment:
   the SDK's safe defaults, explicitly inherited variables, then provider `env`.
   Stdio children run under the SDK's Windows Job Object; launched HTTP servers get Nexus's
   own Job Object or POSIX process group.
4. **Discover.** `tools/list` is paginated to completion; each tool is classified and given
   a policy decision, which is re-checked on every call with the actual arguments.
5. **Operate.** `perform(operation, target, params)` goes through the adapter. Adapters
   check that their bound tools still exist, prepare a per-target session (open database,
   load APK) using a **staged copy**, call tools, and normalise results while keeping the raw output.
6. **Recover.** A closed connection (`MCPError CONNECTION_CLOSED`, broken pipe) tears the
   owner down. The next call reconnects, up to two restarts with backoff. Timeouts use
   `anyio.fail_after` per tool call, plus a per-operation budget.
7. **Shut down.** Adapters close their sessions (re-mcp saves only Nexus's private engine
   database), owners exit, and process trees are terminated.

## Routing and conflicts

- **Selection:** an explicit `provider_id` wins; otherwise `routing.preferred[operation]`,
  then descending `priority`, then id. Candidates that lack the capability, have a blocked
  binding, or don't handle the target format are skipped, and the reason is reported.
- **Failover:** sequential, at most `analysis.max_failover` extra candidates, only for
  availability errors (unavailable, timeout, provider error, missing capability). Policy
  violations never fail over. Every attempt is returned and audited.
- **Concurrency:** a global semaphore (`max_concurrent_provider_calls`), a per-provider
  semaphore (`max_concurrency`, default 1, so one analysis session is never driven
  concurrently), and a per-(`conflict_group`, target) lock so two drivers of the same engine
  never work on one target at once. Each provider gets its own staged copy, so engines never
  share a database file.
- **Duplicates:** `nexus_list_capabilities` lists operations offered by several providers
  of the same engine family, marked as failover or consistency, not independence.

## Evidence model

Every normalised result is stored with: case, target SHA-256, provider, original tool name,
operation, engine, engine family, engine/server version, subject (type, address, name),
normalised output, a hash-addressed raw output (truncated for storage, but the hash covers
the full output), warnings and, for AI, model provenance. Kinds: `direct_observation`,
`engine_derived`, `ai_generated` and `analyst_note`. Statuses move from `unverified` to
`corroborated`, `contradicted`, `verified`, `rejected` or `resolved`; only `nexus_review`
sets `verified`, `rejected` or `confirmed`. Links (`derived_from`, `agrees_with`,
`contradicts`, `same_subject`, …), comparisons, findings (with supporting and contradicting
evidence) and reviews are first-class tables. The schema is versioned (`schema_migrations`);
a 0.1 database is upgraded in place.

## Cross-engine comparison

`compare.py` compares features, not text: callees, numeric constants (C suffixes
normalised), string literals, control-keyword counts and parameter count from pseudocode;
mnemonic sequence and direct call targets from listings; start, size and name for identity.
Addresses are rebased on each provider's reported image base, and an unknown base is
reported as a limitation. Independence is judged **per group** (decompilation, disassembly,
identity) from engine families, and the overall verdict is the weakest content group. For
example, two Ghidra wrappers plus Capstone give `decompilation: same_family_consistency`
and `disassembly: independent_agreement`, so the overall verdict is
`same_family_consistency`. High-severity differences (callees, function start, call
targets) make the verdict `disagreement` and are stored, never silently resolved. AI output
is checked against engine features (calls or constants absent from every engine are
flagged) and never raises confidence.

## Why adapters instead of one merged codebase

The engines have different runtimes (JVM, idalib, the Binary Ninja GUI, Node, devices), MCP
SDK generations (all current upstreams pin `mcp<2`; the gateway uses 2.3), licences (GPL-3.0,
no licence at all, DeepSeek model terms) and release cadences. Process boundaries keep each
one isolated, replaceable and optional. A missing proprietary engine never disables the
open-source path.
