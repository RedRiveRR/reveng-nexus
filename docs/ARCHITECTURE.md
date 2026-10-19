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
           binary_ninja, jadx, frida_mobile,
           rea (adapter-only)
```

## Package layout (`src/reveng_nexus/`)

| Module | Responsibility |
|---|---|
| `config.py` | YAML schema, validation, `${VAR}` expansion, 0.1 key compatibility |
| `access.py` | The one definition of what a caller can reach: per-tool access state (`exposed`, `callable`, `adapter_only`, `missing_prerequisite`, `blocked_by_profile`, `blocked_by_policy`, `catalogue_mismatch`, `unknown`), provider state, collision-free namespaced names and the exposure map. MCP `tools/list`, namespaced dispatch, `nexus_list_tools`, provider summaries, `describe()`, the CLI and snapshots all use it |
| `policy.py`, `security.py` | Access profile (`restricted`/`balanced`/`full_access`: derived reads callable or not, verified writes under full_access only); tool classification (protection-bypass and deny patterns → override → adapter manifest or the adapter's unlisted-tool class → trusted annotations → verb heuristic; an override may tighten but never relax `blocked`, `execute`, `dynamic` or `lifecycle`, nor a pinned (manifest/adapter) `mutate`, which can only stay `mutate` or become `blocked`, while a `mutate` guessed from the name stays reclassifiable; lifecycle tools are never forwarded for a caller) and enforcement, including refusal of arguments the tool's schema does not declare |
| `artifacts.py` | `WorkspaceGuard` (allowed roots, traversal, symlink/junction, NTFS ADS, size), hashing, identification, per-provider staged copies |
| `formats/` | ELF (pyelftools), PE (pefile), Mach-O headers, sections and `LC_SYMTAB` symbols, DEX header, APK + binary AndroidManifest parser, string extraction |
| `providers/base.py` | `AnalysisProvider` lifecycle, `ToolInfo`, `OperationResult`, policy/timeout/audit wrapper around every raw tool call |
| `providers/builtin.py` | Always-on static engine |
| `providers/mcp.py` | Child MCP servers: stdio, Streamable HTTP, launch-then-connect; owner tasks, restart budget, process-tree containment |
| `providers/llm4decompile.py` | Optional AI decompilation adapter |
| `adapters/` | Per-upstream bindings of Nexus operations to real tool names, manifests and normalisers, with pinned revisions. An adapter may also fix the provider kind (`provider_kind`, Frida: `dynamic`), the class of tools missing from its manifest (`unlisted_tool_class`: Frida `unknown`, REA `blocked`) and refuse all raw passthrough (`adapter_only`, REA). `tool_gate` lets an adapter withhold a tool for a reason beyond its class (REA: pin drift, profile tier, missing helper, not reviewed); it applies to listings, capability status and every call, the adapter's own included. REA's full classification is `adapters/rea_catalogue.py` |
| `registry.py` | `ProviderManager`: start/stop with failure isolation, capability registry and duplicate detection, routing, failover, semaphores, conflict-group locks, evidence recording |
| `compare.py` | Feature-based cross-engine comparison with rebasing and per-group independence |
| `orchestrator.py` | Workflows and function prioritisation |
| `evidence.py` | Evidence store and schema migrations |
| `report.py` | Markdown and JSON case export |
| `server.py` | MCP tool catalogue and handlers; stdio and loopback HTTP serving |
| `cli.py` | `status`, `providers list/check`, `capabilities`, `analyze`, `report`, `serve`, `dashboard`, `config check/init` |
| `snapshot.py` | Sanitised, read-only state file per running gateway (`<data_dir>/dashboard/gateway-<pid>.json`), written by `serve` in a failure-isolated task; carries the gateway's own policy decisions |
| `verification.py` | Documented verification state per provider (mirrors PROVIDER_MATRIX.md; checked by a test) |
| `dashboard/` | Loopback-only, GET-only Starlette app reading snapshots, the audit tail and evidence counts (read-only); static vanilla-JS console ([DASHBOARD.md](DASHBOARD.md)) |

## Provider lifecycle

1. **Configure.** `ProviderConfig` is validated at load time: id, type, command or URL,
   timeouts, priority, `max_concurrency`, `conflict_group`, adapter, `tool_overrides`,
   environment. Unset `${VAR}` references are reported per provider; they never crash the gateway.
   If the adapter declares a provider kind, an entry without `kind` gets it and a different
   `kind` is a config error, so dynamic gating cannot be skipped by omission.
2. **Start.** `ProviderManager.start()` initialises every enabled provider concurrently
   with a startup timeout. A failure is recorded in `provider_errors` and the others
   continue. Dynamic providers are skipped unless dynamic analysis is enabled.
3. **Connect.** Each MCP connection lives in a dedicated *owner task*, because anyio cancel
   scopes must exit in the task that entered them. The child gets a minimal environment:
   the SDK's safe defaults, explicitly inherited variables, then provider `env`.
   Stdio children run under the SDK's Windows Job Object; on POSIX they are started through
   `providers/_stdio_guard.py`, which runs the server in a process group of its own and empties
   that group when the server exits (the SDK alone kills the tree only of a server that fails
   to exit). The server's environment is the one Nexus built (the SDK's defaults merged with
   it), passed to the guard in encoded `REVENG_NEXUS_GUARD_ENV_*` variables that the server never
   sees, because the guard's own interpreter changes its environment at start-up. They are the
   guard's only variables besides the SDK's defaults, so a provider variable using that prefix
   travels inside the encoded copy like any other. A launch whose encoded copy (about 4/3 of the
   environment) would exceed the system's argument/environment limit is refused with a clear
   error. Launched HTTP servers get Nexus's own Job Object or POSIX process group.
4. **Discover.** `tools/list` is paginated to completion; each tool is classified and given
   a policy decision, which is re-checked on every call with the actual arguments and the
   tool's input schema. For an adapter-only provider (REA) every caller-initiated raw call is
   refused before policy, and its tools are not exposed in namespaced mode; only the adapter's
   internal calls reach it.
5. **Operate.** `perform(operation, target, params)` goes through the adapter. Adapters
   check that their bound tools still exist, prepare a per-target session (open database,
   load APK) using a **staged copy**, call tools, and normalise results while keeping the raw output.
6. **Recover.** A closed connection (`MCPError CONNECTION_CLOSED`, broken pipe) tears the
   owner down. The next call reconnects, up to two restarts with backoff; the budget starts over for a restart requested 10 minutes after the last restart attempt ended (successful or not). Timeouts use
   `anyio.fail_after` per tool call, plus a per-operation budget.
7. **Shut down.** Adapters close their sessions (re-mcp saves only Nexus's private engine
   database; the Frida adapter first asks the server to stop all instrumentation, bounded to
   5 s), owners exit, and process trees are terminated.

### Timeouts and their bounds (since 2026-10-14)

| Wait | Bound |
|---|---|
| Process start and MCP `initialize` handshake | `startup_timeout_seconds` (launched HTTP: `launch.startup_timeout_seconds`); the client's default read timeout is `max(timeout_seconds, startup budget)`, so a short per-call timeout cannot cut a slow but legitimate handshake short |
| `tools/list` right after a (re)connect | **one** deadline for the whole pagination = the startup budget |
| Any later re-list (`refresh_tools`) | **one** deadline for the whole pagination = `timeout_seconds` (default), at most 100 pages; a hung or slowly paginating server costs at most that budget, never pages × per-page timeout. On expiry the previous catalogue stays in use and the error is recorded in `provider_errors` |
| Health liveness probe | 15 s (`health()` 30 s overall) |
| Each tool call | `timeout_seconds`, passed explicitly; plus `analysis.operation_timeout_seconds` per operation |
| Abandoning a connection (`close`) | cooperative anyio cancel first (lets the SDK's shielded transport shutdown close stdin, kill the process tree and drain stdout), then a native cancel; each wait is bounded by the close timeout (20 s), so at most about 3 × 20 s. A task that still does not stop is reported and abandoned instead of hanging the gateway |

Trade-offs kept on purpose: a server whose initial listing takes longer than the startup budget
fails to start. At gateway start the manager additionally caps handshake **and** initial listing
together at `startup_timeout_seconds + 5`; a reconnect during an operation has no such joint cap
(each step is bounded by the startup budget, so up to twice that, within
`analysis.operation_timeout_seconds` when it happens inside an operation).

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
a 0.1 database is upgraded in place. Pending migrations run in one `BEGIN IMMEDIATE`
transaction that re-reads the ledger under the lock, so concurrent openers apply each version
once and a failed migration leaves no partial schema or ledger row.

Schema v3 adds investigation questions (`questions`, `question_evidence`,
`question_history`): an unknown stays visible until evidence answers it. Only source evidence (parsed
from the artifact or produced by an engine) can resolve a question. `nexus_review` cannot
authenticate its caller (the agent that wrote a note can review it), so a review never turns an
agent note or AI output into qualifying evidence; and when the only thing that removed a
source-derived contradiction is such a review, the resolution is recorded but `contested` and
does not count towards completeness. Contradictions between two cited records (a `contradicts` link) are never hidden by citing both as
support. Requiredness only increases: a required question can never be made optional through the
MCP interface (no caller can be authenticated as an operator entitled to waive it; mark it
`blocked` instead), and a question that was ever required counts as required everywhere. The
history keeps the evidence each resolution rested on and every `required` change; the report lists
every question.
The gateway checks provenance and contradictions, not whether the evidence semantically entails
the answer; that stays a reviewer's job. States are `open`,
`investigating`, `partial`, `blocked`, `contradicted` and `resolved`. Every update names the
revision it read (compare-and-set under a write lock), so a stale writer gets
`revision_conflict` instead of overwriting. `resolved` needs an answer and standing support
that is direct or engine-derived (a review never upgrades other evidence): AI output and agent
notes alone never resolve a question, and contradicting evidence (cited, or recorded as a
`contradicts` link against the support) must be rejected first. `nexus_compare_function` links
only records it compared with each other: records of one operation (decompilation with
decompilation, instruction listing with listing), pair by pair. A pair is `contradicts` when a
high-severity disagreement in that operation's aspects or in the function's start address is
between exactly those two records, `agrees_with` when they come from different engine families
and do not disagree, and `same_subject` when one engine family produced both. A re-run of one side
(same case, target, provider, operation and subject, with matching parameters where both runs
recorded them) gets a new evidence id but inherits that disagreement. Only an explicit
`agrees_with` between the same two sides, from a record with the support's engine identity
(engine and version), clears it, and a newer `contradicts` restores it; `same_subject` (single
source, one engine family, nothing to compare) is neutral and never clears one. Subjects match by
address when both records have one; otherwise by exact name, only when the provider reported that
name at no more than one address on the target. Links between different operations, which older
comparisons created by linking every compared record, are ambiguous and are not read as
contradictions. A stored state
that later reviews undermine is reported as `stale` and keeps the case incomplete. A target scope
(counts, listings, case brief, plan checklist) also covers the case-level questions (no target)
of the target's cases, so a target view is never complete while one of them is open. Listings are
bounded (ids capped per question, text truncated, offset paging that also stops by size with
`size_limited`); the case brief and the plan checklist rank required unresolved questions first
before applying their limits. Full detail is per question.

Retrieval is sized for agents. `nexus_get_evidence` lists newest first by
`(created_at, rowid)` and pages with an opaque keyset cursor bound to the query's filters; a
page holds at most 500 records and at most 150,000 characters as rendered in the response
(indentation included; less when the rest of the response needs the room). It holds at least one
record; `size_limited` says when the size cut the page, and the cursor continues after the last
record returned. A record too large for any page is returned alone with its bulky fields replaced
by size notes and an `oversized` note naming how to get it in full (`nexus_export_report` with
`include_raw`). No tool response is cut mid-text: one that would exceed the 200,000-character
limit is shortened into valid JSON, its largest strings and lists elided, under a
`response_truncated` note. With one writer and a monotonic clock, pages never repeat or skip
records while new evidence arrives (new records sort before the first page); a second
process committing an older timestamp late can sort behind a cursor already issued.
`view: summary` returns one short provenance line per record. `nexus_case_brief` gives a delegated agent a bounded summary:
counts always cover every record, every critical/high finding that is not rejected is listed
(up to 100, newest first), a target scope includes findings that cite any evidence about the
target and case-level findings without evidence, other lists are capped by `limit`, and anything left out is counted in
`omitted`. Findings and their evidence links load in two queries, not one per finding.

Schema v4 adds result reuse and idempotent writes. A single-operation tool (metadata,
functions, decompile, disassembly, xrefs, CFG, strings, APK components/class source, REA
operations) first asks whether this case already holds evidence for the same target SHA-256,
provider, operation, canonical parameters and engine fingerprint, from the provider routing
would try first; if so it returns that evidence with `reused: true` and an audit line
(`outcome: reused`) instead of calling the engine. The fingerprint is known before the call: the policy and access profile (a result is never
handed back under a different profile), provider class and a hash of its config, adapter pin,
a hash of this package's sources (a parser or adapter change is a new engine), and a verified
engine identity. Identity sources, per provider:

| Provider | Identity | Reused? |
|---|---|---|
| built-in | capstone, pyelftools and pefile versions | yes |
| re-mcp-ghidra, MCPyGhidra | `<GHIDRA_INSTALL_DIR>/Ghidra/application.properties` of the directory the child is given (version, release, build date, Ghidra git revision, file SHA-256; the file pyghidra reads at launch), the SHA-256 of `support/launch.properties` (`JAVA_HOME_OVERRIDE`, JVM arguments), and the runtime version and vendor from `<JAVA_HOME>/release` of the JDK the child is given | yes, when the Ghidra files exist |
| REA | the server-reported `rea-agents` version, which the adapter pins (any other version is drift and disables REA) | yes |
| IDA, Binary Ninja, JADX, others | none verifiable | no, unless the operator sets `settings.engine_identity` |

The Ghidra identity is computed only for servers Nexus launches (`mcp_stdio`,
`mcp_launched_http`), from the exact environment their child process gets (`build_child_env`,
case-insensitive on Windows), and only from absolute paths; an `mcp_http` server Nexus did not
start, or a relative `GHIDRA_INSTALL_DIR`, has no identity. The wrappers' MCP serverInfo is never
used as the engine identity: re-mcp-ghidra reports the FastMCP framework version there, so a
wrapper/framework version change neither proves nor hides a Ghidra change. The wrapper itself is
identified by the provider config (its hash is in the key), which is why the launch arguments must
pin the wrapper version (the example config does: `re-mcp-ghidra==3.0.3`, `mcpyghidra==0.8.0`). An
in-place Ghidra upgrade under the same path changes `application.properties` and therefore the
key. A raw provider call that is not classified `read` (rename, patch, script) clears the reuse
markers of that provider's stored results (for the target, or all targets of a shared server)
and records a persisted reuse block for that provider and target (or for every target of a
shared server): from then on its results there are never stored as reusable, because they
derive from analysis state Nexus cannot identify (an unsaved change can be lost on an engine
restart or rebuild). This applies to every such call that reached the engine, whether it
succeeds, fails, times out or is cancelled by the client (the block write runs as one job in a
worker thread that the caller waits for through AnyIO scope cancellation and repeated native
`Task.cancel()` alike, without blocking the event loop; a native cancellation that arrives
during the write is raised once the write has finished, even if the engine call had succeeded,
so that caller sees a cancellation for a change the engine made, while an AnyIO scope
cancellation is held off during the write and takes effect at the caller's next checkpoint), but not to a call the policy refused or to
a tool name the provider does not list, since neither reaches the engine. The shield cannot
help if the database write itself fails or cannot be started (for example a worker pool that is
already shut down): that is audited (`reuse_block_failed`), no block is claimed, and it is
reported as an error when the call itself had succeeded; an error or cancellation already
propagating is left unchanged. Reuse then stays off for that provider and target (or every target
of a shared server): a failed write fails closed, in this process and after a restart (below).
Until the block is written, an in-memory marker set before the call is sent (per provider and
target, like the block) keeps lookups from reusing results and keeps new results from being
stored as reusable, so a read that overlaps the mutation, its cancellation or its block write runs
the engine after the mutation instead of being served the earlier result.

The protection is also kept on disk, in a mutation journal (`<data_dir>/mutation-journal/`, one
small file per call, independent of the SQLite file whose write may fail). Before such a call is
sent, an entry is written durably: a temporary file is written, flushed and fsynced, then renamed
into place, and the directory is fsynced where the platform allows it (not on Windows, where NTFS
journals the metadata itself). If the entry cannot be written, the call is not sent (an error
names the cause and the audit log records `mutation_journal_failed`). The entry is removed only
after the reuse block is confirmed, or when the call was refused before reaching the engine or
cancelled before it was sent. When a gateway starts, it reads the journal before anything can be
reused (until then no result is reused at all) and, for every entry left behind - a failed block
write, or a stop between recording the call and confirming its block - re-applies the block and
then removes the entry; if the block still cannot be written, reuse stays off in that process and
the entry stays for the next start. This is conservative: a stop after the entry was written but
before the call left the gateway still blocks reuse for that provider and target, because a new
process cannot tell whether the engine saw the call. Entry names carry the provider id and the
target hash (or `all-targets`); the content adds only the tool name, process id and time, never
arguments, credentials, environment values or evidence. An entry whose content is damaged still
blocks what its name says. A file whose name cannot be parsed, or a journal location that cannot be
listed, turns reuse off for every provider until an operator inspects and removes it (the reason is
in each result's `reuse_status` and in the audit log as `mutation_journal_unreadable`); leftover
`.tmp` files come from a stop while recording, before the call could be sent, and are ignored.
Removing an entry by hand re-enables reuse only for results that no persisted block covers.
Gateways that share a data directory share the journal: one that starts while another has a call
in flight re-applies that call's block (the block the call itself would write) before removing its
entry, so this errs towards blocking.
One ordering edge is accepted: if an AnyIO scope cancellation is
already propagating and a native `Task.cancel()` also arrives during the write, AnyIO attributes
the native cancellation to its own scope (it follows the exception chain) and that scope absorbs
both; the block is still persisted.
Storing a result takes the write lock (`BEGIN IMMEDIATE`) before it checks for a block, and
writing a block clears existing keys in the same transaction, so a read that was in flight
during the mutation cannot leave a reusable result; lookups check the block as well. The evidence itself is kept, and
`reuse_status` names the call that caused the block. Servers Nexus did not launch have no
Ghidra identity, so changes other MCP clients make there are never cached over. When no identity can be verified, nothing is reused and each result's
`reuse_status` gives the reason; `settings.engine_identity` is an explicit, operator-attested opt-in
(change it after an upgrade).

Not covered, by design (use `refresh: true`, or change any provider `settings` value such as
`settings.cache_epoch`, which changes the config hash and so every key): a JDK Ghidra chooses
itself (no `JAVA_HOME` for the child, or a `JAVA_HOME_OVERRIDE`/saved JDK choice in the user's Ghidra
settings; `launch.properties` is hashed, the user settings directory is not); Ghidra extensions
installed in the user's settings directory; transitive Python packages of the `uvx` environments;
and Ghidra jars or native binaries patched in place without a new `application.properties`, which
official Ghidra releases never do (each release is a new versioned directory with its own
properties). Rejected or contradicted
evidence, AI-generated and dynamic results, and other cases are never reused; rows from before v4
carry no reuse key. `refresh: true` runs again. Workflows (`nexus_analyze_binary`,
`nexus_analyze_apk`, `nexus_compare_function`) still run fresh.

Writes take an optional `idempotency_key` (`idempotency_keys`, primary key tool + key). The
key row is written in the same transaction as the record, so a failed write does not consume
the key and concurrent retries write once; the same key with the same arguments returns the
current state of the original record (`idempotent_replay: true`), with different arguments it
is refused. The request is hashed as the handler reads it (lower-case target, parsed
address, schema defaults filled), and a replay repeats the original write's warnings, which are
stored in the same transaction as the record and its key (a concurrent replay never sees the key
without them, and a write whose warnings cannot be stored is rolled back as a whole). There
is no automatic retry anywhere in the gateway.

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

The engines have different runtimes (JVM, idalib, the Binary Ninja GUI, Node, including a
dedicated Node 24 for REA, devices), MCP
SDK generations (all current upstreams pin `mcp<2`; the gateway uses 2.3), licences (GPL-3.0,
no licence at all, DeepSeek model terms) and release cadences. Process boundaries keep each
one isolated, replaceable and optional. A missing proprietary engine never disables the
open-source path.
