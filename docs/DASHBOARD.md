# Local dashboard

A read-only web console for RevEng Nexus in five sections: Overview (is Nexus healthy?),
Catalog (providers and tools), Security (what is allowed and blocked), Activity (what has
happened) and System (architecture, definitions, diagnostics). Simple by default; every
technical detail stays reachable through disclosures, drawers and filters. It cannot call a tool, change policy or read arbitrary files.

```powershell
reveng-nexus --config "$env:LOCALAPPDATA\RevEngNexus\config\providers.yaml" dashboard
# -> http://127.0.0.1:8770/   (Ctrl+C stops it)
```

Options: `--port N` (default 8770), `--host 127.0.0.1|localhost|::1`. Any other host is
refused (exit 2). Confirm the binding with `netstat -ano | findstr :8770`: the only
`LISTENING` line must be `127.0.0.1:8770`.

## Architecture: snapshots, not a second gateway

```
Claude Code ──stdio──> reveng-nexus serve ──> providers (Ghidra, REA, ...)
                              │ best effort: heartbeat every 10 s, rewrite on change
                              ▼
          <data_dir>/dashboard/gateway-<pid>.json   (sanitised state)
                              │ read only
                              ▼
   reveng-nexus dashboard (127.0.0.1:8770) <── browser (GET only)
        also reads: <data_dir>/audit.jsonl (tail), evidence.sqlite3 (mode=ro, counts)
```

* **The gateway is the only authority.** `snapshot.py` runs inside `reveng-nexus serve` and
  serialises the gateway's live catalogue together with each tool's `PolicyDecision` and
  `ToolInfo.callable`, the adapter's operation bindings, the last health result and the
  effective policy. The dashboard never classifies or decides anything itself.
* **No duplicate gateway.** The dashboard starts no provider and opens no connection to the
  gateway. It reads files in the configured `data_dir`; no request parameter can choose a
  path.
* **Isolated from MCP.** The snapshot writer is a separate asyncio task. A failure is
  counted, reported on stderr and never raised; nothing is written to stdout (the stdio
  transport). Set `REVENG_NEXUS_DASHBOARD_SNAPSHOT=0` to disable it. Health is refreshed at
  most every 5 minutes (one `tools/list` round trip per provider, as `nexus_status` does);
  heartbeats in between do not trigger probes. The dashboard need not run for MCP
  calls to work, and it works without a running gateway (configuration and documented
  verification only).
* **Several gateways.** Each Claude Code session runs its own gateway, so there can be
  several snapshot files. The newest *live* one is primary; all are listed with their state.
* **Liveness without touching processes.** A snapshot is `live` if its last heartbeat (the
  newer of `written_at` and the file's modification time) is within 30 s, `stopped` if the
  gateway marked it on a clean shutdown, `stale` otherwise (killed or hung). The dashboard
  never signals or probes processes.

## Snapshot files: location, writes and retention

* **Location:** `<data_dir>\dashboard\gateway-<pid>.json`, one stable file per gateway
  process (about 1 MB with the Ghidra and REA catalogues). No history file is created per
  heartbeat.
* **Atomic updates:** the writer writes `gateway-<pid>.json.tmp` and moves it over the stable
  file with an atomic replace. The dashboard reads only `gateway-<pid>.json`, never a `.tmp`,
  so it cannot see a partial file. On Windows a read that coincides with the replace can fail
  with a momentary sharing violation (measured 2026-10-16: 12 such errors during 300 replaces
  of a 1 MB file with a reader polling in a tight loop, all recovered by retry, no partial
  read); the reader retries those, and a file that is still unreadable is
  skipped and counted in the Overview warnings. The writer composes the snapshot on the
  gateway's event loop but does all file I/O, including replace retries, in a worker thread,
  so a reader holding the file can never stall MCP traffic; a replace that loses every retry
  is counted as a write failure and repeated at the next heartbeat.
* **Write volume:** the full file is rewritten only when its content changes, or every 5
  minutes; otherwise each 10-second heartbeat only updates the file's modification time.
* **Retention (bounded, owner-scoped):** when a gateway writes for the first time, and then
  at most hourly, it removes old files of *other, inactive* gateways: only regular files
  named `gateway-<pid>.json` or `gateway-<pid>.json.tmp` directly in `<data_dir>\dashboard`;
  never its own file; never a file touched in the last 15 minutes (a running gateway touches
  its file every 10 s). Of the rest, the 10 newest snapshots younger than 7 days are kept;
  older ones and leftover `.tmp` files from interrupted writes are deleted. Nothing else in
  the data directory is ever deleted. Disk use is bounded by (running gateways + 10) files.
* **Missing or stale snapshots:** with no snapshot the dashboard shows the configuration and
  the documented verification only, marked unavailable; a stopped or stale snapshot is shown
  as last known state with its age, never as live.

## Metric definitions

The figures are deliberately separate, because they measure different things. One is
never used in place of another.

| Metric | Definition | Source |
|---|---|---|
| Upstream tools discovered | tools the provider's MCP server returned from `tools/list` | gateway catalogue |
| Allowed by policy | discovered tools whose effective decision is *allowed* (access profile and adapter gate included); includes tools an adapter-only provider uses internally and tools waiting for a prerequisite | `access.tool_access().policy_allowed` |
| Available | usable now, directly or through a `nexus_*` operation: states `exposed`, `callable`, `adapter_only` | `access.tool_access().available` |
| Callable through Nexus | allowed, not adapter-only, not withheld by the adapter: what a caller can invoke via `nexus_call_provider_tool` (every call is re-decided with its arguments) | `access.tool_access().callable` |
| Exposed to MCP clients | raw provider tools listed to Claude Code as their own tools: exactly the names `tools/list` returns (`access.exposure_map`). Only in `tool_mode: namespaced` with `expose_tools`. In the default `compact` mode it is **0** | `access.exposure_map` |
| Blocked | discovered tools that are not allowed (mutate under read-only, unverified mutate, execute, dynamic, lifecycle for callers, blocked, unknown, profile- or adapter-withheld, drifted) | `policy_allowed == false` |
| Access states | one per tool: `exposed`, `callable`, `adapter_only`, `missing_prerequisite`, `blocked_by_profile`, `blocked_by_policy`, `catalogue_mismatch`, `unknown` ([SECURITY.md](SECURITY.md#access-profiles)) | `access.tool_access().state`, snapshot `tool_states` |
| Operations declared / usable | Nexus operations an adapter binds / whose required tools are present and allowed now | `list_capabilities()` |
| Nexus tools exposed | the gateway's own `nexus_*` tools (always listed) | `server.TOOL_SPECS` |

The same counts are in `nexus_list_providers` (`tool_count`, `policy_allowed_tool_count`,
`available_tool_count`, `callable_tool_count`, `exposed_tool_count`, `adapter_only`, and
`access.tool_states`) and in `providers check` (`tools_total`, `tools_policy_allowed_count`,
`tools_callable_count`, `tool_states`). Since 2026-10-17 every one of them, MCP `tools/list` and
namespaced dispatch come from one module, `access.py`; `tests/test_access_profiles.py` checks
that they agree in every profile and tool mode and that they match actual invocation. The
snapshot schema is version 2 (adds `access_profile`, per-tool `access_state`, `tool_states`).

Each datum is labelled with its freshness: **live** (recent heartbeat), **stopped** or
**stale** (last known state), **historical** (the documented verification record from
[PROVIDER_MATRIX.md](PROVIDER_MATRIX.md), via `verification.py`), **unavailable** (no
source). A provider's documented verification is never inferred from it being enabled or
healthy; `tests/test_dashboard.py` checks `verification.py` against the matrix.

## Finding: "41 callable" versus 66 (re-mcp-ghidra), 2026-10-16

**What changed:** nothing in the policy. **What differed:** what was counted.

* The 2026-10-13 records ("134 tools / 41 callable" in [TESTING.md](TESTING.md), the
  provider matrix and the private vault) came from `providers check`. Without `--verbose` it
  printed `tools_callable` shortened to the first 40 names plus a `"..."` entry
  (`cli.py` at `06a8443`, lines 218-219). A list of 41 entries was read as a count. The
  same truncation was still in place at `2bbef45`, and its 2026-10-16 output showed 40
  names and `"..."` again.
* Evidence: the live re-mcp-ghidra 3.0.3 catalogue (134 tools, captured 2026-10-16 with a
  read-only `tools/list`, no target opened) was classified offline with the policy, security
  and adapter code of `06a8443` and of `2bbef45`. Both give **66 allowed of 134**, with no
  tool classified differently. The `2bbef45` replay matched the running gateway's decision
  for every tool. `security.py` (the verb heuristic) is unchanged since `06a8443`, the re-mcp
  manifest is identical, and the later `policy.py` changes only *tighten* `readOnlyHint`
  handling, so they could not have raised a count.
* Breakdown at HEAD: 60 read via trusted annotations + 6 read via the pinned manifest = 66
  allowed; 62 + 2 mutate (annotations / manifest), 3 lifecycle, 1 blocked meta-tool = 68
  blocked.
* Not provable: the 2026-10-13 catalogue itself was not retained. The conclusion assumes it
  equalled today's, which is supported by the same pinned package (`re-mcp-ghidra==3.0.3`)
  and the same total (134).
* Fix: `providers check` now prints explicit counts and marks a shortened list as
  `"... (+N more)"`; provider listings carry the three distinct counts.

## REA: 207 discovered, 10 enabled, 0 callable

Since 2026-10-17 all 207 tools are classified at the pin and ten file-scoped reads can be enabled:
the two below in every profile, plus eight `artifact.inspect` analyses (`nexus_inspect_artifact`)
under balanced and full_access, which were reviewed at the pin but not run live. Under the default
(balanced) the dashboard therefore shows 10 allowed, 9 available when `REA_WABT_BIN_DIRECTORY` is
unset (`wasm_artifact` is `missing_prerequisite`), 0 callable, 3/3 operations; under restricted
2 allowed and 2/3 operations. The history below describes the state before that change.

### 2026-10-16: 207 discovered, 2 allowed, 0 callable, 2/2 operations

Consistent, and now reported explicitly. REA's catalogue has 207 tools. The adapter
allowlists exactly two, `analyze_javascript_application` (operation `js.application`, Nexus
tool `nexus_analyze_javascript_app`) and `inspect_electron_fuses` (`electron.fuses`,
`nexus_get_electron_fuses`). Because REA is adapter-only, those two are *allowed* for the
adapter but *callable* by no caller, so `callable_tools` is 0, by design. The other 205 are
blocked and cannot be reopened by overrides (`tests/test_rea_mocked.py`). Raw calls,
namespaced aliases and `nexus_call_provider_tool` are refused
(`test_aliases_and_adapter_only_tools_cannot_bypass_policy`). Before this change only
`callable_tool_count: 0` was reported, which hid the two adapter-allowed tools; listings now
also carry `policy_allowed_tool_count` and `adapter_only`.

## Security of the dashboard

| Control | Implementation | Test (`tests/test_dashboard.py`) |
|---|---|---|
| loopback only | `build_server` and the CLI refuse other hosts | `test_dashboard_refuses_non_loopback_binds` |
| GET/HEAD only | middleware answers 405 to every other method before routing | `test_dashboard_refuses_every_mutating_method` |
| DNS rebinding | `Host` must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` (421 otherwise) | `test_dashboard_rejects_foreign_hosts_and_origins` |
| cross-origin | a request with a foreign `Origin` is refused (403); API requests marked `Sec-Fetch-Site: cross-site` are refused; no CORS headers are sent | same |
| fixed surface | 5 routes (`/`, `/static/{name}` with a 3-file allowlist, `/api/state`, `/api/activity`, `/api/health`); nothing reaches a provider, a shell, the network or a chosen path | `test_dashboard_route_surface_is_fixed_and_read_only`, `test_dashboard_has_no_file_or_tool_access_routes` |
| browser hardening | CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, COOP/CORP; no inline script; no third-party assets | `test_dashboard_serves_real_state_with_security_headers`, `test_frontend_never_writes_html_from_data` |
| untrusted text | upstream descriptions and schemas are inserted as text nodes only (no `innerHTML`) | `test_frontend_never_writes_html_from_data` |
| redaction | snapshots never contain provider commands, arguments or environments; credential-shaped text and credential-named keys are redacted; the home directory becomes `~`; audit target hashes are shortened | `test_sanitize_redacts_secrets_and_shortens_home`, `test_snapshot_never_contains_provider_commands_or_environment`, `test_activity_is_sanitised_and_aggregated` |
| MCP unaffected | snapshot failures are counted, not raised; stdio still answers and the snapshot is marked stopped on shutdown | `test_snapshot_writer_failure_is_counted_not_raised`, `test_stdio_gateway_still_works_and_writes_a_snapshot`, `test_snapshot_file_io_runs_off_the_event_loop` |
| snapshot retention and atomicity | bounded, owner-scoped pruning; one stable file per gateway; touch-only heartbeats; readers never see partial files | `test_prune_is_bounded_owner_scoped_and_spares_active_files`, `test_snapshot_is_replaced_atomically_and_unchanged_heartbeats_only_touch`, `test_freshness_uses_heartbeat_mtime_and_marks_stale_and_stopped`, `test_concurrent_reader_never_sees_a_partial_snapshot`, `test_replace_retries_a_transient_sharing_violation` |
| history vs health | audit records labelled `this gateway` / `history`; legacy cancellation records annotated, never rewritten | `test_historical_failures_are_labelled_and_do_not_override_current_health` |
| test isolation | no test may open an audit log or evidence store under the permanent runtime; misplaced `data_dir` warns | `test_guard_refuses_permanent_runtime_paths`, `test_test_configs_never_resolve_to_the_permanent_runtime`, `test_misplaced_top_level_data_dir_is_reported` |

Limitations: there is no authentication, which is why the dashboard binds loopback only;
any local process of the same user can read it. Snapshot files hold the tool catalogue and
policy decisions (no secrets, no target data) and are readable by the same user. Workspace
roots and the config path are shown with the home directory shortened.

## Navigation and pages

Simple by default, comprehensive on demand: each page answers one question at a glance,
and every technical datum is one disclosure, drawer or filter away. Five sections, with a
second row of views only where a section has several:

| Section | Question | Views and routes |
|---|---|---|
| **Overview** | Is Nexus healthy? | `#/overview` |
| **Catalog** | What is available, and how does it work? | Providers `#/catalog/providers`, provider detail `#/catalog/providers/<id>`; Tools `#/catalog/tools`, tool detail `#/catalog/tools/<provider>/<tool>` |
| **Security** | What is allowed and what is blocked? | `#/security` |
| **Activity** | What has happened? | `#/activity` |
| **System** | How is everything connected, and what do the figures mean? | Architecture `#/system/architecture`, Definitions `#/system/definitions`, Diagnostics `#/system/diagnostics` |

Routes are hash routes, so links can be shared, and browser back and forward work.
The routes of the earlier seven-page layout redirect: `#/providers[/<id>]`,
`#/tools`, `#/tools/provider/<id>` (opens Tools filtered to that provider),
`#/architecture`, `#/definitions`. Filters, sort order, open disclosures and the
architecture toggle are kept in memory while the page is open (not in the URL). Escape
closes a drawer; tables, rows, disclosures and graph nodes are keyboard-operable.

* **Overview:** one status line: health, freshness, version, uptime (live only), the
  policy in a phrase, and providers ready of enabled. Four figures: ready providers,
  callable tools, blocked tools, warnings. When the snapshot is not live, the figures are
  labelled "last known". A single *Needs attention* list (severity, source, link; at most five
  items, the rest in Diagnostics) and the five latest audit events (labelled `history` when
  older than the running gateway). *Detailed metrics* (collapsed) lists all eight counts with
  their definitions.
* **Catalog › Providers:** a compact table (name and engine, health, enabled, documented
  verification, one count summary) with search and a status filter; verification and
  enabled filters under *Advanced filters*. The provider page has *Summary* (health and
  detail, freshness, enabled, verification, adapter-only), *Capabilities* (declared and usable
  operations, operation → upstream tools), *Tools* (discovered/allowed/callable/blocked/exposed
  and a searchable tool list), and collapsed *Technical details* (upstream pin, engine and
  transport, server-reported version, restarts, last health check, configuration diagnostics,
  how the adapter works, documented limitations, verification record and prerequisite, the
  class × decision breakdown) and *Detailed health result* (fields and the raw record).
* **Catalog › Tools:** tool, provider, access, operation and a one-line explanation per row;
  search, provider and access filters; operation, policy class and verification under
  *Advanced filters*. The drawer has six sections: *Summary*, *Access decision* (the
  gateway's decision and reason, allowed / callable / adapter-only / exposed), *How it works*
  (operations, upstream tool, public name with copy, request path), *Input schema* (required
  first, constraints, raw schema collapsed), *Security classification* (class and meaning,
  source, unrelaxable restriction, upstream annotations), *Verification* (provider record;
  per-tool coverage is not recorded and says so). Nothing can be invoked.
* **Security:** the five controls with their state and consequence in plain words, and
  which policy classes are callable, adapter-internal or blocked. Collapsed: hard blocks
  (unrelaxable classes, mutation patterns, global deny patterns), configured vs effective
  policy, provider-specific restrictions, the REA allowlist (tool → operation → Nexus tool),
  targets/staging/workspace, network and dashboard access (including the no-authentication
  caveat), every distinct policy-decision reason with counts, recorded policy denials.
* **Activity:** time, event, provider, outcome, duration and explanation per record; event
  and outcome filters, provider and era under *Advanced filters*; a note when legacy
  cancellation records exist. Selecting a record opens all its sanitised fields, its era and
  note. *Summary and evidence* (collapsed): audit-log facts, event counts, calls by provider,
  evidence-store counts, telemetry notes.
* **System › Architecture:** the request path with the gateway, policy, registry, stores,
  enabled providers and their upstreams; disabled providers fold into one node. *Show internal
  components* adds the workspace guard, module names, edge labels and each disabled provider.
  Every node opens its full explanation. No traffic is animated.
* **System › Definitions:** searchable, grouped (provider and tool counts, operations, policy
  and access, freshness, verification, findings including the Ghidra 41-versus-66 and REA
  explanations); each entry expands to its exact source.
* **System › Diagnostics:** searchable, severity-filtered findings in six groups (gateway,
  providers, snapshots, configuration, verification, dependencies and blockers), most severe
  first; groups that need attention open by default, empty groups say so. Gateway facts (pid,
  Python, platform, transport, tool mode, start, health check, heartbeat, config path) and the
  snapshot-file table are here. Every item is derived from the API; nothing is synthesised.

### Where the earlier pages went

| Earlier location | Now |
|---|---|
| Top bar: pid, transport, load time | System › Diagnostics › Gateway facts (header keeps freshness and age) |
| Overview cards: gateway, policy, provider health, seven metrics, activity, verification coverage, unavailable dependencies, warnings, gateway processes | Overview status line, four figures, *Needs attention*, *Recent activity*, *Detailed metrics* (all eight counts); verification and dependencies → Diagnostics; processes → Diagnostics › Snapshots |
| Providers cards and detail page | Catalog › Providers (table) and provider page (Summary, Capabilities, Tools, Technical details, Detailed health result) |
| Tool Explorer and drawer | Catalog › Tools and its six-section drawer |
| Architecture | System › Architecture (simplified default, internal toggle) |
| Security cards | Security summary and its collapsed technical sections |
| Activity cards and table | Activity table, record drawer, *Summary and evidence* |
| Definitions | System › Definitions (grouped, searchable) |

## Unavailable telemetry

* No live request stream: the audit log is read on refresh (auto-refresh every 15 s, pausable).
* Arguments, results and target content are never logged, so they cannot be shown.
* Per-target servers (MCPyGhidra) list their tools only once a target session exists, so
  their "discovered" count is 0 until then.
* Audit records are history, not health. Activity marks every record written before the
  running gateway started with a `history` tag (era filter: current / historical, and the
  record drawer states it); provider health comes only from the gateway snapshot. Audit lines written before 2026-10-16 recorded a provider
  start cut short by gateway shutdown (`claude mcp add/get/list` stop the server right after
  the handshake) as `failed` with `CancelledError`. Such starts are now recorded as
  `cancelled`. The old lines are shown exactly as written, with an explanatory note and a
  count on the Overview; they are never rewritten or reclassified.

## Configuration safeguard

`data_dir` and `allowed_roots` belong under `workspace:`; the 0.1 top-level spelling is still
accepted as a fallback. When both are present with different values the workspace value
wins, and `--check-config` (and the dashboard's warnings) now say so. A top-level `data_dir`
next to a `workspace.data_dir` used to be ignored silently. The test suite also refuses, in
every test, to open an audit log or evidence store under `%LOCALAPPDATA%\RevEngNexus`
(`tests/conftest.py`).

## Troubleshooting

* "No gateway snapshot found": no gateway has run since this version was installed, or
  `REVENG_NEXUS_DASHBOARD_SNAPSHOT=0` is set. Start a Claude Code session or `reveng-nexus serve`.
* Snapshot `stale`: the gateway was killed or hangs. Its last state stays visible.
* 421 from the browser: open exactly `http://127.0.0.1:<port>/`, not via a hostname alias.
* Port in use: `--port 8771`.
* Tests: `python -m pytest tests/test_dashboard.py -q`.
