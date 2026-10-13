# Security model

RevEng Nexus is for software you own or are explicitly authorised to analyse: defensive
research, interoperability, debugging, and malware analysis in controlled environments.
It **does not provide a sandbox.** Engines run as ordinary child processes with your user's
privileges. Analyse unknown samples in a disposable VM with no access to your credentials.

## Enforced controls (with tests)

| Control | Where | Test |
|---|---|---|
| Read-only by default: tools classified `mutate` are blocked | `policy.py` | `test_security.py`, `test_mcp_providers.py` |
| Classification precedence: operator override → adapter manifest (pinned upstream) → trusted annotations → verb heuristic; deny patterns always win; **unknown tools blocked** | `policy.py` | `test_classification_precedence…`, `test_unknown_tools_are_blocked…` |
| A `readOnlyHint` cannot whitelist an execution- or instrumentation-shaped name | `policy.py` | `test_read_only_hint_cannot_whitelist…` |
| Arbitrary code (`execute_python`, `pyghidra`, `run_script`) needs `allow_code_execution` **and** a provider allowlist; adapters can never use it internally | `policy.py` | `test_execute_needs_explicit_provider_opt_in` |
| Meta-tools that proxy to any tool (`call`, `batch`, `execute`) are hard-blocked | `adapters/re_mcp.py` | `test_upstream_manifests_close_the_0_1_name_filter_gaps` |
| Session lifecycle tools are gateway-internal | `policy.py` | `test_lifecycle_tools_internal_only` |
| Dynamic providers are not started unless `policy.dynamic_analysis.enabled` with non-empty authorised devices and targets; instrumentation tools need an explicit allowlist; device and target arguments are checked | `config.py`, `policy.py`, `registry.py` | `test_dynamic_tools_require…`, `test_disabled_and_dynamic_providers_are_not_started` |
| Protection-bypass, memory-write, custom-script and process-kill tools are never forwarded, whatever the policy | `adapters/others.py` (Frida manifest) | `test_protection_bypass_is_hard_blocked…` |
| Every call is re-checked against the live catalogue and policy with its actual arguments | `providers/base.py` | `test_catalogue_enforcement…` |
| Workspace allowlist; absolute paths only; no `..`; prefix-sibling, symlink and junction refusal; NTFS ADS refusal; regular files only; size cap | `artifacts.py` | `test_guard_*` |
| Targets are hashed at intake and re-verified before byte access; providers get a hash-verified, read-only **staged copy** and never the original | `artifacts.py`, `providers/builtin.py` | `test_stage_copy…`, `test_changed_file_after_intake…`, `test_staged_copy_is_used…` |
| No target is ever executed; discovery and tests use generated, never-run fixtures | design + tests | fixtures are generated from Python source |
| Child processes get a minimal environment (SDK safe set, explicit `inherit_env`, provider `env`); the 0.1 behaviour of passing all of `os.environ` is gone | `providers/mcp.py` | `test_child_environment_is_minimal` |
| Launched servers bind loopback only; non-loopback readiness is refused | `providers/mcp.py` | adapter tests |
| Process trees (uvx → launcher → JVM) are reaped through a Windows Job Object or POSIX process group | `providers/mcp.py` | `test_launched_server_process_tree_is_reaped` |
| Audit log is metadata only: argument **keys**, never values, code or bytes; errors are redacted and bounded | `audit.py` | `test_audit_log_is_metadata_only`, `test_catalogue_enforcement…` |
| Secret redaction (Bearer/Basic, key=value, URL userinfo, common key shapes) in errors and logs; API keys rejected in YAML (use `api_key_env`) | `redaction.py`, `config.py` | `test_redaction_audit.py`, `test_api_keys_are_rejected_in_yaml` |
| AI endpoints must be loopback unless `model.allow_remote` **and** `policy.allow_remote_ai` | `providers/llm4decompile.py` | `test_remote_endpoint_needs_two_explicit_opt_ins` |
| No model substitution: configured id must be served, look like LLM4Decompile (unless overridden), and match the response | `providers/llm4decompile.py` | `test_refuses_*`, `test_rejects_substituted_model…` |
| Nexus HTTP server binds loopback only; DNS-rebinding protection from the SDK | `server.py` | `test_streamable_http_transport_on_loopback` |
| Target-derived text is labelled untrusted in every result; report code fences cannot be broken out of | `server.py`, `report.py` | `test_code_fences_from_targets_cannot_break_out` |
| Findings: non-hypothesis findings need evidence; "confirmed" cannot rest on AI evidence alone | `evidence.py` | `test_findings_need_evidence…` |

## Prompt-injection posture

Strings, symbol names, decompiled code and model output can contain text written to look
like instructions. Nexus never interprets such text: it is stored and returned as data, and
every result carries an `untrusted_content_notice`. The server instructions tell the agent
the same. Nexus has no tool that executes shell commands, and model output is never turned
into a command.

## Residual risks and limitations

- **No isolation.** A malicious sample that exploits a parser in Ghidra, IDA, Binary Ninja,
  JADX or pyelftools/pefile runs with your privileges. Use a VM.
- **Annotations are hints.** Where Nexus trusts upstream annotations (re-mcp, MCPyGhidra,
  ida-mcp, ida-mcp-rs), a buggy or malicious upstream could mislabel a tool. Pin versions
  (the example config does), review `providers check --verbose`, and use `tool_overrides`.
- **Engine databases are written** (Ghidra projects, `.i64`) next to staged copies inside
  `data/work/`. That is intentional and never touches your sample folder; delete
  `data/work/` to discard them.
- **Same-user access.** The evidence DB, audit log and the loopback HTTP endpoint are
  readable by other processes running as your user. The HTTP mode has no authentication.
- **Local data sensitivity.** The evidence DB stores decompiled output and raw provider
  responses (within `analysis.raw_output_limit_kb`). Treat `data/` like the samples.
- **Windows Job Object assignment** happens right after process creation; a grandchild
  spawned in that instant could escape it (the SDK has the same race). `taskkill /T` is the
  fallback.

## Recommended deployment

1. A dedicated analysis VM or user; snapshot before opening unknown software.
2. Outbound network off for unknown binaries.
3. `workspace.allowed_roots` pointing at one samples folder; `data_dir` outside synced folders.
4. Pin provider versions (as in the example) and update one at a time, re-running
   `providers check`.
5. Keep `read_only`, `allow_code_execution: false` and dynamic analysis disabled until a
   specific authorised test needs otherwise, and record why.
6. Review reports for secrets before sharing them.
