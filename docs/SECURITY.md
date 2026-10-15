# Security model

RevEng Nexus is for software you own or are explicitly authorised to analyse: defensive
research, interoperability, debugging, and malware analysis in controlled environments.
It **does not provide a sandbox.** Engines run as ordinary child processes with your user's
privileges. Analyse unknown samples in a disposable VM with no access to your credentials.

## Enforced controls (with tests)

| Control | Where | Test |
|---|---|---|
| Read-only by default: tools classified `mutate` are blocked | `policy.py` | `test_security.py`, `test_mcp_providers.py` |
| Classification precedence: operator override → adapter manifest (pinned upstream) or the adapter's class for unlisted tools → trusted annotations → verb heuristic; deny patterns always win; **unknown tools blocked** | `policy.py` | `test_classification_precedence…`, `test_unknown_tools_are_blocked…` |
| `tool_overrides` can tighten any class but never relax `blocked`, `execute`, `dynamic` or `lifecycle`, whether the class comes from the pinned manifest, the adapter's class for unlisted tools, or the tool's name | `policy.py` | `test_tool_overrides_cannot_unblock_adapter_hard_blocks`, `test_tool_overrides_cannot_downgrade_execute_or_dynamic`, `test_override_cannot_relax_a_dynamic_manifest_class`, `test_override_cannot_relax_unlisted_execute_named_tool`, `test_override_cannot_relax_lifecycle` |
| Arguments the tool's input schema does not declare are refused (dynamic tools always; static tools on caller-initiated calls), so a decoy argument cannot satisfy a Nexus check; a dynamic tool whose schema does not enumerate its arguments is refused outright | `policy.py` | `test_decoy_target_argument_does_not_authorise`, `test_static_tool_with_undeclared_arguments_is_refused_for_callers`, `test_dynamic_tool_without_enumerated_schema_is_refused` |
| A `readOnlyHint` cannot whitelist an execution-, instrumentation- or mutation-shaped name, or a default-blocked pattern (`patch_bytes`, `open_database`) | `policy.py` | `test_read_only_hint_cannot_whitelist…` (execution and mutation variants) |
| Arbitrary code (`execute_python`, `pyghidra`, `run_script`) needs `allow_code_execution` **and** a provider allowlist; adapters can never use it internally | `policy.py` | `test_execute_needs_explicit_provider_opt_in` |
| Meta-tools that proxy to any tool (`call`, `batch`, `execute`) are hard-blocked | `adapters/re_mcp.py` | `test_upstream_manifests_close_the_0_1_name_filter_gaps` |
| Session lifecycle tools (open database/IDB/APK, select binary, stop instrumentation) are gateway-internal and **never** forwarded for a caller: they take filesystem paths the workspace guard never sees. `policy.allow_lifecycle_passthrough` was removed and is a config error | `policy.py`, `config.py` | `test_lifecycle_tools_internal_only`, `test_lifecycle_never_forwarded_for_callers`, `test_lifecycle_tools_never_reach_server_even_with_overrides`, `test_allow_lifecycle_passthrough_true_is_rejected`, `test_callers_cannot_invoke_stop_instrumentation` |
| Dynamic providers are not started unless `policy.dynamic_analysis.enabled` with non-empty authorised devices and targets; instrumentation tools need an explicit allowlist; device and target arguments are checked | `config.py`, `policy.py`, `registry.py` | `test_dynamic_tools_require…`, `test_disabled_and_dynamic_providers_are_not_started` |
| A dynamic call to a tool that declares a device argument must name an authorised device (no upstream fallback to an environment default, the first USB device or the host) | `policy.py` | `test_instrumentation_without_explicit_device_is_refused` |
| A dynamic call's target must be an authorised app-identifier string (a numeric `attach_process` target is a pid and is refused) | `policy.py` | `test_numeric_dynamic_target_is_refused` |
| An adapter that is inherently dynamic (Frida) forces `kind: dynamic`; a contradicting `kind` is a config error | `config.py`, `adapters/base.py` | `test_frida_adapter_is_gated_even_without_kind_dynamic`, `test_contradicting_kind_for_a_pinned_dynamic_adapter_is_a_config_error` |
| Protection-bypass, memory-write, custom-script and process-kill tools are never forwarded, whatever the policy; Frida tools missing from the pinned manifest are `blocked` (an override cannot reopen them); `mobile_action` (app install/launch through a second, unpinned `npx` server) is hard-blocked | `adapters/others.py` (Frida manifest) | `test_protection_bypass_is_hard_blocked…`, `test_unmanifested_upstream_tools_are_blocked_on_a_pinned_adapter`, `test_overrides_cannot_open_unlisted_tools_on_the_pinned_adapter` |
| A command that launches Frida Mobile MCP or REA is refused unless it uses that adapter (otherwise Frida would run as a static provider and REA with raw passthrough); the shared `re_mcp` adapter needs `engine: ghidra` or `ida`, inferred from the package and never contradicting it, because the label decides the engine family | `config.py` | `test_servers_with_adapter_gates_cannot_run_without_their_adapter`, `test_re_mcp_engine_label_is_restricted_and_inferred_from_the_package` |
| REA is adapter-only: two reviewed static tools allowed, every other current or future tool `blocked` (not reopenable), no raw passthrough or namespaced exposure, so REA only receives the hash-verified staged copy; REA's evidence must carry the target's SHA-256 (exact lowercase match); both operations are disabled when the live catalogue (tool count and name hash) or the server version differs from the reviewed pin | `adapters/rea.py`, `providers/base.py`, `server.py` | `test_rea_mocked.py` (`test_upstream_drift_disables_both_operations`, `test_overrides_cannot_reopen_unlisted_rea_tools`, `test_raw_passthrough_is_refused_before_the_server`, `test_rea_tools_are_not_exposed_as_namespaced_tools`, `test_bad_answers_are_bounded_errors_without_evidence`) |
| Every call is re-checked against the live catalogue and policy with its actual arguments | `providers/base.py` | `test_catalogue_enforcement…` |
| Workspace allowlist; absolute paths only; no `..`; prefix-sibling, symlink and junction refusal; NTFS ADS refusal; UNC and device paths refused before any filesystem access (no SMB connection or NTLM offer); regular files only; size cap | `artifacts.py` | `test_guard_*`, `test_unc_paths_are_refused_before_any_filesystem_access` |
| Targets are hashed at intake and re-verified before byte access; providers get a hash-verified, read-only **staged copy** and never the original | `artifacts.py`, `providers/builtin.py` | `test_stage_copy…`, `test_changed_file_after_intake…`, `test_staged_copy_is_used…` |
| No target is ever executed; discovery and tests use generated, never-run fixtures | design + tests | fixtures are generated from Python source |
| Child processes get a minimal environment (SDK safe set, explicit `inherit_env`, provider `env`); the 0.1 behaviour of passing all of `os.environ` is gone | `providers/mcp.py` | `test_child_environment_is_minimal` |
| Launched servers must announce a loopback host (literal `127.0.0.1`/`::1`/`localhost`, never resolved), a valid port, and the final URL built from `launch.url_template` must stay loopback | `providers/mcp.py`, `netguard.py` | `test_launched_server_non_loopback_readiness_is_refused`, `test_launched_url_template_cannot_redirect_to_remote_host`, `test_launched_ipv6_loopback_readiness_builds_bracketed_url`, `test_launched_readiness_with_invalid_port_is_refused` |
| `mcp_http` URLs must be loopback unless the provider's `allow_remote` **and** `policy.allow_remote_providers` are both set; malformed or credential-carrying URLs and ports outside 1-65535 are rejected; loopback HTTP clients ignore proxy environment variables (`trust_env=False`) and never follow redirects | `config.py`, `providers/mcp.py`, `netguard.py` | `test_remote_mcp_http_needs_two_explicit_opt_ins`, `test_remote_mcp_http_with_both_opt_ins_is_attempted`, `test_mcp_http_config_rejects_malformed_or_credentialed_url`, `test_parse_http_url_rejects_out_of_range_ports`, `test_loopback_http_client_ignores_proxy_environment`, `test_llm4decompile_loopback_client_ignores_proxy` |
| Engine identity: Binary Ninja's active view must be the exact staged copy (full normalised path, not a basename), JADX's `load_apk` must report this target's staged path; a raw call on a one-server-per-target provider is answered only by that target's own server | `adapters/others.py`, `providers/mcp.py`, `registry.py` | `test_binary_ninja_same_basename_elsewhere_is_refused`, `test_jadx_refuses_when_the_daemon_loaded_another_apk`, `test_raw_call_is_answered_by_its_own_targets_server`, `test_raw_call_never_falls_back_to_another_targets_session` |
| A provider that binds no usable Nexus operation reports `degraded` and fails `providers check` (also a one-server-per-target provider once a session has listed its tools) | `providers/mcp.py`, `cli.py` | `test_provider_without_bound_operations_is_degraded`, `test_providers_check_fails_for_provider_without_operations`, `test_per_target_provider_with_no_usable_operations_is_degraded` |
| Partial or malformed upstream answers are never a clean success: an error alongside items, upstream truncation, an incomplete IDA auto-analysis or an unrecognised page shape is returned with a warning; a decompile answer without a pseudocode field, malformed REA Evidence or a null metadata section is an error or an unknown value, never invented data | `adapters/base.py`, `adapters/re_mcp.py`, `adapters/mcpyghidra.py`, `adapters/others.py`, `adapters/rea.py` | `test_partial_error_with_items_is_not_a_clean_success`, `test_ida_rs_requests_auto_analysis_and_flags_an_incomplete_one`, `test_remcp_decompile_without_a_code_field_is_an_error`, `test_mcpyghidra_metadata_null_sections_are_unknown_not_a_crash`, `test_bad_answers_are_bounded_errors_without_evidence` |
| Process trees (uvx → launcher → JVM) are reaped through a Windows Job Object or POSIX process group | `providers/mcp.py` | `test_launched_server_process_tree_is_reaped` |
| Audit log is metadata only: argument **keys**, never values, code or bytes; errors are redacted and bounded | `audit.py` | `test_audit_log_is_metadata_only`, `test_catalogue_enforcement…` |
| Secret redaction (Bearer/Basic, key=value, URL userinfo, common key shapes) in errors and logs; API keys rejected in YAML (use `api_key_env`) | `redaction.py`, `config.py` | `test_redaction_audit.py`, `test_api_keys_are_rejected_in_yaml` |
| AI endpoints must be loopback unless `model.allow_remote` **and** `policy.allow_remote_ai` | `providers/llm4decompile.py` | `test_remote_endpoint_needs_two_explicit_opt_ins` |
| No model substitution: configured id must be served, look like LLM4Decompile (unless overridden), and match the response | `providers/llm4decompile.py` | `test_refuses_*`, `test_rejects_substituted_model…` |
| Nexus HTTP server binds loopback only; DNS-rebinding protection from the SDK | `server.py` | `test_streamable_http_transport_on_loopback`, `test_http_rejects_foreign_host_header`, `test_serve_http_refuses_non_loopback_bind` |
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
- **REA** parses attacker-controlled JavaScript and executable bytes in its own Node process
  with your privileges; it has no read-only mode or path containment upstream, which is why
  Nexus allows only two tools and no passthrough. Its prebuilt Windows addon is checked only
  against a manifest inside the same npm tarball. HOME/TEMP in the example config point into
  the Nexus data dir; that is a convention, not a sandbox.
- **Fixed after the 2026-10-15 security audit** (see the controls table): `mcp_http` loopback rule,
  launched-server URL/port checks and proxy isolation; lifecycle tools never forwarded (the
  `allow_lifecycle_passthrough` switch is gone); Binary Ninja full-path identity; per-target raw-call
  routing; `degraded` health for providers without operations; MCPyGhidra CFG/xref normalisation.
- **Fixed in the final review the same day:** UNC/device paths refused before filesystem access;
  URL port range; a trusted `readOnlyHint` no longer whitelists mutation-shaped names; REA
  disabled on catalogue/version drift; Frida `mobile_action` and unlisted tools hard-blocked and
  its status envelope checked exactly; adapter required for Frida/REA commands; `re_mcp` engine
  label restricted; re-mcp-ida response shapes, ida_rs auto-analysis/truncation, JADX loaded-APK
  identity and partial answers reported truthfully.
- **Remaining limits:** a launched server that binds `0.0.0.0` while announcing `127.0.0.1` cannot
  be detected from its readiness line. Binary Ninja's bridge reads the active view separately for
  each call, so a view switch inside the bridge between the before/after status checks cannot be
  fully excluded. A remote `mcp_http` provider (both opt-ins) still has no Nexus-side
  authentication; its traffic may use proxy settings. `ida_official` stays `degraded` even when
  `execute_python` is enabled by policy, because it binds no normalised operation.
  The workspace guard's messages distinguish "does not exist" from "outside allowed_roots", so a
  caller can probe for local files by name. `localhost` is trusted literally (the hosts file
  decides). With `max_concurrency` above 1 (default 1), two concurrent first uses of one target can
  start a second server; every traced case fails with an error rather than reaching another
  target. `expose_tools: false` only hides tools from listings; policy still decides calls.
  REA's version check uses the version the server reports; the byte-verified install is the
  real control.
- **Frida design limits:** tools whose subject is a session, pid or program cannot be tied to
  an authorised app and stay unusable. Upstream's `FRIDA_MCP_*` switches only react to `1`, so
  `0` values are not a protection; Nexus' hard blocks are. Without `--no-mobile-mcp` upstream
  launches an unpinned `npx -y @mobilenext/mobile-mcp@latest`. `npx -y frida-mobile-mcp@0.2.3`
  pins only the top-level package (no shrinkwrap), and upstream reads and writes
  `~/.config/frida-mobile-mcp/`; install it locally with its own HOME before any live use.

## Recommended deployment

1. A dedicated analysis VM or user; snapshot before opening unknown software.
2. Outbound network off for unknown binaries.
3. `workspace.allowed_roots` pointing at one samples folder; `data_dir` outside synced folders.
4. Pin provider versions (as in the example) and update one at a time, re-running
   `providers check`.
5. Keep `read_only`, `allow_code_execution: false` and dynamic analysis disabled until a
   specific authorised test needs otherwise, and record why.
6. Review reports for secrets before sharing them.
