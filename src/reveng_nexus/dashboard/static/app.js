/* RevEng Nexus console. Read-only: renders /api/state and /api/activity, never calls a tool.
   All text from the gateway (including untrusted upstream descriptions) is inserted as text nodes. */
"use strict";

const S = { state: null, activity: null, error: null, loadedAt: null, timer: null, sort: {}, filters: {} };

// ---------- DOM helpers ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const svgNS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...children) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, String(v));
  for (const c of children.flat()) if (c !== null && c !== undefined) el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const $ = (sel) => document.querySelector(sel);
const fmtNum = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString());
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function fmtAge(sec) {
  if (sec === null || sec === undefined) return "—";
  if (sec < 60) return `${Math.round(sec)} s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)} min ago`;
  if (sec < 86400) return `${(sec / 3600).toFixed(1)} h ago`;
  return `${(sec / 86400).toFixed(1)} d ago`;
}
function fmtDuration(sec) {
  if (!sec || sec < 0) return "—";
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m}m ${Math.floor(sec % 60)}s`;
}
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 1800);
}
function copyBtn(value, label = "Copy") {
  return h("button", { class: "btn small", type: "button", "aria-label": `Copy ${value}`, onclick: (e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value).then(() => toast("Copied"), () => toast("Copy failed"));
  } }, label);
}

// ---------- status vocabulary ----------
const STATUS_CLASS = { ready: "s-ok", live: "s-ok", ok: "s-ok", degraded: "s-warn", stale: "s-warn", cancelled: "s-warn",
  unavailable: "s-bad", failed: "s-bad", error: "s-bad", blocked: "s-bad", stopped: "s-off", disabled: "s-off", unknown: "s-off",
  historical: "s-violet", callable: "s-ok", "adapter-only": "s-info", exception: "s-bad", timeout: "s-bad", provider_error: "s-bad" };
function pill(text, cls, extra) { return h("span", { class: `pill ${cls || STATUS_CLASS[text] || "s-off"} ${extra || ""}`, text }); }
const VERIF_CLASS = { live_analysis_verified: "s-ok", connection_verified: "s-info", mock_tested: "s-violet", unit_tested: "s-violet",
  reviewed_not_tested: "s-off", blocked: "s-bad", not_integrated: "s-off", unrecorded: "s-off" };
function verifPill(v) {
  const state = (v && v.state) || "unrecorded";
  return h("span", { class: `pill ${VERIF_CLASS[state] || "s-off"}`, title: `${(v && v.meaning) || ""} — documented record (${(v && v.source) || "provider matrix"}), not a live measurement` }, state.replaceAll("_", " "));
}
function boolPill(value, goodWhen, onText, offText) {
  if (value === null || value === undefined) return pill("unknown", "s-off");
  const good = value === goodWhen;
  return pill(value ? onText : offText, good ? "s-ok" : "s-bad");
}
function freshnessPill(f) {
  return h("span", { class: `pill ${STATUS_CLASS[f] || "s-off"} ${f === "live" ? "s-live" : ""}`, title: (S.state?.freshness_legend || {})[f] || "" }, f);
}

// ---------- data ----------
async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}
async function load(soft = false) {
  try {
    const [state, activity] = await Promise.all([getJSON("/api/state"), getJSON("/api/activity")]);
    S.state = state; S.activity = activity; S.error = null; S.loadedAt = Date.now();
  } catch (e) {
    S.error = String(e.message || e);
  }
  renderTopbar();
  route(soft === true);
}
function primary() { return S.state && S.state.primary; }
function providersList() {
  const p = primary();
  const live = new Map(((p && p.providers) || []).map((x) => [x.id, x]));
  return ((S.state && S.state.configured.providers) || []).map((cfg) => ({ cfg, live: live.get(cfg.id) || null }));
}
function providerStatus(entry) {
  if (entry.live && entry.live.health && entry.live.health.status) return entry.live.health.status;
  if (!entry.cfg.enabled) return "disabled";
  if (entry.live && entry.live.skipped) return "disabled";
  if (entry.live && entry.live.error) return "unavailable";
  return primary() ? "unknown" : "unknown";
}
function allTools() {
  const out = [];
  const p = primary();
  if (!p) return out;
  for (const t of p.nexus_tools || []) {
    out.push({ kind: "nexus", provider: "nexus", name: t.name, public: t.name, description: t.description, schema: t.input_schema,
      status: "exposed", tool_class: t.read ? "readOnlyHint: true" : "readOnlyHint: false", reason: `Nexus tool, always listed to MCP clients and validated against its schema. The gateway advertises readOnlyHint=${t.read}. Any provider call it makes is decided by the policy individually, with its actual arguments.`,
      operations: t.operations, raw: t });
  }
  for (const prov of p.providers || []) {
    for (const t of prov.tools || []) {
      const status = t.callable ? "callable" : t.policy_allowed ? "adapter-only" : "blocked";
      out.push({ kind: "provider", provider: prov.id, name: t.name, public: t.public_name, description: t.description, schema: t.input_schema,
        status, tool_class: t.tool_class, class_meaning: t.class_meaning, source: t.classification_source, reason: t.policy_reason,
        operations: t.used_by_operations, exposed: t.exposed_to_clients, adapter_only: t.adapter_only, annotations: t.annotations,
        verification: prov.verification, raw: t });
    }
  }
  return out;
}

// ---------- shell ----------
function renderTopbar() {
  const bar = $("#topbar-status"); bar.replaceChildren();
  if (S.error) { bar.append(pill("dashboard API error", "s-bad"), h("span", { class: "muted", text: S.error })); return; }
  const p = primary();
  if (!p) { bar.append(pill("no gateway snapshot", "s-off"), h("span", { class: "muted", text: "Start a gateway (Claude Code session) to populate live state." })); return; }
  bar.append(freshnessPill(p.freshness), h("span", { class: "mono" }, `gateway ${p.gateway.version} · pid ${p.gateway.pid} · ${p.gateway.transport}`),
    h("span", { class: "faint", text: `snapshot ${fmtAge(p.age_seconds)} · loaded ${new Date(S.loadedAt).toLocaleTimeString()}` }));
}
function setNav(name) {
  document.querySelectorAll("[data-nav]").forEach((a) => { if (a.dataset.nav === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
}
function page(title, lede, ...body) {
  const main = $("#main");
  main.replaceChildren(h("div", { class: "page-head" }, h("div", null, h("h1", { text: title }), lede ? h("p", { class: "lede", text: lede }) : null)), ...body);
}
function empty(title, text) { return h("div", { class: "empty" }, h("strong", { text: title }), text); }
function card(title, ...body) { return h("section", { class: "card" }, title ? h("div", { class: "card-head" }, typeof title === "string" ? h("h2", { text: title }) : title) : null, ...body); }
function kv(pairs) { return h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", { text: k }), h("dd", null, v instanceof Node ? v : String(v ?? "—"))])); }

function route(soft = false) {
  const scrollY = window.scrollY;
  if (!soft) closeDrawer(false);
  const hash = location.hash.replace(/^#\/?/, "") || "overview";
  const [name, ...rest] = hash.split("/");
  setNav(name);
  if (S.error && !S.state) { page("Dashboard unavailable", null, h("div", { class: "error-box", text: S.error })); return; }
  if (!S.state) return;
  const views = { overview: viewOverview, providers: viewProviders, tools: viewTools, architecture: viewArchitecture, security: viewSecurity, activity: viewActivity, definitions: viewDefinitions };
  (views[name] || viewOverview)(rest.map(decodeURIComponent));
  if (soft) window.scrollTo(0, scrollY);
  else $("#main").focus({ preventScroll: true });
}

// ---------- tables ----------
function table(id, columns, rows, onRow) {
  const sort = S.sort[id] || {};
  let sorted = rows;
  if (sort.key) {
    const col = columns.find((c) => c.key === sort.key);
    const val = col && (col.sortValue || col.value);
    sorted = [...rows].sort((a, b) => {
      const x = val(a), y = val(b);
      const r = typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""));
      return sort.dir === "desc" ? -r : r;
    });
  }
  const thead = h("thead", null, h("tr", null, columns.map((c) => h("th", { scope: "col", "aria-sort": sort.key === c.key ? (sort.dir === "desc" ? "descending" : "ascending") : null, class: c.num ? "num" : null },
    c.sortable === false ? c.label : h("button", { type: "button", onclick: () => { S.sort[id] = { key: c.key, dir: sort.key === c.key && sort.dir !== "desc" ? "desc" : "asc" }; route(); } }, c.label)))));
  const tbody = h("tbody", null, sorted.map((r) => {
    const tr = h("tr", onRow ? { class: "clickable", tabindex: "0", onclick: () => onRow(r), onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onRow(r); } } } : null,
      columns.map((c) => { const v = (c.render || c.value)(r); return h("td", { class: [c.num ? "num" : "", c.cls || ""].join(" ").trim() || null }, v instanceof Node ? v : String(v ?? "—")); }));
    return tr;
  }));
  return h("div", { class: "table-wrap" }, h("table", null, thead, tbody));
}

// ---------- overview ----------
function metricCard(key, value, note) {
  const d = (S.state.definitions || {})[key] || { label: key, definition: "" };
  return h("div", { class: "card metric", tabindex: "0", title: `${d.definition}\nSource: ${d.source || ""}`, role: "group", "aria-label": `${d.label}: ${value}` },
    h("div", { class: "label", text: d.label }), h("div", { class: "value", text: fmtNum(value) }), h("div", { class: "note", text: note || d.source || "" }));
}
function viewOverview() {
  const st = S.state, p = primary(), act = S.activity || {};
  const body = [];
  if (!p) {
    body.push(h("div", { class: "callout warn" }, h("strong", null, "No gateway snapshot found. "),
      "Live state appears once a gateway runs (`reveng-nexus serve`, e.g. a Claude Code session). The configuration and documented verification below are shown meanwhile."));
  } else if (p.freshness !== "live") {
    body.push(h("div", { class: "callout warn" }, h("strong", null, `Gateway snapshot is ${p.freshness}. `),
      `Last written ${fmtAge(p.age_seconds)}. Values below are the last known state, not live.`));
  }
  for (const m of st.policy_mismatches || []) body.push(h("div", { class: "callout bad", text: m }));

  const g = p && p.gateway;
  const statusCard = card("Gateway",
    p ? kv([
      ["State", freshnessPill(p.freshness)],
      ["Version", g.version], ["Transport / tool mode", `${g.transport} / ${g.tool_mode}`],
      ["Process", `pid ${g.pid} · Python ${g.python}`],
      ["Uptime", p.freshness === "live" ? fmtDuration((Date.now() / 1000) - g.started_at) : "— (not live)"],
      ["Startup complete", g.startup_complete ? "yes" : "no — providers still starting"],
      ["Last health check", g.last_health_at ? `${fmtTime(g.last_health_at)}` : "none yet"],
      ["Config", h("span", { class: "mono", text: g.config_path || "—" })],
    ]) : empty("Unavailable", "No snapshot written yet."));

  const pol = p ? p.policy : st.configured;
  const policyCard = card(h("div", { class: "card-head" }, h("h2", { text: "Effective policy" }), h("a", { href: "#/security", text: "Security console →" })),
    kv([
      ["Read-only", boolPill(pol.read_only, true, "enforced", "OFF")],
      ["Code execution", boolPill(pol.code_execution, false, "enabled", "disabled")],
      ["Dynamic analysis", boolPill(pol.dynamic_analysis, false, "enabled", "disabled")],
      ["Remote AI", boolPill(pol.remote_ai, false, "allowed", "disabled")],
      ["Remote providers", boolPill(pol.remote_providers, false, "allowed", "loopback only")],
    ]),
    h("p", { class: "faint", text: p ? "Reported by the running gateway (effective)." : "From the configuration file (configured; no gateway snapshot)." }));

  const entries = providersList();
  const byStatus = {};
  entries.forEach((e) => { const k = providerStatus(e); byStatus[k] = (byStatus[k] || 0) + 1; });
  const colors = { ready: "var(--ok)", degraded: "var(--warn)", unavailable: "var(--bad)", disabled: "var(--off)", unknown: "var(--faint)" };
  const total = entries.length || 1;
  const healthCard = card(h("div", { class: "card-head" }, h("h2", { text: "Provider health" }), h("a", { href: "#/providers", text: "All providers →" })),
    h("div", { class: "bar", role: "img", "aria-label": Object.entries(byStatus).map(([k, v]) => `${v} ${k}`).join(", ") },
      Object.entries(byStatus).map(([k, v]) => h("span", { style: null, "data-w": v / total, "data-c": colors[k] || "var(--faint)" }))),
    h("div", { class: "legend" }, Object.entries(byStatus).map(([k, v]) => h("span", null, h("i", { "data-c": colors[k] || "var(--faint)" }), `${v} ${k}`))),
    h("div", { class: "section" }, entries.filter((e) => e.cfg.enabled).map((e) => h("div", { class: "card-head", style: null },
      h("a", { href: `#/providers/${encodeURIComponent(e.cfg.id)}`, text: e.cfg.id }), h("span", { class: "chips" }, pill(providerStatus(e)), verifPill(e.cfg.verification))))));

  const t = (p && p.totals) || {};
  const metrics = h("div", { class: "grid metrics" },
    metricCard("upstream_tools_discovered", p ? t.upstream_tools_discovered : null),
    metricCard("policy_allowed_tools", p ? t.policy_allowed_tools : null),
    metricCard("callable_tools", p ? t.callable_tools : null),
    metricCard("exposed_tools", p ? t.exposed_tools : null, p ? `tool_mode ${p.gateway.tool_mode}` : null),
    metricCard("blocked_tools", p ? t.blocked_tools : null),
    metricCard("operations_usable", p ? t.operations_usable : null),
    metricCard("nexus_tools", p ? (p.nexus_tools || []).length : null));

  const warnings = [];
  for (const w of (g && g.config_warnings) || st.configured.warnings || []) warnings.push(h("li", { text: w }));
  if (g && g.audit_write_failures) warnings.push(h("li", { text: `${g.audit_write_failures} audit write failure(s)` }));
  if (g && g.snapshot_write_failures) warnings.push(h("li", { text: `${g.snapshot_write_failures} snapshot write failure(s)` }));
  if (st.unreadable_snapshots) warnings.push(h("li", { text: `${st.unreadable_snapshots} snapshot file(s) could not be read and were ignored` }));
  const ev = (act.event_counts || []);
  const startRows = (act.recent || []).filter((r) => r.event === "provider_started");
  const tally = (rows) => Object.entries(rows.reduce((m, r) => ((m[r.outcome] = (m[r.outcome] || 0) + 1), m), {})).map(([k, v]) => `${v} ${k}`).join(", ") || "none";
  const denials = ev.filter((e) => e.event === "tool_call_blocked").reduce((a, e) => a + e.count, 0);
  const actCard = card(h("div", { class: "card-head" }, h("h2", { text: "Recorded activity" }), h("a", { href: "#/activity", text: "Activity →" })),
    act.audit && act.audit.available ? kv([
      ["Audit records read", fmtNum(act.audit.records_read) + (act.audit.tail_only ? " (tail)" : "")],
      ["Last audit write", fmtTime(act.audit.last_modified)],
      ["Provider starts — this gateway", act.current_gateway_since ? tally(startRows.filter((r) => r.era === "current")) : "no live gateway"],
      ["Provider starts — earlier (history)", tally(startRows.filter((r) => r.era !== "current"))],
      ["Policy denials", fmtNum(denials)],
      ["Tool calls / operations", fmtNum(ev.filter((e) => ["tool_call", "operation"].includes(e.event)).reduce((a, e) => a + e.count, 0))],
      ["Evidence records", act.evidence && act.evidence.available ? fmtNum(act.evidence.counts.evidence) : "unavailable"],
    ]) : empty("No audit log", "Nothing has been recorded yet."),
    act.audit && act.audit.available ? h("p", { class: "faint", text: "Audit records are history, not health: an old failure does not mean a provider is failing now. Current state is on the Provider health card." + (act.legacy_cancel_records ? ` ${act.legacy_cancel_records} older 'failed' start(s) were shutdown cancellations logged before the 2026-10-16 fix (see Activity).` : "") }) : null);

  const verifCounts = {};
  entries.forEach((e) => { const k = (e.cfg.verification || {}).state || "unrecorded"; verifCounts[k] = (verifCounts[k] || 0) + 1; });
  const verifCard = card("Verification coverage (documented)",
    h("div", { class: "chips" }, Object.entries(verifCounts).map(([k, v]) => h("span", { class: `pill ${VERIF_CLASS[k] || "s-off"}` }, `${v} × ${k.replaceAll("_", " ")}`))),
    h("p", { class: "faint", text: "From docs/PROVIDER_MATRIX.md — a historical record, never inferred from health." }),
    h("h3", { text: "Known unavailable dependencies" }),
    h("ul", null, entries.filter((e) => e.cfg.verification && e.cfg.verification.blocker).map((e) => h("li", null, h("b", { text: e.cfg.id }), ": ", e.cfg.verification.blocker))));

  const inst = (st.instances || []);
  const instCard = card(`Gateway processes (${inst.length})`, inst.length ? table("instances", [
    { key: "pid", label: "PID", value: (r) => r.pid, num: true },
    { key: "freshness", label: "State", value: (r) => r.freshness, render: (r) => freshnessPill(r.freshness) },
    { key: "transport", label: "Transport", value: (r) => r.transport },
    { key: "started_at", label: "Started", value: (r) => r.started_at || 0, render: (r) => fmtTime(r.started_at) },
    { key: "age", label: "Last snapshot", value: (r) => r.age_seconds, render: (r) => fmtAge(r.age_seconds) },
  ], inst) : empty("None", "No snapshot files."), h("p", { class: "faint", text: "Each Claude Code session runs its own gateway; stopped ones keep their last snapshot." }));

  page("Overview", "State of the RevEng Nexus gateway, as reported by the gateway itself. Hover a figure for its exact definition.",
    ...body, h("div", { class: "grid cols-3" }, statusCard, policyCard, healthCard),
    h("div", { class: "section" }, h("h3", { text: "Tool and operation counts — distinct definitions" }), metrics),
    h("div", { class: "grid cols-3 section" }, actCard, verifCard, warnings.length ? card("Warnings", h("ul", null, warnings)) : card("Warnings", h("p", { class: "muted", text: "No configuration warnings, audit or snapshot write failures reported." }))),
    h("div", { class: "section" }, instCard));
  paintBars();
}
function paintBars() {
  document.querySelectorAll("[data-w]").forEach((el) => { el.style.width = `${(Number(el.dataset.w) * 100).toFixed(2)}%`; el.style.background = el.dataset.c; });
  document.querySelectorAll("i[data-c]").forEach((el) => { el.style.background = el.dataset.c; });
}

// ---------- providers ----------
function viewProviders(args) {
  if (args[0]) return viewProvider(args[0]);
  const f = S.filters.providers || (S.filters.providers = { q: "", status: "", verif: "", enabled: "" });
  const entries = providersList();
  const rows = entries.filter((e) => {
    const st = providerStatus(e), v = (e.cfg.verification || {}).state;
    const hay = `${e.cfg.id} ${e.cfg.name} ${e.cfg.engine} ${e.cfg.adapter}`.toLowerCase();
    return (!f.q || hay.includes(f.q.toLowerCase())) && (!f.status || st === f.status) && (!f.verif || v === f.verif) && (!f.enabled || String(e.cfg.enabled) === f.enabled);
  });
  const sel = (key, label, options) => h("select", { "aria-label": label, onchange: (ev) => { f[key] = ev.target.value; route(); } },
    h("option", { value: "", text: `${label}: all` }), options.map((o) => h("option", { value: o, selected: f[key] === o ? true : null, text: o })));
  const statuses = [...new Set(entries.map(providerStatus))];
  const verifs = [...new Set(entries.map((e) => (e.cfg.verification || {}).state).filter(Boolean))];
  const search = h("input", { type: "search", placeholder: "Search providers…", value: f.q, "aria-label": "Search providers",
    oninput: (ev) => { f.q = ev.target.value; clearTimeout(viewProviders._t); viewProviders._t = setTimeout(() => { route(); const i = $("input[type=search]"); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 180); } });
  const cards = rows.map((e) => {
    const c = (e.live && e.live.counts) || null;
    const open = () => (location.hash = `#/providers/${encodeURIComponent(e.cfg.id)}`);
    return h("article", { class: "card provider-card", tabindex: "0", role: "link", "aria-label": `Provider ${e.cfg.id}`, onclick: open, onkeydown: (ev) => { if (ev.key === "Enter") open(); } },
      h("div", { class: "pc-head" }, h("div", null, h("div", { class: "pc-title", text: e.cfg.id }), h("div", { class: "pc-sub", text: `${e.cfg.engine || e.cfg.type} · ${e.cfg.adapter || e.cfg.type} · ${e.cfg.transport || "in-process"}` })), pill(providerStatus(e))),
      c ? h("div", { class: "stat-row" },
        h("div", null, h("b", { text: fmtNum(c.upstream_tools_discovered) }), h("small", { text: "discovered" })),
        h("div", null, h("b", { text: fmtNum(c.policy_allowed_tools) }), h("small", { text: "allowed" })),
        h("div", null, h("b", { text: fmtNum(c.callable_tools) }), h("small", { text: "callable" })),
        h("div", null, h("b", { text: `${c.operations_usable}/${c.operations_declared}` }), h("small", { text: "ops usable" })))
        : h("div", { class: "faint", text: e.cfg.enabled ? "No live data for this provider." : "Disabled in the configuration." }),
      h("div", { class: "chips" }, verifPill(e.cfg.verification), e.live && e.live.adapter_only ? pill("adapter-only", "s-info") : null));
  });
  page("Providers", "Every configured provider. Health is live from the gateway; verification is the documented record. Neither implies the other.",
    h("div", { class: "filters" }, search, sel("status", "Status", statuses), sel("verif", "Verification", verifs), sel("enabled", "Enabled", ["true", "false"]),
      h("span", { class: "count-note", text: `${rows.length} of ${entries.length}` })),
    rows.length ? h("div", { class: "grid cols-3" }, cards) : empty("No provider matches", "Clear the filters."));
}
function opsTable(ops) {
  const rows = Object.entries(ops || {}).filter(([k]) => !k.startsWith("_"));
  if (!rows.length) return empty("No operations", "This provider exposes no Nexus operations, or it is not running.");
  return table("ops", [
    { key: "op", label: "Operation", value: (r) => r[0], render: (r) => h("code", { text: r[0] }) },
    { key: "avail", label: "Usable", value: (r) => (r[1].available ? 1 : 0), render: (r) => pill(r[1].available ? "ready" : "unavailable") },
    { key: "tools", label: "Upstream tools", value: (r) => (r[1].tools || []).join(","), render: (r) => h("span", { class: "chips" }, (r[1].tools || []).map((t) => h("span", { class: "chip", text: t }))) },
    { key: "note", label: "Note / reason", value: (r) => r[1].reason || r[1].note || "", render: (r) => r[1].reason || r[1].note || (r[1].formats ? `formats: ${r[1].formats.join(", ")}` : "") },
  ], rows);
}
function classBreakdown(tools) {
  const m = {};
  tools.forEach((t) => { const k = `${t.tool_class}|${t.policy_allowed ? (t.callable ? "callable" : "adapter-only") : "blocked"}`; m[k] = (m[k] || 0) + 1; });
  return Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, v]) => { const [c, st] = k.split("|"); return { tool_class: c, status: st, count: v }; });
}
function viewProvider(id) {
  const entry = providersList().find((e) => e.cfg.id === id);
  if (!entry) { page("Provider not found", null, empty("Unknown provider", id)); return; }
  const { cfg, live } = entry;
  const c = live && live.counts;
  const up = (live && live.upstream) || {};
  const health = (live && live.health) || {};
  const status = providerStatus(entry);
  const how = [];
  if (cfg.type === "builtin") how.push("In-process parsers (pyelftools, pefile, own Mach-O/APK parsers) and Capstone. No external process; no code discovery.");
  else how.push(`Runs the pinned upstream as a separate process and talks MCP over ${cfg.transport || "stdio"}. The adapter maps each Nexus operation to specific upstream tools and normalises the answer; raw output is kept as evidence.`);
  if (live && live.adapter_only) how.push("Adapter-only: callers can reach this provider only through its nexus_* operations. Every raw tool is refused for callers, even the two the adapter itself uses.");
  if (cfg.kind === "dynamic") how.push("Dynamic provider: instruments live processes or devices. Disabled unless policy.dynamic_analysis is enabled with explicit device and target allowlists.");
  const tools = (live && live.tools) || [];
  page(cfg.id, cfg.name,
    h("p", null, h("a", { href: "#/providers", text: "← All providers" })),
    h("div", { class: "grid cols-3" },
      card("Identity & health", kv([
        ["Health", pill(status)], ["Detail", health.detail || (live && (live.skipped || live.error)) || (cfg.enabled ? "no health data yet" : "disabled in config")],
        ["Last health check", primary() && primary().gateway.last_health_at ? fmtTime(primary().gateway.last_health_at) : "—"],
        ["Engine / family", `${cfg.engine || "—"} / ${(live && live.engine_family) || "—"}`],
        ["Server-reported version", health.version || (live && live.server_info && live.server_info.version) || "—"],
        ["Type / transport", `${cfg.type} / ${cfg.transport || "in-process"}`], ["Kind", cfg.kind],
        ["Restarts", live && live.restarts !== undefined ? live.restarts : "—"],
      ])),
      card("Upstream pin", up.upstream ? kv([
        ["Repository", h("span", { class: "mono", text: up.upstream })], ["Revision", h("span", { class: "mono", text: up.pinned_revision })],
        ["Package", `${up.package || "—"}${up.package_version ? " " + up.package_version : ""}`],
        ["Pin verified", `${up.verification} on ${up.verified_on}`],
      ]) : empty("No pin", cfg.type === "builtin" ? "Built into Nexus." : "No adapter data (provider not running).")),
      card("Verification (documented)", kv([
        ["State", verifPill(cfg.verification)], ["Scope", (cfg.verification || {}).scope || "—"],
        ["Last recorded", (cfg.verification || {}).last_recorded || "—"], ["Blocker", (cfg.verification || {}).blocker || "none"],
        ["Source", (cfg.verification || {}).source || "—"],
      ]), h("p", { class: "faint", text: "Health shows whether it runs now; this shows what was verified, and when." }))),
    h("div", { class: "section" }, h("h3", { text: "Counts — each a different concept" }),
      c ? h("div", { class: "grid metrics" }, metricCard("upstream_tools_discovered", c.upstream_tools_discovered), metricCard("policy_allowed_tools", c.policy_allowed_tools),
        metricCard("callable_tools", c.callable_tools), metricCard("exposed_tools", c.exposed_tools), metricCard("blocked_tools", c.blocked_tools),
        metricCard("operations_usable", c.operations_usable, `of ${c.operations_declared} declared`))
        : empty("No live counts", cfg.enabled ? "The provider is not running in the gateway that wrote the snapshot." : "Disabled in the configuration.")),
    h("div", { class: "grid cols-2 section" },
      card("How this adapter works", h("ul", null, how.map((t) => h("li", { text: t }))),
        (up.limitations || []).length ? [h("h3", { text: "Documented limitations" }), h("ul", null, up.limitations.map((l) => h("li", { text: l })))] : null),
      card("Why tools are restricted", tools.length ? table("classes", [
        { key: "tool_class", label: "Class", value: (r) => r.tool_class, render: (r) => h("code", { text: r.tool_class }) },
        { key: "status", label: "Decision", value: (r) => r.status, render: (r) => pill(r.status) },
        { key: "count", label: "Tools", value: (r) => r.count, num: true },
        { key: "meaning", label: "Meaning", value: (r) => (S.state.tool_classes || {})[r.tool_class] || "", sortable: false },
      ], classBreakdown(tools)) : empty("No catalogue", "No tools listed by this provider."),
        tools.length ? h("p", null, h("a", { href: `#/tools/provider/${encodeURIComponent(cfg.id)}`, text: `Open its ${tools.length} tools in the Tool Explorer →` })) : null)),
    h("div", { class: "section" }, card("Operation mappings", opsTable(live && live.operations))));
}

// ---------- tools ----------
function statusPill(t) {
  if (t.kind === "nexus") return pill("exposed", "s-info");
  return pill(t.status);
}
function viewTools(args) {
  const f = S.filters.tools || (S.filters.tools = { q: "", provider: "", op: "", status: "", cls: "", verif: "" });
  if (args[0] === "provider" && args[1]) { f.provider = args[1]; history.replaceState(null, "", "#/tools"); }
  const tools = allTools();
  if (!primary()) { page("Tools", null, empty("No gateway snapshot", "The tool catalogue comes from a running gateway's live tools/list.")); return; }
  const rows = tools.filter((t) => {
    const hay = `${t.name} ${t.public} ${t.description}`.toLowerCase();
    return (!f.q || hay.includes(f.q.toLowerCase())) && (!f.provider || t.provider === f.provider) && (!f.op || (t.operations || []).includes(f.op)) &&
      (!f.status || t.status === f.status) && (!f.cls || t.tool_class === f.cls) && (!f.verif || ((t.verification || {}).state === f.verif));
  });
  const uniq = (fn) => [...new Set(tools.flatMap(fn))].filter(Boolean).sort();
  const sel = (key, label, options) => h("select", { "aria-label": label, onchange: (ev) => { f[key] = ev.target.value; route(); } },
    h("option", { value: "", text: `${label}: all` }), options.map((o) => h("option", { value: o, selected: f[key] === o ? true : null, text: o })));
  const search = h("input", { type: "search", placeholder: "Search name or description…", value: f.q, "aria-label": "Search tools",
    oninput: (ev) => { f.q = ev.target.value; clearTimeout(viewTools._t); viewTools._t = setTimeout(() => { route(); const i = $("input[type=search]"); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 180); } });
  const shown = rows.slice(0, 600);
  page("Tool Explorer", "Every nexus_* tool and every upstream tool the gateway discovered, with the gateway's own policy decision. Nothing here can be invoked.",
    h("div", { class: "filters" }, search, sel("provider", "Provider", uniq((t) => [t.provider])), sel("op", "Operation", uniq((t) => t.operations || [])),
      sel("status", "Status", ["callable", "adapter-only", "blocked", "exposed"]), sel("cls", "Policy class", uniq((t) => [t.tool_class])),
      sel("verif", "Verification", uniq((t) => [(t.verification || {}).state])),
      h("button", { class: "btn small", type: "button", onclick: () => { S.filters.tools = null; route(); } }, "Clear"),
      h("span", { class: "count-note", text: `${rows.length} of ${tools.length}${rows.length > shown.length ? ` (first ${shown.length} shown)` : ""}` })),
    h("div", { class: "callout" }, "Policy class comes from the gateway's classification (adapter manifest, trusted annotations, or verb heuristic, in that order, with deny patterns first) — never from this page. ",
      h("a", { href: "#/definitions", text: "Definitions" })),
    h("div", { class: "card flush" }, rows.length ? table("tools", [
      { key: "name", label: "Tool", value: (r) => r.name, render: (r) => h("code", { text: r.name }) },
      { key: "provider", label: "Provider", value: (r) => r.provider },
      { key: "status", label: "Status", value: (r) => r.status, render: statusPill },
      { key: "cls", label: "Class", value: (r) => r.tool_class, render: (r) => h("code", { text: r.tool_class }) },
      { key: "ops", label: "Operations", value: (r) => (r.operations || []).join(","), render: (r) => h("span", { class: "chips" }, (r.operations || []).slice(0, 3).map((o) => h("span", { class: "chip", text: o }))) },
      { key: "desc", label: "Description", value: (r) => r.description, cls: "truncate", sortable: false },
    ], shown, openTool) : empty("No tool matches", "Clear the filters.")));
}
function schemaView(schema) {
  if (!schema || typeof schema !== "object") return empty("No schema", "The tool declares no input schema.");
  const props = schema.properties || {};
  const req = new Set(schema.required || []);
  const names = Object.keys(props);
  const describe = (p) => {
    if (!p || typeof p !== "object") return "";
    const parts = [];
    if (p.enum) parts.push(`one of: ${p.enum.join(", ")}`);
    if (p.default !== undefined) parts.push(`default ${JSON.stringify(p.default)}`);
    if (p.minimum !== undefined || p.maximum !== undefined) parts.push(`range ${p.minimum ?? "…"}–${p.maximum ?? "…"}`);
    if (p.pattern) parts.push(`pattern ${p.pattern}`);
    return parts.join(" · ");
  };
  const typeOf = (p) => (p && (p.type ? [].concat(p.type).join(" | ") : p.anyOf ? "anyOf" : p.oneOf ? "oneOf" : p.$ref ? "ref" : "any")) || "any";
  return h("div", null,
    names.length ? h("div", { class: "schema" }, names.map((n) => h("div", { class: "schema-row" },
      h("div", null, h("code", { text: n }), req.has(n) ? h("span", { class: "req", text: "required" }) : h("span", { class: "faint", text: " optional" })),
      h("div", null, h("span", { class: "type", text: typeOf(props[n]) }), " ", h("span", { class: "muted", text: (props[n] && props[n].description) || "" }),
        describe(props[n]) ? h("div", { class: "faint", text: describe(props[n]) }) : null))))
      : h("p", { class: "muted", text: "No parameters." }),
    schema.anyOf || schema.oneOf ? h("p", { class: "faint", text: "The schema also has alternative requirement sets (anyOf/oneOf); see the raw schema." }) : null,
    h("details", { class: "raw" }, h("summary", { text: "Raw JSON schema" }), h("pre", { text: JSON.stringify(schema, null, 2) })));
}
function flowFor(t) {
  const steps = [];
  const step = (text, cls) => h("span", { class: `step ${cls || ""}`, text });
  const arrow = () => h("span", { class: "arrow", text: "→" });
  if (t.kind === "nexus") {
    const ops = (t.operations || []).filter((o) => o !== "local");
    steps.push(step("MCP client"), arrow(), step(t.name), arrow(), step("schema validation", "gate"), arrow());
    if (!ops.length) steps.push(step("Nexus gateway / evidence store"));
    else steps.push(step("registry: route " + ops.join(", ")), arrow(), step("policy re-check per upstream call", "gate"), arrow(), step("provider adapter"), arrow(), step("upstream"));
  } else if (t.status === "callable") {
    steps.push(step("MCP client"), arrow(), step(t.exposed ? t.public : "nexus_call_provider_tool"), arrow(), step("catalogue lookup", "gate"), arrow(),
      step("policy decide(arguments)", "gate"), arrow(), step(t.provider), arrow(), step(`upstream ${t.name}`));
  } else if (t.status === "adapter-only") {
    steps.push(step("MCP client"), arrow(), step("nexus_call_provider_tool"), arrow(), step("refused: adapter-only", "stop"));
    steps.push(h("br"));
    steps.push(step("nexus_* operation"), arrow(), step(`${t.provider} adapter (internal)`), arrow(), step("policy decide", "gate"), arrow(), step(`upstream ${t.name}`));
  } else {
    steps.push(step("MCP client"), arrow(), step("nexus_call_provider_tool"), arrow(), step("catalogue lookup", "gate"), arrow(), step(`refused: ${t.tool_class}`, "stop"));
  }
  return h("div", { class: "flow" }, steps);
}
function openTool(t) {
  const body = [
    h("div", { class: "chips" }, statusPill(t), h("span", { class: "chip", text: `class: ${t.tool_class}` }), t.source ? h("span", { class: "chip", text: `source: ${t.source}` }) : null,
      t.verification ? verifPill(t.verification) : null),
    h("h3", { text: "Policy decision" }),
    h("div", { class: `callout ${t.status === "blocked" ? "bad" : t.status === "callable" ? "ok" : ""}` }, t.reason || "—"),
    t.class_meaning ? h("p", { class: "muted", text: `"${t.tool_class}": ${t.class_meaning}` }) : null,
    h("h3", { text: "Request path" }), flowFor(t),
    h("h3", { text: "Identity" }),
    kv([
      ["Tool name", h("span", null, h("code", { text: t.name }), " ", copyBtn(t.name))],
      ["Public name", t.kind === "provider" ? h("span", null, h("code", { text: t.public }), " ", copyBtn(t.public)) : "—"],
      ["Provider", t.provider], ["Registered (in catalogue)", "yes"],
      ["Exposed to MCP clients", t.kind === "nexus" ? "yes (nexus_* tool)" : t.exposed ? "yes (namespaced mode)" : "no"],
      ["Callable directly", t.kind === "nexus" ? "yes (schema-validated)" : t.status === "callable" ? "yes — re-checked per call with its arguments" : "no"],
      ["Used by operations", (t.operations || []).join(", ") || "none"],
      t.annotations && Object.keys(t.annotations).length ? ["Upstream annotations", h("span", { class: "mono", text: JSON.stringify(t.annotations) })] : null,
    ]),
    h("h3", { text: "Description" }), h("p", { class: "desc", text: t.description || "—" }),
    t.kind === "provider" ? h("p", { class: "faint", text: "Upstream text is untrusted data, shown verbatim; it does not influence the decision above." }) : null,
    h("h3", { text: "Input schema" }), schemaView(t.schema),
  ];
  openDrawer(t.name, body);
}

// ---------- drawer ----------
let lastFocus = null;
function openDrawer(title, content) {
  lastFocus = document.activeElement;
  $("#drawer-title").textContent = title;
  $("#drawer-body").replaceChildren(...[].concat(content));
  $("#drawer").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false");
  $("#drawer-backdrop").hidden = false;
  $("#drawer-close").focus();
}
function closeDrawer(restore = true) {
  if (!$("#drawer").classList.contains("open")) return;
  $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").hidden = true;
  if (restore && lastFocus) lastFocus.focus();
}

// ---------- architecture ----------
function viewArchitecture() {
  const arch = S.state.architecture || { nodes: [], edges: [] };
  // Stores sit under the gateway core, so every provider edge visibly starts at the registry.
  const cols = { client: 0, core: 1, store: 1, provider: 2, upstream: 3 };
  const colX = [40, 320, 660, 980];
  const colW = 210, nodeH = 46, gap = 14;
  const byCol = [[], [], [], []];
  arch.nodes.forEach((n) => byCol[cols[n.group] ?? 1].push(n));
  const pos = {};
  const height = Math.max(...byCol.map((c) => c.length)) * (nodeH + gap) + 80;
  byCol.forEach((nodes, ci) => {
    const total = nodes.length * (nodeH + gap) - gap;
    const top = Math.max(50, (height - total) / 2);
    nodes.forEach((n, i) => (pos[n.id] = { x: colX[ci], y: top + i * (nodeH + gap) }));
  });
  const W = 1220;
  const svg = s("svg", { class: "arch", viewBox: `0 0 ${W} ${height}`, role: "group", "aria-label": "System architecture" });
  ["Client", "Gateway core and stores", "Provider adapters", "Upstream engines"].forEach((l, i) => svg.appendChild(s("text", { class: "col-label", x: colX[i], y: 26 }, l)));
  const edgeEls = [];
  arch.edges.forEach((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const x1 = a.x + colW, y1 = a.y + nodeH / 2, x2 = b.x, y2 = b.y + nodeH / 2;
    const back = x2 <= x1;
    const d = back ? `M${a.x + colW / 2},${a.y + nodeH} C${a.x + colW / 2},${y2} ${b.x + colW / 2},${a.y + nodeH} ${b.x + colW / 2},${b.y}`
      : `M${x1},${y1} C${x1 + 50},${y1} ${x2 - 50},${y2} ${x2},${y2}`;
    const cls = e.active === undefined ? "edge on" : e.active ? "edge on" : "edge off";
    const path = s("path", { class: cls, d, "data-from": e.from, "data-to": e.to });
    edgeEls.push(path); svg.appendChild(path);
  });
  const statusColor = { ready: "var(--ok)", live: "var(--ok)", degraded: "var(--warn)", unavailable: "var(--bad)", disabled: "var(--off)", unknown: "var(--faint)" };
  arch.nodes.forEach((n) => {
    const p = pos[n.id];
    if (!p) return;
    const dim = n.enabled === false;
    const g = s("g", { class: `node ${dim ? "dim" : ""}`, transform: `translate(${p.x},${p.y})`, tabindex: "0", role: "button", "aria-label": `${n.label}: ${n.status || n.group}. Open details` });
    g.appendChild(s("rect", { width: colW, height: nodeH, rx: 8 }));
    g.appendChild(s("text", { class: "t", x: 12, y: 19 }, String(n.label).slice(0, 26)));
    g.appendChild(s("text", { class: "s", x: 12, y: 35 }, String(n.subtitle || "").slice(0, 30)));
    if (n.status) g.appendChild(s("circle", { class: "dot", cx: colW - 14, cy: 14, r: 5, fill: statusColor[n.status] || "var(--faint)" }));
    const hl = (on) => {
      g.classList.toggle("hl", on);
      edgeEls.forEach((el) => { if (el.dataset.from === n.id || el.dataset.to === n.id) el.classList.toggle("hl", on); });
    };
    g.addEventListener("mouseenter", () => hl(true)); g.addEventListener("mouseleave", () => hl(false));
    g.addEventListener("focus", () => hl(true)); g.addEventListener("blur", () => hl(false));
    const open = () => openNode(n);
    g.addEventListener("click", open);
    g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } });
    g.appendChild(s("title", {}, `${n.label} — ${n.responsibility || ""}`));
    svg.appendChild(g);
  });
  page("Architecture", "The real request path. Select a node (click, or Tab + Enter) for its responsibility, health, verification and restrictions. Edges are solid for ready providers and dashed otherwise; nothing here is animated as traffic, because no live request stream exists.",
    h("div", { class: "card flush arch-wrap" }, svg),
    h("div", { class: "legend" }, h("span", null, h("i", { "data-c": "var(--ok)" }), "ready"), h("span", null, h("i", { "data-c": "var(--warn)" }), "degraded"),
      h("span", null, h("i", { "data-c": "var(--bad)" }), "unavailable"), h("span", null, h("i", { "data-c": "var(--off)" }), "disabled (dimmed)")));
  paintBars();
}
function openNode(n) {
  const body = [
    h("div", { class: "chips" }, n.status ? pill(n.status) : null, h("span", { class: "chip", text: n.group }), n.verification ? verifPill(n.verification) : null),
    h("h3", { text: "Responsibility" }), h("p", { text: n.responsibility || "—" }),
    kv([
      ["Inputs", n.inputs], ["Outputs", n.outputs],
      ["Depends on", (n.dependencies || []).filter(Boolean).join(", ") || "—"],
      n.pin ? ["Pinned revision", h("span", { class: "mono", text: n.pin })] : null,
      n.usable_operations ? ["Usable operations", n.usable_operations.join(", ") || "none"] : null,
    ]),
    n.restrictions ? [h("h3", { text: "Restrictions" }), h("ul", null, n.restrictions.map((r) => h("li", { text: r })))] : null,
    n.counts && Object.keys(n.counts).length ? [h("h3", { text: "Counts" }), kv(Object.entries(n.counts).map(([k, v]) => [(S.state.definitions[k] || {}).label || k, fmtNum(v)]))] : null,
    n.id.startsWith("provider:") ? h("p", null, h("a", { href: `#/providers/${encodeURIComponent(n.id.slice(9))}`, text: "Open provider details →" })) : null,
  ];
  openDrawer(n.label, body);
}

// ---------- security ----------
function viewSecurity() {
  const p = primary(), cfg = S.state.configured;
  const eff = p ? p.policy : null;
  const row = (label, key, goodWhen, on, off) => [label, boolPill(cfg[key], goodWhen, on, off), eff ? boolPill(eff[key], goodWhen, on, off) : pill("unavailable", "s-off")];
  const policyRows = [
    row("Read-only", "read_only", true, "enforced", "OFF"),
    row("Code execution", "code_execution", false, "enabled", "disabled"),
    row("Dynamic analysis", "dynamic_analysis", false, "enabled", "disabled"),
    row("Remote AI", "remote_ai", false, "allowed", "disabled"),
    row("Remote MCP providers", "remote_providers", false, "allowed", "loopback only"),
  ];
  const provs = (p && p.providers) || [];
  const rea = provs.find((x) => x.id === "rea");
  const reaAllowed = rea ? (rea.tools || []).filter((t) => t.policy_allowed) : [];
  const opToNexus = {};
  ((p && p.nexus_tools) || []).forEach((t) => (t.operations || []).forEach((o) => (opToNexus[o] = (opToNexus[o] || []).concat(t.name))));
  const restrictions = provs.filter((x) => x.started).map((x) => ({ id: x.id, adapter_only: x.adapter_only, ...x.counts,
    classes: classBreakdown(x.tools || []).filter((r) => r.status === "blocked").map((r) => `${r.count} ${r.tool_class}`).join(", ") }));
  const act = S.activity || {};
  page("Security & policy", "Configured values come from the config file; effective values are what the running gateway reports. Every tool decision is made by the gateway; this page only displays it and offers no control to change it.",
    (S.state.policy_mismatches || []).map((m) => h("div", { class: "callout bad", text: m })),
    h("div", { class: "grid cols-2" },
      card("Policy: configured vs effective", h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", { text: "Control" }), h("th", { text: "Configured" }), h("th", { text: "Effective (gateway)" }))),
        h("tbody", null, policyRows.map((r) => h("tr", null, h("td", { text: r[0] }), h("td", null, r[1]), h("td", null, r[2]))))))),
      card("Hard blocks", eff ? [
        h("p", { class: "muted", text: "An operator tool_override may tighten any class but never relax these classes:" }),
        h("div", { class: "chips" }, (eff.unrelaxable_classes || []).map((c) => h("span", { class: "chip", text: c }))),
        h("h3", { text: "Mutation-shaped names (blocked under read-only even with a read-only hint)" }),
        h("div", { class: "chips" }, (eff.default_blocked_tool_patterns || []).map((c) => h("span", { class: "chip", text: c }))),
        h("h3", { text: "Global deny patterns (config)" }),
        (eff.global_blocked_tool_patterns || []).length ? h("div", { class: "chips" }, eff.global_blocked_tool_patterns.map((c) => h("span", { class: "chip", text: c }))) : h("p", { class: "faint", text: "none configured" }),
      ] : empty("Unavailable", "Needs a gateway snapshot."))),
    h("div", { class: "grid cols-2 section" },
      card("REA: explicit two-operation allowlist", rea ? [
        kv([["Upstream tools discovered", fmtNum(rea.counts.upstream_tools_discovered)], ["Allowed for the adapter", fmtNum(rea.counts.policy_allowed_tools)],
          ["Callable by callers", fmtNum(rea.counts.callable_tools)], ["Adapter-only", rea.adapter_only ? "yes" : "NO"], ["Operations usable", `${rea.counts.operations_usable}/${rea.counts.operations_declared}`]]),
        h("h3", { text: "Allowed upstream tools → operation → Nexus tool" }),
        reaAllowed.length ? h("ul", null, reaAllowed.map((t) => h("li", null, h("code", { text: t.name }), " → ", (t.used_by_operations || []).join(", ") || "no operation",
          " → ", (t.used_by_operations || []).flatMap((o) => opToNexus[o] || []).join(", ") || "—"))) : h("p", { class: "faint", text: "none allowed" }),
        h("p", { class: "faint", text: "Every other REA tool is blocked and cannot be reopened by overrides; raw passthrough is refused; the process's last argument is fixed to 'mcp' by config validation." }),
      ] : empty("REA not running", "No REA data in the current snapshot (disabled or not started).")),
      card("Targets and network", h("ul", null,
        h("li", { text: "Targets are admitted only from workspace.allowed_roots; '..', UNC, device, ADS paths and links outside the roots are refused before use." }),
        h("li", { text: "Each target is hashed (SHA-256) at intake and re-verified before byte access; providers receive a hash-verified, read-only staged copy, never the original." }),
        h("li", { text: `HTTP providers are loopback-only unless both provider allow_remote and policy.allow_remote_providers are set (now: ${eff ? eff.remote_providers : cfg.remote_providers}).` }),
        h("li", { text: "This dashboard binds loopback only, checks Host/Origin, serves GET only and sends no CORS headers." }),
        h("li", { text: "It has no authentication: loopback binding keeps it off the network, but any process running under your user account can read it." })),
        p ? kv([["Workspace roots", (p.workspace.allowed_roots || []).join(", ") || "none (intake disabled)"], ["Max artifact size", `${fmtNum(Math.round(p.workspace.max_artifact_bytes / 1048576))} MB`], ["Follow symlinks", String(p.workspace.follow_symlinks)]]) : null)),
    h("div", { class: "section" }, card("Provider restrictions", restrictions.length ? table("restr", [
      { key: "id", label: "Provider", value: (r) => r.id, render: (r) => h("a", { href: `#/providers/${encodeURIComponent(r.id)}`, text: r.id }) },
      { key: "adapter_only", label: "Adapter-only", value: (r) => (r.adapter_only ? 1 : 0), render: (r) => (r.adapter_only ? pill("yes", "s-info") : "no") },
      { key: "d", label: "Discovered", value: (r) => r.upstream_tools_discovered, num: true },
      { key: "a", label: "Allowed", value: (r) => r.policy_allowed_tools, num: true },
      { key: "c", label: "Callable", value: (r) => r.callable_tools, num: true },
      { key: "b", label: "Blocked", value: (r) => r.blocked_tools, num: true },
      { key: "classes", label: "Blocked by class", value: (r) => r.classes, sortable: false },
    ], restrictions) : empty("No running providers", "Needs a gateway snapshot."))),
    h("div", { class: "section" }, card(`Recorded policy denials (${(act.policy_denials || []).length})`, (act.policy_denials || []).length ? table("denials", [
      { key: "t", label: "Time", value: (r) => r.timestamp, render: (r) => fmtTime(r.timestamp) },
      { key: "p", label: "Provider", value: (r) => r.provider_id },
      { key: "tool", label: "Tool", value: (r) => r.tool_name, render: (r) => h("code", { text: r.tool_name || "—" }) },
      { key: "c", label: "Class", value: (r) => r.tool_class },
      { key: "r", label: "Reason", value: (r) => r.policy_reason, sortable: false },
    ], act.policy_denials) : empty("No denials recorded", "The audit log contains no tool_call_blocked events."))));
}

// ---------- activity ----------
function viewActivity() {
  const a = S.activity || {};
  const f = S.filters.activity || (S.filters.activity = { event: "", outcome: "", provider: "" });
  if (!a.audit || !a.audit.available) {
    page("Activity", null, empty("No telemetry yet", (a.audit && a.audit.reason) || "The audit log does not exist yet. It is written by the gateway as operations run."));
    return;
  }
  const recent = (a.recent || []).filter((r) => (!f.event || r.event === f.event) && (!f.outcome || r.outcome === f.outcome) && (!f.provider || r.provider_id === f.provider));
  const uniq = (k) => [...new Set((a.recent || []).map((r) => r[k]).filter(Boolean))].sort();
  const sel = (key, label) => h("select", { "aria-label": label, onchange: (ev) => { f[key] = ev.target.value; route(); } },
    h("option", { value: "", text: `${label}: all` }), uniq(key === "provider" ? "provider_id" : key).map((o) => h("option", { value: o, selected: f[key] === o ? true : null, text: o })));
  const ev = a.evidence || {};
  page("Activity & diagnostics", "Read from the metadata-only audit log and the evidence database (read-only). Arguments, results and target content are never logged, so they cannot be shown.",
    h("div", { class: "callout" }, (a.telemetry_notes || []).join(" ")),
    a.legacy_cancel_records ? h("div", { class: "callout warn" }, h("strong", null, `${a.legacy_cancel_records} historical 'failed' provider start(s) `),
      "carry CancelledError: they were recorded before the 2026-10-16 fix, when a start cut short by the gateway's own shutdown (e.g. `claude mcp list`) was logged as failed. Their outcome is shown as recorded; it says nothing about current health.") : null,
    h("div", { class: "grid cols-3" },
      card("Audit log", kv([["Records read", fmtNum(a.audit.records_read) + (a.audit.tail_only ? " (last 2 MB)" : "")], ["Size", `${fmtNum(Math.round(a.audit.bytes / 1024))} KB`], ["Last write", fmtTime(a.audit.last_modified)]])),
      card("Event counts", (a.event_counts || []).length ? table("evc", [
        { key: "e", label: "Event", value: (r) => r.event, render: (r) => h("code", { text: r.event }) },
        { key: "o", label: "Outcome", value: (r) => r.outcome || "", render: (r) => (r.outcome ? pill(r.outcome) : "—") },
        { key: "c", label: "Count", value: (r) => r.count, num: true },
      ], a.event_counts) : empty("Empty", "")),
      card("Evidence store (read-only)", ev.available ? [kv(Object.entries(ev.counts || {}).map(([k, v]) => [k, fmtNum(v)])),
        (ev.evidence_by_provider_tool || []).length ? [h("h3", { text: "Evidence by provider / tool" }), table("evp", [
          { key: "p", label: "Provider", value: (r) => r.provider_id }, { key: "t", label: "Tool", value: (r) => r.tool_name, render: (r) => h("code", { text: r.tool_name }) },
          { key: "c", label: "Records", value: (r) => r.count, num: true }], ev.evidence_by_provider_tool)] : h("p", { class: "faint", text: "No evidence recorded yet." })]
        : empty("Unavailable", ev.reason || ""))),
    h("div", { class: "section" }, card("Recent events",
      h("div", { class: "filters" }, sel("event", "Event"), sel("outcome", "Outcome"), sel("provider", "Provider"), h("span", { class: "count-note", text: `${recent.length} shown` })),
      recent.length ? table("recent", [
        { key: "t", label: "Time", value: (r) => r.timestamp, render: (r) => fmtTime(r.timestamp) },
        { key: "era", label: "Era", value: (r) => r.era, render: (r) => pill(r.era === "current" ? "this gateway" : "history", r.era === "current" ? "s-info" : "s-violet") },
        { key: "e", label: "Event", value: (r) => r.event, render: (r) => h("code", { text: r.event }) },
        { key: "p", label: "Provider", value: (r) => r.provider_id || "" },
        { key: "x", label: "Tool / operation", value: (r) => r.tool_name || r.operation || "", render: (r) => h("code", { text: r.tool_name || r.operation || "—" }) },
        { key: "o", label: "Outcome", value: (r) => r.outcome || "", render: (r) => (r.outcome ? pill(r.outcome) : "—") },
        { key: "d", label: "ms", value: (r) => r.duration_ms ?? -1, render: (r) => (r.duration_ms ?? "—"), num: true },
        { key: "info", label: "Detail", value: (r) => [r.error || r.policy_reason || r.detail || "", r.note ? `Note: ${r.note}` : ""].filter(Boolean).join(" — "), cls: "truncate", sortable: false },
      ], recent.slice(0, 300)) : empty("No events match", "Clear the filters."))));
}

// ---------- definitions ----------
function viewDefinitions() {
  const st = S.state;
  page("Definitions", "Exact meanings of every figure and label on this console.",
    card("Metrics", table("defs", [
      { key: "l", label: "Metric", value: (r) => r[1].label },
      { key: "d", label: "Definition", value: (r) => r[1].definition, sortable: false },
      { key: "s", label: "Source", value: (r) => r[1].source, sortable: false },
    ], Object.entries(st.definitions || {}))),
    h("div", { class: "grid cols-2 section" },
      card("Data freshness", kv(Object.entries(st.freshness_legend || {}).map(([k, v]) => [k, v]))),
      card("Policy classes", kv(Object.entries(st.tool_classes || {}).map(([k, v]) => [k, v])))),
    h("div", { class: "section" }, card("Verification states (provider matrix)", kv(Object.entries(st.verification_states || {}).map(([k, v]) => [k.replaceAll("_", " "), v])))),
    h("div", { class: "section" }, card("Why historical counts may differ", h("p", null,
      "Older notes recorded \"41 callable\" for re-mcp-ghidra. That number was the length of the `providers check` output list, which was shortened to 40 names plus a \"...\" marker. Replaying the same 134-tool catalogue through the 2026-10-13 policy code gives 66 allowed, the same as today. `providers check` now prints explicit counts. See docs/DASHBOARD.md."))));
}

// ---------- boot ----------
function boot() {
  window.addEventListener("hashchange", route);
  $("#refresh-btn").addEventListener("click", () => load(false));
  $("#drawer-close").addEventListener("click", () => closeDrawer());
  $("#drawer-backdrop").addEventListener("click", () => closeDrawer());
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  const menu = $("#menu-btn");
  menu.addEventListener("click", () => { const open = !$(".sidebar").classList.contains("open"); $(".sidebar").classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); });
  document.querySelectorAll(".sidebar nav a").forEach((a) => a.addEventListener("click", () => $(".sidebar").classList.remove("open")));
  const auto = $("#auto-refresh");
  const schedule = () => { clearInterval(S.timer); if (auto.checked) S.timer = setInterval(() => { if (!document.hidden && !$("#drawer").classList.contains("open") && !document.activeElement.matches("input, select")) load(true); }, 15000); };
  auto.addEventListener("change", schedule);
  schedule();
  load();
}
document.addEventListener("DOMContentLoaded", boot);
