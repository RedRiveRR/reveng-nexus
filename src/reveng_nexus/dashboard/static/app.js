/* RevEng Nexus console. Read-only: renders /api/state and /api/activity, never calls a tool.
   Simple by default, comprehensive on demand. All text from the gateway (including untrusted
   upstream descriptions and schemas) is inserted as text nodes, never as HTML. */
"use strict";

const S = { state: null, activity: null, error: null, loadedAt: null, timer: null, sort: {}, filters: {}, disclosures: {}, archInternal: false };

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
  return new Date(ts * 1000).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
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
const fmtMs = (ms) => (ms === null || ms === undefined ? "—" : ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`);
const firstSentence = (t) => (String(t || "").split(/(?<=[.;])\s/)[0] || "").slice(0, 160).replace(/;$/, ".");
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 1600);
}
function copyBtn(value) {
  return h("button", { class: "btn small", type: "button", "aria-label": `Copy ${value}`, onclick: (e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value).then(() => toast("Copied"), () => toast("Copy failed"));
  } }, "Copy");
}

// ---------- status vocabulary ----------
const TONE = { ready: "ok", live: "ok", ok: "ok", callable: "ok", enforced: "ok", degraded: "warn", stale: "warn", cancelled: "warn",
  unavailable: "bad", failed: "bad", error: "bad", blocked: "bad", exception: "bad", timeout: "bad", provider_error: "bad",
  stopped: "off", disabled: "off", unknown: "off", "adapter-only": "info", exposed: "info", historical: "violet" };
function mark(text, tone) { return h("span", { class: `mark ${tone || TONE[text] || "off"}`, text }); }
const VERIF_TONE = { live_analysis_verified: "ok", connection_verified: "info", mock_tested: "violet", unit_tested: "violet",
  reviewed_not_tested: "off", blocked: "bad", not_integrated: "off", unrecorded: "off" };
const verifLabel = (v) => ((v && v.state) || "unrecorded").replaceAll("_", " ");
function verifMark(v) {
  const el = mark(verifLabel(v), VERIF_TONE[(v && v.state) || "unrecorded"] || "off");
  el.title = `${(v && v.meaning) || ""} (documented record, not a live measurement)`;
  return el;
}
function tag(text, code) { return h("span", { class: `tag ${code ? "code" : ""}`, text }); }

// ---------- generic components ----------
function page(title, subtitle, ...body) {
  $("#main").replaceChildren(h("div", { class: "page-head" }, h("div", null, title instanceof Node ? title : h("h1", { text: title }), subtitle ? h("p", { class: "subtitle", text: subtitle }) : null)), ...body);
}
function panel(title, ...body) {
  return h("section", { class: "panel" }, title ? (typeof title === "string" ? h("div", { class: "panel-head" }, h("h2", { text: title })) : title) : null, ...body);
}
function panelHead(title, link) { return h("div", { class: "panel-head" }, h("h2", { text: title }), link || null); }
function empty(title, text) { return h("div", { class: "empty" }, h("strong", { text: title }), text || ""); }
function notice(text, tone) { return h("div", { class: `notice ${tone || ""}` }, text); }
function kv(pairs) { return h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", { text: k }), h("dd", null, v instanceof Node ? v : String(v ?? "—"))])); }
/** Native <details> disclosure; the body is built only when first opened. */
function more(title, hint, build, open = false) {
  // The user's choice to open or close a disclosure survives re-renders (auto-refresh, filters).
  const key = `${location.hash.split("/").slice(0, 3).join("/")}|${title.replace(/\s*\(\d+\)$/, "")}`;
  const isOpen = key in S.disclosures ? S.disclosures[key] : open;
  const body = h("div", { class: "more-body" });
  const d = h("details", { class: "more", open: isOpen || null }, h("summary", null, h("span", { text: title }), hint ? h("span", { class: "hint", text: hint }) : null), body);
  let built = false;
  const fill = () => { if (!built && d.open) { built = true; body.replaceChildren(...[].concat(build()).flat(Infinity).filter(Boolean)); } };
  d.addEventListener("toggle", () => { S.disclosures[key] = d.open; fill(); });
  fill();
  return d;
}
function select(label, value, options, onChange) {
  return h("select", { "aria-label": label, onchange: (ev) => onChange(ev.target.value) },
    h("option", { value: "", text: `${label}: all` }), options.map((o) => h("option", { value: o, selected: value === o ? true : null, text: o })));
}
function searchBox(placeholder, value, onInput) {
  return h("input", { type: "search", placeholder, value, "aria-label": placeholder,
    oninput: (ev) => { onInput(ev.target.value); clearTimeout(searchBox._t); searchBox._t = setTimeout(() => { route(true); const i = $("main input[type=search]"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, 180); } });
}
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
  const thead = h("thead", null, h("tr", null, columns.map((c) => h("th", { scope: "col", class: c.num ? "num" : null, "aria-sort": sort.key === c.key ? (sort.dir === "desc" ? "descending" : "ascending") : null },
    c.sortable === false ? c.label : h("button", { type: "button", onclick: () => { S.sort[id] = { key: c.key, dir: sort.key === c.key && sort.dir !== "desc" ? "desc" : "asc" }; route(true); } }, c.label)))));
  const tbody = h("tbody", null, sorted.map((r) => h("tr", onRow ? { class: "clickable", tabindex: "0", onclick: () => onRow(r), onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onRow(r); } } } : null,
    columns.map((c) => { const v = (c.render || c.value)(r); return h("td", { class: [c.num ? "num" : "", c.cls || ""].join(" ").trim() || null }, v instanceof Node ? v : String(v ?? "—")); }))));
  return h("div", { class: "table-wrap" }, h("table", null, thead, tbody));
}
function filterBar(common, advanced, note) {
  return h("div", { class: "filters" }, common, note ? h("span", { class: "count-note", text: note }) : null,
    advanced && advanced.length ? h("details", { class: "advanced", open: advanced.some((a) => a.value) ? true : null }, h("summary", { text: "Advanced filters" }), h("div", { class: "filters-inner" }, advanced)) : null);
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
  renderHeader();
  route(soft === true);
}
const primary = () => S.state && S.state.primary;
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
  return "unknown";
}
function toolStatus(t) { return t.callable ? "callable" : t.policy_allowed ? "adapter-only" : "blocked"; }
function allTools() {
  const p = primary();
  if (!p) return [];
  const out = [];
  for (const t of p.nexus_tools || []) {
    out.push({ kind: "nexus", provider: "nexus", name: t.name, public: t.name, description: t.description, schema: t.input_schema,
      status: "exposed", tool_class: t.read ? "readOnlyHint: true" : "readOnlyHint: false", operations: t.operations, readHint: t.read,
      reason: `Nexus tool, always listed to MCP clients and validated against its schema. The gateway advertises readOnlyHint=${t.read}. Any provider call it makes is decided by the policy individually, with its actual arguments.` });
  }
  for (const prov of p.providers || []) {
    for (const t of prov.tools || []) {
      out.push({ kind: "provider", provider: prov.id, name: t.name, public: t.public_name, description: t.description, schema: t.input_schema,
        status: toolStatus(t), tool_class: t.tool_class, class_meaning: t.class_meaning, source: t.classification_source, reason: t.policy_reason,
        operations: t.used_by_operations || [], exposed: t.exposed_to_clients, adapter_only: t.adapter_only, annotations: t.annotations,
        verification: prov.verification, policy_allowed: t.policy_allowed, callable: t.callable });
    }
  }
  return out;
}
function totals() {
  const p = primary();
  if (!p) return null;
  const sum = (k) => (p.providers || []).reduce((a, x) => a + ((x.counts || {})[k] || 0), 0);
  return { ...p.totals, operations_declared: sum("operations_declared"), nexus_tools: (p.nexus_tools || []).length };
}
function explainTool(t) {
  if (t.kind === "nexus") return firstSentence(t.description);
  if (t.status === "callable") return t.exposed ? "Callable; also listed to MCP clients as its own tool" : "Callable through nexus_call_provider_tool (checked per call)";
  if (t.status === "adapter-only") return `Used only inside ${(t.operations || []).join(", ") || "its adapter"}; refused for direct calls`;
  return firstSentence(t.reason);
}

// ---------- diagnostics (derived only from data the backend supplied) ----------
const DIAG_GROUPS = ["Gateway", "Providers", "Snapshots", "Configuration", "Verification", "Dependencies and blockers"];
const SEV_ORDER = { bad: 0, warn: 1, info: 2, ok: 3 };
function diagnostics() {
  const st = S.state, p = primary(), act = S.activity || {}, items = [];
  const add = (group, sev, title, detail, link) => items.push({ group, sev, title, detail: detail || "", link });
  if (!st) return items;
  if (!p) add("Gateway", "warn", "No gateway snapshot", "No running gateway has written state yet; health and the tool catalogue are unavailable. Start a Claude Code session or reveng-nexus serve.");
  else {
    const g = p.gateway;
    if (p.freshness === "live") add("Gateway", "ok", "Gateway is live", `Last heartbeat ${fmtAge(p.age_seconds)}.`);
    else if (p.freshness === "stale") add("Gateway", "warn", "Gateway snapshot is stale", `No heartbeat for ${fmtAge(p.age_seconds).replace(" ago", "")}; the gateway was killed or hangs. Values are its last known state.`);
    else add("Gateway", "info", "Gateway has stopped", `Shut down cleanly ${fmtAge(p.age_seconds)}; values are its last known state.`);
    if (!g.startup_complete) add("Gateway", "info", "Providers are still starting", "Tool calls wait until startup finishes.");
    if (g.audit_write_failures) add("Gateway", "bad", `${g.audit_write_failures} audit write failure(s)`, "The gateway could not append to its audit log.");
    if (g.snapshot_write_failures) add("Gateway", "warn", `${g.snapshot_write_failures} snapshot write failure(s)`, "Counted and retried at the next heartbeat; the dashboard may show older state.");
    add("Gateway", "info", "Last health check", g.last_health_at ? fmtTime(g.last_health_at) : "No health check has run yet.");
  }
  for (const m of st.policy_mismatches || []) add("Configuration", "bad", "Configured and effective policy differ", m, "#/security");
  for (const w of (p && p.gateway.config_warnings) || st.configured.warnings || []) add("Configuration", "warn", "Configuration warning", w);
  for (const e of providersList()) {
    const status = providerStatus(e), detail = (e.live && e.live.health && e.live.health.detail) || (e.live && (e.live.error || e.live.skipped)) || "";
    const link = `#/catalog/providers/${encodeURIComponent(e.cfg.id)}`;
    if (!e.cfg.enabled) add("Providers", "info", `${e.cfg.id} is disabled`, "Disabled in the configuration.", link);
    else if (status === "ready") add("Providers", "ok", `${e.cfg.id} is ready`, detail, link);
    else if (status === "degraded") add("Providers", "warn", `${e.cfg.id} is degraded`, detail, link);
    else if (status === "unavailable") add("Providers", "bad", `${e.cfg.id} is unavailable`, detail, link);
    else add("Providers", "info", `${e.cfg.id}: no live data`, p ? "Not running in the gateway that wrote the snapshot." : "Needs a gateway snapshot.", link);
    const v = e.cfg.verification || {};
    add("Verification", "info", `${e.cfg.id}: ${verifLabel(v)}`, [v.scope, v.last_recorded ? `recorded ${v.last_recorded}` : ""].filter(Boolean).join(" — ") || (v.meaning || ""), link);
    if (v.blocker) add("Dependencies and blockers", e.cfg.enabled ? "warn" : "info", `${e.cfg.id}: ${v.blocker}`, e.cfg.enabled ? "Enabled, but live verification is blocked." : "Disabled; live use needs this prerequisite.", link);
  }
  if (st.unreadable_snapshots) add("Snapshots", "warn", `${st.unreadable_snapshots} snapshot file(s) unreadable`, "Skipped after retries; see docs/DASHBOARD.md.");
  const inst = st.instances || [];
  add("Snapshots", "info", `${inst.length} gateway snapshot file(s)`, inst.length ? inst.map((i) => `pid ${i.pid}: ${i.freshness}`).join(", ") : "None yet.");
  if (act.audit && !act.audit.available) add("Gateway", "info", "No audit log yet", act.audit.reason || "");
  return items.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
}
const attention = () => diagnostics().filter((d) => d.sev === "bad" || d.sev === "warn");

// ---------- routing ----------
const SUBNAV = {
  catalog: [["providers", "Providers"], ["tools", "Tools"]],
  system: [["architecture", "Architecture"], ["definitions", "Definitions"], ["diagnostics", "Diagnostics"]],
};
// Routes of the previous seven-page layout keep working as redirects.
const LEGACY = { providers: "catalog/providers", tools: "catalog/tools", architecture: "system/architecture", definitions: "system/definitions" };
function resolve(hash) {
  let parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (!parts.length) parts = ["overview"];
  if (parts[0] === "tools" && parts[1] === "provider" && parts[2]) {
    S.filters.tools = { ...(S.filters.tools || {}), provider: parts[2] };
    return { redirect: "catalog/tools" };
  }
  if (LEGACY[parts[0]]) return { redirect: [LEGACY[parts[0]], ...parts.slice(1).map(encodeURIComponent)].join("/") };
  if (parts[0] in SUBNAV && !parts[1]) return { redirect: `${parts[0]}/${SUBNAV[parts[0]][0][0]}` };
  return { section: parts[0], view: parts[0] in SUBNAV ? parts[1] : null, args: parts.slice(parts[0] in SUBNAV ? 2 : 1) };
}
const VIEWS = {
  overview: () => viewOverview(), security: () => viewSecurity(), activity: () => viewActivity(),
  "catalog/providers": (r) => (r.args[0] ? viewProvider(r.args[0]) : viewProviders()),
  "catalog/tools": (r) => viewTools(r.args),
  "system/architecture": () => viewArchitecture(), "system/definitions": () => viewDefinitions(), "system/diagnostics": () => viewDiagnostics(),
};
function setNav(section, view) {
  document.querySelectorAll("[data-section]").forEach((a) => { if (a.dataset.section === section) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  const sub = $("#sub-nav");
  if (!SUBNAV[section]) { sub.hidden = true; sub.replaceChildren(); return; }
  sub.hidden = false;
  sub.replaceChildren(...SUBNAV[section].map(([id, label]) => h("a", { href: `#/${section}/${id}`, "aria-current": id === view ? "page" : null, text: label })));
}
function route(soft = false) {
  const r = resolve(location.hash);
  if (r.redirect) { history.replaceState(null, "", `#/${r.redirect}`); return route(soft); }
  const key = r.view ? `${r.section}/${r.view}` : r.section;
  const known = Boolean(VIEWS[key]);
  setNav(known ? r.section : "overview", r.view);
  const scrollY = window.scrollY;
  if (!soft) closeDrawer(false);
  if (S.error && !S.state) { page("Dashboard unavailable", null, notice(S.error, "bad")); return; }
  if (!S.state) return;
  (known ? VIEWS[key] : VIEWS.overview)(r);
  if (soft) window.scrollTo(0, scrollY);
  else $("#main").focus({ preventScroll: true });
}

// ---------- header ----------
function renderHeader() {
  const bar = $("#header-status"); bar.replaceChildren();
  if (S.error) { bar.append(mark("API error", "bad")); bar.title = S.error; return; }
  const p = primary();
  if (!p) { bar.append(mark("no gateway snapshot", "off")); bar.title = ""; return; }
  bar.append(mark(p.freshness), h("span", { text: `snapshot ${fmtAge(p.age_seconds)}` }));
  bar.title = `Gateway ${p.gateway.version}, loaded ${new Date(S.loadedAt).toLocaleTimeString()}`;
}

// ---------- overview ----------
function policyPhrase(pol) {
  if (!pol) return "unknown";
  return [pol.read_only ? "read-only" : "WRITES ALLOWED", pol.code_execution ? "code execution ON" : "no code execution",
    pol.dynamic_analysis ? "dynamic analysis ON" : "no dynamic analysis", pol.remote_ai ? "remote AI ON" : "no remote AI"].join(" · ");
}
function viewOverview() {
  const st = S.state, p = primary(), entries = providersList(), warn = attention(), t = totals();
  const enabled = entries.filter((e) => e.cfg.enabled), ready = enabled.filter((e) => providerStatus(e) === "ready");
  const unhealthy = enabled.filter((e) => ["degraded", "unavailable"].includes(providerStatus(e)));
  let tone = "off", title = "No live gateway";
  if (p && p.freshness === "live") {
    const bad = warn.some((w) => w.sev === "bad") || unhealthy.some((e) => providerStatus(e) === "unavailable");
    tone = bad ? "bad" : warn.length || unhealthy.length ? "warn" : "ok";
    title = tone === "ok" ? "Nexus is healthy" : "Nexus needs attention";
  } else if (p) {
    tone = p.freshness === "stale" ? "warn" : "off";
    title = p.freshness === "stale" ? "Gateway not responding: last known state" : "Gateway stopped: last known state";
  }
  const pol = p ? p.policy : st.configured;
  const lk = p && p.freshness !== "live" ? " (last known)" : "";
  const hero = h("section", { class: "panel" }, h("div", { class: "hero" },
    h("div", { class: "hero-state" }, h("span", { class: `hero-dot ${tone}`, "aria-hidden": "true" }), h("div", null, h("div", { class: "hero-title", text: title }),
      h("div", { class: "muted", text: p ? `${p.freshness === "live" ? "Live" : p.freshness === "stale" ? "Stale" : "Stopped"} · snapshot ${fmtAge(p.age_seconds)}` : "Start a Claude Code session or reveng-nexus serve to see live state." }))),
    h("div", { class: "hero-facts" },
      p ? h("span", null, "Version ", h("b", { text: p.gateway.version })) : null,
      p && p.freshness === "live" ? h("span", null, "Uptime ", h("b", { text: fmtDuration(Date.now() / 1000 - p.gateway.started_at) })) : null,
      h("span", null, "Policy ", h("b", { text: policyPhrase(pol) }), p ? null : h("span", { class: "faint", text: " (configured)" })),
      h("span", null, "Providers ", h("b", { text: p ? `${ready.length} of ${enabled.length} enabled ready${lk}` : `${enabled.length} enabled, health unknown` }),
        entries.length > enabled.length ? h("span", { class: "faint", text: ` · ${entries.length - enabled.length} disabled` }) : null))));
  const fig = (label, value, note, href) => h("a", { class: "figure", href }, h("div", { class: "label", text: label }), h("div", { class: "value", text: value }), h("div", { class: "note", text: note }));
  const figures = h("div", { class: "figures" },
    fig("Ready providers", p ? `${ready.length}/${enabled.length}` : "—", p ? `enabled providers reporting ready${lk}` : "unavailable: no snapshot", "#/catalog/providers"),
    fig("Callable tools", t ? fmtNum(t.callable_tools) : "—", t ? `raw tools callers may invoke${lk}` : "unavailable: no snapshot", "#/catalog/tools"),
    fig("Blocked tools", t ? fmtNum(t.blocked_tools) : "—", t ? `denied by the policy${lk}` : "unavailable: no snapshot", "#/security"),
    fig("Warnings", fmtNum(warn.length), warn.length ? "need attention" : "nothing needs attention", "#/system/diagnostics"));
  const warnPanel = panel(panelHead("Needs attention", h("a", { href: "#/system/diagnostics", text: "All diagnostics" })),
    warn.length ? h("ul", { class: "warn-list" }, warn.slice(0, 5).map((w) => h("li", null, mark(w.sev === "bad" ? "error" : "warning", w.sev),
      h("span", { class: "msg" }, h("span", { text: w.title }), w.detail ? h("div", { class: "faint", text: firstSentence(w.detail) }) : null),
      h("span", { class: "src", text: w.group }), w.link ? h("a", { href: w.link, text: "Details" }) : null)))
      : h("p", { class: "muted", text: "Nothing needs attention: configuration, snapshots and enabled providers report no problems." }),
    warn.length > 5 ? h("p", { class: "faint", text: `${warn.length - 5} more in Diagnostics.` }) : null);
  const act = S.activity || {};
  const recent = (act.recent || []).slice(0, 5);
  const actPanel = panel(panelHead("Recent activity", h("a", { href: "#/activity", text: "All activity" })),
    recent.length ? h("ul", { class: "warn-list" }, recent.map((r) => h("li", null, h("span", { class: "src", text: fmtTime(r.timestamp) }),
      h("span", { class: "msg" }, eventLabel(r), r.provider_id ? h("span", { class: "faint", text: ` · ${r.provider_id}` }) : null),
      r.outcome ? mark(r.outcome) : null, r.era !== "current" ? tag("history") : null)))
      : h("p", { class: "muted", text: act.audit && act.audit.available ? "No events recorded." : "No audit log yet." }),
    h("p", { class: "faint", text: "History, not health: an old failure does not mean a provider is failing now." }));
  const detailed = more("Detailed metrics", "every count, with its exact definition", () => {
    if (!t) return empty("Unavailable", "The counts come from a running gateway's snapshot.");
    const defs = st.definitions || {};
    const keys = ["upstream_tools_discovered", "policy_allowed_tools", "callable_tools", "exposed_tools", "blocked_tools", "operations_declared", "operations_usable", "nexus_tools"];
    return [table("metrics", [
      { key: "l", label: "Metric", value: (k) => (defs[k] || {}).label || k },
      { key: "v", label: "Value", value: (k) => t[k] ?? -1, render: (k) => fmtNum(t[k]), num: true },
      { key: "d", label: "Definition", value: (k) => (defs[k] || {}).definition || "", cls: "explain", sortable: false },
    ], keys),
    h("p", { class: "faint" }, "Different concepts, never added together. Why Ghidra shows 66 callable tools, not the 41 in older notes: ", h("a", { href: "#/system/definitions", text: "Definitions" }), ".")];
  });
  page("Overview", null, hero, h("div", { class: "stack" }, figures, h("div", { class: "grid two" }, warnPanel, actPanel), detailed));
}

// ---------- catalog: providers ----------
function countSummary(e) {
  const c = e.live && e.live.counts;
  if (!c) return e.cfg.enabled ? "no live data" : "—";
  if (c.upstream_tools_discovered) return `${fmtNum(c.upstream_tools_discovered)} tools · ${fmtNum(c.callable_tools)} callable`;
  return `${c.operations_usable}/${c.operations_declared} operations usable`;
}
function viewProviders() {
  const f = S.filters.providers || (S.filters.providers = { q: "", status: "", verif: "", enabled: "" });
  const entries = providersList();
  const rows = entries.filter((e) => {
    const hay = `${e.cfg.id} ${e.cfg.name} ${e.cfg.engine} ${e.cfg.adapter}`.toLowerCase();
    return (!f.q || hay.includes(f.q.toLowerCase())) && (!f.status || providerStatus(e) === f.status) &&
      (!f.verif || ((e.cfg.verification || {}).state || "unrecorded") === f.verif) && (!f.enabled || String(e.cfg.enabled) === f.enabled);
  });
  const set = (k) => (v) => { f[k] = v; route(true); };
  const verifs = [...new Set(entries.map((e) => (e.cfg.verification || {}).state || "unrecorded"))];
  const open = (e) => (location.hash = `#/catalog/providers/${encodeURIComponent(e.cfg.id)}`);
  page("Providers", "Engines behind the gateway. Health is live; verification is the documented record.",
    filterBar([searchBox("Search providers", f.q, (v) => (f.q = v)), select("Status", f.status, [...new Set(entries.map(providerStatus))], set("status"))],
      [select("Verification", f.verif, verifs, set("verif")), select("Enabled", f.enabled, ["true", "false"], set("enabled"))], `${rows.length} of ${entries.length}`),
    h("div", { class: "panel flush" }, rows.length ? table("providers", [
      { key: "id", label: "Provider", value: (e) => e.cfg.id, render: (e) => h("div", null, h("a", { href: `#/catalog/providers/${encodeURIComponent(e.cfg.id)}`, text: e.cfg.id, onclick: (ev) => ev.stopPropagation() }), h("div", { class: "faint", text: e.cfg.engine || e.cfg.type })) },
      { key: "health", label: "Health", value: providerStatus, render: (e) => mark(providerStatus(e)) },
      { key: "enabled", label: "Enabled", value: (e) => (e.cfg.enabled ? "yes" : "no") },
      { key: "verif", label: "Verification", value: (e) => verifLabel(e.cfg.verification), render: (e) => verifMark(e.cfg.verification) },
      { key: "counts", label: "Summary", value: countSummary, cls: "explain", sortable: false },
    ], rows, open) : empty("No provider matches", "Clear the search or filters.")));
}
function opsTable(ops) {
  const rows = Object.entries(ops || {}).filter(([k]) => !k.startsWith("_"));
  if (!rows.length) return empty("No operations", "This provider exposes no Nexus operations, or it is not running.");
  return table("ops", [
    { key: "op", label: "Operation", value: (r) => r[0], render: (r) => h("code", { text: r[0] }) },
    { key: "avail", label: "Usable", value: (r) => (r[1].available ? 1 : 0), render: (r) => mark(r[1].available ? "ready" : "unavailable") },
    { key: "tools", label: "Upstream tools", value: (r) => (r[1].tools || []).join(","), render: (r) => h("span", { class: "tags" }, (r[1].tools || []).map((x) => tag(x, true))) },
    { key: "note", label: "Note", value: (r) => r[1].reason || r[1].note || "", render: (r) => r[1].reason || r[1].note || (r[1].formats ? `formats: ${r[1].formats.join(", ")}` : ""), cls: "explain", sortable: false },
  ], rows);
}
function classBreakdown(tools) {
  const m = {};
  tools.forEach((t) => { const k = `${t.tool_class}|${toolStatus(t)}`; m[k] = (m[k] || 0) + 1; });
  return Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, v]) => { const [c, st] = k.split("|"); return { tool_class: c, status: st, count: v }; });
}
function stats(pairs) { return h("div", { class: "tags" }, pairs.map(([label, value]) => h("span", { class: "tag" }, `${label} `, h("b", { text: fmtNum(value) })))); }
function viewProvider(id) {
  const entry = providersList().find((e) => e.cfg.id === id);
  if (!entry) { page("Provider not found", null, empty("Unknown provider", id), h("p", null, h("a", { href: "#/catalog/providers", text: "All providers" }))); return; }
  const { cfg, live } = entry, p = primary();
  const c = live && live.counts, up = (live && live.upstream) || {}, health = (live && live.health) || {}, v = cfg.verification || {};
  const tools = (live && live.tools) || [], status = providerStatus(entry);
  const f = S.filters["ptools:" + id] || (S.filters["ptools:" + id] = { q: "" });
  const shownTools = tools.filter((t) => !f.q || `${t.name} ${t.description}`.toLowerCase().includes(f.q.toLowerCase()));
  const how = [];
  if (cfg.type === "builtin") how.push("In-process parsers (pyelftools, pefile, own Mach-O/APK parsers) and Capstone. No external process; no code discovery.");
  else how.push(`Runs the pinned upstream as a separate process and talks MCP over ${cfg.transport || "stdio"}. The adapter maps each Nexus operation to specific upstream tools and normalises the answer; raw output is kept as evidence.`);
  if (live && live.adapter_only) how.push("Adapter-only: callers reach it only through its nexus_* operations; every raw tool is refused for callers, even the ones the adapter uses.");
  if (cfg.kind === "dynamic") how.push("Dynamic provider: instruments live processes or devices; disabled unless dynamic analysis is enabled with explicit device and target allowlists.");
  page(h("div", null, h("div", { class: "crumbs" }, h("a", { href: "#/catalog/providers", text: "Providers" }), " /"), h("h1", { text: cfg.id })), cfg.name,
    h("div", { class: "stack" },
      panel("Summary", kv([
        ["Health", h("span", null, mark(status), health.detail ? h("span", { class: "faint", text: `  ${health.detail}` }) : null)],
        ["Freshness", p ? `${p.freshness} · snapshot ${fmtAge(p.age_seconds)}` : "unavailable (no snapshot)"],
        ["Enabled", cfg.enabled ? "yes" : "no (disabled in the configuration)"],
        ["Verification", h("span", null, verifMark(v), v.scope ? h("span", { class: "faint", text: `  ${v.scope}` }) : null)],
        live && live.adapter_only ? ["Access", h("span", null, mark("adapter-only"), h("span", { class: "faint", text: "  no raw tool is callable" }))] : null,
      ])),
      panel("Capabilities", c ? h("p", { class: "faint", text: `${c.operations_usable} of ${c.operations_declared} declared operations usable now.` }) : null, opsTable(live && live.operations)),
      panel(panelHead("Tools", tools.length ? h("a", { href: "#/catalog/tools", onclick: () => { S.filters.tools = { provider: cfg.id }; }, text: "Open in Tools view" }) : null),
        c ? stats([["discovered", c.upstream_tools_discovered], ["allowed", c.policy_allowed_tools], ["callable", c.callable_tools], ["blocked", c.blocked_tools], ["exposed", c.exposed_tools]])
          : h("p", { class: "muted", text: cfg.enabled ? "No live counts: not running in the gateway that wrote the snapshot." : "Disabled in the configuration." }),
        tools.length ? [h("div", { class: "filters" }, searchBox(`Search ${cfg.id} tools`, f.q, (q) => (f.q = q)), h("span", { class: "count-note", text: `${shownTools.length} of ${tools.length}` })),
          table("ptools", [
            { key: "n", label: "Tool", value: (t) => t.name, render: (t) => h("code", { text: t.name }) },
            { key: "s", label: "Access", value: toolStatus, render: (t) => mark(toolStatus(t)) },
            { key: "c", label: "Class", value: (t) => t.tool_class },
          ], shownTools.slice(0, 300), (t) => (location.hash = `#/catalog/tools/${encodeURIComponent(cfg.id)}/${encodeURIComponent(t.name)}`))] : null),
      more("Technical details", "pin, engine, transport, health, verification, restrictions", () => [
        h("h3", { text: "Upstream" }),
        up.upstream ? kv([["Repository", h("span", { class: "mono", text: up.upstream })], ["Pinned revision", h("span", { class: "mono", text: up.pinned_revision })],
          ["Package", `${up.package || "—"}${up.package_version ? " " + up.package_version : ""}`], ["Pin verified", `${up.verification} on ${up.verified_on}`]])
          : h("p", { class: "muted", text: cfg.type === "builtin" ? "Built into Nexus." : "No adapter data (provider not running)." }),
        h("h3", { text: "Engine and transport" }),
        kv([["Engine / family", `${cfg.engine || "—"} / ${(live && live.engine_family) || "—"}`], ["Type / transport", `${cfg.type} / ${cfg.transport || "in-process"}`], ["Kind", cfg.kind],
          ["Server-reported version", health.version || (live && live.server_info && live.server_info.version) || "—"], ["Restarts", live && live.restarts !== undefined ? live.restarts : "—"],
          ["Last health check", p && p.gateway.last_health_at ? fmtTime(p.gateway.last_health_at) : "—"], ["Health detail", health.detail || "—"],
          live && (live.error || live.skipped) ? ["Configuration diagnostics", live.error || live.skipped] : null]),
        h("h3", { text: "How the adapter works" }), h("ul", { class: "plain" }, how.map((x) => h("li", { text: x }))),
        (up.limitations || []).length ? [h("h3", { text: "Documented limitations" }), h("ul", { class: "plain" }, up.limitations.map((l) => h("li", { text: l })))] : null,
        h("h3", { text: "Verification record" }),
        kv([["State", verifMark(v)], ["Meaning", v.meaning || "—"], ["Scope", v.scope || "—"], ["Last recorded", v.last_recorded || "—"], ["Prerequisite / blocker", v.blocker || "none"], ["Source", v.source || "—"]]),
        tools.length ? [h("h3", { text: "Why tools are restricted" }), table("classes", [
          { key: "c", label: "Class", value: (r) => r.tool_class, render: (r) => h("code", { text: r.tool_class }) },
          { key: "s", label: "Decision", value: (r) => r.status, render: (r) => mark(r.status) },
          { key: "n", label: "Tools", value: (r) => r.count, num: true },
          { key: "m", label: "Meaning", value: (r) => (S.state.tool_classes || {})[r.tool_class] || "", cls: "explain", sortable: false },
        ], classBreakdown(tools))] : null,
      ]),
      Object.keys(health).length ? more("Detailed health result", "as reported by the gateway", () => [kv(Object.entries(health).filter(([, x]) => typeof x !== "object").map(([k, x]) => [k, String(x)])),
        h("details", { class: "raw" }, h("summary", { text: "Raw health record" }), h("pre", { text: JSON.stringify(health, null, 2) }))]) : null));
}

// ---------- catalog: tools ----------
function viewTools(args) {
  const f = S.filters.tools || (S.filters.tools = {});
  for (const k of ["q", "provider", "status", "op", "cls", "verif"]) if (f[k] === undefined) f[k] = "";
  const tools = allTools();
  if (!primary()) { page("Tools", null, empty("No gateway snapshot", "The catalogue comes from a running gateway's live tools/list.")); return; }
  const rows = tools.filter((t) => {
    const hay = `${t.name} ${t.public} ${t.description}`.toLowerCase();
    return (!f.q || hay.includes(f.q.toLowerCase())) && (!f.provider || t.provider === f.provider) && (!f.status || t.status === f.status) &&
      (!f.op || (t.operations || []).includes(f.op)) && (!f.cls || t.tool_class === f.cls) && (!f.verif || ((t.verification || {}).state || "") === f.verif);
  });
  const uniq = (fn) => [...new Set(tools.flatMap(fn))].filter(Boolean).sort();
  const set = (k) => (v) => { f[k] = v; route(true); };
  const shown = rows.slice(0, 500);
  const openRow = (t) => (location.hash = `#/catalog/tools/${encodeURIComponent(t.provider)}/${encodeURIComponent(t.name)}`);
  page("Tools", "Every nexus_* tool and every upstream tool the gateway discovered, with the gateway's own decision. Nothing here can be invoked.",
    filterBar([searchBox("Search tools", f.q, (v) => (f.q = v)), select("Provider", f.provider, uniq((t) => [t.provider]), set("provider")),
      select("Access", f.status, ["callable", "adapter-only", "blocked", "exposed"], set("status"))],
      [select("Operation", f.op, uniq((t) => t.operations || []), set("op")), select("Policy class", f.cls, uniq((t) => [t.tool_class]), set("cls")),
        select("Verification", f.verif, uniq((t) => [(t.verification || {}).state]), set("verif")),
        h("button", { class: "btn small", type: "button", onclick: () => { S.filters.tools = null; route(true); } }, "Clear all")],
      `${rows.length} of ${tools.length}${rows.length > shown.length ? ` (first ${shown.length})` : ""}`),
    h("div", { class: "panel flush" }, rows.length ? table("tools", [
      { key: "name", label: "Tool", value: (t) => t.name, render: (t) => h("code", { text: t.name }) },
      { key: "provider", label: "Provider", value: (t) => t.provider },
      { key: "status", label: "Access", value: (t) => t.status, render: (t) => mark(t.status) },
      { key: "op", label: "Operation", value: (t) => (t.operations || [])[0] || "", render: (t) => ((t.operations || []).length ? h("span", null, h("code", { text: t.operations[0] }), t.operations.length > 1 ? h("span", { class: "faint", text: ` +${t.operations.length - 1}` }) : null) : "—") },
      { key: "why", label: "Explanation", value: explainTool, render: (t) => h("span", { class: "clamp", text: explainTool(t) }), cls: "explain", sortable: false },
    ], shown, openRow) : empty("No tool matches", "Clear the search or filters.")));
  if (args[0] && args[1]) {
    const t = tools.find((x) => x.provider === args[0] && x.name === args[1]);
    if (t) openTool(t);
    else toast("That tool is not in the current catalogue");
  }
}
function schemaView(schema) {
  if (!schema || typeof schema !== "object") return h("p", { class: "muted", text: "The tool declares no input schema." });
  const props = schema.properties || {}, req = new Set(schema.required || []), names = Object.keys(props);
  const typeOf = (x) => (x && (x.type ? [].concat(x.type).join(" | ") : x.anyOf ? "anyOf" : x.oneOf ? "oneOf" : x.$ref ? "ref" : "any")) || "any";
  const describe = (x) => {
    if (!x || typeof x !== "object") return "";
    const parts = [];
    if (x.enum) parts.push(`one of: ${x.enum.join(", ")}`);
    if (x.default !== undefined) parts.push(`default ${JSON.stringify(x.default)}`);
    if (x.minimum !== undefined || x.maximum !== undefined) parts.push(`range ${x.minimum ?? "…"}–${x.maximum ?? "…"}`);
    if (x.pattern) parts.push(`pattern ${x.pattern}`);
    return parts.join(" · ");
  };
  const order = [...names].sort((a, b) => Number(req.has(b)) - Number(req.has(a)));
  return h("div", null,
    names.length ? h("div", { class: "schema" }, order.map((n) => h("div", { class: "schema-row" },
      h("div", null, h("code", { text: n }), req.has(n) ? h("span", { class: "req", text: "required" }) : h("span", { class: "faint", text: " optional" })),
      h("div", null, h("span", { class: "type", text: typeOf(props[n]) }), " ", h("span", { class: "muted", text: (props[n] && props[n].description) || "" }),
        describe(props[n]) ? h("div", { class: "faint", text: describe(props[n]) }) : null))))
      : h("p", { class: "muted", text: "No parameters." }),
    schema.anyOf || schema.oneOf ? h("p", { class: "faint", text: "The schema also has alternative requirement sets (anyOf/oneOf); see the raw schema." }) : null,
    h("details", { class: "raw" }, h("summary", { text: "Raw JSON schema" }), h("pre", { text: JSON.stringify(schema, null, 2) })));
}
function flowFor(t) {
  const step = (text, cls) => h("span", { class: `step ${cls || ""}`, text });
  const arrow = () => h("span", { class: "arrow", text: "→" });
  const out = [];
  if (t.kind === "nexus") {
    const ops = (t.operations || []).filter((o) => o !== "local");
    out.push(step("MCP client"), arrow(), step(t.name), arrow(), step("schema validation", "gate"), arrow());
    if (!ops.length) out.push(step("gateway / evidence store"));
    else out.push(step("registry: " + ops.join(", ")), arrow(), step("policy check per upstream call", "gate"), arrow(), step("provider adapter"), arrow(), step("upstream"));
  } else if (t.status === "callable") {
    out.push(step("MCP client"), arrow(), step(t.exposed ? t.public : "nexus_call_provider_tool"), arrow(), step("catalogue lookup", "gate"), arrow(),
      step("policy decide(arguments)", "gate"), arrow(), step(t.provider), arrow(), step(`upstream ${t.name}`));
  } else if (t.status === "adapter-only") {
    out.push(step("MCP client"), arrow(), step("nexus_call_provider_tool"), arrow(), step("refused: adapter-only", "stop"), h("span", { class: "flow-break" }),
      step(`nexus_* → ${(t.operations || []).join(", ") || "operation"}`), arrow(), step(`${t.provider} adapter`), arrow(), step("policy decide", "gate"), arrow(), step(`upstream ${t.name}`));
  } else {
    out.push(step("MCP client"), arrow(), step("nexus_call_provider_tool"), arrow(), step("catalogue lookup", "gate"), arrow(), step(`refused: ${t.tool_class}`, "stop"));
  }
  return h("div", { class: "flow" }, out);
}
function openTool(t) {
  const unrelaxable = ((primary() || {}).policy || {}).unrelaxable_classes || [];
  const v = t.verification || {};
  const sec = (title, ...body) => h("section", null, h("h3", { text: title }), ...body);
  openDrawer(t.name, [
    sec("Summary", h("p", { class: "desc", text: t.description || "No description." }),
      kv([["Provider", t.provider], ["Access", mark(t.status)], t.kind === "provider" ? ["Provider verification", verifMark(v)] : null]),
      t.kind === "provider" ? h("p", { class: "faint", text: "Upstream text is untrusted data, shown verbatim; it does not influence the decision." }) : null),
    sec("Access decision", notice(t.reason || "—", t.status === "blocked" ? "bad" : t.status === "callable" ? "ok" : ""),
      kv([["Allowed by policy", t.kind === "nexus" ? "yes" : t.policy_allowed ? "yes" : "no"],
        ["Callable directly", t.kind === "nexus" ? "yes (schema-validated)" : t.callable ? "yes, re-checked per call with its arguments" : "no"],
        ["Adapter-only", t.adapter_only ? "yes" : "no"], ["Exposed to MCP clients", t.kind === "nexus" ? "yes (nexus_* tool)" : t.exposed ? "yes (namespaced mode)" : "no"]])),
    sec("How it works", kv([["Nexus operations", (t.operations || []).join(", ") || "none"], ["Upstream tool", t.kind === "provider" ? h("span", null, h("code", { text: t.name }), " ", copyBtn(t.name)) : "—"],
      ["Public name", h("span", null, h("code", { text: t.public }), " ", copyBtn(t.public))]]), h("div", { class: "stack" }, flowFor(t))),
    sec("Input schema", schemaView(t.schema)),
    sec("Security classification", kv([["Policy class", h("code", { text: t.tool_class })], t.class_meaning ? ["Meaning", t.class_meaning] : null,
      t.source ? ["Classification source", t.source] : null, unrelaxable.includes(t.tool_class) ? ["Restriction", "This class can never be relaxed by an operator override."] : null,
      t.annotations && Object.keys(t.annotations).length ? ["Upstream annotations", h("span", { class: "mono", text: JSON.stringify(t.annotations) })] : null])),
    sec("Verification", t.kind === "provider" ? kv([["Provider state", verifMark(v)], ["Scope", v.scope || "—"], ["Prerequisite / blocker", v.blocker || "none"], ["Last recorded", v.last_recorded || "—"],
      ["Per-tool coverage", "Not recorded per tool; the provider-level record above applies."]]) : h("p", { class: "muted", text: "Nexus tools are covered by the gateway's own test suite (tests/test_server.py)." })),
  ], () => { if (location.hash.startsWith("#/catalog/tools/")) location.hash = "#/catalog/tools"; });
}

// ---------- drawer ----------
let lastFocus = null, onDrawerClose = null;
function openDrawer(title, content, onClose) {
  lastFocus = document.activeElement; onDrawerClose = onClose || null;
  $("#drawer-title").textContent = title;
  $("#drawer-body").replaceChildren(...[].concat(content).filter(Boolean));
  $("#drawer").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false");
  $("#drawer-backdrop").hidden = false;
  $("#drawer-close").focus();
}
function closeDrawer(restore = true) {
  if (!$("#drawer").classList.contains("open")) return;
  $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").hidden = true;
  const cb = onDrawerClose; onDrawerClose = null;
  if (restore && lastFocus && document.contains(lastFocus)) lastFocus.focus();
  if (restore && cb) cb();
}

// ---------- security ----------
function classCounts() {
  const m = {};
  for (const prov of (primary() || {}).providers || []) for (const t of prov.tools || []) {
    const k = t.tool_class; m[k] = m[k] || { allowed: 0, blocked: 0, adapter: 0 };
    if (!t.policy_allowed) m[k].blocked++; else if (t.callable) m[k].allowed++; else m[k].adapter++;
  }
  return m;
}
function viewSecurity() {
  const p = primary(), cfg = S.state.configured, eff = p ? p.policy : null, pol = eff || cfg;
  const controls = [
    { name: "Read-only", ok: pol.read_only === true, state: pol.read_only ? "enforced" : "OFF", why: "Tools that would change an analysis database or artefact are blocked." },
    { name: "Code execution", ok: pol.code_execution === false, state: pol.code_execution ? "enabled" : "disabled", why: "Tools that run supplied code (scripts, eval) are blocked for every provider." },
    { name: "Dynamic analysis", ok: pol.dynamic_analysis === false, state: pol.dynamic_analysis ? "enabled" : "disabled", why: "Nothing attaches to, launches or instruments live processes or devices." },
    { name: "Remote AI", ok: pol.remote_ai === false, state: pol.remote_ai ? "allowed" : "disabled", why: "No analysis data is sent to remote AI services." },
    { name: "Remote providers", ok: pol.remote_providers === false, state: pol.remote_providers ? "allowed" : "loopback only", why: "HTTP providers must run on this machine." },
  ];
  const cc = classCounts();
  const cats = (key) => Object.entries(cc).filter(([, v]) => v[key]).map(([k, v]) => `${k} (${v[key]})`).join(", ") || "none";
  const provs = (p && p.providers) || [];
  const rea = provs.find((x) => x.id === "rea");
  const opToNexus = {};
  ((p && p.nexus_tools) || []).forEach((t) => (t.operations || []).forEach((o) => (opToNexus[o] = (opToNexus[o] || []).concat(t.name))));
  const act = S.activity || {};
  page("Security", "What the gateway allows and blocks. Display only: no control here can change a policy.",
    (S.state.policy_mismatches || []).map((m) => notice(m, "bad")),
    h("div", { class: "stack" },
      panel(panelHead("Effective policy", h("span", { class: "faint", text: eff ? "reported by the running gateway" : "from the configuration (no gateway snapshot)" })),
        table("controls", [
          { key: "c", label: "Control", value: (r) => r.name, sortable: false },
          { key: "s", label: "State", value: (r) => r.state, render: (r) => mark(r.state, r.ok ? "ok" : "bad"), sortable: false },
          { key: "m", label: "Consequence", value: (r) => r.why, cls: "explain", sortable: false },
        ], controls)),
      panel("What is permitted and what is blocked", p ? kv([["Callable by callers", cats("allowed")], ["Used only inside adapters", cats("adapter")], ["Blocked", cats("blocked")]])
        : h("p", { class: "muted", text: "Needs a gateway snapshot." }), h("p", { class: "faint", text: "Upstream tools per policy class, as decided by the gateway." })),
      more("Hard security blocks", "classes that can never be relaxed, mutation-shaped names", () => eff ? [
        h("p", { class: "muted", text: "An operator tool_override may tighten any class but never relax these:" }),
        h("div", { class: "tags" }, (eff.unrelaxable_classes || []).map((c) => tag(c, true))),
        h("h3", { text: "Mutation-shaped names (blocked under read-only even with a read-only hint)" }),
        h("div", { class: "tags" }, (eff.default_blocked_tool_patterns || []).map((c) => tag(c, true))),
        h("h3", { text: "Global deny patterns (configuration)" }),
        (eff.global_blocked_tool_patterns || []).length ? h("div", { class: "tags" }, eff.global_blocked_tool_patterns.map((c) => tag(c, true))) : h("p", { class: "faint", text: "none configured" }),
      ] : empty("Unavailable", "Needs a gateway snapshot.")),
      more("Configured and effective policy", "file values next to what the gateway enforces", () => table("cfgeff", [
        { key: "c", label: "Control", value: (r) => r[0], sortable: false },
        { key: "a", label: "Configured", value: (r) => String(cfg[r[1]]), sortable: false },
        { key: "b", label: "Effective (gateway)", value: (r) => (eff ? String(eff[r[1]]) : "unavailable"), sortable: false },
      ], [["Read-only", "read_only"], ["Code execution", "code_execution"], ["Dynamic analysis", "dynamic_analysis"], ["Remote AI", "remote_ai"], ["Remote providers", "remote_providers"]])),
      more("Provider-specific restrictions", "adapter-only providers and blocked tools per class", () => provs.filter((x) => x.started).length ? table("restr", [
        { key: "id", label: "Provider", value: (r) => r.id, render: (r) => h("a", { href: `#/catalog/providers/${encodeURIComponent(r.id)}`, text: r.id }) },
        { key: "ao", label: "Adapter-only", value: (r) => (r.adapter_only ? "yes" : "no") },
        { key: "d", label: "Discovered", value: (r) => r.counts.upstream_tools_discovered, num: true },
        { key: "a", label: "Allowed", value: (r) => r.counts.policy_allowed_tools, num: true },
        { key: "c", label: "Callable", value: (r) => r.counts.callable_tools, num: true },
        { key: "b", label: "Blocked", value: (r) => r.counts.blocked_tools, num: true },
        { key: "bc", label: "Blocked by class", value: (r) => classBreakdown(r.tools || []).filter((x) => x.status === "blocked").map((x) => `${x.count} ${x.tool_class}`).join(", "), cls: "explain", sortable: false },
      ], provs.filter((x) => x.started)) : empty("No running providers", "Needs a gateway snapshot.")),
      more("REA two-operation allowlist", "adapter-only; every other REA tool blocked", () => rea ? [
        kv([["Upstream tools discovered", fmtNum(rea.counts.upstream_tools_discovered)], ["Allowed for the adapter", fmtNum(rea.counts.policy_allowed_tools)], ["Callable by callers", fmtNum(rea.counts.callable_tools)],
          ["Adapter-only", rea.adapter_only ? "yes" : "NO"], ["Operations usable", `${rea.counts.operations_usable}/${rea.counts.operations_declared}`]]),
        h("h3", { text: "Allowed upstream tool → operation → Nexus tool" }),
        h("ul", { class: "plain" }, (rea.tools || []).filter((x) => x.policy_allowed).map((x) => h("li", null, h("code", { text: x.name }), " → ", (x.used_by_operations || []).join(", ") || "no operation", " → ",
          (x.used_by_operations || []).flatMap((o) => opToNexus[o] || []).join(", ") || "—"))),
        h("p", { class: "faint", text: "Overrides cannot reopen the blocked tools, raw passthrough is refused, and the process's last argument is fixed to 'mcp' by config validation." }),
      ] : empty("REA not running", "No REA data in the current snapshot (disabled or not started).")),
      more("Targets, staging and workspace", "how files reach an engine", () => [h("ul", { class: "plain" },
        h("li", { text: "Targets are admitted only from workspace.allowed_roots; '..', UNC, device, ADS paths and links outside the roots are refused before use." }),
        h("li", { text: "Each target is hashed (SHA-256) at intake and re-verified before byte access; providers receive a hash-verified, read-only staged copy, never the original." })),
        p ? kv([["Workspace roots", (p.workspace.allowed_roots || []).join(", ") || "none (intake disabled)"], ["Max artifact size", `${fmtNum(Math.round(p.workspace.max_artifact_bytes / 1048576))} MB`], ["Follow symlinks", String(p.workspace.follow_symlinks)]]) : null]),
      more("Network and dashboard access", "loopback rules and this dashboard's own limits", () => h("ul", { class: "plain" },
        h("li", { text: `HTTP providers are loopback-only unless both provider allow_remote and policy.allow_remote_providers are set (now: ${pol.remote_providers}).` }),
        h("li", { text: "This dashboard binds loopback only, checks Host and Origin, serves GET/HEAD only and sends no CORS headers." }),
        h("li", { text: "It has no authentication: loopback keeps it off the network, but any process running under your user account can read it." }))),
      more("Policy decision reasons", "every distinct reason the gateway gave, with tool counts", () => {
        const m = {};
        for (const prov of provs) for (const t of prov.tools || []) {
          const k = `${t.policy_allowed ? "allowed" : "blocked"}|${t.policy_reason}`;
          m[k] = m[k] || { n: 0, providers: new Set() }; m[k].n++; m[k].providers.add(prov.id);
        }
        const rows = Object.entries(m).map(([k, x]) => ({ decision: k.split("|")[0], reason: k.slice(k.indexOf("|") + 1), n: x.n, providers: [...x.providers].join(", ") }));
        return rows.length ? table("reasons", [
          { key: "d", label: "Decision", value: (r) => r.decision, render: (r) => mark(r.decision, r.decision === "allowed" ? "ok" : "bad") },
          { key: "n", label: "Tools", value: (r) => r.n, num: true },
          { key: "r", label: "Reason", value: (r) => r.reason, cls: "explain" },
          { key: "p", label: "Providers", value: (r) => r.providers },
        ], rows) : empty("No decisions", "Needs a gateway snapshot.");
      }),
      more(`Recorded policy denials (${(act.policy_denials || []).length})`, "tool_call_blocked events from the audit log", () => (act.policy_denials || []).length ? table("denials", [
        { key: "t", label: "Time", value: (r) => r.timestamp, render: (r) => fmtTime(r.timestamp) },
        { key: "p", label: "Provider", value: (r) => r.provider_id },
        { key: "tool", label: "Tool", value: (r) => r.tool_name, render: (r) => h("code", { text: r.tool_name || "—" }) },
        { key: "c", label: "Class", value: (r) => r.tool_class },
        { key: "r", label: "Reason", value: (r) => r.policy_reason, cls: "explain", sortable: false },
      ], act.policy_denials) : empty("No denials recorded", "The audit log contains no tool_call_blocked events."))));
}

// ---------- activity ----------
const EVENT_LABELS = { provider_started: "Provider start", provider_stopped: "Provider stop", tool_call: "Tool call", tool_call_blocked: "Policy denial", operation: "Operation", model_call: "Model call", target_intake: "Target intake" };
function eventLabel(r) { return EVENT_LABELS[r.event] || r.event; }
function explainEvent(r) {
  if (r.note) return "Old shutdown cancellation, recorded before the 2026-10-16 fix";
  if (r.event === "tool_call_blocked") return firstSentence(r.policy_reason);
  if (r.event === "provider_started" && r.outcome === "ok") return `Started in ${fmtMs(r.duration_ms)}`;
  if (r.event === "provider_started" && r.outcome === "cancelled") return "Start cut short by the gateway's own shutdown";
  return firstSentence(r.error || r.detail || r.tool_name || r.operation || "");
}
function openRecord(r) {
  openDrawer(eventLabel(r), [
    h("section", null, h("h3", { text: "Record" }), kv([["Time", fmtTime(r.timestamp)], ["Event", h("code", { text: r.event })], ["Provider", r.provider_id || "—"],
      ["Outcome", r.outcome ? mark(r.outcome) : "—"], ["Duration", fmtMs(r.duration_ms)],
      ["Era", r.era === "current" ? "written since the running gateway started" : "history: before the running gateway started"]])),
    r.note ? h("section", null, h("h3", { text: "Note" }), notice(r.note, "warn")) : null,
    r.policy_reason ? h("section", null, h("h3", { text: "Policy reason" }), h("p", { text: r.policy_reason })) : null,
    h("section", null, h("h3", { text: "All sanitised fields" }), kv(Object.entries(r).filter(([k]) => k !== "note").map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)]))),
    h("p", { class: "faint", text: "Source: the metadata-only audit log. Arguments, results and target content are never logged." }),
  ]);
}
function viewActivity() {
  const a = S.activity || {};
  const f = S.filters.activity || (S.filters.activity = { event: "", outcome: "", provider: "", era: "" });
  if (!a.audit || !a.audit.available) { page("Activity", null, empty("No activity yet", (a.audit && a.audit.reason) || "The audit log is written by the gateway as operations run.")); return; }
  const all = a.recent || [];
  const rows = all.filter((r) => (!f.event || r.event === f.event) && (!f.outcome || r.outcome === f.outcome) && (!f.provider || r.provider_id === f.provider) && (!f.era || r.era === f.era));
  const uniq = (k) => [...new Set(all.map((r) => r[k]).filter(Boolean))].sort();
  const set = (k) => (v) => { f[k] = v; route(true); };
  const ev = a.evidence || {};
  page("Activity", "What has happened, from the metadata-only audit log. Records are history; current health is on Overview.",
    a.legacy_cancel_records ? notice(`${a.legacy_cancel_records === 1 ? "One older 'failed' provider start was a shutdown cancellation" : `${a.legacy_cancel_records} older 'failed' provider starts were shutdown cancellations`} recorded before the 2026-10-16 fix. Shown as recorded; this says nothing about current health.`, "warn") : null,
    filterBar([select("Event", f.event, uniq("event"), set("event")), select("Outcome", f.outcome, uniq("outcome"), set("outcome"))],
      [select("Provider", f.provider, uniq("provider_id"), set("provider")), select("Era", f.era, ["current", "historical"], set("era"))], `${rows.length} of ${all.length}`),
    h("div", { class: "stack" },
      h("div", { class: "panel flush" }, rows.length ? table("events", [
        { key: "t", label: "Time", value: (r) => r.timestamp, render: (r) => fmtTime(r.timestamp) },
        { key: "e", label: "Event", value: eventLabel, render: (r) => h("span", null, eventLabel(r), r.era !== "current" ? h("span", null, " ", tag("history")) : null) },
        { key: "p", label: "Provider", value: (r) => r.provider_id || "" },
        { key: "o", label: "Outcome", value: (r) => r.outcome || "", render: (r) => (r.outcome ? mark(r.outcome) : "—") },
        { key: "d", label: "Duration", value: (r) => r.duration_ms ?? -1, render: (r) => fmtMs(r.duration_ms), num: true },
        { key: "x", label: "Explanation", value: explainEvent, render: (r) => h("span", { class: "clamp", text: explainEvent(r) }), cls: "explain", sortable: false },
      ], rows.slice(0, 300), openRecord) : empty("No events match", "Clear the filters.")),
      more("Summary and evidence", "audit log, event counts, evidence store", () => [
        kv([["Audit records read", fmtNum(a.audit.records_read) + (a.audit.tail_only ? " (last 2 MB)" : "")], ["Audit log size", `${fmtNum(Math.round(a.audit.bytes / 1024))} KB`], ["Last audit write", fmtTime(a.audit.last_modified)],
          ["Running gateway since", a.current_gateway_since ? fmtTime(a.current_gateway_since) : "no live gateway"]]),
        h("h3", { text: "Event counts (all records)" }),
        table("evc", [{ key: "e", label: "Event", value: (r) => r.event, render: (r) => h("code", { text: r.event }) }, { key: "o", label: "Outcome", value: (r) => r.outcome || "", render: (r) => (r.outcome ? mark(r.outcome) : "—") }, { key: "c", label: "Count", value: (r) => r.count, num: true }], a.event_counts || []),
        Object.keys(a.calls_by_provider || {}).length ? [h("h3", { text: "Calls by provider" }), table("cbp", [{ key: "p", label: "Provider", value: (r) => r[0] }, { key: "c", label: "Calls", value: (r) => r[1].calls, num: true }, { key: "e", label: "Errors", value: (r) => r[1].errors, num: true }, { key: "m", label: "Total time", value: (r) => r[1].total_ms, render: (r) => fmtMs(r[1].total_ms), num: true }], Object.entries(a.calls_by_provider))] : null,
        h("h3", { text: "Evidence store (read-only)" }),
        ev.available ? [kv(Object.entries(ev.counts || {}).map(([k, x]) => [k, fmtNum(x)])), (ev.evidence_by_provider_tool || []).length ? table("evp", [{ key: "p", label: "Provider", value: (r) => r.provider_id }, { key: "t", label: "Tool", value: (r) => r.tool_name, render: (r) => h("code", { text: r.tool_name }) }, { key: "c", label: "Records", value: (r) => r.count, num: true }], ev.evidence_by_provider_tool) : h("p", { class: "faint", text: "No evidence recorded yet." })] : h("p", { class: "muted", text: ev.reason || "Unavailable." }),
        h("p", { class: "faint", text: (a.telemetry_notes || []).join(" ") }),
      ])));
}

// ---------- system: architecture ----------
function viewArchitecture() {
  const arch = S.state.architecture || { nodes: [], edges: [] };
  const internal = S.archInternal;
  const disabledProviders = arch.nodes.filter((n) => n.group === "provider" && n.enabled === false);
  let nodes = arch.nodes.filter((n) => internal || (n.id !== "guard" && !(n.enabled === false && (n.group === "provider" || n.group === "upstream"))));
  let edges = arch.edges.filter((e) => nodes.some((n) => n.id === e.from) && nodes.some((n) => n.id === e.to));
  if (!internal && disabledProviders.length) {
    nodes = nodes.concat([{ id: "disabled-group", label: `${disabledProviders.length} disabled provider${disabledProviders.length === 1 ? "" : "s"}`, subtitle: "not started", group: "provider", status: "disabled", enabled: false,
      responsibility: "Configured but disabled providers. They are not started and receive no traffic. Show internal components to see each one.", members: disabledProviders.map((n) => n.label) }]);
    edges = edges.concat([{ from: "registry", to: "disabled-group", active: false }]);
  }
  const cols = { client: 0, core: 1, store: 1, provider: 2, upstream: 3 };
  const colX = [30, 300, 640, 960], colW = 210, nodeH = internal ? 46 : 40, gap = internal ? 14 : 18;
  const byCol = [[], [], [], []];
  const coreOrder = ["gateway", "policy", "registry", "guard", "evidence", "audit"];
  nodes.forEach((n) => byCol[cols[n.group] ?? 1].push(n));
  byCol[1].sort((a, b) => coreOrder.indexOf(a.id) - coreOrder.indexOf(b.id));
  const pos = {};
  const height = Math.max(...byCol.map((c) => c.length)) * (nodeH + gap) + 70;
  byCol.forEach((list, ci) => {
    const total = list.length * (nodeH + gap) - gap, top = Math.max(44, (height - total) / 2);
    list.forEach((n, i) => (pos[n.id] = { x: colX[ci], y: top + i * (nodeH + gap) }));
  });
  const svg = s("svg", { class: "arch", viewBox: `0 0 1200 ${height}`, role: "group", "aria-label": "System architecture" });
  ["CLIENT", internal ? "GATEWAY CORE AND STORES" : "GATEWAY", "PROVIDER ADAPTERS", "UPSTREAM ENGINES"].forEach((l, i) => svg.appendChild(s("text", { class: "col-label", x: colX[i], y: 22 }, l)));
  const edgeEls = [];
  edges.forEach((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const x1 = a.x + colW, y1 = a.y + nodeH / 2, x2 = b.x, y2 = b.y + nodeH / 2;
    const d = x2 <= x1 ? `M${a.x + 14},${a.y + (b.y > a.y ? nodeH : 0)} L${b.x + 14},${b.y + (b.y > a.y ? 0 : nodeH)}`
      : `M${x1},${y1} C${x1 + 50},${y1} ${x2 - 50},${y2} ${x2},${y2}`;
    const path = s("path", { class: `edge ${e.active === false ? "off" : "on"}`, d, "data-from": e.from, "data-to": e.to });
    edgeEls.push(path); svg.appendChild(path);
    if (internal && e.label && x2 > x1) svg.appendChild(s("text", { class: "edge-label", x: (x1 + x2) / 2 - 20, y: (y1 + y2) / 2 - 4 }, e.label));
  });
  const dot = { ready: "var(--ok)", live: "var(--ok)", degraded: "var(--warn)", unavailable: "var(--bad)", disabled: "var(--off)", unknown: "var(--faint)" };
  nodes.forEach((n) => {
    const pp = pos[n.id];
    if (!pp) return;
    const g = s("g", { class: `node ${n.enabled === false ? "dim" : ""}`, transform: `translate(${pp.x},${pp.y})`, tabindex: "0", role: "button", "aria-label": `${n.label}: ${n.status || n.group}. Open details` });
    g.appendChild(s("rect", { width: colW, height: nodeH, rx: 7 }));
    g.appendChild(s("text", { class: "t", x: 12, y: internal ? 19 : 24 }, String(n.label).slice(0, 27)));
    if (internal) g.appendChild(s("text", { class: "s", x: 12, y: 35 }, String(n.subtitle || "").slice(0, 31)));
    if (n.status) g.appendChild(s("circle", { class: "dot", cx: colW - 13, cy: nodeH / 2, r: 5, fill: dot[n.status] || "var(--faint)" }));
    const hl = (on) => { g.classList.toggle("hl", on); edgeEls.forEach((el) => { if (el.dataset.from === n.id || el.dataset.to === n.id) el.classList.toggle("hl", on); }); };
    g.addEventListener("mouseenter", () => hl(true)); g.addEventListener("mouseleave", () => hl(false));
    g.addEventListener("focus", () => hl(true)); g.addEventListener("blur", () => hl(false));
    g.addEventListener("click", () => openNode(n));
    g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openNode(n); } });
    g.appendChild(s("title", {}, `${n.label}: ${n.responsibility || ""}`));
    svg.appendChild(g);
  });
  page("Architecture", "How a request travels. Select a node (click, or Tab and Enter) for its full explanation.",
    h("div", { class: "arch-tools" }, h("label", { class: "toggle" }, h("input", { type: "checkbox", checked: internal ? true : null, onchange: (e) => { S.archInternal = e.target.checked; route(true); } }), h("span", { text: "Show internal components" })),
      h("span", { class: "faint", text: internal ? "All nodes, module names, edge labels and every disabled provider." : "Simplified: the workspace guard and disabled providers are folded away." })),
    h("div", { class: "panel flush arch-wrap" }, svg),
    h("div", { class: "legend" }, mark("ready", "ok"), mark("degraded", "warn"), mark("unavailable", "bad"), mark("disabled (dimmed)", "off"),
      h("span", { text: "Solid edges: ready providers; dashed: not running. Nothing is animated as traffic: there is no live request stream." })));
}
function openNode(n) {
  openDrawer(n.label, [
    h("section", null, h("h3", { text: "Responsibility" }), h("p", { text: n.responsibility || "—" }),
      kv([n.status ? ["Status", mark(n.status)] : null, ["Group", n.group], n.subtitle ? ["Component", h("span", { class: "mono", text: n.subtitle })] : null,
        ["Inputs", n.inputs || "—"], ["Outputs", n.outputs || "—"], ["Depends on", (n.dependencies || []).filter(Boolean).join(", ") || "—"],
        n.pin ? ["Pinned revision", h("span", { class: "mono", text: n.pin })] : null, n.verification ? ["Verification", verifMark(n.verification)] : null,
        n.usable_operations ? ["Usable operations", n.usable_operations.join(", ") || "none"] : null])),
    n.members ? h("section", null, h("h3", { text: "Providers" }), h("ul", { class: "plain" }, n.members.map((m) => h("li", null, h("a", { href: `#/catalog/providers/${encodeURIComponent(m)}`, text: m }))))) : null,
    n.restrictions ? h("section", null, h("h3", { text: "Restrictions" }), h("ul", { class: "plain" }, n.restrictions.map((r) => h("li", { text: r })))) : null,
    n.counts && Object.keys(n.counts).length ? h("section", null, h("h3", { text: "Counts" }), kv(Object.entries(n.counts).map(([k, v]) => [(S.state.definitions[k] || {}).label || k, fmtNum(v)]))) : null,
    n.id.startsWith("provider:") ? h("p", null, h("a", { href: `#/catalog/providers/${encodeURIComponent(n.id.slice(9))}`, text: "Open provider details" })) : null,
  ]);
}

// ---------- system: definitions ----------
const DEF_CATEGORIES = [
  ["Provider and tool counts", ["upstream_tools_discovered", "policy_allowed_tools", "callable_tools", "exposed_tools", "blocked_tools", "nexus_tools"]],
  ["Operations", ["operations_declared", "operations_usable"]],
];
const ACCESS_TERMS = [
  ["callable", "Allowed by the policy and not adapter-only: a caller may invoke it through nexus_call_provider_tool. Each call is re-decided with its actual arguments."],
  ["adapter-only", "Allowed by the policy, but only for the provider's own adapter inside its nexus_* operations (REA). Refused for direct calls."],
  ["blocked", "Denied by the policy; shown for transparency and never executable."],
  ["exposed", "Listed to MCP clients as its own tool: every nexus_* tool, and raw provider tools only in tool_mode 'namespaced'."],
];
const FINDINGS = [
  ["Ghidra: 66 callable, not 41", "Older notes recorded \"41 callable\" for re-mcp-ghidra. That was the length of the providers check list, shortened to 40 names plus a \"...\" marker, not a count. Replaying the same 134-tool catalogue through the 2026-10-13 policy code gives 66 allowed, the same as today (60 read by trusted annotation + 6 by the pinned manifest; 68 blocked). providers check now prints explicit counts.", "docs/DASHBOARD.md, \"Finding: 41 callable versus 66\""],
  ["REA: discovered, adapter-allowed, callable, usable", "REA lists 207 upstream tools; the policy allows exactly 2 (analyze_javascript_application, inspect_electron_fuses) for its adapter; 0 are callable by callers because REA is adapter-only; both declared operations (js.application, electron.fuses) are usable.", "docs/DASHBOARD.md, \"REA: 207 discovered, 2 allowed, 0 callable\""],
];
function viewDefinitions() {
  const st = S.state, defs = st.definitions || {};
  const f = S.filters.defs || (S.filters.defs = { q: "" });
  const q = f.q.toLowerCase();
  const item = (term, short, detail) => (!q || `${term} ${short} ${detail || ""}`.toLowerCase().includes(q)) ? h("details", { class: "more" },
    h("summary", null, h("span", { text: term }), h("span", { class: "hint", text: firstSentence(short) })),
    h("div", { class: "more-body" }, h("p", { text: short }), detail ? h("p", { class: "faint", text: detail }) : null)) : null;
  const known = new Set(DEF_CATEGORIES.flatMap(([, keys]) => keys));
  const other = Object.keys(defs).filter((k) => !known.has(k));
  const groups = [
    ...DEF_CATEGORIES.map(([title, keys]) => [title, keys.filter((k) => defs[k]).map((k) => item(defs[k].label, defs[k].definition, `Source: ${defs[k].source} (key ${k}).`))]),
    ["Policy and access", [...ACCESS_TERMS.map(([t, d]) => item(t, d)), ...Object.entries(st.tool_classes || {}).map(([k, v]) => item(`policy class: ${k}`, v))]],
    ["Freshness", Object.entries(st.freshness_legend || {}).map(([k, v]) => item(k, v))],
    ["Verification", Object.entries(st.verification_states || {}).map(([k, v]) => item(k.replaceAll("_", " "), v, "Documented in docs/PROVIDER_MATRIX.md; never inferred from health."))],
    ["Findings", FINDINGS.map(([t, d, src]) => item(t, d, `Source: ${src}.`))],
    other.length ? ["Other", other.map((k) => item(defs[k].label || k, defs[k].definition, `Source: ${defs[k].source}.`))] : null,
  ].filter(Boolean).map(([title, items]) => [title, items.filter(Boolean)]).filter(([, items]) => items.length);
  page("Definitions", "What every figure and label means. Expand an entry for its exact source.",
    h("div", { class: "filters" }, searchBox("Search definitions", f.q, (v) => (f.q = v))),
    groups.length ? groups.map(([title, items]) => h("section", { class: "stack" }, h("h3", { text: title }), items)) : empty("No definition matches", "Clear the search."));
}

// ---------- system: diagnostics ----------
function viewDiagnostics() {
  const st = S.state, p = primary();
  const f = S.filters.diag || (S.filters.diag = { q: "", sev: "" });
  const q = f.q.toLowerCase();
  const items = diagnostics().filter((d) => (!q || `${d.title} ${d.detail} ${d.group}`.toLowerCase().includes(q)) && (!f.sev || d.sev === f.sev));
  const sevLabel = { bad: "error", warn: "warning", info: "info", ok: "ok" };
  const groupBody = (group) => {
    const list = items.filter((d) => d.group === group);
    const extra = [];
    if (group === "Gateway" && p && !q && !f.sev) {
      const g = p.gateway;
      extra.push(more("Gateway facts", "process, transport and configuration", () => kv([["Process", `pid ${g.pid}`], ["Python", g.python], ["Platform", g.platform], ["Transport / tool mode", `${g.transport} / ${g.tool_mode}`],
        ["Started", fmtTime(g.started_at)], ["Startup complete", g.startup_complete ? "yes" : "no"], ["Last health check", g.last_health_at ? fmtTime(g.last_health_at) : "none yet"],
        ["Heartbeat interval", `${g.heartbeat_seconds} s`], ["Snapshot written", fmtTime(p.written_at)], ["Config", h("span", { class: "mono", text: g.config_path || "—" })]])));
    }
    if (group === "Snapshots" && (st.instances || []).length && !q && !f.sev) {
      extra.push(more("Gateway snapshot files", "one per gateway process", () => table("instances", [
        { key: "pid", label: "PID", value: (r) => r.pid, num: true }, { key: "f", label: "State", value: (r) => r.freshness, render: (r) => mark(r.freshness) },
        { key: "t", label: "Transport", value: (r) => r.transport }, { key: "s", label: "Started", value: (r) => r.started_at || 0, render: (r) => fmtTime(r.started_at) },
        { key: "a", label: "Last heartbeat", value: (r) => r.age_seconds, render: (r) => fmtAge(r.age_seconds) },
      ], st.instances)));
    }
    if (!list.length && !extra.length) return q || f.sev ? null : more(group, "nothing reported", () => h("p", { class: "muted", text: "Nothing reported in this group." }));
    const flagged = list.filter((d) => d.sev === "bad" || d.sev === "warn").length;
    return more(group, `${list.length} item${list.length === 1 ? "" : "s"}${flagged ? ` · ${flagged} need attention` : ""}`, () => [
      list.length ? h("ul", { class: "warn-list" }, list.map((d) => h("li", null, mark(sevLabel[d.sev], d.sev), h("span", { class: "msg" }, h("span", { text: d.title }), d.detail ? h("div", { class: "faint", text: d.detail }) : null), d.link ? h("a", { href: d.link, text: "Details" }) : null))) : null,
      extra.length ? h("div", { class: "stack" }, extra) : null,
    ], flagged > 0 || Boolean(q || f.sev));
  };
  const blocks = DIAG_GROUPS.map(groupBody).filter(Boolean);
  page("Diagnostics", "Health, configuration, snapshot and verification findings, most important first. Only what the gateway and the configuration actually report.",
    h("div", { class: "filters" }, searchBox("Search diagnostics", f.q, (v) => (f.q = v)), select("Severity", f.sev, ["bad", "warn", "info", "ok"], (v) => { f.sev = v; route(true); })),
    blocks.length ? h("div", null, blocks) : empty("No diagnostic matches", "Clear the search or severity filter."));
}

// ---------- boot ----------
function boot() {
  window.addEventListener("hashchange", () => route(false));
  $("#refresh-btn").addEventListener("click", () => load(false));
  $("#drawer-close").addEventListener("click", () => closeDrawer());
  $("#drawer-backdrop").addEventListener("click", () => closeDrawer());
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  const auto = $("#auto-refresh");
  const schedule = () => { clearInterval(S.timer); if (auto.checked) S.timer = setInterval(() => { if (!document.hidden && !$("#drawer").classList.contains("open") && !document.activeElement.matches("input, select, summary")) load(true); }, 15000); };
  auto.addEventListener("change", schedule);
  schedule();
  load();
}
document.addEventListener("DOMContentLoaded", boot);
