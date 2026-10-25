// Sieve web app (dependency-free). Every value that came from logs is escaped with esc() before display.
"use strict";
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const BAND = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const STATUS = { new: "New", acknowledged: "Acknowledged", resolved: "Resolved", false_positive: "False positive" };
let me = null, timer = null;

function csrf() { return (document.cookie.match(/(?:^|; )sieve_csrf=([^;]+)/) || [])[1] || ""; }

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "content-type": "application/json" }, credentials: "same-origin" };
  if (init.method !== "GET") init.headers["x-sieve-csrf"] = csrf();
  if (opts.body) init.body = JSON.stringify(opts.body);
  let r;
  try { r = await fetch(path, init); } catch (e) {
    throw { code: "SIEVE-NET-000", message: "Cannot reach Sieve.", fix: "Check that the container is running." };
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw (data.detail && data.detail.code) ? data.detail : (data.code ? data : { code: `HTTP ${r.status}`, message: "Request failed.", fix: "" });
  return data;
}

function toast(msg) { const t = $("#toast"); t.textContent = msg; t.hidden = false; clearTimeout(t._h); t._h = setTimeout(() => (t.hidden = true), 5000); }
function errText(e) { return `${e.message || e} ${e.fix ? "— " + e.fix : ""} (${e.code || "error"})`; }
function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (s < 90) return `${Math.round(s)} s`; if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`; return `${Math.round(s / 86400)} d`;
}
function pill(band) { return `<span class="pill ${esc(band)}">${esc(BAND[band] || band)}</span>`; }
function setNav(route) {
  document.querySelectorAll(".nav a").forEach((a) => a.toggleAttribute("aria-current", a.dataset.route === route) || a.removeAttribute("aria-current"));
  document.querySelectorAll(".nav a").forEach((a) => { if (a.dataset.route === route) a.setAttribute("aria-current", "page"); });
}

async function healthMini() {
  try {
    const h = await api("/api/health");
    const rows = [`<div class="row"><span class="dot ${h.queue.failed ? "bad" : ""}"></span>Queue<span>${h.queue.pending} waiting</span></div>`];
    h.llm.forEach((p) => {
      const cls = p.state === "ok" ? "" : p.state === "unknown" ? "warn" : "bad";
      rows.push(`<div class="row"><span class="dot ${cls}"></span>${esc(p.name)}<span>${esc(p.state)}</span></div>`);
    });
    h.notifiers.forEach((n) => rows.push(`<div class="row"><span class="dot"></span>${esc(n)}<span>on</span></div>`));
    $("#health-mini").innerHTML = `<span class="small muted">System health</span>${rows.join("")}`;
  } catch { $("#health-mini").innerHTML = `<span class="error small">Health unavailable</span>`; }
}

// ---------- views ----------
function authView(kind) {
  $("#nav").hidden = true;
  const setup = kind === "setup";
  $("#main").innerHTML = `
  <section class="auth panel pad stack" aria-labelledby="auth-h">
    <h1 id="auth-h">${setup ? "Set up Sieve" : "Sign in"}</h1>
    <p class="muted">${setup ? "Create the admin account. You can add more people later. Use a passphrase of 12 or more characters." : "Use the account an admin created for you."}</p>
    <form id="auth" class="stack" novalidate>
      <div class="field"><label for="u">Username</label><input id="u" type="text" autocomplete="username" required></div>
      <div class="field"><label for="p">Password</label><input id="p" type="password" autocomplete="${setup ? "new-password" : "current-password"}" required minlength="${setup ? 12 : 1}"></div>
      <p class="error" id="auth-err" role="alert"></p>
      <button class="btn primary" type="submit">${setup ? "Create admin and continue" : "Sign in"}</button>
    </form>
  </section>`;
  $("#auth").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await api(setup ? "/api/setup/admin" : "/api/auth/login", { method: "POST", body: { username: $("#u").value, password: $("#p").value } });
      location.hash = "#/overview"; route();
    } catch (e) { $("#auth-err").textContent = errText(e); }
  });
}

async function overview() {
  setNav("overview");
  const [st, incs] = await Promise.all([api("/api/stats"), api("/api/incidents")]);
  const need = incs.filter((i) => i.status === "new" && (i.band === "critical" || i.band === "high" || i.tripwire)).slice(0, 4);
  const needHtml = need.length ? need.map((i) => `
    <div class="item">
      ${i.tripwire ? `<span class="pill trip">Tripwire</span>` : ""}${pill(i.band)}
      <div class="grow stack g4"><span class="title">${esc(i.title)} on ${esc(i.agent_name)}</span>
      <span class="muted">${esc(i.alert_count)} alert(s) grouped, opened ${ago(i.opened_at)} ago.${i.tripwire ? " A log field tried to instruct the AI; it was treated as data." : ""}</span></div>
      <a class="btn primary" href="#/incident/${i.id}">Open incident</a>
    </div>`).join("") : `<div class="empty">Nothing needs you right now.</div>`;
  const rows = incs.map((i) => `<tr>
      <td>${pill(i.band)}</td>
      <td><a href="#/incident/${i.id}"><b>${esc(i.title)}</b></a>${i.tripwire ? ` <span class="pill trip">tripwire</span>` : ""}</td>
      <td class="mono">${esc(i.agent_name)}</td><td class="num">${esc(i.alert_count)}</td>
      <td class="muted">${ago(i.last_seen)}</td><td>${esc(STATUS[i.status] || i.status)}</td>
      <td class="muted">${esc(i.assignee || "Unassigned")}</td></tr>`).join("");
  $("#main").innerHTML = `
    <header class="row-wrap between"><div class="stack g6"><h1>Overview</h1>
      <p class="muted">${st.needs_action ? `${st.needs_action} incident(s) need you.` : "Nothing urgent."} Updates every 10 seconds.</p></div></header>
    <section class="stack" aria-labelledby="n"><h2 id="n">Needs you now</h2><div class="panel">${needHtml}</div></section>
    <section class="stack" aria-labelledby="d"><h2 id="d">So far</h2><div class="panel stats">
      <div class="stat"><span class="small muted">Alerts received from Wazuh</span><b>${st.alerts_received.toLocaleString()}</b></div>
      <div class="stat"><span class="small muted">Notifications sent</span><b>${st.notifications}</b></div>
      <div class="stat"><span class="small muted">Suppressed, each with a reason</span><b>${st.suppressed.toLocaleString()}</b><a class="small" href="#/hidden">See why</a></div>
      <div class="stat"><span class="small muted">Median time to acknowledge</span><b>${st.median_tta_min == null ? "–" : st.median_tta_min + " min"}</b></div>
    </div></section>
    <section class="stack" aria-labelledby="q"><div class="row-wrap between"><h2 id="q">Incident queue</h2><span class="small muted">Sorted by severity, then age</span></div>
      <div class="panel table-wrap">${incs.length ? `<table><thead><tr><th scope="col">Severity</th><th scope="col">Incident</th><th scope="col">Host</th><th scope="col" class="num">Alerts</th><th scope="col">Last seen</th><th scope="col">Status</th><th scope="col">Owner</th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty">No incidents yet. Point Wazuh at Sieve, or run the demo.</div>`}</div></section>`;
  timer = setTimeout(() => location.hash.startsWith("#/overview") && overview().catch(() => {}), 10000);
}

async function incident(id) {
  setNav("overview");
  const i = await api(`/api/incidents/${id}`);
  const byId = Object.fromEntries(i.alerts.map((a) => [`alert:${a.id}`, a]));
  const ex = i.explanation && i.explanation.summary && i.explanation.summary.summary ? i.explanation : null;
  const summary = ex ? ex.summary.summary : i.facts;
  const evLink = (e) => byId[e] ? `<a class="ev" href="#ev-${esc(e.split(":")[1])}">${esc(e)}</a>` : `<span class="ev muted">${esc(e)}</span>`;
  const facts = summary.map((f) => `<li>${esc(f.text)} ${f.evidence.map(evLink).join(" ")}</li>`).join("");
  const hyps = ex && ex.summary.hypotheses && ex.summary.hypotheses.length ? ex.summary.hypotheses.map((h) => `
     <div class="panel pad stack g6"><b>${esc(h.name)}</b>
     ${h.supports.length ? `<span class="small">Supports: ${h.supports.map(esc).join("; ")}</span>` : ""}
     ${h.refutes.length ? `<span class="small muted">Against: ${h.refutes.map(esc).join("; ")}</span>` : ""}</div>`).join("") : "";
  const tripIds = new Set((i.tripwire_hits || []).map((h) => h.alert_id));
  const shown = i.alerts.filter((a, k) => k === 0 || k === i.alerts.length - 1 || tripIds.has(a.id) || byId && summary.some((f) => f.evidence.includes(`alert:${a.id}`)));
  const evidence = shown.map((a) => `
     <div class="stack g8" id="ev-${a.id}"><span class="small"><b>alert:${a.id}</b> · rule ${esc(a.rule_id)} · level ${esc(a.level)} · ${new Date(a.timestamp).toLocaleTimeString()}</span>
     <pre>${esc(a.full_log)}</pre>
     ${Object.entries(a.untrusted).filter(([k]) => k !== "full_log").map(([k, v]) => `<div class="untrusted"><span class="label">Untrusted field: ${esc(k)}</span><code>${esc(v)}</code></div>`).join("")}</div>`).join("");
  const steps = (i.playbook ? i.playbook.steps : []).map((st) => `<label class="check"><input type="checkbox"><span>${esc(st.text)}${st.approval ? `<span class="small muted block">Runs only after you approve it</span>` : ""}</span></label>`).join("");
  const breakdown = i.breakdown.map((b) => `<div class="score-row"><span>${esc(b.label)}</span><span class="num">+${b.points}</span></div>`).join("");
  const aiLine = ex ? `Written by ${esc(ex.provider)} (${esc(ex.model)}), checked against the evidence${ex.validation && ex.validation.dropped_sentences ? `; ${ex.validation.dropped_sentences} unsupported sentence(s) removed` : ""}.` : "Rule-based facts. AI summary not available yet.";
  const canAct = me && me.role !== "viewer";
  $("#main").innerHTML = `
    <div class="small"><a href="#/overview">Incidents</a><span class="muted"> / INC-${i.id}</span></div>
    <header class="row-wrap between top">
      <div class="grow stack">
        <div class="row-wrap g12"><span class="pill ${esc(i.band)}">${esc(BAND[i.band])}, score ${Math.round(i.score)}</span><h1>${esc(i.title)}</h1></div>
        <dl class="meta">
          <div><dt>Host</dt><dd class="mono">${esc(i.agent_name)}</dd></div>
          ${i.srcip ? `<div><dt>Source</dt><dd class="mono">${esc(i.srcip)}</dd></div>` : ""}
          ${i.user ? `<div><dt>User</dt><dd class="mono">${esc(i.user)}</dd></div>` : ""}
          <div><dt>Alerts</dt><dd>${esc(i.alert_count)} grouped</dd></div>
          <div><dt>Status</dt><dd>${esc(STATUS[i.status] || i.status)}</dd></div>
          ${i.techniques.length ? `<div><dt>ATT&amp;CK</dt><dd>${i.techniques.map(esc).join(", ")}</dd></div>` : ""}
        </dl>
      </div>
      ${canAct ? `<div class="row-wrap g8">
        <button class="btn primary" data-act="acknowledge" ${i.status !== "new" ? "disabled" : ""}>Acknowledge</button>
        <button class="btn" data-act="resolve">Resolve</button>
        <button class="btn" data-act="false-positive">Mark false positive</button></div>` : ""}
    </header>
    ${i.tripwire ? `<div class="note" role="note"><div><b>Tripwire: someone tried to steer the AI</b>
      ${[...new Map((i.tripwire_hits || []).map((h) => [h.field, h])).values()].slice(0, 3).map((h) => `Field <code>${esc(h.field)}</code> matched: ${esc(h.reasons.join(", "))}.`).join(" ")}
      Sieve treated it as data. Severity comes from rules and did not change.</div></div>` : ""}
    <div class="cols">
      <div class="col-main">
        <section class="panel pad stack" aria-labelledby="w"><div class="row-wrap between"><h2 id="w">What happened</h2><span class="small muted">${aiLine}</span></div>
          <ol class="facts">${facts}</ol>
          <div class="row-wrap small g16"><span>Wazuh query: <code>${esc(i.wazuh_query)}</code></span>
          ${canAct ? `<button class="btn" id="explain">Ask AI again</button>` : ""}</div></section>
        ${hyps ? `<section class="panel pad stack" aria-labelledby="h"><h2 id="h">Explanations considered</h2>${hyps}</section>` : ""}
        <section class="panel pad stack" aria-labelledby="y"><h2 id="y">Why it is ${esc(BAND[i.band]).toLowerCase()}</h2>
          <div>${breakdown}<div class="score-row"><span>${i.overrides.length ? "Score, and override: " + i.overrides.map(esc).join("; ") : "Score"}</span><span class="num">${Math.round(i.score)}</span></div></div></section>
      </div>
      <div class="col-side">
        <section class="panel pad stack" aria-labelledby="t"><h2 id="t">What to do now</h2><div>${steps}</div>
          <span class="small muted">From playbook ${esc(i.playbook ? i.playbook.id : "")}, written by people, not the AI.</span></section>
        <section class="panel pad stack" aria-labelledby="e"><h2 id="e">Evidence</h2>${evidence}<span class="small muted">Showing ${shown.length} of ${esc(i.alert_count)} alerts.</span></section>
      </div>
    </div>`;
  document.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      const reason = b.dataset.act === "false-positive" ? (prompt("Why is this a false positive? (helps tuning)") || "") : "";
      await api(`/api/incidents/${i.id}/${b.dataset.act}`, { method: "POST", body: b.dataset.act === "acknowledge" ? undefined : { reason } });
      toast("Saved."); incident(id);
    } catch (e) { toast(errText(e)); b.disabled = false; }
  }));
  const exb = $("#explain");
  if (exb) exb.addEventListener("click", async () => {
    exb.disabled = true; exb.textContent = "Asking…";
    try { const r = await api(`/api/incidents/${i.id}/explain`, { method: "POST" }); toast(r.ok ? "AI summary updated." : r.message); incident(id); }
    catch (e) { toast(errText(e)); exb.disabled = false; exb.textContent = "Ask AI again"; }
  });
}

async function hidden() {
  setNav("hidden");
  const d = await api("/api/suppressions");
  $("#main").innerHTML = `
    <header class="stack g6"><h1>Hidden alerts</h1><p class="muted">${d.total.toLocaleString()} alerts were suppressed. Each has a recorded reason. Check this week's random sample and bring back anything real.</p></header>
    <section class="panel pad stack"><h2>Reasons</h2>${d.by_reason.map((r) => `<div class="score-row"><span>${esc(r.reason)}</span><span class="num">${r.count}</span></div>`).join("") || `<p class="muted">None yet.</p>`}</section>
    <section class="panel table-wrap"><table><thead><tr><th scope="col">Rule</th><th scope="col">Description</th><th scope="col">Reason</th><th scope="col">Your check</th></tr></thead><tbody>
    ${d.sample.map((x) => `<tr><td class="mono">${esc(x.rule_id)}</td><td>${esc(x.description)}</td><td class="muted">${esc(x.reason)}</td>
      <td>${x.outcome ? esc(x.outcome === "noise" ? "Confirmed noise" : "Restored") : `<button class="btn" data-s="${x.id}" data-o="noise">Noise</button> <button class="btn" data-s="${x.id}" data-o="restored">Bring back</button>`}</td></tr>`).join("")}
    </tbody></table></section>`;
  document.querySelectorAll("[data-s]").forEach((b) => b.addEventListener("click", async () => {
    try { await api(`/api/suppressions/${b.dataset.s}/${b.dataset.o}`, { method: "POST" }); hidden(); } catch (e) { toast(errText(e)); }
  }));
}

async function health() {
  setNav("health");
  const h = await api("/api/health");
  $("#main").innerHTML = `
    <header class="stack g6"><h1>Health</h1><p class="muted">Sieve ${esc(h.version)}. Status: ${esc(h.status)}. Last alert: ${h.last_alert_at ? ago(h.last_alert_at) + " ago" : "none yet"}.</p></header>
    <section class="panel pad stack"><h2>Queue</h2><div class="score-row"><span>Waiting</span><span class="num">${h.queue.pending}</span></div><div class="score-row"><span>Failed after retries</span><span class="num">${h.queue.failed}</span></div></section>
    <section class="panel pad stack"><h2>AI providers, in fallback order</h2>
    ${h.llm.map((p, k) => `<div class="score-row"><span>${k + 1}. ${esc(p.name)} <span class="muted">${esc(p.kind)}, ${esc(p.model)}${p.cloud ? ", cloud" : ", local"}</span>${p.last_error ? `<br><span class="small error">${esc(p.last_error.message || "")} ${esc(p.last_error.fix || "")}</span>` : ""}</span><span>${esc(p.state)}</span></div>`).join("")}
    <div class="score-row"><span>${h.llm.length + 1}. No AI (rule-based facts)</span><span>always on</span></div></section>
    <section class="panel pad stack"><h2>Notifications</h2>${h.notifiers.map((n) => `<div class="score-row"><span>${esc(n)}</span><span>on</span></div>`).join("")}</section>`;
}

async function route() {
  clearTimeout(timer);
  const hash = location.hash || "#/overview";
  try {
    const st = await api("/api/setup/status");
    if (st.needs_admin) return authView("setup");
    try { me = await api("/api/me"); } catch { return authView("login"); }
    $("#nav").hidden = false; healthMini();
    const m = hash.match(/^#\/incident\/(\d+)/);
    if (m) await incident(m[1]);
    else if (hash.startsWith("#/hidden")) await hidden();
    else if (hash.startsWith("#/health")) await health();
    else await overview();
    $("#main").focus({ preventScroll: true });
  } catch (e) {
    $("#main").innerHTML = `<div class="panel pad stack"><h2>Something went wrong</h2><p class="error">${esc(errText(e))}</p><button class="btn" id="retry">Try again</button></div>`;
    $("#retry").addEventListener("click", route);
  }
}

$("#logout").addEventListener("click", async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => {}); me = null; route(); });
window.addEventListener("hashchange", route);
route();
