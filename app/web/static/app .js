"use strict";
/* SecAgent console. Vanilla JS. All backend data is rendered with textContent / text nodes only. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const SCAN_TIMEOUT_MS = 240000;
const FIXTURES = [["10.10.10.3", "legacy web/FTP"], ["10.10.10.4", "mail/file server"], ["10.10.10.5", "hardened host"]];
const state = { health: null, result: null, source: null, busy: false };

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const sevBadge = (s) => h("span", { class: `badge sev-${String(s).toLowerCase()}`, text: s });
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

/* ---------- navigation ---------- */
function show(view) {
  $$(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.view === view)));
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  window.scrollTo(0, 0);
}
$$(".tab").forEach((t) => t.addEventListener("click", () => show(t.dataset.view)));
$$("[data-goto]").forEach((b) => b.addEventListener("click", () => show(b.dataset.goto)));

/* ---------- health ---------- */
async function checkHealth() {
  setPill("wait", "Checking API…");
  try {
    const r = await fetch("/health", { cache: "no-store", signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    state.health = await r.json();
  } catch (e) {
    state.health = null;
  }
  renderHealth();
}
function setPill(kind, text) {
  const p = $("#status-pill");
  p.className = `pill pill-${kind}`;
  $("span", p).textContent = text;
}
function renderHealth() {
  const hd = state.health;
  if (!hd) {
    setPill("bad", "API unreachable");
    $("#c-api").textContent = "Unreachable";
    $("#c-api-sub").textContent = "GET /health failed. Is uvicorn running?";
    $("#c-mode").textContent = $("#c-pipe").textContent = "—";
    $("#c-mode-sub").textContent = $("#c-pipe-sub").textContent = "";
    $("#fixtures").hidden = true;
    return;
  }
  const mock = hd.tool_mode === "mock";
  setPill("ok", `API connected · ${hd.tool_mode} mode`);
  $("#c-api").textContent = String(hd.status || "ok").toUpperCase();
  $("#c-api-sub").textContent = "GET /health responded";
  $("#c-mode").textContent = mock ? "Mock" : "Live";
  $("#c-mode-sub").textContent = mock ? "Fixture data, no packets sent" : "Real nmap against allow-listed CIDRs";
  const agentic = hd.pipeline === "agentic";
  $("#c-pipe").textContent = agentic ? "Agentic" : "Deterministic";
  $("#c-pipe-sub").textContent = agentic ? "LLM agents configured; falls back if they fail" : "No LLM in the loop (agents disabled or no API key)";
  const fx = $("#fixtures");
  fx.replaceChildren();
  if (mock) {
    fx.append("Mock fixtures:", ...FIXTURES.map(([ip, label]) => h("button", { type: "button", class: "chip", title: label, onclick: () => { $("#f-target").value = ip; $("#f-target").focus(); } }, ip)), h("span", { text: "(legacy · mail/file · hardened)" }));
  }
  fx.hidden = !mock;
}

/* ---------- form ---------- */
function errorMessages(status, body) {
  const d = body && body.detail;
  if (Array.isArray(d)) return d.map((e) => { const loc = (e.loc || []).filter((x) => x !== "body").join("."); return (loc ? `${loc}: ` : "") + String(e.msg || "invalid value").replace(/^Value error, /, ""); });
  if (typeof d === "string") return [d];
  return [`The server returned HTTP ${status}.`];
}
function showError(title, msgs) {
  const box = $("#form-error");
  box.replaceChildren(h("strong", { text: title }), h("ul", {}, msgs.map((m) => h("li", { text: m }))));
  box.hidden = false;
}
function setBusy(b) {
  state.busy = b;
  $("#submit").disabled = b;
  $("#submit .spinner").hidden = !b;
  $("#submit-label").textContent = b ? "Assessing…" : "Run assessment";
  $("#busy-note").hidden = !b;
  $("#scan-form").setAttribute("aria-busy", String(b));
}
async function onSubmit(ev) {
  ev.preventDefault();
  if (state.busy) return;
  $("#form-error").hidden = true;
  const target = $("#f-target").value.trim(), raw = $("#f-raw").value.trim(), ports = $("#f-ports").value.trim() || "1-1024";
  const problems = [];
  if (!target && !raw) problems.push("Enter a target IP address, or paste existing nmap output.");
  if (!$("#f-auth").checked) problems.push("Confirm that you are authorised to assess this target.");
  if (problems.length) return showError("Check the form", problems);

  const payload = { authorization_confirmed: true, ports };
  if (target) payload.target = target;
  if (raw) payload.raw_scan_data = raw;

  setBusy(true);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), SCAN_TIMEOUT_MS);
  try {
    const r = await fetch("/api/v1/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload), signal: ctl.signal });
    const body = await r.json().catch(() => null);
    if (!r.ok) {
      const titles = { 403: "Target outside authorised scope", 422: "Request rejected by validation", 502: "Scan failed", 503: "Nmap is not available", 504: "Scan timed out" };
      return showError(titles[r.status] || "Request failed", errorMessages(r.status, body));
    }
    state.result = body;
    state.source = { live_nmap: "live", mock_fixture: "mock", provided_scan_data: "provided" }[body.data_source] || "mock";
    renderReport();
    renderOverviewLast();
    show("report");
  } catch (e) {
    showError(e.name === "AbortError" ? "Assessment timed out" : "Could not reach the API", [e.name === "AbortError" ? `No response after ${SCAN_TIMEOUT_MS / 1000}s. The scan may still be running on the server.` : "Check that the server is running, then retry."]);
    checkHealth();
  } finally {
    clearTimeout(timer);
    setBusy(false);
  }
}
$("#scan-form").addEventListener("submit", onSubmit);

/* ---------- rendering ---------- */
function statCard(label, value, sub, mono) {
  return h("div", { class: "card" }, h("span", { class: "label", text: label }), h("strong", { class: mono ? "mono" : "", text: value }), sub ? h("small", { text: sub }) : null);
}
function countSev(cves) {
  const c = {};
  cves.forEach((x) => (c[x.severity] = (c[x.severity] || 0) + 1));
  return c;
}
function summaryCards(res) {
  const r = res.report, c = countSev(r.identified_cves), urgent = (c.CRITICAL || 0) + (c.HIGH || 0);
  return h("div", { class: "cards" },
    statCard("Target", r.target_host, null, true),
    statCard("Open ports", r.open_ports.length, plural(r.detected_services.length, "service") + " detected"),
    statCard("CVE matches", r.identified_cves.length, r.identified_cves.length ? `${urgent} critical/high` : "none in local KB"),
    statCard("Remediation steps", r.recommended_remediation_plan.length, `${res.tool_calls} tool calls · ${(res.duration_ms / 1000).toFixed(2)}s`));
}
function renderOverviewLast() {
  const root = $("#overview-last");
  root.replaceChildren();
  if (!state.result) {
    root.append(h("div", { class: "panel empty" }, "No assessment has been run in this session.", h("br"), "The backend does not expose scan history, so only your most recent result is shown here."));
    return;
  }
  root.append(summaryCards(state.result), h("p", { class: "help" }, h("a", { href: "#", onclick: (e) => { e.preventDefault(); show("report"); } }, "Open full report →")));
}

const SOURCE_NOTE = {
  mock: ["notice-warn", "Mock data.", "Generated by the built-in fixture backend. No packets were sent to the target."],
  provided: ["notice-info", "Analysis of supplied scan output.", "SecAgent parsed the nmap output you provided and did not scan this host."],
  live: ["notice-ok", "Real scan.", "Ports and services were observed by nmap, run from the backend host for this request."],
};
const SOURCE_LABEL = { mock: "mock fixture", provided: "supplied nmap output", live: "live nmap scan" };

function renderReportEmpty() {
  $("#report-root").replaceChildren(
    h("h1", { class: "page-title", text: "Assessment report" }),
    h("div", { class: "panel empty" }, "No report yet. Run an assessment and the findings and remediation plan will appear here.", h("br"), h("br"),
      h("button", { class: "btn btn-primary", type: "button", onclick: () => show("assess") }, "New assessment")));
}

function renderReport() {
  const res = state.result, r = res.report, root = $("#report-root");
  root.replaceChildren();
  const agentic = res.execution_mode === "agentic";
  const [cls, lead, rest] = SOURCE_NOTE[state.source];

  root.append(
    h("div", { class: "report-head" },
      h("div", {}, h("h1", {}, "Assessment report · ", h("span", { class: "mono", text: r.target_host })),
        h("div", { class: "meta" },
          h("span", { class: `badge ${agentic ? "badge-ok" : "badge-muted"}`, text: agentic ? "Agentic pipeline" : "Deterministic pipeline" }),
          h("span", { class: `badge ${res.real_scan ? "badge-ok" : "badge-warn"}`, text: res.real_scan ? "Real nmap scan" : SOURCE_LABEL[state.source] }),
          h("span", { text: `scan ${res.scan_id}` }))),
      h("button", { class: "btn", type: "button", onclick: exportJson }, "Export JSON")),
    h("div", { class: `notice ${cls}` }, h("strong", { text: lead + " " }), rest, " ", res.evidence_note,
      res.scan_evidence ? h("div", { class: "help" }, `nmap ${res.scan_evidence.nmap_version || ""} · exit ${res.scan_evidence.exit_code} · ${res.scan_evidence.elapsed_s ?? "?"}s · `, h("code", { text: res.scan_evidence.command.join(" ") })) : null));

  if (res.warnings.length) {
    root.append(h("div", { class: "notice notice-warn" }, h("strong", { text: "Pipeline notes" }), h("ul", {}, res.warnings.map((w) => h("li", { text: w })))));
  }
  root.append(summaryCards(res));

  /* services */
  root.append(h("h2", { class: "section-title", text: "Exposed services" }));
  if (!r.detected_services.length) {
    root.append(h("div", { class: "panel empty", text: "No open ports were reported in the scanned range." }));
  } else {
    root.append(h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Port", "Service", "Product", "Version", "Banner evidence"].map((t) => h("th", { text: t })))),
      h("tbody", {}, r.detected_services.map((s) => h("tr", {},
        h("td", { class: "mono", text: `${s.port}/${s.protocol}` }), h("td", { text: s.name }), h("td", { text: s.product || "—" }),
        h("td", { class: "mono", text: s.version || "unknown" }), h("td", { class: "mono", text: s.banner || "not collected" })))))));
  }

  /* findings */
  const cves = r.identified_cves;
  root.append(h("h2", { class: "section-title" }, "Findings", h("span", { class: "muted", text: `${cves.length} version-matched, ordered by CVSS` })));
  if (!cves.length) {
    root.append(h("div", { class: "panel empty", text: "No known CVEs in the local knowledge base matched the detected versions. This is not proof the host is secure." }));
  }
  cves.forEach((c, i) => root.append(findingCard(c, r, i === 0)));

  /* remediation */
  const sevById = Object.fromEntries(cves.map((c) => [c.cve_id, c]));
  root.append(h("h2", { class: "section-title" }, "Remediation plan", h("span", { class: "muted", text: "in priority order" })));
  root.append(h("ol", { class: "steps" }, r.recommended_remediation_plan.map((st) => {
    const refs = st.related_cves.map((id) => sevById[id]).filter(Boolean);
    return h("li", { class: "step" },
      h("span", { class: "num", text: st.step }),
      h("div", {},
        h("div", { class: "top" }, sevBadge(st.priority), h("span", { class: "badge badge-muted", text: "Retest: not performed" })),
        h("p", { text: st.action }),
        refs.length
          ? h("div", { class: "addr" }, "Addresses: ", refs.map((c) => `${c.cve_id} (${c.severity}, port ${c.affected_port})`).join(" · "))
          : h("div", { class: "addr", text: "General hygiene step, not tied to a specific CVE." })));
  })));
  root.append(h("p", { class: "help", text: "SecAgent does not verify fixes. Apply the changes, then run a new assessment to confirm the findings no longer match." }));
}

function findingCard(c, r, open) {
  const svc = r.detected_services.find((s) => s.port === c.affected_port);
  const nvd = /^CVE-\d{4}-\d{4,}$/.test(c.cve_id) ? `https://nvd.nist.gov/vuln/detail/${c.cve_id}` : null;
  return h("details", { class: "finding", open },
    h("summary", {}, sevBadge(c.severity), h("span", { class: "cve", text: c.cve_id }), h("span", { class: "where", text: `CVSS ${c.cvss_score.toFixed(1)} · ${c.affected_service} · port ${c.affected_port}` })),
    h("div", { class: "fbody" },
      h("div", {}, h("h3", { text: "What was matched" }), h("p", { text: c.summary })),
      h("div", {}, h("h3", { text: "Evidence" }), h("dl", { class: "kv" },
        h("dt", { text: "Detected service" }), h("dd", { class: "mono", text: svc ? `${svc.product || svc.name} ${svc.version || ""} on ${svc.port}/${svc.protocol}`.replace(/\s+/g, " ") : c.affected_service }),
        h("dt", { text: "Banner" }), h("dd", { class: "mono", text: (svc && svc.banner) || "not collected" }),
        h("dt", { text: "Data source" }), h("dd", { text: SOURCE_LABEL[state.source] }))),
      h("div", {}, h("h3", { text: "Potential attack path (conceptual)" }), h("p", { text: c.exploit_path })),
      h("div", { class: "tags" }, h("span", { class: "badge badge-info", text: "Version-matched" }), h("span", { class: "badge badge-muted", text: "Exploit not validated" }), h("span", { class: "badge badge-muted", text: "Not retested" }),
        nvd ? h("a", { href: nvd, target: "_blank", rel: "noopener noreferrer", text: "NVD record ↗" }) : null)));
}

function exportJson() {
  if (!state.result) return;
  const doc = { exported_at: new Date().toISOString(), data_source: state.source, note: "Version-matched findings; exploitability not validated.", response: state.result };
  const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }));
  const a = h("a", { href: url, download: `secagent-${state.result.scan_id}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

renderOverviewLast();
renderReportEmpty();
checkHealth();
setInterval(() => { if (!state.busy) checkHealth(); }, 30000);
