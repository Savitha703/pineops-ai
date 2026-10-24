/* Plain JavaScript: hash navigation, Flask API calls, and Chart.js charts. */
"use strict";

const state = { incidents: [], historyError: "", health: null, sample: false, events: [], charts: {}, deleteId: null, route: 0, chatHistory: {} };
const severityRank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const colors = ["#9c8ce4", "#83a6e7", "#e8bb7b", "#d997aa", "#80bdab", "#a7b1c7"];
const $ = (selector) => document.querySelector(selector);
const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const badge = (severity) => `<span class="severity severity-${Object.hasOwn(severityRank, severity) ? severity : "Low"}">${escapeHTML(severity)}</span>`;
// Use one consistent India-local display regardless of the computer's timezone.
// Timestamps in stored incident JSON remain timezone-aware and unchanged.
const DISPLAY_TIME_ZONE = "Asia/Kolkata";
const formatDate = (value) => value ? new Date(value).toLocaleString("en-IN", { timeZone: DISPLAY_TIME_ZONE, month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: true }) : "Not available";
const formatLogTime = (value) => value ? new Date(value).toLocaleString("en-IN", { timeZone: DISPLAY_TIME_ZONE, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true }) : "Not available";
// History date filters must use the same local calendar date as the UI.
function localDateKey(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: DISPLAY_TIME_ZONE, year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(date).filter((part) => part.type !== "literal").map((part) => [part.type, part.value]));
  return `${parts.year}-${parts.month}-${parts.day}`;
}
const byteCount = (value) => new TextEncoder().encode(value).length;
const incidentURL = (id) => `/api/incidents/${encodeURIComponent(id)}`;

async function api(url, options = {}) {
  let response;
  try { response = await fetch(url, options); }
  catch { throw new Error("Cannot reach Flask. Check that the application is running, then try again."); }
  let data;
  try { data = await response.json(); }
  catch { throw new Error("The server returned an unreadable response. Please try again."); }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function notice(selector, message) {
  const element = $(selector);
  element.textContent = message;
  element.classList.toggle("hidden", !message);
}

let toastTimer;
function toast(message) {
  notice("#toast", message);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => notice("#toast", ""), 4500);
}

function emptyState(title, description, action = true) {
  return `<div class="empty-state"><span class="empty-icon">${icon("file")}</span><h3>${escapeHTML(title)}</h3><p>${escapeHTML(description)}</p>${action ? '<a href="#analyze" class="text-link">Analyze your first incident <span>→</span></a>' : ""}</div>`;
}

function statsHTML(incidents) {
  const values = [incidents.length, incidents.filter((item) => item.severity === "Critical").length, incidents.filter((item) => item.severity === "High").length, incidents.slice(0, 5).reduce((sum, item) => sum + item.total_error_lines, 0)];
  const labels = ["Total incidents analyzed", "Critical incidents", "High-severity incidents", "Errors in recent analyses"];
  const sampleCount = incidents.filter((item) => item.is_sample).length;
  const notes = [sampleCount ? `${sampleCount} labelled sample reports included` : "Saved in this workspace", "Preliminary severity", "Preliminary severity", "Across the latest 5 reports"];
  return values.map((value, index) => `<div class="stat-card ${["total", "critical", "high", "errors"][index]}"><div class="stat-top"><span>${labels[index]}</span><div class="stat-icon">${icon(["file", "alert", "clock", "scan"][index])}</div></div><div class="stat-value">${value.toLocaleString()}</div><div class="stat-note"><span class="note-dot">•</span>${notes[index]}</div></div>`).join("");
}

function incidentRows(incidents, full = false) {
  return `<div class="table-wrap"><table><thead><tr><th>Incident</th>${full ? "<th>Service</th>" : ""}<th>Severity</th><th>Created</th>${full ? "<th>Mode</th><th>Actions</th>" : "<th></th>"}</tr></thead><tbody>${incidents.map((item) => `<tr><td><a href="#report/${encodeURIComponent(item.id)}"><strong>${escapeHTML(item.title)}</strong><small class="incident-link">${escapeHTML(item.id)}${item.is_sample ? " · SAMPLE" : ""}</small></a></td>${full ? `<td>${escapeHTML(item.service)}</td>` : ""}<td>${badge(item.severity)}</td><td>${escapeHTML(formatDate(item.created_at))}</td>${full ? `<td><span class="mode-label">${escapeHTML(item.analysis_mode)}</span></td><td><div class="actions"><a class="button subtle small" href="#report/${encodeURIComponent(item.id)}">Open</a><button class="icon-button" data-download="${escapeHTML(item.id)}" aria-label="Download ${escapeHTML(item.id)}">${icon("download")}</button><button class="text-link delete-button" data-delete="${escapeHTML(item.id)}">Delete</button></div></td>` : `<td><a href="#report/${encodeURIComponent(item.id)}" class="text-link" aria-label="Open ${escapeHTML(item.id)}">${icon("arrow")}</a></td>`}</tr>`).join("")}</tbody></table></div>`;
}

function drawChart(id, counts, type = "doughnut") {
  if (state.charts[id]) { state.charts[id].destroy(); delete state.charts[id]; }
  const canvas = document.getElementById(id);
  if (!canvas) return;
  const entries = Object.entries(counts).filter(([, count]) => count > 0);
  if (!entries.length) { canvas.classList.add("hidden"); return; }
  canvas.classList.remove("hidden");
  if (typeof Chart === "undefined") {
    canvas.classList.add("hidden");
    const fallback = document.createElement("p");
    fallback.className = "chart-fallback";
    fallback.textContent = "Chart.js could not load from the CDN. " + entries.map(([name, count]) => `${name}: ${count}`).join(" · ");
    canvas.parentElement.appendChild(fallback);
    return;
  }
  state.charts[id] = new Chart(canvas, {
    type,
    data: { labels: entries.map(([name]) => name), datasets: [{ data: entries.map(([, count]) => count), backgroundColor: colors, borderWidth: type === "doughnut" ? 5 : 0, borderColor: "#fff", hoverOffset: 4, borderRadius: type === "doughnut" ? 6 : 5 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "74%", plugins: { legend: { display: false }, tooltip: { padding: 12, backgroundColor: "#28334a" } }, ...(type === "bar" ? { scales: { y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#f1f2f7" } }, x: { grid: { display: false }, ticks: { font: { size: 9 } } } } } : {}) }
  });
}

function renderActivity() {
  const savedEvents = state.incidents.slice(0, 5).map((item) => ({ title: `${item.is_sample ? "Sample analysis" : "Analysis"} saved · ${item.id}`, detail: `${item.severity} suggestion · ${item.analysis_mode}`, time: item.created_at }));
  const events = [...state.events, ...savedEvents].sort((a, b) => b.time.localeCompare(a.time)).slice(0, 5);
  $("#activity-feed").innerHTML = events.length ? events.map((item) => `<div class="activity-item"><span class="event-dot"></span><div><p>${escapeHTML(item.title)}</p><small>${escapeHTML(item.detail)} · ${escapeHTML(formatDate(item.time))}</small></div></div>`).join("") : `<div class="activity-empty">${icon("clock")}<div><strong>Your story starts here</strong><p>Analyze some logs to see real workspace activity. Saved analyses stay in this feed; other actions appear during this session.</p></div></div>`;
}

function renderOverview() {
  $("#overview-stats").innerHTML = statsHTML(state.incidents);
  $("#recent-incidents").innerHTML = state.incidents.length ? incidentRows(state.incidents.slice(0, 4)) : emptyState("A clean slate. A clear view.", "No incidents analyzed yet. Bring your first log file and we'll help connect the dots.");
  const counts = {};
  for (const incident of state.incidents) {
    for (const [signal, count] of Object.entries(incident.signal_counts)) counts[signal] = (counts[signal] || 0) + count;
    const other = incident.error_patterns.filter((item) => item.signals.includes("Other errors")).reduce((sum, item) => sum + item.count, 0);
    counts["Other errors"] = (counts["Other errors"] || 0) + other;
  }
  const entries = Object.entries(counts).filter(([, count]) => count > 0);
  $("#chart-empty").classList.toggle("hidden", entries.length > 0);
  $("#chart-legend").innerHTML = entries.map(([name, count], index) => `<span class="legend-item"><i class="legend-dot" style="background:${colors[index % colors.length]}"></i>${escapeHTML(name)} (${count})</span>`).join("");
  $("#overview-chart").parentElement.querySelectorAll(".chart-fallback").forEach((element) => element.remove());
  drawChart("overview-chart", counts);
  renderActivity();
}

function renderHistory() {
  if (state.historyError) {
    $("#history-stats").innerHTML = "";
    $("#history-content").innerHTML = `<div class="notice danger inline-error">${escapeHTML(state.historyError)}</div>`;
    return;
  }
  $("#history-stats").innerHTML = statsHTML(state.incidents);
  const query = $("#history-query").value.trim().toLowerCase();
  const severity = $("#severity-filter").value;
  const from = $("#date-from").value;
  const to = $("#date-to").value;
  if (from && to && from > to) {
    $("#history-content").innerHTML = '<div class="notice danger inline-error">The start date must be on or before the end date.</div>';
    return;
  }
  const incidents = state.incidents.filter((item) => {
    const haystack = [item.id, item.title, item.service, ...item.error_patterns.map((pattern) => pattern.pattern)].join(" ").toLowerCase();
    const date = localDateKey(item.created_at);
    return (!query || haystack.includes(query)) && (!severity || severity === item.severity) && (!from || date >= from) && (!to || date <= to);
  });
  const order = $("#history-sort").value;
  incidents.sort((a, b) => order === "severity" ? severityRank[a.severity] - severityRank[b.severity] || b.created_at.localeCompare(a.created_at) : order === "oldest" ? a.created_at.localeCompare(b.created_at) : b.created_at.localeCompare(a.created_at));
  $("#history-content").innerHTML = incidents.length ? incidentRows(incidents, true) + `<div class="table-count">${incidents.length} of ${state.incidents.length} saved reports · Date filters use local calendar dates · Sample analyses are included and labelled</div>` : emptyState(state.incidents.length ? "No matching incidents" : "Your incident history starts here", state.incidents.length ? "Try a different search, severity, or date range." : "Every completed analysis is saved automatically so you can return to the evidence.", !state.incidents.length);
}

function renderReports() {
  const exportLabel = document.querySelector("#view-reports .small-tag");
  if (exportLabel) exportLabel.textContent = "PDF exports";
  $("#saved-reports").innerHTML = state.incidents.length ? state.incidents.map((item) => `<section class="card report-tile"><div class="tile-top"><span class="tile-icon">${icon("file")}</span>${badge(item.severity)}</div><small>${escapeHTML(item.id)}${item.is_sample ? " · SAMPLE DATA" : ""}</small><h2>${escapeHTML(item.title)}</h2><p>${escapeHTML(formatDate(item.created_at))}<br>${item.total_error_lines} error lines · ${escapeHTML(item.analysis_mode)}</p><div class="actions"><a class="text-link" href="#report/${encodeURIComponent(item.id)}">Open report →</a><button class="button subtle small" data-download="${escapeHTML(item.id)}">${icon("download")}PDF</button></div></section>`).join("") : `<section class="card">${emptyState("Your reports, ready to revisit", "Analyze a log to create a complete report with patterns, evidence, and diagnostic guidance.")}</section>`;
}

function listHTML(items, ordered = false) {
  const tag = ordered ? "ol" : "ul";
  return `<${tag}>${items.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</${tag}>`;
}

// These small HTML helpers keep report sections easy to read and change.
// Dynamic values are escaped before being inserted into any HTML template.
function reportSection(title, content) {
  return `<section class="card report-section"><h2>${title}</h2>${content}</section>`;
}

function analysisSourceHTML(report) {
  const ai = report.analysis_mode === "AI-assisted" && report.ai_guidance;
  if (ai) return `
    <section class="card report-section report-full">
      <h2>Analysis methodology & limitations <span class="small-tag">AI-Analyzed</span></h2>
      <p>AI generated the incident narrative using the supplied log evidence. The log parser independently calculated the counts, error patterns, timestamps, and preliminary severity. Supporting evidence is listed in this report.</p>
      <p class="limitation">${escapeHTML(report.ai_guidance.limitations)} The root-cause hypotheses require verification through system metrics and further diagnostics.</p>
    </section>`;
  return `<section class="card report-section report-full">
    <h2>Analysis methodology & limitations <span class="small-tag">Local rules only</span></h2>
    <p>No model-generated narrative was saved for this incident. The fallback findings above come from predefined log-analysis rules.</p>
    <p class="limitation">${escapeHTML(report.confidence_limitations)}</p>
  </section>`;
}

function patternsHTML(report) {
  const rows = report.error_patterns.map((pattern) => `
    <tr>
      <td class="pattern-message">${escapeHTML(pattern.pattern)}</td>
      <td>${pattern.count}</td>
      <td>${escapeHTML(formatLogTime(pattern.first_occurrence))}</td>
      <td>${escapeHTML(formatLogTime(pattern.last_occurrence))}</td>
    </tr>`).join("");
  const table = rows ? `
    <div class="table-wrap">
      <table class="patterns-table">
        <thead><tr><th>Error pattern (redacted)</th><th>Count</th><th>First occurrence</th><th>Last occurrence</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>` : emptyState("No recognized error patterns", "Review the source format and service metrics if symptoms persist.", false);
  return `
    <section class="card report-full">
      <div class="card-heading"><div>
        <h2>Error patterns</h2>
        <p>Times are displayed in local time. Entries without a timezone follow the parser's documented assumption.
        Changing IDs and numbers are normalized; HTTP status codes are preserved.</p>
      </div></div>
      ${table}
    </section>`;
}

function renderReport(report) {
  const range = report.time_range;
  const timeRangeHTML = range.start
    ? `${escapeHTML(formatLogTime(range.start))}<br>→ ${escapeHTML(formatLogTime(range.end))}`
    : "No recognized timestamps";
  const warningHTML = report.warnings.map((warning) => `<div class="notice warning">${escapeHTML(warning)}</div>`).join("");
  const ai = report.analysis_mode === "AI-assisted" && report.ai_guidance ? report.ai_guidance : null;
  const extension = ai && report.ai_extensions ? report.ai_extensions : {};
  const aiTag = ai ? ' <span class="small-tag">AI-Analyzed</span>' : ' <span class="small-tag">Local rules</span>';
  const oldModelNote = "This field was not captured in the earlier AI response. Run AI analysis again to generate it.";
  const summary = `<p>${escapeHTML(ai ? ai.summary : report.summary)}</p>`;
  const causes = `${listHTML(ai ? ai.hypotheses : report.likely_causes)}<p class="limitation">These are possible explanations, not a confirmed root cause. Correlate with service metrics.</p>`;
  const impact = `<p>${escapeHTML(ai ? extension.impact_assessment || oldModelNote : report.potential_impact)}</p><p class="limitation">Business/customer impact must be confirmed using monitoring and operations data.</p>`;
  const escalation = `<p>${escapeHTML(ai ? extension.escalation_guidance || oldModelNote : report.escalation.team + ": " + report.escalation.reason)}</p><p class="limitation">Confirm ownership and urgency using your team's incident process.</p>`;
  const steps = ai ? ai.diagnostic_checks : report.recommended_steps;

  $("#report-content").innerHTML = `
    <div class="page-heading report-heading">
      <div>
        <div class="eyebrow"><a href="#history">← INCIDENT HISTORY</a><span>/</span>${escapeHTML(report.id)}</div>
        <h1>${escapeHTML(report.title)}</h1>
        <p>${escapeHTML(formatDate(report.created_at))} · ${escapeHTML(report.service)}</p>
      </div>
      <div class="report-actions">
        ${badge(report.severity)}
        <button class="button primary" data-download="${escapeHTML(report.id)}">${icon("download")}Download PDF Report</button>
      </div>
    </div>
    <div class="report-source">
      <span class="small-tag">${ai ? "AI-Analyzed" : "Local rules only"}</span>
      ${report.is_sample ? '<span class="small-tag">SAMPLE DATA · fictional incident</span>' : ""}
      <span class="mode-label">Parser metrics · preliminary severity</span>
    </div>
    ${warningHTML}
    <div class="notice info">
      <strong>${escapeHTML(report.severity)} — preliminary suggestion.</strong>
      ${escapeHTML(report.severity_rationale)} ${escapeHTML(report.severity_notice)}
    </div>
    <div class="report-metrics">
      <section class="card report-metric">
        <span>Total error lines</span><strong>${report.total_error_lines}</strong>
        <p class="report-subtitle">of ${report.total_lines} non-empty lines</p>
      </section>
      <section class="card report-metric">
        <span>Unique error patterns</span><strong>${report.unique_error_patterns}</strong>
        <p class="report-subtitle">Normalized by the log parser</p>
      </section>
      <section class="card report-metric time">
        <span>Observed time range</span><strong>${timeRangeHTML}</strong>
      </section>
    </div>
    <div class="report-grid">
      ${reportSection("Incident summary" + aiTag, summary)}
      ${reportSection('Observed log evidence <span class="small-tag">Parser-extracted facts</span>', listHTML(report.observed_evidence))}
      ${reportSection('Root-cause hypotheses' + aiTag, causes)}
      ${reportSection("Potential impact" + aiTag, impact)}
      ${reportSection("Recommended diagnostic checks" + aiTag, listHTML(steps, true))}
      ${reportSection("Escalation guidance" + aiTag, escalation)}
    </div>
    ${analysisSourceHTML(report)}
    ${chatHTML(report)}
    ${patternsHTML(report)}
    <section class="card report-full">
      <div class="card-heading"><div>
        <h2>Error signal distribution</h2>
        <p>A line can match more than one signal. Categories may overlap.</p>
      </div></div>
      <div class="chart-wrap">
        <canvas id="report-chart" role="img" aria-label="Error signal counts for this report"></canvas>
        ${report.total_error_lines ? "" : '<p class="chart-fallback">No recognized errors to chart.</p>'}
      </div>
    </section>`;

  const counts = { ...report.signal_counts };
  counts["Other errors"] = report.error_patterns
    .filter((pattern) => pattern.signals.includes("Other errors"))
    .reduce((sum, pattern) => sum + pattern.count, 0);
  drawChart("report-chart", counts, "bar");
  renderChatHistory(report.id);
}

// Follow-up conversation lives in browser memory only, never in the saved report.
// The backend sends Gemini the incident's redacted parser facts, not raw logs.
const chatExamples = ["Which errors appeared first?", "Why might the database pool be exhausted?", "What evidence supports the suspected cause?", "What should support investigate next?"];

function addChatStyles() {
  if (document.getElementById("incident-chat-css")) return;
  const style = document.createElement("style");
  style.id = "incident-chat-css";
  style.textContent = `
    .chat-card{margin-top:24px}.chat-head{display:flex;justify-content:space-between;gap:15px;align-items:flex-start;margin-bottom:10px}
    .chat-head h2{margin:0 0 6px}.chat-head p,.chat-note{color:#79839a;font-size:13px;line-height:1.6;margin:0}
    .chat-examples{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0}.chat-example{background:#f1f0ff;color:#5347b8;border:1px solid #dedafb;border-radius:22px;padding:8px 13px;font-size:12px}
    .chat-messages{display:flex;flex-direction:column;gap:14px;max-height:440px;overflow-y:auto;padding:14px;background:#f8f9fc;border:1px solid #e7eaf2;border-radius:12px;margin-bottom:16px}
    .chat-item{max-width:91%;padding:12px 14px;border-radius:12px;font-size:13px;line-height:1.7;white-space:pre-wrap;word-break:break-word}
    .chat-item.user{align-self:flex-end;background:#6758e8;color:white}.chat-item.assistant{align-self:flex-start;background:white;border:1px solid #e2e6f0;color:#26334a}
    .chat-item strong{display:block;margin-bottom:4px;font-size:12px}.chat-source{display:block;background:#f5f4ff;border:1px solid #ebe8ff;border-radius:8px;padding:7px 9px;margin-top:7px;font-size:12px;white-space:normal}
    .chat-uncertainty{color:#7255a4;font-size:12px;margin-top:8px}.chat-form{display:flex;align-items:flex-end;gap:10px;margin-top:12px}
    .chat-form textarea{flex:1;min-height:58px;resize:vertical;border:1px solid #dfe4ee;border-radius:10px;padding:10px 13px;color:#213048;background:white;width:100%;font:inherit}
    .chat-form button{align-self:stretch;min-width:90px}.chat-empty{font-size:13px;color:#7b859c;margin:4px 0}
    .chat-status{font-size:12px;color:#606c84;margin:8px 0}.chat-clear{font-size:12px;border:0;background:transparent;color:#6b62bf;text-decoration:underline;padding:4px}
    @media(max-width:680px){.chat-head{flex-direction:column}.chat-form{flex-direction:column}.chat-form button{width:100%}}
  `;
  document.head.appendChild(style);
}

function chatHTML(report) {
  addChatStyles();
  const canAsk = state.health?.ai_provider === "Google Gemini" && state.health?.api_key_configured;
  return `<section class="card report-full chat-card" id="incident-chat" data-incident="${escapeHTML(report.id)}">
    <div class="chat-head"><div><h2>Ask AI About This Incident <span class="small-tag">Evidence-grounded</span></h2>
      <p>Ask follow-up questions about this incident's saved error patterns, timestamps and parser facts.</p></div>
      <button type="button" class="chat-clear" data-chat-clear="${escapeHTML(report.id)}">Clear conversation</button></div>
    ${canAsk ? `<div class="chat-examples">${chatExamples.map((q) => `<button type="button" class="chat-example" data-chat-example="${escapeHTML(q)}">${escapeHTML(q)}</button>`).join("")}</div>` :
      '<div class="notice info">Follow-up AI chat requires Gemini to be configured as the active provider.</div>'}
    <div class="chat-messages" id="chat-messages" aria-live="polite"></div>
    <form class="chat-form" id="incident-chat-form" data-incident="${escapeHTML(report.id)}">
      <textarea id="chat-question" maxlength="400" rows="2" aria-label="Ask a question about this incident" placeholder="Ask which errors happened first, possible causes, or what to check next..." ${canAsk ? "" : "disabled"} required></textarea>
      <button class="button primary" id="chat-send" type="submit" ${canAsk ? "" : "disabled"}>Ask AI</button>
    </form><p id="chat-status" class="chat-status" role="status"></p>
    <p class="chat-note">Answers use saved parsed log evidence, not full original logs. Citations reference saved error patterns or parser facts. AI hypotheses are not confirmed root causes. Chat is cleared on page reload.</p>
  </section>`;
}

function renderChatHistory(id) {
  const pane = document.querySelector('#incident-chat[data-incident="' + CSS.escape(id) + '"]');
  if (!pane) return;
  const messages = state.chatHistory[id] || [];
  const holder = pane.querySelector("#chat-messages");
  holder.innerHTML = messages.length ? messages.map((m) => m.role === "user"
    ? `<div class="chat-item user"><strong>You</strong>${escapeHTML(m.content)}</div>`
    : `<div class="chat-item assistant"><strong>AI Analysis</strong>${escapeHTML(m.content)}
      ${(m.sources || []).map((s) => `<span class="chat-source"><strong>${escapeHTML(s.id)} · ${escapeHTML(s.kind)}</strong>${escapeHTML(s.detail)}</span>`).join("")}
      ${m.uncertainty ? `<div class="chat-uncertainty">Limitation: ${escapeHTML(m.uncertainty)}</div>` : ""}</div>`).join("")
    : '<p class="chat-empty">No questions yet. Try one of the examples or type your own question.</p>';
  holder.scrollTop = holder.scrollHeight;
}

async function askAIForIncident(form) {
  const id = form.dataset.incident;
  const textarea = form.querySelector("#chat-question");
  const question = textarea.value.trim();
  const existing = state.chatHistory[id] || [];
  const status = document.getElementById("chat-status");
  const button = form.querySelector("#chat-send");
  if (button.disabled || question.length < 5 || question.length > 400) {
    status.textContent = "Enter a question between 5 and 400 characters.";
    return;
  }
  const history = existing.slice(-6).map((m) => ({ role: m.role, content: m.content.slice(0, 1200) }));
  existing.push({ role: "user", content: question });
  state.chatHistory[id] = existing;
  textarea.value = "";
  renderChatHistory(id);
  status.textContent = "Reviewing saved evidence with AI...";
  button.disabled = true;
  try {
    const answer = await api(`${incidentURL(id)}/ask`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({question, history})});
    existing.push({role: "assistant", content: answer.answer, sources: answer.sources || [], uncertainty: answer.uncertainty});
    status.textContent = "Answer generated from saved incident evidence.";
  } catch (error) {
    // Never fake an AI response if the API is unavailable.
    existing.pop();
    textarea.value = question;
    status.textContent = error.message;
  } finally {
    button.disabled = false;
    renderChatHistory(id);
  }
}

document.addEventListener("submit", (event) => {
  if (event.target.id === "incident-chat-form") {
    event.preventDefault();
    askAIForIncident(event.target);
  }
});
document.addEventListener("click", (event) => {
  const sample = event.target.closest("[data-chat-example]");
  if (sample) {
    const form = document.getElementById("incident-chat-form");
    if (form && !form.querySelector("#chat-send").disabled) {
      form.querySelector("#chat-question").value = sample.dataset.chatExample;
      form.requestSubmit();
    }
  }
  const clear = event.target.closest("[data-chat-clear]");
  if (clear) {
    state.chatHistory[clear.dataset.chatClear] = [];
    renderChatHistory(clear.dataset.chatClear);
    const status = document.getElementById("chat-status");
    if (status) status.textContent = "Conversation cleared from this browser session.";
  }
});

async function loadIncidents() {
  const result = await api("/api/incidents");
  state.incidents = result.incidents;
  state.historyError = "";
}

async function route() {
  const currentRoute = ++state.route;
  const [pageName = "overview", id] = location.hash.slice(1).split("/");
  const page = ["overview", "analyze", "history", "reports", "settings", "report"].includes(pageName) ? pageName : "overview";
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("hidden", view.id !== `view-${page}`));
  document.querySelectorAll("[data-nav]").forEach((link) => {
    const active = link.dataset.nav === (page === "report" ? "history" : page);
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
  $("#sidebar").classList.remove("open");
  $("#menu-toggle").setAttribute("aria-expanded", "false");
  $("#breadcrumb").textContent = { overview: "Overview", analyze: "Analyze Logs", history: "Incident History", reports: "Saved Reports", settings: "Settings", report: "Incident Report" }[page];
  document.title = `${$("#breadcrumb").textContent} · PineOps AI`;
  notice("#page-error", "");
  window.scrollTo(0, 0);
  try {
    if (["overview", "history", "reports"].includes(page)) {
      const target = { overview: "#recent-incidents", history: "#history-content", reports: "#saved-reports" }[page];
      $(target).innerHTML = '<div class="loading" role="status">Loading saved incidents…</div>';
      await loadIncidents();
      if (currentRoute !== state.route) return;
      if (page === "overview") renderOverview();
      if (page === "history") renderHistory();
      if (page === "reports") renderReports();
    } else if (page === "report") {
      $("#report-content").innerHTML = '<div class="loading" role="status">Opening report…</div>';
      const report = await api(incidentURL(id || "unknown"));
      if (currentRoute !== state.route) return;
      renderReport(report);
    } else if (page === "settings") {
      const config = await api("/api/health");
      if (currentRoute !== state.route) return;
      const settings = { Application: `${config.name} ${config.version}`, "AI provider": config.ai_provider, "Configured model": config.model, "API key": config.api_key_configured ? "Configured (not verified)" : "Not configured · rule-based fallback", "Maximum log size": `${(config.max_log_bytes / 1024).toFixed(0)} KB`, Storage: "Local JSON file · single-user workspace" };
      $("#settings-details").innerHTML = Object.entries(settings).map(([key, value]) => `<div><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("");
    }
  } catch (error) {
    if (currentRoute !== state.route) return;
    notice("#page-error", `${error.message} Reload the page to retry.`);
    if (["overview", "history", "reports"].includes(page)) {
      state.historyError = error.message;
      state.incidents = [];
    }
    document.querySelectorAll(".loading").forEach((element) => { element.textContent = "Unable to load this view."; });
    if (page === "overview") {
      $("#overview-stats").innerHTML = "";
      $("#overview-chart").classList.add("hidden");
      $("#chart-empty").classList.remove("hidden");
      $("#chart-legend").innerHTML = "";
      $("#overview-chart").parentElement.querySelectorAll(".chart-fallback").forEach((element) => element.remove());
      $("#chart-empty").innerHTML = '<strong>History unavailable</strong><span>Restore access to saved reports to view metrics.</span>';
      $("#activity-feed").textContent = "Saved activity is unavailable while history cannot be read.";
    }
    if (page === "history") $("#history-stats").innerHTML = "";
  }
}

function updateInputSize() { $("#input-size").textContent = `${byteCount($("#log-text").value).toLocaleString()} bytes`; }

async function selectFile(file) {
  notice("#analysis-error", "");
  if (!file) return;
  const limit = state.health?.max_log_bytes || 204800;
  if (!/\.(log|txt)$/i.test(file.name)) { notice("#analysis-error", "Choose a .log or .txt file."); return; }
  if (file.size > limit) { notice("#analysis-error", `File is too large. Maximum size is ${Math.floor(limit / 1024)} KB.`); return; }
  try {
    const logs = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
    if (!logs.trim() || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(logs)) throw new Error("Choose a non-empty UTF-8 log file without binary content.");
    $("#log-text").value = logs;
    $("#file-name").textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB · contents loaded below`;
    state.sample = logs.includes("# SAMPLE DATA");
    $("#sample-notice").classList.toggle("hidden", !state.sample);
    updateInputSize();
  } catch (error) { notice("#analysis-error", error.message.includes("UTF-8") ? error.message : "Unable to read this file as UTF-8 text."); }
  finally { $("#log-file").value = ""; }
}

$("#analysis-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  notice("#analysis-error", "");
  const logs = $("#log-text").value;
  if (!logs.trim()) { notice("#analysis-error", "Paste logs or choose a file before analyzing."); return; }
  const limit = state.health?.max_log_bytes || 204800;
  if (byteCount(logs) > limit) { notice("#analysis-error", `Logs exceed the ${Math.floor(limit / 1024)} KB limit. Shorten the incident window.`); return; }
  const button = $("#analyze-button");
  button.disabled = true;
  button.innerHTML = `${icon("clock")}Analyzing…`;
  $("#analysis-progress").classList.remove("hidden");
  try {
    const report = await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ logs, is_sample: state.sample }) });
    location.hash = `report/${report.id}`;
    toast("Analysis complete. Your report has been saved.");
  } catch (error) { notice("#analysis-error", error.message); }
  finally { button.disabled = false; button.innerHTML = `${icon("scan")}Analyze Incident`; $("#analysis-progress").classList.add("hidden"); }
});

$("#log-file").addEventListener("change", (event) => selectFile(event.target.files[0]));
$("#log-text").addEventListener("input", () => { state.sample = $("#log-text").value.includes("# SAMPLE DATA"); $("#sample-notice").classList.toggle("hidden", !state.sample); updateInputSize(); });
$("#clear-input").addEventListener("click", () => { $("#log-text").value = ""; $("#log-file").value = ""; $("#file-name").textContent = ""; state.sample = false; $("#sample-notice").classList.add("hidden"); notice("#analysis-error", ""); updateInputSize(); });
for (const eventName of ["dragenter", "dragover"]) $("#upload-zone").addEventListener(eventName, (event) => { event.preventDefault(); $("#upload-zone").classList.add("dragging"); });
$("#upload-zone").addEventListener("dragleave", () => $("#upload-zone").classList.remove("dragging"));
$("#upload-zone").addEventListener("drop", (event) => { event.preventDefault(); $("#upload-zone").classList.remove("dragging"); if (event.dataTransfer.files.length !== 1) { notice("#analysis-error", "Choose one log file at a time."); return; } selectFile(event.dataTransfer.files[0]); });

document.querySelectorAll("[data-sample]").forEach((button) => button.addEventListener("click", async () => {
  button.disabled = true;
  notice("#analysis-error", "");
  try { const sample = await api(`/api/samples/${button.dataset.sample}`); $("#log-text").value = sample.logs; $("#file-name").textContent = ""; $("#log-file").value = ""; state.sample = true; $("#sample-notice").classList.remove("hidden"); updateInputSize(); }
  catch (error) { notice("#analysis-error", error.message); }
  finally { button.disabled = false; }
}));

$("#history-filters").addEventListener("submit", (event) => event.preventDefault());
$("#history-filters").addEventListener("input", renderHistory);
$("#history-filters").addEventListener("change", renderHistory);
$("#history-filters").addEventListener("reset", () => setTimeout(renderHistory, 0));
$("#global-search").addEventListener("submit", (event) => { event.preventDefault(); $("#history-query").value = $("#global-query").value; if (location.hash === "#history") renderHistory(); else location.hash = "history"; });
$("#menu-toggle").addEventListener("click", () => { const open = $("#sidebar").classList.toggle("open"); $("#menu-toggle").setAttribute("aria-expanded", String(open)); });
$("#notifications").addEventListener("click", () => { if (location.hash === "#overview" || !location.hash) $("#activity-feed").scrollIntoView({ behavior: "smooth", block: "center" }); else { location.hash = "overview"; setTimeout(() => $("#activity-feed").scrollIntoView({ behavior: "smooth", block: "center" }), 350); } });

async function downloadReport(id) {
  let response;
  try { response = await fetch(`${incidentURL(id)}/pdf`, { cache: "no-store" }); }
  catch { throw new Error("Cannot reach the PDF server. Check that Flask is running."); }
  if (!response.ok) {
    let message = `PDF download failed (HTTP ${response.status}).`;
    try { const info = await response.json(); message = info.error || message; } catch { /* non-JSON error */ }
    throw new Error(message);
  }
  if (!(response.headers.get("content-type") || "").includes("application/pdf")) {
    throw new Error("Server returned something other than a PDF. Install requirements.txt and restart Flask.");
  }
  const blob = await response.blob();
  if (blob.size < 100 || !blob.type.includes("pdf")) throw new Error("PDF report was empty or invalid.");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `PineOpsAI_${id}_Report.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  state.events.unshift({ title: `Report downloaded · ${id}`, detail: "Two-page PDF export · this session", time: new Date().toISOString() });
  toast("Two-page PDF report downloaded.");
}

document.addEventListener("click", async (event) => {
  const download = event.target.closest("[data-download]");
  if (download) { try { download.disabled = true; await downloadReport(download.dataset.download); } catch (error) { toast(error.message); } finally { download.disabled = false; } }
  const remove = event.target.closest("[data-delete]");
  if (remove) { state.deleteId = remove.dataset.delete; $("#delete-incident-name").textContent = state.deleteId; notice("#delete-error", ""); $("#delete-dialog").showModal(); }
});
$("#cancel-delete").addEventListener("click", () => $("#delete-dialog").close());
$("#confirm-delete").addEventListener("click", async () => {
  const button = $("#confirm-delete"); button.disabled = true;
  try {
    await api(incidentURL(state.deleteId), { method: "DELETE" });
    delete state.chatHistory[state.deleteId];
    state.events.unshift({ title: `Incident deleted · ${state.deleteId}`, detail: "Removed from saved history · this session", time: new Date().toISOString() });
    $("#delete-dialog").close(); toast("Incident deleted."); await route();
  } catch (error) { notice("#delete-error", error.message); }
  finally { button.disabled = false; }
});

window.addEventListener("hashchange", route);
async function initialize() {
  try { state.health = await api("/api/health"); $("#upload-help").textContent = `UTF-8 .log or .txt · Maximum ${Math.floor(state.health.max_log_bytes / 1024)} KB`; }
  catch (error) { toast(error.message); }
  await route();
}
initialize();
