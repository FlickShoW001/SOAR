const state = { data: null, query: "", reviewing: new Set(), loadSequence: 0, controller: null };
const canReview = ["admin", "operator"].includes(document.body.dataset.role);
const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => {
  const node = document.createElement("div");
  node.textContent = String(value ?? "");
  return node.innerHTML;
};
const matches = (...values) => !state.query || values.some((value) => String(value ?? "").toLowerCase().includes(state.query));
const formatDate = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();
};
const formatNumber = (value, digits = 1) => value == null || !Number.isFinite(Number(value)) ? "—" : Number(value).toFixed(digits);
const formatPercent = (value) => value == null || !Number.isFinite(Number(value)) ? "—" : `${Math.round(Number(value) * 100)}%`;

function severityLabel(value) {
  const level = Number(value);
  if (level >= 4) return ["High", "high"];
  if (level === 3) return ["Medium", "medium"];
  return ["Low", "low"];
}

function renderEvents(items) {
  const rows = items.filter((item) => matches(item.id, item.source_ip, item.event_type, item.status));
  byId("event-count").textContent = items.length;
  byId("events-body").innerHTML = rows.length ? rows.map((event) => {
    const [severity, severityClass] = severityLabel(event.severity);
    return `<tr>
      <td><button class="event-link" data-event-id="${event.id}">#${event.id}</button></td>
      <td class="event-source"><strong>${escapeHtml(event.source_ip)}</strong><small>${escapeHtml(formatDate(event.timestamp))}</small></td>
      <td>${escapeHtml(String(event.event_type ?? "Unknown").replaceAll("_", " "))}</td>
      <td><span class="severity ${severityClass}">${severity} · ${event.severity}</span></td>
      <td><span class="badge badge-${escapeHtml(event.status)}">${escapeHtml(String(event.status ?? "unknown").replaceAll("_", " "))}</span></td>
    </tr>`;
  }).join("") : '<tr><td colspan="5" class="empty-state">No matching events.</td></tr>';
}

function renderPending(items) {
  const rows = items.filter((item) => matches(item.id, item.source_ip, item.event_type, item.status));
  byId("pending-count").textContent = items.length;
  byId("pending-pill").textContent = items.length;
  byId("pending-body").innerHTML = rows.length ? rows.map((event) => {
    const [severity, severityClass] = severityLabel(event.severity);
    return `<tr>
      <td><button class="event-link" data-event-id="${event.id}">#${event.id}</button></td>
      <td class="event-source"><strong>${escapeHtml(event.source_ip)}</strong><small>External source</small></td>
      <td>${escapeHtml(String(event.event_type ?? "Unknown").replaceAll("_", " "))}</td>
      <td><span class="severity ${severityClass}">${severity} · ${event.severity}</span></td>
      <td><span class="badge badge-${escapeHtml(event.status)}">${escapeHtml(String(event.status ?? "unknown").replaceAll("_", " "))}</span></td>
      <td>${canReview ? `<div class="action-group"><button class="action-button approve" data-approve="${event.id}" ${state.reviewing.has(String(event.id)) ? "disabled" : ""}>Approve</button><button class="action-button reject" data-reject="${event.id}" ${state.reviewing.has(String(event.id)) ? "disabled" : ""}>Reject</button></div>` : '<span class="badge">View only</span>'}</td>
    </tr>`;
  }).join("") : '<tr><td colspan="6" class="empty-state">No matching approvals.</td></tr>';
}

function renderDecisions(items) {
  const rows = items.filter((item) => matches(item.event_id, item.action, item.risk_score));
  byId("decision-count").textContent = items.length;
  byId("decisions-body").innerHTML = rows.length ? rows.map((decision) => `<tr>
    <td><button class="event-link" data-event-id="${decision.event_id}">#${decision.event_id}</button></td>
    <td><span class="badge badge-${escapeHtml(decision.action)}">${escapeHtml(decision.action)}</span></td>
    <td>${formatNumber(decision.risk_score)}</td>
    <td>${formatPercent(decision.confidence)}</td>
    <td>${decision.requires_approval ? "Required" : "Automatic"}</td>
  </tr>`).join("") : '<tr><td colspan="5" class="empty-state">No matching decisions.</td></tr>';
}

function renderAudit(items) {
  const rows = items.filter((item) => matches(item.event_id, item.actor, item.action, item.hash));
  byId("audit-count").textContent = items.length;
  byId("audit-list").innerHTML = rows.length ? rows.map((entry) => `<article class="audit-item">
    <strong>${escapeHtml(entry.action)} · Event #${escapeHtml(entry.event_id)}</strong>
    <p>${escapeHtml(entry.actor)} · ${escapeHtml(formatDate(entry.timestamp))}</p>
    <p><code>${escapeHtml(entry.hash)}</code></p>
  </article>`).join("") : '<p class="empty-state">No matching audit entries.</p>';
}

function render() {
  if (!state.data) return;
  renderEvents(state.data.events ?? []);
  renderPending(state.data.pending ?? []);
  renderDecisions(state.data.decisions ?? []);
  renderAudit(state.data.audit ?? []);
  const valid = state.data.audit_chain_valid;
  byId("chain-status").textContent = valid ? "Chain verified" : "Integrity warning";
  byId("chain-card").classList.toggle("invalid", !valid);
}

function showToast(message) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 2600);
}

function redirectIfUnauthorized(response) {
  if (response.status !== 401) return false;
  window.location.assign("/login");
  return true;
}

async function loadDashboard(showFeedback = false) {
  const sequence = ++state.loadSequence;
  state.controller?.abort();
  state.controller = new AbortController();
  try {
    const response = await fetch("/dashboard/data", {
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal: state.controller.signal
    });
    if (redirectIfUnauthorized(response)) return;
    if (!response.ok) throw new Error(`Dashboard request failed (${response.status})`);
    const data = await response.json();
    if (sequence !== state.loadSequence) return;
    state.data = data;
    render();
    byId("last-sync").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    if (showFeedback) showToast("Dashboard refreshed");
  } catch (error) {
    if (error.name === "AbortError") return;
    byId("last-sync").textContent = "Connection interrupted";
    showToast(error.message);
  }
}

async function reviewEvent(eventId, approved) {
  eventId = String(eventId);
  if (state.reviewing.has(eventId)) return;
  let rejectedReason = null;
  if (approved) {
    if (!window.confirm(`Approve the response for event #${eventId}?`)) return;
  } else {
    rejectedReason = window.prompt(`Why are you rejecting event #${eventId}?`);
    if (rejectedReason === null) return;
  }

  state.reviewing.add(eventId);
  render();
  try {
    const response = await fetch(`/approvals/${eventId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ approved, rejected_reason: rejectedReason })
    });
    if (redirectIfUnauthorized(response)) return;
    const result = await response.json().catch(() => ({}));
    if (!response.ok) return showToast(result.detail || `Review action failed (${response.status})`);
    showToast(approved ? `Event #${eventId} approved` : `Event #${eventId} rejected`);
    await loadDashboard();
  } catch (error) {
    showToast(error.message || "Review action failed");
  } finally {
    state.reviewing.delete(eventId);
    render();
  }
}

async function openEvent(eventId) {
  let data;
  try {
    const response = await fetch(`/events/${eventId}`, { headers: { Accept: "application/json" } });
    if (redirectIfUnauthorized(response)) return;
    if (!response.ok) return showToast(`Could not load event details (${response.status})`);
    data = await response.json();
  } catch (error) {
    return showToast(error.message || "Could not load event details");
  }
  const details = [
    ["Source IP", data.event.source_ip], ["Detection", data.event.event_type],
    ["Severity", data.event.severity], ["Status", data.event.status],
    ["Action", data.decision?.action ?? "Pending"], ["Risk score", formatNumber(data.decision?.risk_score)],
    ["Confidence", formatPercent(data.decision?.confidence)], ["Country", data.enrichment?.country ?? "Unknown"]
  ];
  byId("dialog-title").textContent = `Event #${eventId}`;
  byId("dialog-content").innerHTML = `<div class="detail-grid">${details.map(([label, value]) => `<div class="detail"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`).join("")}</div>`;
  byId("event-dialog").showModal();
}

document.addEventListener("click", (event) => {
  const eventButton = event.target.closest("[data-event-id]");
  const approveButton = event.target.closest("[data-approve]");
  const rejectButton = event.target.closest("[data-reject]");
  if (eventButton) openEvent(eventButton.dataset.eventId);
  if (approveButton) reviewEvent(approveButton.dataset.approve, true);
  if (rejectButton) reviewEvent(rejectButton.dataset.reject, false);
  if (event.target.closest("[data-refresh]")) loadDashboard(true);
  if (event.target.closest("[data-close-dialog]")) byId("event-dialog").close();
});

byId("global-search").addEventListener("input", (event) => {
  state.query = event.target.value.trim().toLowerCase();
  render();
});

loadDashboard();
window.setInterval(loadDashboard, 5000);
