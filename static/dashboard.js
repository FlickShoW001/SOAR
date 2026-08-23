const state = { data: null, query: "" };
const canReview = ["admin", "operator"].includes(document.body.dataset.role);
const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => {
  const node = document.createElement("div");
  node.textContent = String(value ?? "");
  return node.innerHTML;
};
const matches = (...values) => !state.query || values.some((value) => String(value ?? "").toLowerCase().includes(state.query));

function severityLabel(value) {
  const level = Number(value);
  if (level >= 4) return ["High", "high"];
  if (level === 3) return ["Medium", "medium"];
  return ["Low", "low"];
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
      <td>${escapeHtml(event.event_type.replaceAll("_", " "))}</td>
      <td><span class="severity ${severityClass}">${severity} · ${event.severity}</span></td>
      <td><span class="badge badge-${escapeHtml(event.status)}">${escapeHtml(event.status.replaceAll("_", " "))}</span></td>
      <td>${canReview ? `<div class="action-group"><button class="action-button approve" data-approve="${event.id}">Approve</button><button class="action-button reject" data-reject="${event.id}">Reject</button></div>` : '<span class="badge">View only</span>'}</td>
    </tr>`;
  }).join("") : '<tr><td colspan="6" class="empty-state">No matching approvals.</td></tr>';
}

function renderDecisions(items) {
  const rows = items.filter((item) => matches(item.event_id, item.action, item.risk_score));
  byId("decision-count").textContent = items.length;
  byId("decisions-body").innerHTML = rows.length ? rows.map((decision) => `<tr>
    <td><button class="event-link" data-event-id="${decision.event_id}">#${decision.event_id}</button></td>
    <td><span class="badge badge-${escapeHtml(decision.action)}">${escapeHtml(decision.action)}</span></td>
    <td>${Number(decision.risk_score).toFixed(1)}</td>
    <td>${Math.round(Number(decision.confidence) * 100)}%</td>
    <td>${decision.requires_approval ? "Required" : "Automatic"}</td>
  </tr>`).join("") : '<tr><td colspan="5" class="empty-state">No matching decisions.</td></tr>';
}

function renderAudit(items) {
  const rows = items.filter((item) => matches(item.event_id, item.actor, item.action, item.hash));
  byId("audit-count").textContent = items.length;
  byId("audit-list").innerHTML = rows.length ? rows.map((entry) => `<article class="audit-item">
    <strong>${escapeHtml(entry.action)} · Event #${escapeHtml(entry.event_id)}</strong>
    <p>${escapeHtml(entry.actor)} · ${new Date(entry.timestamp + "Z").toLocaleString()}</p>
    <p><code>${escapeHtml(entry.hash)}</code></p>
  </article>`).join("") : '<p class="empty-state">No matching audit entries.</p>';
}

function render() {
  if (!state.data) return;
  renderPending(state.data.pending);
  renderDecisions(state.data.decisions);
  renderAudit(state.data.audit);
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

async function loadDashboard(showFeedback = false) {
  try {
    const response = await fetch("/dashboard/data", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`Dashboard request failed (${response.status})`);
    state.data = await response.json();
    render();
    byId("last-sync").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    if (showFeedback) showToast("Dashboard refreshed");
  } catch (error) {
    byId("last-sync").textContent = "Connection interrupted";
    showToast(error.message);
  }
}

async function reviewEvent(eventId, approved) {
  let rejectedReason = null;
  if (approved) {
    if (!window.confirm(`Approve the response for event #${eventId}?`)) return;
  } else {
    rejectedReason = window.prompt(`Why are you rejecting event #${eventId}?`);
    if (rejectedReason === null) return;
  }

  const response = await fetch(`/approvals/${eventId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approved, rejected_reason: rejectedReason })
  });
  const result = await response.json();
  if (!response.ok) return showToast(result.detail || "Review action failed");
  showToast(approved ? `Event #${eventId} approved` : `Event #${eventId} rejected`);
  await loadDashboard();
}

async function openEvent(eventId) {
  const response = await fetch(`/events/${eventId}`);
  if (!response.ok) return showToast("Could not load event details");
  const data = await response.json();
  const details = [
    ["Source IP", data.event.source_ip], ["Detection", data.event.event_type],
    ["Severity", data.event.severity], ["Status", data.event.status],
    ["Action", data.decision?.action ?? "Pending"], ["Risk score", data.decision?.risk_score?.toFixed(1) ?? "—"],
    ["Confidence", data.decision ? `${Math.round(data.decision.confidence * 100)}%` : "—"], ["Country", data.enrichment?.country ?? "Unknown"]
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
