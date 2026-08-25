const POLL_INTERVAL_MS = 5000;

const state = {
  data: null,
  query: "",
  reviewing: new Set(),
  review: null,
  controller: null,
  etag: null,
  pollTimer: null,
  searchFrame: null,
  toastTimer: null
};

const canReview = ["admin", "operator"].includes(document.body.dataset.role);
const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => {
  const node = document.createElement("div");
  node.textContent = String(value ?? "");
  return node.innerHTML;
};
const normalizeLabel = (value, fallback = "Unknown") => {
  const label = String(value ?? fallback).replaceAll("_", " ").trim();
  return label ? label.replace(/\b\w/g, (letter) => letter.toUpperCase()) : fallback;
};
const matches = (...values) => !state.query || values.some((value) => String(value ?? "").toLowerCase().includes(state.query));
const formatNumber = (value, digits = 1) => value == null || !Number.isFinite(Number(value)) ? "—" : Number(value).toFixed(digits);
const formatPercent = (value) => value == null || !Number.isFinite(Number(value)) ? "—" : `${Math.round(Number(value) * 100)}%`;

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return { relative: "Unknown time", full: "Unknown time" };
  const elapsed = Math.max(0, Date.now() - date.getTime());
  const seconds = Math.floor(elapsed / 1000);
  let relative;
  if (seconds < 45) relative = "Just now";
  else if (seconds < 3600) relative = `${Math.floor(seconds / 60)}m ago`;
  else if (seconds < 86400) relative = `${Math.floor(seconds / 3600)}h ago`;
  else if (seconds < 604800) relative = `${Math.floor(seconds / 86400)}d ago`;
  else relative = date.toLocaleDateString([], { month: "short", day: "numeric" });
  return { relative, full: date.toLocaleString() };
}

function severityMeta(value) {
  const level = Number(value);
  if (level >= 5) return { label: "Critical", className: "critical" };
  if (level === 4) return { label: "High", className: "high" };
  if (level === 3) return { label: "Medium", className: "medium" };
  if (level === 2) return { label: "Low", className: "low" };
  return { label: "Informational", className: "info" };
}

function riskMeta(value) {
  const score = Math.max(0, Math.min(100, Number(value) || 0));
  return { score, className: score >= 75 ? "high" : score >= 50 ? "medium" : "low" };
}

function emptyState(title, detail = "") {
  return `<div class="empty-state">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h12v18H6z"/><path d="M9 8h6m-6 4h6m-6 4h4"/></svg>
    <strong>${escapeHtml(title)}</strong>${detail ? `<span>${escapeHtml(detail)}</span>` : ""}
  </div>`;
}

function renderEvents(items) {
  const rows = items.filter((item) => matches(item.id, item.source_ip, item.event_type, item.severity, item.status));
  byId("event-count").textContent = items.length;
  byId("events-body").innerHTML = rows.length ? rows.map((event) => {
    const severity = severityMeta(event.severity);
    const time = formatDate(event.timestamp);
    const sourceIp = String(event.source_ip ?? "Unknown");
    const monogram = sourceIp.includes(":") ? "v6" : sourceIp.split(".").slice(-2).join(".");
    return `<tr>
      <td><button class="event-link" data-event-id="${escapeHtml(event.id)}" aria-label="Open event ${escapeHtml(event.id)}">#${escapeHtml(event.id)}</button></td>
      <td><div class="source-cell"><span class="source-monogram" aria-hidden="true">${escapeHtml(monogram)}</span><span class="source-copy"><strong>${escapeHtml(sourceIp)}</strong><small title="${escapeHtml(time.full)}">${escapeHtml(time.relative)}</small></span></div></td>
      <td><span class="detection-name">${escapeHtml(normalizeLabel(event.event_type))}</span></td>
      <td><span class="severity ${severity.className}">${severity.label} · ${escapeHtml(event.severity)}</span></td>
      <td><span class="badge badge-${escapeHtml(event.status)}">${escapeHtml(normalizeLabel(event.status))}</span></td>
      <td><button class="row-open" data-event-id="${escapeHtml(event.id)}" aria-label="Open event ${escapeHtml(event.id)} details"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 5 7 7-7 7"/></svg></button></td>
    </tr>`;
  }).join("") : `<tr><td colspan="6">${emptyState("No matching events", state.query ? "Try a broader search term." : "New detections will appear here.")}</td></tr>`;
}

function renderPending(items) {
  const rows = items.filter((item) => matches(item.id, item.source_ip, item.event_type, item.severity, item.status));
  const count = items.length;
  byId("pending-count").textContent = count;
  byId("pending-pill").textContent = count;
  byId("nav-pending-count").textContent = count;
  byId("nav-pending-count").hidden = count === 0;
  byId("approval-permission-note").textContent = canReview ? "Every decision is recorded in the audit chain" : "View-only access · Operator role required to review";

  byId("pending-list").innerHTML = rows.length ? rows.map((event) => {
    const severity = severityMeta(event.severity);
    const busy = state.reviewing.has(String(event.id));
    return `<article class="approval-item">
      <div class="approval-item-top">
        <button class="approval-event" data-event-id="${escapeHtml(event.id)}"><strong>Event #${escapeHtml(event.id)}</strong><small>${escapeHtml(event.source_ip)}</small></button>
        <span class="severity ${severity.className}">${severity.label} · ${escapeHtml(event.severity)}</span>
      </div>
      <div class="approval-meta"><span class="approval-type">${escapeHtml(normalizeLabel(event.event_type))}</span><span class="badge badge-pending_approval">Awaiting review</span></div>
      ${canReview ? `<div class="approval-actions"><button class="action-button reject" data-reject="${escapeHtml(event.id)}" ${busy ? "disabled" : ""}>Reject</button><button class="action-button approve" data-approve="${escapeHtml(event.id)}" ${busy ? "disabled" : ""}>Approve</button></div>` : ""}
    </article>`;
  }).join("") : emptyState(state.query ? "No matching approvals" : "Review queue is clear", state.query ? "Try a broader search term." : "There are no decisions awaiting operator action.");
}

function renderDecisions(items) {
  const rows = items.filter((item) => matches(item.event_id, item.action, item.risk_score, item.requires_approval ? "required" : "automatic"));
  byId("decision-count").textContent = items.length;
  byId("decisions-body").innerHTML = rows.length ? rows.map((decision) => {
    const risk = riskMeta(decision.risk_score);
    return `<tr>
      <td><button class="event-link" data-event-id="${escapeHtml(decision.event_id)}">#${escapeHtml(decision.event_id)}</button></td>
      <td><span class="badge badge-${escapeHtml(decision.action)}">${escapeHtml(normalizeLabel(decision.action))}</span></td>
      <td class="risk-cell"><div class="risk-value"><span>${formatNumber(decision.risk_score)}</span><span class="risk-track" aria-hidden="true"><i class="${risk.className}" style="width:${risk.score}%"></i></span></div></td>
      <td>${formatPercent(decision.confidence)}</td>
      <td>${decision.requires_approval ? '<span class="badge badge-pending_approval">Human review</span>' : '<span class="badge badge-auto_approved">Automatic</span>'}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="5">${emptyState("No matching decisions", state.query ? "Try a broader search term." : "Automated outcomes will appear here.")}</td></tr>`;
}

function renderAudit(items) {
  const rows = items.filter((item) => matches(item.event_id, item.actor, item.action, item.hash));
  byId("audit-count").textContent = items.length;
  byId("audit-list").innerHTML = rows.length ? rows.map((entry) => {
    const time = formatDate(entry.timestamp);
    const target = entry.event_id == null ? "System activity" : `Event #${entry.event_id}`;
    return `<article class="audit-item">
      <div class="audit-heading"><strong>${escapeHtml(normalizeLabel(entry.action))}</strong><time title="${escapeHtml(time.full)}">${escapeHtml(time.relative)}</time></div>
      <p>${escapeHtml(target)} · ${escapeHtml(entry.actor)}</p>
      <p><code>${escapeHtml(entry.hash)}</code></p>
    </article>`;
  }).join("") : emptyState("No matching audit records", state.query ? "Try a broader search term." : "Verified transitions will appear here.");
}

function render() {
  if (!state.data) return;
  renderEvents(state.data.events ?? []);
  renderPending(state.data.pending ?? []);
  renderDecisions(state.data.decisions ?? []);
  renderAudit(state.data.audit ?? []);

  const valid = state.data.audit_chain_valid === true;
  const chainCard = byId("chain-card");
  chainCard.classList.toggle("invalid", !valid);
  byId("chain-chip").textContent = valid ? "Verified" : "Attention";
  byId("chain-status").textContent = valid ? "Chain verified" : "Integrity warning";
  byId("chain-description").textContent = valid ? "Recent records are linked and intact." : "Audit verification failed. Investigate immediately.";
}

function showToast(message, type = "success") {
  const toast = byId("toast");
  window.clearTimeout(state.toastTimer);
  byId("toast-message").textContent = message;
  toast.classList.toggle("error", type === "error");
  toast.classList.add("show");
  state.toastTimer = window.setTimeout(() => toast.classList.remove("show"), 3200);
}

function redirectIfUnauthorized(response) {
  if (response.status !== 401) return false;
  window.location.assign("/login");
  return true;
}

async function loadDashboard(showFeedback = false) {
  if (state.controller && !showFeedback) return;
  state.controller?.abort();
  const controller = new AbortController();
  state.controller = controller;
  const headers = { Accept: "application/json" };
  if (state.etag) headers["If-None-Match"] = state.etag;

  try {
    const response = await fetch("/dashboard/data", { headers, cache: "no-store", signal: controller.signal });
    if (redirectIfUnauthorized(response)) return;
    if (response.status === 304) {
      byId("last-sync").textContent = `Synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
      if (showFeedback) showToast("Operational data is already current");
      return;
    }
    if (!response.ok) throw new Error(`Dashboard request failed (${response.status})`);
    state.data = await response.json();
    state.etag = response.headers.get("ETag");
    render();
    byId("last-sync").textContent = `Synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    if (showFeedback) showToast("Operational data refreshed");
  } catch (error) {
    if (error.name === "AbortError") return;
    byId("last-sync").textContent = "Connection interrupted";
    showToast(error.message || "Could not refresh the dashboard", "error");
  } finally {
    if (state.controller === controller) state.controller = null;
  }
}

function schedulePoll(delay = POLL_INTERVAL_MS) {
  window.clearTimeout(state.pollTimer);
  if (document.hidden) return;
  state.pollTimer = window.setTimeout(async () => {
    await loadDashboard();
    schedulePoll();
  }, delay);
}

function openReview(eventId, approved) {
  const event = state.data?.pending?.find((item) => String(item.id) === String(eventId));
  if (!event || state.reviewing.has(String(eventId))) return;
  state.review = { eventId: String(eventId), approved };
  const dialog = byId("review-dialog");
  const reasonField = byId("reason-field");
  const reasonInput = byId("rejection-reason");
  const severity = severityMeta(event.severity);
  dialog.classList.toggle("rejecting", !approved);
  byId("review-eyebrow").textContent = approved ? "Authorize response" : "Decline response";
  byId("review-title").textContent = approved ? `Approve event #${eventId}` : `Reject event #${eventId}`;
  byId("review-summary").innerHTML = `<strong>${escapeHtml(event.source_ip)} · ${escapeHtml(normalizeLabel(event.event_type))}</strong><small>${severity.label} severity · This decision will be written to the audit chain.</small>`;
  byId("confirm-review").textContent = approved ? "Approve response" : "Reject decision";
  reasonField.hidden = approved;
  reasonInput.required = !approved;
  reasonInput.value = "";
  byId("reason-count").textContent = "0";
  dialog.showModal();
  if (!approved) window.setTimeout(() => reasonInput.focus(), 50);
}

async function submitReview() {
  if (!state.review) return;
  const { eventId, approved } = state.review;
  const rejectedReason = byId("rejection-reason").value.trim();
  if (!approved && !rejectedReason) {
    byId("rejection-reason").focus();
    showToast("Add a reason before rejecting this decision", "error");
    return;
  }

  state.reviewing.add(eventId);
  byId("confirm-review").disabled = true;
  byId("confirm-review").textContent = "Recording decision…";
  renderPending(state.data?.pending ?? []);
  try {
    const response = await fetch(`/approvals/${encodeURIComponent(eventId)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ approved, rejected_reason: approved ? null : rejectedReason })
    });
    if (redirectIfUnauthorized(response)) return;
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.detail || `Review action failed (${response.status})`);
    byId("review-dialog").close();
    state.review = null;
    showToast(approved ? `Event #${eventId} approved` : `Event #${eventId} rejected`);
    await loadDashboard();
  } catch (error) {
    showToast(error.message || "Review action failed", "error");
  } finally {
    state.reviewing.delete(eventId);
    byId("confirm-review").disabled = false;
    renderPending(state.data?.pending ?? []);
  }
}

async function openEvent(eventId) {
  const dialog = byId("event-dialog");
  byId("dialog-title").textContent = `Event #${eventId}`;
  byId("dialog-content").innerHTML = '<div class="loading-state"><span></span>Loading event intelligence…</div>';
  if (!dialog.open) dialog.showModal();

  try {
    const response = await fetch(`/events/${encodeURIComponent(eventId)}`, { headers: { Accept: "application/json" }, cache: "no-store" });
    if (redirectIfUnauthorized(response)) return;
    if (!response.ok) throw new Error(`Could not load event details (${response.status})`);
    const data = await response.json();
    const severity = severityMeta(data.event.severity);
    const eventTime = formatDate(data.event.timestamp);
    const details = [
      ["Detection type", normalizeLabel(data.event.event_type)],
      ["Severity", `${severity.label} · ${data.event.severity}`],
      ["Pipeline state", normalizeLabel(data.event.status)],
      ["Recommended action", normalizeLabel(data.decision?.action, "Pending")],
      ["Risk score", formatNumber(data.decision?.risk_score)],
      ["Confidence", formatPercent(data.decision?.confidence)],
      ["Country", data.enrichment?.country ?? "Unknown"],
      ["Network provider", data.enrichment?.isp ?? "Unknown"],
      ["Abuse confidence", data.enrichment?.abuse_score == null ? "Unavailable" : `${formatNumber(data.enrichment.abuse_score)} / 100`],
      ["Abuse reports", data.enrichment?.report_count ?? "Unavailable"],
      ["Approval", normalizeLabel(data.approval?.status, data.decision?.requires_approval ? "Pending" : "Not required")]
    ];
    const auditRows = (data.audit_trail ?? []).map((entry) => `<div class="event-audit-row"><strong>${escapeHtml(normalizeLabel(entry.action))} · ${escapeHtml(entry.actor)}</strong><p>${escapeHtml(entry.reasoning)} · ${escapeHtml(formatDate(entry.timestamp).full)}</p></div>`).join("");
    const approvalReasons = data.decision?.reasoning?.approval_reasons ?? [];
    byId("dialog-content").innerHTML = `
      <div class="detail-hero"><div><h3>${escapeHtml(data.event.source_ip)}</h3><p>Observed ${escapeHtml(eventTime.full)}</p></div><span class="badge badge-${escapeHtml(data.event.status)}">${escapeHtml(normalizeLabel(data.event.status))}</span></div>
      <div class="detail-grid">${details.map(([label, value]) => `<div class="detail"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`).join("")}</div>
      <h3 class="detail-section-title">Source evidence</h3>
      <div class="raw-evidence"><code>${escapeHtml(data.event.raw_log_line ?? "No raw event evidence was stored.")}</code></div>
      ${approvalReasons.length ? `<h3 class="detail-section-title">Approval rationale</h3><div class="reason-tags">${approvalReasons.map((reason) => `<span>${escapeHtml(normalizeLabel(reason))}</span>`).join("")}</div>` : ""}
      <h3 class="detail-section-title">Event audit history</h3>
      <div class="event-audit-list">${auditRows || emptyState("No audit history available")}</div>`;
  } catch (error) {
    byId("dialog-content").innerHTML = emptyState("Event details unavailable", error.message || "Try again in a moment.");
    showToast(error.message || "Could not load event details", "error");
  }
}

function closeDialog(dialog) {
  if (dialog?.open) dialog.close();
  if (dialog?.id === "review-dialog") state.review = null;
}

document.addEventListener("click", (event) => {
  const eventButton = event.target.closest("[data-event-id]");
  const approveButton = event.target.closest("[data-approve]");
  const rejectButton = event.target.closest("[data-reject]");
  const closeButton = event.target.closest("[data-close-dialog]");
  if (eventButton) openEvent(eventButton.dataset.eventId);
  if (approveButton) openReview(approveButton.dataset.approve, true);
  if (rejectButton) openReview(rejectButton.dataset.reject, false);
  if (event.target.closest("[data-refresh]")) loadDashboard(true);
  if (closeButton) closeDialog(byId(closeButton.dataset.closeDialog));
});

document.querySelectorAll("dialog").forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) closeDialog(dialog);
  });
});

byId("review-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitReview();
});

byId("rejection-reason").addEventListener("input", (event) => {
  byId("reason-count").textContent = event.target.value.length;
});

byId("global-search").addEventListener("input", (event) => {
  state.query = event.target.value.trim().toLowerCase();
  window.cancelAnimationFrame(state.searchFrame);
  state.searchFrame = window.requestAnimationFrame(render);
});

document.addEventListener("keydown", (event) => {
  const isTyping = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
  if (event.key === "/" && !isTyping) {
    event.preventDefault();
    byId("global-search").focus();
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    window.clearTimeout(state.pollTimer);
    return;
  }
  loadDashboard().finally(() => schedulePoll());
});

if ("IntersectionObserver" in window) {
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    document.querySelectorAll("[data-section-link]").forEach((link) => link.classList.toggle("active", link.dataset.sectionLink === visible.target.id));
  }, { rootMargin: "-15% 0px -65%", threshold: [0.05, 0.25, 0.5] });
  document.querySelectorAll("[data-dashboard-section]").forEach((section) => observer.observe(section));
}

loadDashboard().finally(() => schedulePoll());
