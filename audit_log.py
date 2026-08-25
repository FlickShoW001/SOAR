"""
Audit log module: implements tamper-evident audit trail with hash-chaining.
Every audit entry includes SHA256 of previous entry for integrity verification.
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models import AuditAnchor, AuditLog

logger = logging.getLogger(__name__)


def _export_external_anchor(audit: AuditLog) -> None:
    """Optionally export the chain head to an externally mounted anchor path."""
    anchor_path = os.getenv("AUDIT_EXTERNAL_ANCHOR_PATH")
    if not anchor_path:
        return
    try:
        Path(anchor_path).write_text(
            json.dumps(
                {
                    "entry_id": audit.id,
                    "entry_hash": audit.entry_hash,
                    "timestamp": _canonical_utc_iso(audit.timestamp),
                }
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError:
        logger.exception("Failed to export the external audit anchor")


def _external_anchor_matches(audit: AuditLog) -> bool:
    anchor_path = os.getenv("AUDIT_EXTERNAL_ANCHOR_PATH")
    if not anchor_path:
        return True
    try:
        anchored = json.loads(Path(anchor_path).read_text(encoding="utf-8"))
        return int(anchored["entry_id"]) == audit.id and secrets_compare(
            anchored["entry_hash"], audit.entry_hash
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        logger.exception("External audit anchor is missing or invalid")
        return False


def secrets_compare(left: str, right: str) -> bool:
    """Compare stored hashes without data-dependent early exit."""
    return hmac.compare_digest(str(left), str(right))


def _canonical_utc_iso(value: datetime) -> str:
    """Serialize datetimes consistently even when SQLite returns them as naive."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _canonical_state_json(value: dict[str, Any] | None) -> str:
    """Serialize state deterministically for database-independent hashing."""
    if value is None:
        return ""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _entry_hash_content(
    timestamp: datetime,
    event_id: int | None,
    actor: str,
    action: str,
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    reasoning: str,
    prev_hash: str | None,
) -> str:
    """Build the current audit hash payload, including every mutable field."""
    return (
        f"{_canonical_utc_iso(timestamp)}|{event_id if event_id is not None else ''}|"
        f"{actor}|{action}|{_canonical_state_json(before_state)}|"
        f"{_canonical_state_json(after_state)}|{reasoning}|{prev_hash or ''}"
    )


def create_audit_entry(
    event_id: int | None,
    actor: str,
    action: str,
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    reasoning: str,
    session,
) -> AuditLog:
    """
    Create a new audit log entry with hash-chain integrity.

    Hash-chain: each entry contains SHA256 hash of previous entry's content.
    This makes the audit trail tamper-evident: if any previous entry is modified,
    the hash chain breaks and verify_audit_chain() will detect it.

    Args:
        event_id: The security event being audited (can be None for system actions)
        actor: "system" or username
        action: detect, enrich, decide, approve, reject, respond, close
        before_state: JSON-serializable snapshot before action
        after_state: JSON-serializable snapshot after action
        reasoning: Text explanation of why this action occurred
        session: SQLAlchemy session

    Returns:
        AuditLog entry (persisted to DB)
    """
    # Get previous entry to build hash chain
    prev_entry = session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = prev_entry.entry_hash if prev_entry else None

    # Include all mutable audit fields in a deterministic hash payload. In
    # particular, event_id must be covered so an entry cannot be reassigned to
    # a different incident without invalidating the chain.
    now = datetime.now(timezone.utc)
    hash_content = _entry_hash_content(
        now,
        event_id,
        actor,
        action,
        before_state,
        after_state,
        reasoning,
        prev_hash,
    )
    entry_hash = hashlib.sha256(hash_content.encode()).hexdigest()

    # Create audit entry
    audit = AuditLog(
        timestamp=now,
        event_id=event_id,
        actor=actor,
        action=action,
        before_state=before_state,
        after_state=after_state,
        reasoning=reasoning,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    session.add(audit)
    session.flush()
    anchor = session.query(AuditAnchor).filter_by(id=1).first()
    if anchor is None:
        anchor = AuditAnchor(
            id=1, latest_entry_id=audit.id, latest_entry_hash=entry_hash
        )
        session.add(anchor)
    else:
        anchor.latest_entry_id = audit.id
        anchor.latest_entry_hash = entry_hash
    session.commit()
    _export_external_anchor(audit)

    logger.info(
        f"Audit entry created: actor={actor}, action={action}, event_id={event_id}, hash={entry_hash[:16]}..."
    )

    return audit


def verify_audit_chain(session, depth: int = 1000) -> bool:
    """
    Verify the integrity of the audit log by checking hash chain.

    Algorithm:
      1. Fetch the last N entries (depth parameter)
      2. For each entry, recompute its hash using the stored states + reasoning + prev_hash
      3. Compare computed hash against stored entry_hash
      4. If any mismatch, audit trail has been tampered with

    Args:
        session: SQLAlchemy session
        depth: How many recent entries to verify (for performance)

    Returns:
        True if chain is intact, False if tampering detected
    """
    entries = list(
        reversed(
            session.query(AuditLog).order_by(AuditLog.id.desc()).limit(depth).all()
        )
    )

    anchor = session.query(AuditAnchor).filter_by(id=1).first()
    if not entries:
        if anchor is not None:
            logger.error("Audit log was truncated but an anchor remains")
            return False
        logger.debug("Audit log is empty; verification passed")
        return True

    # The descending, limited query above necessarily includes the chain head.
    # Reuse it instead of issuing another query on every dashboard refresh.
    actual_latest = entries[-1]
    if anchor is not None and (
        anchor.latest_entry_id != actual_latest.id
        or anchor.latest_entry_hash != actual_latest.entry_hash
    ):
        logger.error("Audit chain head does not match its local anchor")
        return False
    if not _external_anchor_matches(actual_latest):
        return False

    boundary = (
        session.query(AuditLog)
        .filter(AuditLog.id < entries[0].id)
        .order_by(AuditLog.id.desc())
        .first()
    )
    expected_prev_hash = boundary.entry_hash if boundary else None
    expected_id = boundary.id + 1 if boundary else 1

    for entry in entries:
        if entry.id != expected_id:
            logger.error(
                "Audit entry deletion or reordering detected near id=%s", entry.id
            )
            return False
        if entry.prev_hash != expected_prev_hash:
            logger.error(
                "Audit entry %s does not reference the preceding hash", entry.id
            )
            return False

        # Recompute the current hash format first.
        current_hash_content = _entry_hash_content(
            entry.timestamp,
            entry.event_id,
            entry.actor,
            entry.action,
            entry.before_state,
            entry.after_state,
            entry.reasoning,
            entry.prev_hash,
        )
        computed_hash = hashlib.sha256(current_hash_content.encode()).hexdigest()

        # Preserve verification of entries created before event_id and
        # canonical JSON were added to the hash payload.
        before_json = json.dumps(entry.before_state) if entry.before_state else ""
        after_json = json.dumps(entry.after_state) if entry.after_state else ""
        if computed_hash != entry.entry_hash:
            legacy_hash_content = (
                f"{entry.timestamp.isoformat()}|{entry.actor}|{entry.action}|"
                f"{before_json}|{after_json}|{entry.reasoning}|{entry.prev_hash or ''}"
            )
            computed_hash = hashlib.sha256(legacy_hash_content.encode()).hexdigest()

        if computed_hash != entry.entry_hash:
            legacy_utc_hash_content = (
                f"{_canonical_utc_iso(entry.timestamp)}|{entry.actor}|{entry.action}|"
                f"{before_json}|{after_json}|{entry.reasoning}|{entry.prev_hash or ''}"
            )
            computed_hash = hashlib.sha256(
                legacy_utc_hash_content.encode()
            ).hexdigest()

        if computed_hash != entry.entry_hash:
            logger.error(
                f"Audit entry {entry.id} hash mismatch! "
                f"Computed: {computed_hash}, Stored: {entry.entry_hash}"
            )
            return False

        expected_prev_hash = entry.entry_hash
        expected_id = entry.id + 1

    logger.debug("Audit chain verification passed for %s entries", len(entries))
    return True


def get_audit_log_for_event(event_id: int, session) -> list[AuditLog]:
    """
    Retrieve complete audit trail for a specific event.

    Args:
        event_id: Event ID to retrieve audit for
        session: SQLAlchemy session

    Returns:
        List of AuditLog entries in chronological order
    """
    return (
        session.query(AuditLog)
        .filter_by(event_id=event_id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )


def audit_event_detection(event, session, actor="system"):
    """Helper: audit the detection of a new event."""
    create_audit_entry(
        event_id=event.id,
        actor=actor,
        action="detect",
        before_state=None,
        after_state={
            "event_id": event.id,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "status": "new",
        },
        reasoning="Security event detected and persisted",
        session=session,
    )


def audit_enrichment(event, enrichment, session, actor="system"):
    """Helper: audit enrichment of an event."""
    create_audit_entry(
        event_id=event.id,
        actor=actor,
        action="enrich",
        before_state={"status": "new"},
        after_state={
            "status": "enriched",
            "enrichment_id": enrichment.id,
            "abuse_score": enrichment.abuse_score,
            "report_count": enrichment.report_count,
            "error": enrichment.error,
        },
        reasoning=f"IP {event.source_ip} enriched via AbuseIPDB",
        session=session,
    )


def audit_decision(event, decision, session, actor="system"):
    """Helper: audit automated decision."""
    create_audit_entry(
        event_id=event.id,
        actor=actor,
        action="decide",
        before_state={"status": "enriched"},
        after_state={
            "status": "decided",
            "decision_id": decision.id,
            "action": decision.action,
            "risk_score": decision.risk_score,
            "confidence": decision.confidence,
            "requires_approval": decision.requires_approval,
        },
        reasoning=f"Decision made: {decision.action} (risk={decision.risk_score:.1f})",
        session=session,
    )


def audit_approval(event, approval, session):
    """Helper: audit approval, auto-approval, or rejection."""
    if approval.status in ("approved", "auto_approved"):
        action = "approve"
        before_status = (
            "decided" if approval.status == "auto_approved" else "pending_approval"
        )
        after_status = "approved" if approval.status == "auto_approved" else "responding"
        reasoning = (
            "Decision automatically approved"
            if approval.status == "auto_approved"
            else "Decision approved by human operator"
        )
    else:
        action = "reject"
        before_status = "pending_approval"
        after_status = "rejected"
        reasoning = approval.rejected_reason or "Decision rejected"

    create_audit_entry(
        event_id=event.id,
        actor=approval.approved_by or "system",
        action=action,
        before_state={"status": before_status, "approval_status": "pending"},
        after_state={"status": after_status, "approval_status": approval.status},
        reasoning=reasoning,
        session=session,
    )


def audit_response(event, decision, response_result, session, actor="system"):
    """Helper: audit the actual response result."""

    response_status = response_result.get("status", "unknown")

    if response_status == "success":
        reasoning = "Response action executed successfully"
    elif response_status == "simulation":
        reasoning = "Response action simulated; no device was changed"
    elif response_status == "skipped":
        reasoning = f"Response skipped: decision action was '{decision.action}'"
    else:
        reasoning = response_result.get("message", "Response action failed")

    create_audit_entry(
        event_id=event.id,
        actor=actor,
        action="respond",
        before_state={"status": "responding"},
        after_state={
            "status": event.status,
            "response_status": response_status,
            "decision_action": decision.action,
        },
        reasoning=reasoning,
        session=session,
    )
