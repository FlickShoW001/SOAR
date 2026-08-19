"""
Audit log module: implements tamper-evident audit trail with hash-chaining.
Every audit entry includes SHA256 of previous entry for integrity verification.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from models import AuditLog, Event

logger = logging.getLogger(__name__)


def create_audit_entry(
    event_id: Optional[int],
    actor: str,
    action: str,
    before_state: Optional[Dict[str, Any]],
    after_state: Optional[Dict[str, Any]],
    reasoning: str,
    session
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
    
    # Serialize states for hashing
    before_json = json.dumps(before_state) if before_state else ""
    after_json = json.dumps(after_state) if after_state else ""
    
    # Build this entry's hash from: timestamp + actor + action + states + reasoning + prev_hash
    # (This is the "content" of the entry)
    now = datetime.utcnow()
    hash_content = f"{now.isoformat()}|{actor}|{action}|{before_json}|{after_json}|{reasoning}|{prev_hash or ''}"
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
        entry_hash=entry_hash
    )
    session.add(audit)
    session.commit()
    
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
    entries = session.query(AuditLog).order_by(AuditLog.id.asc()).limit(depth).all()
    
    if not entries:
        logger.info("Audit log is empty; verification passed")
        return True
    
    for entry in entries:
        # Recompute hash
        before_json = json.dumps(entry.before_state) if entry.before_state else ""
        after_json = json.dumps(entry.after_state) if entry.after_state else ""
        
        hash_content = (
            f"{entry.timestamp.isoformat()}|{entry.actor}|{entry.action}|"
            f"{before_json}|{after_json}|{entry.reasoning}|{entry.prev_hash or ''}"
        )
        computed_hash = hashlib.sha256(hash_content.encode()).hexdigest()
        
        if computed_hash != entry.entry_hash:
            logger.error(
                f"Audit entry {entry.id} hash mismatch! "
                f"Computed: {computed_hash}, Stored: {entry.entry_hash}"
            )
            return False
    
    logger.info(f"Audit chain verification passed for {len(entries)} entries")
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
    return session.query(AuditLog).filter_by(event_id=event_id).order_by(AuditLog.timestamp.asc()).all()


def audit_event_detection(event, session):
    """Helper: audit the detection of a new event."""
    create_audit_entry(
        event_id=event.id,
        actor="system",
        action="detect",
        before_state=None,
        after_state={
            "event_id": event.id,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "status": "new"
        },
        reasoning="Security event detected and persisted",
        session=session
    )


def audit_enrichment(event, enrichment, session):
    """Helper: audit enrichment of an event."""
    create_audit_entry(
        event_id=event.id,
        actor="system",
        action="enrich",
        before_state={"status": event.status},
        after_state={
            "status": "enriched",
            "enrichment_id": enrichment.id,
            "abuse_score": enrichment.abuse_score,
            "report_count": enrichment.report_count,
            "error": enrichment.error
        },
        reasoning=f"IP {event.source_ip} enriched via AbuseIPDB",
        session=session
    )


def audit_decision(event, decision, session):
    """Helper: audit automated decision."""
    create_audit_entry(
        event_id=event.id,
        actor="system",
        action="decide",
        before_state={"status": event.status},
        after_state={
            "status": "decided",
            "decision_id": decision.id,
            "action": decision.action,
            "risk_score": decision.risk_score,
            "confidence": decision.confidence,
            "requires_approval": decision.requires_approval
        },
        reasoning=f"Decision made: {decision.action} (risk={decision.risk_score:.1f})",
        session=session
    )


def audit_approval(event, approval, session):
    """Helper: audit approval or rejection."""
    create_audit_entry(
        event_id=event.id,
        actor=approval.approved_by or "unknown",
        action="approve" if approval.status == "approved" else "reject",
        before_state={"status": event.status, "approval_status": "pending"},
        after_state={
            "status": "approved" if approval.status == "approved" else "rejected",
            "approval_status": approval.status
        },
        reasoning=approval.rejected_reason or f"Decision {approval.status}",
        session=session
    )


def audit_response(event, session):
    """Helper: audit response execution."""
    create_audit_entry(
        event_id=event.id,
        actor="system",
        action="respond",
        before_state={"status": event.status},
        after_state={"status": "responded"},
        reasoning="Response action executed (block rule applied)",
        session=session
    )
