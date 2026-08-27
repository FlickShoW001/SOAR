"""
SQLAlchemy database models for SOAR platform.
Defines the schema for events, enrichment, decisions, approvals, and audit logs.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


def utc_now():
    """Return an aware UTC datetime for database defaults."""
    return datetime.now(timezone.utc)


class Event(Base):
    """
    Represents a security event detected by the platform.
    Status flow includes new, enriched, decided, pending_approval, responding,
    responded, closed, rejected, response_failed, and processing_failed.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True)  # Support IPv4 and IPv6
    event_type = Column(String(50), index=True)
    severity = Column(Integer)  # 1-5: info, low, medium, high, critical
    raw_log_line = Column(Text)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    status = Column(
        String(50), default="new", index=True
    )  # new, enriched, decided, approved, responded, closed
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class EnrichmentResult(Base):
    """
    Caches enrichment data for each IP address.
    Foreign key to Event for direct association.
    """

    __tablename__ = "enrichment_results"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), index=True)
    source_ip = Column(String(45), index=True)
    abuse_score = Column(Float)  # 0-100 from AbuseIPDB
    country = Column(String(100))
    isp = Column(String(200))
    report_count = Column(Integer)
    is_vpn = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    raw_response = Column(JSON)  # Full API response stored for audit
    retrieved_at = Column(DateTime(timezone=True), default=utc_now)
    cached_at = Column(DateTime(timezone=True), default=utc_now)
    cache_ttl_minutes = Column(Integer)
    error = Column(String(500), nullable=True)  # If enrichment failed


class Decision(Base):
    """
    Represents the automated decision made by the decision engine.
    Links to Event and EnrichmentResult.
    """

    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), unique=True, index=True)
    enrichment_id = Column(Integer, ForeignKey("enrichment_results.id"))
    action = Column(String(50))  # block, monitor, ignore
    confidence = Column(Float)  # 0.0-1.0
    risk_score = Column(Float)  # 0-100
    requires_approval = Column(Boolean, default=False)
    reasoning = Column(Text)  # JSON string detailing which rules fired
    created_at = Column(DateTime(timezone=True), default=utc_now)


class Approval(Base):
    """
    Tracks human approval/rejection of decisions.
    Status: pending -> approved/rejected, or auto_approved.
    """

    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), unique=True, index=True)
    decision_id = Column(Integer, ForeignKey("decisions.id"))
    status = Column(
        String(20), default="pending"
    )  # pending, approved, rejected, auto_approved
    approved_by = Column(String(100))  # Username or email
    rejected_reason = Column(Text, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(
        DateTime(timezone=True), nullable=True
    )  # Optional approval expiration
    created_at = Column(DateTime(timezone=True), default=utc_now)


class ResponseJob(Base):
    """Durable, idempotent intent and result record for device responses."""

    __tablename__ = "response_jobs"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("events.id"), unique=True, index=True)
    decision_id = Column(Integer, ForeignKey("decisions.id"), nullable=False)
    idempotency_key = Column(String(128), unique=True, nullable=False, index=True)
    status = Column(String(20), default="pending", nullable=False, index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(JSON, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class AuditLog(Base):
    """
    Tamper-evident audit trail of all platform actions.
    Implements hash-chaining: each entry includes hash of previous entry.
    Schema: timestamp, event_id, actor, action, before_state, after_state, reasoning, prev_hash, entry_hash
    """

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True, index=True)
    actor = Column(String(100))  # "system" or username
    action = Column(
        String(50)
    )  # detect, enrich, decide, approve, reject, respond, close
    before_state = Column(JSON)  # Previous state snapshot
    after_state = Column(JSON)  # New state snapshot
    reasoning = Column(Text)  # Why this action was taken
    prev_hash = Column(String(64))  # SHA256 of previous audit entry
    entry_hash = Column(
        String(64), index=True
    )  # SHA256 of this entry (for integrity check)


class AuditAnchor(Base):
    """Local chain head used to detect truncation of the latest audit entries."""

    __tablename__ = "audit_anchor"

    id = Column(Integer, primary_key=True, default=1)
    latest_entry_id = Column(Integer, nullable=False)
    latest_entry_hash = Column(String(64), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


def init_db(database_url: str = "sqlite:///./soar.db"):
    """
    Initialize the database with all tables.

    Args:
        database_url: SQLAlchemy connection string

    Returns:
        engine, SessionLocal factory
    """
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal
