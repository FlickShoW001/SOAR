"""
FastAPI main application: SOAR platform detect → enrich → decide → approve → respond → log pipeline.
Exposes REST endpoints for detection intake, approvals, and dashboard.
"""

import os
import logging
from datetime import datetime
from contextlib import contextmanager
from sqlalchemy import create_engine, text
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
import yaml

from models import (
    Event, EnrichmentResult, Decision, Approval, AuditLog,
    init_db
)
from enrichment import enrich_ip, clear_cache as clear_enrichment_cache
from decision_engine import decide, load_config as load_decision_config, persist_decision
from audit_log import (
    create_audit_entry, verify_audit_chain, get_audit_log_for_event,
    audit_event_detection, audit_enrichment, audit_decision, audit_approval, audit_response
)
from responder import init_lab_allowlist, execute_response

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./soar.db")
engine, SessionLocal = init_db(DATABASE_URL)

# Load configuration files
load_decision_config("config.yaml")
init_lab_allowlist()

# FastAPI app
app = FastAPI(
    title="SOAR Platform",
    description="Security Orchestration, Automation, and Response platform",
    version="1.0.0"
)

# Dependency: database session
def get_db():
    """Provide SQLAlchemy session for each request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# Pydantic Models (Request/Response)
# ============================================================================

class DetectionRequest(BaseModel):
    """POST /detections endpoint accepts this JSON."""
    source_ip: str
    event_type: str
    severity: int  # 1-5: info, low, medium, high, critical
    raw_log_line: str
    timestamp: str = None  # ISO 8601; defaults to now


class ApprovalRequest(BaseModel):
    """POST /approvals/{event_id} endpoint."""
    approved: bool
    rejected_reason: str = None


class EventResponse(BaseModel):
    """Response model for event details."""
    id: int
    source_ip: str
    event_type: str
    severity: int
    status: str
    created_at: str


# ============================================================================
# Core Pipeline Endpoints
# ============================================================================

@app.post("/detections")
def post_detection(req: DetectionRequest, db: Session = Depends(get_db)):
    """
    POST /detections: Intake a security event.
    
    Example:
    {
      "source_ip": "192.168.1.100",
      "event_type": "port_scan",
      "severity": 3,
      "raw_log_line": "SYN scan from 192.168.1.100 to ports 22,80,443",
      "timestamp": "2026-08-19T10:00:00Z"
    }
    
    Flow:
      1. Store event in DB with status="new"
      2. Audit the detection
      3. Trigger enrichment in the background
      4. Return event details
    """
    try:
        # Step 1: Create event
        ts = datetime.fromisoformat(req.timestamp) if req.timestamp else datetime.utcnow()
        event = Event(
            source_ip=req.source_ip,
            event_type=req.event_type,
            severity=req.severity,
            raw_log_line=req.raw_log_line,
            timestamp=ts,
            status="new"
        )
        db.add(event)
        db.flush()  # Get the ID
        
        # Step 2: Audit detection
        audit_event_detection(event, db)
        
        # Step 3: Enrich immediately (synchronously for simplicity; could be async)
        enrichment = enrich_ip(req.source_ip, db,event.id)
        event.status = "enriched"
        db.commit()
        audit_enrichment(event, enrichment, db)
        
        # Step 4: Decide
        from decision_engine import decide
        decision_result = decide(event, enrichment)
        decision = persist_decision(event, enrichment, decision_result, db)
        event.status = "decided"
        db.commit()
        audit_decision(event, decision, db)
        
        # Step 5: Check approval gate
        if decision.requires_approval:
            event.status = "pending_approval"
            db.commit()
            logger.info(f"Event {event.id} requires approval")
            return {
                "id": event.id,
                "source_ip": event.source_ip,
                "status": "pending_approval",
                "message": "Awaiting human approval",
                "decision": {
                    "action": decision.action,
                    "risk_score": decision.risk_score,
                    "confidence": decision.confidence
                }
            }
        else:
            # Auto-approve: proceed to response
            event.status = "approved"
            approval = Approval(event_id=event.id, decision_id=decision.id, status="auto_approved")
            db.add(approval)
            db.commit()
            audit_approval(event, approval, db)
            
            # Execute response
            resp_result = execute_response(event, decision)
            event.status = "responded"
            db.commit()
            audit_response(event, decision, resp_result, db)
            
            return {
                "id": event.id,
                "source_ip": event.source_ip,
                "status": "responded",
                "message": "Auto-approved and responded",
                "response": resp_result
            }
    
    except Exception as e:
        logger.error(f"Detection intake error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/approvals/{event_id}")
def approve_decision(event_id: int, req: ApprovalRequest, db: Session = Depends(get_db)):
    """
    POST /approvals/{event_id}: Approve or reject a pending decision.
    
    Example:
    {
      "approved": true,
      "rejected_reason": null
    }
    """
    try:
        event = db.query(Event).filter_by(id=event_id).first()
        if not event:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
        
        if event.status != "pending_approval":
            raise HTTPException(status_code=400, detail=f"Event status is {event.status}, not pending_approval")
        
        decision = db.query(Decision).filter_by(event_id=event_id).first()
        approval = db.query(Approval).filter_by(event_id=event_id).first()
        
        if not approval:
            approval = Approval(event_id=event_id, decision_id=decision.id)
            db.add(approval)
        
        if req.approved:
            approval.status = "approved"
            approval.approved_by = "human_operator"  # In real system, use authenticated user
            event.status = "approved"
            db.commit()
            audit_approval(event, approval, db)
            
            # Execute response
            resp_result = execute_response(event, decision)
            event.status = "responded"
            db.commit()
            audit_response(event, decision, resp_result, db)
            
            return {
                "id": event.id,
                "status": "responded",
                "message": "Approved and responded",
                "response": resp_result
            }
        else:
            approval.status = "rejected"
            approval.rejected_reason = req.rejected_reason or "No reason provided"
            event.status = "rejected"
            db.commit()
            audit_approval(event, approval, db)
            
            return {
                "id": event.id,
                "status": "rejected",
                "message": "Decision rejected",
                "reason": approval.rejected_reason
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Approval error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Dashboard Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db)):
    """GET /: Render main dashboard."""
    # Fetch pending events
    pending = db.query(Event).filter_by(status="pending_approval").all()
    
    # Fetch recent decisions
    recent_decisions = db.query(Decision).order_by(Decision.created_at.desc()).limit(10).all()
    
    # Fetch recent audit entries
    recent_audit = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20).all()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOAR Platform Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            h1 {{ color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }}
            h2 {{ color: #0066cc; margin-top: 30px; }}
            table {{ width: 100%; border-collapse: collapse; background-color: white; margin-top: 10px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #0066cc; color: white; }}
            tr:hover {{ background-color: #f9f9f9; }}
            .badge {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; }}
            .badge-pending {{ background-color: #ff9800; color: white; }}
            .badge-approved {{ background-color: #4caf50; color: white; }}
            .badge-rejected {{ background-color: #f44336; color: white; }}
            .badge-block {{ background-color: #f44336; color: white; }}
            .badge-monitor {{ background-color: #ff9800; color: white; }}
            .badge-ignore {{ background-color: #4caf50; color: white; }}
            .stats {{ display: flex; gap: 20px; margin-top: 20px; }}
            .stat-box {{ background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; text-align: center; }}
            .stat-box h3 {{ margin: 0; color: #0066cc; }}
            .stat-box .number {{ font-size: 32px; font-weight: bold; color: #333; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SOAR Platform Dashboard</h1>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>Pending Approvals</h3>
                    <div class="number">{len(pending)}</div>
                </div>
                <div class="stat-box">
                    <h3>Recent Decisions</h3>
                    <div class="number">{len(recent_decisions)}</div>
                </div>
                <div class="stat-box">
                    <h3>Audit Entries</h3>
                    <div class="number">{len(recent_audit)}</div>
                </div>
            </div>
            
            <h2>Pending Approvals ({len(pending)})</h2>
            {'<table><tr><th>Event ID</th><th>Source IP</th><th>Type</th><th>Severity</th><th>Status</th></tr>' + ''.join(f'<tr><td>{e.id}</td><td>{e.source_ip}</td><td>{e.event_type}</td><td>{e.severity}</td><td><span class="badge badge-pending">{e.status}</span></td></tr>' for e in pending) + '</table>' if pending else '<p>No pending approvals.</p>'}
            
            <h2>Recent Decisions ({len(recent_decisions)})</h2>
            {'<table><tr><th>Event ID</th><th>Action</th><th>Risk Score</th><th>Confidence</th><th>Requires Approval</th></tr>' + ''.join(f'<tr><td>{d.event_id}</td><td><span class="badge badge-{d.action}">{d.action}</span></td><td>{d.risk_score:.1f}</td><td>{d.confidence:.2f}</td><td>{"Yes" if d.requires_approval else "No"}</td></tr>' for d in recent_decisions) + '</table>' if recent_decisions else '<p>No decisions yet.</p>'}
            
            <h2>Audit Log (Recent 20)</h2>
            {'<table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Event ID</th><th>Hash</th></tr>' + ''.join(f'<tr><td>{a.timestamp.isoformat()}</td><td>{a.actor}</td><td>{a.action}</td><td>{a.event_id}</td><td>{a.entry_hash[:16]}...</td></tr>' for a in recent_audit) + '</table>' if recent_audit else '<p>No audit entries.</p>'}
            
            <h2>Audit Chain Integrity</h2>
            <p><strong>Chain Valid:</strong> <span style="color: {'green' if verify_audit_chain(db) else 'red'}; font-weight: bold;">{"✓ VALID" if verify_audit_chain(db) else "✗ INVALID"}</span></p>
        </div>
    </body>
    </html>
    """
    return html


@app.get("/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    """GET /events/{event_id}: Retrieve detailed event info + decision + audit trail."""
    event = db.query(Event).filter_by(id=event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    
    enrichment = db.query(EnrichmentResult).filter_by(event_id=event_id).first()
    decision = db.query(Decision).filter_by(event_id=event_id).first()
    approval = db.query(Approval).filter_by(event_id=event_id).first()
    audit = get_audit_log_for_event(event_id, db)
    
    return {
        "event": {
            "id": event.id,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "status": event.status,
            "timestamp": event.timestamp.isoformat()
        },
        "enrichment": {
            "abuse_score": enrichment.abuse_score if enrichment else None,
            "country": enrichment.country if enrichment else None,
            "isp": enrichment.isp if enrichment else None,
            "report_count": enrichment.report_count if enrichment else None
        } if enrichment else None,
        "decision": {
            "action": decision.action if decision else None,
            "risk_score": decision.risk_score if decision else None,
            "confidence": decision.confidence if decision else None,
            "requires_approval": decision.requires_approval if decision else None
        } if decision else None,
        "approval": {
            "status": approval.status if approval else None,
            "approved_by": approval.approved_by if approval else None
        } if approval else None,
        "audit_trail": [
            {
                "timestamp": a.timestamp.isoformat(),
                "actor": a.actor,
                "action": a.action,
                "reasoning": a.reasoning
            } for a in audit
        ]
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """GET /health: Health check endpoint."""
    try:
        db.execute(text("SELECT 1"))
        audit_valid = verify_audit_chain(db, depth=100)
        return {
            "status": "healthy",
            "database": "connected",
            "audit_chain": "valid" if audit_valid else "invalid"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# ============================================================================
# Startup/Shutdown
# ============================================================================

@app.on_event("startup")
def startup():
    logger.info("SOAR Platform starting up...")
    logger.info(f"Database: {DATABASE_URL}")
    logger.info("Config loaded: config.yaml")
    logger.info("Lab allow-list initialized")


@app.on_event("shutdown")
def shutdown():
    logger.info("SOAR Platform shutting down...")
    clear_enrichment_cache()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        reload=os.getenv("API_RELOAD", "True").lower() == "true"
    )
