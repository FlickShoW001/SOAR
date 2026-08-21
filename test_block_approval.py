from models import init_db, Event, EnrichmentResult, Decision, Approval, AuditLog
from decision_engine import decide, persist_decision, load_config
load_config("config.yaml")
from audit_log import (
    audit_event_detection,
    audit_enrichment,
    audit_decision,
    audit_approval,
    audit_response,
)
from responder import init_lab_allowlist, execute_response
from datetime import datetime


# Use the same database as the application
engine, SessionLocal = init_db("sqlite:///./soar.db")
db = SessionLocal()

try:
    init_lab_allowlist()

    # 1. Create a completely synthetic event.
    event = Event(
        source_ip="192.168.1.100",
        event_type="synthetic_block_test",
        severity=5,
        raw_log_line="SOAR SAFE TEST - synthetic high-risk event",
        timestamp=datetime.utcnow(),
        status="new",
    )
    db.add(event)
    db.flush()

    audit_event_detection(event, db)

    # 2. Create synthetic enrichment.
    #    100 abuse score + critical severity + 200 reports => risk 100.
    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip=event.source_ip,
        abuse_score=100.0,
        country="TEST",
        isp="SOAR-TEST",
        report_count=200,
        is_vpn=False,
        is_proxy=False,
        raw_response={"test": True},
        cache_ttl_minutes=0,
    )
    db.add(enrichment)
    db.commit()

    event.status = "enriched"
    db.commit()
    audit_enrichment(event, enrichment, db)

    # 3. Run the REAL decision engine.
    decision_result = decide(event, enrichment)
    decision = persist_decision(event, enrichment, decision_result, db)

    event.status = "decided"
    db.commit()
    audit_decision(event, decision, db)

    print("\n=== DECISION ===")
    print(f"Event ID:          {event.id}")
    print(f"Risk score:        {decision.risk_score}")
    print(f"Action:            {decision.action}")
    print(f"Requires approval: {decision.requires_approval}")

    if decision.action != "block":
        raise RuntimeError("TEST FAILED: decision was not BLOCK")

    if not decision.requires_approval:
        raise RuntimeError("TEST FAILED: BLOCK did not require approval")

    # 4. Simulate the approval gate.
    event.status = "pending_approval"
    db.commit()

    approval = Approval(
        event_id=event.id,
        decision_id=decision.id,
        status="approved",
        approved_by="test_operator",
        approved_at=datetime.utcnow(),
    )
    db.add(approval)

    event.status = "approved"
    db.commit()
    audit_approval(event, approval, db)

    print("\n=== APPROVAL ===")
    print("Status: approved")
    print("Approved by: test_operator")

    # 5. Execute the REAL responder in simulation mode.
    response = execute_response(
        event,
        decision,
        dry_run=True,
        simulation_mode=True,
    )

    event.status = "responded"
    db.commit()
    audit_response(event, decision, response, db)

    print("\n=== RESPONSE ===")
    print(f"Status:   {response['status']}")
    print(f"Message:  {response['message']}")
    print("Commands:")
    for command in response.get("commands_sent", []):
        print(f"  {command}")

    print("\n=== TEST RESULT ===")
    print("SUCCESS: BLOCK -> APPROVAL -> SIMULATED RESPONSE")

finally:
    db.close()

