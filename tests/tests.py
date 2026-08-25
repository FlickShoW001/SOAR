"""
Unit tests for SOAR platform: enrichment, decision engine, and API endpoints.
Run with: pytest tests/ -v
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from decision_engine import decide, load_config
from enrichment import clear_cache, enrich_ip
from models import Base, EnrichmentResult, Event

# ============================================================================
# Fixtures: In-memory database for testing
# ============================================================================


@pytest.fixture(scope="function")
def test_db():
    """Create an in-memory SQLite database for each test."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    yield db
    db.close()


# ============================================================================
# Enrichment Tests
# ============================================================================


def test_enrich_ip_missing_api_key(test_db, monkeypatch):
    """Test enrichment gracefully handles missing API key."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = enrich_ip("192.168.1.100", test_db)

    assert result is not None
    assert result.error is not None
    assert "API key" in result.error


def test_enrich_ip_caching(test_db, monkeypatch):
    """Test enrichment caching: second call returns cached result."""

    # Mock the API to return a result
    class MockResponse:
        status_code = 200

        def json(self):
            return {
                "data": {
                    "abuseConfidenceScore": 75,
                    "countryCode": "US",
                    "isp": "Evil ISP",
                    "totalReports": 50,
                    "usageType": "Residential",
                }
            }

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")
    monkeypatch.setattr("enrichment.requests.get", mock_get)

    # First call
    clear_cache()
    result1 = enrich_ip("192.168.1.100", test_db)
    # Second call (should use cache)
    result2 = enrich_ip("192.168.1.100", test_db)
    count2 = test_db.query(EnrichmentResult).count()

    # Both should succeed
    assert result1.abuse_score == 75
    assert result2.abuse_score == 75
    # Cache returns new DB record each time (for audit), so count increases
    assert count2 == 2


# ============================================================================
# Decision Engine Tests
# ============================================================================


def test_decision_engine_high_risk_block(test_db):
    """Test decision engine blocks high-risk IP."""
    load_config("config.yaml")

    # Create event: high severity
    event = Event(
        source_ip="192.168.1.100",
        event_type="port_scan",
        severity=5,  # critical
        raw_log_line="SYN scan detected",
        timestamp=datetime.now(timezone.utc),
        status="enriched",
    )
    test_db.add(event)
    test_db.flush()

    # Create enrichment: high abuse score
    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip="192.168.1.100",
        abuse_score=85.0,  # Very high
        country="US",
        isp="Evil ISP",
        report_count=150,
        cache_ttl_minutes=60,
    )
    test_db.add(enrichment)
    test_db.commit()

    # Decide
    decision = decide(event, enrichment)

    # Should recommend block
    assert decision.action == "block"
    assert decision.risk_score > 75  # High risk
    assert decision.requires_approval  # Block always requires approval


def test_decision_engine_medium_risk_monitor(test_db):
    """Test decision engine monitors medium-risk IP."""
    load_config("config.yaml")

    event = Event(
        source_ip="10.0.0.50",
        event_type="failed_login",
        severity=3,  # medium
        raw_log_line="Multiple failed SSH logins",
        timestamp=datetime.now(timezone.utc),
        status="enriched",
    )
    test_db.add(event)
    test_db.flush()

    # Medium abuse score
    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip="10.0.0.50",
        abuse_score=45.0,
        country="CN",
        isp="Unknown",
        report_count=100,
        cache_ttl_minutes=60,
    )
    test_db.add(enrichment)
    test_db.commit()

    decision = decide(event, enrichment)

    # Should recommend monitor
    assert decision.action == "monitor"
    assert 50 <= decision.risk_score < 75


def test_decision_engine_low_risk_ignore(test_db):
    """Test decision engine ignores low-risk IP."""
    load_config("config.yaml")

    event = Event(
        source_ip="8.8.8.8",  # Google DNS
        event_type="dns_query",
        severity=1,  # info
        raw_log_line="DNS query",
        timestamp=datetime.now(timezone.utc),
        status="enriched",
    )
    test_db.add(event)
    test_db.flush()

    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip="8.8.8.8",
        abuse_score=0.0,
        country="US",
        isp="Google",
        report_count=0,
        cache_ttl_minutes=60,
    )
    test_db.add(enrichment)
    test_db.commit()

    decision = decide(event, enrichment)

    # Should recommend ignore
    assert decision.action == "ignore"
    assert decision.risk_score < 50


def test_decision_engine_reasoning_logged(test_db):
    """Test that decision reasoning is captured."""
    load_config("config.yaml")

    event = Event(
        source_ip="192.168.1.100",
        event_type="port_scan",
        severity=4,
        raw_log_line="SYN scan",
        timestamp=datetime.now(timezone.utc),
        status="enriched",
    )
    test_db.add(event)
    test_db.flush()

    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip="192.168.1.100",
        abuse_score=70.0,
        country="RU",
        isp="RuNet",
        report_count=80,
        cache_ttl_minutes=60,
    )
    test_db.add(enrichment)
    test_db.commit()

    decision = decide(event, enrichment)

    # Check reasoning contains expected keys
    assert "risk_calculation" in decision.reasoning
    assert "confidence_factors" in decision.reasoning
    assert "approval_reasons" in decision.reasoning

    # Verify risk calculation details are logged
    risk_calc = decision.reasoning["risk_calculation"]
    assert risk_calc["abuse_score"] == 70.0
    assert risk_calc["event_severity"] == 4
    assert risk_calc["report_count"] == 80


def test_high_severity_ignore_still_requires_human_approval(test_db):
    """Critical events cannot bypass review because their risk action is ignore."""
    load_config("config.yaml")
    event = Event(
        source_ip="192.168.1.100",
        event_type="critical_unknown_activity",
        severity=5,
        raw_log_line="Critical event with unavailable enrichment",
        timestamp=datetime.now(timezone.utc),
        status="enriched",
    )
    test_db.add(event)
    test_db.flush()
    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip=event.source_ip,
        abuse_score=None,
        report_count=None,
        error="Enrichment unavailable",
        cache_ttl_minutes=60,
    )

    decision = decide(event, enrichment)

    assert decision.action == "ignore"
    assert decision.requires_approval is True
    assert "high_severity_event" in decision.reasoning["approval_reasons"]
    assert "uncached_or_unknown_ip" in decision.reasoning["approval_reasons"]


def test_unknown_ip_approval_rule_is_honored(test_db):
    """The configured unknown-IP rule must apply to low-severity events too."""
    load_config("config.yaml")
    event = Event(
        source_ip="192.168.1.101",
        event_type="unknown_activity",
        severity=1,
        raw_log_line="Low severity event with unavailable enrichment",
        timestamp=datetime.now(timezone.utc),
        status="enriched",
    )
    test_db.add(event)
    test_db.flush()
    enrichment = EnrichmentResult(
        event_id=event.id,
        source_ip=event.source_ip,
        abuse_score=None,
        report_count=None,
        error="Enrichment unavailable",
        cache_ttl_minutes=60,
    )

    decision = decide(event, enrichment)

    assert decision.requires_approval is True
    assert decision.reasoning["approval_reasons"] == ["uncached_or_unknown_ip"]


# ============================================================================
# Audit Log Tests
# ============================================================================


def test_audit_log_hash_chain_integrity(test_db):
    """Test that audit log hash chain detects tampering."""
    from audit_log import create_audit_entry, verify_audit_chain

    # Create a few audit entries
    for i in range(3):
        create_audit_entry(
            event_id=1,
            actor="system",
            action="detect",
            before_state=None,
            after_state={"step": i},
            reasoning="Test",
            session=test_db,
        )

    # Chain should be valid
    assert verify_audit_chain(test_db)

    # Tamper with an entry
    from models import AuditLog

    entry = test_db.query(AuditLog).filter_by(id=1).one()
    entry.reasoning = "tampered"
    test_db.commit()
    assert verify_audit_chain(test_db) is False


# ============================================================================
# API Endpoint Tests (Integration)
# ============================================================================


@pytest.fixture
def client(monkeypatch):
    """Create an isolated FastAPI test client without touching soar.db."""
    from fastapi.testclient import TestClient

    from main import app, get_db

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_health_check(client):
    """Test GET /health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_health_check_reports_invalid_audit_chain(client, monkeypatch):
    """Audit tampering must make the service unhealthy for monitoring systems."""
    monkeypatch.setattr("main.verify_audit_chain", lambda *_args, **_kwargs: False)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unhealthy",
        "database": "connected",
        "audit_chain": "invalid",
    }


def test_detection_intake_endpoint(client):
    """Test POST /detections endpoint."""
    payload = {
        "source_ip": "192.168.1.100",
        "event_type": "port_scan",
        "severity": 4,
        "raw_log_line": "SYN scan from X to ports Y",
        "timestamp": "2026-08-19T10:00:00Z",
    }

    response = client.post("/detections", json=payload, auth=("admin", "admin"))
    assert response.status_code == 200


def test_detection_can_only_be_reviewed_once(client):
    payload = {
        "source_ip": "192.168.1.100",
        "event_type": "port_scan",
        "severity": 4,
        "raw_log_line": "Synthetic review conflict test",
    }
    detection = client.post("/detections", json=payload, auth=("admin", "admin"))
    assert detection.status_code == 200
    event_id = detection.json()["id"]

    first = client.post(
        f"/approvals/{event_id}",
        json={"approved": False, "rejected_reason": "Known test source"},
        auth=("admin", "admin"),
    )
    second = client.post(
        f"/approvals/{event_id}",
        json={"approved": True},
        auth=("admin", "admin"),
    )

    assert first.status_code == 200
    assert second.status_code == 409


def test_dashboard_endpoint(client):
    """Test GET / (dashboard) renders HTML."""
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "admin"},
        follow_redirects=False,
    )
    response = client.get("/")

    assert login_response.status_code == 303
    assert response.status_code == 200
    assert "SOAR Command Center" in response.text
    assert "<table>" in response.text


def test_dashboard_requires_authentication(client):
    """Dashboard and its live data must reject anonymous requests."""
    dashboard_response = client.get("/", follow_redirects=False)
    data_response = client.get("/dashboard/data")

    assert dashboard_response.status_code == 303
    assert dashboard_response.headers["location"] == "/login"
    assert data_response.status_code == 401


def test_dashboard_data_includes_events_that_do_not_need_approval(client):
    """All detections remain visible, including automatically handled events."""
    payload = {
        "source_ip": "192.168.1.100",
        "event_type": "dns_query",
        "severity": 1,
        "raw_log_line": "Benign synthetic dashboard event",
    }
    detection_response = client.post(
        "/detections", json=payload, auth=("admin", "admin")
    )
    assert detection_response.status_code == 200

    data_response = client.get("/dashboard/data", auth=("admin", "admin"))
    assert data_response.status_code == 200
    event_id = detection_response.json()["id"]
    assert any(event["id"] == event_id for event in data_response.json()["events"])


def test_dashboard_data_does_not_truncate_pending_approvals(test_db):
    """Every pending event must remain actionable in the approval queue."""
    from fastapi import Request, Response

    from main import UserIdentity, dashboard_data

    for index in range(25):
        test_db.add(
            Event(
                source_ip=f"192.168.1.{index + 1}",
                event_type="approval_test",
                severity=5,
                raw_log_line="Synthetic pending event",
                timestamp=datetime.now(timezone.utc),
                status="pending_approval",
            )
        )
    test_db.commit()

    response = Response()
    request = Request({"type": "http", "headers": []})
    data = dashboard_data(request, response, UserIdentity("admin", "admin"), test_db)

    assert len(data["pending"]) == 25
    assert data["pending"][0]["id"] > data["pending"][-1]["id"]
    assert response.headers["cache-control"] == "no-store"


def test_dashboard_data_uses_etag_for_unchanged_payload(test_db):
    """Unchanged polls avoid resending and rerendering the dashboard payload."""
    from fastapi import Request, Response

    from main import UserIdentity, dashboard_data

    first_response = Response()
    payload = dashboard_data(
        Request({"type": "http", "headers": []}),
        first_response,
        UserIdentity("admin", "admin"),
        test_db,
    )
    etag = first_response.headers["etag"]

    second_request = Request(
        {"type": "http", "headers": [(b"if-none-match", etag.encode())]}
    )
    second = dashboard_data(
        second_request,
        Response(),
        UserIdentity("admin", "admin"),
        test_db,
    )

    assert isinstance(payload, dict)
    assert second.status_code == 304
    assert second.body == b""
    assert second.headers["etag"] == etag


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
