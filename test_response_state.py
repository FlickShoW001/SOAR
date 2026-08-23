"""Focused tests for mapping responder outcomes to persistent event states."""

from types import SimpleNamespace

from fastapi import HTTPException
from pydantic import ValidationError

from main import (
    DetectionRequest,
    UserIdentity,
    _create_session_token,
    _credentials_are_valid,
    _read_session_token,
    apply_response_result,
    require_operator,
    require_viewer,
)


def test_success_is_responded():
    event = SimpleNamespace(status="approved")
    assert apply_response_result(event, {"status": "success"}) == (
        "responded",
        "Response executed",
    )


def test_simulation_is_responded():
    event = SimpleNamespace(status="approved")
    assert apply_response_result(event, {"status": "simulation"}) == (
        "responded",
        "Response simulated",
    )


def test_skipped_is_closed():
    event = SimpleNamespace(status="approved")
    assert apply_response_result(event, {"status": "skipped"}) == (
        "closed",
        "No response action was required",
    )


def test_failure_is_not_responded():
    event = SimpleNamespace(status="approved")
    assert apply_response_result(event, {"status": "failed"}) == (
        "response_failed",
        "Response failed",
    )


def test_unknown_result_fails_closed():
    event = SimpleNamespace(status="approved")
    assert apply_response_result(event, {}) == (
        "response_failed",
        "Response failed",
    )


def test_detection_rejects_out_of_range_severity():
    try:
        DetectionRequest(
            source_ip="8.8.8.8",
            event_type="test",
            severity=10,
            raw_log_line="test event",
        )
    except ValidationError:
        return
    raise AssertionError("severity 10 should be rejected")


def test_detection_rejects_invalid_ip():
    try:
        DetectionRequest(
            source_ip="not-an-ip",
            event_type="test",
            severity=3,
            raw_log_line="test event",
        )
    except ValidationError:
        return
    raise AssertionError("invalid source IP should be rejected")


def test_detection_rejects_naive_timestamp():
    try:
        DetectionRequest(
            source_ip="192.168.1.20",
            event_type="test",
            severity=3,
            raw_log_line="test event",
            timestamp="2026-08-24T02:00:00",
        )
    except ValidationError:
        return
    raise AssertionError("timestamp without timezone should be rejected")


def test_default_dashboard_credentials_authenticate():
    assert _credentials_are_valid("admin", "admin")


def test_invalid_dashboard_credentials_are_rejected():
    assert not _credentials_are_valid("admin", "wrong")


def test_signed_dashboard_session_round_trip():
    token = _create_session_token("admin")
    identity = _read_session_token(token)
    assert identity.username == "admin"
    assert identity.role == "admin"


def test_tampered_dashboard_session_is_rejected():
    token = _create_session_token("admin")
    assert _read_session_token(token + "tampered") is None


def test_login_page_route_is_available():
    from main import app

    login_routes = [route for route in app.routes if route.path == "/login"]
    assert any("GET" in route.methods for route in login_routes)
    assert any("POST" in route.methods for route in login_routes)


def test_viewer_role_is_read_only():
    viewer = UserIdentity("viewer1", "viewer")
    assert require_viewer(viewer) == viewer
    try:
        require_operator(viewer)
    except HTTPException as exc:
        assert exc.status_code == 403
        return
    raise AssertionError("viewer should not receive operator permissions")
