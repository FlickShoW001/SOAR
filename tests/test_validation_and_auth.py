"""Regression tests for request validation and authentication helpers."""

import base64
import hashlib
import hmac
import json

import pytest
from pydantic import ValidationError

import main


def test_detection_normalizes_event_type_without_changing_raw_evidence():
    request = main.DetectionRequest(
        source_ip="192.168.1.20",
        event_type="  port_scan  ",
        severity=4,
        raw_log_line="  original evidence  ",
    )

    assert request.event_type == "port_scan"
    assert request.raw_log_line == "  original evidence  "


@pytest.mark.parametrize("field", ["event_type", "raw_log_line"])
def test_detection_rejects_whitespace_only_text(field):
    payload = {
        "source_ip": "192.168.1.20",
        "event_type": "port_scan",
        "severity": 3,
        "raw_log_line": "evidence",
    }
    payload[field] = "   \n"

    with pytest.raises(ValidationError):
        main.DetectionRequest(**payload)


def test_rejection_requires_a_meaningful_reason():
    with pytest.raises(ValidationError):
        main.ApprovalRequest(approved=False, rejected_reason="   ")

    request = main.ApprovalRequest(
        approved=False,
        rejected_reason="  Known lab traffic  ",
    )
    assert request.rejected_reason == "Known lab traffic"


def test_malformed_users_json_fails_closed(monkeypatch):
    monkeypatch.setenv("SOAR_USERS_JSON", '[{"username":"unexpected-list"}]')
    users = main._load_users()

    assert users == {
        main.ADMIN_USERNAME: {"password": main.ADMIN_PASSWORD, "role": "admin"}
    }


def test_malformed_user_record_is_ignored(monkeypatch):
    monkeypatch.setenv(
        "SOAR_USERS_JSON",
        json.dumps({"broken": "not-an-object", "reader": {"password": "pw", "role": "viewer"}}),
    )
    users = main._load_users()

    assert "broken" not in users
    assert users["reader"]["role"] == "viewer"


def test_signed_malformed_session_payload_is_rejected():
    encoded = base64.urlsafe_b64encode(b"not-json").decode("ascii").rstrip("=")
    signature = hmac.new(
        main.SESSION_SECRET.encode("utf-8"),
        encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    assert main._read_session_token(f"{encoded}.{signature}") is None


def test_decision_reasoning_parser_fails_closed():
    assert main._parse_decision_reasoning('{"approval_reasons":["high_severity"]}') == {
        "approval_reasons": ["high_severity"]
    }
    assert main._parse_decision_reasoning("not-json") == {}
    assert main._parse_decision_reasoning("[]") == {}
