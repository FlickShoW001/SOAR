"""Fail-closed response connector tests."""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from responder import execute_response, init_lab_allowlist


class ResponderSecurityTests(unittest.TestCase):
    def setUp(self):
        init_lab_allowlist("192.168.1.0/24")
        self.decision = SimpleNamespace(action="block")

    def test_unclaimed_event_cannot_execute(self):
        event = SimpleNamespace(id=1, status="approved", source_ip="192.168.1.20")
        result = execute_response(event, self.decision)
        self.assertEqual(result["status"], "failed")

    def test_non_lab_target_never_reaches_connector(self):
        event = SimpleNamespace(id=1, status="responding", source_ip="8.8.8.8")
        with patch("responder.ConnectHandler") as connector:
            result = execute_response(
                event, self.decision, dry_run=False, simulation_mode=False
            )
        self.assertEqual(result["status"], "failed")
        connector.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "LAB_DEVICE_IP": "192.168.1.1",
            "LAB_DEVICE_USERNAME": "lab-user",
            "LAB_DEVICE_PASSWORD": "lab-password",
        },
    )
    def test_disconnect_runs_when_command_execution_fails(self):
        event = SimpleNamespace(id=1, status="responding", source_ip="192.168.1.20")
        handler = Mock()
        handler.send_config_set.side_effect = RuntimeError("device failure")
        with patch("responder.ConnectHandler", return_value=handler):
            result = execute_response(
                event, self.decision, dry_run=False, simulation_mode=False
            )
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("device failure", result["message"])
        handler.disconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
