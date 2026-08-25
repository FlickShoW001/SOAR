"""Fail-closed response connector tests."""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from responder import _generate_block_commands, execute_response, init_lab_allowlist


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

    @patch.dict(os.environ, {"LAB_DEVICE_TYPE": "cisco_ios"})
    def test_cisco_acl_preserves_non_blocked_traffic(self):
        commands = _generate_block_commands("192.168.1.20")
        self.assertIn("deny ip host 192.168.1.20 any", commands)
        self.assertIn("permit ip any any", commands)
        self.assertNotIn("no deny ip host 192.168.1.20 any", commands)

    @patch.dict(os.environ, {"LAB_DEVICE_TYPE": "juniper_junos"})
    def test_juniper_filter_matches_the_source_address(self):
        commands = _generate_block_commands("192.168.1.20")
        self.assertTrue(any("source-address 192.168.1.20/32" in c for c in commands))
        self.assertFalse(any("destination-address" in c for c in commands))
        self.assertTrue(any("term BLOCK_192_168_1_20" in c for c in commands))

    @patch.dict(
        os.environ,
        {
            "LAB_DEVICE_IP": "192.168.1.1",
            "LAB_DEVICE_USERNAME": "lab-user",
            "LAB_DEVICE_PASSWORD": "lab-password",
            "LAB_DEVICE_TYPE": "juniper_junos",
        },
    )
    def test_juniper_changes_are_committed(self):
        event = SimpleNamespace(id=1, status="responding", source_ip="192.168.1.20")
        handler = Mock()
        handler.send_config_set.return_value = "configured"
        handler.commit.return_value = "committed"
        with patch("responder.ConnectHandler", return_value=handler):
            result = execute_response(
                event, self.decision, dry_run=False, simulation_mode=False
            )
        self.assertEqual(result["status"], "success")
        handler.commit.assert_called_once_with()

    @patch.dict(os.environ, {"LAB_DEVICE_TYPE": "unsupported_os"})
    def test_unknown_device_type_fails_closed(self):
        event = SimpleNamespace(id=1, status="responding", source_ip="192.168.1.20")
        with patch("responder.ConnectHandler") as connector:
            result = execute_response(event, self.decision)
        self.assertEqual(result["status"], "failed")
        connector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
