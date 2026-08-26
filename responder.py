"""
Response Connector: Push blocking rules to lab firewall/router via Netmiko.
Only executes after approval gate is cleared.
Validates target against lab allow-list for safety.
Implements dry-run/simulation mode for testing.
"""

import importlib
import ipaddress
import logging
import os

from models import Decision, Event

logger = logging.getLogger(__name__)


def ConnectHandler(**device):
    """Load Netmiko only when a live device connection is requested."""
    try:
        netmiko = importlib.import_module("netmiko")
    except ImportError as exc:
        raise RuntimeError(
            "Live response requires the optional 'netmiko' dependency"
        ) from exc
    return netmiko.ConnectHandler(**device)

# Lab allow-list: IPs/subnets that are permitted to block targets
_LAB_ALLOW_LIST: list[ipaddress.IPv4Network] = []


def init_lab_allowlist(env_csv: str | None = None):
    """
    Initialize lab allow-list from environment variable.

    Comma-separated CIDR blocks, e.g.:
      LAB_ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8

    Args:
        env_csv: Override with explicit CSV (useful for testing)
    """
    global _LAB_ALLOW_LIST
    _LAB_ALLOW_LIST = []

    csv_str = env_csv or os.getenv("LAB_ALLOWED_IPS", "192.168.1.0/24,10.0.0.0/8")

    for cidr in csv_str.split(","):
        cidr = cidr.strip()
        if cidr:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                _LAB_ALLOW_LIST.append(net)
                logger.info(f"Added to lab allow-list: {net}")
            except ValueError as e:
                logger.error(f"Invalid CIDR in allow-list: {cidr}: {e}")

    logger.info(f"Lab allow-list initialized with {len(_LAB_ALLOW_LIST)} networks")


def is_ip_in_lab_allowlist(ip: str) -> bool:
    """
    Check if an IP is in the lab allow-list.

    Args:
        ip: IP address to check

    Returns:
        True if IP is in allow-list, False otherwise
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        for net in _LAB_ALLOW_LIST:
            if ip_obj in net:
                logger.info(f"IP {ip} is in lab allow-list ({net})")
                return True
        logger.warning(f"IP {ip} is NOT in lab allow-list")
        return False
    except ValueError:
        logger.error(f"Invalid IP format: {ip}")
        return False


def execute_response(
    event: Event, decision: Decision, dry_run: bool = True, simulation_mode: bool = True
) -> dict | None:
    """
    Execute response: push block rule to lab device.

    Safety checks:
      1. Only runs after approval or auto-approval
      2. Target IP must be in lab allow-list
      3. Can run in dry-run/simulation mode without touching real device

    Args:
        event: Security event
        decision: Decision to execute
        dry_run: If True, don't connect to real device
        simulation_mode: If True, log what would be sent instead of sending it

    Returns:
        {"status": "success"/"failed", "message": "...", "commands_sent": [...]}
    """

    # Validate action
    if decision.action != "block":
        logger.warning(
            f"Decision action is '{decision.action}', not 'block'; skipping response"
        )
        return {
            "status": "skipped",
            "message": f"Response only executes on 'block' action, got '{decision.action}'",
        }

    if event.status != "responding":
        logger.error("Event %s is not in the claimed responding state", event.id)
        return {
            "status": "failed",
            "message": "Response execution was not safely claimed",
        }

    # Validate target IP against allow-list
    if not is_ip_in_lab_allowlist(event.source_ip):
        logger.error(
            f"Target IP {event.source_ip} not in lab allow-list; blocking execution"
        )
        return {
            "status": "failed",
            "message": f"Target IP {event.source_ip} not in lab allow-list",
        }

    # Generate commands. Unknown device types fail closed rather than reporting
    # a successful simulation for a comment that cannot block anything.
    try:
        commands = _generate_block_commands(event.source_ip)
    except ValueError as exc:
        logger.error("Cannot generate a safe response: %s", exc)
        return {"status": "failed", "message": "Unsupported lab device type"}

    if dry_run or simulation_mode:
        logger.info(f"[SIMULATION] Would execute on {event.source_ip}:")
        for cmd in commands:
            logger.info(f"  > {cmd}")
        return {
            "status": "simulation",
            "message": f"Simulated block of {event.source_ip}",
            "commands_sent": commands,
        }

    # Real execution: connect and push commands
    handler = None
    try:
        device_ip = os.getenv("LAB_DEVICE_IP")
        device_username = os.getenv("LAB_DEVICE_USERNAME")
        device_password = os.getenv("LAB_DEVICE_PASSWORD")
        device_type = os.getenv("LAB_DEVICE_TYPE", "cisco_ios")
        device_port = int(os.getenv("LAB_DEVICE_PORT", "22"))

        if not all([device_ip, device_username, device_password]):
            logger.error("Lab device credentials not fully configured")
            return {
                "status": "failed",
                "message": "Lab device credentials not configured",
            }

        # Final fail-closed safety check immediately before opening a socket.
        if not is_ip_in_lab_allowlist(event.source_ip) or not is_ip_in_lab_allowlist(
            device_ip
        ):
            logger.error("Final lab safety check rejected target or device")
            return {"status": "failed", "message": "Final lab safety check failed"}

        # Connect via Netmiko
        handler = ConnectHandler(
            device_type=device_type,
            host=device_ip,
            username=device_username,
            password=device_password,
            port=device_port,
            timeout=10,
        )

        # Send commands
        output = handler.send_config_set(commands)
        if device_type == "juniper_junos":
            output = f"{output}\n{handler.commit()}"

        logger.info(f"Successfully pushed block rules for {event.source_ip}")
        return {
            "status": "success",
            "message": f"Block rule applied to {event.source_ip}",
            "commands_sent": commands,
            "device_output": output,
        }

    except Exception:
        logger.exception("Failed to connect/push commands")
        return {"status": "failed", "message": "Connection or command execution failed"}
    finally:
        if handler is not None:
            try:
                handler.disconnect()
            except Exception:
                logger.warning(
                    "Failed to disconnect cleanly from lab device", exc_info=True
                )


def _generate_block_commands(source_ip: str) -> list[str]:
    """
    Generate device-specific ACL commands to block an IP.

    Example for Cisco IOS:
      access-list 100 deny ip any host 192.168.1.100
      access-list 100 permit ip any any

    Args:
        source_ip: IP to block

    Returns:
        List of command strings
    """
    device_type = os.getenv("LAB_DEVICE_TYPE", "cisco_ios")

    if device_type == "cisco_ios":
        interface_name = os.getenv(
            "LAB_DEVICE_INTERFACE", "GigabitEthernet0/0"
        )
        return [
            "ip access-list extended SOAR_BLOCK",
            f"deny ip host {source_ip} any",
            "permit ip any any",
            "exit",
            f"interface {interface_name}",
            "ip access-group SOAR_BLOCK in",
            "exit",
        ]

    elif device_type == "juniper_junos":
        interface_name = os.getenv("LAB_DEVICE_INTERFACE", "ge-0/0/0")
        term_name = f"BLOCK_{source_ip.replace('.', '_')}"
        return [
            f"set firewall family inet filter BLOCK_LIST term {term_name} "
            f"from source-address {source_ip}/32",
            f"set firewall family inet filter BLOCK_LIST term {term_name} then discard",
            f"set interfaces {interface_name} unit 0 family inet filter input BLOCK_LIST",
        ]

    else:
        raise ValueError(f"Unsupported device type: {device_type}")
