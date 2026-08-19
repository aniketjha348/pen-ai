"""Scope and Rules of Engagement enforcement."""

import ipaddress
from typing import Optional

from pydantic import BaseModel, Field


class RulesOfEngagement(BaseModel):
    """Defines what PEN-AI is allowed to do."""

    # Target scope
    allowed_networks: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    excluded_ports: list[int] = Field(default_factory=list)

    # Behavior limits
    max_pivots: int = 3
    max_concurrent_actions: int = 5
    require_approval_for_exploitation: bool = True
    require_approval_for_pivoting: bool = True
    max_scan_intensity: str = "normal"  # light, normal, aggressive

    # Evidence requirements
    capture_screenshots: bool = True
    capture_raw_output: bool = True
    capture_commands: bool = True

    # Time limits
    max_engagement_hours: int = 48
    allowed_hours_start: int = 0  # 24h format
    allowed_hours_end: int = 23

    def is_host_allowed(self, ip: str) -> bool:
        """Check if a host is within scope."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        # Check exclusions first
        if ip in self.excluded_hosts:
            return False

        # Check if any allowed network contains this IP
        if not self.allowed_networks:
            return True  # No restrictions = all allowed

        for network_str in self.allowed_networks:
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                if addr in network:
                    return True
            except ValueError:
                continue

        return False

    def is_port_allowed(self, port: int) -> bool:
        """Check if a port is within scope."""
        if port in self.excluded_ports:
            return False

        if not self.allowed_ports:
            return True

        return port in self.allowed_ports

    def can_pivot(self, current_depth: int) -> bool:
        """Check if another pivot is allowed."""
        return current_depth < self.max_pivots

    def can_exploit(self) -> bool:
        """Check if exploitation is allowed."""
        return not self.require_approval_for_exploitation

    def can_pivot_explicit(self) -> bool:
        """Check if pivoting is allowed."""
        return not self.require_approval_for_pivoting


class ScopeValidator:
    """Validates actions against the Rules of Engagement."""

    def __init__(self, roe: RulesOfEngagement):
        self.roe = roe
        self.violations: list[str] = []

    def validate_target(self, target: str) -> tuple[bool, Optional[str]]:
        """Validate a target against scope."""
        if not self.roe.is_host_allowed(target):
            msg = f"Target {target} is out of scope"
            self.violations.append(msg)
            return False, msg
        return True, None

    def validate_port(self, port: int) -> tuple[bool, Optional[str]]:
        """Validate a port against scope."""
        if not self.roe.is_port_allowed(port):
            msg = f"Port {port} is out of scope"
            self.violations.append(msg)
            return False, msg
        return True, None

    def validate_pivot(self, current_depth: int) -> tuple[bool, Optional[str]]:
        """Validate a pivot action."""
        if not self.roe.can_pivot(current_depth):
            msg = f"Maximum pivot depth {self.roe.max_pivots} reached"
            self.violations.append(msg)
            return False, msg
        return True, None

    def validate_exploit(self) -> tuple[bool, Optional[str]]:
        """Validate an exploitation action."""
        if not self.roe.can_exploit():
            msg = "Exploitation requires approval"
            self.violations.append(msg)
            return False, msg
        return True, None

    def get_violations(self) -> list[str]:
        """Get all recorded violations."""
        return self.violations.copy()
