"""Event system models for PEN-AI."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Types of events PEN-AI tracks."""

    # Recon events
    HOST_DISCOVERED = "host_discovered"
    PORT_OPEN = "port_open"
    SERVICE_FOUND = "service_found"
    OS_IDENTIFIED = "os_identified"
    DNS_RESOLVED = "dns_resolved"

    # Access events
    CREDENTIAL_FOUND = "credential_found"
    ACCESS_GAINED = "access_gained"
    PRIVILEGE_ESCALATED = "privilege_escalated"

    # Exploitation events
    VULNERABILITY_FOUND = "vulnerability_found"
    EXPLOIT_ATTEMPTED = "exploit_attempted"
    EXPLOIT_SUCCESS = "exploit_success"
    EXPLOIT_FAILED = "exploit_failed"

    # Network events
    NETWORK_DISCOVERED = "network_discovered"
    PIVOT_ESTABLISHED = "pivot_established"
    PIVOT_FAILED = "pivot_failed"

    # Objective events
    OBJECTIVE_DISCOVERED = "objective_discovered"
    OBJECTIVE_COMPLETED = "objective_completed"
    FLAG_CAPTURED = "flag_captured"

    # Tool events
    TOOL_CALLED = "tool_called"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    # System events
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    AGENT_ERROR = "agent_error"
    STATE_UPDATED = "state_updated"
    REPLAN_TRIGGERED = "replan_triggered"


class Event(BaseModel):
    """Represents a single event in the engagement."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: EventType
    target: Optional[str] = None
    range_type: Optional[str] = None  # ad, web, binary, iot, ctf
    tool: Optional[str] = None
    action: str
    command: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    screenshot: Optional[str] = None
    artifact: Optional[str] = None
    finding: Optional[str] = None
    parent_event_id: Optional[UUID] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"json_encoders": {UUID: str, datetime: str}}


class EventChain(BaseModel):
    """A chain of related events forming an attack path."""

    id: UUID = Field(default_factory=uuid4)
    events: list[Event] = Field(default_factory=list)
    description: str = ""
    evidence_refs: list[str] = Field(default_factory=list)

    def add_event(self, event: Event) -> None:
        """Add an event to the chain."""
        if self.events:
            event.parent_event_id = self.events[-1].id
        self.events.append(event)

    @property
    def duration(self) -> float:
        """Calculate duration of the event chain in seconds."""
        if len(self.events) < 2:
            return 0.0
        start = self.events[0].timestamp
        end = self.events[-1].timestamp
        return (end - start).total_seconds()
