"""Engagement State - Live digital twin of the target environment."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AccessLevel(str, Enum):
    """Access levels PEN-AI can achieve."""

    NONE = "none"
    UNAUTHENTICATED = "unauthenticated"
    LOW_USER = "low_user"
    USER = "user"
    PRIVILEGED = "privileged"
    ADMIN = "admin"
    SYSTEM = "system"
    DOMAIN_ADMIN = "domain_admin"


class NetworkSegment(BaseModel):
    """Represents a discovered network segment."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    cidr: str
    gateway: Optional[str] = None
    vlan_id: Optional[int] = None
    zone: str = "unknown"  # dmz, internal, restricted, management
    reachable_from: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Host(BaseModel):
    """Represents a discovered host."""

    id: UUID = Field(default_factory=uuid4)
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    mac_address: Optional[str] = None
    network_segment: Optional[str] = None
    is_alive: bool = True
    services: list["Service"] = Field(default_factory=list)
    access_level: AccessLevel = AccessLevel.NONE
    credentials: list["Credential"] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"json_encoders": {UUID: str}}


class Service(BaseModel):
    """Represents a discovered service on a host."""

    id: UUID = Field(default_factory=uuid4)
    host_id: UUID
    port: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    scripts: dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Credential(BaseModel):
    """Represents discovered credentials."""

    id: UUID = Field(default_factory=uuid4)
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    hash_type: Optional[str] = None
    credential_type: str = "password"  # password, hash, key, token
    source: Optional[str] = None
    target: Optional[str] = None
    domain: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability."""

    id: UUID = Field(default_factory=uuid4)
    host_id: UUID
    service_id: Optional[UUID] = None
    title: str
    description: Optional[str] = None
    severity: str = "unknown"  # info, low, medium, high, critical
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    evidence: Optional[str] = None
    exploitable: bool = False
    exploited: bool = False
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class PivotPoint(BaseModel):
    """Represents an established pivot."""

    id: UUID = Field(default_factory=uuid4)
    source_host: str
    destination_network: str
    method: str  # ssh_tunnel, proxy, socks, etc.
    local_port: Optional[int] = None
    remote_port: Optional[int] = None
    status: str = "active"  # active, failed, closed
    evidence_event_id: Optional[UUID] = None
    established_at: datetime = Field(default_factory=datetime.utcnow)


class Objective(BaseModel):
    """Represents an objective/flag to capture."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    target: Optional[str] = None
    requirement: Optional[str] = None
    access_required: AccessLevel = AccessLevel.NONE
    status: str = "discovered"  # discovered, in_progress, completed, failed
    flag: Optional[str] = None
    flag_validated: bool = False
    evidence_events: list[UUID] = Field(default_factory=list)
    completed_at: Optional[datetime] = None


class EngagementState(BaseModel):
    """The complete live state of the engagement."""

    id: UUID = Field(default_factory=uuid4)
    name: str = "Enterprise Engagement"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    # Environment model
    networks: list[NetworkSegment] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    pivot_points: list[PivotPoint] = Field(default_factory=list)
    objectives: list[Objective] = Field(default_factory=list)

    # Current state
    current_host: Optional[str] = None
    current_access: AccessLevel = AccessLevel.NONE
    current_network: Optional[str] = None
    pivot_depth: int = 0
    max_pivot_depth: int = 3

    # Statistics
    hosts_discovered: int = 0
    services_discovered: int = 0
    vulnerabilities_found: int = 0
    credentials_found: int = 0
    objectives_completed: int = 0

    # History
    visited_hosts: list[str] = Field(default_factory=list)
    failed_actions: list[dict[str, Any]] = Field(default_factory=list)

    def add_host(self, host: Host) -> None:
        """Add a host to the state."""
        self.hosts.append(host)
        self.hosts_discovered += 1
        self.last_updated = datetime.utcnow()

    def add_service(self, service: Service) -> None:
        """Add a service to the state."""
        self.services.append(service)
        self.services_discovered += 1
        self.last_updated = datetime.utcnow()

    def add_credential(self, credential: Credential) -> None:
        """Add a credential to the state."""
        self.credentials.append(credential)
        self.credentials_found += 1
        self.last_updated = datetime.utcnow()

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to the state."""
        self.vulnerabilities.append(vuln)
        self.vulnerabilities_found += 1
        self.last_updated = datetime.utcnow()

    def add_pivot(self, pivot: PivotPoint) -> None:
        """Add a pivot point to the state."""
        self.pivot_points.append(pivot)
        self.pivot_depth += 1
        self.last_updated = datetime.utcnow()

    def add_objective(self, objective: Objective) -> None:
        """Add an objective to the state."""
        self.objectives.append(objective)
        self.last_updated = datetime.utcnow()

    def get_host_by_ip(self, ip: str) -> Optional[Host]:
        """Get a host by IP address."""
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def get_services_for_host(self, host_id: UUID) -> list[Service]:
        """Get all services for a specific host."""
        return [s for s in self.services if s.host_id == host_id]

    def get_credentials_for_host(self, host_id: UUID) -> list[Credential]:
        """Get all credentials for a specific host."""
        return [c for c in self.credentials if c.target and c.target == str(host_id)]

    def record_failure(self, action: str, reason: str) -> None:
        """Record a failed action for learning."""
        self.failed_actions.append({
            "action": action,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.last_updated = datetime.utcnow()

    def mark_host_visited(self, ip: str) -> None:
        """Mark a host as visited."""
        if ip not in self.visited_hosts:
            self.visited_hosts.append(ip)
            self.last_updated = datetime.utcnow()

    def to_summary(self) -> str:
        """Generate a human-readable summary of the current state."""
        return f"""
=== Engagement State Summary ===
Hosts Discovered: {self.hosts_discovered}
Services Found: {self.services_discovered}
Vulnerabilities: {self.vulnerabilities_found}
Credentials Found: {self.credentials_found}
Objectives Completed: {self.objectives_completed}/{len(self.objectives)}
Current Access: {self.current_access.value}
Pivot Depth: {self.pivot_depth}/{self.max_pivot_depth}
Hosts Visited: {len(self.visited_hosts)}
Failed Actions: {len(self.failed_actions)}
================================
"""
