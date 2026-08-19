"""Planner - Generates and ranks candidate actions.

No hardcoded tool assignments. The LLM decides what tools to use.
This module provides contextual action suggestions based on current state.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ActionPriority(str, Enum):
    """Priority levels for actions."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ActionType(str, Enum):
    """Types of actions PEN-AI can take."""

    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    PIVOT = "pivot"
    ESCALATE = "escalate"
    EXPLORE = "explore"
    OBJECTIVE = "objective"
    EVIDENCE = "evidence"
    REPORT = "report"


@dataclass
class CandidateAction:
    """A candidate action the AI is considering."""

    name: str
    action_type: ActionType
    description: str
    priority: ActionPriority = ActionPriority.MEDIUM
    confidence: float = 0.5  # 0-1
    information_gain: float = 0.5  # Expected new info
    objective_relevance: float = 0.0  # How relevant to objectives
    prerequisites: list[str] = field(default_factory=list)
    tool_name: Optional[str] = None
    parameters: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    estimated_duration: str = "unknown"
    risk_level: str = "low"  # low, medium, high

    @property
    def score(self) -> float:
        """Calculate overall action score."""
        priority_weights = {
            ActionPriority.CRITICAL: 1.0,
            ActionPriority.HIGH: 0.8,
            ActionPriority.MEDIUM: 0.5,
            ActionPriority.LOW: 0.2,
        }
        priority_score = priority_weights.get(self.priority, 0.5)

        return (
            priority_score * 0.3
            + self.confidence * 0.2
            + self.information_gain * 0.3
            + self.objective_relevance * 0.2
        )


class Planner:
    """Generates and ranks candidate actions based on current state.

    No hardcoded tool assignments - the LLM decides what tools to use
    based on the action context and current state.
    """

    def __init__(self):
        self._history: list[CandidateAction] = []

    def generate_actions(
        self,
        state: Any,
        memory: Any,
        available_tools: list[str],
    ) -> list[CandidateAction]:
        """Generate candidate actions based on current state.

        Actions describe WHAT to accomplish, not HOW (no fixed tools).
        The LLM interprets these actions and chooses appropriate tools.
        """
        actions = []

        # Discovery actions (if few hosts discovered)
        if state.hosts_discovered < 3:
            actions.append(CandidateAction(
                name="host_discovery",
                action_type=ActionType.RECON,
                description="Discover live hosts in the target network",
                priority=ActionPriority.HIGH,
                confidence=0.9,
                information_gain=0.8,
                reasoning="Need to identify all live hosts before enumeration",
            ))

            actions.append(CandidateAction(
                name="network_mapping",
                action_type=ActionType.RECON,
                description="Map network topology and routing",
                priority=ActionPriority.MEDIUM,
                confidence=0.8,
                information_gain=0.7,
                reasoning="Understanding network layout helps plan attack paths",
            ))

        # Enumeration actions (for discovered hosts)
        for host in state.hosts:
            if host.ip not in state.visited_hosts:
                actions.append(CandidateAction(
                    name=f"enumerate_{host.ip}",
                    action_type=ActionType.ENUMERATE,
                    description=f"Enumerate services on {host.ip}",
                    priority=ActionPriority.HIGH,
                    confidence=0.8,
                    information_gain=0.7,
                    parameters={"target": host.ip},
                    reasoning=f"Host {host.ip} discovered but not yet enumerated",
                ))

        # Exploitation actions (if vulnerabilities found)
        for vuln in state.vulnerabilities:
            if vuln.exploitable and not vuln.exploited:
                actions.append(CandidateAction(
                    name=f"exploit_{vuln.title}",
                    action_type=ActionType.EXPLOIT,
                    description=f"Attempt exploitation: {vuln.title}",
                    priority=ActionPriority.HIGH if vuln.severity == "critical" else ActionPriority.MEDIUM,
                    confidence=0.6,
                    information_gain=0.9,
                    objective_relevance=0.8,
                    parameters={"vulnerability_id": str(vuln.id)},
                    reasoning=f"Vulnerability {vuln.title} is exploitable",
                ))

        # Post-exploitation actions (if access gained)
        if state.current_access.value not in ["none", "unauthenticated"]:
            actions.append(CandidateAction(
                name="system_enumeration",
                action_type=ActionType.POST_EXPLOIT,
                description="Enumerate system info, users, processes on compromised host",
                priority=ActionPriority.HIGH,
                confidence=0.9,
                information_gain=0.8,
                reasoning="Need to understand compromised system",
            ))

            actions.append(CandidateAction(
                name="credential_harvest",
                action_type=ActionType.POST_EXPLOIT,
                description="Search for credentials on compromised system",
                priority=ActionPriority.HIGH,
                confidence=0.7,
                information_gain=0.9,
                objective_relevance=0.7,
                reasoning="Credentials enable lateral movement",
            ))

        # Pivoting actions (if deeper networks reachable)
        if state.pivot_depth < state.max_pivot_depth:
            actions.append(CandidateAction(
                name="network_discovery_from_host",
                action_type=ActionType.EXPLORE,
                description="Discover networks reachable from compromised host",
                priority=ActionPriority.MEDIUM,
                confidence=0.7,
                information_gain=0.8,
                reasoning="Compromised host may reveal hidden networks",
            ))

        # Objective-focused actions
        for obj in state.objectives:
            if obj.status != "completed":
                actions.append(CandidateAction(
                    name=f"objective_{obj.name}",
                    action_type=ActionType.OBJECTIVE,
                    description=f"Work on objective: {obj.name}",
                    priority=ActionPriority.HIGH,
                    confidence=0.5,
                    information_gain=0.3,
                    objective_relevance=1.0,
                    reasoning=f"Objective {obj.name} still incomplete",
                ))

        # Sort by score
        actions.sort(key=lambda a: a.score, reverse=True)

        return actions

    def record_action(self, action: CandidateAction) -> None:
        """Record an action taken for learning."""
        self._history.append(action)

    def get_history(self) -> list[CandidateAction]:
        """Get action history."""
        return self._history.copy()

    def get_failed_patterns(self) -> list[str]:
        """Analyze history for failed action patterns."""
        return []
