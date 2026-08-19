"""Reasoner - Generates hypotheses and reasons about next steps."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class HypothesisConfidence(str, Enum):
    """Confidence levels for hypotheses."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Hypothesis:
    """A hypothesis about the environment or attack path."""

    statement: str
    confidence: HypothesisConfidence = HypothesisConfidence.MEDIUM
    evidence: list[str] = field(default_factory=list)
    counter_evidence: list[str] = field(default_factory=list)
    suggested_actions: list[str] = field(default_factory=list)
    category: str = "general"  # network, service, vulnerability, credential, objective

    @property
    def net_confidence(self) -> float:
        """Calculate net confidence score."""
        base = {"high": 0.9, "medium": 0.6, "low": 0.3}.get(self.confidence.value, 0.5)
        penalty = len(self.counter_evidence) * 0.1
        bonus = len(self.evidence) * 0.05
        return max(0.0, min(1.0, base - penalty + bonus))


class Reasoner:
    """Generates hypotheses and reasons about attack paths."""

    def __init__(self):
        self._hypotheses: list[Hypothesis] = []
        self._reasoning_chain: list[str] = []

    def observe(self, observation: str) -> None:
        """Record an observation."""
        self._reasoning_chain.append(f"OBSERVE: {observation}")

    def hypothesize(self, state: Any, memory: Any) -> list[Hypothesis]:
        """Generate hypotheses based on current state and memory."""
        hypotheses = []

        # Network hypotheses
        if state.hosts:
            hypotheses.extend(self._hypothesize_network(state))

        # Service hypotheses
        if state.services:
            hypotheses.extend(self._hypothesize_services(state))

        # Vulnerability hypotheses
        if state.vulnerabilities:
            hypotheses.extend(self._hypothesize_vulnerabilities(state))

        # Access hypotheses
        if state.current_access.value not in ["none", "unauthenticated"]:
            hypotheses.extend(self._hypothesize_access(state))

        # Objective hypotheses
        if state.objectives:
            hypotheses.extend(self._hypothesize_objectives(state))

        self._hypotheses = hypotheses
        return hypotheses

    def _hypothesize_network(self, state: Any) -> list[Hypothesis]:
        """Generate network-related hypotheses."""
        hypotheses = []

        # Check for unexplored networks
        discovered_nets = {n.cidr for n in state.networks}
        visited_hosts = set(state.visited_hosts)

        for host in state.hosts:
            if host.ip not in visited_hosts and host.is_alive:
                hypotheses.append(
                    Hypothesis(
                        statement=f"Host {host.ip} ({host.hostname or 'unknown'}) likely has unexplored services",
                        confidence=HypothesisConfidence.HIGH,
                        evidence=[f"Host {host.ip} is alive but not visited"],
                        suggested_actions=[f"Enumerate {host.ip}"],
                        category="network",
                    )
                )

        return hypotheses

    def _hypothesize_services(self, state: Any) -> list[Hypothesis]:
        """Generate service-related hypotheses."""
        hypotheses = []

        for service in state.services:
            if service.service_name in ["ssh", "smb", "http", "https", "rdp"]:
                hypotheses.append(
                    Hypothesis(
                        statement=f"Service {service.service_name} on port {service.port} may have authentication weaknesses",
                        confidence=HypothesisConfidence.MEDIUM,
                        evidence=[f"Service {service.service_name} detected"],
                        suggested_actions=[f"Test authentication on {service.service_name}"],
                        category="service",
                    )
                )

        return hypotheses

    def _hypothesize_vulnerabilities(self, state: Any) -> list[Hypothesis]:
        """Generate vulnerability-related hypotheses."""
        hypotheses = []

        for vuln in state.vulnerabilities:
            if vuln.exploitable and not vuln.exploited:
                hypotheses.append(
                    Hypothesis(
                        statement=f"Vulnerability '{vuln.title}' can be exploited for access",
                        confidence=HypothesisConfidence.MEDIUM,
                        evidence=[f"Vulnerability {vuln.title} marked as exploitable"],
                        suggested_actions=[f"Attempt exploitation of {vuln.title}"],
                        category="vulnerability",
                    )
                )

        return hypotheses

    def _hypothesize_access(self, state: Any) -> list[Hypothesis]:
        """Generate access-related hypotheses."""
        hypotheses = []

        hypotheses.append(
            Hypothesis(
                statement=f"Current access level ({state.current_access.value}) may allow privilege escalation",
                confidence=HypothesisConfidence.MEDIUM,
                evidence=[f"Access level: {state.current_access.value}"],
                suggested_actions=["Check for privilege escalation vectors"],
                category="access",
            )
        )

        return hypotheses

    def _hypothesize_objectives(self, state: Any) -> list[Hypothesis]:
        """Generate objective-related hypotheses."""
        hypotheses = []

        for obj in state.objectives:
            if obj.status != "completed":
                hypotheses.append(
                    Hypothesis(
                        statement=f"Objective '{obj.name}' requires {obj.access_required.value} access",
                        confidence=HypothesisConfidence.HIGH,
                        evidence=[f"Objective {obj.name} status: {obj.status}"],
                        suggested_actions=[f"Work towards objective: {obj.name}"],
                        category="objective",
                    )
                )

        return hypotheses

    def update_hypothesis(
        self,
        hypothesis: Hypothesis,
        new_evidence: Optional[str] = None,
        counter_evidence: Optional[str] = None,
    ) -> None:
        """Update a hypothesis with new evidence."""
        if new_evidence:
            hypothesis.evidence.append(new_evidence)
        if counter_evidence:
            hypothesis.counter_evidence.append(counter_evidence)

    def get_best_hypothesis(self) -> Optional[Hypothesis]:
        """Get the highest-confidence hypothesis."""
        if not self._hypotheses:
            return None
        return max(self._hypotheses, key=lambda h: h.net_confidence)

    def reason(self, question: str, state: Any, memory: Any) -> str:
        """Answer a question by reasoning about state and memory."""
        self._reasoning_chain.append(f"QUESTION: {question}")

        # Build reasoning context
        context = [
            f"Current access: {state.current_access.value}",
            f"Hosts discovered: {state.hosts_discovered}",
            f"Services found: {state.services_discovered}",
            f"Vulnerabilities: {state.vulnerabilities_found}",
            f"Credentials: {state.credentials_found}",
            f"Objectives completed: {state.objectives_completed}/{len(state.objectives)}",
            f"Pivot depth: {state.pivot_depth}/{state.max_pivot_depth}",
        ]

        # Add active hypotheses
        if self._hypotheses:
            context.append("\nActive hypotheses:")
            for h in self._hypotheses[:5]:
                context.append(f"  - [{h.confidence.value}] {h.statement}")

        reasoning = "\n".join(context)
        self._reasoning_chain.append(f"REASONING: {reasoning}")

        return reasoning

    def get_reasoning_chain(self) -> list[str]:
        """Get the full reasoning chain."""
        return self._reasoning_chain.copy()

    def clear_reasoning(self) -> None:
        """Clear the reasoning chain."""
        self._reasoning_chain.clear()
