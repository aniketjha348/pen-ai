"""Findings Engine - Tracks and manages security findings."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


@dataclass
class SecurityFinding:
    """A security finding."""

    id: UUID = field(default_factory=uuid4)
    title: str = ""
    severity: Severity = Severity.INFO
    status: FindingStatus = FindingStatus.OPEN
    description: str = ""
    affected_component: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    references: list[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    confirmed_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class FindingsEngine:
    """Manages security findings throughout the engagement."""

    def __init__(self):
        self._findings: list[SecurityFinding] = []

    def add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        affected_component: str = "",
        evidence: Optional[list[str]] = None,
        remediation: Optional[str] = None,
        cvss_score: Optional[float] = None,
        cve: Optional[str] = None,
        cwe: Optional[str] = None,
    ) -> SecurityFinding:
        """Add a new finding."""
        finding = SecurityFinding(
            title=title,
            severity=severity,
            description=description,
            affected_component=affected_component,
            evidence=evidence or [],
            remediation=remediation,
            cvss_score=cvss_score,
            cve=cve,
            cwe=cwe,
        )
        self._findings.append(finding)
        return finding

    def confirm_finding(self, finding_id: UUID) -> bool:
        """Confirm a finding."""
        for finding in self._findings:
            if finding.id == finding_id:
                finding.status = FindingStatus.CONFIRMED
                finding.confirmed_at = datetime.utcnow()
                return True
        return False

    def mark_false_positive(self, finding_id: UUID) -> bool:
        """Mark a finding as false positive."""
        for finding in self._findings:
            if finding.id == finding_id:
                finding.status = FindingStatus.FALSE_POSITIVE
                return True
        return False

    def add_evidence(self, finding_id: UUID, evidence: str) -> bool:
        """Add evidence to a finding."""
        for finding in self._findings:
            if finding.id == finding_id:
                finding.evidence.append(evidence)
                return True
        return False

    def get_findings(
        self,
        severity: Optional[Severity] = None,
        status: Optional[FindingStatus] = None,
    ) -> list[SecurityFinding]:
        """Get findings with optional filters."""
        results = self._findings

        if severity:
            results = [f for f in results if f.severity == severity]
        if status:
            results = [f for f in results if f.status == status]

        return results

    def get_statistics(self) -> dict:
        """Get finding statistics."""
        stats = {
            "total": len(self._findings),
            "by_severity": {},
            "by_status": {},
        }

        for finding in self._findings:
            # Count by severity
            sev_key = finding.severity.value
            stats["by_severity"][sev_key] = stats["by_severity"].get(sev_key, 0) + 1

            # Count by status
            status_key = finding.status.value
            stats["by_status"][status_key] = stats["by_status"].get(status_key, 0) + 1

        return stats

    def to_report_format(self) -> list[dict]:
        """Convert findings to report format."""
        return [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value,
                "status": f.status.value,
                "description": f.description,
                "affected_component": f.affected_component,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cvss_score": f.cvss_score,
                "cve": f.cve,
                "cwe": f.cwe,
                "discovered_at": f.discovered_at.isoformat(),
            }
            for f in self._findings
        ]
