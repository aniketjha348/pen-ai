"""Report Generator - Generates penetration testing reports."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from core.state.engagement_state import EngagementState, AccessLevel


@dataclass
class Finding:
    """A security finding."""

    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: list[str] = field(default_factory=list)
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    target: Optional[str] = None


class ReportGenerator:
    """Generates penetration testing reports."""

    def __init__(self, state: EngagementState):
        self.state = state
        self._findings: list[Finding] = []
        self._attack_narrative: list[str] = []

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self._findings.append(finding)

    def add_narrative_step(self, step: str) -> None:
        """Add a step to the attack narrative."""
        self._attack_narrative.append(step)

    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        critical = len([f for f in self._findings if f.severity == "critical"])
        high = len([f for f in self._findings if f.severity == "high"])
        medium = len([f for f in self._findings if f.severity == "medium"])
        low = len([f for f in self._findings if f.severity == "low"])

        summary = f"""# Executive Summary

## Engagement Overview
- **Engagement Name:** {self.state.name}
- **Start Date:** {self.state.started_at.strftime('%Y-%m-%d')}
- **End Date:** {datetime.utcnow().strftime('%Y-%m-%d')}

## Key Metrics
- **Hosts Discovered:** {self.state.hosts_discovered}
- **Services Enumerated:** {self.state.services_discovered}
- **Vulnerabilities Found:** {self.state.vulnerabilities_found}
- **Credentials Discovered:** {self.state.credentials_found}
- **Objectives Completed:** {self.state.objectives_completed}/{len(self.state.objectives)}
- **Maximum Access Level:** {self.state.current_access.value}

## Findings Summary
- **Critical:** {critical}
- **High:** {high}
- **Medium:** {medium}
- **Low:** {low}
- **Informational:** {len(self._findings) - critical - high - medium - low}

## Risk Assessment
The engagement identified {len(self._findings)} security findings.
"""
        return summary

    def generate_methodology(self) -> str:
        """Generate methodology section."""
        return """# Methodology

## Approach
This penetration test followed an adaptive, intelligence-driven methodology:

1. **Reconnaissance** - Network discovery and service enumeration
2. **Enumeration** - Detailed service and application analysis
3. **Vulnerability Analysis** - Identification of security weaknesses
4. **Exploitation** - Controlled exploitation of vulnerabilities
5. **Post-Exploitation** - Privilege escalation and lateral movement
6. **Reporting** - Documentation of findings and recommendations

## Tools Used
- PEN-AI Automated Testing Platform
- Nmap for network scanning
- Custom exploit modules
- Post-exploitation frameworks

## Rules of Engagement
- All testing was conducted within authorized scope
- Testing was performed during approved time windows
- All evidence was captured and preserved
"""

    def generate_findings_section(self) -> str:
        """Generate findings section."""
        if not self._findings:
            return "# Findings\n\nNo findings identified.\n"

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self._findings,
            key=lambda f: severity_order.get(f.severity, 5),
        )

        section = "# Technical Findings\n\n"

        for i, finding in enumerate(sorted_findings, 1):
            section += f"""## {i}. {finding.title}

**Severity:** {finding.severity.upper()}
**CVSS Score:** {finding.cvss_score or 'N/A'}
**CVE:** {finding.cve or 'N/A'}
**Target:** {finding.target or 'N/A'}

### Description
{finding.description}

### Evidence
"""
            for evidence in finding.evidence:
                section += f"- {evidence}\n"

            if finding.remediation:
                section += f"\n### Remediation\n{finding.remediation}\n"

            section += "\n---\n\n"

        return section

    def generate_attack_narrative(self) -> str:
        """Generate attack narrative."""
        if not self._attack_narrative:
            return "# Attack Narrative\n\nNo attack narrative available.\n"

        narrative = "# Attack Timeline\n\n"

        for i, step in enumerate(self._attack_narrative, 1):
            narrative += f"{i}. {step}\n"

        return narrative

    def generate_recommendations(self) -> str:
        """Generate recommendations section."""
        recommendations = []

        # Generate recommendations based on findings
        for finding in self._findings:
            if finding.severity in ["critical", "high"]:
                recommendations.append(f"- **{finding.title}:** {finding.remediation or 'Address immediately'}")

        if not recommendations:
            recommendations = ["- Continue monitoring security posture"]

        section = "# Recommendations\n\n## Priority Actions\n\n"
        section += "\n".join(recommendations)

        section += """

## General Recommendations
1. Implement network segmentation
2. Enable multi-factor authentication
3. Regular security assessments
4. Security awareness training
5. Incident response planning
"""
        return section

    def generate_full_report(self) -> str:
        """Generate complete report."""
        report = f"""# Penetration Test Report

**{self.state.name}**

**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}

---

{self.generate_executive_summary()}

---

{self.generate_methodology()}

---

{self.generate_findings_section()}

---

{self.generate_attack_narrative()}

---

{self.generate_recommendations()}

---

*Report generated by PEN-AI*
"""
        return report

    def to_json(self) -> dict:
        """Export report as JSON."""
        return {
            "engagement": {
                "name": self.state.name,
                "start_date": self.state.started_at.isoformat(),
                "end_date": datetime.utcnow().isoformat(),
            },
            "summary": {
                "hosts_discovered": self.state.hosts_discovered,
                "services_found": self.state.services_discovered,
                "vulnerabilities": self.state.vulnerabilities_found,
                "credentials": self.state.credentials_found,
                "objectives_completed": self.state.objectives_completed,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in self._findings
            ],
            "narrative": self._attack_narrative,
        }
