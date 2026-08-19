"""HTML Report Generator - Professional Penetration Test Reports.

Follows industry-standard pentest report format:
1. Target Identified - with command output evidence
2. Enumeration - with nmap/web/AD enumeration evidence
3. Vulnerability Identified - with vulnerability evidence
4. Exploitation - with exploitation evidence
5. Access Obtained - with proof-of-access
6. Privilege Escalation - with proof
7. Sensitive Data / Objective Achieved - with evidence
8. Remediation - with written recommendations
"""

import json
import html
from datetime import datetime
from typing import Any, Optional


class HTMLReportGenerator:
    """Generate professional penetration test reports."""

    def __init__(self, title: str = "Penetration Test Report"):
        self.title = title
        self.target = ""
        self.scope = ""
        self.session_id = ""
        self.start_time = None
        self.end_time = None

        # Report sections (in order)
        self.phases = {
            "target_identified": [],
            "enumeration": [],
            "vulnerability_identified": [],
            "exploitation": [],
            "access_obtained": [],
            "privilege_escalation": [],
            "sensitive_data": [],
            "remediation": [],
        }

        # Raw data
        self.hosts = []
        self.services = {}
        self.credentials = []
        self.access_map = {}
        self.pivoted = []
        self.commands_run = []
        self.findings = []

    def load_from_state(self, state: dict):
        """Load data from engagement state."""
        self.target = state.get("target", "")
        self.scope = state.get("scope", self.target)
        self.session_id = state.get("session_id", "")
        self.hosts = state.get("known_hosts", [])
        self.services = state.get("known_services", {})
        self.credentials = state.get("credentials", [])
        self.access_map = state.get("access_map", {})
        self.pivoted = state.get("pivoted_networks", [])
        self.commands_run = state.get("commands_run", [])

    def add_evidence(self, phase: str, title: str, command: str, output: str,
                     severity: str = "info", notes: str = ""):
        """Add evidence to a specific phase."""
        if phase in self.phases:
            self.phases[phase].append({
                "title": title,
                "command": command,
                "output": output[:5000],  # Limit output size
                "severity": severity,
                "notes": notes,
                "timestamp": datetime.now().isoformat(),
            })

    def add_finding(self, title: str, severity: str, description: str,
                    evidence: str = "", remediation: str = ""):
        """Add a finding with remediation."""
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat(),
        })

    def generate_html(self) -> str:
        """Generate the professional pentest report."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        total_svcs = sum(len(v) for v in self.services.values())
        duration = ""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            mins = int(delta.total_seconds() / 60)
            duration = f"{mins} minutes"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 40px; border-radius: 10px; margin-bottom: 30px; border: 1px solid #333; }}
        .header h1 {{ color: #ff4444; font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ color: #888; font-size: 1.1em; }}
        .header .meta {{ display: flex; gap: 20px; margin-top: 20px; flex-wrap: wrap; }}
        .header .meta span {{ background: #1a1a2e; padding: 8px 16px; border-radius: 5px; border: 1px solid #333; font-size: 0.9em; }}

        /* Sections */
        .section {{ background: #111; padding: 30px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #222; }}
        .section h2 {{ color: #ff6666; font-size: 1.5em; margin-bottom: 20px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .section h3 {{ color: #44aaff; font-size: 1.2em; margin: 15px 0 10px 0; }}

        /* Evidence blocks */
        .evidence {{ background: #0a0a0a; border: 1px solid #333; border-radius: 8px; margin: 15px 0; overflow: hidden; }}
        .evidence-header {{ background: #1a1a2e; padding: 10px 15px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; }}
        .evidence-title {{ color: #44aaff; font-weight: 600; }}
        .evidence-severity {{ padding: 2px 10px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }}
        .evidence-severity.critical {{ background: #ff4444; color: white; }}
        .evidence-severity.high {{ background: #ff8800; color: white; }}
        .evidence-severity.medium {{ background: #ffcc00; color: black; }}
        .evidence-severity.low {{ background: #44aaff; color: white; }}
        .evidence-severity.info {{ background: #44ff44; color: black; }}
        .evidence-command {{ background: #111; padding: 10px 15px; font-family: monospace; font-size: 0.9em; color: #44ff44; border-bottom: 1px solid #222; }}
        .evidence-output {{ background: #0a0a0a; padding: 15px; font-family: monospace; font-size: 0.85em; color: #aaa; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }}
        .evidence-notes {{ background: #1a1a2e; padding: 10px 15px; font-size: 0.9em; color: #888; border-top: 1px solid #333; }}

        /* Stats */
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        .stat .label {{ color: #888; font-size: 0.9em; margin-top: 5px; }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #1a1a2e; color: #ff6666; font-weight: 600; }}
        tr:hover {{ background: #1a1a2e; }}

        /* Remediation */
        .remediation {{ background: #1a2e1a; border: 1px solid #2a4a2a; border-radius: 8px; padding: 15px; margin: 10px 0; }}
        .remediation h4 {{ color: #44ff44; margin-bottom: 10px; }}
        .remediation p {{ color: #88ff88; }}

        /* Footer */
        .footer {{ text-align: center; padding: 30px; color: #666; font-size: 0.9em; margin-top: 30px; }}

        /* TOC */
        .toc {{ background: #1a1a2e; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333; }}
        .toc h3 {{ color: #ff6666; margin-bottom: 15px; }}
        .toc ul {{ list-style: none; }}
        .toc li {{ padding: 5px 0; }}
        .toc a {{ color: #44aaff; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}

        /* Phase numbers */
        .phase-number {{ display: inline-block; background: #ff4444; color: white; width: 30px; height: 30px; border-radius: 50%; text-align: center; line-height: 30px; margin-right: 10px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <h1>🎯 {self.title}</h1>
            <div class="subtitle">Professional Penetration Test Report</div>
            <div class="meta">
                <span>🎯 Target: {self.target}</span>
                <span>📋 Scope: {self.scope}</span>
                <span>🔑 Session: {self.session_id}</span>
                <span>📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                <span>⏱️ Duration: {duration}</span>
                <span>💻 Commands: {len(self.commands_run)}</span>
            </div>
        </div>

        <!-- TABLE OF CONTENTS -->
        <div class="toc">
            <h3>📑 Table of Contents</h3>
            <ul>
                <li><a href="#executive-summary">Executive Summary</a></li>
                <li><a href="#phase1">1. Target Identified</a></li>
                <li><a href="#phase2">2. Enumeration</a></li>
                <li><a href="#phase3">3. Vulnerability Identified</a></li>
                <li><a href="#phase4">4. Exploitation</a></li>
                <li><a href="#phase5">5. Access Obtained</a></li>
                <li><a href="#phase6">6. Privilege Escalation</a></li>
                <li><a href="#phase7">7. Sensitive Data / Objective Achieved</a></li>
                <li><a href="#phase8">8. Remediation</a></li>
            </ul>
        </div>

        <!-- EXECUTIVE SUMMARY -->
        <div class="section" id="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="number" style="color: #ff4444;">{severity_counts['critical']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #ff8800;">{severity_counts['high']}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #ffcc00;">{severity_counts['medium']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #44aaff;">{severity_counts['low']}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #44ff44;">{severity_counts['info']}</div>
                    <div class="label">Info</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #44aaff;">{len(self.hosts)}</div>
                    <div class="label">Hosts</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #44aaff;">{total_svcs}</div>
                    <div class="label">Services</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #ff4444;">{len(self.credentials)}</div>
                    <div class="label">Credentials</div>
                </div>
            </div>
        </div>
"""

        # PHASE 1: Target Identified
        html_content += self._render_phase(
            "phase1",
            "1. Target Identified",
            "target_identified",
            "Initial target identification and reconnaissance."
        )

        # Add hosts if no evidence
        if not self.phases["target_identified"] and self.hosts:
            html_content += f"""
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">Hosts Discovered</span>
                    <span class="evidence-severity info">INFO</span>
                </div>
                <div class="evidence-output">"""
            for h in self.hosts:
                html_content += f"\n{h}"
            html_content += """
                </div>
            </div>
"""

        # PHASE 2: Enumeration
        html_content += self._render_phase(
            "phase2",
            "2. Enumeration",
            "enumeration",
            "Service enumeration and information gathering."
        )

        # Add services if no evidence
        if not self.phases["enumeration"] and self.services:
            html_content += """
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">Services Discovered</span>
                    <span class="evidence-severity info">INFO</span>
                </div>
                <div class="evidence-output">"""
            for host, svcs in self.services.items():
                html_content += f"\n\nHost: {host}"
                for svc in svcs:
                    html_content += f"\n  {svc.get('port', '?')}/{svc.get('service', '?')} {svc.get('version', '')}"
            html_content += """
                </div>
            </div>
"""

        # PHASE 3: Vulnerability Identified
        html_content += self._render_phase(
            "phase3",
            "3. Vulnerability Identified",
            "vulnerability_identified",
            "Vulnerabilities discovered during testing."
        )

        # Add findings as vulnerabilities
        for f in self.findings:
            if f.get("severity") in ["critical", "high", "medium"]:
                html_content += f"""
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">{html.escape(f.get('title', ''))}</span>
                    <span class="evidence-severity {f.get('severity', 'info')}">{f.get('severity', 'info').upper()}</span>
                </div>
                <div class="evidence-output">{html.escape(f.get('description', ''))}</div>
                {f'<div class="evidence-notes">Evidence: {html.escape(f.get("evidence", ""))}</div>' if f.get('evidence') else ''}
            </div>
"""

        # PHASE 4: Exploitation
        html_content += self._render_phase(
            "phase4",
            "4. Exploitation",
            "exploitation",
            "Exploitation attempts and results."
        )

        # PHASE 5: Access Obtained
        html_content += self._render_phase(
            "phase5",
            "5. Access Obtained",
            "access_obtained",
            "Proof of access gained."
        )

        # Add access map
        if self.access_map:
            html_content += """
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">Access Levels Achieved</span>
                    <span class="evidence-severity critical">CRITICAL</span>
                </div>
                <div class="evidence-output">"""
            for host, level in self.access_map.items():
                html_content += f"\n{host}: {level}"
            html_content += """
                </div>
            </div>
"""

        # PHASE 6: Privilege Escalation
        html_content += self._render_phase(
            "phase6",
            "6. Privilege Escalation",
            "privilege_escalation",
            "Privilege escalation attempts and results."
        )

        # PHASE 7: Sensitive Data
        html_content += self._render_phase(
            "phase7",
            "7. Sensitive Data / Objective Achieved",
            "sensitive_data",
            "Sensitive data discovered and objectives achieved."
        )

        # Add credentials
        if self.credentials:
            html_content += """
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">Credentials Discovered</span>
                    <span class="evidence-severity critical">CRITICAL</span>
                </div>
                <div class="evidence-output">"""
            for c in self.credentials:
                html_content += f"\n[{c.get('type', '?')}] {c.get('username', '?')}: {str(c.get('value', ''))[:50]}"
            html_content += """
                </div>
            </div>
"""

        # PHASE 8: Remediation
        html_content += """
        <div class="section" id="phase8">
            <h2><span class="phase-number">8</span> Remediation</h2>
            <p>Recommendations to address identified vulnerabilities.</p>
"""

        # Add remediation for each finding
        for f in self.findings:
            if f.get("remediation"):
                html_content += f"""
            <div class="remediation">
                <h4>{html.escape(f.get('title', ''))} ({f.get('severity', 'info').upper()})</h4>
                <p>{html.escape(f.get('remediation', ''))}</p>
            </div>
"""

        # Generic remediation if none specific
        if not any(f.get("remediation") for f in self.findings):
            html_content += """
            <div class="remediation">
                <h4>General Recommendations</h4>
                <p>• Implement network segmentation to limit lateral movement</p>
                <p>• Enable multi-factor authentication on all external-facing services</p>
                <p>• Regularly update and patch all systems</p>
                <p>• Implement principle of least privilege</p>
                <p>• Monitor for suspicious activity with SIEM/IDS</p>
                <p>• Conduct regular penetration tests</p>
            </div>
"""

        html_content += """
        </div>

        <!-- FOOTER -->
        <div class="footer">
            <p>Generated by PEN-AI - Autonomous Penetration Testing Agent</p>
            <p>Session: """ + self.session_id + """ | Target: """ + self.target + """</p>
            <p style="margin-top: 10px; color: #444;">This report is for authorized security assessments only.</p>
        </div>
    </div>
</body>
</html>"""

        return html_content

    def _render_phase(self, phase_id: str, title: str, phase_key: str, description: str) -> str:
        """Render a phase section."""
        evidence_list = self.phases.get(phase_key, [])

        html_content = f"""
        <div class="section" id="{phase_id}">
            <h2>{title}</h2>
            <p>{description}</p>
"""

        if evidence_list:
            for ev in evidence_list:
                severity = ev.get("severity", "info")
                html_content += f"""
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">{html.escape(ev.get('title', ''))}</span>
                    <span class="evidence-severity {severity}">{severity.upper()}</span>
                </div>
                <div class="evidence-command">$ {html.escape(ev.get('command', ''))}</div>
                <div class="evidence-output">{html.escape(ev.get('output', ''))}</div>
                {f'<div class="evidence-notes">{html.escape(ev.get("notes", ""))}</div>' if ev.get('notes') else ''}
            </div>
"""
        else:
            html_content += f"""
            <div class="evidence">
                <div class="evidence-header">
                    <span class="evidence-title">No evidence recorded for this phase</span>
                    <span class="evidence-severity info">INFO</span>
                </div>
                <div class="evidence-output">This phase was not executed or no evidence was captured.</div>
            </div>
"""

        html_content += "        </div>\n"
        return html_content

    def save_html(self, filepath: str):
        """Save the HTML report to a file."""
        html = self.generate_html()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath

    def save_json(self, filepath: str):
        """Save the report data as JSON."""
        data = {
            "title": self.title,
            "target": self.target,
            "scope": self.scope,
            "session_id": self.session_id,
            "hosts": self.hosts,
            "services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted": self.pivoted,
            "phases": self.phases,
            "findings": self.findings,
            "commands_run": self.commands_run,
            "generated_at": datetime.now().isoformat(),
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath
