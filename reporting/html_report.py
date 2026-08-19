"""HTML Report Generator - Professional penetration test reports."""

import json
from datetime import datetime
from typing import Any, Optional


class HTMLReportGenerator:
    """Generate professional HTML reports from engagement data."""

    def __init__(self, title: str = "Penetration Test Report"):
        self.title = title
        self.findings = []
        self.hosts = []
        self.services = {}
        self.credentials = []
        self.access_map = {}
        self.pivoted = []
        self.commands_run = []
        self.target = ""
        self.session_id = ""
        self.start_time = None
        self.end_time = None

    def load_from_state(self, state: dict):
        """Load data from engagement state."""
        self.target = state.get("target", "")
        self.session_id = state.get("session_id", "")
        self.hosts = state.get("known_hosts", [])
        self.services = state.get("known_services", {})
        self.credentials = state.get("credentials", [])
        self.access_map = state.get("access_map", {})
        self.pivoted = state.get("pivoted_networks", [])
        self.commands_run = state.get("commands_run", [])

    def add_finding(self, title: str, severity: str, description: str, evidence: str = ""):
        """Add a finding to the report."""
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat(),
        })

    def generate_html(self) -> str:
        """Generate the HTML report."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        total_svcs = sum(len(v) for v in self.services.values())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 40px; border-radius: 10px; margin-bottom: 30px; border: 1px solid #333; }}
        .header h1 {{ color: #ff4444; font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ color: #888; font-size: 1.1em; }}
        .header .meta {{ display: flex; gap: 30px; margin-top: 20px; color: #aaa; }}
        .header .meta span {{ background: #1a1a2e; padding: 8px 16px; border-radius: 5px; border: 1px solid #333; }}
        .section {{ background: #111; padding: 30px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #222; }}
        .section h2 {{ color: #ff6666; font-size: 1.5em; margin-bottom: 20px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        .stat .label {{ color: #888; font-size: 0.9em; margin-top: 5px; }}
        .stat.critical .number {{ color: #ff4444; }}
        .stat.high .number {{ color: #ff8800; }}
        .stat.medium .number {{ color: #ffcc00; }}
        .stat.low .number {{ color: #44aaff; }}
        .stat.info .number {{ color: #44ff44; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #1a1a2e; color: #ff6666; font-weight: 600; }}
        tr:hover {{ background: #1a1a2e; }}
        .severity {{ padding: 4px 12px; border-radius: 15px; font-size: 0.85em; font-weight: 600; }}
        .severity.critical {{ background: #ff4444; color: white; }}
        .severity.high {{ background: #ff8800; color: white; }}
        .severity.medium {{ background: #ffcc00; color: black; }}
        .severity.low {{ background: #44aaff; color: white; }}
        .severity.info {{ background: #44ff44; color: black; }}
        .host-card {{ background: #1a1a2e; padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #333; }}
        .host-card h3 {{ color: #44aaff; margin-bottom: 10px; }}
        .service-tag {{ display: inline-block; background: #222; padding: 4px 10px; border-radius: 15px; margin: 3px; font-size: 0.85em; border: 1px solid #444; }}
        .credential {{ background: #1a1a2e; padding: 10px; border-radius: 5px; margin: 5px 0; border-left: 3px solid #ff4444; }}
        .network {{ background: #1a1a2e; padding: 10px; border-radius: 5px; margin: 5px 0; border-left: 3px solid #44ff44; }}
        .footer {{ text-align: center; padding: 30px; color: #666; font-size: 0.9em; }}
        .chart {{ display: flex; align-items: center; gap: 10px; margin: 10px 0; }}
        .chart-bar {{ height: 20px; border-radius: 10px; min-width: 20px; }}
        .chart-label {{ color: #888; font-size: 0.9em; min-width: 80px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 {self.title}</h1>
            <div class="subtitle">Autonomous AI Penetration Test Report</div>
            <div class="meta">
                <span>Target: {self.target}</span>
                <span>Session: {self.session_id}</span>
                <span>Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                <span>Commands: {len(self.commands_run)}</span>
            </div>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat critical">
                    <div class="number">{severity_counts['critical']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat high">
                    <div class="number">{severity_counts['high']}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat medium">
                    <div class="number">{severity_counts['medium']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat low">
                    <div class="number">{severity_counts['low']}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat info">
                    <div class="number">{severity_counts['info']}</div>
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

            <h3>Severity Distribution</h3>
            <div class="chart">
                <span class="chart-label">Critical</span>
                <div class="chart-bar" style="width: {max(severity_counts['critical'] * 50, 5)}px; background: #ff4444;"></div>
                <span class="chart-label">{severity_counts['critical']}</span>
            </div>
            <div class="chart">
                <span class="chart-label">High</span>
                <div class="chart-bar" style="width: {max(severity_counts['high'] * 50, 5)}px; background: #ff8800;"></div>
                <span class="chart-label">{severity_counts['high']}</span>
            </div>
            <div class="chart">
                <span class="chart-label">Medium</span>
                <div class="chart-bar" style="width: {max(severity_counts['medium'] * 50, 5)}px; background: #ffcc00;"></div>
                <span class="chart-label">{severity_counts['medium']}</span>
            </div>
            <div class="chart">
                <span class="chart-label">Low</span>
                <div class="chart-bar" style="width: {max(severity_counts['low'] * 50, 5)}px; background: #44aaff;"></div>
                <span class="chart-label">{severity_counts['low']}</span>
            </div>
            <div class="chart">
                <span class="chart-label">Info</span>
                <div class="chart-bar" style="width: {max(severity_counts['info'] * 50, 5)}px; background: #44ff44;"></div>
                <span class="chart-label">{severity_counts['info']}</span>
            </div>
        </div>

        <div class="section">
            <h2>🖥️ Discovered Hosts</h2>
"""

        for host in self.hosts:
            svcs = self.services.get(host, [])
            access = self.access_map.get(host, "")
            access_html = f' <span class="severity critical">{access}</span>' if access else ""
            html += f'            <div class="host-card">\n'
            html += f'                <h3>{host}{access_html}</h3>\n'
            if svcs:
                for svc in svcs:
                    port = svc.get("port", "?")
                    name = svc.get("service", "?")
                    ver = svc.get("version", "")
                    html += f'                <span class="service-tag">{port}/{name} {ver}</span>\n'
            else:
                html += f'                <span class="service-tag">No services discovered</span>\n'
            html += f'            </div>\n'

        html += """        </div>

        <div class="section">
            <h2>🔑 Credentials Found</h2>
"""

        if self.credentials:
            for cred in self.credentials:
                cred_type = cred.get("type", "?")
                value = str(cred.get("value", ""))[:80]
                html += f'            <div class="credential"><strong>{cred_type}:</strong> {value}</div>\n'
        else:
            html += '            <p style="color: #666;">No credentials discovered.</p>\n'

        html += """        </div>

        <div class="section">
            <h2>🌐 Network Segments</h2>
"""

        if self.pivoted:
            for net in self.pivoted:
                html += f'            <div class="network">{net}</div>\n'
        else:
            html += '            <p style="color: #666;">No additional networks discovered.</p>\n'

        html += """        </div>

        <div class="section">
            <h2>📋 Findings</h2>
"""

        if self.findings:
            html += """            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
            for finding in self.findings:
                sev = finding.get("severity", "info").lower()
                html += f"""                    <tr>
                        <td><span class="severity {sev}">{sev.upper()}</span></td>
                        <td>{finding.get('title', '')}</td>
                        <td>{finding.get('description', '')}</td>
                    </tr>
"""
            html += """                </tbody>
            </table>
"""
        else:
            html += '            <p style="color: #666;">No findings recorded.</p>\n'

        html += f"""        </div>

        <div class="section">
            <h2>📝 Commands Executed</h2>
            <p style="color: #888;">Total commands: {len(self.commands_run)}</p>
            <details>
                <summary style="cursor: pointer; color: #44aaff;">Show command history</summary>
                <div style="margin-top: 10px; font-family: monospace; font-size: 0.85em; max-height: 300px; overflow-y: auto; background: #0a0a0a; padding: 10px; border-radius: 5px;">
"""
        for i, cmd in enumerate(self.commands_run, 1):
            html += f'                    <div style="color: #888;">{i}. {cmd[:120]}</div>\n'

        html += f"""                </div>
            </details>
        </div>

        <div class="footer">
            <p>Generated by PEN-AI - Autonomous Penetration Testing Agent</p>
            <p>Session: {self.session_id} | Target: {self.target}</p>
            <p style="margin-top: 10px; color: #444;">This report is for authorized security assessments only.</p>
        </div>
    </div>
</body>
</html>"""

        return html

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
            "session_id": self.session_id,
            "hosts": self.hosts,
            "services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted": self.pivoted,
            "findings": self.findings,
            "commands_run": self.commands_run,
            "generated_at": datetime.now().isoformat(),
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath
