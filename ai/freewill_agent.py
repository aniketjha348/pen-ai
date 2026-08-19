"""FreewillAgent - Fully LLM-Driven Autonomous Penetration Testing Agent.

This agent uses the LLM as its brain for EVERY decision:
- Scanning strategy
- Service analysis
- Vulnerability identification
- Exploit selection
- Post-exploitation
- Pivoting
- Reporting

No hardcoded rules. No fixed attack chains. Pure LLM intelligence.
"""

import asyncio
import json
import re
from datetime import datetime
from typing import Optional

from ai.autonomous_executor import AutonomousExecutor, CommandResult
from ai.brain import AttackSurface
from ai.credential_manager import CredentialManager
from reporting.html_report import HTMLReportGenerator


class FreewillAgent:
    """Fully autonomous LLM-driven penetration testing agent.

    This agent:
    1. Receives a target
    2. Asks the LLM what to do
    3. Executes the LLM's command
    4. Feeds output back to LLM
    5. LLM decides next action
    6. Repeats until done

    The LLM decides EVERYTHING. No hardcoded logic.
    """

    def __init__(self, llm_client=None):
        self.executor = AutonomousExecutor(timeout=300)
        self.cred_manager = CredentialManager()
        self.llm = llm_client

        # Engagement state
        self.target = ""
        self.scope = ""
        self.hosts = []
        self.services = {}
        self.credentials = []
        self.access_map = {}
        self.pivoted = []
        self.findings = []
        self.commands_run = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = datetime.now()

        # LLM conversation memory
        self.memory = []
        self.max_memory = 50  # Keep last N exchanges

    def get_system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        state_json = json.dumps({
            "target": self.target,
            "hosts": self.hosts,
            "services": self.services,
            "credentials_found": len(self.credentials),
            "access_level": self.access_map,
            "pivoted_networks": self.pivoted,
            "findings": len(self.findings),
            "commands_run": len(self.commands_run),
        }, indent=2, default=str)

        return f"""You are PEN-AI, an expert autonomous penetration tester. You have FULL CONTROL of a terminal.

TARGET: {self.target}
SCOPE: {self.scope}

CURRENT STATE:
{state_json}

YOUR MISSION:
Discover vulnerabilities in the target environment and exploit them. You are authorized to test this environment.

DECISION FRAMEWORK:
1. OBSERVE: Run commands to discover hosts, ports, services, versions
2. ANALYZE: Think about what each service/version means for security
3. PLAN: Decide the best attack vector based on what you found
4. EXECUTE: Run the attack command
5. EVALUATE: Check if the attack succeeded
6. ADAPT: If it failed, try a different approach. If it succeeded, go deeper.

AVAILABLE TOOLS (install if missing):
- nmap, masscan, rustscan (scanning)
- enum4linux, ldapsearch, smbclient (AD)
- nikto, gobuster, ffuf, sqlmap (web)
- hydra, medusa, john, hashcat (cracking)
- impacket suite (AD attacks: secretsdump, psexec, wmiexec, kerberoast)
- metasploit framework (exploitation)
- linpeas, linenum (privesc)
- chisel, ligolo (pivoting)
- curl, wget, python3 (scripting)
- sshpass, ssh (remote access)

OUTPUT FORMAT:
Respond with EXACTLY this format:

ANALYSIS: [Your analysis of the current situation]
NEXT_COMMAND: [The exact command to run]
REASONING: [Why you chose this command]
EXPECTED: [What you expect to learn or achieve]
CONFIDENCE: [high/medium/low]

IMPORTANT RULES:
- NEVER conclude early or say 'done' until you've tried EVERY possible attack
- If a tool is not installed, install it first
- If an attack fails, try a DIFFERENT approach (different tool, different user, different technique)
- If you gain access, enumerate EVERYTHING on the compromised system
- If you find credentials, try them on EVERY other host and service
- If you find new networks, scan them ALL
- If SSH fails, try SMB. If SMB fails, try HTTP. If HTTP fails, try FTP.
- If brute force fails, try default creds. If default creds fail, try null session.
- ALWAYS keep going until you've tried: scanning, enum, exploit, privesc, pivot, loot
- Only stop when you've exhausted ALL options on ALL hosts
- Remember: the goal is to find as many vulnerabilities as possible
"""

    def get_analysis_prompt(self, command: str, output: str, exit_code: int) -> str:
        """Get the analysis prompt for LLM to decide next action."""
        return f"""Command executed: {command}
Exit code: {exit_code}
Output (first 3000 chars):
{output[:3000]}

Based on this output, what should I do next?
Respond with EXACTLY this format:

ANALYSIS: [Your analysis of what the output reveals]
NEXT_COMMAND: [The exact command to run next]
REASONING: [Why you chose this command]
EXPECTED: [What you expect to learn or achieve]
CONFIDENCE: [high/medium/low]

If you believe the engagement is complete, respond with:
ANALYSIS: [Summary of findings]
NEXT_COMMAND: none
REASONING: [Why you're stopping]
"""

    async def observe_and_decide(self) -> tuple[str, str]:
        """Ask LLM what to do next based on current state."""
        system_prompt = self.get_system_prompt()

        # Build user message with recent history
        user_msg = "Current state summary:\n"
        user_msg += f"- Target: {self.target}\n"
        user_msg += f"- Hosts found: {len(self.hosts)}\n"
        user_msg += f"- Services: {sum(len(v) for v in self.services.values())}\n"
        user_msg += f"- Credentials: {len(self.credentials)}\n"
        user_msg += f"- Access: {self.access_map}\n"
        user_msg += f"- Commands run: {len(self.commands_run)}\n\n"
        user_msg += "What should I do next? Give me the exact command to run."

        if self.llm:
            response = await self.llm.chat(
                system=system_prompt,
                messages=[{"role": "user", "content": user_msg}]
            )
        else:
            response = self._fallback_decide()

        return response

    async def analyze_output(self, command: str, result: CommandResult) -> str:
        """Ask LLM to analyze command output and decide next step."""
        output = result.stdout if result.stdout else result.stderr
        prompt = self.get_analysis_prompt(command, output, result.exit_code)

        if self.llm:
            response = await self.llm.chat(
                system=self.get_system_prompt(),
                messages=[{"role": "user", "content": prompt}]
            )
        else:
            response = self._fallback_analyze(command, output)

        return response

    def parse_llm_response(self, response: str) -> dict:
        """Parse LLM response into structured format."""
        parsed = {
            "analysis": "",
            "next_command": "",
            "reasoning": "",
            "expected": "",
            "confidence": "medium",
        }

        lines = response.split("\n")
        current_key = None

        for line in lines:
            line = line.strip()
            if line.startswith("ANALYSIS:"):
                parsed["analysis"] = line[9:].strip()
                current_key = "analysis"
            elif line.startswith("NEXT_COMMAND:"):
                parsed["next_command"] = line[13:].strip()
                current_key = "next_command"
            elif line.startswith("REASONING:"):
                parsed["reasoning"] = line[10:].strip()
                current_key = "reasoning"
            elif line.startswith("EXPECTED:"):
                parsed["expected"] = line[9:].strip()
                current_key = "expected"
            elif line.startswith("CONFIDENCE:"):
                parsed["confidence"] = line[11:].strip().lower()
                current_key = None
            elif current_key and line:
                parsed[current_key] += " " + line

        return parsed

    def update_state_from_output(self, command: str, output: str):
        """Parse command output and update engagement state."""
        # Extract hosts
        hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
        for h in hosts:
            if h not in self.hosts:
                self.hosts.append(h)

        # Extract services
        services = re.findall(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?", output)
        for port, proto, svc, ver in services:
            host = self.target
            for h in self.hosts:
                if h in command:
                    host = h
                    break
            if host not in self.services:
                self.services[host] = []
            svc_info = {"port": int(port), "service": svc, "version": ver.strip() if ver else ""}
            if svc_info not in self.services[host]:
                self.services[host].append(svc_info)

        # Extract credentials
        new_creds = self.cred_manager.add_from_output(output, target=self.target)
        for cred in new_creds:
            self.credentials.append({
                "type": cred.credential_type,
                "value": cred.password or cred.hash_value,
                "username": cred.username,
                "target": cred.target,
            })

        # Detect access
        if "uid=0" in output or "nt authority\\system" in output.lower():
            for h in self.hosts:
                if h in command:
                    self.access_map[h] = "root/system"
        elif "uid=" in output:
            for h in self.hosts:
                if h in command:
                    self.access_map[h] = "user"

        # Detect networks
        routes = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", output)
        for route in routes:
            if route not in self.pivoted and route != self.target:
                self.pivoted.append(route)

    def is_safe_command(self, cmd: str) -> bool:
        """Check if command is safe to run."""
        dangerous = [
            "rm -rf /", "rm -rf /*", ":(){:|:&};:", "mkfs",
            "dd if=", "> /dev/sda",
        ]
        for pattern in dangerous:
            if pattern in cmd:
                return False
        return True

    def _fallback_decide(self) -> str:
        """Fallback decision when no LLM is available - keeps trying."""
        if not self.hosts:
            return f"""ANALYSIS: No hosts discovered yet. Need to scan the target.
NEXT_COMMAND: nmap -sn -T4 {self.target}
REASONING: Host discovery is the first step
EXPECTED: Find live hosts
CONFIDENCE: high"""

        if not self.services:
            host = self.hosts[0]
            return f"""ANALYSIS: Hosts found but no services enumerated. Need to scan for open ports.
NEXT_COMMAND: nmap -sV -sC -p- {host} --open
REASONING: Full port scan with version detection
EXPECTED: Find open services and their versions
CONFIDENCE: high"""

        # Try exploitation if services found
        if self.services and not self.access_map:
            host = list(self.services.keys())[0]
            svc = self.services[host][0] if self.services[host] else None
            if svc:
                service = svc.get('service', 'http')
                port = svc.get('port', 80)
                return f"""ANALYSIS: Services found. Trying exploitation on {host}:{port} ({service}).
NEXT_COMMAND: hydra -l admin -P /usr/share/wordlists/rockyou.txt {service}://{host} -t 4 -f
REASONING: Brute force {service} service
EXPECTED: Find credentials
CONFIDENCE: medium"""

        # Try different scan types
        if self.hosts:
            host = self.hosts[0]
            return f"""ANALYSIS: Trying different scan approach on {host}.
NEXT_COMMAND: nmap -sU --top-ports 100 -T4 {host}
REASONING: UDP scan to find additional services
EXPECTED: Find UDP services
CONFIDENCE: medium"""

        return f"""ANALYSIS: Continuing enumeration.
NEXT_COMMAND: nmap -A -T4 {self.target}
REASONING: Aggressive scan for more details
EXPECTED: Find more information
CONFIDENCE: medium"""

    def _fallback_analyze(self, command: str, output: str) -> str:
        """Fallback analysis when no LLM is available - always suggests next step."""
        hosts_found = len(re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output))
        services_found = len(re.findall(r"\d+/\w+\s+open\s+\S+", output))

        if hosts_found > 0 and "nmap -sn" in command:
            return f"""ANALYSIS: Found {hosts_found} live hosts. Now need to enumerate services.
NEXT_COMMAND: nmap -sV -sC -p- {self.hosts[0] if self.hosts else self.target} --open
REASONING: Service enumeration after host discovery
EXPECTED: Find open ports and service versions
CONFIDENCE: high"""

        if services_found > 0:
            host = self.hosts[0] if self.hosts else self.target
            return f"""ANALYSIS: Found {services_found} open services. Trying exploitation.
NEXT_COMMAND: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f
REASONING: Brute force SSH on first host
EXPECTED: Find credentials
CONFIDENCE: medium"""

        # Always suggest something - never return none
        return f"""ANALYSIS: Trying additional enumeration.
NEXT_COMMAND: nmap --script=vuln -T4 {self.target}
REASONING: Vulnerability scan to find exploitable services
EXPECTED: Find known vulnerabilities
CONFIDENCE: medium"""

    async def engage(self, target: str, scope: str = None, max_cycles: int = 100):
        """Main engagement loop. Fully autonomous."""
        self.target = target
        self.scope = scope or target
        self.start_time = datetime.now()

        print(f"\n{'='*60}")
        print(f"  🎯 PEN-AI FREEWILL AGENT")
        print(f"  Target: {target}")
        print(f"  Scope: {self.scope}")
        print(f"  Mode: Fully Autonomous (LLM-Driven)")
        print(f"{'='*60}\n")

        cycle = 0
        consecutive_failures = 0
        max_failures = 20  # Keep trying even if many commands fail

        while cycle < max_cycles:
            cycle += 1
            print(f"\n{'─'*60}")
            print(f"  CYCLE {cycle} | Hosts: {len(self.hosts)} | Services: {sum(len(v) for v in self.services.values())} | Creds: {len(self.credentials)} | Access: {self.access_map}")
            print(f"{'─'*60}")

            # 1. OBSERVE - Ask LLM what to do
            print(f"\n  [1] Observing and deciding...")
            decision = await self.observe_and_decide()
            parsed = self.parse_llm_response(decision)

            print(f"  [LLM Analysis] {parsed['analysis'][:200]}")
            print(f"  [Next Command] {parsed['next_command'][:100]}")
            print(f"  [Reasoning] {parsed['reasoning'][:150]}")

            # 2. Check if done - but only if LLM explicitly says so with reasoning
            if parsed['next_command'].lower() in ['none', 'done', 'stop', 'complete']:
                # Don't stop immediately - ask LLM to confirm
                if cycle > 10 and len(self.credentials) > 0:
                    print(f"\n  [DONE] LLM decided engagement is complete.")
                    break
                else:
                    print(f"  [CONTINUING] LLM said done but more work to do. Retrying...")
                    continue

            # 3. Safety check
            if not self.is_safe_command(parsed['next_command']):
                print(f"  [BLOCKED] Command failed safety check")
                consecutive_failures += 1
                if consecutive_failures >= max_failures:
                    print(f"\n  [STOP] Too many consecutive failures")
                    break
                continue

            # 4. EXECUTE (with auto-install)
            print(f"\n  [2] Executing: {parsed['next_command'][:100]}...")
            # Extract tool name and auto-install if needed
            tool_name = parsed['next_command'].split()[0] if parsed['next_command'].split() else ""
            result = await self.executor.run_with_install(parsed['next_command'], tool_name, timeout=300)
            self.commands_run.append(parsed['next_command'])

            if result.exit_code == 0:
                print(f"  [OK] Command succeeded ({result.duration_seconds:.1f}s)")
                consecutive_failures = 0
            else:
                print(f"  [FAIL] Command failed (exit {result.exit_code})")
                consecutive_failures += 1
                if consecutive_failures >= max_failures:
                    print(f"\n  [STOP] Too many consecutive failures")
                    break

            # 5. Show output preview
            output = result.stdout if result.stdout else result.stderr
            if output:
                lines = output.strip().split("\n")
                for line in lines[:10]:
                    print(f"    {line[:100]}")
                if len(lines) > 10:
                    print(f"    ... ({len(lines)-10} more lines)")

            # 6. UPDATE STATE
            self.update_state_from_output(parsed['next_command'], output)

            # 7. ANALYZE - Ask LLM what the output means
            print(f"\n  [3] Analyzing output...")
            analysis = await self.analyze_output(parsed['next_command'], result)
            analysis_parsed = self.parse_llm_response(analysis)

            print(f"  [Analysis] {analysis_parsed['analysis'][:200]}")

            # Store in memory
            self.memory.append({
                "cycle": cycle,
                "command": parsed['next_command'],
                "exit_code": result.exit_code,
                "analysis": analysis_parsed['analysis'],
                "next_suggestion": analysis_parsed['next_command'],
            })

            # Trim memory
            if len(self.memory) > self.max_memory:
                self.memory = self.memory[-self.max_memory:]

        # Final report
        self._print_final_report()

    def _print_final_report(self):
        """Print the final engagement report."""
        elapsed = datetime.now() - self.start_time
        minutes = int(elapsed.total_seconds() / 60)

        print(f"\n{'='*60}")
        print(f"  📊 ENGAGEMENT COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration: {minutes} minutes")
        print(f"  Commands: {len(self.commands_run)}")
        print(f"  Hosts: {len(self.hosts)}")
        print(f"  Services: {sum(len(v) for v in self.services.values())}")
        print(f"  Credentials: {len(self.credentials)}")
        print(f"  Access: {self.access_map}")
        print(f"  Networks: {len(self.pivoted)}")
        print(f"{'='*60}")

        if self.hosts:
            print(f"\n  HOSTS:")
            for h in self.hosts:
                svcs = self.services.get(h, [])
                access = self.access_map.get(h, "")
                access_str = f" [{access}]" if access else ""
                print(f"    {h}{access_str}")
                for s in svcs:
                    print(f"      {s.get('port', '?')}/{s.get('service', '?')} {s.get('version', '')}")

        if self.credentials:
            print(f"\n  CREDENTIALS:")
            for c in self.credentials:
                print(f"    [{c.get('type', '?')}] {c.get('username', '?')}: {str(c.get('value', ''))[:40]}")

        # Generate HTML report
        report = HTMLReportGenerator(title="PEN-AI Autonomous Engagement Report")
        report.load_from_state({
            "target": self.target,
            "session_id": self.session_id,
            "known_hosts": self.hosts,
            "known_services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted_networks": self.pivoted,
            "commands_run": self.commands_run,
        })

        for host, level in self.access_map.items():
            report.add_finding(
                title=f"Access gained on {host}",
                severity="critical",
                description=f"Gained {level} access on {host}",
            )

        import tempfile
        report_dir = os.path.join(tempfile.gettempdir(), f"penai_{self.session_id}")
        os.makedirs(report_dir, exist_ok=True)

        html_file = os.path.join(report_dir, "report.html")
        report.save_html(html_file)

        print(f"\n  Report: {html_file}")
        print(f"{'='*60}")

    def get_report(self) -> dict:
        """Get the engagement report as dict."""
        return {
            "target": self.target,
            "scope": self.scope,
            "session_id": self.session_id,
            "hosts": self.hosts,
            "services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted": self.pivoted,
            "findings": self.findings,
            "commands_run": self.commands_run,
            "memory": self.memory,
            "duration_minutes": int((datetime.now() - self.start_time).total_seconds() / 60),
        }
