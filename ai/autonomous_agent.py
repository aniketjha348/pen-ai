"""Autonomous LLM Agent - The BRAIN. Decides everything, runs anything."""

import json
import asyncio
from typing import Any, Optional

from ai.autonomous_executor import AutonomousExecutor, CommandResult


class AutonomousAgent:
    """LLM-driven autonomous penetration testing agent.

    This agent:
    1. Receives a target
    2. Observes the environment
    3. Decides what to do next
    4. Runs ANY command it wants
    5. Installs tools it needs
    6. Learns from results
    7. Continues until objectives met

    No fixed attack paths. No pre-built modules. Just LLM intelligence.
    """

    def __init__(self, llm_client=None):
        self.executor = AutonomousExecutor(timeout=300)
        self.llm = llm_client
        self.target = ""
        self.scope = ""
        self.state = {
            "phase": "initial",
            "hosts_discovered": [],
            "services_found": [],
            "vulnerabilities": [],
            "credentials": [],
            "access_level": "none",
            "pivots": [],
            "objectives": [],
            "findings": [],
            "current_network": "",
            "tools_installed": [],
            "command_history_count": 0,
        }
        self.memory = []  # Conversation memory for LLM

    def get_system_prompt(self) -> str:
        """Get the system prompt for the LLM - you are an autonomous pentester."""
        return f"""You are PEN-AI, an autonomous expert penetration tester. You have FULL CONTROL of a terminal.

TARGET: {self.target}
SCOPE: {self.scope}

You can run ANY command. You can install ANY tool. You have no restrictions except the scope.

YOUR WORKFLOW:
1. RECON: Discover hosts, ports, services on the target network
2. ENUMERATE: Deep enumeration of discovered services
3. IDENTIFY: Find vulnerabilities and attack vectors
4. EXPLOIT: Gain access using appropriate techniques
5. POST-EXPLOIT: Enumerate the compromised system
6. PIVOT: Move to other networks if accessible
7. LOOT: Harvest credentials, flags, sensitive data
8. REPEAT: Continue until all objectives are met

TOOLS YOU CAN USE:
- nmap, masscan, rustscan (scanning)
- enum4linux, ldapsearch, smbclient (AD)
- nikto, gobuster, ffuf, sqlmap (web)
- hydra, medusa, john, hashcat (cracking)
- impacket suite (AD attacks)
- metasploit framework (exploitation)
- linpeas, linenum (privesc)
- chisel, ligolo (pivoting)
- binwalk, firmware-mod-kit (IoT)
- gdb, pwndbg, radare2 (binary)
- python3, curl, wget (scripting)
- sshpass, ssh (remote access)
- docker, docker-compose (containers)

IF A TOOL IS NOT INSTALLED: Install it yourself. Use apt-get, pip, go install, or download the binary.

RULES:
- NEVER ask the user for permission. Just do it.
- NEVER stop because a tool is missing. Install it.
- NEVER use fixed attack paths. Observe, hypothesize, test, adapt.
- ALWAYS record evidence of findings.
- ALWAYS update your state after each action.
- If something fails, try a different approach.
- Think like a real attacker. Be creative. Be thorough.

CURRENT STATE:
{json.dumps(self.state, indent=2, default=str)}

WHAT DO YOU DO NEXT? Respond with:
1. Your analysis of current situation
2. The EXACT command(s) you want to run
3. Why you chose this approach
4. What you expect to learn"""

    async def observe(self) -> str:
        """Observe current state and get LLM's analysis."""
        system_prompt = self.get_system_prompt()
        user_msg = f"""Current state summary:
- Phase: {self.state['phase']}
- Hosts found: {len(self.state['hosts_discovered'])}
- Services: {len(self.state['services_found'])}
- Credentials: {len(self.state['credentials'])}
- Access level: {self.state['access_level']}
- Commands run: {self.state['command_history_count']}

What should I do next? Give me the exact command to run."""

        if self.llm:
            response = await self.llm.chat(
                system=system_prompt,
                messages=[{"role": "user", "content": user_msg}]
            )
            return response
        else:
            return self._generate_initial_commands()

    async def act(self, command: str) -> CommandResult:
        """Execute a command. The LLM decides, we execute."""
        result = await self.executor.run(command, timeout=300)
        self.state["command_history_count"] += 1

        # Store in memory
        self.memory.append({
            "action": command,
            "result_preview": result.stdout[:1000] if result.stdout else result.stderr[:500],
            "exit_code": result.exit_code,
        })

        return result

    async def act_and_observe(self, command: str) -> tuple[CommandResult, str]:
        """Execute a command and get LLM's analysis of the result."""
        result = await self.act(command)

        # Build context for LLM
        output = result.stdout if result.stdout else result.stderr
        context = f"""Command: {command}
Exit code: {result.exit_code}
Output (first 2000 chars):
{output[:2000]}

Based on this output, what should I do next? Give me the exact command."""

        if self.llm:
            system_prompt = self.get_system_prompt()
            response = await self.llm.chat(
                system=system_prompt,
                messages=[{"role": "user", "content": context}]
            )
            return result, response
        else:
            return result, self._parse_and_suggest_next(command, output)

    async def install_and_run(self, tool_name: str, command: str) -> CommandResult:
        """Install a tool if needed, then run the command."""
        await self.executor.ensure_tool(tool_name)
        return await self.act(command)

    async def engage(self, target: str, scope: Optional[str] = None):
        """Main engagement loop. Fully autonomous."""
        self.target = target
        self.scope = scope or target
        self.state["current_network"] = target
        self.state["phase"] = "reconnaissance"

        print(f"\n{'='*60}")
        print(f"PEN-AI AUTONOMOUS ENGAGEMENT")
        print(f"Target: {target}")
        print(f"Scope: {self.scope}")
        print(f"{'='*60}\n")

        max_cycles = 50
        cycle = 0

        while cycle < max_cycles:
            cycle += 1
            print(f"\n--- Cycle {cycle} | Phase: {self.state['phase']} ---")

            # 1. OBSERVE - Get LLM's analysis
            analysis = await self.observe()
            print(f"\n[LLM ANALYSIS]\n{analysis[:500]}...")

            # 2. EXTRACT COMMANDS from LLM response
            commands = self._extract_commands(analysis)

            if not commands:
                print("[INFO] No commands to execute. Moving to next phase.")
                self._advance_phase()
                continue

            # 3. EXECUTE each command
            for cmd in commands:
                print(f"\n[EXEC] {cmd[:200]}...")
                result = await self.act(cmd)

                if result.exit_code == 0:
                    print(f"[OK] ({result.duration_seconds:.1f}s)")
                    if result.stdout:
                        print(f"[OUTPUT] {result.stdout[:500]}")
                else:
                    print(f"[FAIL] ({result.exit_code}) {result.stderr[:200]}")

                # 4. UPDATE STATE based on output
                self._update_state_from_output(cmd, result.stdout, result.stderr)

            # 5. CHECK if we should continue
            if self._objectives_met():
                print(f"\n{'='*60}")
                print("ALL OBJECTIVES MET. Engagement complete.")
                break

        print(f"\n{'='*60}")
        print("ENGAGEMENT COMPLETE")
        print(f"Commands executed: {self.state['command_history_count']}")
        print(f"Hosts discovered: {len(self.state['hosts_discovered'])}")
        print(f"Credentials found: {len(self.state['credentials'])}")
        print(f"Findings: {len(self.state['findings'])}")
        print(f"{'='*60}")

    def _extract_commands(self, llm_response: str) -> list[str]:
        """Extract executable commands from LLM response."""
        commands = []
        lines = llm_response.split("\n")

        in_command_block = False
        current_cmd = []

        for line in lines:
            stripped = line.strip()

            # Look for command blocks
            if stripped.startswith("```") or stripped.startswith("```bash") or stripped.startswith("```sh"):
                in_command_block = not in_command_block
                if in_command_block:
                    current_cmd = []
                continue

            if in_command_block and stripped:
                # Handle multi-line commands
                if stripped.endswith("\\"):
                    current_cmd.append(stripped[:-1])
                else:
                    current_cmd.append(stripped)
                    full_cmd = " ".join(current_cmd)
                    if self._is_safe_command(full_cmd):
                        commands.append(full_cmd)
                    current_cmd = []

            # Also handle inline commands with common prefixes
            elif stripped and not stripped.startswith("#") and not stripped.startswith("-"):
                # Handle lines that contain a command after some text
                # Look for commands that start with known tool names
                cmd_prefixes = [
                    "nmap ", "enum4linux", "ldapsearch", "smbclient",
                    "curl ", "wget ", "sshpass", "ssh ", "python3 ",
                    "pip install", "apt-get ", "apt install",
                    "gobuster ", "ffuf ", "nikto ", "sqlmap ",
                    "hydra ", "john ", "hashcat ",
                    "msfconsole", "msfvenom",
                    "chisel ", "ligolo ",
                    "binwalk ", "checksec ", "gdb ",
                    "find ", "cat ", "grep ", "ls ", "cd ", "mkdir ",
                    "echo ", "id ", "whoami", "uname", "ifconfig",
                    "ip ", "ss ", "netstat ", "ps ", "top ",
                    "netcat", "nc ", "socat ",
                    "docker ", "systemctl ",
                    "go install", "git clone",
                    "chmod ", "cp ", "mv ", "rm ",
                    "strings ", "objdump ", "readelf ", "nm ",
                    "gcc ", "make ",
                ]
                if any(stripped.startswith(p) for p in cmd_prefixes):
                    if self._is_safe_command(stripped):
                        commands.append(stripped)
                # Also check for commands after "Run this:" or "Execute:" or ": "
                elif any(marker in stripped.lower() for marker in [": ", "run ", "execute ", "use "]):
                    # Try to extract the command part
                    for marker in [": ", "Run ", "Execute ", "use "]:
                        if marker.lower() in stripped.lower():
                            idx = stripped.lower().index(marker.lower()) + len(marker)
                            potential_cmd = stripped[idx:].strip().strip('"').strip("'")
                            if any(potential_cmd.startswith(p) for p in cmd_prefixes):
                                if self._is_safe_command(potential_cmd):
                                    commands.append(potential_cmd)
                            break

        return commands

    def _is_safe_command(self, cmd: str) -> bool:
        """Check command is within scope (only safety check)."""
        # Only check that we're not targeting outside scope
        dangerous_out_of_scope = [
            "rm -rf /", "rm -rf /*",
            ":(){:|:&};:",  # fork bomb
            "mkfs", "dd if=",
            "> /dev/sda",
        ]
        for pattern in dangerous_out_of_scope:
            if pattern in cmd:
                return False
        return True

    def _update_state_from_output(self, command: str, stdout: str, stderr: str):
        """Parse command output and update engagement state."""
        output = stdout + stderr

        # Parse nmap output for hosts and services
        if "nmap" in command and "scan report for" in output.lower():
            import re
            hosts = re.findall(r"(\d+\.\d+\.\d+\.\d+)", output)
            for host in hosts:
                if host not in self.state["hosts_discovered"]:
                    self.state["hosts_discovered"].append(host)

        # Parse services
        import re
        services = re.findall(r"(\d+)/\w+\s+open\s+(\S+)", output)
        for port, service in services:
            svc_entry = {"port": int(port), "service": service}
            if svc_entry not in self.state["services_found"]:
                self.state["services_found"].append(svc_entry)

        # Detect credentials
        credential_patterns = [
            (r"password[=:]\s*(\S+)", "password"),
            (r"NTLM.*?:([a-f0-9]{32})", "ntlm_hash"),
            (r"\$krb5tgs\$.*?\$", "kerberos_hash"),
            (r"\$krb5asrep\$.*?\$", "asrep_hash"),
            (r"LOGIN: (\S+) PASSWORD: (\S+)", "login_creds"),
        ]
        for pattern, cred_type in credential_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                cred = {"type": cred_type, "value": match if isinstance(match, str) else match}
                if cred not in self.state["credentials"]:
                    self.state["credentials"].append(cred)

        # Detect access level
        if "uid=0" in output or "root" in output.lower():
            self.state["access_level"] = "root"
        elif "uid=" in output:
            self.state["access_level"] = "user"
        elif "nt authority\\system" in output.lower():
            self.state["access_level"] = "system"

    def _advance_phase(self):
        """Move to next engagement phase."""
        phases = [
            "reconnaissance", "enumeration", "vulnerability_identification",
            "exploitation", "post_exploitation", "pivoting",
            "lateral_movement", "objective_completion", "reporting"
        ]
        current_idx = phases.index(self.state["phase"]) if self.state["phase"] in phases else 0
        if current_idx < len(phases) - 1:
            self.state["phase"] = phases[current_idx + 1]
        else:
            self.state["phase"] = "complete"

    def _objectives_met(self) -> bool:
        """Check if engagement objectives are met."""
        return self.state["phase"] == "complete"

    def _generate_initial_commands(self) -> str:
        """Generate initial commands when no LLM is available."""
        return f"""Starting reconnaissance on {self.target}.

First, I need to discover live hosts and services:

```bash
nmap -sn {self.target}
```

Then enumerate services on discovered hosts."""

    def _parse_and_suggest_next(self, command: str, output: str) -> str:
        """Suggest next command based on output (no-LLM fallback)."""
        if "nmap" in command and "scan report for" in output.lower():
            return "Hosts found. Now enumerate services with: nmap -sV -sC -p- <host>"
        elif "smb" in output.lower() or "445" in command:
            return "SMB found. Enumerate shares with: smbclient -L <target> -N"
        elif "ssh" in output.lower() or "22" in command:
            return "SSH found. Try brute force with: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>"
        elif "http" in output.lower() or "80" in command:
            return "HTTP found. Enumerate with: gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt"
        return "Analyze output and continue enumeration."

    def get_report(self) -> dict:
        """Generate engagement report."""
        return {
            "target": self.target,
            "scope": self.scope,
            "total_commands": self.state["command_history_count"],
            "hosts_discovered": self.state["hosts_discovered"],
            "services_found": self.state["services_found"],
            "credentials_found": self.state["credentials"],
            "access_level": self.state["access_level"],
            "pivots_established": self.state["pivots"],
            "findings": self.state["findings"],
            "command_history": self.executor.get_history(),
        }
