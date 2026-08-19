"""Zero-Day Fingerprinting Engine

Identifies unknown/unusual services, fingerprints them, and researches
potential vulnerabilities including zero-days via:
- Banner grabbing and protocol analysis
- Service version fingerprinting
- CVE database querying (NVD, exploit-db, searchsploit)
- GTFOBins/similar research
- Vulnerability correlation

No hardcoded rules. Pure analysis engine.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceFingerprint:
    """Fingerprint of a discovered service."""
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    banner: str = ""
    version: str = ""
    extra_info: str = ""
    product: str = ""
    cpe: str = ""
    is_custom: bool = False
    is_unusual: bool = False


@dataclass
class VulnMatch:
    """A matched vulnerability."""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""
    cvss: float = 0.0
    exploit_available: bool = False
    exploit_path: str = ""
    service: str = ""
    version: str = ""
    confidence: str = "medium"
    source: str = ""


class ZeroDayFingerprint:
    """Engine for fingerprinting services and researching vulnerabilities.

    This engine:
    1. Takes raw scan output and identifies ALL services
    2. Fingerprints unknown/unusual services
    3. Researches CVEs for each service+version combination
    4. Matches exploits to services
    5. Returns prioritized vulnerability list
    """

    def __init__(self, executor=None):
        self.executor = executor
        self.fingerprints: list[ServiceFingerprint] = []
        self.vulns: list[VulnMatch] = []

    # ─── Service Fingerprinting ────────────────────────────────────

    def parse_nmap_output(self, output: str, target_host: str = "") -> list[ServiceFingerprint]:
        """Parse nmap output into service fingerprints."""
        fps = []

        for match in re.finditer(
            r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?",
            output,
        ):
            port = int(match.group(1))
            proto = match.group(2)
            state = match.group(3)
            service = match.group(4)
            rest = (match.group(5) or "").strip()

            version = ""
            product = ""
            extra = ""
            cpe = ""

            # Parse version info
            if rest:
                # Pattern: "Service/Version Extra"
                parts = rest.split(None, 1)
                if parts:
                    product = parts[0]
                if len(parts) > 1:
                    version = parts[1]

            # Extract CPE
            cpe_match = re.search(r"cpe:/[ao]:(.+?)(?:\s|$)", rest)
            if cpe_match:
                cpe = cpe_match.group(1)

            # Detect custom/unusual services
            is_custom = self._is_custom_service(service, product)
            is_unusual = self._is_unusual_port_service(port, service)

            fp = ServiceFingerprint(
                host=target_host,
                port=port,
                protocol=proto,
                service_name=service,
                product=product,
                version=version,
                extra_info=extra,
                cpe=cpe,
                is_custom=is_custom,
                is_unusual=is_unusual,
            )
            fps.append(fp)

        self.fingerprints.extend(fps)
        return fps

    async def banner_grab(self, target: str, port: int, timeout: int = 10) -> str:
        """Grab banner from a service."""
        if not self.executor:
            return ""

        # Try multiple methods
        methods = [
            f"echo '' | timeout {timeout} nc -w {timeout} {target} {port} 2>/dev/null",
            f"echo 'HEAD / HTTP/1.0\r\n\r\n' | timeout {timeout} nc -w {timeout} {target} {port} 2>/dev/null",
            f"echo '' | timeout {timeout} openssl s_client -connect {target}:{port} 2>/dev/null | head -20",
        ]

        for cmd in methods:
            result = await self.executor.run(cmd, timeout=timeout + 5)
            if result.stdout.strip():
                return result.stdout.strip()

        return ""

    async def deep_fingerprint(self, target: str, port: int, service: str) -> dict:
        """Deep fingerprint a service to identify exact version and potential vulns."""
        if not self.executor:
            return {"error": "No executor available"}

        info = {
            "target": target,
            "port": port,
            "service": service,
            "banner": "",
            "version_info": "",
            "http_headers": "",
            "ssl_info": "",
            "scripts_output": "",
            "potential_vulns": [],
        }

        # 1. Banner grab
        banner = await self.banner_grab(target, port)
        info["banner"] = banner

        # 2. Service-specific fingerprinting
        if service in ("http", "https"):
            info.update(await self._fingerprint_web(target, port, service))
        elif service in ("ssh", "openssh"):
            info.update(await self._fingerprint_ssh(target, port))
        elif service in ("smb", "microsoft-ds", "netbios-ssn"):
            info.update(await self._fingerprint_smb(target, port))
        elif service in ("ldap", "ldapssl"):
            info.update(await self._fingerprint_ldap(target, port))
        elif service in ("ftp",):
            info.update(await self._fingerprint_ftp(target, port))
        elif service in ("mysql", "mariadb"):
            info.update(await self._fingerprint_mysql(target, port))
        elif service in ("ms-wbt-server", "rdp"):
            info.update(await self._fingerprint_rdp(target, port))
        else:
            # Generic fingerprint with nmap scripts
            info.update(await self._fingerprint_generic(target, port, service))

        # 3. Nmap version scan for precise version
        nmap_cmd = f"nmap -sV -sC -p {port} --version-intensity 9 {target}"
        if self.executor:
            result = await self.executor.run(nmap_cmd, timeout=60)
            if result.exit_code == 0:
                info["scripts_output"] = result.stdout
                # Parse version from nmap
                ver_match = re.search(r"Service Info:.*?Version:\s*(.+?)(?:\n|$)", result.stdout)
                if ver_match:
                    info["version_info"] = ver_match.group(1).strip()

        return info

    async def _fingerprint_web(self, target: str, port: int, service: str) -> dict:
        """Fingerprint web services."""
        info = {"http_headers": "", "potential_vulns": []}
        scheme = "https" if service == "https" or port == 443 else "http"

        # Get HTTP headers
        if self.executor:
            result = await self.executor.run(
                f"curl -sI -m 10 {scheme}://{target}:{port}/ 2>/dev/null", timeout=15
            )
            if result.exit_code == 0:
                info["http_headers"] = result.stdout

                # Check for server header
                server_match = re.search(r"Server:\s*(.+?)(?:\r?\n|$)", result.stdout, re.IGNORECASE)
                if server_match:
                    server = server_match.group(1).strip()
                    info["version_info"] = server

                    # Known vulnerable servers
                    vuln_patterns = [
                        (r"Apache/2\.4\.\d+", "Apache 2.4.x", "Check for CVE-2021-41773, CVE-2021-42013"),
                        (r"nginx/1\.\d+\.\d+", "nginx 1.x", "Check for CVE-2021-23017"),
                        (r"IIS/\d+\.\d+", "Microsoft IIS", "Check for IIS-specific vulns"),
                        (r"Tomcat/(\S+)", "Apache Tomcat", "Check for Ghostcat CVE-2020-1938"),
                        (r"WebLogic", "Oracle WebLogic", "Check for CVE-2020-14882, CVE-2019-2725"),
                        (r"Jenkins", "Jenkins", "Check for CVE-2024-23897, CVE-2023-23897"),
                        (r"WordPress", "WordPress", "Run wpscan"),
                        (r"Drupal", "Drupal", "Check for Drupalgeddon"),
                        (r"Joomla", "Joomla", "Check for known Joomla vulns"),
                    ]
                    for pattern, name, note in vuln_patterns:
                        if re.search(pattern, server, re.IGNORECASE):
                            info["potential_vulns"].append(f"{name}: {note}")

        return info

    async def _fingerprint_ssh(self, target: str, port: int) -> dict:
        """Fingerprint SSH service."""
        info = {"ssl_info": "", "potential_vulns": []}

        if self.executor:
            # Get SSH version
            result = await self.executor.run(
                f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 {target} -p {port} 2>&1 | head -5",
                timeout=10,
            )
            if result.exit_code == 0 or result.stderr:
                output = result.stdout + result.stderr
                info["version_info"] = output[:500]

                # Check for vulnerable SSH versions
                ver_match = re.search(r"OpenSSH[_ ](\d+\.\d+[p\d]*)", output)
                if ver_match:
                    ssh_ver = ver_match.group(1)
                    major = float(ssh_ver.split(".")[0])
                    if major < 7.4:
                        info["potential_vulns"].append(f"OpenSSH {ssh_ver}: Check for user enumeration CVE-2018-15473")
                    if major < 8.0:
                        info["potential_vulns"].append(f"OpenSSH {ssh_ver}: Check for SCP vulnerability CVE-2019-6111")

        return info

    async def _fingerprint_smb(self, target: str, port: int) -> dict:
        """Fingerprint SMB service."""
        info = {"potential_vulns": []}

        if self.executor:
            # smbclient enumeration
            result = await self.executor.run(
                f"timeout 10 smbclient -N -L //{target} 2>&1", timeout=15
            )
            if result.exit_code == 0:
                info["scripts_output"] = result.stdout

                # Check for anonymous access
                if "Sharename" in result.stdout:
                    info["potential_vulns"].append("SMB: Anonymous share listing possible")

            # Check signing
            result = await self.executor.run(
                f"nmap --script=smb-security-mode -p {port} {target} 2>/dev/null",
                timeout=30,
            )
            if "Message signing enabled but not required" in result.stdout:
                info["potential_vulns"].append("SMB: Signing not required (relay attack possible)")

        return info

    async def _fingerprint_ldap(self, target: str, port: int) -> dict:
        """Fingerprint LDAP service."""
        info = {"potential_vulns": []}

        if self.executor:
            # Check for anonymous bind
            result = await self.executor.run(
                f"ldapsearch -x -H ldap://{target} -b '' -s base '(objectclass=*)' namingContexts 2>&1",
                timeout=15,
            )
            if "namingContexts" in result.stdout:
                info["potential_vulns"].append("LDAP: Anonymous bind allowed")
                info["scripts_output"] = result.stdout[:2000]

        return info

    async def _fingerprint_ftp(self, target: str, port: int) -> dict:
        """Fingerprint FTP service."""
        info = {"potential_vulns": []}

        if self.executor:
            # Check for anonymous FTP
            result = await self.executor.run(
                f"timeout 10 ftp -n {target} {port} << 'EOF'\nuser anonymous anonymous\nls\nquit\nEOF",
                timeout=15,
            )
            if "230" in result.stdout or "Welcome" in result.stdout:
                info["potential_vulns"].append("FTP: Anonymous access possible")

        return info

    async def _fingerprint_mysql(self, target: str, port: int) -> dict:
        """Fingerprint MySQL service."""
        info = {"potential_vulns": []}

        if self.executor:
            result = await self.executor.run(
                f"nmap --script=mysql-info -p {port} {target} 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0:
                info["scripts_output"] = result.stdout[:2000]

        return info

    async def _fingerprint_rdp(self, target: str, port: int) -> dict:
        """Fingerprint RDP service."""
        info = {"potential_vulns": []}

        if self.executor:
            # Check for BlueKeep
            result = await self.executor.run(
                f"nmap --script=rdp-vuln-ms12-020,rdp-enum-encryption -p {port} {target} 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0 and "VULNERABLE" in result.stdout:
                info["potential_vulns"].append("RDP: Vulnerable to MS12-020")
                info["scripts_output"] = result.stdout[:2000]

        return info

    async def _fingerprint_generic(self, target: str, port: int, service: str) -> dict:
        """Generic fingerprint for unknown services."""
        info = {"potential_vulns": []}

        if self.executor:
            # Try nmap scripts
            result = await self.executor.run(
                f"nmap --script=banner,ssl-enum-ciphers -p {port} {target} 2>/dev/null",
                timeout=30,
            )
            if result.exit_code == 0:
                info["scripts_output"] = result.stdout[:2000]

        return info

    def _is_custom_service(self, service_name: str, product: str) -> bool:
        """Detect if a service is custom/proprietary."""
        known_services = {
            "http", "https", "ssh", "ftp", "smtp", "pop3", "imap",
            "dns", "dhcp", "tftp", "snmp", "ldap", "kerberos",
            "smb", "microsoft-ds", "netbios-ssn", "rdp", "vnc",
            "mysql", "postgresql", "mssql", "oracle", "mongodb",
            "redis", "memcached", "elasticsearch", "rabbitmq",
            "docker", "kubernetes", "jenkins", "gitlab", "grafana",
            "prometheus", "nagios", "zabbix", "apache", "nginx",
            "tomcat", "iis", "weblogic", "jboss", "wildfly",
        }
        return service_name.lower() not in known_services

    def _is_unusual_port_service(self, port: int, service: str) -> bool:
        """Detect if a service is running on an unusual port."""
        expected_ports = {
            "http": [80, 8080, 8443, 8000, 3000, 5000, 9090],
            "https": [443, 8443],
            "ssh": [22],
            "ftp": [21],
            "smtp": [25, 587, 465],
            "dns": [53],
            "mysql": [3306],
            "postgresql": [5432],
            "mssql": [1433],
            "rdp": [3389],
            "smb": [445, 139],
            "ldap": [389, 636],
            "vnc": [5900, 5901],
        }
        expected = expected_ports.get(service.lower(), [])
        return expected and port not in expected

    # ─── CVE Research ──────────────────────────────────────────────

    async def research_cves(self, service: str, version: str) -> list[VulnMatch]:
        """Research CVEs for a given service and version."""
        vulns = []

        if not self.executor:
            return vulns

        # Method 1: searchsploit (exploit-db)
        searchsploit_vulns = await self._searchsploit_research(service, version)
        vulns.extend(searchsploit_vulns)

        # Method 2: nmap vuln scripts
        nmap_vulns = await self._nmap_vuln_research(service, version)
        vulns.extend(nmap_vulns)

        # Method 3: Python-based CVE research (NVD API)
        nvd_vulns = await self._nvd_research(service, version)
        vulns.extend(nvd_vulns)

        # Deduplicate and prioritize
        vulns = self._deduplicate_vulns(vulns)
        vulns.sort(key=lambda v: v.cvss, reverse=True)

        self.vulns.extend(vulns)
        return vulns

    async def _searchsploit_research(self, service: str, version: str) -> list[VulnMatch]:
        """Research using searchsploit/exploit-db."""
        vulns = []
        if not self.executor:
            return vulns

        # Search with service name
        queries = [service]
        if version:
            queries.append(f"{service} {version}")
        # Also search product name
        product = service.split("/")[-1] if "/" in service else service
        if product != service:
            queries.append(product)

        for query in queries[:3]:  # Limit queries
            result = await self.executor.run(
                f"searchsploit --json '{query}' 2>/dev/null", timeout=30
            )
            if result.exit_code == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for exploit in data.get("RESULTS_EXPLOIT", [])[:10]:
                        cvss = 0.0
                        if exploit.get("CVSS", ""):
                            try:
                                cvss = float(exploit["CVSS"])
                            except (ValueError, TypeError):
                                pass

                        vulns.append(VulnMatch(
                            cve_id=exploit.get("EDB-ID", ""),
                            title=exploit.get("Title", ""),
                            description=exploit.get("Description", "")[:200],
                            severity=self._cvss_to_severity(cvss),
                            cvss=cvss,
                            exploit_available=True,
                            exploit_path=exploit.get("Path", ""),
                            service=service,
                            version=version,
                            confidence="high",
                            source="exploit-db",
                        ))
                except json.JSONDecodeError:
                    pass

            # Also try raw search
            result = await self.executor.run(
                f"searchsploit '{query}' 2>/dev/null | head -30", timeout=30
            )
            if result.exit_code == 0 and result.stdout.strip():
                # Parse text output for additional results
                for line in result.stdout.split("\n"):
                    if "exploits/" in line or "webapps/" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            title = " ".join(parts[1:])
                            if not any(v.title == title for v in vulns):
                                vulns.append(VulnMatch(
                                    title=title,
                                    service=service,
                                    version=version,
                                    exploit_available=True,
                                    confidence="medium",
                                    source="exploit-db",
                                ))

        return vulns

    async def _nmap_vuln_research(self, service: str, version: str) -> list[VulnMatch]:
        """Research using nmap vulnerability scripts."""
        vulns = []
        if not self.executor:
            return vulns

        # Map service to nmap script
        script_map = {
            "http": "http-vuln*",
            "smb": "smb-vuln*",
            "ssh": "ssh-vuln*",
            "ftp": "ftp-vuln*",
            "ssl": "ssl-vuln*",
            "rdp": "rdp-vuln*",
            "mysql": "mysql-vuln*",
        }

        for svc_key, script in script_map.items():
            if svc_key in service.lower():
                result = await self.executor.run(
                    f"nmap --script={script} -p- --min-rate 1000 -T4 2>/dev/null | grep -A5 'VULNERABLE'",
                    timeout=60,
                )
                if "VULNERABLE" in result.stdout:
                    # Parse vulnerability info
                    for match in re.finditer(
                        r"(\S+):\s*VULNERABLE.*?State:\s*(VULNERABLE|LIKELY VULNERABLE)",
                        result.stdout, re.DOTALL
                    ):
                        cve = match.group(1)
                        state = match.group(2)
                        vulns.append(VulnMatch(
                            cve_id=cve if cve.startswith("CVE-") else "",
                            title=f"{cve}: {service}",
                            severity="high" if "LIKELY" in state else "critical",
                            cvss=8.0 if "LIKELY" in state else 9.0,
                            exploit_available=True,
                            service=service,
                            version=version,
                            confidence="high" if "VULNERABLE" == state else "medium",
                            source="nmap",
                        ))
                break

        return vulns

    async def _nvd_research(self, service: str, version: str) -> list[VulnMatch]:
        """Research using NVD API (National Vulnerability Database)."""
        vulns = []
        if not self.executor:
            return vulns

        # Use curl to query NVD API
        keyword = f"{service} {version}".strip()
        result = await self.executor.run(
            f'curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword.replace(" ", "%20")}&resultsPerPage=10" 2>/dev/null',
            timeout=30,
        )

        if result.exit_code == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Get CVSS score
                    cvss = 0.0
                    severity = "unknown"
                    metrics = cve.get("metrics", {})
                    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if version_key in metrics and metrics[version_key]:
                            metric = metrics[version_key][0]
                            cvss_data = metric.get("cvssData", {})
                            cvss = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            break

                    # Get description
                    descriptions = cve.get("descriptions", [])
                    desc = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:200]
                            break

                    vulns.append(VulnMatch(
                        cve_id=cve_id,
                        title=f"{cve_id}: {service} {version}",
                        description=desc,
                        severity=severity.lower() if severity else self._cvss_to_severity(cvss),
                        cvss=cvss,
                        service=service,
                        version=version,
                        confidence="medium",
                        source="nvd",
                    ))
            except json.JSONDecodeError:
                pass

        return vulns

    # ─── Exploit Matching ──────────────────────────────────────────

    async def match_exploits(self, vulns: list[VulnMatch]) -> list[dict]:
        """Match found CVEs to available exploits."""
        exploits = []
        if not self.executor:
            return exploits

        for vuln in vulns[:10]:  # Top 10 vulns
            if vuln.cve_id:
                # Search for exploit
                result = await self.executor.run(
                    f"searchsploit {vuln.cve_id} 2>/dev/null | head -10", timeout=15
                )
                if result.exit_code == 0 and "Exploits" in result.stdout:
                    exploit_info = {
                        "cve": vuln.cve_id,
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "cvss": vuln.cvss,
                        "exploits_found": result.stdout[:500],
                        "recommended_action": self._recommend_exploit(vuln),
                    }
                    exploits.append(exploit_info)

            elif vuln.service and vuln.version:
                # Search by service+version
                result = await self.executor.run(
                    f"searchsploit '{vuln.service} {vuln.version}' 2>/dev/null | head -10",
                    timeout=15,
                )
                if result.exit_code == 0 and "Exploits" in result.stdout:
                    exploit_info = {
                        "cve": "N/A",
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "cvss": vuln.cvss,
                        "exploits_found": result.stdout[:500],
                        "recommended_action": self._recommend_exploit(vuln),
                    }
                    exploits.append(exploit_info)

        return exploits

    def _recommend_exploit(self, vuln: VulnMatch) -> str:
        """Recommend exploitation approach based on vulnerability."""
        if vuln.service in ("http", "https"):
            if "sql" in vuln.title.lower():
                return "Use sqlmap for SQL injection"
            elif "xss" in vuln.title.lower():
                return "Manual XSS testing recommended"
            elif "rce" in vuln.title.lower() or "remote code" in vuln.description.lower():
                return "Use Metasploit for RCE exploitation"
            else:
                return "Use nikto/gobuster for web enumeration, then manual testing"

        elif vuln.service in ("ssh",):
            return "Try hydra for brute force, or check for known SSH vulns"

        elif vuln.service in ("smb", "microsoft-ds"):
            return "Try CrackMapExec, smbclient, or Metasploit smb modules"

        elif vuln.service in ("rdp", "ms-wbt-server"):
            return "Try Metasploit rdp modules or BlueKeep exploit"

        elif vuln.service in ("ftp",):
            return "Check anonymous access, try hydra for brute force"

        elif vuln.service in ("mysql",):
            return "Try Metasploit mysql modules or default credentials"

        else:
            return "Research service-specific exploits via searchsploit"

    # ─── Utility ───────────────────────────────────────────────────

    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity string."""
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0.0:
            return "low"
        return "info"

    def _deduplicate_vulns(self, vulns: list[VulnMatch]) -> list[VulnMatch]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique = []
        for v in vulns:
            key = (v.cve_id, v.service, v.version)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    def get_summary(self) -> dict:
        """Get summary of all findings."""
        return {
            "total_fingerprints": len(self.fingerprints),
            "custom_services": [f for f in self.fingerprints if f.is_custom],
            "unusual_ports": [f for f in self.fingerprints if f.is_unusual],
            "total_vulns": len(self.vulns),
            "critical": [v for v in self.vulns if v.severity == "critical"],
            "high": [v for v in self.vulns if v.severity == "high"],
            "medium": [v for v in self.vulns if v.severity == "medium"],
            "low": [v for v in self.vulns if v.severity == "low"],
            "exploits_available": [v for v in self.vulns if v.exploit_available],
        }
