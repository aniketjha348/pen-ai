# PEN-AI - Autonomous AI Penetration Testing Agent

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-208-passing-brightgreen.svg)](tests/)

> **Autonomous AI-driven penetration testing agent** - From recon to exploitation, everything decided by LLM.

---

## What Is PEN-AI?

PEN-AI is a fully autonomous penetration testing tool that uses **LLM (Large Language Model)** to make every decision. Give it a target, and it will:

1. **Scan** the network
2. **Enumerate** services
3. **Fingerprint** versions
4. **Research** CVEs
5. **Exploit** vulnerabilities
6. **Escalate** privileges
7. **Pivot** to new networks
8. **Generate** professional reports

**No hardcoded rules. Pure AI decision-making.**

---

## Quick Start

```bash
# Clone
git clone https://github.com/aniketjha348/pen-ai.git
cd pen-ai

# Install
pip install -r requirements.txt

# Run
python -m app.cli.main 10.10.10.0/24
```

---

## 3 Operating Modes

```bash
# MODE 1: FULL AUTONOMOUS (LLM decides everything)
pen-ai freewill 10.10.10.0/24

# MODE 2: INTERACTIVE (you decide, tool executes)
pen-ai 10.10.10.0/24

# MODE 3: BUG BOUNTY (internet-facing web apps)
pen-ai bugbounty https://example.com
```

### Safe AI Brain REPL Modes

The interactive REPL now includes **safe, analyst-guided AI Brain workflows**.
These modes are designed to help with reasoning and single-step execution
without enabling unattended autonomous loops.

```bash
# Show brain status + learned lessons
brain

# Suggest the next safe moves
think

# Dry-run with fallbacks + lessons applied
think simulate

# Explain why the suggested moves make sense
think explain

# Execute only the top suggested move (single safe step)
think run

# Alias of think run (still single-step only)
think auto
```

Use these inside the interactive REPL after starting `pen-ai`.

---

## 23 CLI Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `main` | Start interactive REPL terminal |
| `freewill` | Fully autonomous LLM-driven engagement |
| `enterprise` | Enterprise pentesting mode |
| `scan` | Quick scan and show results |
| `fingerprint` | Fingerprint service and research CVEs |
| `sessions` | List saved sessions |
| `tools` | List available tools |
| `chains` | List enterprise attack chains |

### OSCP/CPENT Commands

| Command | Description |
|---------|-------------|
| `analyze` | Analyze binary protections and vulnerabilities |
| `shellcode` | Generate msfvenom shellcode |
| `exploit` | Generate pwntools exploit script |
| `gdb` | Generate GDB debug script |
| `reverse` | Reverse engineer binary with radare2 |
| `oscp` | Full OSCP/CPENT workflow |
| `advanced-binary` | Heap, format string, ASLR/DEP bypass, ROP |

### Web Exploitation Commands

| Command | Description |
|---------|-------------|
| `advanced-web` | Deserialization, SSRF, XXE, race conditions, JWT, SSTI |
| `bugbounty` | Full bug bounty scan (CORS, IDOR, open redirect, etc.) |

### Enterprise Commands

| Command | Description |
|---------|-------------|
| `ad-attack` | AD CS, Golden/Silver tickets, DCShadow, delegation abuse |

### Post-Exploitation Commands

| Command | Description |
|---------|-------------|
| `evade` | AV bypass, C2 framework, anti-forensics, DNS tunneling |
| `pivot` | Chisel, Ligolo, SSH tunnels, double pivoting |
| `forensics` | Memory, disk, network, log analysis |

### Other Commands

| Command | Description |
|---------|-------------|
| `social-engineering` | Phishing pages, USB drop, pretexting |
| `report` | Generate HTML/JSON/OSCP/CPENT/GPEN reports |

---

## Certification Coverage

| Certification | Coverage | Key Features |
|--------------|----------|--------------|
| **CEH** | 95% | Scanning, web attacks, social engineering |
| **eJPT** | 95% | Network penetration, exploitation |
| **OSCP** | 85% | Binary exploitation, pivoting, reporting |
| **OSCE** | 70% | Advanced buffer overflow, exploit dev |
| **CPENT** | 70% | Binary RE, web exploits, AD attacks |
| **GPEN** | 80% | Enterprise AD, network attacks |
| **OSEP** | 60% | Evasion, C2, advanced pivoting |
| **OSWE** | 75% | Deserialization, SSRF, XXE, race conditions |
| **CRTP/CRTE** | 75% | AD CS, Kerberos, delegation abuse |
| **PNPT** | 75% | Real-world methodology, reporting |

---

## Bug Bounty Features

```bash
# Full bug bounty scan
pen-ai bugbounty https://target.com

# What it tests:
# - Subdomain enumeration (amass, subfinder, crt.sh)
# - CORS misconfiguration
# - Open redirect
# - Host header injection
# - API endpoint discovery (GraphQL, REST)
# - IDOR testing
# - Subdomain takeover
# - Cache poisoning
```

---

## Advanced Exploitation

### Binary Exploitation (OSCP/CPENT/OSCE)

```bash
# Analyze binary
pen-ai analyze ./vuln_binary

# Generate shellcode
pen-ai shellcode --payload reverse_tcp --lhost 10.10.14.5 --lport 4444

# Generate exploit
pen-ai exploit ./vuln_binary --technique bof --offset 72

# Advanced exploitation
pen-ai advanced-binary ./vuln --technique heap
pen-ai advanced-binary ./vuln --technique rop
pen-ai advanced-binary ./vuln --technique fmtstr

# Debug with GDB
pen-ai gdb ./vuln_binary --offset 72

# Reverse engineer
pen-ai reverse ./vuln_binary
```

### Web Exploitation (OSWE/CPENT)

```bash
# Advanced web attacks
pen-ai advanced-web http://target.com --technique deser
pen-ai advanced-web http://target.com --technique ssrf
pen-ai advanced-web http://target.com --technique xxe
pen-ai advanced-web http://target.com --technique jwt
pen-ai advanced-web http://target.com --technique ssti
pen-ai advanced-web http://target.com --technique race
```

### Enterprise AD Attacks (GPEN/CRTP/CRTE)

```bash
# AD CS abuse
pen-ai ad-attack 10.10.10.1 --chain adcs --username admin --password P@ss --domain corp.local

# Golden ticket
pen-ai ad-attack 10.10.10.1 --chain golden --domain corp.local

# LLMNR poisoning
pen-ai ad-attack 10.10.10.1 --chain llmnr

# RBCD delegation
pen-ai ad-attack 10.10.10.1 --chain delegation --username admin --password P@ss --domain corp.local
```

### Evasion & C2 (OSEP)

```bash
# AV bypass
pen-ai evade --technique encoding
pen-ai evade --technique encryption
pen-ai evade --technique injection

# C2 framework
pen-ai evade --technique c2 --lhost 10.10.14.5

# Anti-forensics
pen-ai evade --technique antiforensics

# DNS tunneling
pen-ai evade --technique dns
```

### Pivoting (OSCP/OSEP)

```bash
# Chisel pivot
pen-ai pivot --technique chisel

# Ligolo pivot
pen-ai pivot --technique ligolo

# SSH tunnel
pen-ai pivot --technique ssh --target 10.10.10.1

# Double pivot
pen-ai pivot --technique double
```

### Forensics (CHFI/CPENT)

```bash
# Memory forensics
pen-ai forensics /tmp/memory.dump --type memory

# Network forensics
pen-ai forensics capture.pcap --type pcap

# Log analysis
pen-ai forensics /var/log/auth.log --type log
```

### Social Engineering (CEH/CPENT)

```bash
# Phishing page
pen-ai social-engineering --scenario phishing --service o365

# USB drop payload
pen-ai social-engineering --scenario usb --lhost 10.10.14.5

# Pretexting script
pen-ai social-engineering --scenario pretext
```

### Reports

```bash
# HTML report
pen-ai report --format html

# OSCP report template
pen-ai report --format oscp

# CPENT report template
pen-ai report --format cpent

# GPEN report template
pen-ai report --format gpen
```

---

## Interactive REPL Commands

```
scan <target>          Scan target
enum                   Enumerate all services
exploit                Auto-exploit all services
privesc                Privilege escalation
pivot                  Discover pivot points
loot                   Harvest credentials
map                    ASCII network map
dashboard              Engagement status
creds                  Show all credentials
auto                   Full auto chain
auto-recon             Recon chain
auto-exploit           Exploit chain
auto-post              Post-exploit chain
report                 Generate HTML report
suggest                Get AI suggestions
install <tool>         Install missing tool
replay <session_id>    Replay session
shell <command>        Run shell command
help                   Show all commands
exit                   Exit
```

---

## Supported Tools

The tool auto-installs missing dependencies:

| Category | Tools |
|----------|-------|
| **Scanning** | nmap, masscan, rustscan |
| **Web** | nikto, gobuster, ffuf, sqlmap |
| **AD** | enum4linux, ldapsearch, smbclient, impacket, crackmapexec |
| **Brute Force** | hydra, medusa, john, hashcat |
| **Binary** | checksec, gdb, pwndbg, radare2, ROPgadget |
| **Exploitation** | metasploit, searchsploit |
| **Post-Exploit** | linpeas, linenum, chisel, ligolo |
| **Forensics** | volatility, tshark, sleuth-kit |
| **Bug Bounty** | amass, subfinder, assetfinder |

---

## Requirements

- **Python 3.10+**
- **Linux** (Kali recommended)
- **LLM API key** (optional, for autonomous mode)
- See `requirements.txt` for Python packages

---

## Configuration

```bash
# Create .env file
cp .env.example .env

# Edit .env with your LLM API key
nano .env
```

---

## Project Structure

```
pen-ai/
├── app/
│   ├── cli/main.py           # 23 CLI commands
│   ├── terminal/repl.py      # Interactive REPL
│   └── terminal/ui.py        # Rich UI
├── ai/
│   ├── freewill_agent.py     # LLM-driven autonomous agent
│   ├── auto_chains.py        # Auto engagement chains
│   ├── autonomous_executor.py # Command executor + auto-install
│   └── credential_manager.py # Credential tracking
├── exploitation/
│   ├── advanced_binary.py    # Heap, ROP, ASLR bypass
│   ├── advanced_web.py       # Deserialization, SSRF, XXE
│   ├── advanced_ad.py        # AD CS, Golden ticket, DCShadow
│   ├── advanced_pivoting.py  # Chisel, Ligolo, double pivot
│   ├── binary_analysis.py    # Binary analysis
│   ├── exploit_dev.py        # Exploit generation
│   ├── shellcode_gen.py      # Shellcode generation
│   ├── gdb_helper.py         # GDB integration
│   ├── reverse_eng.py        # Reverse engineering
│   ├── evasion.py            # AV bypass, C2, anti-forensics
│   ├── forensics.py          # Memory, disk, network forensics
│   ├── social_engineering.py # Phishing, USB, pretexting
│   └── bugbounty.py          # Bug bounty testing
├── enterprise/
│   ├── zeroday_fingerprint.py # CVE research
│   └── attack_chains.py       # AD, Exchange, SCCM
├── reporting/
│   ├── html_report.py        # Professional HTML reports
│   └── cvss.py               # CVSS scoring
├── recon/
│   ├── network.py            # Network scanning
│   └── network_viz.py        # ASCII network maps
├── core/
│   ├── safety.py             # Command safety checks
│   ├── session.py            # Session persistence
│   └── session_replay.py     # Session replay
└── tests/
    └── test_*.py             # 208 tests
```

---

## License

MIT License - For authorized security testing only.

---

## Disclaimer

This tool is for **authorized penetration testing and security research only**. Always obtain proper authorization before testing. The authors are not responsible for misuse.
