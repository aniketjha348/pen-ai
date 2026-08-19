# PEN-AI 🎯

**Autonomous AI Penetration Testing Agent for Enterprise Networks**

> An autonomous red-team operator that discovers, enumerates, exploits, pivots, and reports across **any authorized enterprise environment**. Zero to advanced, end to end. **100% LLM-driven** — no hardcoded rules, no fixed attack chains.

---

## ✨ Why PEN-AI

- **Fully LLM-driven, zero hardcoded rules** — the LLM decides every action
- **Zero-Day Fingerprinting** — identifies unknown services and researches CVEs
- **Enterprise Attack Chains** — AD, Exchange, SCCM, network infrastructure, databases
- **3 Operating Modes** — Full Auto, Enterprise, Manual
- **Auto-Install** — installs missing tools automatically
- **Works against hardened networks** — firewall bypass, ACL analysis, rate limiting
- **Evidence & reporting built-in** — HTML + JSON reports with CVSS scoring

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Setup & Configuration](#-setup--configuration)
- [How to Run](#-how-to-run)
- [CLI Commands](#-cli-commands)
- [REPL Commands (Manual Mode)](#-repl-commands-manual-mode)
- [Enterprise Pentesting](#-enterprise-pentesting)
- [Zero-Day Fingerprinting](#-zero-day-fingerprinting)
- [Operating Modes](#-operating-modes)
- [Example Walkthrough](#-example-walkthrough)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Responsible Use](#-responsible-use)

---

## 📦 Prerequisites

### Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Python 3.10+** | Runtime | `apt install python3 python3-pip` |
| **pip** | Package manager | Comes with Python |
| **git** | Clone repo | `apt install git` |

### Recommended (auto-installed by PEN-AI)

| Tool | Purpose | Auto-Install |
|------|---------|--------------|
| **nmap** | Port scanning | ✅ `apt install nmap` |
| **hydra** | Brute force | ✅ `apt install hydra` |
| **enum4linux** | SMB enumeration | ✅ `apt install enum4linux` |
| **smbclient** | SMB client | ✅ `apt install smbclient` |
| **nikto** | Web scanner | ✅ `apt install nikto` |
| **gobuster** | Directory brute | ✅ `apt install gobuster` |
| **ffuf** | Web fuzzer | ✅ `go install github.com/ffuf/ffuf/v2@latest` |
| **sqlmap** | SQL injection | ✅ `apt install sqlmap` |
| **john** | Password cracking | ✅ `apt install john` |
| **hashcat** | GPU password cracking | ✅ `apt install hashcat` |
| **curl** | HTTP requests | ✅ `apt install curl` |
| **wget** | File download | ✅ `apt install wget` |
| **sshpass** | SSH with password | ✅ `apt install sshpass` |

### Enterprise Tools (auto-installed)

| Tool | Purpose | Auto-Install |
|------|---------|--------------|
| **impacket** | AD attacks (Kerberoast, DCSync, PtH) | ✅ `pip install impacket` |
| **crackmapexec** | AD enumeration & attacks | ✅ `pip install crackmapexec` |
| **bloodhound-python** | AD attack path collection | ✅ `pip install bloodhound` |
| **metasploit** | Exploitation framework | ⚠️ Manual install recommended |
| **chisel** | Pivoting/SOCKS proxy | ✅ Auto-download |
| **linpeas** | Linux privesc enumeration | ✅ Auto-download |
| **searchsploit** | Exploit database | ✅ `apt install exploitdb` |
| **odat** | Oracle attacks | ✅ `pip install odat` |

### Kali Linux (Recommended)

If you're on Kali Linux, most tools are pre-installed:

```bash
# Update and install extras
sudo apt update
sudo apt install -y enum4linux smbclient nikto gobuster john hashcat exploitdb
pip install impacket crackmapexec bloodhound
```

### Ubuntu/Debian

```bash
# Install base tools
sudo apt update
sudo apt install -y nmap hydra enum4linux smbclient nikto gobuster \
    sqlmap john curl wget sshpass python3-pip

# Install Python packages
pip install impacket crackmapexec bloodhound httpx paramiko pydantic
```

### Windows (WSL2 Required)

```bash
# Install WSL2 with Ubuntu
wsl --install -d Ubuntu

# Then follow Ubuntu instructions above
```

> ⚠️ **PEN-AI requires Linux.** On Windows, use WSL2.

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/aniketjha348/pen-ai.git
cd pen-ai
```

### Step 2: Install Python Dependencies

```bash
# Install in development mode (includes all extras)
pip install -e ".[dev,rag]"

# Or install just the base
pip install -e .
```

### Step 3: Verify Installation

```bash
# Check CLI works
python -m app.cli.main --help

# Should show:
#   pen-ai - Autonomous AI Penetration Testing Agent
#   Commands: main, freewill, enterprise, fingerprint, scan, sessions, tools, chains
```

### Step 4: Run Tests

```bash
# Run all tests
pytest tests/ -v

# Quick check
pytest tests/ -q
# Should show: 208 passed
```

---

## ⚙️ Setup & Configuration

### Step 1: Create .env File

```bash
# Copy the example
cp .env.example .env

# Edit with your settings
nano .env
```

### Step 2: Configure LLM

```env
# LLM Configuration
PENAI_LLM_MODEL=mimo-v2.5-free
PENAI_LLM_BASE_URL=https://opencode.ai/zen/v1
PENAI_LLM_API_KEY=your_api_key_here
PENAI_LLM_TEMPERATURE=0.3
PENAI_LLM_MAX_TOKENS=8192
```

### Available LLM Models

| Model | Best For | API Key Required |
|-------|----------|-----------------|
| `mimo` | General pentesting | Optional (free tier) |
| `deepseek` | Complex analysis | Yes |
| `gpt-4` | Advanced reasoning | Yes |
| `claude` | Detailed reports | Yes |

### Step 3: Configure Scope (Optional)

```env
# Recon Configuration
PENAI_RECON_MAX_THREADS=10

# Scope Configuration
PENAI_SCOPE_MAX_PIVOTS=3
PENAI_SCOPE_REQUIRE_APPROVAL=false
```

### Step 4: Configure BloodHound (Optional - for AD)

```env
# BloodHound / Neo4j (optional)
BLOODHOUND_URI=bolt://localhost:7687
BLOODHOUND_USER=neo4j
BLOODHOUND_PASSWORD=neo4j
```

### Full .env.example

```env
[TEMPLATE]
# PEN-AI Configuration

# LLM Configuration
PENAI_LLM_MODEL=mimo-v2.5-free
PENAI_LLM_BASE_URL=https://opencode.ai/zen/v1
PENAI_LLM_API_KEY=
PENAI_LLM_TEMPERATURE=0.3
PENAI_LLM_MAX_TOKENS=8192
PENAI_LLM_TIMEOUT=120

# Recon Configuration
PENAI_RECON_MAX_THREADS=10

# Scope Configuration
PENAI_SCOPE_MAX_PIVOTS=3
PENAI_SCOPE_REQUIRE_APPROVAL=false

# BloodHound / Neo4j (optional)
# BLOODHOUND_URI=bolt://localhost:7687
# BLOODHOUND_USER=neo4j
# BLOODHOUND_PASSWORD=neo4j
```

---

## 🏃 How to Run

### Mode 1: Full Autonomous (LLM decides everything)

```bash
# Give a target, LLM does everything
pen-ai freewill 10.10.10.0/24

# With specific LLM model
pen-ai freewill 10.10.10.0/24 --model deepseek

# With custom scope
pen-ai freewill 10.10.10.5 --scope 10.10.10.0/24

# Limit cycles
pen-ai freewill 10.10.10.0/24 --max-cycles 50
```

**What happens:**
```
1. LLM scans the target (nmap)
2. LLM analyzes results
3. LLM decides what to enumerate
4. LLM identifies vulnerabilities
5. LLM selects and runs exploits
6. LLM post-exploits (credential harvesting)
7. LLM pivots to new networks
8. LLM generates HTML report
```

### Mode 2: Enterprise (Targeted attack chains)

```bash
# Full AD attack chain
pen-ai enterprise 10.10.10.0/24 --chain ad \
    --username admin \
    --password P@ssw0rd \
    --domain corp.local

# Exchange Server attacks
pen-ai enterprise 10.10.10.5 --chain exchange

# Run ALL enterprise chains
pen-ai enterprise 10.10.10.0/24 --chain auto

# Database attacks
pen-ai enterprise 10.10.10.5 --chain database

# Network infrastructure
pen-ai enterprise 10.10.10.1 --chain network
```

### Mode 3: Manual (Interactive REPL)

```bash
# Start interactive mode
pen-ai

# Start with target
pen-ai 10.10.10.0/24

# Resume a previous session
pen-ai --resume 20260819_1430
```

### Quick Scan

```bash
# Just scan and show results
pen-ai scan 10.10.10.0/24
pen-ai scan 192.168.1.0/24
```

### Zero-Day Fingerprinting

```bash
# Fingerprint a specific service
pen-ai fingerprint 10.10.10.5 80 http
pen-ai fingerprint 10.10.10.5 22 ssh
pen-ai fingerprint 10.10.10.5 445 smb
pen-ai fingerprint 10.10.10.5 3306 mysql
```

### Utility Commands

```bash
# List all saved sessions
pen-ai sessions

# List available tools
pen-ai tools

# List enterprise attack chains
pen-ai chains

# Show help
pen-ai --help
```

---

## 📋 CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `pen-ai` | Start interactive REPL | `pen-ai` |
| `pen-ai <target>` | REPL with target | `pen-ai 10.10.10.0/24` |
| `pen-ai freewill <target>` | Full autonomous mode | `pen-ai freewill 10.10.10.0/24` |
| `pen-ai enterprise <target>` | Enterprise attack chains | `pen-ai enterprise 10.10.10.0/24 --chain ad` |
| `pen-ai fingerprint <target> <port> <svc>` | Zero-day fingerprinting | `pen-ai fingerprint 10.10.10.5 80 http` |
| `pen-ai scan <target>` | Quick scan | `pen-ai scan 192.168.1.0/24` |
| `pen-ai sessions` | List saved sessions | `pen-ai sessions` |
| `pen-ai tools` | List available tools | `pen-ai tools` |
| `pen-ai chains` | List enterprise chains | `pen-ai chains` |
| `pen-ai --help` | Show all commands | `pen-ai --help` |
| `pen-ai --resume <id>` | Resume session | `pen-ai --resume 20260819_1430` |

---

## 🎮 REPL Commands (Manual Mode)

When you start `pen-ai 10.10.10.0/24`, you get an interactive prompt. Here are ALL available commands:

### Recon Commands

```
scan <target>              Scan target (auto: host discovery + service enum)
                           Example: scan 10.10.10.0/24

enum                       Enumerate all discovered services
                           Runs enum4linux, nikto, gobuster, etc.

map                        Show ASCII network visualization
                           Shows hosts, services, access levels
```

### Exploit Commands

```
exploit                    Auto-exploit all found services
                           Tries brute force, default creds, known vulns

attack <host>:<port>       Attack specific host:port
                           Example: attack 10.10.10.5:22

crack                      Crack found hashes
                           Uses john/hashcat
```

### Post-Exploit Commands

```
privesc                    Attempt privilege escalation
                           Checks sudo, SUID, kernel exploits

loot                       Harvest credentials and sensitive data
                           Reads shadow, SSH keys, history files

pivot                      Find and pivot to new networks
                           Discovers routes, ARP tables

shell <type>               Generate reverse shell
                           Types: bash, python, php, powershell
```

### Enterprise Commands

```
enterprise ad              Run Active Directory attack chain
                           Requires: username, password, domain

enterprise exchange        Run Exchange Server attack chain

fingerprint <port>         Zero-day fingerprint a service
                           Example: fingerprint 80
```

### Auto Chain Commands

```
auto                       Full auto chain
                           Flow: scan → enum → exploit → privesc → pivot → loot

auto-recon                 Auto recon chain
                           Flow: host_discovery → port_scan → service_enum

auto-exploit               Auto exploit chain
                           Flow: check_vuln → select_exploit → execute

auto-post                  Auto post-exploit chain
                           Flow: privesc → loot → credential_harvest
```

### Info Commands

```
dashboard                  Show engagement dashboard
                           Shows: hosts, services, creds, access, time

suggest                    Get attack suggestions from LLM
                           LLM analyzes state and suggests next steps

report                     Generate HTML + JSON report
                           Saves to /tmp/penai_<session>/report.html

creds                      Show all discovered credentials
                           Organized by type, source, target
```

### Session Commands

```
sessions                   List saved sessions
resume <session_id>        Resume a previous session
replay                     List replayable sessions
replay <session_id>        Show session details
set target <ip>            Set target (auto-scans)
```

### Tool Commands

```
install <tool>             Install a tool
                           Example: install nmap
                           Auto-detects package manager

run <command>              Run any command (safety checked)
                           Example: run whoami
```

### Other Commands

```
help                       Show all commands
exit / quit / q            Exit (saves session automatically)
```

---

## 🏢 Enterprise Pentesting

### Active Directory Full Kill Chain

```bash
pen-ai enterprise 10.10.10.0/24 --chain ad \
    --username admin \
    --password P@ssw0rd \
    --domain corp.local
```

**What happens (8 steps):**

```
Step 1: Domain Enumeration
  → ldapsearch, enum4linux, rpcclient
  → Discovers domain name, SID, forest info

Step 2: User Enumeration
  → crackmapexec ldap, rpcclient
  → Finds all domain users

Step 3: Group Analysis
  → crackmapexec --groups --privileged-groups
  → Identifies Domain Admins, Enterprise Admins, etc.

Step 4: Kerberoasting
  → impacket GetUserSPNs, crackmapexec --kerberoast
  → Extracts service account hashes

Step 5: Password Spraying
  → crackmapexec smb with common passwords
  → Tests Password1, Welcome1, etc.

Step 6: Lateral Movement
  → impacket psexec, wmiexec, smbexec
  → Moves to other hosts

Step 7: Privilege Escalation
  → impacket secretsdump (DCSync)
  → ACL abuse, GPO relay

Step 8: Domain Compromise
  → KRBTGT hash extraction
  → Golden Ticket possible
```

### Exchange Server Attacks

```bash
pen-ai enterprise 10.10.10.5 --chain exchange
```

**What happens:**

```
Step 1: Exchange Enumeration
  → Checks EWS, OWA endpoints
  → Identifies Exchange version

Step 2: Vulnerability Check
  → ProxyShell (CVE-2021-34473)
  → ProxyLogon (CVE-2021-26855)
  → ProxyNotShell (CVE-2022-41040)

Step 3: Exploitation
  → Remote code execution via Exchange
```

### Database Attacks

```bash
pen-ai enterprise 10.10.10.5 --chain database
```

**Supported databases:**

| Database | Attacks |
|----------|---------|
| **MySQL** | Default creds, Metasploit modules, UDF privesc |
| **MSSQL** | Impacket mssqlclient,xp_cmdshell, linked servers |
| **PostgreSQL** | Default creds, COPY command RCE |
| **Oracle** | ODAT, TNS listener attacks |

### Network Infrastructure

```bash
pen-ai enterprise 10.10.10.1 --chain network
```

**Supported devices:**

| Device | Attacks |
|--------|---------|
| **Cisco** | SNMP (community strings), default creds, IOS exploits |
| **Juniper** | SSH/HTTPS management, default creds |
| **Palo Alto** | PAN-OS exploits, management interface |
| **Fortinet** | SSL-VPN exploits, default creds |

---

## 🔬 Zero-Day Fingerprinting

### What It Does

Identifies unknown services and researches potential vulnerabilities:

```bash
pen-ai fingerprint 10.10.10.5 80 http
```

**Process:**

```
1. Banner Grabbing
   → Connects to service, reads banner
   → Identifies server software and version

2. Deep Fingerprint
   → Service-specific analysis:
     - HTTP: Server header, technologies, CMS detection
     - SSH: OpenSSH version, key exchange algorithms
     - SMB: Signing status, anonymous access
     - LDAP: Anonymous bind, domain info
     - FTP: Anonymous access, banner
     - MySQL: Version, default creds
     - RDP: BlueKeep vulnerability check

3. Version Detection
   → nmap -sV with version intensity 9
   → Precise version identification

4. CVE Research
   → NVD API (National Vulnerability Database)
   → exploit-db via searchsploit
   → nmap vulnerability scripts

5. Exploit Matching
   → Finds available exploits for discovered versions
   → Recommends exploitation approach
```

### Supported Services

| Service | Fingerprinting | CVE Research | Exploit Matching |
|---------|---------------|--------------|-----------------|
| HTTP/HTTPS | ✅ Server header, technologies | ✅ NVD, exploit-db | ✅ sqlmap, nikto, gobuster |
| SSH | ✅ OpenSSH version | ✅ CVE database | ✅ hydra, Metasploit |
| SMB | ✅ Signing, shares | ✅ MS17-010, etc. | ✅ CrackMapExec, Metasploit |
| LDAP | ✅ Anonymous bind | ✅ AD vulns | ✅ ldapsearch |
| FTP | ✅ Anonymous access | ✅ Known vulns | ✅ hydra |
| MySQL | ✅ Version, default creds | ✅ CVE database | ✅ Metasploit |
| MSSQL | ✅ Version, xp_cmdshell | ✅ CVE database | ✅ Impacket |
| RDP | ✅ BlueKeep check | ✅ MS12-020 | ✅ Metasploit |
| Oracle | ✅ ODAT scan | ✅ CVE database | ✅ ODAT |

---

## 🔄 Operating Modes

### 🔴 Mode 1: Full Autonomous (`freewill`)

The LLM decides **everything**. No human input needed.

```bash
pen-ai freewill 10.10.10.0/24
```

**Best for:** Full engagement, CTF, authorized pentest

### 🟡 Mode 2: Enterprise (`enterprise`)

Targeted attack chains for specific environments.

```bash
pen-ai enterprise 10.10.10.0/24 --chain ad
```

**Best for:** AD pentesting, Exchange testing, specific targets

### 🟢 Mode 3: Manual (Interactive REPL)

You decide every step. Tool executes your commands.

```bash
pen-ai 10.10.10.0/24
```

**Best for:** Learning, precise control, custom workflows

---

## 📝 Example Walkthrough

### Example 1: Quick Scan

```bash
$ pen-ai scan 10.10.10.0/24

  Scanning 10.10.10.0/24...
  [1/3] Host Discovery...
  Found 5 hosts: 10.10.10.1, 10.10.10.5, 10.10.10.10, 10.10.10.15, 10.10.10.20
  [2/3] Port Scanning...
  10.10.10.5: 22/ssh, 80/http, 445/smb
  10.10.10.10: 22/ssh, 3389/rdp
  10.10.10.15: 80/http, 3306/mysql
  [3/3] Service Enumeration...
  Complete!

  Dashboard:
  ┌─────────────────────────────────────────┐
  │  Hosts:      5                          │
  │  Services:   8                          │
  │  Credentials: 0                         │
  │  Access:     none                       │
  └─────────────────────────────────────────┘

  Suggestions:
  → Try brute force on SSH (10.10.10.5:22)
  → Enumerate SMB shares (10.10.10.5:445)
  → Test web app (10.10.10.5:80)
```

### Example 2: Manual Engagement

```bash
$ pen-ai 10.10.10.0/24

pen-ai:10.10.10.0/24 [0h 0s 0c] > scan 10.10.10.0/24
  Scanning... Found 5 hosts, 12 services

pen-ai:10.10.10.0/24 [0h 30s 0c] > enum
  Enumerating SMB... Enumerating HTTP... Complete

pen-ai:10.10.10.0/24 [2h 15s 0c] > exploit
  Trying SSH brute force... Found credentials!
  admin:password123 on 10.10.10.5:22

pen-ai:10.10.10.0/24 [3h 0s 1c] [admin] > privesc
  Checking sudo... Found sudo misconfiguration!
  Gained root access

pen-ai:10.10.10.0/24 [3h 30s 1c] [root] > loot
  Reading /etc/shadow... Found 5 password hashes
  Reading SSH keys... Found 2 private keys

pen-ai:10.10.10.0/24 [4h 0s 1c] [root] > report
  Generating HTML report... Done!
  Report saved to /tmp/penai_20260819_1430/report.html
```

### Example 3: Enterprise AD Attack

```bash
$ pen-ai enterprise 10.10.10.0/24 --chain ad --username admin --password P@ssw0rd --domain corp.local

  🏢 PEN-AI ENTERPRISE MODE
  Target: 10.10.10.0/24
  Chain: ad
  User: admin@corp.local

  [AD] Running Active Directory attack chain...

  Step 1: Domain Enumeration
    ✓ Domain: corp.local
    ✓ SID: S-1-5-21-...
    ✓ Forest: corp.local

  Step 2: User Enumeration
    ✓ Found 47 domain users
    ✓ Found 12 computer accounts

  Step 3: Group Analysis
    ✓ Domain Admins: 3 members
    ✓ Enterprise Admins: 1 member

  Step 4: Kerberoasting
    ✓ Found 5 SPN accounts
    ✓ Extracted 5 TGS hashes
    → Crack with: hashcat -m 13100 hash.txt wordlist.txt

  Step 5: Password Spraying
    ✓ Password1 works on svc_sql account

  Step 6: Lateral Movement
    ✓ PsExec to DC01 successful
    ✓ WMIExec to WEB01 successful

  Step 7: Privilege Escalation
    ✓ DCSync successful
    ✓ Extracted NTLM hashes

  Step 8: Domain Compromise
    ✓ KRBTGT hash extracted
    ✓ Golden Ticket possible

  [FINDINGS]:
    • Domain: corp.local
    • Users: 47
    • Compromised: 3 hosts
    • Domain Admin: YES
    • KRBTGT: YES
```

### Example 4: Zero-Day Fingerprinting

```bash
$ pen-ai fingerprint 10.10.10.5 80 http

  🔍 Fingerprinting 10.10.10.5:80 (http)...

  Banner: HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)
  Version: Apache/2.4.41 (Ubuntu)

  Potential Vulnerabilities:
    ⚠️  Apache 2.4.x: Check for CVE-2021-41773, CVE-2021-42013
    ⚠️  Apache 2.4.41: Check for CVE-2021-39274

  🔬 Researching CVEs for http Apache/2.4.41...

  Found 12 potential vulnerabilities:
    [CRITICAL] CVE-2021-41773: Apache HTTP Server Path Traversal
    [HIGH] CVE-2021-42013: Apache HTTP Server Path Traversal
    [HIGH] CVE-2021-39274: Apache HTTP Server Request Smuggling
    [MEDIUM] CVE-2021-40438: Apache HTTP Server SSRF
    ...
```

---

## 🔧 Troubleshooting

### "Command not found: pen-ai"

```bash
# Make sure you installed in development mode
pip install -e .

# Or run directly
python -m app.cli.main --help
```

### "No module named 'ai'"

```bash
# Make sure you're in the pen-ai directory
cd pen-ai
pip install -e .
```

### "Tool not found: nmap"

```bash
# PEN-AI auto-installs, but you can install manually
sudo apt install nmap

# Or let PEN-AI install it
pen-ai > install nmap
```

### "LLM not responding"

```bash
# Check your .env file
cat .env

# Make sure API key is set (if required)
PENAI_LLM_API_KEY=your_key_here

# Try with free model (no API key needed)
pen-ai freewill 10.10.10.0/24 --model mimo
```

### "Permission denied"

```bash
# Some tools need root
sudo pen-ai freewill 10.10.10.0/24

# Or install tools manually
sudo apt install nmap hydra john
```

### "Tests failing"

```bash
# Run tests from pen-ai directory
cd pen-ai
pytest tests/ -v

# Check specific test
pytest tests/test_pipeline.py -v
```

### "Session not saving"

```bash
# Check if /tmp is writable
ls -la /tmp/penai_*

# Sessions are saved automatically on exit
# Resume with: pen-ai --resume SESSION_ID
```

---

## 📁 Project Structure

```
pen-ai/
├── app/
│   ├── cli/main.py              # CLI commands (freewill, enterprise, scan, fingerprint)
│   ├── terminal/
│   │   ├── repl.py              # Interactive REPL (manual mode)
│   │   └── ui.py                # Rich UI (tables, panels, colors)
│   └── config/
│       └── models.py            # LLM model configuration
├── ai/
│   ├── freewill_agent.py        # Full autonomous agent (enterprise-enhanced)
│   ├── autonomous_executor.py   # Command execution with auto-install
│   ├── autonomous_agent.py      # Core agent logic
│   ├── brain.py                 # Observation layer (no hardcoded rules)
│   ├── planner.py               # Action generation
│   ├── credential_manager.py    # Credential tracking & dedup
│   ├── credential_cracker.py    # Hash cracking
│   ├── shell_generator.py       # Reverse shell generation
│   ├── auto_chains.py           # Auto engagement chains
│   ├── streaming.py             # LLM streaming output
│   ├── context_compressor.py    # Context window management
│   └── llm_client.py            # LLM API client
├── enterprise/
│   ├── zeroday_fingerprint.py   # Zero-day fingerprinting engine
│   ├── attack_chains.py         # Enterprise attack chains (AD, Exchange, etc.)
│   ├── tools.py                 # Enterprise tool integrations
│   └── bloodhound_queries.py    # BloodHound integration
├── core/
│   ├── state/engagement_state.py # Engagement state management
│   ├── safety.py                # Command safety checks
│   ├── session_replay.py        # Session replay
│   ├── session.py               # Session persistence
│   └── orchestrator/pipeline.py # Engagement pipeline
├── recon/
│   ├── network.py               # Host/port scanning
│   ├── network_viz.py           # ASCII network maps
│   ├── parallel.py              # Parallel scanning
│   └── firewall_analysis.py     # Filter detection
├── exploitation/
│   ├── modules/
│   │   ├── ssh.py               # SSH attacks
│   │   ├── smb.py               # SMB attacks
│   │   ├── web.py               # Web attacks
│   │   └── privesc.py           # Privilege escalation
│   └── engine.py                # Exploitation engine
├── reporting/
│   ├── html_report.py           # HTML report generation
│   ├── generator.py             # Report generation
│   └── cvss.py                  # CVSS scoring
├── knowledge/
│   └── methodology_data.py      # Attack methodology knowledge base
├── ranges/
│   ├── web/agent.py             # Web application testing
│   ├── ad/agent.py              # Active Directory testing
│   ├── iot/agent.py             # IoT testing
│   ├── binary/agent.py          # Binary analysis
│   └── ctf/agent.py             # CTF challenges
├── tests/                       # 208 tests (all passing)
├── .env.example                 # Environment configuration template
├── .gitignore                   # Git ignore rules
├── pyproject.toml               # Python project configuration
└── README.md                    # This file
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_pipeline.py -v

# Run with output
pytest tests/ -s

# Quick check
pytest tests/ -q
# Output: 208 passed
```

Current suite: **208 tests** (all passing).

---

## 🛡️ Responsible Use

**Only use against systems you own or have written authorization to test.**

- ✅ Your own lab environment
- ✅ Systems with written permission (scope document)
- ✅ CTF challenges
- ✅ Bug bounty programs (within rules)
- ❌ Any system without authorization
- ❌ Production systems without permission
- ❌ Other people's networks

**Unauthorized access is illegal. Stay in scope.**

---

## 📄 License

MIT License

---

**Built for authorized enterprise penetration testing.** Stay in scope. Report clearly.
