# PEN-AI 🎯

**Autonomous AI Penetration Testing Agent for Enterprise Networks**

> An autonomous red-team operator that discovers, enumerates, exploits, pivots, and reports across **any authorized enterprise environment**. Zero to advanced, end to end. **100% LLM-driven** — no hardcoded rules, no fixed attack chains.

---

## ✨ Why PEN-AI

- **Fully LLM-driven, zero hardcoded rules** — the LLM decides every action
- **Zero-Day Fingerprinting** — identifies unknown services and researches CVEs
- **Enterprise Attack Chains** — AD, Exchange, SCCM, network infrastructure, databases
- **3 Operating Modes** — Full Auto, Semi-Auto, Manual
- **Works against hardened networks** — firewall bypass, ACL analysis, rate limiting
- **Evidence & reporting built-in** — HTML + JSON reports with CVSS scoring

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/aniketjha348/pen-ai.git
cd pen-ai
pip install -e ".[dev,rag]"
```

### Three Ways to Use

```bash
# 🔴 MODE 1: FULL AUTONOMOUS (LLM decides everything)
pen-ai freewill 10.10.10.0/24

# 🟡 MODE 2: ENTERPRISE (targeted attack chains)
pen-ai enterprise 10.10.10.0/24 --chain ad

# 🟢 MODE 3: MANUAL (you decide, tool executes)
pen-ai 10.10.10.0/24
```

---

## 📋 Command Reference

### CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `pen-ai <target>` | Interactive REPL | `pen-ai 10.10.10.0/24` |
| `pen-ai freewill <target>` | Full autonomous mode | `pen-ai freewill 10.10.10.0/24` |
| `pen-ai enterprise <target>` | Enterprise attack chains | `pen-ai enterprise 10.10.10.0/24 --chain ad` |
| `pen-ai fingerprint <target> <port> <service>` | Zero-day fingerprinting | `pen-ai fingerprint 10.10.10.5 80 http` |
| `pen-ai scan <target>` | Quick scan | `pen-ai scan 192.168.1.0/24` |
| `pen-ai chains` | List enterprise attack chains | `pen-ai chains` |
| `pen-ai sessions` | List sessions | `pen-ai sessions` |
| `pen-ai tools` | List tools | `pen-ai tools` |

### Enterprise Attack Chains

```bash
# Full Active Directory attack chain
pen-ai enterprise 10.10.10.0/24 --chain ad --username admin --password P@ssw0rd --domain corp.local

# Exchange Server attacks
pen-ai enterprise 10.10.10.5 --chain exchange

# Run ALL enterprise chains automatically
pen-ai enterprise 10.10.10.0/24 --chain auto

# Zero-day fingerprinting
pen-ai fingerprint 10.10.10.5 80 http
```

### Available Enterprise Chains

| Chain | Description |
|-------|-------------|
| `ad` | Full AD kill chain: enum → kerberoast → DCSync → domain compromise |
| `exchange` | Exchange attacks: ProxyShell, ProxyLogon, ProxyNotShell |
| `sccm` | SCCM/ConfigMgr attacks |
| `network` | Router/switch/firewall attacks (SNMP, default creds) |
| `database` | MySQL, MSSQL, PostgreSQL, Oracle attacks |
| `aws` | AWS cloud attacks (S3, EC2 metadata) |
| `azure` | Azure cloud attacks |
| `auto` | Run ALL applicable chains |

### REPL Commands (Interactive Mode)

```
RECON:
  scan <target>          - Scan target (auto: host discovery + service enum)
  enum                   - Enumerate all discovered services
  map                    - Show network visualization

EXPLOIT:
  exploit                - Auto-exploit all found services
  attack <host>:<port>   - Attack specific host:port
  crack                  - Crack found hashes

POST-EXPLOIT:
  privesc                - Attempt privilege escalation
  loot                   - Harvest credentials and sensitive data
  pivot                  - Find and pivot to new networks
  shell <type>           - Generate reverse shell (bash/python/php)

ENTERPRISE:
  enterprise ad          - Run AD attack chain
  enterprise exchange    - Run Exchange attack chain
  fingerprint <port>     - Zero-day fingerprint a service

AUTO CHAINS:
  auto                   - Full auto: scan → enum → exploit → privesc → pivot → loot
  auto-recon             - Auto recon chain
  auto-exploit           - Auto exploit chain
  auto-post              - Auto post-exploit chain

INFO:
  dashboard              - Show engagement dashboard
  suggest                - Get attack suggestions
  report                 - Generate HTML + JSON report
  creds                  - Show all discovered credentials

SESSION:
  sessions               - List saved sessions
  resume <session_id>    - Resume previous session
  replay                 - List replayable sessions
  set target <ip>        - Set target (auto-scans)

OTHER:
  help                   - Show this help
  exit / quit / q        - Exit (saves session)
```

---

## 🏢 Enterprise Pentesting

### Active Directory Full Kill Chain

```bash
pen-ai enterprise 10.10.10.0/24 --chain ad --username admin --password P@ssw0rd --domain corp.local
```

**What happens:**
```
1. Domain Enumeration     → LDAP/SMB/DNS enumeration
2. User Enumeration       → Find all domain users
3. Group Analysis         → Identify high-value groups
4. Kerberoasting          → Extract service account hashes
5. Password Spraying      → Test common passwords
6. Lateral Movement       → PsExec, WMIExec, SMBExec
7. Privilege Escalation   → DCSync, ACL abuse
8. Domain Compromise      → KRBTGT hash extraction
```

### Exchange Server Attacks

```bash
pen-ai enterprise 10.10.10.5 --chain exchange
```

**What happens:**
```
1. Exchange Enumeration   → EWS, OWA endpoint discovery
2. Vulnerability Check    → ProxyShell, ProxyLogon, ProxyNotShell
3. Exploitation           → Remote code execution
```

### Zero-Day Fingerprinting

```bash
pen-ai fingerprint 10.10.10.5 80 http
```

**What happens:**
```
1. Banner Grabbing        → Identify service banner
2. Deep Fingerprint       → Service-specific fingerprinting
3. Version Detection      → Exact version identification
4. CVE Research           → NVD, exploit-db, searchsploit
5. Exploit Matching       → Find available exploits
```

**Supported Services:**
- HTTP/HTTPS (Apache, nginx, IIS, Tomcat, Jenkins, WebLogic)
- SSH (OpenSSH version analysis)
- SMB (signing checks, anonymous access)
- LDAP (anonymous bind detection)
- FTP (anonymous access)
- MySQL/MSSQL/PostgreSQL
- RDP (BlueKeep detection)
- Generic (banner analysis + nmap scripts)

---

## 🔄 Engagement Lifecycle

```
1. RECON          LLM decides scan strategy
2. ENUMERATE      LLM picks enumeration tools
3. FINGERPRINT    Zero-day identification of unknown services
4. CVE RESEARCH   NVD, exploit-db, searchsploit matching
5. IDENTIFY       LLM reasons about vulnerabilities
6. EXPLOIT        LLM selects exploitation tools
7. POST-EXPLOIT   LLM explores compromised host
8. PIVOT          LLM discovers routes
9. LOOT           LLM harvests credentials
10. REPORT        LLM writes findings with evidence
```

**No phase is forced.** The LLM adapts to what's discovered.

---

## 🗺️ Enterprise Coverage

| Target Area | Capabilities |
|-------------|--------------|
| **Active Directory** | LDAP/SMB enum, kerberoasting, DCSync, pass-the-hash, BloodHound |
| **Exchange Server** | ProxyShell, ProxyLogon, ProxyNotShell, credential extraction |
| **SCCM/ConfigMgr** | Site server enumeration, credential extraction |
| **Web Applications** | SQLi, XSS, command injection, LFI, API enum, version detection |
| **Network Infrastructure** | SNMP, default creds, router/switch/firewall attacks |
| **Databases** | MySQL, MSSQL, PostgreSQL, Oracle attacks |
| **Cloud (AWS/Azure)** | S3 buckets, EC2 metadata, Azure management |
| **IoT** | Device discovery, firmware analysis, protocol testing |
| **Binary** | checksec, static/dynamic analysis, buffer overflow |
| **Host** | SUID, cron, kernel exploits, credential hunting |
| **Post-Exploit** | SSH sessions, credential harvesting, SOCKS pivots |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    LLM (MiMo/DeepSeek)              │
│              Decides EVERYTHING                      │
└──────────────────────┬──────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
    ┌─────────┐  ┌──────────┐  ┌──────────┐
    │ Scanner │  │ Exploiter│  │ Reporter │
    │ (nmap)  │  │ (hydra)  │  │ (HTML)   │
    └─────────┘  └──────────┘  └──────────┘
         │             │             │
         └─────────────┼─────────────┘
                       │
              ┌────────▼────────┐
              │ Enterprise      │
              │ Attack Chains   │
              │ (AD, Exchange)  │
              └─────────────────┘
                       │
              ┌────────▼────────┐
              │ Zero-Day        │
              │ Fingerprinting  │
              │ (CVE Research)  │
              └─────────────────┘
```

---

## 📁 Project Structure

```
pen-ai/
├── app/
│   ├── cli/main.py              # CLI (freewill, enterprise, scan, fingerprint)
│   └── terminal/repl.py         # Interactive REPL
├── ai/
│   ├── freewill_agent.py        # Full autonomous agent (enterprise-enhanced)
│   ├── autonomous_executor.py   # Command execution with auto-install
│   ├── brain.py                 # Observation layer
│   ├── credential_manager.py    # Credential tracking
│   └── llm_client.py            # LLM API client
├── enterprise/
│   ├── zeroday_fingerprint.py   # Zero-day fingerprinting engine
│   ├── attack_chains.py         # Enterprise attack chains (AD, Exchange, etc.)
│   ├── tools.py                 # Enterprise tool integrations
│   └── bloodhound_queries.py    # BloodHound integration
├── core/
│   ├── safety.py                # Command safety checks
│   └── session_replay.py        # Session replay
├── recon/
│   ├── network.py               # Host/port scanning
│   ├── network_viz.py           # ASCII network maps
│   └── firewall_analysis.py     # Filter detection
├── exploitation/
│   ├── modules/                 # ssh, smb, web, privesc
│   └── engine.py                # Exploitation engine
├── reporting/
│   ├── html_report.py           # HTML report generation
│   └── cvss.py                  # CVSS scoring
└── tests/                       # 208 tests
```

---

## ⚙️ Configuration

### .env File

```env
PENAI_LLM_MODEL=mimo-v2.5-free
PENAI_LLM_BASE_URL=https://opencode.ai/zen/v1
PENAI_LLM_API_KEY=
PENAI_LLM_TEMPERATURE=0.3
PENAI_LLM_MAX_TOKENS=8192
```

---

## 🧪 Testing

```bash
pytest tests/ -v
```

Current suite: **208 tests** (all passing).

---

## 🛡️ Responsible Use

**Only use against systems you own or have written authorization to test.**

Unauthorized access is illegal. Stay in scope.

---

## 📄 License

MIT License

---

**Built for authorized enterprise penetration testing.** Stay in scope. Report clearly.
