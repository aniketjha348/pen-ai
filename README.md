# PEN-AI 🎯

**Autonomous AI Penetration Testing Agent for Enterprise Internal Networks**

> An autonomous red-team operator that discovers, enumerates, exploits, pivots, and reports across **any authorized enterprise internal environment**. Zero to advanced, end to end. **100% LLM-driven** — no hardcoded rules, no fixed attack chains.

---

## ✨ Why PEN-AI

- **Fully LLM-driven, zero hardcoded rules** — the LLM decides every action
- **3 Operating Modes** — Full Auto, Semi-Auto, Manual
- **Zero-to-advanced lifecycle** — scan → enum → exploit → privesc → pivot → loot → report
- **Works against hardened networks** — firewall bypass, ACL analysis, rate limiting
- **Full attack-surface coverage** — AD, web, binary, IoT, host targets
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

# 🟡 MODE 2: SEMI-AUTOMATIC (auto chain, you review)
pen-ai auto 10.10.10.0/24

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
| `pen-ai auto <target>` | Semi-auto mode | `pen-ai auto 10.10.10.0/24` |
| `pen-ai scan <target>` | Quick scan | `pen-ai scan 192.168.1.0/24` |
| `pen-ai sessions` | List sessions | `pen-ai sessions` |
| `pen-ai tools` | List tools | `pen-ai tools` |

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
  replay <session_id>    - Show session details
  set target <ip>        - Set target (auto-scans)

TOOLS:
  install <tool>         - Install a tool
  run <command>          - Run any command (safety checked)

OTHER:
  help                   - Show this help
  exit / quit / q        - Exit (saves session)
```

---

## 🔄 Three Operating Modes

### 🔴 Mode 1: Full Autonomous (`freewill`)

The LLM decides **everything**. No human input needed.

```bash
pen-ai freewill 10.10.10.0/24
```

**What happens:**
1. LLM decides scan strategy → executes
2. LLM analyzes results → decides next step
3. LLM identifies vulnerabilities → picks exploits
4. LLM exploits → evaluates success
5. LLM post-exploits → harvests credentials
6. LLM pivots → discovers new networks
7. LLM generates report

**No hardcoded rules. Pure LLM intelligence.**

### 🟡 Mode 2: Semi-Automatic (`auto`)

Tool runs the full chain automatically, you review results.

```bash
pen-ai auto 10.10.10.0/24
```

**What happens:**
```
[1/6] Auto-Scanning...        ✓ Found 5 hosts, 12 services
[2/6] Auto-Enumerating...     ✓ Vulnerability checks complete
[3/6] Auto-Exploiting...      ✓ 2 services exploited
[4/6] Auto-PrivEsc...         ✓ Root access on 1 host
[5/6] Auto-Pivoting...        ✓ 1 new network discovered
[6/6] Auto-Reporting...       ✓ HTML report generated
```

### 🟢 Mode 3: Manual (Interactive REPL)

You decide every step. Tool executes your commands.

```bash
pen-ai 10.10.10.0/24
```

```
pen-ai:10.10.10.0 [0h 0s 0c] > scan 10.10.10.0/24
pen-ai:10.10.10.0 [5h 12s 0c] > exploit
pen-ai:10.10.10.0 [5h 12s 2c] [root] > privesc
pen-ai:10.10.10.0 [5h 12s 2c] [admin] > loot
pen-ai:10.10.10.0 [5h 12s 2c] [admin] > report
```

---

## 🔄 Auto Chains

### Full Auto Chain

```bash
# In REPL:
auto

# Or from CLI:
pen-ai auto 10.10.10.0/24
```

**Chain flow:**
```
SCAN → ENUM → EXPLOIT → PRIVESC → PIVOT → LOOT → REPORT
```

Each step:
- Runs automatically
- Shows progress
- Updates state
- Continues to next step
- Stops on completion or error

### Auto Recon Chain

```bash
auto-recon
```

**Chain flow:**
```
HOST_DISCOVERY → PORT_SCAN → SERVICE_ENUM → OS_DETECT → VERSION_DETECT
```

### Auto Exploit Chain

```bash
auto-exploit
```

**Chain flow:**
```
FOR EACH SERVICE:
  → CHECK_VULNERABILITY
  → SELECT_EXPLOIT
  → EXECUTE_EXPLOIT
  → CHECK_SUCCESS
  → RECORD_FINDING
```

### Auto Post-Exploit Chain

```bash
auto-post
```

**Chain flow:**
```
PRIVESC → LOOT → CREDENTIAL_HARVEST → PIVOT_DISCOVERY → NETWORK_SCAN
```

---

## 🗺️ Enterprise Coverage

| Target Area | Capabilities |
|-------------|--------------|
| **Network** | Host discovery, port/service scanning, OS detection, subnet mapping |
| **Firewall / Filter** | Filter detection, ICMP analysis, source-port bypass |
| **Active Directory** | LDAP/SMB enum, kerberoasting, DCSync, pass-the-hash |
| **Web Applications** | SQLi, XSS, command injection, LFI, API enum |
| **IoT** | Device discovery, firmware analysis, protocol testing |
| **Binary** | checksec, static/dynamic analysis, buffer overflow |
| **Host** | SUID, cron, kernel exploits, credential hunting |
| **Post-Exploit** | SSH sessions, credential harvesting, SOCKS pivots |

---

## 🔄 Engagement Lifecycle

```
1. RECON          LLM decides scan strategy
2. ENUMERATE      LLM picks enumeration tools
3. FILTER ANALYZE LLM analyzes filtering
4. IDENTIFY       LLM reasons about vulnerabilities
5. EXPLOIT        LLM selects exploitation tools
6. POST-EXPLOIT   LLM explores compromised host
7. PIVOT          LLM discovers routes
8. LOOT           LLM harvests credentials
9. REPORT         LLM writes findings
```

**No phase is forced.** The LLM adapts to what's discovered.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    LLM (MiMo/DeepSeek/Hy3)          │
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
              │ Engagement State│
              │ (Digital Twin)  │
              └─────────────────┘
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

## 📁 Project Structure

```
pen-ai/
├── app/
│   ├── cli/main.py              # CLI (freewill, auto, scan, sessions, tools)
│   └── terminal/repl.py         # Interactive REPL with 3 modes
├── ai/
│   ├── freewill_agent.py        # Full autonomous LLM-driven agent
│   ├── autonomous_agent.py      # Core agent logic
│   ├── brain.py                 # Observation layer (no hardcoded rules)
│   ├── planner.py               # Action generation (no fixed tools)
│   ├── credential_manager.py    # Credential tracking
│   └── llm_client.py            # LLM API client
├── core/
│   ├── state/engagement_state.py
│   ├── safety.py                # Command safety checks
│   ├── session_replay.py        # Session replay
│   └── orchestrator/pipeline.py
├── recon/
│   ├── network.py               # Host/port scanning
│   ├── network_viz.py           # ASCII network maps
│   └── firewall_analysis.py     # Filter detection
├── exploitation/
│   ├── modules/                 # ssh, smb, web, privesc
│   └── engine.py                # Exploitation engine
├── reporting/
│   ├── html_report.py           # HTML report generation
│   ├── generator.py
│   └── cvss.py                  # CVSS scoring
└── tests/                       # 208 tests
```

---

## 🛡️ Responsible Use

**Only use against systems you own or have written authorization to test.**

Unauthorized access is illegal. Stay in scope.

---

## 📄 License

MIT License

---

**Built for authorized enterprise penetration testing.** Stay in scope. Report clearly.
