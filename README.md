# PEN-AI 🎯

**Autonomous AI Penetration Testing Agent for Enterprise Internal Networks**

> An autonomous red-team operator that discovers, enumerates, exploits, pivots, and reports across **any authorized enterprise internal environment** — from a single workstation to fully segmented multi-zone corporate networks. Zero to advanced/ultra-advanced, end to end.

Covers the full internal-engagement attack surface: **network**, **Active Directory**, **web applications**, **IoT/specialty devices**, **binary/software**, and **host-based targets**. It combines structured tooling with adaptive LLM-driven decision making and a "Go Deeper" firewall/filter bypass engine so it keeps working even against networks that filter, rate-limit, and otherwise resist scanning.

> **Intended use:** authorized penetration testing and defensive security assessment only (your own infrastructure, or explicit written engagement scope). Unauthorized access is illegal — see [Responsible Use](#-responsible-use--authorization).

---

## ✨ Why PEN-AI

Most automated scanners stop at "find an open port." PEN-AI is built as an **adversary, not a scanner**:

- **Fully LLM-driven, zero hardcoded rules** — the LLM decides every action: which scan tools to use, which attacks to attempt, which post-exploit paths to explore. No fixed attack chains, no hardcoded tool mappings, no preset vulnerability lists.
- **Zero-to-advanced lifecycle** — host discovery → deep enumeration → filter/firewall bypass → exploitation → post-exploitation → privilege escalation → lateral movement → pivoting → objective completion → reporting.
- **Works against hardened networks** — understands ICMP filtering, rate limiting, stateless ACLs, and firewall misconfigurations, and adjusts scanning vigor accordingly.
- **Full attack-surface coverage** — one operator across AD, web, binary, IoT, and host targets, with enterprise tool integration (Metasploit, CrackMapExec, BloodHound, SQLMap, Hydra, LinPEAS, Chisel...).
- **Evidence & reporting built-in** — every action is logged; findings, credentials, and access are tracked and exported for a professional report.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/aniketjha348/pen-ai.git
cd pen-ai

# Install with all dependencies (dev + RAG knowledge base)
pip install -e ".[dev,rag]"

# Or install core only
pip install -e .
```

> **Runtime environment:** PEN-AI is a Kali/Linux-oriented tool (it shells out to `nmap`, `sshpass`, `smbclient`, etc.). Run it inside a Kali VM/container, or any Linux box with the required tooling. See [Environment](#-environment--required-tools).

### First Run

```bash
# Start interactive REPL
pen-ai

# Start with a target
pen-ai 10.10.10.0/24

# Quick scan mode
pen-ai scan 10.10.10.0/24
```

---

## 📋 Command Reference

### CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `pen-ai` | Start interactive REPL | `pen-ai` |
| `pen-ai <target>` | Start REPL with target | `pen-ai 10.10.10.0/24` |
| `pen-ai scan <target>` | Quick scan and show results | `pen-ai scan 192.168.1.0/24` |
| `pen-ai sessions` | List saved sessions | `pen-ai sessions` |
| `pen-ai tools` | List available tools | `pen-ai tools` |

### Engagement Options

```bash
# Basic engagement against an internal segment
pen-ai 10.10.10.0/24

# With a specific model
pen-ai 10.10.10.0/24 --model mimo
pen-ai 10.10.10.0/24 --model deepseek
pen-ai 10.10.10.0/24 --model hy3

# Resume a previous session
pen-ai --resume 20260819_1430
```

### REPL Commands (inside interactive mode)

```
RECON:
  scan <target>          - Scan target (hosts + services)
  enum                   - Enumerate all discovered services

EXPLOIT:
  exploit                - Auto-exploit all found services
  attack <host>:<port>   - Attack specific host:port
  crack                  - Crack found hashes

POST-EXPLOIT:
  pivot                  - Find and pivot to new networks
  shell <type>           - Generate reverse shell (bash/python/php)

INFO:
  state                  - Show current engagement state
  suggest                - Get attack suggestions
  report                 - Show final report

SESSION:
  sessions               - List saved sessions
  resume <session_id>    - Resume previous session
  set target <ip>        - Set target

TOOLS:
  install <tool>         - Install a tool
  run <command>          - Run any command
  auto                   - Start autonomous mode (never stops)

OTHER:
  help                   - Show help
  exit / quit / q        - Exit (saves session)
```

---

## 🗺️ Enterprise Coverage

PEN-AI treats an internal network like a real one — starting from a foothold and working outward across zones, filtering, and trust boundaries.

| Target Area | Capabilities |
|-------------|--------------|
| **Network** | Host discovery, controlled port/service scanning, OS detection, subnet/segment mapping, unreachable detection |
| **Firewall / Filter Bypass** | Filter-mechanism identification (router ACL / firewall / iptables / device), ICMP-signature analysis, rule mapping, stateless weak-rule source-port bypass |
| **Active Directory** | LDAP/SMB enumeration, kerberoasting, AS-REP roasting, DCSync, pass-the-hash, BloodHound attack paths |
| **Web Applications** | Directory discovery, SQLi / XSS / command injection / LFI, JWT analysis, API enumeration, SQLMap |
| **IoT / Specialty** | Device discovery, firmware acquisition & extraction, firmware analysis, hardcoded credential review, protocol analysis |
| **Binary / Software** | checksec-style hardening checks, static & dynamic analysis, fuzzing, buffer-overflow / format-string exploit generation |
| **Host / Privilege Escalation** | SUID, writable cron, kernel, credential hunting, LinPEAS-style enumeration |
| **Post-Exploitation & Pivoting** | Persistent SSH sessions (connect once, exec many, auto-reconnect), credential harvesting, SOCKS/chisel pivots, lateral movement |

### Go Deeper: Firewall & Filter Engine

Segment-protected networks are where scanners fail. PEN-AI ships a dedicated filter-analysis stack (`recon/firewall_analysis.py`) that:

1. **Detects** the filtering mechanism by interpreting responses — a TCP probe answered with **ICMP Type 3 Code 13 (Communication Administratively Prohibited)** is the classic signature of a Cisco router / stateless ACL.
2. **Maps** filter rules: `closed` responses prove a host is live and routed behind the filter; `filtered` responses mean silent-drop. This both confirms reachability and flags misconfigurations (e.g. exposed ICMP-unreachable messages).
3. **Bypasses** weak stateless rules with source-port spoofing (`-g 20` to mimic an active-FTP data channel, or `53`/`67`/`68`), then diffs baseline vs. bypass to reveal newly-visible attack surface.

```bash
# In the interactive REPL, run a controlled scan then let the agent classify it:
#   pen-ai 10.10.20.5            (start REPL targeting the segment)
#   run nmap -Pn -sS -T1 --max-retries 1 -p 1-100 10.10.20.5

# The agent's tool registry exposes the analysis directly:
#   filter_detect            -> identify the filtering mechanism (router/fw/iptables/device)
#   filter_rule_map          -> which ports pass (open/closed) vs. dropped (filtered)
#   filter_sourceport_bypass -> re-scan from a spoofed source port (e.g. -g 20) and diff
```

---

## 🔄 Engagement Lifecycle (All LLM-Decided)

```
1. RECON          LLM decides scan strategy (nmap/masscan/rustscan, flags, ports)
2. ENUMERATE      LLM picks enumeration tools per discovered service
3. FILTER ANALYZE LLM analyzes filtering and decides bypass approach
4. IDENTIFY       LLM reasons about vulnerabilities (no fixed CVE list)
5. EXPLOIT        LLM selects exploitation tools and payloads
6. POST-EXPLOIT   LLM explores compromised host (GTFOBins, kernel, config)
7. PIVOT          LLM discovers routes and chooses pivoting method
8. LOOT           LLM harvests credentials and sensitive data
9. REPORT         LLM writes findings with CVSS scoring
```

**No phase is forced.** The LLM skips phases that don't apply and revisits phases when new information emerges. The engagement adapts to what's discovered, not a predetermined sequence.

---

## ⚙️ DeepEngage: One-Shot Chained Engagement

The `deep_engage` tool runs the entire zero-to-advanced lifecycle against a target in one call:

```
RECON → FILTER_ANALYZE → ENUMERATE → EXPLOIT → POST_EXPLOIT → PIVOT → REPORT
```

- **RECON** — host discovery + port/service scan
- **FILTER_ANALYZE** — identifies the firewall/filter in front of the target and records it as a finding
- **ENUMERATE** — records observed services (no hardcoded risk ratings — LLM decides what's important)
- **EXPLOIT** — attempts every open service via the exploit modules and promotes access on success
- **POST_EXPLOIT** — documents the beachhead and harvested credentials
- **PIVOT** — records pivot points once access is held
- **REPORT** — writes Markdown + JSON report artifacts to `reports/`

```python
from core.orchestrator.pipeline import DeepEngagePipeline

async def go():
    payload = await DeepEngagePipeline(target="10.10.20.5").run()
    print(payload["artifacts"])  # paths to report.md / report.json
```

The pipeline's scan/filter/exploit runners are injectable (sync or async), so it runs end-to-end offline in tests and degrades gracefully on hosts without the Kali toolchain.

---

## 🏗️ Architecture

```
                       MASTER AI AGENT
            (LLM: MiMo/DeepSeek/Hy3 -> Reasoning -> Tool Calling)
                              |
            +-----------------+-----------------+
            |                 |                 |
            v                 v                 v
   Engagement State    Knowledge RAG        Tool Registry
   (Digital Twin)      (ChromaDB)           (recon/exploit/
                                             post-exploit/
                                             pivoting/filter)
                              |
   +------------+------------+------------+------------+
   |            |            |            |            |
   v            v            v            v            v
 ACTIVE DIR    WEB         BINARY         IOT        HOST TARGETS
 (kerberoast,  (sqli,      (reverse       (firmware   (privesc,
  dcsync, pth)  xss, lfi)   engineering)   analysis)   lateral)
```

Two complementary operating modes:

- **Structured `MasterAgent`** — a disciplined planner/reasoner/registry loop with **Rules-of-Engagement scope validation** and approval gates. Best for controlled, authorized engagements.
- **Autonomous `RelentlessAgent`** — an LLM-driven terminal operator with full tool control, installs what it needs, and keeps going until stopped. Best when maximum adaptability is required (use only within authorized scope).

---

## 🌐 Environment & Required Tools

- **OS:** Kali Linux (or any Linux with the toolchain below). The shell-outs use `apt-get`, `which`, `/tmp`, `sshpass`, `smbclient`, `nmap`, etc., so a Windows host is **not** the runtime target.
- **LLM API:** a reasoning model (MiMo / DeepSeek / Hy3 via an OpenAI-compatible endpoint, default `https://opencode.ai/zen/v1`). Without a key, PEN-AI falls back to built-in heuristic commands (reduced "freewill").
- **Recommended tooling** (auto-usable if installed): `nmap`, `sshpass`, `smbclient`, `crackmapexec`, `impacket`, `bloodhound-python`, `sqlmap`, `hydra`, `searchsploit`, `metasploit`, `john`/`hashcat`, `linpeas`, `chisel`, `binwalk`, `gdb`/`pwndbg`/`radare2`.
- **Neo4j (optional)** — BloodHound attack-path queries (`enterprise/bloodhound_queries.py`) auto-connect via `BLOODHOUND_URI`/`BLOODHOUND_USER`/`BLOODHOUND_PASSWORD` env vars, or `bolt://localhost:7687` with `neo4j`/`bloodhound` defaults; return empty results when offline.

---

## ⚙️ Configuration

### .env File

```env
# PEN-AI Configuration
PENAI_LLM_MODEL=mimo-v2.5-free
PENAI_LLM_BASE_URL=https://opencode.ai/zen/v1
PENAI_LLM_API_KEY=
PENAI_LLM_TEMPERATURE=0.3
PENAI_LLM_MAX_TOKENS=8192
PENAI_LLM_TIMEOUT=120
PENAI_RECON_MAX_THREADS=10
PENAI_SCOPE_MAX_PIVOTS=3
PENAI_SCOPE_REQUIRE_APPROVAL=false
```

> `.env` and the local RAG store are git-ignored — never commit real API keys or target data.

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific suites
pytest tests/test_core.py -v
pytest tests/test_llm.py -v
pytest tests/test_exploits.py -v
pytest tests/test_rag.py -v
pytest tests/test_parallel_recon.py -v
pytest tests/test_firewall.py -v   # firewall/filter analysis engine

# Run with coverage
pytest tests/ --cov=pen-ai --cov-report=html
```

Current suite: **208 tests** (all passing).

---

## 📁 Project Structure

```
pen-ai/
├── app/
│   ├── cli/main.py              # Typer CLI
│   ├── terminal/
│   │   ├── ui.py                # Rich terminal UI
│   │   └── repl.py              # Interactive REPL
│   └── config/                  # Settings, model registry, loader
├── ai/
│   ├── master_agent.py          # Structured orchestrator (RoE-validated)
│   ├── relentless_agent.py      # Autonomous continuous operator
│   ├── planner.py               # Action generation
│   ├── reasoner.py              # Hypothesis generation
│   ├── memory.py                # 3-level memory
│   ├── llm_client.py            # LLM API client + tool calling
│   ├── sessions.py              # Persistent paramiko SSH session manager
│   └── tool_registry.py         # Dynamic tool registry
├── core/
│   ├── state/engagement_state.py # Digital twin of the network
│   ├── scope/rules.py           # Rules of Engagement enforcement
│   ├── events/models.py         # Event system
│   └── orchestrator/
│       ├── main.py              # Engagement loop
│       └── pipeline.py          # DeepEngage: zero-to-advanced chained pipeline
│   └── utils/shell.py           # Safe shell command builders (quoting)
├── recon/
│   ├── network.py               # Host discovery, port/service scan
│   ├── parallel.py              # Parallel scanning
│   └── firewall_analysis.py     # Filter detection, rule mapping, source-port bypass
├── ranges/
│   ├── ad/agent.py              # Active Directory attacks
│   ├── web/agent.py             # Web app testing
│   ├── binary/agent.py          # Binary exploitation / RE
│   ├── iot/agent.py             # IoT / firmware
│   └── ctf/agent.py             # Host / web-based targets (Linux & web misconfigs)
├── exploitation/
│   ├── modules/                 # ssh, smb, web, privesc exploits
│   ├── orchestrator.py          # Exploit orchestrator
│   └── engine.py                # Exploitation engine
├── enterprise/tools.py          # MSF, CrackMapExec, BloodHound, SQLMap, Hydra, LinPEAS, Chisel
├── enterprise/bloodhound_queries.py  # Neo4j attack-path Cypher queries
├── post_exploitation/engine.py   # Post-access actions
├── pivoting/manager.py           # Pivot management
├── objectives/tracker.py
├── evidence/collector.py
├── attack_graph/graph.py
├── findings/engine.py
├── reporting/generator.py        # CVSS v3.1 auto-scored findings
├── reporting/cvss.py             # CVSS v3.1 scoring engine
├── knowledge/
│   ├── methodology_data.py       # Enterprise pentest knowledge base
│   └── rag.py                    # ChromaDB RAG
└── tests/                        # 208 tests (all passing)
```

---

## 🛡️ Responsible Use & Authorization

PEN-AI is a full-featured enterprise penetration testing operator. **You may only use it against systems you own or systems for which you have explicit, written authorization (e.g., an authorized internal engagement/scope of work).**

- Define your **scope and Rules of Engagement** before starting (`core/scope/rules.py` enforces this in structured mode).
- The autonomous ("never stop") mode will aggressively discover and move — **point it only at in-scope targets**.
- Anything you discover is evidence for a defensive report, not for misuse.

Unauthorized scanning or access is illegal in most jurisdictions and can carry criminal penalties. You — the operator — are responsible for staying within scope and applicable law.

---

## 📄 License

MIT License

---

## 🤝 Contributing

Contributions welcome! See CONTRIBUTING.md for guidelines.

---

**Built for authorized enterprise internal penetration testing.** Stay in scope. Report clearly.
