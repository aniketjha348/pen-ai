# PEN-AI 🎯

**Autonomous AI Penetration Testing Agent for Enterprise Internal Networks**

> An autonomous red-team operator that discovers, enumerates, exploits, pivots, and reports across **any authorized enterprise internal environment** — from a single workstation to fully segmented multi-zone corporate networks. Zero to advanced/ultra-advanced, end to end.

Covers the full internal-engagement attack surface: **network**, **Active Directory**, **web applications**, **IoT/specialty devices**, **binary/software**, and **host-based targets**. It combines structured tooling with adaptive LLM-driven decision making and a "Go Deeper" firewall/filter bypass engine so it keeps working even against networks that filter, rate-limit, and otherwise resist scanning.

> **Intended use:** authorized penetration testing and defensive security assessment only (your own infrastructure, or explicit written engagement scope). Unauthorized access is illegal — see [Responsible Use](#-responsible-use--authorization).

---

## ✨ Why PEN-AI

Most automated scanners stop at "find an open port." PEN-AI is built as an **adversary, not a scanner**:

- **Adaptive, not scripted** — no fixed attack chains. It observes, builds a model of the network, generates hypotheses, and re-plans as it learns.
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
# Initialize configuration
pen-ai config --init

# Initialize the vector knowledge base
pen-ai knowledge --init

# Start an engagement against an internal segment
pen-ai engage --target 192.168.1.0/24
```

---

## 📋 Command Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `pen-ai engage` | Start a new engagement | `pen-ai engage --target 10.10.10.0/24` |
| `pen-ai config` | Show/configure settings | `pen-ai config --init` |
| `pen-ai version` | Show version | `pen-ai version` |

### Engagement Options

```bash
# Basic engagement against an internal segment
pen-ai engage --target 192.168.1.0/24

# With a specific reasoning model
pen-ai engage --target 10.10.10.0/24 --model mimo
pen-ai engage --target 10.10.10.0/24 --model deepseek
pen-ai engage --target 10.10.10.0/24 --model hy3

# Full options
pen-ai engage \
  --target 10.10.10.0/24 \
  --name "Internal Segment Alpha" \
  --model mimo \
  --max-pivots 3 \
  --max-cycles 100

# Without RAG (faster startup)
pen-ai engage --target 10.10.10.0/24 --no-rag
```

### Model Selection

```bash
# List all models
pen-ai models

# Model aliases
pen-ai engage --target 10.10.10.0/24 --model mimo       # Best overall
pen-ai engage --target 10.10.10.0/24 --model deepseek    # Fastest
pen-ai engage --target 10.10.10.0/24 --model hy3         # Best reasoning

# Semantic aliases
pen-ai engage --target 10.10.10.0/24 --model fast        # = deepseek
pen-ai engage --target 10.10.10.0/24 --model best        # = mimo
pen-ai engage --target 10.10.10.0/24 --model reasoning   # = hy3
```

### Knowledge Base

```bash
# Initialize the vector store
pen-ai knowledge --init

# Search methodology / technique knowledge
pen-ai knowledge --query "nmap scanning"
pen-ai knowledge --query "kerberoasting"
pen-ai knowledge --query "buffer overflow"
pen-ai knowledge --query "firewall bypass"

# Filter by category
pen-ai knowledge --query "exploitation" --category exploitation
pen-ai knowledge --query "privesc" --category privesc

# Show stats
pen-ai knowledge --stats
```

### Tools & Exploit Modules

```bash
# List all tools
pen-ai tools

# Filter by category
pen-ai tools --category recon
pen-ai tools --category exploitation
pen-ai tools --category web

# List exploit modules
pen-ai exploits
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
| **Post-Exploitation & Pivoting** | SSH/command execution, credential harvesting, SOCKS/chisel pivots, lateral movement |

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

## 🔄 Engagement Lifecycle

```
1. RECON          Discover hosts, ports, segments — adapt to ICMP/rate filtering
2. ENUMERATE      Deep-dive every relevant service (AD, web, IoT, files)
3. FILTER ANALYZE Identify & bypass firewalls/filters between you and the target
4. IDENTIFY       Convert findings into prioritized attack vectors
5. EXPLOIT        Gain access (credentials, injection, binary, service)
6. POST-EXPLOIT   Enumerate the compromised host, escalate privileges
7. PIVOT          Move to adjacent segments / trust boundaries
8. LOOT           Harvest credentials, secrets, keys, sensitive data
9. REPORT         Produce structured findings + executive summary
```

PEN-AI does not assume a flat network. It expects segmentation, filtering, and defensive awareness — and is built to work *through* them.

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

Current suite: **180 tests** (2 Windows-specific autonomous-executor tests fail only on non-Linux hosts).

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
│   └── tool_registry.py         # Dynamic tool registry
├── core/
│   ├── state/engagement_state.py # Digital twin of the network
│   ├── scope/rules.py           # Rules of Engagement enforcement
│   ├── events/models.py         # Event system
│   └── orchestrator/main.py     # Engagement loop
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
├── post_exploitation/engine.py   # Post-access actions
├── pivoting/manager.py           # Pivot management
├── objectives/tracker.py
├── evidence/collector.py
├── attack_graph/graph.py
├── findings/engine.py
├── reporting/generator.py
├── knowledge/
│   ├── methodology_data.py       # Enterprise pentest knowledge base
│   └── rag.py                    # ChromaDB RAG
└── tests/                        # 180 tests
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
