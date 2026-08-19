# PEN-AI 🎯

**AI-Powered Adaptive Penetration Testing Operator for Enterprise CPENT Environments**

> An autonomous red-team operator that discovers, enumerates, exploits, pivots, and reports across 5 CPENT range types: **Active Directory, Web, Binary, IoT, CTF**

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/pen-ai.git
cd pen-ai

# Install with all dependencies
pip install -e ".[dev,rag]"

# Or install core only
pip install -e .
```

### First Run

```bash
# Initialize configuration
pen-ai config --init

# Initialize knowledge base
pen-ai knowledge --init

# Start engagement
pen-ai engage --target 192.168.1.0/24
```

---

## 📋 Complete Command Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `pen-ai engage` | Start new engagement | `pen-ai engage --target 10.10.10.0/24` |
| `pen-ai config` | Show/configure settings | `pen-ai config --init` |
| `pen-ai version` | Show version | `pen-ai version` |

### Engagement Options

```bash
# Basic engagement
pen-ai engage --target 192.168.1.0/24

# With specific model
pen-ai engage --target 10.10.10.0/24 --model mimo
pen-ai engage --target 10.10.10.0/24 --model deepseek
pen-ai engage --target 10.10.10.0/24 --model hy3

# Full options
pen-ai engage \
  --target 10.10.10.0/24 \
  --name "CPENT Practice Range" \
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

# Use aliases
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
# Initialize vector store
pen-ai knowledge --init

# Search knowledge
pen-ai knowledge --query "nmap scanning"
pen-ai knowledge --query "kerberoasting"
pen-ai knowledge --query "buffer overflow"

# Filter by category
pen-ai knowledge --query "exploitation" --category exploitation
pen-ai knowledge --query "privesc" --category privesc

# Show stats
pen-ai knowledge --stats
```

### Tools & Exploits

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

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MASTER AI AGENT                       │
│  (LLM: MiMo/DeepSeek/Hy3 → Reasoning → Tool Calling)  │
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ Engagement    │ │ Knowledge     │ │ Tool Registry │
│ State         │ │ RAG           │ │ (25+ tools)   │
│ (Digital Twin)│ │ (ChromaDB)    │ │               │
└───────────────┘ └───────────────┘ └───────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  SCOPE / RoE GATE                        │
│              (Authorization Enforcement)                 │
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ Recon Engine  │ │ 5 Range       │ │ Exploitation  │
│ (Parallel)    │ │ Agents        │ │ Engine        │
│               │ │               │ │ (15 modules)  │
│ • Host Disc   │ │ • AD          │ │               │
│ • Port Scan   │ │ • Web         │ │ • SSH         │
│ • Service Enum│ │ • Binary      │ │ • SMB         │
│ • OS Detect   │ │ • IoT         │ │ • Web         │
│               │ │ • CTF         │ │ • Privesc     │
└───────────────┘ └───────────────┘ └───────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              POST-EXPLOITATION ENGINE                    │
│  (Enumeration → Credential Harvest → Privilege Escalate)│
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ Exploration   │ │ Pivot Manager │ │ Objectives    │
│ Engine        │ │ (Double)      │ │ Tracker       │
└───────────────┘ └───────────────┘ └───────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                 EVIDENCE ENGINE                          │
│  (Raw Output → Screenshots → Artifacts → Timeline)      │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                ATTACK GRAPH (NetworkX)                   │
│  (Nodes: Hosts, Services, Vulns → Edges: Attack Paths)  │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              REPORT GENERATOR                            │
│  (PDF/DOCX → Executive Summary → Technical Findings)    │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Tool Registry (25+ Tools)

### Reconnaissance Tools
| Tool | Description |
|------|-------------|
| `nmap_host_scan` | Discover live hosts |
| `nmap_service_scan` | Scan ports & enumerate services |
| `network_map` | Map network topology |
| `parallel_scan` | Parallel multi-target scanning |

### Active Directory Tools
| Tool | Description |
|------|-------------|
| `ad_enumerate` | Enumerate AD domain |
| `ad_kerberoast` | Kerberoasting attack |
| `ad_asreproast` | AS-REP Roasting |
| `ad_dcsync` | DCSync attack |

### Web Tools
| Tool | Description |
|------|-------------|
| `web_enumerate` | Enumerate web application |
| `web_dir_scan` | Directory discovery |
| `web_api_enum` | API endpoint enumeration |
| `web_sqli_test` | SQL injection testing |
| `web_xss_test` | XSS testing |

### Binary Tools
| Tool | Description |
|------|-------------|
| `binary_analyze` | Analyze binary file |
| `binary_checksec` | Check security features |
| `binary_fuzz` | Fuzz binary target |

### IoT Tools
| Tool | Description |
|------|-------------|
| `iot_discover` | Discover IoT devices |
| `iot_firmware_analyze` | Analyze firmware |

### CTF Tools
| Tool | Description |
|------|-------------|
| `ctf_linux_enum` | Linux enumeration |
| `ctf_privesc_check` | Privilege escalation check |

### Exploitation Tools
| Tool | Description |
|------|-------------|
| `exploit_executor` | Execute exploit |
| `exploit_auto` | Auto-exploit service |
| `exploit_list` | List exploit modules |

---

## 💥 Exploit Modules (15 Modules)

### SSH Exploits
| Module | Difficulty | Description |
|--------|------------|-------------|
| `ssh_brute_force` | Easy | Credential brute force |
| `ssh_key_attack` | Medium | Key permission check |
| `ssh_command_exec` | Easy | Command execution |

### SMB Exploits
| Module | Difficulty | Description |
|--------|------------|-------------|
| `smb_enum_shares` | Easy | Share enumeration |
| `smb_anonymous_access` | Easy | Anonymous access check |
| `smb_brute_force` | Medium | Credential brute force |

### Web Exploits
| Module | Difficulty | Description |
|--------|------------|-------------|
| `http_dir_brute` | Easy | Directory brute force |
| `sqli_test` | Medium | SQL injection testing |
| `xss_test` | Medium | XSS testing |
| `cmdi_test` | Medium | Command injection |
| `lfi_test` | Medium | File inclusion |

### Privilege Escalation
| Module | Difficulty | Description |
|--------|------------|-------------|
| `suid_exploit` | Medium | SUID binary exploitation |
| `cron_exploit` | Medium | Writable cron jobs |
| `kernel_exploit` | Hard | Kernel vulnerabilities |
| `shadow_read` | Easy | Read /etc/shadow |

---

## 📚 Knowledge Base Categories

| Category | Entries | Topics |
|----------|---------|--------|
| Methodology | 2 | Engagement phases, adaptive strategy |
| Reconnaissance | 3 | Nmap, service enum, network mapping |
| Exploitation | 2 | Techniques, credential attacks |
| Privilege Escalation | 2 | Linux/Windows privesc |
| Post-Exploitation | 2 | Enumeration, credential harvesting |
| Pivoting | 2 | SSH tunneling, double pivoting |
| Active Directory | 2 | AD enum, AD attacks |
| Web | 2 | Web testing, web shells |
| Binary | 1 | Buffer overflow, format strings |
| IoT | 1 | Firmware analysis, protocols |
| Tools | 2 | Essential tools, Metasploit |

---

## 🔐 Enterprise CPENT Coverage

### ✅ CPENT Range 1: Active Directory
- [x] Domain enumeration (LDAP, SMB, Kerberos)
- [x] User/Group/Computer enumeration
- [x] SPN enumeration
- [x] Kerberoasting
- [x] AS-REP Roasting
- [x] Pass-the-Hash
- [x] Golden/Silver Ticket
- [x] DCSync
- [x] Unconstrained Delegation
- [x] ACL abuse
- [x] Lateral movement

### ✅ CPENT Range 2: Web Applications
- [x] OWASP Top 10 testing
- [x] SQL Injection
- [x] XSS (Reflected, Stored, DOM)
- [x] Command Injection
- [x] File Inclusion (LFI/RFI)
- [x] SSRF
- [x] XXE
- [x] JWT attacks
- [x] API security testing
- [x] WAF bypass
- [x] Web shell upload

### ✅ CPENT Range 3: Binary Exploitation
- [x] Buffer overflow
- [x] Format string
- [x] Heap exploitation
- [x] Use-after-free
- [x] Binary protection analysis (NX, ASLR, Canary, PIE)
- [x] Shellcode generation
- [x] ROP chain development
- [x] Fuzzing

### ✅ CPENT Range 4: IoT
- [x] Firmware acquisition
- [x] Firmware extraction
- [x] Firmware analysis
- [x] Device emulation
- [x] Protocol analysis (MQTT, CoAP, Modbus)
- [x] Default credential testing
- [x] Hardcoded credential extraction
- [x] Network traffic analysis

### ✅ CPENT Range 5: CTF/Linux
- [x] System enumeration
- [x] User enumeration
- [x] File permission analysis
- [x] SUID/SGID binary exploitation
- [x] Cron job exploitation
- [x] Kernel exploit detection
- [x] Docker/LXC escape
- [x] Password hash cracking
- [x] Flag capture workflow

### ✅ Cross-Cutting Capabilities
- [x] Network segmentation handling
- [x] Pivot/double-pivot workflows
- [x] Hidden network discovery
- [x] Firewall detection
- [x] Proxy/VPN handling
- [x] Custom tool/script execution
- [x] Evidence capture (raw, screenshots, artifacts)
- [x] Attack graph visualization
- [x] Report generation (PDF/DOCX)
- [x] Adaptive decision making (no hardcoded chains)

---

## 🎯 Enterprise Readiness Checklist

| Feature | Status | Notes |
|---------|--------|-------|
| LLM Integration | ✅ | MiMo, DeepSeek, Hy3 (free tier) |
| Tool Calling | ✅ | 25+ tools with function schemas |
| Scope Enforcement | ✅ | RoE validation before every action |
| Parallel Scanning | ✅ | Async with concurrency control |
| Evidence Capture | ✅ | Raw output, screenshots, timeline |
| Attack Graph | ✅ | NetworkX-based visualization |
| RAG Knowledge | ✅ | ChromaDB with 20+ CPENT entries |
| 5 Range Agents | ✅ | AD, Web, Binary, IoT, CTF |
| 15 Exploit Modules | ✅ | SSH, SMB, Web, Privesc |
| Pivot Management | ✅ | Single/double pivot tracking |
| Objective Tracking | ✅ | Flag capture workflow |
| Report Generation | ✅ | PDF/DOCX with executive summary |
| Failure Learning | ✅ | Records and avoids failed actions |
| Adaptive Reasoning | ✅ | No hardcoded attack chains |

---

## 🔧 Configuration

### Environment Variables

```bash
# LLM Configuration
PENAI_LLM_MODEL=mimo-v2.5-free
PENAI_LLM_BASE_URL=https://opencode.ai/zen/v1
PENAI_LLM_TEMPERATURE=0.3
PENAI_LLM_MAX_TOKENS=8192

# Recon Configuration
PENAI_RECON_MAX_THREADS=10
PENAI_RECON_TIMEOUT=300

# Scope Configuration
PENAI_SCOPE_MAX_PIVOTS=3
PENAI_SCOPE_REQUIRE_APPROVAL=false
```

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
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test suite
pytest tests/test_core.py -v
pytest tests/test_llm.py -v
pytest tests/test_exploits.py -v
pytest tests/test_rag.py -v
pytest tests/test_parallel_recon.py -v

# Run with coverage
pytest tests/ --cov=pen-ai --cov-report=html
```

---

## 📁 Project Structure

```
pen-ai/
├── app/
│   ├── cli/main.py              # Typer CLI
│   ├── terminal/ui.py           # Rich terminal UI
│   └── config/
│       ├── settings.py          # Pydantic settings
│       ├── models.py            # Model registry
│       └── loader.py            # Config loader
├── ai/
│   ├── master_agent.py          # Main AI orchestrator
│   ├── planner.py               # Action generation
│   ├── reasoner.py              # Hypothesis generation
│   ├── memory.py                # 3-level memory
│   ├── llm_client.py            # LLM API client
│   └── tool_registry.py         # Dynamic tool registry
├── core/
│   ├── state/engagement_state.py # Digital twin
│   ├── scope/rules.py           # RoE enforcement
│   ├── events/models.py         # Event system
│   └── orchestrator/main.py     # Engagement loop
├── recon/
│   ├── network.py               # Network recon
│   └── parallel.py              # Parallel scanning
├── ranges/
│   ├── ad/agent.py              # Active Directory
│   ├── web/agent.py             # Web applications
│   ├── binary/agent.py          # Binary exploitation
│   ├── iot/agent.py             # IoT devices
│   └── ctf/agent.py             # CTF challenges
├── exploitation/
│   ├── modules/
│   │   ├── base.py              # Base exploit framework
│   │   ├── ssh.py               # SSH exploits
│   │   ├── smb.py               # SMB exploits
│   │   ├── web.py               # Web exploits
│   │   └── privesc.py           # Privilege escalation
│   ├── orchestrator.py          # Exploit orchestrator
│   └── engine.py                # Exploitation engine
├── post_exploitation/engine.py  # Post-access actions
├── pivoting/manager.py          # Pivot management
├── objectives/tracker.py        # Objective tracking
├── evidence/collector.py        # Evidence collection
├── attack_graph/graph.py        # Attack visualization
├── findings/engine.py           # Finding management
├── reporting/generator.py       # Report generation
├── knowledge/
│   ├── cpent_data.py            # CPENT knowledge base
│   └── rag.py                   # ChromaDB RAG
└── tests/                       # Test suite (146 tests)
```

---

## 🎓 CPENT Exam Tips

1. **Always enumerate thoroughly** before exploiting
2. **Document everything** - evidence is crucial for reporting
3. **Think adaptively** - no fixed attack chains
4. **Pivot carefully** - double pivoting requires planning
5. **Check all 5 ranges** - don't miss any objectives
6. **Use the knowledge base** - CPENT-specific techniques
7. **Report properly** - executive summary + technical details

---

## 📄 License

MIT License

---

## 🤝 Contributing

Contributions welcome! See CONTRIBUTING.md for guidelines.

---

**Built for CPENT exam preparation and authorized penetration testing only.**
