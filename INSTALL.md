# PEN-AI Installation Guide

## Quick Install

```bash
# Clone the repository
git clone <repo-url> pen-ai
cd pen-ai

# Install in development mode
pip install -e ".[dev]"

# Verify installation
pen-ai --help
```

## Requirements

- Python 3.10+
- Linux/WSL recommended (Windows works but some tools need WSL)
- Nmap installed (`apt-get install nmap` or `choco install nmap`)

## Full Install (All Tools)

```bash
# System tools
sudo apt-get update
sudo apt-get install -y \
    nmap \
    enum4linux \
    smbclient \
    ldapsearch \
    sshpass \
    gobuster \
    nikto \
    whatweb \
    hydra \
    john \
    hashcat \
    binwalk \
    checksec \
    curl \
    wget \
    netcat-openbsd \
    socat

# Python tools
pip install impacket httpx python-Levenshtein

# Go tools (optional)
go install github.com/ffuf/ffuf/v2@latest

# Wordlists
sudo apt-get install -y wordlists
sudo ln -sf /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/common.txt
```

## Windows Install

```bash
# Install Python 3.10+ from python.org
# Install Nmap from https://nmap.org/download.html

pip install -e ".[dev]"

# Most tools work natively on Windows
# For Linux-only tools, use WSL:
wsl --install
```

## Usage

### Interactive Mode (Recommended)

```bash
# Start interactive REPL
pen-ai

# Start with target
pen-ai 192.168.1.0/24

# Resume previous session
pen-ai --resume 20260819_143022
```

### CLI Commands

```bash
# Quick scan
pen-ai scan 192.168.1.0/24

# List sessions
pen-ai sessions

# List tools
pen-ai tools
```

### Interactive Commands

Once in the REPL:

```
pen-ai > scan 192.168.1.0/24        # Full scan
pen-ai > exploit                     # Auto-exploit all
pen-ai > enum                        # Deep enumeration
pen-ai > attack 192.168.1.10:80     # Attack specific target
pen-ai > pivot                       # Find new networks
pen-ai > crack                       # Crack found hashes
pen-ai > suggest                     # Get AI suggestions
pen-ai > auto                        # Full auto mode (never stops)
pen-ai > state                       # Show current status
pen-ai > report                      # Generate report
pen-ai > install gobuster            # Install a tool
pen-ai > run nmap -sV 192.168.1.1   # Run any command
pen-ai > shell bash 10.10.10.1 4444  # Generate reverse shell
pen-ai > sessions                    # List saved sessions
pen-ai > resume 20260819_1430        # Resume session
pen-ai > help                        # Show help
pen-ai > exit                        # Exit (saves session)
```

## LLM Configuration

PEN-AI works with free models from OpenCode.ai:

```bash
# Default (MiMo V2.5 - best overall)
pen-ai

# Use DeepSeek (fastest)
pen-ai --model deepseek

# Use Hy3 (best reasoning)
pen-ai --model hy3

# Use custom API
export PENAI_LLM_API_KEY=your-key
export PENAI_LLM_BASE_URL=https://your-api.com/v1
pen-ai --model your-model
```

### Available Free Models

| Model | Speed | Quality | Use Case |
|-------|-------|---------|----------|
| MiMo V2.5 | Medium | Best | General pentesting |
| DeepSeek V4 Flash | Fast | Good | Quick decisions |
| Hy3 | Slow | Best | Complex analysis |

## Project Structure

```
pen-ai/
├── ai/                    # AI brain and decision engine
│   ├── autonomous_executor.py  # Run any command
│   ├── autonomous_agent.py     # LLM-driven agent
│   ├── brain.py                # Attack surface analysis
│   ├── context_compressor.py   # Token management
│   ├── credential_cracker.py   # Auto hash cracking
│   ├── shell_generator.py      # Reverse shell generator
│   ├── streaming.py            # Real-time output
│   ├── llm_client.py           # LLM API client
│   └── relentless_agent.py     # Never-stop agent
├── app/
│   ├── cli/main.py             # CLI entry point
│   ├── terminal/repl.py        # Interactive REPL
│   └── config/                 # Configuration
├── core/
│   ├── session.py              # Session persistence
│   ├── state/                  # Engagement state
│   └── orchestrator/           # Main loop
├── ranges/
│   ├── ad/agent.py             # Active Directory
│   ├── web/agent.py            # Web applications
│   ├── binary/agent.py         # Binary exploitation
│   ├── iot/agent.py            # IoT devices
│   └── ctf/agent.py            # CTF/Linux
├── exploitation/               # Exploit modules
├── recon/                      # Reconnaissance
├── pivoting/                   # Network pivoting
├── post_exploitation/          # Post-exploit
├── knowledge/                  # CPENT knowledge base
├── enterprise/                 # Enterprise tools
└── tests/                      # 168 tests
```

## Troubleshooting

### "Command not found: pen-ai"
```bash
pip install -e .
# or
python -m app.cli.main
```

### "nmap: command not found"
```bash
sudo apt-get install nmap
```

### "sshpass: command not found"
```bash
sudo apt-get install sshpass
```

### Windows Unicode Issues
```bash
# Use Windows Terminal or Git Bash
# Or set PYTHONIOENCODING=utf-8
```

## Testing

```bash
# Run all tests
cd pen-ai
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_autonomous.py -v
```

## Safety

PEN-AI is for **authorized penetration testing only**.

- Always get written authorization before testing
- Stay within the defined scope
- The tool enforces basic safety checks
- All sessions are logged for audit
- Use responsibly and ethically
