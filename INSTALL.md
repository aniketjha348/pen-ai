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
â”œâ”€â”€ ai/                    # AI brain and decision engine
â”‚   â”œâ”€â”€ autonomous_executor.py  # Run any command
â”‚   â”œâ”€â”€ autonomous_agent.py     # LLM-driven agent
â”‚   â”œâ”€â”€ brain.py                # Attack surface analysis
â”‚   â”œâ”€â”€ context_compressor.py   # Token management
â”‚   â”œâ”€â”€ credential_cracker.py   # Auto hash cracking
â”‚   â”œâ”€â”€ shell_generator.py      # Reverse shell generator
â”‚   â”œâ”€â”€ streaming.py            # Real-time output
â”‚   â”œâ”€â”€ llm_client.py           # LLM API client
â”‚   â””â”€â”€ relentless_agent.py     # Never-stop agent
â”œâ”€â”€ app/
â”‚   â”œâ”€â”€ cli/main.py             # CLI entry point
â”‚   â”œâ”€â”€ terminal/repl.py        # Interactive REPL
â”‚   â””â”€â”€ config/                 # Configuration
â”œâ”€â”€ core/
â”‚   â”œâ”€â”€ session.py              # Session persistence
â”‚   â”œâ”€â”€ state/                  # Engagement state
â”‚   â””â”€â”€ orchestrator/           # Main loop
â”œâ”€â”€ ranges/
â”‚   â”œâ”€â”€ ad/agent.py             # Active Directory
â”‚   â”œâ”€â”€ web/agent.py            # Web applications
â”‚   â”œâ”€â”€ binary/agent.py         # Binary exploitation
â”‚   â”œâ”€â”€ iot/agent.py            # IoT devices
â”‚   â””â”€â”€ ctf/agent.py            # CTF/Linux
â”œâ”€â”€ exploitation/               # Exploit modules
â”œâ”€â”€ recon/                      # Reconnaissance
â”œâ”€â”€ pivoting/                   # Network pivoting
â”œâ”€â”€ post_exploitation/          # Post-exploit
â”œâ”€â”€ knowledge/                  # methodology knowledge base
â”œâ”€â”€ enterprise/                 # Enterprise tools
â””â”€â”€ tests/                      # 168 tests
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
