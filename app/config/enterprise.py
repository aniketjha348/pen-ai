"""Enterprise Mode - Full auto pentesting with no permission prompts."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EnterpriseMode(str, Enum):
    """Enterprise operation modes."""

    FULL_AUTO = "full_auto"           # No prompts, full automation
    SEMI_AUTO = "semi_auto"           # Prompts for high-risk actions
    MANUAL = "manual"                 # Prompts for everything
    SANDBOX = "sandbox"               # Safe testing mode


class ToolAvailability(str, Enum):
    """Tool availability status."""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    PARTIAL = "partial"


@dataclass
class EnterpriseConfig:
    """Enterprise pentesting configuration."""

    # Mode settings
    mode: EnterpriseMode = EnterpriseMode.FULL_AUTO
    auto_exploit: bool = True
    auto_pivot: bool = True
    auto_loot: bool = True
    auto_report: bool = True

    # No permission prompts
    require_approval_exploitation: bool = False
    require_approval_pivoting: bool = False
    require_approval_shells: bool = False
    require_approval_loot: bool = False

    # Aggressive settings
    max_pivots: int = 5
    max_concurrent_shells: int = 10
    aggressive_scanning: bool = True
    deep_enumeration: bool = True

    # Tool paths
    metasploit_path: str = "msfconsole"
    crackmapexec_path: str = "crackmapexec"
    bloodhound_path: str = "bloodhound-python"
    chisel_path: str = "chisel"
    ligolo_path: str = "proxy"    responder_path: str = "responder"
    ntlmrelayx_path: str = "ntlmrelayx"
    linpeas_path: str = "linpeas.sh"
    winpeas_path: str = "winPEASany.exe"
    burpsuite_path: str = "burpsuite"

    # Evidence settings
    capture_all_commands: bool = True
    capture_all_output: bool = True
    capture_screenshots: bool = True
    auto_screenshot_loot: bool = True

    # Reporting
    auto_generate_report: bool = True
    report_format: str = "pdf"  # pdf, docx, html


# Global enterprise config
enterprise_config = EnterpriseConfig()


class ToolChecker:
    """Check availability of enterprise tools."""

    REQUIRED_TOOLS = {
        # Reconnaissance
        "nmap": {"category": "recon", "critical": True},
        "masscan": {"category": "recon", "critical": False},
        "enum4linux": {"category": "recon", "critical": True},
        "ldapsearch": {"category": "recon", "critical": True},

        # Exploitation
        "msfconsole": {"category": "exploitation", "critical": True},
        "searchsploit": {"category": "exploitation", "critical": True},
        "sqlmap": {"category": "exploitation", "critical": True},
        "hydra": {"category": "exploitation", "critical": True},

        # AD Attacks
        "crackmapexec": {"category": "ad", "critical": True},
        "bloodhound-python": {"category": "ad", "critical": True},
        "GetUserSPNs.py": {"category": "ad", "critical": True},
        "secretsdump.py": {"category": "ad", "critical": True},
        "psexec.py": {"category": "ad", "critical": True},
        "wmiexec.py": {"category": "ad", "critical": True},

        # Pivoting
        "chisel": {"category": "pivot", "critical": True},
        "ligolo-ng": {"category": "pivot", "critical": False},
        "sshpass": {"category": "pivot", "critical": True},

        # Post-Exploitation
        "linpeas.sh": {"category": "post", "critical": True},
        "winPEASany.exe": {"category": "post", "critical": False},

        # Web
        "nikto": {"category": "web", "critical": False},
        "gobuster": {"category": "web", "critical": True},
        "ffuf": {"category": "web", "critical": False},

        # Binary
        "checksec": {"category": "binary", "critical": True},
        "gdb": {"category": "binary", "critical": True},
        "pwntools": {"category": "binary", "critical": False},

        # IoT
        "binwalk": {"category": "iot", "critical": True},

        # Password
        "hashcat": {"category": "password", "critical": True},
        "john": {"category": "password", "critical": True},

        # Evidence
        "screenshot": {"category": "evidence", "critical": False},
    }

    @staticmethod
    async def check_tool(tool_name: str) -> ToolAvailability:
        """Check if a tool is installed."""
        import asyncio
        try:
            cmd = f"which {tool_name} 2>/dev/null || where {tool_name} 2>nul"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode("utf-8", errors="replace").strip()
            if output and "not found" not in output.lower():
                return ToolAvailability.INSTALLED
            return ToolAvailability.NOT_INSTALLED
        except Exception:
            return ToolAvailability.NOT_INSTALLED

    @staticmethod
    async def check_all_tools() -> dict:
        """Check all enterprise tools."""
        results = {}
        for tool, info in ToolChecker.REQUIRED_TOOLS.items():
            status = await ToolChecker.check_tool(tool)
            results[tool] = {
                "status": status.value,
                "category": info["category"],
                "critical": info["critical"],
            }
        return results

    @staticmethod
    async def get_missing_critical() -> list[str]:
        """Get list of missing critical tools."""
        missing = []
        for tool, info in ToolChecker.REQUIRED_TOOLS.items():
            if info["critical"]:
                status = await ToolChecker.check_tool(tool)
                if status == ToolAvailability.NOT_INSTALLED:
                    missing.append(tool)
        return missing


# Installation commands for missing tools
INSTALL_COMMANDS = {
    "nmap": "apt-get install -y nmap",
    "masscan": "apt-get install -y masscan",
    "enum4linux": "apt-get install -y enum4linux",
    "ldapsearch": "apt-get install -y ldap-utils",
    "msfconsole": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | bash",
    "searchsploit": "apt-get install -y exploitdb",
    "sqlmap": "apt-get install -y sqlmap",
    "hydra": "apt-get install -y hydra",
    "crackmapexec": "pip install crackmapexec",
    "bloodhound-python": "pip install bloodhound",
    "GetUserSPNs.py": "pip install impacket",
    "secretsdump.py": "pip install impacket",
    "psexec.py": "pip install impacket",
    "wmiexec.py": "pip install impacket",
    "chisel": "apt-get install -y chisel || pip install chisel",
    "sshpass": "apt-get install -y sshpass",
    "linpeas.sh": "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash",
    "nikto": "apt-get install -y nikto",
    "gobuster": "apt-get install -y gobuster",
    "ffuf": "apt-get install -y ffuf",
    "checksec": "apt-get install -y checksec",
    "gdb": "apt-get install -y gdb",
    "binwalk": "apt-get install -y binwalk",
    "hashcat": "apt-get install -y hashcat",
    "john": "apt-get install -y john",
}
