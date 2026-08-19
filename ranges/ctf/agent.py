"""CTF Range Agent - Real CTF enumeration via SSH and local analysis."""

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


class CTFCategory(str, Enum):
    """CTF challenge categories."""
    WEB = "web"
    CRYPTO = "crypto"
    REVERSING = "reversing"
    FORENSICS = "forensics"
    MISC = "misc"
    PWN = "pwn"
    STEGO = "stego"
    OSINT = "osint"


class LinuxEnumPhase(str, Enum):
    """Linux enumeration phases."""
    SYSTEM_INFO = "system_info"
    USER_ENUM = "user_enum"
    FILE_PERMS = "file_perms"
    PROCESS_ENUM = "process_enum"
    SUID_SGID = "suid_sgid"
    CRON_JOBS = "cron_jobs"
    NETWORK = "network"
    SERVICES = "services"
    KERNEL = "kernel"
    DOCKER = "docker"


@dataclass
class Flag:
    """A captured or discovered flag."""
    value: str
    category: CTFCategory
    challenge: Optional[str] = None
    validated: bool = False
    captured_at: Optional[str] = None


@dataclass
class CTFChallenge:
    """A CTF challenge."""
    name: str
    category: CTFCategory
    description: Optional[str] = None
    target: Optional[str] = None
    port: Optional[int] = None
    status: str = "discovered"
    flag: Optional[Flag] = None


class CTFAgent:
    """CTF solving agent with real SSH-based enumeration."""

    def __init__(self):
        self._challenges: list[CTFChallenge] = []
        self._flags: list[Flag] = []

    async def _ssh_exec(self, target: str, command: str, credentials: Optional[dict] = None) -> str:
        """Execute a command via SSH."""
        if credentials:
            username = credentials.get("username", "root")
            password = credentials.get("password", "")
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {username}@{target} '{command}'"
        else:
            cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {target} '{command}'"

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            return stdout.decode("utf-8", errors="replace")
        except Exception as e:
            return f"SSH error: {e}"

    async def linux_enumeration(self, target: str, phase: LinuxEnumPhase, credentials: Optional[dict] = None) -> dict:
        """Perform real Linux enumeration via SSH."""
        enum_funcs = {
            LinuxEnumPhase.SYSTEM_INFO: self._enum_system_info,
            LinuxEnumPhase.USER_ENUM: self._enum_users,
            LinuxEnumPhase.FILE_PERMS: self._enum_file_perms,
            LinuxEnumPhase.PROCESS_ENUM: self._enum_processes,
            LinuxEnumPhase.SUID_SGID: self._enum_suid_sgid,
            LinuxEnumPhase.CRON_JOBS: self._enum_cron,
            LinuxEnumPhase.NETWORK: self._enum_network,
            LinuxEnumPhase.SERVICES: self._enum_services,
            LinuxEnumPhase.KERNEL: self._enum_kernel,
            LinuxEnumPhase.DOCKER: self._enum_docker,
        }
        func = enum_funcs.get(phase)
        if func:
            return await func(target, credentials)
        return {"error": f"Unknown phase: {phase}"}

    async def _enum_system_info(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate system information."""
        output = await self._ssh_exec(target,
            "echo HOSTNAME=$(hostname) && echo KERNEL=$(uname -r) && echo OS=$(cat /etc/os-release 2>/dev/null | head -5) && echo UPTIME=$(uptime) && echo ARCH=$(uname -m)",
            credentials)

        results = {"raw": output, "hostname": "unknown", "kernel": "unknown", "os": "unknown", "arch": "unknown"}

        for line in output.split("\n"):
            if "HOSTNAME=" in line:
                results["hostname"] = line.split("=", 1)[1].strip()
            elif "KERNEL=" in line:
                results["kernel"] = line.split("=", 1)[1].strip()
            elif "OS=" in line:
                results["os"] = line.split("=", 1)[1].strip()
            elif "ARCH=" in line:
                results["arch"] = line.split("=", 1)[1].strip()

        return results

    async def _enum_users(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate users."""
        output = await self._ssh_exec(target,
            "cat /etc/passwd | grep -v nologin | grep -v false && echo '---SUDO---' && grep -r sudo /etc/sudoers 2>/dev/null && echo '---LOGGED---' && w 2>/dev/null",
            credentials)

        users = []
        sudo_users = []
        logged_in = []

        for line in output.split("\n"):
            if ":" in line and "/bin/" in line:
                parts = line.split(":")
                users.append({"username": parts[0], "uid": parts[2], "shell": parts[-1].strip()})
            elif "sudo" in line.lower():
                sudo_users.append(line.strip())

        return {
            "users": users,
            "sudo_users": sudo_users,
            "logged_in": logged_in,
            "total_users": len(users),
        }

    async def _enum_file_perms(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate file permissions - world writable, sensitive files."""
        output = await self._ssh_exec(target,
            "echo '---WORLD_WRITABLE---' && find / -writable -type f 2>/dev/null | head -30 && echo '---SENSITIVE---' && ls -la /etc/shadow /etc/passwd /etc/sudoers /root/.ssh/ /root/.bash_history 2>/dev/null && echo '---CONFIGS---' && find /etc -name '*.conf' -readable 2>/dev/null | head -20",
            credentials)

        world_writable = []
        sensitive = []

        section = ""
        for line in output.split("\n"):
            if "WORLD_WRITABLE" in line:
                section = "writable"
            elif "SENSITIVE" in line:
                section = "sensitive"
            elif "CONFIGS" in line:
                section = "configs"
            elif line.strip():
                if section == "writable":
                    world_writable.append(line.strip())
                elif section == "sensitive":
                    sensitive.append(line.strip())

        return {"world_writable": world_writable, "sensitive_files": sensitive}

    async def _enum_processes(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate processes."""
        output = await self._ssh_exec(target,
            "ps aux --sort=-%mem | head -20 && echo '---LISTENERS---' && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
            credentials)

        processes = []
        listeners = []

        section = ""
        for line in output.split("\n"):
            if "LISTENERS" in line:
                section = "listeners"
            elif line.strip():
                if section == "listeners" or ("tcp" in line.lower() and ("listen" in line.lower() or "local" in line.lower())):
                    listeners.append(line.strip())
                elif line.split()[0:1] != ["USER"] and len(line.split()) > 3:
                    processes.append(line.strip()[:120])

        return {"processes": processes[:20], "listeners": listeners}

    async def _enum_suid_sgid(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate SUID/SGID binaries."""
        output = await self._ssh_exec(target,
            "echo '---SUID---' && find / -perm -u=s -type f 2>/dev/null && echo '---SGID---' && find / -perm -g=s -type f 2>/dev/null",
            credentials)

        exploitable_suids = [
            "nmap", "vim", "find", "bash", "less", "more", "nano", "cp",
            "python", "python3", "perl", "ruby", "env", "awk", "php",
            "wget", "curl", "dd", "tar", "zip", "strace", "ltrace",
            "gdb", "git", "man", "ftp", "socat", "nc", "ncat",
        ]

        suid = []
        sgid = []
        exploitable = []

        section = ""
        for line in output.split("\n"):
            if "SUID" in line:
                section = "suid"
            elif "SGID" in line:
                section = "sgid"
            elif line.strip():
                binary_name = line.strip().split("/")[-1]
                if section == "suid":
                    suid.append(line.strip())
                    if binary_name in exploitable_suids:
                        exploitable.append({"binary": line.strip(), "name": binary_name})
                elif section == "sgid":
                    sgid.append(line.strip())

        return {"suid": suid, "sgid": sgid, "exploitable": exploitable}

    async def _enum_cron(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate cron jobs."""
        output = await self._ssh_exec(target,
            "echo '---SYSTEM_CRON---' && cat /etc/crontab 2>/dev/null && echo '---CRON_D---' && ls -la /etc/cron.d/ 2>/dev/null && echo '---USER_CRON---' && for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null && echo \"---\$u---\"; done && echo '---WRITABLE---' && find /etc/cron* -writable -type f 2>/dev/null",
            credentials)

        system_cron = []
        user_cron = []
        writable = []

        section = ""
        for line in output.split("\n"):
            if "SYSTEM_CRON" in line:
                section = "system"
            elif "USER_CRON" in line:
                section = "user"
            elif "WRITABLE" in line:
                section = "writable"
            elif line.strip() and not line.startswith("---"):
                if section == "system":
                    system_cron.append(line.strip())
                elif section == "writable":
                    writable.append(line.strip())

        return {"system_cron": system_cron, "user_cron": user_cron, "writable_scripts": writable}

    async def _enum_network(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate network configuration."""
        output = await self._ssh_exec(target,
            "echo '---IFACES---' && ip addr 2>/dev/null || ifconfig && echo '---ROUTES---' && ip route 2>/dev/null && echo '---CONN---' && ss -tnp 2>/dev/null | head -20 && echo '---ARP---' && arp -a 2>/dev/null",
            credentials)

        interfaces = []
        routes = []
        connections = []

        section = ""
        for line in output.split("\n"):
            if "IFACES" in line:
                section = "ifaces"
            elif "ROUTES" in line:
                section = "routes"
            elif "CONN" in line:
                section = "conn"
            elif line.strip():
                if section == "ifaces" and ("inet " in line or "eth" in line or "ens" in line):
                    interfaces.append(line.strip())
                elif section == "routes" and ("via" in line or "default" in line):
                    routes.append(line.strip())
                elif section == "conn" and ("ESTAB" in line or "tcp" in line.lower()):
                    connections.append(line.strip()[:120])

        return {"interfaces": interfaces, "routes": routes, "connections": connections}

    async def _enum_services(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate running services."""
        output = await self._ssh_exec(target,
            "echo '---RUNNING---' && ps aux | awk '{print $11}' | sort -u && echo '---SYSTEMD---' && systemctl list-units --type=service --state=running 2>/dev/null | head -20 && echo '---DOCKER---' && docker ps 2>/dev/null",
            credentials)

        running = []
        custom = []

        section = ""
        for line in output.split("\n"):
            if "RUNNING" in line:
                section = "running"
            elif line.strip():
                if section == "running" and line.strip():
                    running.append(line.strip())
                elif "docker" in line.lower() and "CONTAINER" not in line:
                    custom.append(line.strip())

        return {"running": running, "custom_services": custom}

    async def _enum_kernel(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate kernel version and check for exploits."""
        output = await self._ssh_exec(target,
            "uname -r && uname -a && cat /proc/version 2>/dev/null",
            credentials)

        kernel_version = output.strip().split("\n")[0] if output.strip() else "unknown"

        # Check for known vulnerable kernels
        vulnerable_kernels = [
            {"pattern": "2.6.22", "exploit": "dirty_cow", "cve": "CVE-2016-5195"},
            {"pattern": "3.13.0", "exploit": "dirty_cow", "cve": "CVE-2016-5195"},
            {"pattern": "4.4.0", "exploit": "dirty_cow", "cve": "CVE-2016-5195"},
            {"pattern": "4.8.0", "exploit": "dirty_cow", "cve": "CVE-2016-5195"},
            {"pattern": "5.8.0", "exploit": "dirty_pipe", "cve": "CVE-2022-0847"},
            {"pattern": "5.15", "exploit": "dirty_pipe", "cve": "CVE-2022-0847"},
            {"pattern": "6.0", "exploit": "stack_rot", "cve": "CVE-2023-3269"},
        ]

        vulnerabilities = []
        for vuln in vulnerable_kernels:
            if vuln["pattern"] in kernel_version:
                vulnerabilities.append(vuln)

        return {
            "version": kernel_version,
            "full": output.strip(),
            "vulnerabilities": vulnerabilities,
        }

    async def _enum_docker(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate Docker configuration."""
        output = await self._ssh_exec(target,
            "docker ps -a 2>/dev/null && echo '---IMAGES---' && docker images 2>/dev/null && echo '---VOLUMES---' && docker volume ls 2>/dev/null && echo '---GROUPS---' && groups 2>/dev/null",
            credentials)

        containers = []
        in_containers = False

        for line in output.split("\n"):
            if "IMAGES" in line:
                in_containers = False
            if line.strip() and not line.startswith("---") and in_containers:
                containers.append(line.strip()[:120])
            if "CONTAINER" in line.upper():
                in_containers = True

        docker_group = "docker" in output

        return {
            "running": bool(containers),
            "containers": containers,
            "in_docker_group": docker_group,
            "raw": output,
        }

    async def privilege_escalation_check(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Check for privilege escalation vectors via SSH."""
        # SUID check
        suid_result = await self._enum_suid_sgid(target, credentials)

        # Kernel check
        kernel_result = await self._enum_kernel(target, credentials)

        # Sudo check
        sudo_output = await self._ssh_exec(target, "sudo -l 2>/dev/null", credentials)

        # Capabilities check
        caps_output = await self._ssh_exec(target,
            "getcap -r / 2>/dev/null | head -20", credentials)

        # Writable paths
        writable_output = await self._ssh_exec(target,
            "find / -writable -type d 2>/dev/null | grep -v proc | head -20", credentials)

        return {
            "suid_exploits": suid_result.get("exploitable", []),
            "kernel_exploits": kernel_result.get("vulnerabilities", []),
            "sudo_info": sudo_output,
            "capabilities": caps_output,
            "writable_dirs": writable_output.split("\n") if writable_output else [],
        }

    def capture_flag(self, flag_value: str, category: CTFCategory = CTFCategory.MISC) -> Flag:
        """Capture a flag."""
        import datetime
        flag = Flag(
            value=flag_value,
            category=category,
            captured_at=datetime.datetime.now().isoformat(),
        )
        self._flags.append(flag)
        return flag

    def validate_flag(self, flag: Flag, expected_format: str = "flag{.*}") -> bool:
        """Validate a flag format."""
        flag.validated = bool(re.match(expected_format, flag.value))
        return flag.validated

    def get_flags(self) -> list[Flag]:
        """Get all captured flags."""
        return self._flags.copy()


# Register CTF tools
@register_tool(
    name="ctf_linux_enum",
    description="Perform Linux enumeration via SSH for CTF challenges",
    category=ToolCategory.CTF,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="phase", type="str", description="Phase: system_info, user_enum, suid_sgid, kernel, network, processes, cron, docker"),
    ],
)
async def ctf_linux_enum(target: str, phase: str = "system_info") -> dict:
    """Execute Linux enumeration."""
    agent = CTFAgent()
    try:
        enum_phase = LinuxEnumPhase(phase)
    except ValueError:
        return {"error": f"Unknown phase: {phase}. Use: system_info, user_enum, suid_sgid, kernel, network, processes, cron, docker, services, file_perms"}
    return await agent.linux_enumeration(target, enum_phase)


@register_tool(
    name="ctf_privesc_check",
    description="Check for privilege escalation vectors on a Linux system",
    category=ToolCategory.CTF,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
    ],
)
async def ctf_privesc_check(target: str) -> dict:
    """Execute privilege escalation check."""
    agent = CTFAgent()
    return await agent.privilege_escalation_check(target)
