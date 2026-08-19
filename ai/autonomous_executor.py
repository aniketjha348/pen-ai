"""Autonomous Executor - LLM can run ANY command, install tools, manage processes."""

import asyncio
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    timed_out: bool = False


class AutonomousExecutor:
    """Execute any command the LLM wants. No restrictions except scope."""

    def __init__(self, timeout: int = 300, cwd: str = None):
        import tempfile
        self.timeout = timeout
        self.cwd = cwd or tempfile.gettempdir()
        self.history: list[CommandResult] = []
        self._env = os.environ.copy()

    async def run(self, command: str, timeout: Optional[int] = None, cwd: Optional[str] = None) -> CommandResult:
        """Run any command. This is the LLM's hands."""
        timeout = timeout or self.timeout
        work_dir = cwd or self.cwd

        started = datetime.now()
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
                env=self._env,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
            completed = datetime.now()

            result = CommandResult(
                command=command,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=process.returncode or 0,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
            )
        except asyncio.TimeoutError:
            completed = datetime.now()
            try:
                process.kill()
            except Exception:
                pass
            result = CommandResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                started_at=started,
                completed_at=completed,
                duration_seconds=timeout,
                timed_out=True,
            )
        except Exception as e:
            completed = datetime.now()
            result = CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
            )

        self.history.append(result)
        return result

    async def install_tool(self, tool_name: str) -> CommandResult:
        """Install any tool the LLM needs."""
        # Detect package manager and install
        installers = [
            (f"which apt-get && apt-get update -qq && apt-get install -y -qq {tool_name}", "debian"),
            (f"which yum && yum install -y {tool_name}", "redhat"),
            (f"which apk && apk add {tool_name}", "alpine"),
            (f"which pacman && pacman -S --noconfirm {tool_name}", "arch"),
            (f"pip install {tool_name}", "pip"),
            (f"pip3 install {tool_name}", "pip3"),
            (f"go install {tool_name}@latest", "go"),
        ]

        # Check if already installed
        check = await self.run(f"which {tool_name} 2>/dev/null || command -v {tool_name} 2>/dev/null")
        if check.exit_code == 0 and check.stdout.strip():
            return CommandResult(
                command=f"which {tool_name}",
                stdout=f"{tool_name} already installed: {check.stdout.strip()}",
                stderr="",
                exit_code=0,
            )

        # Try each installer
        for cmd, pkg_mgr in installers:
            if "which" in cmd:
                check_pkg = await self.run(cmd.split("&&")[0].strip().replace("which ", "which "))
                if check_pkg.exit_code != 0:
                    continue

            result = await self.run(cmd, timeout=120)
            if result.exit_code == 0:
                return result

        return CommandResult(
            command=f"install {tool_name}",
            stdout="",
            stderr=f"Could not find package manager to install {tool_name}",
            exit_code=1,
        )

    async def install_python_package(self, package: str) -> CommandResult:
        """Install a Python package."""
        return await self.run(f"pip install {package}", timeout=120)

    async def install_go_tool(self, tool: str) -> CommandResult:
        """Install a Go-based security tool."""
        return await self.run(f"go install {tool}@latest", timeout=180)

    async def install_binary(self, name: str, url: str) -> CommandResult:
        """Download and install a binary tool."""
        cmds = [
            f"curl -sL {url} -o /tmp/{name}",
            f"chmod +x /tmp/{name}",
            f"mv /tmp/{name} /usr/local/bin/{name} 2>/dev/null || cp /tmp/{name} ~/bin/{name} 2>/dev/null || echo 'Installed to /tmp/{name}'",
        ]
        results = []
        for cmd in cmds:
            result = await self.run(cmd, timeout=60)
            results.append(result)
            if result.exit_code != 0:
                return result
        return results[-1]

    async def ensure_tool(self, tool_name: str, install_command: Optional[str] = None) -> bool:
        """Ensure a tool is available. Install if not."""
        check = await self.run(f"which {tool_name} 2>/dev/null")
        if check.exit_code == 0 and check.stdout.strip():
            return True

        if install_command:
            result = await self.run(install_command, timeout=120)
            return result.exit_code == 0

        result = await self.install_tool(tool_name)
        return result.exit_code == 0

    async def run_background(self, command: str) -> asyncio.subprocess.Process:
        """Run a command in background (for long-running pivots, servers)."""
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.cwd,
            env=self._env,
        )
        return process

    async def check_connectivity(self, target: str, port: int = 80) -> bool:
        """Check if target is reachable."""
        result = await self.run(f"nc -zv -w 3 {target} {port} 2>&1", timeout=10)
        return "succeeded" in result.stderr.lower() or result.exit_code == 0

    async def read_file(self, path: str) -> str:
        """Read a file from the system."""
        result = await self.run(f"cat {path}", timeout=10)
        return result.stdout

    async def write_file(self, path: str, content: str) -> bool:
        """Write content to a file."""
        # Escape content for shell
        escaped = content.replace("'", "'\\''")
        result = await self.run(f"echo '{escaped}' > {path}", timeout=10)
        return result.exit_code == 0

    def get_history(self) -> list[dict]:
        """Get command history."""
        return [
            {
                "command": r.command,
                "exit_code": r.exit_code,
                "stdout_preview": r.stdout[:500],
                "stderr_preview": r.stderr[:200],
                "duration": r.duration_seconds,
            }
            for r in self.history
        ]

    def get_installed_tools(self) -> list[str]:
        """Get list of tools that were used."""
        return list(set(
            r.command.split()[0] if r.command.split() else ""
            for r in self.history
            if r.exit_code == 0
        ))
