"""Autonomous Executor - LLM can run ANY command, install tools, manage processes.

Enhanced with:
- Auto-install with error detection
- Error fixing and retry logic
- Dependency resolution
- Only proceeds after successful installation
"""

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
    """Execute any command the LLM wants. Auto-installs missing tools."""

    def __init__(self, timeout: int = 300, cwd: str = None):
        import tempfile
        self.timeout = timeout
        self.cwd = cwd or tempfile.gettempdir()
        self.history: list[CommandResult] = []
        self._env = os.environ.copy()
        self._installed_tools: set = set()  # Cache of installed tools

    async def run(self, command: str, timeout: Optional[int] = None, cwd: Optional[str] = None) -> CommandResult:
        """Run any command."""
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
        """Install any tool the LLM needs with error detection and fixing.

        Flow:
        1. Check if already installed
        2. Try to install
        3. If fails, analyze error
        4. Try to fix error
        5. Retry installation
        6. Only return success when tool is installed
        """
        # Check if already installed
        check = await self.run(f"which {tool_name} 2>/dev/null || command -v {tool_name} 2>/dev/null")
        if check.exit_code == 0 and check.stdout.strip():
            self._installed_tools.add(tool_name)
            return CommandResult(
                command=f"which {tool_name}",
                stdout=f"{tool_name} already installed: {check.stdout.strip()}",
                stderr="",
                exit_code=0,
            )

        print(f"  [INSTALL] {tool_name} not found. Installing...")

        # Try installation methods with error fixing
        max_retries = 3
        for attempt in range(max_retries):
            result = await self._try_install(tool_name)
            if result.exit_code == 0:
                # Verify installation
                verify = await self.run(f"which {tool_name} 2>/dev/null || command -v {tool_name} 2>/dev/null")
                if verify.exit_code == 0 and verify.stdout.strip():
                    self._installed_tools.add(tool_name)
                    print(f"  [INSTALL] {tool_name} installed successfully!")
                    return CommandResult(
                        command=f"install {tool_name}",
                        stdout=f"{tool_name} installed successfully",
                        stderr="",
                        exit_code=0,
                    )

            # Installation failed - try to fix
            if attempt < max_retries - 1:
                print(f"  [INSTALL] Attempt {attempt + 1} failed. Analyzing error...")
                fix_result = await self._fix_install_error(tool_name, result.stderr)
                if fix_result:
                    print(f"  [INSTALL] Applied fix: {fix_result}")

        # All attempts failed
        error_msg = f"Could not install {tool_name} after {max_retries} attempts"
        print(f"  [INSTALL] {error_msg}")
        return CommandResult(
            command=f"install {tool_name}",
            stdout="",
            stderr=error_msg,
            exit_code=1,
        )

    async def _try_install(self, tool_name: str) -> CommandResult:
        """Try different installation methods."""
        # Method 1: apt-get (Debian/Kali/Ubuntu)
        result = await self.run("which apt-get 2>/dev/null")
        if result.exit_code == 0:
            # Update package list first
            await self.run("apt-get update -qq", timeout=60)
            result = await self.run(f"apt-get install -y -qq {tool_name}", timeout=120)
            if result.exit_code == 0:
                return result

        # Method 2: yum (RedHat/CentOS)
        result = await self.run("which yum 2>/dev/null")
        if result.exit_code == 0:
            result = await self.run(f"yum install -y {tool_name}", timeout=120)
            if result.exit_code == 0:
                return result

        # Method 3: apk (Alpine)
        result = await self.run("which apk 2>/dev/null")
        if result.exit_code == 0:
            result = await self.run(f"apk add {tool_name}", timeout=120)
            if result.exit_code == 0:
                return result

        # Method 4: pacman (Arch)
        result = await self.run("which pacman 2>/dev/null")
        if result.exit_code == 0:
            result = await self.run(f"pacman -S --noconfirm {tool_name}", timeout=120)
            if result.exit_code == 0:
                return result

        # Method 5: pip (Python packages)
        result = await self.run(f"pip install {tool_name}", timeout=120)
        if result.exit_code == 0:
            return result

        # Method 6: pip3
        result = await self.run(f"pip3 install {tool_name}", timeout=120)
        if result.exit_code == 0:
            return result

        # Method 7: go install (Go tools)
        result = await self.run(f"go install {tool_name}@latest", timeout=180)
        if result.exit_code == 0:
            return result

        # Method 8: npm (Node.js tools)
        result = await self.run(f"npm install -g {tool_name}", timeout=120)
        if result.exit_code == 0:
            return result

        # Method 9: cargo (Rust tools)
        result = await self.run(f"cargo install {tool_name}", timeout=300)
        if result.exit_code == 0:
            return result

        return CommandResult(
            command=f"install {tool_name}",
            stdout="",
            stderr=f"No package manager found or installation failed for {tool_name}",
            exit_code=1,
        )

    async def _fix_install_error(self, tool_name: str, error: str) -> Optional[str]:
        """Analyze installation error and try to fix it."""
        error_lower = error.lower()

        # Fix 1: Missing dependencies
        if "depends on" in error_lower or "dependency" in error_lower:
            # Extract dependency name
            import re
            dep_match = re.search(r"depends on (\S+)", error_lower)
            if dep_match:
                dep = dep_match.group(1)
                print(f"  [FIX] Installing missing dependency: {dep}")
                await self.install_tool(dep)
                return f"Installed missing dependency: {dep}"

        # Fix 2: Package not found - try alternative name
        if "unable to locate package" in error_lower or "no package found" in error_lower:
            # Try common alternative names
            alternatives = {
                "impacket": "impacket-scripts",
                "smbclient": "smbclient",
                "enum4linux": "enum4linux",
                "gobuster": "gobuster",
                "nikto": "nikto",
                "ffuf": "ffuf",
                "sqlmap": "sqlmap",
                "hydra": "hydra",
                "john": "john",
                "hashcat": "hashcat",
                "binwalk": "binwalk",
                "checksec": "checksec",
            }
            alt = alternatives.get(tool_name)
            if alt and alt != tool_name:
                print(f"  [FIX] Trying alternative package name: {alt}")
                result = await self.run(f"apt-get install -y -qq {alt}", timeout=120)
                if result.exit_code == 0:
                    return f"Installed via alternative package: {alt}"

        # Fix 3: Permission denied
        if "permission denied" in error_lower or "eacc" in error_lower:
            print(f"  [FIX] Retrying with sudo...")
            result = await self.run(f"sudo apt-get install -y -qq {tool_name}", timeout=120)
            if result.exit_code == 0:
                return "Installed with sudo"

        # Fix 4: Disk space
        if "no space left" in error_lower:
            print(f"  [FIX] Cleaning up disk space...")
            await self.run("apt-get clean", timeout=30)
            await self.run("apt-get autoremove -y", timeout=30)
            return "Cleaned disk space"

        # Fix 5: Network error
        if "could not resolve" in error_lower or "network" in error_lower:
            print(f"  [FIX] Retrying in 5 seconds...")
            await asyncio.sleep(5)
            return "Retrying after network delay"

        # Fix 6: Python version mismatch
        if "python" in error_lower and "version" in error_lower:
            print(f"  [FIX] Trying pip3 instead of pip...")
            result = await self.run(f"pip3 install {tool_name}", timeout=120)
            if result.exit_code == 0:
                return "Installed with pip3"

        # Fix 7: Already installed error
        if "already installed" in error_lower or "already satisfied" in error_lower:
            return "Tool already installed (ignoring error)"

        return None

    async def ensure_tool(self, tool_name: str, install_command: Optional[str] = None) -> bool:
        """Ensure a tool is available. Install if not."""
        # Check cache first
        if tool_name in self._installed_tools:
            return True

        check = await self.run(f"which {tool_name} 2>/dev/null")
        if check.exit_code == 0 and check.stdout.strip():
            self._installed_tools.add(tool_name)
            return True

        if install_command:
            result = await self.run(install_command, timeout=120)
            if result.exit_code == 0:
                # Verify
                verify = await self.run(f"which {tool_name} 2>/dev/null")
                if verify.exit_code == 0:
                    self._installed_tools.add(tool_name)
                    return True

        result = await self.install_tool(tool_name)
        return result.exit_code == 0

    async def run_with_install(self, command: str, tool_name: str = None, timeout: Optional[int] = None) -> CommandResult:
        """Run a command, auto-installing the tool if needed.

        This is the smart method - it:
        1. Extracts the tool name from command if not provided
        2. Checks if tool is installed
        3. Installs if missing
        4. Runs the command
        5. Returns result
        """
        if not tool_name:
            # Extract tool name from command
            tool_name = command.split()[0] if command.split() else ""

        if tool_name:
            # Ensure tool is installed
            installed = await self.ensure_tool(tool_name)
            if not installed:
                return CommandResult(
                    command=command,
                    stdout="",
                    stderr=f"Tool '{tool_name}' could not be installed",
                    exit_code=1,
                )

        # Run the command
        return await self.run(command, timeout=timeout)

    async def install_python_package(self, package: str) -> CommandResult:
        """Install a Python package."""
        result = await self.run(f"pip install {package}", timeout=120)
        if result.exit_code == 0:
            return result
        # Try pip3
        return await self.run(f"pip3 install {package}", timeout=120)

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

    async def run_background(self, command: str) -> asyncio.subprocess.Process:
        """Run a command in background."""
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
