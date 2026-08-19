"""Tests for Autonomous Agent."""

import pytest
import asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from ai.autonomous_executor import AutonomousExecutor, CommandResult
from ai.autonomous_agent import AutonomousAgent


class TestAutonomousExecutor:
    """Test the command executor."""

    def test_init(self):
        executor = AutonomousExecutor()
        assert executor.timeout == 300
        assert executor.history == []
        assert executor.cwd == tempfile.gettempdir()

    @pytest.mark.asyncio
    async def test_run_command(self):
        executor = AutonomousExecutor()
        result = await executor.run("echo hello")
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert len(executor.history) == 1

    @pytest.mark.asyncio
    async def test_run_failing_command(self):
        executor = AutonomousExecutor()
        result = await executor.run("false")
        assert result.exit_code != 0

    @pytest.mark.asyncio
    async def test_run_with_timeout(self):
        executor = AutonomousExecutor()
        result = await executor.run("sleep 10", timeout=1)
        assert result.timed_out is True

    @pytest.mark.asyncio
    async def test_install_tool_already_installed(self):
        executor = AutonomousExecutor()
        result = await executor.install_tool("python3")
        # On Windows, python3 might not be available but python is
        # Just check it doesn't crash
        assert isinstance(result.exit_code, int)

    @pytest.mark.asyncio
    async def test_check_connectivity(self):
        executor = AutonomousExecutor()
        result = await executor.run("nc -zv -w 1 127.0.0.1 1 2>&1", timeout=5)
        assert isinstance(result.exit_code, int)

    @pytest.mark.asyncio
    async def test_history_tracking(self):
        executor = AutonomousExecutor()
        await executor.run("echo one")
        await executor.run("echo two")
        assert len(executor.history) == 2
        history = executor.get_history()
        assert len(history) == 2
        assert history[0]["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_read_file(self):
        executor = AutonomousExecutor()
        result = await executor.run("echo testcontent > test_read.txt")
        content = await executor.read_file("test_read.txt")
        assert "testcontent" in content

    @pytest.mark.asyncio
    async def test_get_installed_tools(self):
        executor = AutonomousExecutor()
        await executor.run("echo test")
        tools = executor.get_installed_tools()
        assert "echo" in tools


class TestAutonomousAgent:
    """Test the autonomous agent."""

    def test_init(self):
        agent = AutonomousAgent()
        assert agent.target == ""
        assert agent.state["phase"] == "initial"
        assert agent.state["access_level"] == "none"

    def test_system_prompt(self):
        agent = AutonomousAgent()
        agent.target = "10.10.10.0/24"
        prompt = agent.get_system_prompt()
        assert "10.10.10.0/24" in prompt
        assert "pentester" in prompt.lower() or "penetration" in prompt.lower()

    @pytest.mark.asyncio
    async def test_act(self):
        agent = AutonomousAgent()
        result = await agent.act("echo test123")
        assert result.exit_code == 0
        assert "test123" in result.stdout
        assert agent.state["command_history_count"] == 1

    def test_extract_commands(self):
        agent = AutonomousAgent()
        response = """Here's what I'll do:

```bash
nmap -sn 10.10.10.0/24
```

Then enumerate services."""
        commands = agent._extract_commands(response)
        assert len(commands) >= 1
        assert any("nmap" in c for c in commands)

    def test_extract_inline_commands(self):
        agent = AutonomousAgent()
        # Test extraction from code blocks
        response = """Analysis:
```bash
nmap -sV -sC 10.10.10.1
```
Next steps above."""
        commands = agent._extract_commands(response)
        assert len(commands) >= 1
        assert any("nmap" in c for c in commands)

    def test_extract_inline_shell_lines(self):
        agent = AutonomousAgent()
        # Test extraction of lines that look like shell commands
        response = """Run these commands:
nmap -sn 10.10.10.0/24
gobuster dir -u http://10.10.10.1 -w wordlist.txt
# This is a comment
"""
        commands = agent._extract_commands(response)
        assert len(commands) >= 2
        assert any("nmap" in c for c in commands)
        assert any("gobuster" in c for c in commands)

    def test_is_safe_command(self):
        agent = AutonomousAgent()
        assert agent._is_safe_command("nmap -sn 10.10.10.0/24") is True
        assert agent._is_safe_command("rm -rf /") is False
        assert agent._is_safe_command("ls -la") is True

    def test_update_state_from_nmap(self):
        agent = AutonomousAgent()
        agent._update_state_from_output(
            "nmap -sn 10.10.10.0/24",
            "Nmap scan report for 10.10.10.1\nNmap scan report for 10.10.10.2",
            ""
        )
        assert "10.10.10.1" in agent.state["hosts_discovered"]
        assert "10.10.10.2" in agent.state["hosts_discovered"]

    def test_update_state_from_services(self):
        agent = AutonomousAgent()
        agent._update_state_from_output(
            "nmap -sV 10.10.10.1",
            "22/tcp open ssh\n80/tcp open http\n445/tcp open microsoft-ds",
            ""
        )
        assert len(agent.state["services_found"]) == 3
        assert any(s["service"] == "ssh" for s in agent.state["services_found"])

    def test_update_state_from_credentials(self):
        agent = AutonomousAgent()
        agent._update_state_from_output(
            "secretsdump.py",
            "password=SuperSecret123",
            ""
        )
        assert len(agent.state["credentials"]) >= 1

    def test_update_state_access_level(self):
        agent = AutonomousAgent()
        agent._update_state_from_output("id", "uid=0(root) gid=0(root)", "")
        assert agent.state["access_level"] == "root"

    def test_advance_phase(self):
        agent = AutonomousAgent()
        agent.state["phase"] = "reconnaissance"
        agent._advance_phase()
        assert agent.state["phase"] == "enumeration"

    def test_get_report(self):
        agent = AutonomousAgent()
        agent.target = "10.10.10.0/24"
        report = agent.get_report()
        assert report["target"] == "10.10.10.0/24"
        assert "hosts_discovered" in report
        assert "command_history" in report

    @pytest.mark.asyncio
    async def test_observe_without_llm(self):
        agent = AutonomousAgent()
        agent.target = "10.10.10.0/24"
        response = await agent.observe()
        assert "nmap" in response.lower() or "recon" in response.lower()
