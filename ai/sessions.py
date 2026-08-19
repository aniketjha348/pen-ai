"""Persistent SSH session manager built on paramiko.

Gives PEN-AI real persistent access channels: connect once, execute many,
reconnect transparently. Uses asyncio.to_thread so blocking paramiko I/O
never stalls the event loop.
"""

import asyncio
from typing import Optional

import paramiko

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


class SSHSession:
    """A single persistent SSH connection."""

    def __init__(self, host: str, username: str, port: int = 22):
        self.host = host
        self.username = username
        self.port = port
        self.connected = False
        self._client: Optional[paramiko.SSHClient] = None

    @property
    def key(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    async def connect(self, password: str = "", key_path: str = "") -> bool:
        def _do_connect() -> paramiko.SSHClient:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs: dict = {"hostname": self.host, "port": self.port,
                            "username": self.username, "timeout": 10}
            if key_path:
                kwargs["key_filename"] = key_path
            else:
                kwargs["password"] = password
            client.connect(**kwargs)
            return client

        try:
            self._client = await asyncio.to_thread(_do_connect)
            self.connected = True
            return True
        except Exception:
            self.connected = False
            return False

    async def exec(self, command: str, timeout: int = 30, password: str = "", key_path: str = "") -> tuple[str, int]:
        if not self.connected:
            if not await self.connect(password, key_path):
                return "", 1
        try:
            return await self._exec_once(command, timeout)
        except (paramiko.SSHException, EOFError, OSError):
            await asyncio.to_thread(self._close_client)
            if not await self.connect(password, key_path):
                return "", 1
            return await self._exec_once(command, timeout)

    async def _exec_once(self, command: str, timeout: int = 30) -> tuple[str, int]:
        def _run() -> tuple[str, int]:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return out, exit_code

        return await asyncio.to_thread(_run)

    async def write_file(self, remote_path: str, content: str) -> bool:
        def _write() -> None:
            with self._client.open_sftp() as sftp:
                with sftp.file(remote_path, "w") as f:
                    f.write(content)

        try:
            await asyncio.to_thread(_write)
            return True
        except Exception:
            return False

    def _close_client(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        self.connected = False

    def close(self) -> None:
        self._close_client()


class SSHSessionManager:
    """Registry of persistent SSH sessions, keyed by user@host:port."""

    def __init__(self):
        self._sessions: dict[str, SSHSession] = {}

    async def get_session(self, host: str, username: str, password: str = "",
                          port: int = 22, key_path: str = "") -> SSHSession:
        key = f"{username}@{host}:{port}"
        session = self._sessions.get(key)
        if session is None:
            session = SSHSession(host, username, port)
            self._sessions[key] = session
        if not session.connected:
            await session.connect(password, key_path)
        return session

    async def exec_on(self, host: str, username: str, password: str = "",
                      command: str = "id", port: int = 22, key_path: str = "") -> tuple[str, int]:
        session = await self.get_session(host, username, password, port, key_path)
        return await session.exec(command, password=password, key_path=key_path)

    async def close_all(self) -> int:
        count = 0
        for session in self._sessions.values():
            if session.connected:
                session.close()
                count += 1
        self._sessions.clear()
        return count

    def list_sessions(self) -> list[dict]:
        return [
            {"key": s.key, "host": s.host, "username": s.username,
             "port": s.port, "connected": s.connected}
            for s in self._sessions.values()
        ]


SSH_SESSION_MANAGER = SSHSessionManager()


@register_tool(
    name="ssh_session_exec",
    description="Execute a command over a PERSISTENT SSH session (reconnects transparently, reuses the connection for subsequent commands)",
    category=ToolCategory.EXPLOITATION,
    parameters=[
        ToolParameter(name="host", type="str", description="Target IP"),
        ToolParameter(name="username", type="str", description="SSH username"),
        ToolParameter(name="password", type="str", description="SSH password"),
        ToolParameter(name="command", type="str", description="Command to execute"),
        ToolParameter(name="port", type="int", description="SSH port", required=False, default=22),
    ],
)
async def ssh_session_exec(host: str, username: str, password: str, command: str, port: int = 22) -> dict:
    out, code = await SSH_SESSION_MANAGER.exec_on(host, username, password, command, port)
    return {"success": code == 0, "output": out, "exit_code": code, "persistent": True}


@register_tool(
    name="session_status",
    description="List all open persistent SSH sessions",
    category=ToolCategory.EXPLOITATION,
    parameters=[],
)
async def session_status() -> dict:
    return {"sessions": SSH_SESSION_MANAGER.list_sessions()}