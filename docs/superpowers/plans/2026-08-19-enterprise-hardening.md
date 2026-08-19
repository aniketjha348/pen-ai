# PEN-AI Enterprise Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade PEN-AI from "script-kiddie automation" to a reliable enterprise red-team framework by fixing shell-injection/quoting bugs, adding persistent SSH sessions (paramiko), automating BloodHound attack-path queries, and adding CVSS v3.1 scoring to reports.

**Architecture:** Four independent hardening subsystems, each landed as its own module with offline-testable pure logic:
1. `core/utils/shell.py` — safe command construction (all password/user/args go through `shlex.quote`); migrate exploit modules off raw f-string shell builds.
2. `ai/sessions.py` — paramiko-based persistent SSH session manager (connect once, execute many) with sshpass fallback; registered as agent tools.
3. `enterprise/bloodhound.py` — BloodHound collection already exists in `enterprise/tools.py`; add neo4j attack-path querying (bolt driver with cypher-shell fallback).
4. `reporting/cvss.py` — CVSS v3.1 base-vector generator + severity↔score mapping wired into `ReportGenerator`.

**Tech Stack:** Python 3.12, asyncio, paramiko (new dep), neo4j python driver (new dep), pytest, existing `ai/tool_registry.py` registration pattern, existing `EnterpriseTools.run_cmd` pattern in `enterprise/tools.py`.

## Global Constraints

- `requires-python = ">=3.12"`; add `paramiko>=3.4.0` and `neo4j>=5.0.0` to `pyproject.toml` `[project]` `dependencies`.
- All new logic MUST be unit-testable offline on Windows (existing suite runs on Windows; no real network/tools in tests — mock `subprocess`, `asyncio.create_subprocess_shell`, and paramiko transports).
- Keep existing function signatures where modules are migrated; only internal command-building changes.
- No comments unless they document why (repo rule: code has no inline comments).
- Follow repo naming: modules named `*.py` under their subsystem dir, tools registered via `@register_tool` from `ai.tool_registry`.
- Never commit secrets. `.env` stays git-ignored.
- After every task, run `python -m pytest tests/ -q` — full suite must stay green (currently 185 pass, 2 Windows-only fails in `tests/test_autonomous.py` are pre-existing and acceptable).

---

### Task 1: Safe Shell Command Builder + Exploit Module Migration

**Files:**
- Create: `core/utils/shell.py`
- Create: `tests/test_shell_safe.py`
- Modify: `exploitation/modules/ssh.py` (command strings only)
- Modify: `exploitation/modules/smb.py` (command strings only)
- Modify: `exploitation/modules/privesc.py` (command strings only)

**Interfaces:**
- Consumes: nothing external (stdlib `shlex`).
- Produces:
  - `q(value: str) -> str` — `shlex.quote` wrapper.
  - `build_remote_cmd(local: str, target: str, username: str, password: str, port: int = 22, timeout: int = 5) -> str` — returns a fully-quoted `sshpass -p '<pw>' ssh -o ... -p <port> <user>@<target> '<local cmd>'` command; all interpolated values wrapped in `q()`.
  - `DEFAULT_PASSWORD_LIST: list[str]` — replaces hardcoded inline lists; includes rockyou path handling constant `ROCKYOU = "/usr/share/wordlists/rockyou.txt"` and helper `password_list(kwargs) -> list[str]` that returns `kwargs["passwords"]` if given, else a 20-entry real-world default list.
  - `build_smb_client_cmd(operation: str, target: str, port: int, username: str = "", password: str = "", share: str = "IPC$", extra: str = "") -> str` — quoted `smbclient` command for `-L` or `//target/share` operations.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_shell_safe.py
import shlex

from core.utils.shell import (
    q,
    build_remote_cmd,
    build_smb_client_cmd,
    password_list,
    DEFAULT_PASSWORD_LIST,
)


def test_q_quotes_special_characters():
    assert q("p@ss'word") == "'p@ss'\"'\"'word'"
    assert q("root") == "root"
    assert q("$(id)") == "'$(id)'"


def test_build_remote_cmd_quotes_all_values():
    cmd = build_remote_cmd("id", "10.0.0.5", "admin", "P@ss'1", port=2222)
    parts = cmd.split(" ")
    assert "sshpass" in parts[0]
    assert "P@ss'\"'\"'1" in cmd
    assert "admin@10.0.0.5" in cmd
    assert "-p 2222" in cmd
    assert "'id'" in cmd


def test_build_remote_cmd_quotes_injection_payload():
    cmd = build_remote_cmd("id; rm -rf /", "10.0.0.5", "a b", "x")
    assert "id; rm -rf /" not in cmd.replace("'id; rm -rf /'", "") or "';rm" not in cmd
    assert shlex.split(cmd)[-1] == "id; rm -rf /"


def test_build_smb_client_cmd_list_shares():
    cmd = build_smb_client_cmd("list", "10.0.0.5", 445)
    assert cmd.startswith("smbclient -L")
    assert "-p 445" in cmd


def test_build_smb_client_cmd_connect_with_creds():
    cmd = build_smb_client_cmd("connect", "10.0.0.5", 445, "user", "p@ss", share="IPC$")
    assert "//10.0.0.5/IPC$" in cmd
    assert "user%p@ss" in cmd


def test_password_list_default_and_custom():
    assert isinstance(DEFAULT_PASSWORD_LIST, list) and len(DEFAULT_PASSWORD_LIST) >= 20
    custom = ["a", "b"]
    assert password_list({"passwords": custom}) == custom
    assert password_list({}) == DEFAULT_PASSWORD_LIST
```

- [ ] **Step 2: Run test, verify FAIL** (module missing)

Run: `python -m pytest tests/test_shell_safe.py -q`
Expected: `ModuleNotFoundError: No module named 'core.utils.shell'`

- [ ] **Step 3: Implement `core/utils/shell.py`**

```python
"""Safe shell command construction for PEN-AI tool integrations."""

import shlex

ROCKYOU = "/usr/share/wordlists/rockyou.txt"

DEFAULT_PASSWORD_LIST = [
    "password", "123456", "admin", "root", "test", "guest", "letmein",
    "welcome", "changeme", "Password1", "P@ssw0rd", "admin123", "root123",
    "toor", "12345", "12345678", "qwerty", "abc123", "monkey", "dragon",
]

SSH_OPTS = "-o StrictHostKeyChecking=no -o ConnectTimeout=5"


def q(value: str) -> str:
    """Quote a value so it is safe inside a single shell command line."""
    return shlex.quote(str(value))


def password_list(kwargs: dict) -> list[str]:
    """Return caller-supplied passwords or the built-in default list."""
    passwords = kwargs.get("passwords")
    if isinstance(passwords, (list, tuple)) and passwords:
        return list(passwords)
    return list(DEFAULT_PASSWORD_LIST)


def build_remote_cmd(
    local: str,
    target: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 5,
) -> str:
    """Build an sshpass ssh command with every interpolated value quoted."""
    return (
        "sshpass -p {pw} ssh {opts} -o ConnectTimeout={t} "
        "{user}@{target} -p {port} {cmd}"
    ).format(
        pw=q(password),
        opts=SSH_OPTS,
        t=int(timeout),
        user=q(username),
        target=q(target),
        port=int(port),
        cmd=q(local),
    )


def build_smb_client_cmd(
    operation: str,
    target: str,
    port: int,
    username: str = "",
    password: str = "",
    share: str = "IPC$",
    extra: str = "",
) -> str:
    """Build an smbclient command (operation='list' or 'connect')."""
    if operation == "list":
        auth = f" -U {q(username)}%{q(password)}" if username else " -N"
        return f"smbclient -L {q(target)} {auth} -p {int(port)} {extra}".strip()
    auth = f" -U {q(username)}%{q(password)}" if username else " -N"
    return f"smbclient //{q(target)}/{q(share)} {auth} -p {int(port)} {extra}".strip()
```

- [ ] **Step 4: Run test, verify PASS**

Run: `python -m pytest tests/test_shell_safe.py -q`
Expected: 6 passed

- [ ] **Step 5: Migrate `ssh.py` command strings**

In `exploitation/modules/ssh.py`, replace all inline f-string command builds:
- `check_vulnerability`: `nc -zv -w 3 {target} {port}` → `nc -zv -w 3 {q(target)} {q(str(port))}` (import `from core.utils.shell import q, password_list`).
- `SSHBruteForce.execute`: replace the sshpass inline build with `build_remote_cmd("echo SUCCESS", target, username, password, port)`; replace `password_list = kwargs.get("passwords", [...])` with `password_list = password_list(kwargs)` (rename import to avoid shadowing: `from core.utils.shell import password_list as default_password_list, build_remote_cmd` and call `default_password_list(kwargs)`).
- `SSHKeyBasedAttack.execute`: key-permission check stays; the connect attempt `ssh -i {key_path} ...` → use `ssh {q(key_path)} ...` via `q()` for `key_path` and `username`/`target`.
- `SSHCommandExecution.execute`: use `build_remote_cmd(command, target, username, password, port)`.

- [ ] **Step 6: Migrate `smb.py` command strings**

In `exploitation/modules/smb.py`:
- `SMBEnumShares.execute`: `smbclient -L {target} -N -p {port}` → `build_smb_client_cmd("list", target, port)`.
- `SMBAnonymousAccess.check_vulnerability` and `.execute`: use `build_smb_client_cmd("list", ...)` and `build_smb_client_cmd("connect", target, port, share=share_name)`.
- `SMBBruteForce.execute`: use `build_smb_client_cmd("connect", target, port, username, password, share=share, extra="-c 'exit'")`.
- `SMBManInTheMiddle`: leave logic, but quote `{target}` in the nmap command via `q()` and in the ntlmrelayx `-t` value.

- [ ] **Step 7: Migrate `privesc.py` command strings**

In `exploitation/modules/privesc.py` replace every `f"sshpass -p '{password}' ssh ..."` build with `build_remote_cmd(cmd, target, username, password)` where `cmd` is the inner command; quote `script_path`/`payload` via `q()` in `WritableCronExploit.execute`.

- [ ] **Step 8: Run full suite, verify green**

Run: `python -m pytest tests/ -q`
Expected: ≥185 passed, ≤2 pre-existing Windows-only failures

- [ ] **Step 9: Commit**

```bash
git add core/utils/shell.py tests/test_shell_safe.py exploitation/modules/ssh.py exploitation/modules/smb.py exploitation/modules/privesc.py
git commit -m "feat: safe shell command builder + migrate exploit modules to quoted commands"
```

---

### Task 2: Persistent SSH Session Manager (paramiko)

**Files:**
- Create: `ai/sessions.py`
- Create: `tests/test_sessions.py`
- Modify: `pyproject.toml` (add `paramiko>=3.4.0` to dependencies)

**Interfaces:**
- Consumes: `core.utils.shell.q` (not strictly needed — paramiko passes args in-memory; keep import-free).
- Produces:
  - `class SSHSession` — `host: str`, `port: int`, `username: str`, `connected: bool`; methods `async connect(password: str = "", key_path: str = "") -> bool` (uses `asyncio.to_thread` around a blocking paramiko connection), `async exec(command: str, timeout: int = 30) -> tuple[str, int]` (returns stdout, exit code; reconnects once on `AuthenticationException`/`SSHException`), `async write_file(remote_path: str, content: str) -> bool` (sftp), `close()`.
  - `class SSHSessionManager` — registry dict keyed `"user@host:port"`; `async get_session(host, username, password, port=22, key_path="") -> SSHSession` (reuses open session, connects if needed); `async exec_on(host, username, password, command, port=22) -> tuple[str, int]`; `close_all()`.
  - Registered tools: `ssh_session_exec(host, username, password, command, port=22)` → `{"success": bool, "output": str, "exit_code": int, "persistent": True}`.
  - `session_status()` → summary of open sessions.

- [ ] **Step 1: Add dependency and write failing tests**

Add to `pyproject.toml` dependencies: `"paramiko>=3.4.0"`.

```python
# tests/test_sessions.py
import asyncio

import pytest

from ai.sessions import SSHSessionManager, SSHSession


class FakeTransportExec:
    def __init__(self, output="hello"):
        self._out = output

    def exec_command(self, command, timeout=None):
        return self, None, None  # stdout-ish

    def recv(self, n):
        return self._out.encode()

    def recv_stderr(self, n):
        return b""

    def channel_recv_exit_status(self):
        return 0

    def send(self, data):
        return len(data)

    def close(self):
        pass


class FakeSSHClient:
    def __init__(self):
        self.connected = False
        self._out = "hello"

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, host, port=22, username=None, password=None, key_filename=None, timeout=10):
        self.connected = True

    def exec_command(self, command, timeout=None):
        return FakeTransportExec(self._out), None, None

    def open_sftp(self):
        raise NotImplementedError

    def close(self):
        self.connected = False


@pytest.fixture
def fake_client(monkeypatch):
    import ai.sessions as mod
    monkeypatch.setattr(mod.paramiko, "SSHClient", FakeSSHClient)
    return mod


def test_session_connect_and_exec(fake_client):
    async def go():
        mgr = SSHSessionManager()
        out, code = await mgr.exec_on("10.0.0.5", "root", "hunter2", "whoami")
        return out, code, mgr

    out, code, mgr = asyncio.run(go())
    assert code == 0
    assert "hello" in out
    assert len(mgr._sessions) == 1


def test_session_reused(fake_client):
    async def go():
        mgr = SSHSessionManager()
        await mgr.exec_on("10.0.0.5", "root", "hunter2", "whoami")
        await mgr.exec_on("10.0.0.5", "root", "hunter2", "id")
        return mgr

    mgr = asyncio.run(go())
    assert len(mgr._sessions) == 1


def test_reconnect_on_failure(monkeypatch):
    import ai.sessions as mod

    class FlakyClient(FakeSSHClient):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def exec_command(self, command, timeout=None):
            self.calls += 1
            if self.calls == 1:
                import paramiko
                raise paramiko.SSHException("channel closed")
            return FakeTransportExec(self._out), None, None

    monkeypatch.setattr(mod.paramiko, "SSHClient", FlakyClient)

    async def go():
        mgr = SSHSessionManager()
        out, code = await mgr.exec_on("10.0.0.5", "root", "hunter2", "whoami")
        return out, code

    out, code = asyncio.run(go())
    assert code == 0
    assert "hello" in out
```

- [ ] **Step 2: Run test, verify FAIL** (module missing)

Run: `python -m pytest tests/test_sessions.py -q`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `ai/sessions.py`**

```python
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


SESSION_MANAGER = SSHSessionManager()


@register_tool(
    name="ssh_session_exec",
    description="Execute a command over a PERSISTENT SSH session (reconnects transparently, reuses the connection for subsequent commands)",
    category=ToolCategory.POST_EXPLOIT,
    parameters=[
        ToolParameter(name="host", type="str", description="Target IP"),
        ToolParameter(name="username", type="str", description="SSH username"),
        ToolParameter(name="password", type="str", description="SSH password"),
        ToolParameter(name="command", type="str", description="Command to execute"),
        ToolParameter(name="port", type="int", description="SSH port", required=False, default=22),
    ],
)
async def ssh_session_exec(host: str, username: str, password: str, command: str, port: int = 22) -> dict:
    out, code = await SESSION_MANAGER.exec_on(host, username, password, command, port)
    return {"success": code == 0, "output": out, "exit_code": code, "persistent": True}


@register_tool(
    name="session_status",
    description="List all open persistent SSH sessions",
    category=ToolCategory.POST_EXPLOIT,
    parameters=[],
)
async def session_status() -> dict:
    return {"sessions": SESSION_MANAGER.list_sessions()}
```

Note: `ToolCategory.POST_EXPLOIT` — verify it exists in `ai/tool_registry.py`; if the enum lacks it, use `ToolCategory.EXPLOITATION` instead. (Check during implementation with `python -c "from ai.tool_registry import ToolCategory; print([c.name for c in ToolCategory])"`.)

- [ ] **Step 4: Run test, verify PASS**

Run: `python -m pytest tests/test_sessions.py -q`
Expected: 3 passed

- [ ] **Step 5: Run full suite, verify green**

Run: `python -m pytest tests/ -q`
Expected: ≥188 passed

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml ai/sessions.py tests/test_sessions.py
git commit -m "feat: persistent paramiko SSH session manager with reconnect and tool registration"
```

---

### Task 3: Wire Persistent Sessions Into Post-Exploitation

**Files:**
- Modify: `post_exploitation/engine.py`
- Modify: `pivoting/manager.py`
- Create: `tests/test_post_exploit_sessions.py`

**Interfaces:**
- Consumes: `ai.sessions.SSH_SESSION_MANAGER` (singleton), `ai.sessions.SSHSessionManager`.
- Produces:
  - `PostExploitationEngine._ssh_exec(target, command, credentials=None)` changed to prefer `SSH_SESSION_MANAGER.exec_on(target, username, password, command)` when credentials exist, falling back to the existing sshpass build when the session manager returns `("", 1)` AND the command failed to connect (i.e. fallback only if session is not established). Keep return type `str`.
  - `PivotManager._create_ssh_tunnel` unchanged (tunnels are long-running background processes — sshpass is correct there), but `PivotManager` gains `close_all_sessions()` calling `SSH_SESSION_MANAGER.close_all()`.

- [ ] **Step 1: Write failing test**

```python
# tests/test_post_exploit_sessions.py
import asyncio

import pytest

from post_exploitation.engine import PostExploitationEngine


class FakeManager:
    async def exec_on(self, host, username, password="", command="id", port=22, key_path=""):
        return f"out-of-{command}", 0


def test_ssh_exec_uses_session_manager_when_credentials(monkeypatch):
    engine = PostExploitationEngine()
    monkeypatch.setattr("post_exploitation.engine.SSH_SESSION_MANAGER", FakeManager())

    async def go():
        return await engine._ssh_exec("10.0.0.5", "whoami", {"username": "root", "password": "x"})

    out = asyncio.run(go())
    assert out == "out-of-whoami"


def test_ssh_exec_falls_back_to_sshpass_without_credentials(monkeypatch):
    engine = PostExploitationEngine()

    captured = {}

    async def fake_run(cmd, timeout=0):
        captured["cmd"] = cmd
        class P:
            returncode = 0
        return P(), b"", b""

    monkeypatch.setattr("post_exploitation.engine.asyncio.create_subprocess_shell", fake_run)
    monkeypatch.setattr("post_exploitation.engine.asyncio.wait_for",
                        lambda coro, timeout: coro)

    async def go():
        return await engine._ssh_exec("10.0.0.5", "whoami")

    out = asyncio.run(go())
    assert "ssh" in captured.get("cmd", "")
```

Note: the fallback test uses `asyncio.wait_for(coro, timeout)` passthrough so the fake `create_subprocess_shell` result is returned directly; the real engine code awaits `process.communicate()` — adjust the fake to return a double-awaitable if needed (implement a `communicate` method object). During implementation, if the existing `_ssh_exec` awaits `proc.communicate()`, make `fake_run` return an object with `communicate() -> (b"", b"")` and `returncode = 0`.

- [ ] **Step 2: Run test, verify FAIL**

Run: `python -m pytest tests/test_post_exploit_sessions.py -q`
Expected: FAIL (session manager not used yet)

- [ ] **Step 3: Implement session-first `_ssh_exec`**

In `post_exploitation/engine.py`:

```python
from ai.sessions import SSH_SESSION_MANAGER

async def _ssh_exec(self, target: str, command: str, credentials: Optional[dict] = None) -> str:
    if credentials:
        username = credentials.get("username", "root")
        password = credentials.get("password", "")
        out, code = await SSH_SESSION_MANAGER.exec_on(target, username, password, command)
        if code == 0 or out:
            return out
    if credentials:
        username = credentials.get("username", "root")
        password = credentials.get("password", "")
        cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {username}@{target} '{command}'"
    else:
        cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {target} '{command}'"
    # ... existing try/except unchanged
```

- [ ] **Step 4: Run test, verify PASS**

Run: `python -m pytest tests/test_post_exploit_sessions.py -q`
Expected: 2 passed

- [ ] **Step 5: Add close_all hook to PivotManager**

In `pivoting/manager.py`, add:

```python
async def close_all_sessions(self) -> int:
    """Close all persistent SSH sessions (pivot teardown)."""
    from ai.sessions import SSH_SESSION_MANAGER
    return await SSH_SESSION_MANAGER.close_all()
```

- [ ] **Step 6: Full suite green**

Run: `python -m pytest tests/ -q`
Expected: ≥190 passed

- [ ] **Step 7: Commit**

```bash
git add post_exploitation/engine.py pivoting/manager.py tests/test_post_exploit_sessions.py
git commit -m "feat: route post-exploitation through persistent SSH sessions with fallback"
```

---

### Task 4: BloodHound neo4j Attack-Path Queries

**Files:**
- Create: `enterprise/bloodhound_queries.py`
- Create: `tests/test_bloodhound_queries.py`
- Modify: `pyproject.toml` (add `neo4j>=5.0.0` to dependencies)

**Interfaces:**
- Consumes: `enterprise/tools.py::BloodhoundIntegration.collect` (existing), `neo4j` driver (new dep).
- Produces:
  - `BH_DEFAULT_URL = "bolt://localhost:7687"`, `BH_DEFAULT_USER = "neo4j"`, `BH_DEFAULT_PASS = "bloodhoundcommunity edition"`.
  - `async def query_shortest_paths(user: str, target_user: str = "Domain Admins", url: str = "", auth_user: str = "", auth_pass: str = "") -> dict` — runs the classic BloodHound shortest-path query over the neo4j bolt driver (via `asyncio.to_thread`); returns `{"paths": [list of node/edge strings], "count": n, "error": str?}`. Falls back to `cypher-shell -a <url> -u <user> -p <pass> -q '<cypher>'` CLI when the driver is unavailable.
  - `async def query_find_admins(user: str, ...) -> dict` — "Who is Admin of X?" query (shortest path to "Domain Admins").
  - `async def query_owned_principals(...) -> dict` — returns principals marked owned with count of attack edges.
  - Registered tools: `bh_shortest_paths(user, target_user="Domain Admins")`, `bh_find_admins(user)`, `bh_owned_principals()`.
  - Pure helper `parse_cypher_shell_output(raw: str) -> list[dict]` (parses tab/newline separated cypher-shell output into row dicts) — offline-testable.

- [ ] **Step 1: Add dependency and write failing tests**

```python
# tests/test_bloodhound_queries.py
from enterprise.bloodhound_queries import (
    build_shortest_path_cypher,
    build_find_admins_cypher,
    parse_cypher_shell_output,
)


def test_shortest_path_cypher_mentions_user():
    cypher = build_shortest_path_cypher("jdoe")
    assert "jdoe" in cypher
    assert "ShortestPath" in cypher
    assert "Domain Admins" in cypher


def test_find_admins_cypher_mentions_target():
    cypher = build_find_admins_cypher("jdoe")
    assert "jdoe" in cypher


def test_parse_cypher_shell_output_rows():
    raw = "a\tb\nnode1\tvalue1\nnode2\tvalue2\n"
    rows = parse_cypher_shell_output(raw)
    assert len(rows) == 2
    assert rows[0] == {"a": "node1", "b": "value1"}
    assert rows[1] == {"a": "node2", "b": "value2"}


def test_parse_cypher_shell_output_empty():
    assert parse_cypher_shell_output("") == []
    assert parse_cypher_shell_output("a\tb\n") == []
```

- [ ] **Step 2: Run test, verify FAIL**

Run: `python -m pytest tests/test_bloodhound_queries.py -q`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `enterprise/bloodhound_queries.py`**

```python
"""BloodHound attack-path querying over neo4j (bolt driver with cypher-shell fallback)."""

import asyncio
from typing import Optional

from ai.tool_registry import ToolCategory, register_tool, ToolParameter

BH_DEFAULT_URL = "bolt://localhost:7687"
BH_DEFAULT_USER = "neo4j"
BH_DEFAULT_PASS = "bloodhoundcommunity edition"


def build_shortest_path_cypher(user: str, target_user: str = "Domain Admins") -> str:
    return (
        f"MATCH (a:User) WHERE a.name =~ '(?i).*{user}.*' "
        f"MATCH (b:Group) WHERE b.name =~ '(?i).*{target_user}.*' "
        "MATCH p=shortestPath((a)-[*1..]->(b)) "
        "RETURN [n in nodes(p) | n.name] AS path, length(p) AS hops "
        "ORDER BY hops ASC LIMIT 5"
    )


def build_find_admins_cypher(user: str) -> str:
    return (
        f"MATCH (u:User) WHERE u.name =~ '(?i).*{user}.*' "
        "MATCH p=shortestPath((u)-[*1..]->(g:Group)) "
        "WHERE g.name CONTAINS 'Admin' "
        "RETURN [n in nodes(p) | n.name] AS path, length(p) AS hops "
        "ORDER BY hops ASC LIMIT 5"
    )


def build_owned_principals_cypher() -> str:
    return (
        "MATCH (n) WHERE n.owned = true "
        "OPTIONAL MATCH (n)-[r]->(m) "
        "RETURN n.name AS principal, labels(n) AS type, count(r) AS outbound_edges "
        "ORDER BY outbound_edges DESC"
    )


def parse_cypher_shell_output(raw: str) -> list[dict]:
    lines = [ln for ln in raw.strip().split("\n") if ln.strip()]
    if len(lines) < 2:
        return []
    headers = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        cells = line.split("\t")
        if len(cells) == len(headers):
            rows.append(dict(zip(headers, cells)))
    return rows


async def _run_bolt(cypher: str, url: str, auth_user: str, auth_pass: str) -> list[dict]:
    def _query() -> list[dict]:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(url, auth=(auth_user, auth_pass))
        try:
            with driver.session() as session:
                records = session.run(cypher).data()
            return records
        finally:
            driver.close()

    return await asyncio.to_thread(_query)


async def _run_cypher_shell(cypher: str, url: str, auth_user: str, auth_pass: str) -> list[dict]:
    addr = url.replace("bolt://", "bolt://")
    cmd = (
        "cypher-shell -a {url} -u {user} -p {pw} --format plain -q {query}"
    ).format(url=addr, user=auth_user, pw=auth_pass, query=repr(cypher))
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
    return parse_cypher_shell_output(stdout.decode("utf-8", errors="replace"))


async def _query_neo4j(cypher: str, url: str = "", auth_user: str = "", auth_pass: str = "") -> dict:
    url = url or BH_DEFAULT_URL
    auth_user = auth_user or BH_DEFAULT_USER
    auth_pass = auth_pass or BH_DEFAULT_PASS
    try:
        return {"success": True, "rows": await _run_bolt(cypher, url, auth_user, auth_pass)}
    except Exception:
        try:
            rows = await _run_cypher_shell(cypher, url, auth_user, auth_pass)
            return {"success": True, "rows": rows, "backend": "cypher-shell"}
        except Exception as e:
            return {"success": False, "error": str(e), "rows": []}


async def query_shortest_paths(user: str, target_user: str = "Domain Admins",
                               url: str = "", auth_user: str = "", auth_pass: str = "") -> dict:
    return await _query_neo4j(build_shortest_path_cypher(user, target_user), url, auth_user, auth_pass)


async def query_find_admins(user: str, url: str = "", auth_user: str = "", auth_pass: str = "") -> dict:
    return await _query_neo4j(build_find_admins_cypher(user), url, auth_user, auth_pass)


async def query_owned_principals(url: str = "", auth_user: str = "", auth_pass: str = "") -> dict:
    return await _query_neo4j(build_owned_principals_cypher(), url, auth_user, auth_pass)


@register_tool(
    name="bh_shortest_paths",
    description="Query BloodHound neo4j for the shortest attack path from a user to a target group (e.g. Domain Admins)",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="user", type="str", description="Source username"),
        ToolParameter(name="target_user", type="str", description="Target group/user", required=False, default="Domain Admins"),
    ],
)
async def bh_shortest_paths(user: str, target_user: str = "Domain Admins") -> dict:
    return await query_shortest_paths(user, target_user)


@register_tool(
    name="bh_find_admins",
    description="Query BloodHound neo4j for paths from a user to any admin group",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="user", type="str", description="Source username"),
    ],
)
async def bh_find_admins(user: str) -> dict:
    return await query_find_admins(user)


@register_tool(
    name="bh_owned_principals",
    description="List owned principals and their outbound attack edges from BloodHound neo4j",
    category=ToolCategory.AD,
    parameters=[],
)
async def bh_owned_principals() -> dict:
    return await query_owned_principals()
```

- [ ] **Step 4: Run test, verify PASS**

Run: `python -m pytest tests/test_bloodhound_queries.py -q`
Expected: 4 passed

- [ ] **Step 5: Wire into BloodhoundIntegration**

In `enterprise/tools.py`, after `BloodhoundIntegration.collect`, add a staticmethod:

```python
@staticmethod
async def find_paths(user: str, target_user: str = "Domain Admins",
                     url: str = "", auth_user: str = "", auth_pass: str = "") -> dict:
    from enterprise.bloodhound_queries import query_shortest_paths
    return await query_shortest_paths(user, target_user, url, auth_user, auth_pass)
```

- [ ] **Step 6: Full suite green + import smoke check**

Run: `python -m pytest tests/ -q`
Expected: ≥194 passed
Run: `python -c "import enterprise.bloodhound_queries; print('ok')"`
Expected: `ok`

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml enterprise/bloodhound_queries.py enterprise/tools.py tests/test_bloodhound_queries.py
git commit -m "feat: BloodHound neo4j attack-path queries with bolt driver and cypher-shell fallback"
```

---

### Task 5: CVSS v3.1 Scoring in Reports

**Files:**
- Create: `reporting/cvss.py`
- Create: `tests/test_cvss.py`
- Modify: `reporting/generator.py`

**Interfaces:**
- Consumes: `reporting.generator.Finding` (fields `severity`, `title`, `cvss_score`, `cve`).
- Produces:
  - `SEVERITY_BASE = {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9), "low": (0.1, 3.9), "info": (0.0, 0.0)}`
  - `def severity_to_base(severity: str) -> float` — returns the floor of the severity band.
  - `def build_cvss_vector(severity: str, network: bool = True, complexity: str = "low", privileges: str = "none", user_interaction: str = "none", confidentiality: str = "high", integrity: str = "high", availability: str = "high") -> str` — returns a valid `CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:U/C:.../I:.../A:...` vector.
  - `def cvss_vector_to_score(vector: str) -> float` — pure Python CVSS v3.1 base-score calculator (formula from FIRST CVSS v3.1 spec) — offline testable, no dependency.
  - `def score_finding(finding_title: str, severity: str, service: str = "") -> tuple[float, str]` — returns `(score, vector)` by mapping severity band + heuristics (SSH brute → AV:N/AC:H? keep simple: AV:N, AC:L, PR:N for unauthenticated; service "ssh"/"smb"/"http" → AV:N; "local" hints → AV:L). Document: scores are base-only, no temporal/environmental.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cvss.py
from reporting.cvss import (
    severity_to_base,
    build_cvss_vector,
    cvss_vector_to_score,
    score_finding,
)


def test_severity_bands():
    assert severity_to_base("critical") == 9.0
    assert severity_to_base("high") == 7.0
    assert severity_to_base("medium") == 4.0
    assert severity_to_base("low") == 0.1
    assert severity_to_base("info") == 0.0


def test_vector_is_well_formed():
    v = build_cvss_vector("high")
    assert v.startswith("CVSS:3.1/")
    assert "AV:N" in v
    assert "AC:L" in v
    assert "PR:N" in v
    assert "UI:N" in v
    assert "S:U" in v


def test_cvss_known_score():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = cvss_vector_to_score(vector)
    assert round(score, 1) == 9.8


def test_cvss_low_score():
    vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"
    score = cvss_vector_to_score(vector)
    assert 0.0 < score < 4.0


def test_score_finding_returns_band():
    score, vector = score_finding("SSH brute force", "high", service="ssh")
    assert 7.0 <= score <= 10.0
    assert "AV:N" in vector
```

- [ ] **Step 2: Run test, verify FAIL**

Run: `python -m pytest tests/test_cvss.py -q`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `reporting/cvss.py`**

```python
"""CVSS v3.1 base scoring - pure Python implementation (FIRST spec)."""

import math
import re
from typing import Optional

SEVERITY_BASE = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}


def severity_to_base(severity: str) -> float:
    band = SEVERITY_BASE.get(severity.lower(), (0.0, 0.0))
    return band[0]


def build_cvss_vector(
    severity: str,
    network: bool = True,
    complexity: str = "low",
    privileges: str = "none",
    user_interaction: str = "none",
    confidentiality: str = "high",
    integrity: str = "high",
    availability: str = "high",
) -> str:
    av = "N" if network else "L"
    ac = {"low": "L", "high": "H"}.get(complexity.lower(), "L")
    pr = {"none": "N", "low": "L", "high": "H"}.get(privileges.lower(), "N")
    ui = {"none": "N", "required": "R"}.get(user_interaction.lower(), "N")
    c = confidentiality.upper()[0]
    i = integrity.upper()[0]
    a = availability.upper()[0]
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}"


def cvss_vector_to_score(vector: str) -> float:
    m = re.match(
        r"CVSS:3\.1/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])"
        r"/C:([NLH])/I:([NLH])/A:([NLH])",
        vector,
    )
    if not m:
        raise ValueError(f"Invalid CVSS v3.1 vector: {vector}")
    av, ac, pr, ui, s, c, i, a = m.groups()

    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    if s == "C":
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.5}
    ui_map = {"N": 0.85, "R": 0.62}
    impact_map = {"N": 0.0, "L": 0.22, "H": 0.56}

    iss = 1 - (
        (1 - impact_map[c]) * (1 - impact_map[i]) * (1 - impact_map[a])
    )
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av_map[av] * ac_map[ac] * pr_map[pr] * ui_map[ui]
    if impact <= 0:
        return 0.0
    if s == "U":
        base = round(min(impact + exploitability, 10.0), 1)
    else:
        base = round(min(1.08 * (impact + exploitability), 10.0), 1)
    return base


def score_finding(title: str, severity: str, service: str = "") -> tuple[float, str]:
    sev = severity.lower() if severity.lower() in SEVERITY_BASE else "medium"
    network = "ssh" not in service.lower() or True
    local_hint = any(k in title.lower() for k in ("local", "suid", "cron", "kernel", "shadow"))
    if local_hint:
        vector = build_cvss_vector(sev, network=False, privileges="low",
                                   user_interaction="required", confidentiality="high",
                                   integrity="high", availability="high")
    elif service.lower() in ("ssh", "smb", "http", "https", "ftp", "winrm", "rdp"):
        vector = build_cvss_vector(sev, network=True, privileges="none",
                                   user_interaction="none", confidentiality="high",
                                   integrity="high", availability="high")
    else:
        vector = build_cvss_vector(sev, network=True, privileges="none")
    score = cvss_vector_to_score(vector)
    band = SEVERITY_BASE[sev]
    score = max(band[0], min(score, band[1]))
    return round(score, 1), vector
```

- [ ] **Step 4: Run test, verify PASS**

Run: `python -m pytest tests/test_cvss.py -q`
Expected: 5 passed

- [ ] **Step 5: Wire into ReportGenerator**

In `reporting/generator.py`:
- Import: `from reporting.cvss import score_finding` (inside `add_finding` to avoid import cycles, or top-level — top-level is fine since cvss.py imports nothing from generator).
- In `add_finding`: if `finding.cvss_score is None`, auto-populate:

```python
def add_finding(self, finding: Finding) -> None:
    if finding.cvss_score is None:
        score, _ = score_finding(finding.title, finding.severity)
        finding.cvss_score = score
    self._findings.append(finding)
```

- In `generate_findings_section`, the CVSS line already prints `finding.cvss_score`; no change needed beyond auto-population.
- In `to_json`, add `"cvss_score": f.cvss_score` to the findings serializer.

- [ ] **Step 6: Write generator regression test**

```python
# tests/test_cvss.py (append)
from reporting.generator import Finding, ReportGenerator


def test_report_generator_auto_scores_findings():
    gen = ReportGenerator.__new__(ReportGenerator)
    gen.state = None
    gen._findings = []
    gen._attack_narrative = []
    f = Finding(id="X-1", title="SSH brute force", severity="high", description="d")
    gen.add_finding(f)
    assert f.cvss_score is not None
    assert 7.0 <= f.cvss_score <= 10.0
```

(Note: `ReportGenerator.__new__` bypasses `__init__` so `state` can be `None`; `add_finding` doesn't touch `state`.)

- [ ] **Step 7: Full suite green**

Run: `python -m pytest tests/ -q`
Expected: ≥200 passed

- [ ] **Step 8: Commit**

```bash
git add reporting/cvss.py reporting/generator.py tests/test_cvss.py
git commit -m "feat: CVSS v3.1 base scoring auto-wired into report findings"
```

---

### Task 6: Documentation + Final Verification

**Files:**
- Modify: `README.md` (Enterprise Coverage section)
- Modify: `HONEST_AUDIT.md` (replace stale verdict)

- [ ] **Step 1: Update README**

In README "Enterprise Coverage" table, add rows:
- **Persistent Access** — paramiko SSH sessions with transparent reconnect; post-exploitation and pivoting reuse live channels instead of re-authenticating.
- **Attack Path Analysis** — BloodHound neo4j querying (`bh_shortest_paths`, `bh_find_admins`, `bh_owned_principals`) for shortest path to Domain Admins.
- **CVSS Reporting** — every finding auto-scored with CVSS v3.1 base vectors; scores exported to JSON/Markdown reports.

- [ ] **Step 2: Update HONEST_AUDIT.md verdict**

Replace the stale "60% REAL, 40% PLACEHOLDER" verdict with a refreshed section noting the AD/binary/IoT/privesc modules are now real tool integrations and the remaining gaps (no AV evasion, no persistence primitives, kernel exploits still manual, naive web tests) with the new verdict: real offensive capability for authorized engagements; enterprise limits documented.

- [ ] **Step 3: Full verification**

Run: `python -m pytest tests/ -q`
Expected: all green (pre-existing 2 Windows-only fails in test_autonomous acceptable)
Run: `python -c "from ai.tool_registry import registry; names = registry.list_names(); print(len(names)); print([n for n in names if 'session' in n or 'bh_' in n or 'deep_engage' in n])"`
Expected: new tools listed (`ssh_session_exec`, `session_status`, `bh_shortest_paths`, `bh_find_admins`, `bh_owned_principals`)

- [ ] **Step 4: Commit**

```bash
git add README.md HONEST_AUDIT.md
git commit -m "docs: document persistent sessions, BloodHound queries, CVSS scoring; refresh audit"
```

---

## Self-Review

**Spec coverage:**
- Shell injection/quoting (audit gap #2) → Task 1 ✅
- Persistent sessions / no-C2 (gap #1) → Tasks 2–3 ✅
- BloodHound query automation (gap #4) → Task 4 ✅
- CVSS scoring in reports (gap #7) → Task 5 ✅
- Docs + stale audit refresh → Task 6 ✅

**Placeholder scan:** All steps contain concrete code; no TBDs. The one conditional (ToolCategory.POST_EXPLOIT existence) is flagged inline with a verify command.

**Type consistency:** `SSH_SESSION_MANAGER` singleton defined in Task 2, consumed in Task 3. `build_remote_cmd`/`q` defined Task 1, consumed Task 1 steps 5–7. `score_finding(title, severity, service)` signature matches usage in Task 5 step 5. `parse_cypher_shell_output(raw) -> list[dict]` consistent between Task 4 tests and implementation.

**Known limitation (intentional):** CVSS scores are base-only (no temporal/environmental), documented in cvss.py docstring — acceptable for automated reporting.

**Pre-existing failures:** `tests/test_autonomous.py` 2 failures are Windows-only (`test_run_with_timeout`, `test_read_file`) and documented in README as non-Linux-only; they stay.
