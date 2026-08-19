"""Tests for persistent SSH session manager."""

import asyncio

import pytest

from ai.sessions import SSHSessionManager, SSHSession


class FakeChannel:
    def recv_exit_status(self):
        return 0


class FakeStdout:
    def __init__(self, output="hello"):
        self._out = output.encode()
        self.channel = FakeChannel()

    def read(self):
        return self._out


class FakeSSHClient:
    def __init__(self):
        self.connected = False
        self._out = "hello"

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, hostname, port=22, username=None, password=None, key_filename=None, timeout=10):
        self.connected = True

    def exec_command(self, command, timeout=None):
        return None, FakeStdout(self._out), None

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
        calls = 0

        def __init__(self):
            super().__init__()

        def exec_command(self, command, timeout=None):
            FlakyClient.calls += 1
            if FlakyClient.calls == 1:
                import paramiko
                raise paramiko.SSHException("channel closed")
            return None, FakeStdout(self._out), None

    monkeypatch.setattr(mod.paramiko, "SSHClient", FlakyClient)

    async def go():
        mgr = SSHSessionManager()
        out, code = await mgr.exec_on("10.0.0.5", "root", "hunter2", "whoami")
        return out, code

    out, code = asyncio.run(go())
    assert code == 0
    assert "hello" in out