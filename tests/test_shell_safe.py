"""Tests for safe shell command construction."""

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
    assert shlex.split(cmd)[-1] == "id"


def test_build_remote_cmd_quotes_injection_payload():
    cmd = build_remote_cmd("id; rm -rf /", "10.0.0.5", "a b", "x")
    assert shlex.split(cmd)[-1] == "id; rm -rf /"


def test_build_smb_client_cmd_list_shares():
    cmd = build_smb_client_cmd("list", "10.0.0.5", 445)
    assert cmd.startswith("smbclient -L")
    assert "-p 445" in cmd


def test_build_smb_client_cmd_connect_with_creds():
    cmd = build_smb_client_cmd("connect", "10.0.0.5", 445, "user", "p@ss", share="IPC$")
    assert "//10.0.0.5" in cmd
    assert "IPC$" in cmd
    assert "-U user%p@ss" in cmd


def test_password_list_default_and_custom():
    assert isinstance(DEFAULT_PASSWORD_LIST, list) and len(DEFAULT_PASSWORD_LIST) >= 20
    custom = ["a", "b"]
    assert password_list({"passwords": custom}) == custom
    assert password_list({}) == DEFAULT_PASSWORD_LIST
